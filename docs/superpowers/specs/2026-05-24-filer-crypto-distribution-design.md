# filer-crypto Distribution + Parity Testing — Design

**Date:** 2026-05-24
**Status:** Approved, ready for plan
**Tracks:** [filer-crypto#3](https://github.com/CorvidSoft/filer-crypto/issues/3)
**Prior spec:** [2026-05-20 setup design](./2026-05-20-filer-crypto-setup-design.md)

## 1. Goal

Make `filer-crypto` consumable as a Swift Package by the Filer iOS app on a real device build, and put automated verification machinery in place so a Rust change cannot silently break the Swift surface.

After this spec ships:
- The Filer iOS app can `swift package add` filer-crypto by URL+tag and build for device.
- Every PR runs the Swift parity tests on macOS CI; envelope-format drift is caught by golden fixtures.
- Tag push (`v*`) automatically builds an XCFramework on macOS CI and creates a GitHub Release with a checksummed `.binaryTarget`-ready asset.
- A future contributor can classify a candidate change as patch / minor / major from `docs/VERSIONING.md` alone.

## 2. Scope

### In scope

Six tightly coupled deliverables that together unblock real-device consumption:

1. **`scripts/build-xcframework.sh`** producing an XCFramework with slices for `ios-arm64` and `ios-simulator` (`arm64` + `x86_64` universal via `lipo`).
2. **`.github/workflows/release.yml`** — on `v*` tag push: builds the XCFramework on macOS, computes sha256, creates a GitHub Release, uploads the `.zip` as an asset, emits the `.binaryTarget` snippet for the release notes.
3. **`Package.swift` dual-mode switch** — env-var-gated. Default uses `.binaryTarget(url:, checksum:)`; `FILER_CRYPTO_LOCAL=1` uses a source-Swift target with explicit linker settings against `target/{release,debug}/libfiler_crypto.a` (the staticlib — see §3.3 for why not the dylib).
4. **Real Swift parity tests** replacing the `XCTSkip`: blob round-trip, metadata-field round-trip, sign+verify round-trip, BIP39 round-trip, and golden cross-language fixtures (Rust-produced envelopes decoded by Swift, with checked-in test vectors).
5. **macOS `swift-tests` job** added to `.github/workflows/ci.yml`, running `swift test` on every PR against the local-dev mode.
6. **`docs/VERSIONING.md`** — one-page semver policy with the explicit "envelope format or HKDF context strings = major bump" rule (CLAUDE.md invariants #7 and #8).

### Out of scope (deferred per issue #3)

- Android UniFFI bindings (Filer v2 — separate sibling crate `crates/filer-crypto-uniffi-kotlin/`)
- `wasm-bindgen` bindings (post-launch — separate sibling crate)
- `proptest` round-trip property tests (first feature plan)
- `cargo-fuzz` harness (post-launch hardening)
- `subtle` crate re-add (waits for a path that needs `ConstantTimeEq`)

### Out of repo

- `ios.appleTeamId` (lives in the closed-source mobile repo's `app.config.ts`)

## 3. Architecture

### 3.1 XCFramework layout

```
FilerCryptoFFI.xcframework/
├── Info.plist
├── ios-arm64/                                 # device
│   ├── libfiler_crypto.a
│   └── Headers/
│       ├── filer_cryptoFFI.h
│       └── module.modulemap                   # declares `filer_cryptoFFI`
└── ios-arm64_x86_64-simulator/                # universal sim (lipo)
    ├── libfiler_crypto.a
    └── Headers/
        ├── filer_cryptoFFI.h
        └── module.modulemap
```

Each slice's `libfiler_crypto.a` is the staticlib output of `filer-crypto-uniffi` (already in its `crate-type`). The header and modulemap are the same files currently in `Sources/FilerCrypto/`. The XCFramework is itself zipped for SPM consumption — `.binaryTarget(url:, checksum:)` requires a remote zip and validates the sha256.

### 3.2 Build pipeline — `scripts/build-xcframework.sh`

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo build --release --target aarch64-apple-ios       --package filer-crypto-uniffi
cargo build --release --target aarch64-apple-ios-sim   --package filer-crypto-uniffi
cargo build --release --target x86_64-apple-ios        --package filer-crypto-uniffi

lipo -create \
  target/aarch64-apple-ios-sim/release/libfiler_crypto.a \
  target/x86_64-apple-ios/release/libfiler_crypto.a \
  -output build/ios-sim-universal/libfiler_crypto.a

# Sanity check: lipo -info must report both arches.
lipo -info build/ios-sim-universal/libfiler_crypto.a | grep -q "arm64 x86_64"

# Stage headers from the existing Sources/FilerCrypto/ files.
mkdir -p build/headers
cp Sources/FilerCrypto/filer_cryptoFFI.h        build/headers/
cp Sources/FilerCrypto/filer_cryptoFFI.modulemap build/headers/module.modulemap

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libfiler_crypto.a    -headers build/headers \
  -library build/ios-sim-universal/libfiler_crypto.a             -headers build/headers \
  -output  build/FilerCryptoFFI.xcframework

# Verify committed bindings match what the current Rust source would generate.
./scripts/build.sh release
git diff --exit-code Sources/FilerCrypto/FilerCrypto.swift \
                     Sources/FilerCrypto/filer_cryptoFFI.h \
                     Sources/FilerCrypto/filer_cryptoFFI.modulemap

( cd build && zip -r FilerCryptoFFI.xcframework.zip FilerCryptoFFI.xcframework )
shasum -a 256 build/FilerCryptoFFI.xcframework.zip
```

The bindings-drift check is internal to this script: if the freshly generated bindings differ from the committed ones, the script aborts. This makes both PR CI and release CI catch the same class of error.

### 3.3 `Package.swift` dual mode

The current `Package.swift` declares a source-Swift target but does **not** wire up linkage against the Rust library — that's why `Tests/FilerCryptoTests/FilerCryptoTests.swift` is an `XCTSkip` today. This spec adds explicit linkage on both branches of the dual mode.

```swift
import PackageDescription
import Foundation

let local = ProcessInfo.processInfo.environment["FILER_CRYPTO_LOCAL"] == "1"
let localProfile = ProcessInfo.processInfo.environment["FILER_CRYPTO_LOCAL_PROFILE"] ?? "debug"
// localProfile ∈ {"debug", "release"} — selects which target/<profile>/libfiler_crypto.a to link.

let targets: [Target] = local
    ? [
        .target(
            name: "FilerCrypto",
            path: "Sources/FilerCrypto",
            publicHeadersPath: ".",
            linkerSettings: [
                .unsafeFlags(["-L", "target/\(localProfile)"]),
                .linkedLibrary("filer_crypto"),     // resolves to target/<profile>/libfiler_crypto.a
                // System frameworks the Rust crate's transitive deps pull in:
                .linkedFramework("Security"),       // SecRandomCopyBytes via getrandom
            ]
        ),
    ]
    : [
        .binaryTarget(
            name: "FilerCryptoFFI",
            url: "https://github.com/CorvidSoft/filer-crypto/releases/download/v<X.Y.Z>/FilerCryptoFFI.xcframework.zip",
            checksum: "<sha256>"
        ),
        .target(
            name: "FilerCrypto",
            dependencies: ["FilerCryptoFFI"],
            path: "Sources/FilerCrypto",
            exclude: ["filer_cryptoFFI.h", "filer_cryptoFFI.modulemap"] // shipped inside the binary target
        ),
    ]

let package = Package(
    name: "FilerCrypto",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "FilerCrypto", targets: ["FilerCrypto"])],
    targets: targets + [
        .testTarget(
            name: "FilerCryptoTests",
            dependencies: ["FilerCrypto"],
            path: "Tests/FilerCryptoTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)
```

**Why the staticlib (`.a`) and not the dylib:** linking the staticlib avoids dyld runtime resolution at `swift test` time (no `@rpath` / `DYLD_LIBRARY_PATH` dance). `filer-crypto-uniffi`'s `Cargo.toml` already declares `crate-type = ["cdylib", "staticlib", "rlib"]`, so `./scripts/build.sh debug` produces both `libfiler_crypto.dylib` and `libfiler_crypto.a`; `.linkedLibrary("filer_crypto")` resolves to the static archive when present.

**Why `.unsafeFlags`:** SPM marks targets using `.unsafeFlags` as non-publishable to a binary distribution. That's exactly what we want for the local-dev branch — local-dev is never the distribution path; the `.binaryTarget` branch is, and it has no `.unsafeFlags`.

**The `Security` framework dependency:** The `getrandom` crate on Apple platforms uses `SecRandomCopyBytes`, which lives in `Security.framework`. The XCFramework branch doesn't need this because Apple's static linker picks up framework linkage from the XCFramework's `Info.plist` automatically; the local-dev branch needs it explicit. (If we discover additional framework deps from RustCrypto transitive crates during implementation, add them here.)

**Release commit responsibility:** The two `<X.Y.Z>` / `<sha256>` placeholders are updated by hand on the release commit (one-line edit, human-signed) rather than templated by CI.

### 3.4 Component boundaries

| Component | Owns | Doesn't own |
|---|---|---|
| `scripts/build-xcframework.sh` | Cross-compile, lipo, xcodebuild assembly, zip + sha256, bindings drift check | Tagging, uploading, `Package.swift` edits |
| `.github/workflows/release.yml` | Running the script on macOS, creating the GitHub Release, uploading the asset | Cross-compilation logic (delegates to the script) |
| `Package.swift` | Dual-mode resolution (binary vs. local) | Building anything itself |
| `Tests/FilerCryptoTests/` | Round-trip + golden-fixture parity checks | Producing the fixtures (Rust does that) |
| `crates/filer-crypto/tests/generate_fixtures.rs` | Golden fixture generator (committed bytes) | Swift tests |
| `.github/workflows/ci.yml` (`swift-tests` job) | Building local dylib + running `swift test` on macOS | Cross-compilation, releases |
| `docs/VERSIONING.md` | Semver rules + the wire-format / context-string major-bump rule | Anything implementation-shaped |

## 4. Release CI workflow

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: macos-latest
    timeout-minutes: 30
    permissions:
      contents: write          # to create the GitHub Release
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Add iOS targets
        run: rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

      - name: Verify tag matches workspace version
        run: |
          tag="${GITHUB_REF_NAME#v}"
          ws=$(awk -F'"' '/^version =/ {print $2; exit}' Cargo.toml)
          [ "$tag" = "$ws" ] || { echo "tag $tag != workspace version $ws"; exit 1; }

      - name: Build XCFramework
        run: ./scripts/build-xcframework.sh

      - name: Compute checksum
        id: sum
        run: echo "sha256=$(shasum -a 256 build/FilerCryptoFFI.xcframework.zip | awk '{print $1}')" >> "$GITHUB_OUTPUT"

      - name: Create release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create "$GITHUB_REF_NAME" \
            build/FilerCryptoFFI.xcframework.zip \
            --title "$GITHUB_REF_NAME" \
            --notes "$(./scripts/release-notes.sh ${{ steps.sum.outputs.sha256 }})"
```

`scripts/release-notes.sh` is a tiny helper that prints the release body including the `.binaryTarget` snippet pre-filled with the URL and checksum, so consumers can copy-paste into their own `Package.swift`.

### 4.1 Failure modes the workflow catches

- **Bindings drift** — `build-xcframework.sh` already diffs regenerated bindings against the committed file.
- **Tag-vs-Cargo-version skew** — the `awk` check prevents a `v0.2.0` tag accidentally publishing a `0.1.0`-versioned artifact.
- **Any iOS-triple build failure** — aborts before the release is created.

### 4.2 What the workflow deliberately does NOT do

- **Edit `Package.swift` post-release.** The Package.swift update is a manual commit on the release branch *before* tagging. This avoids CI commits-on-its-own-branch loops and keeps the release a single human-signed commit.
- **Sign or notarize the artifact.** Not required for SPM `.binaryTarget` — the checksum is the integrity check.
- **Publish to crates.io.** The Rust crate is consumed only via the workspace and via this XCFramework; crates.io publishing is a separate decision and not on the iOS critical path.

### 4.3 Release procedure (also lives in VERSIONING.md)

1. Bump `workspace.package.version` in `Cargo.toml`.
2. Update `Package.swift`: `url:` to the new tag, `checksum:` to the expected sha256. First release uses a `-rc1` tag to learn the actual checksum; subsequent releases compute it locally via `./scripts/build-xcframework.sh` first.
3. Commit (`chore: release v<X.Y.Z>`), tag (`git tag v<X.Y.Z>`), push the tag.
4. CI builds and publishes the GitHub Release.
5. If the post-publish checksum doesn't match what's in `Package.swift`, delete the tag + release, fix the checksum, re-tag.

## 5. Swift parity tests

### 5.1 Layout

```
Tests/FilerCryptoTests/
├── FilerCryptoTests.swift              # XCTestCase shell, helpers, removes XCTSkip
├── BlobRoundTripTests.swift            # encrypt_blob ↔ decrypt_blob (+ tamper)
├── MetadataFieldRoundTripTests.swift   # encrypt_metadata_field ↔ decrypt_metadata_field (+ tamper)
├── SigningTests.swift                  # sign_challenge + verify_signature (+ wrong-key)
├── RecoveryPhraseTests.swift           # BIP39 round-trip + known-answer
├── CrossLanguageFixtureTests.swift     # decrypt Rust-produced goldens
└── Fixtures/
    ├── README.md
    ├── fixture_master_secret.bin       # 32 bytes, all-zero — DO NOT use in production
    ├── blob_v1.json                    # { plaintext_hex, blob: { ciphertext_hex, iv_hex, wrapped_key_hex } }
    ├── metadata_v1.json
    └── signature_v1.json               # { nonce_hex, public_key_hex, signature_hex }
```

Each round-trip file covers:
- The happy path.
- One negative test (tamper / wrong key / bad input) confirming `FilerCryptoError` propagates correctly across the FFI — this is where bindings bugs hide.

### 5.2 Golden cross-language fixtures

`crates/filer-crypto/tests/generate_fixtures.rs` is a `cargo test`-runnable binary, gated by `#[ignore]` so it doesn't run on every `cargo test`. It produces the JSON files in `Tests/FilerCryptoTests/Fixtures/` from the all-zero master secret and a fixed RNG seed.

```rust
#[test]
#[ignore = "regenerate with: cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture"]
fn regenerate_fixtures() { /* writes JSON to ../../Tests/FilerCryptoTests/Fixtures/ */ }
```

The Swift `CrossLanguageFixtureTests` reads each JSON, reconstructs the `EncryptedBlob` / `EncryptedField` / `DeviceSignature`, and decrypts/verifies. If anyone changes the AEAD construction, HKDF context strings, envelope layout, or signing curve, the fixture decrypt fails — that's invariant #7 enforcement.

The reverse direction (Swift-encrypt → Rust-decrypt) is **not** done with separate fixtures. The round-trip tests in §5.1 already exercise Swift-encrypt followed by Rust-via-FFI-decrypt; both halves cross the boundary.

A `README.md` in `Tests/FilerCryptoTests/Fixtures/` explains: these are test vectors generated from an all-zero master secret, never use this secret for real keys, regenerate via the `--ignored` test above. The all-zero secret is the standard "obvious test vector" sentinel — generating fixtures from a real-looking random secret would create a misleading file that *looks* sensitive but isn't.

### 5.3 Local-dev mode is the only mode that runs in CI

`swift test` runs in `FILER_CRYPTO_LOCAL=1` mode in `ci.yml`'s `swift-tests` job. That mode is what we want PR feedback against because:
- It builds the current commit's Rust source, not a published release.
- It exercises the source-Swift target the way local developers do.
- It doesn't need the previous release's checksum baked into `Package.swift`.

The `.binaryTarget` mode is exercised manually by the release maintainer in the release procedure. A release smoke job that pulls down the just-uploaded XCFramework and runs `swift test` is bonus polish — not in this spec.

### 5.4 What the parity tests deliberately do NOT cover

- **Property-based tests** — explicitly deferred per issue.
- **Performance benchmarks** — not in scope.
- **Memory-safety / leak detection on the Swift side** — Xcode's leak instruments aren't CI-friendly. Manual check at release time.
- **Concurrent `Vault` use** — `Vault` isn't documented as thread-safe; tests don't assert it is.

## 6. macOS CI job

Adds one job to the existing `.github/workflows/ci.yml`:

```yaml
jobs:
  test:                              # existing — unchanged
    runs-on: ubuntu-latest
    # ...

  swift-tests:
    runs-on: macos-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Build native Rust dylib + regenerate bindings
        run: ./scripts/build.sh debug
      - name: Verify bindings are up to date
        run: |
          if ! git diff --exit-code Sources/FilerCrypto/FilerCrypto.swift \
                                    Sources/FilerCrypto/filer_cryptoFFI.h \
                                    Sources/FilerCrypto/filer_cryptoFFI.modulemap; then
            echo "Committed bindings are stale. Run ./scripts/build.sh and commit the result." >&2
            exit 1
          fi
      - name: Swift test
        env:
          FILER_CRYPTO_LOCAL: "1"
        run: swift test
```

### 6.1 Why this shape

- **`macos-latest`, not a matrix.** The issue mentions "macOS CI matrix" but the only meaningful axis is Xcode/Swift version, and we declare `swift-tools-version:5.9` as the floor. `macos-latest` already provides a recent Swift; explicit matrixing buys nothing until a consumer pins to a specific Swift version. Adding `strategy.matrix.swift-version` later is a one-line change.
- **`build.sh debug`, not `release`.** Debug compiles much faster and the parity tests don't care about optimization. The release pipeline already exercises the release profile.
- **Bindings drift check at PR time.** The release pipeline catches drift as a release-blocking failure (§4); PR CI catches it as a PR-blocking failure. Two levels of defense.
- **`FILER_CRYPTO_LOCAL=1` is the entire reason this works on CI.** Without it `swift test` would try to download a release artifact that doesn't exist for this commit.

The existing Ubuntu job is untouched. Cargo fmt + clippy + `cargo test --workspace` already cover the Rust side; adding macOS to that matrix is unnecessary churn.

## 7. Versioning policy doc

`docs/VERSIONING.md` — one page, written for a future maintainer trying to classify a candidate change in under a minute.

Structure:

```
# Versioning

filer-crypto follows semver (MAJOR.MINOR.PATCH).

## The one rule that overrides everything else

Anything that changes the bytes a consumer's existing vault depends on
is a MAJOR bump. Existing vaults stop decrypting on a MAJOR bump — that
is the entire reason MAJOR exists in this crate.

## Classification

### MAJOR — existing vaults stop decrypting
- Envelope struct changes: field name / order / length in EncryptedBlob,
  EncryptedField, DeviceSignature.
- Wrapped-key layout change (currently IV(12) || GCM ciphertext+tag).
- HKDF context strings (WRAP_CTX, METADATA_CTX, SIGN_CTX in kdf.rs).
  The `v1` in `filer-crypto/v1/...` exists so a v2 context can be added
  later, but adding a v2 context that an existing Vault produces is
  itself a MAJOR change. See CLAUDE.md invariant #8.
- Switching AEAD, KDF, signature scheme, or recovery-phrase wordlist.
- Removing or renaming any pub method on Vault or any pub free function
  exported through the UDL.

### MINOR — additive only
- New methods on Vault that don't change the meaning of existing ones.
- New free functions in recovery.rs or new modules.
- New error variants on FilerCryptoError (source-breaking for `match`
  consumers without a wildcard; tolerated as MINOR — the variants are
  intentionally coarse and matchers should use a wildcard).
- New UDL surface that exposes already-public Rust API to Swift.

### PATCH — internal only
- Bug fixes that don't change envelope bytes or the public API.
- Dependency bumps within semver-compatible ranges.
- Documentation, CI, test-only changes.
- Performance improvements with byte-for-byte equivalent output.

## XCFramework + Swift Package versioning

The Swift Package version tracks the Rust crate version. A `v0.2.0`
tag produces a `v0.2.0` GitHub Release with an XCFramework artifact;
Package.swift's `.binaryTarget` URL on `main` points at the latest
published release.

A pre-1.0 MAJOR bump (e.g. 0.1.0 → 0.2.0) carries the same
break-the-vault implications as a post-1.0 MAJOR. Pre-1.0 does not
mean "we can break vaults silently" — it means "we haven't promised
forward compatibility yet."

## Release procedure

[the four-step procedure from §4.3, inlined here]

## When in doubt

If a change *might* alter envelope bytes for any plausible input, run
the cross-language fixture tests (Tests/FilerCryptoTests/Fixtures/).
If they fail after your change, that's a MAJOR.
```

The doc deliberately omits:
- **A changelog** — `git log` is the source of truth; a hand-maintained `CHANGELOG.md` is a separate decision.
- **Deprecation policy** — no deprecations anticipated pre-1.0; add when actually needed.
- **Yanking guidance** — `gh release delete` is well-understood; no script needed.

## 8. Testing & risks

### 8.1 What "done" looks like

| Surface | Test | Where it runs |
|---|---|---|
| Rust core | `cargo test --workspace` (38 existing + new fixture-regen test) | Ubuntu CI on every PR |
| Rust → Swift FFI | `swift test` against locally-built dylib | macOS CI on every PR |
| Wire format stability | Golden fixture decrypt (`CrossLanguageFixtureTests`) | Inside `swift test` |
| Bindings freshness | `git diff` on `Sources/FilerCrypto/` after `./scripts/build.sh` | Both Ubuntu and macOS CI |
| XCFramework build | `./scripts/build-xcframework.sh` exits 0 with valid output | Release CI on tag push |
| End-to-end SPM consumption | Filer iOS app builds with the released `.binaryTarget` | Manual, on first `v0.1.0` |

The first time we tag `v0.1.0` is also the first end-to-end validation. Wiring a "consume our own XCFramework from a throwaway sample app" smoke test into release CI is more scaffolding than it's worth at this stage.

### 8.2 Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| `xcodebuild -create-xcframework` rejects a slice combination on a future Xcode version. | Medium — Apple changes XCFramework rules occasionally. | Pin `runs-on:` to a specific macOS image when we hit the first incident; until then `macos-latest` surfaces problems early. |
| RustCrypto staticlib symbol collision with another C lib in the consuming app. | Low — Rust mangles symbols. | Unlikely; if it happens we add `-Wl,--allow-multiple-definition` or rename the staticlib in `Cargo.toml`. |
| `.binaryTarget` checksum mismatch after release (reproducibility issue). | Low on macOS-only builds, but possible. | Release procedure documents the re-tag path. |
| iOS simulator universal slice silently drops one arch. | Low — `lipo -info` would catch it. | `build-xcframework.sh` runs `lipo -info` on the merged slice and grep-asserts both arches are present. Fail-fast in the script. |
| UniFFI 0.31 ABI changes in a patch release break the committed bindings without us noticing. | Medium — UniFFI moves quickly and our bindings file is checked in. | Pin `uniffi = "=0.31.x"` (exact version) once we settle on a working point release. CLAUDE.md invariant #10 says pin-to-latest on add; this is the maintenance corollary. |
| Bindings drift between local-dev mode and the released XCFramework. | Low — both come from the same source tree. | Bindings-drift `git diff` check runs in BOTH PR CI and release CI. |
| `FILER_CRYPTO_LOCAL=1` semantics diverge from `.binaryTarget` semantics over time. | Medium — easy to forget the local-mode path when fixing a release-mode bug. | The §6 macOS CI job is the local-mode regression net; the release smoke (manual) is the release-mode net. Acceptable. |
| Tag pushed without bumping `Cargo.toml` workspace version. | Medium — easy human error. | The `awk` version check in `release.yml` hard-fails the release. |

### 8.3 Rollout order

```
docs/VERSIONING.md  ─────────────┐
                                 │
scripts/build-xcframework.sh ────┼──> .github/workflows/release.yml
                                 │
crates/filer-crypto/tests/      │
  generate_fixtures.rs    ──────►│
                                 │
Tests/FilerCryptoTests/*  ───────┼──> .github/workflows/ci.yml (swift-tests job)
                                 │
Package.swift dual-mode  ────────┘
```

Practical sequencing:

1. Land `docs/VERSIONING.md`.
2. Land `scripts/build-xcframework.sh` + `scripts/release-notes.sh` (no Package.swift change).
3. Land `release.yml` (no Package.swift change yet — URL not consumed).
4. Land `crates/filer-crypto/tests/generate_fixtures.rs` + checked-in fixtures.
5. Land `Tests/FilerCryptoTests/*` real tests + the `swift-tests` CI job.
6. Cut `v0.0.2-rc1` to learn the actual checksum.
7. Update `Package.swift` to the dual-mode form with the real URL+checksum from step 6.
8. Cut `v0.1.0`.

`v0.1.0` is the first real release on the new pipeline; `-rc1` exists only to discover a real sha256 for `Package.swift`.

### 8.4 What we'll know after step 8

- The Filer iOS app can `swift package add` filer-crypto by URL+tag and build for device.
- Any future Rust change is gated by `swift test` on macOS CI before merge.
- Any envelope-format regression is caught by golden fixtures decrypting wrong.
- A future contributor (human or agent) can correctly classify a candidate change as patch/minor/major from `docs/VERSIONING.md` alone.
