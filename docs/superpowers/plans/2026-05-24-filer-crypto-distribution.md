# filer-crypto Distribution + Parity Testing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-extended-cc:subagent-driven-development (recommended) or superpowers-extended-cc:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make filer-crypto consumable as a Swift Package by the Filer iOS app on a real device build, with automated verification machinery so a Rust change cannot silently break the Swift surface.

**Architecture:** Six tightly coupled deliverables landing in dependency order: VERSIONING.md → XCFramework build script → release CI → cross-language fixtures → Package.swift dual-mode → Swift parity tests → macOS swift-tests CI job → first releases (`v0.0.2-rc1` to learn the checksum, then `v0.1.0`).

**Tech Stack:** Rust 2024 (core) / 2021 (binding crate), UniFFI 0.31, RustCrypto family, Swift 5.9+, Swift Package Manager `.binaryTarget`, GitHub Actions on `macos-latest`.

**Spec:** [`docs/superpowers/specs/2026-05-24-filer-crypto-distribution-design.md`](../specs/2026-05-24-filer-crypto-distribution-design.md)

---

## File Structure

New files:
- `docs/VERSIONING.md` — semver policy with wire-format major-bump rule
- `scripts/build-xcframework.sh` — cross-compile iOS triples, lipo sim slice, xcodebuild assembly
- `scripts/release-notes.sh` — emit release body with `.binaryTarget` snippet
- `.github/workflows/release.yml` — tag-triggered XCFramework build + GitHub Release
- `crates/filer-crypto/tests/generate_fixtures.rs` — `#[ignore]` regenerator for golden fixtures
- `Tests/FilerCryptoTests/Fixtures/README.md` — fixture provenance + regeneration instructions
- `Tests/FilerCryptoTests/Fixtures/blob_v1.json` — Rust-produced blob test vector
- `Tests/FilerCryptoTests/Fixtures/metadata_v1.json` — Rust-produced metadata test vector
- `Tests/FilerCryptoTests/Fixtures/signature_v1.json` — Rust-produced signature test vector
- `Tests/FilerCryptoTests/BlobRoundTripTests.swift`
- `Tests/FilerCryptoTests/MetadataFieldRoundTripTests.swift`
- `Tests/FilerCryptoTests/SigningTests.swift`
- `Tests/FilerCryptoTests/RecoveryPhraseTests.swift`
- `Tests/FilerCryptoTests/CrossLanguageFixtureTests.swift`

Modified files:
- `Package.swift` — dual-mode env-var switch (local vs. `.binaryTarget`) with explicit linker settings
- `Tests/FilerCryptoTests/FilerCryptoTests.swift` — remove `XCTSkip` placeholder, keep shell or delete
- `.github/workflows/ci.yml` — add `swift-tests` job on `macos-latest`
- `Cargo.toml` (workspace) — bump version for releases (rc1, then 0.1.0)

---

## Task 1: Versioning policy doc

**Goal:** Land `docs/VERSIONING.md` so the wire-format major-bump rule is canonical before any code change has a chance to violate it.

**Files:**
- Create: `docs/VERSIONING.md`

**Acceptance Criteria:**
- [ ] `docs/VERSIONING.md` exists at repo root
- [ ] Document includes the "one rule that overrides everything else" callout
- [ ] MAJOR / MINOR / PATCH classification sections present, each with explicit examples
- [ ] HKDF context strings and envelope struct changes explicitly called out as MAJOR
- [ ] `FilerCryptoError` new-variant carve-out documented as MINOR
- [ ] Pre-1.0 carve-out documented
- [ ] Release procedure (4 steps) included
- [ ] "When in doubt" pointer to cross-language fixture tests included

**Verify:** `test -f docs/VERSIONING.md && wc -l docs/VERSIONING.md` → file exists, < 200 lines

**Steps:**

- [ ] **Step 1: Create `docs/VERSIONING.md`**

Write the file with exactly this content:

```markdown
# Versioning

filer-crypto follows semver (MAJOR.MINOR.PATCH).

## The one rule that overrides everything else

Anything that changes the bytes a consumer's existing vault depends on
is a MAJOR bump. Existing vaults stop decrypting on a MAJOR bump — that
is the entire reason MAJOR exists in this crate.

## Classification

### MAJOR — existing vaults stop decrypting

- Envelope struct changes: field name / order / length in `EncryptedBlob`,
  `EncryptedField`, or `DeviceSignature`.
- Wrapped-key layout change (currently `IV(12) || GCM ciphertext+tag`).
- HKDF context strings (`WRAP_CTX`, `METADATA_CTX`, `SIGN_CTX` in `kdf.rs`).
  The `v1` in `filer-crypto/v1/...` exists so that v2 context strings can
  be added later without rotating the v1 ones — but adding a v2 context
  that an existing `Vault` produces is itself a MAJOR change to the
  produced envelopes. See `CLAUDE.md` invariant #8.
- Switching AEAD, KDF, signature scheme, or recovery-phrase wordlist.
- Removing or renaming any `pub` method on `Vault` or any `pub` free
  function exported through the UDL.

### MINOR — additive only

- New methods on `Vault` that don't change the meaning of existing ones.
- New free functions in `recovery.rs` or new modules.
- New error variants on `FilerCryptoError`. Adding variants is
  source-breaking for `match` consumers without a wildcard; we tolerate
  this as MINOR because the variants are intentionally coarse and
  external matchers should use a wildcard.
- New UDL surface that exposes already-public Rust API to Swift.

### PATCH — internal only

- Bug fixes that don't change envelope bytes or the public API.
- Dependency bumps within semver-compatible ranges.
- Documentation, CI, test-only changes.
- Performance improvements with byte-for-byte equivalent output.

## XCFramework + Swift Package versioning

The Swift Package version tracks the Rust crate version. A `v0.2.0` tag
produces a `v0.2.0` GitHub Release with an XCFramework artifact;
`Package.swift`'s `.binaryTarget` URL on `main` points at the latest
published release.

A pre-1.0 MAJOR bump (e.g. `0.1.0 → 0.2.0`) carries the same
break-the-vault implications as a post-1.0 MAJOR. Pre-1.0 does not mean
"we can break vaults silently" — it means "we haven't promised forward
compatibility yet."

## Release procedure

1. Bump `workspace.package.version` in `Cargo.toml`.
2. Update `Package.swift`: `url:` to the new tag, `checksum:` to the
   expected sha256. The first release uses a `-rc1` tag to learn the
   actual checksum; subsequent releases compute it locally first by
   running `./scripts/build-xcframework.sh` and reading the output.
3. Commit (`chore: release v<X.Y.Z>`), tag (`git tag v<X.Y.Z>`), push the
   tag. CI builds the XCFramework on macOS, computes the checksum,
   creates the GitHub Release, and uploads the asset.
4. If the post-publish checksum doesn't match what's in `Package.swift`,
   delete the tag (`git push --delete origin v<X.Y.Z>`) and release
   (`gh release delete v<X.Y.Z>`), fix the checksum, re-tag.

## When in doubt

If a change *might* alter envelope bytes for any plausible input, run
the cross-language fixture tests (`Tests/FilerCryptoTests/Fixtures/`).
If they fail after your change, that's a MAJOR.
```

- [ ] **Step 2: Verify**

Run: `test -f docs/VERSIONING.md && wc -l docs/VERSIONING.md`
Expected: file exists, line count under 200.

Also run: `grep -c "MAJOR" docs/VERSIONING.md`
Expected: at least 6 occurrences (confirms the major-bump rules are present).

- [ ] **Step 3: Commit**

```bash
git add docs/VERSIONING.md
git commit -m "docs: add VERSIONING.md (semver policy with wire-format major-bump rule)"
```

---

## Task 2: XCFramework build script + release-notes helper

**Goal:** Hand-rolled `scripts/build-xcframework.sh` produces a `FilerCryptoFFI.xcframework.zip` plus an sha256, and `scripts/release-notes.sh` formats the release body with a copy-pasteable `.binaryTarget` snippet.

**Files:**
- Create: `scripts/build-xcframework.sh` (mode `+x`)
- Create: `scripts/release-notes.sh` (mode `+x`)

**Acceptance Criteria:**
- [ ] `./scripts/build-xcframework.sh` (on macOS) produces `build/FilerCryptoFFI.xcframework/` with `ios-arm64/` and `ios-arm64_x86_64-simulator/` slices
- [ ] Each slice contains `libfiler_crypto.a` and a `Headers/` directory with `filer_cryptoFFI.h` and `module.modulemap`
- [ ] `build/FilerCryptoFFI.xcframework.zip` exists
- [ ] `lipo -info build/ios-sim-universal/libfiler_crypto.a` reports both `arm64` and `x86_64`
- [ ] Script refuses to run on non-macOS with a clear error
- [ ] Script verifies committed bindings match what would be regenerated from current source; aborts with a clear error if drift detected
- [ ] `./scripts/release-notes.sh <sha256>` prints a release body that contains the sha256 and a `.binaryTarget(url:, checksum:)` snippet

**Verify:**
- macOS: `./scripts/build-xcframework.sh && test -f build/FilerCryptoFFI.xcframework.zip && shasum -a 256 build/FilerCryptoFFI.xcframework.zip` → exits 0, produces a sha256
- Any OS: `./scripts/release-notes.sh abc123 | grep -q 'checksum: "abc123"'` → exits 0

**Steps:**

- [ ] **Step 1: Create `scripts/build-xcframework.sh`**

```bash
#!/usr/bin/env bash
#
# Cross-compile filer-crypto-uniffi to the iOS targets, assemble an
# XCFramework, zip it, and emit a sha256. Output ends up under build/.
#
# This script is macOS-only — lipo + xcodebuild are not available
# elsewhere. Release CI runs on macos-latest; local dev needs Xcode + the
# three Rust iOS targets installed.
#
set -euo pipefail

if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "build-xcframework.sh requires macOS (xcodebuild + lipo)" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/build"
SIM_UNIVERSAL_DIR="$BUILD_DIR/ios-sim-universal"
HEADERS_DIR="$BUILD_DIR/headers"
XCFRAMEWORK="$BUILD_DIR/FilerCryptoFFI.xcframework"
XCFRAMEWORK_ZIP="$BUILD_DIR/FilerCryptoFFI.xcframework.zip"

# Clean previous output so stale slices can't contaminate the new framework.
rm -rf "$BUILD_DIR"
mkdir -p "$SIM_UNIVERSAL_DIR" "$HEADERS_DIR"

echo "→ Installing iOS Rust targets if missing..."
rustup target add \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    x86_64-apple-ios

echo "→ Building for aarch64-apple-ios (device)..."
cargo build --release --target aarch64-apple-ios --package filer-crypto-uniffi

echo "→ Building for aarch64-apple-ios-sim (Apple Silicon simulator)..."
cargo build --release --target aarch64-apple-ios-sim --package filer-crypto-uniffi

echo "→ Building for x86_64-apple-ios (Intel simulator)..."
cargo build --release --target x86_64-apple-ios --package filer-crypto-uniffi

echo "→ lipo simulator slices into a universal archive..."
lipo -create \
    "$ROOT/target/aarch64-apple-ios-sim/release/libfiler_crypto.a" \
    "$ROOT/target/x86_64-apple-ios/release/libfiler_crypto.a" \
    -output "$SIM_UNIVERSAL_DIR/libfiler_crypto.a"

# Sanity check: both archs must be present.
if ! lipo -info "$SIM_UNIVERSAL_DIR/libfiler_crypto.a" | grep -q "arm64 x86_64"; then
    echo "ERROR: simulator universal slice missing an arch:" >&2
    lipo -info "$SIM_UNIVERSAL_DIR/libfiler_crypto.a" >&2
    exit 3
fi

echo "→ Staging C header + modulemap..."
cp "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.h"        "$HEADERS_DIR/filer_cryptoFFI.h"
cp "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.modulemap" "$HEADERS_DIR/module.modulemap"

echo "→ Bindings drift check..."
# Regenerate bindings into a temp dir and diff against committed.
TMP_BINDINGS="$(mktemp -d)"
trap 'rm -rf "$TMP_BINDINGS"' EXIT
# Use the device staticlib as the input library for bindgen (any slice works;
# they all carry the same UDL-generated metadata).
cargo run --quiet --package filer-crypto-uniffi --bin uniffi-bindgen -- \
    generate \
    --library \
    --language swift \
    --out-dir "$TMP_BINDINGS" \
    "$ROOT/target/aarch64-apple-ios/release/libfiler_crypto.a"

if ! diff -q "$TMP_BINDINGS/FilerCrypto.swift"        "$ROOT/Sources/FilerCrypto/FilerCrypto.swift" \
  || ! diff -q "$TMP_BINDINGS/filer_cryptoFFI.h"      "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.h" \
  || ! diff -q "$TMP_BINDINGS/filer_cryptoFFI.modulemap" "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.modulemap"; then
    echo "ERROR: committed Swift bindings differ from what current Rust source would generate." >&2
    echo "Run ./scripts/build.sh and commit the regenerated files." >&2
    exit 4
fi

echo "→ Assembling XCFramework..."
xcodebuild -create-xcframework \
    -library "$ROOT/target/aarch64-apple-ios/release/libfiler_crypto.a" -headers "$HEADERS_DIR" \
    -library "$SIM_UNIVERSAL_DIR/libfiler_crypto.a"                    -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK"

echo "→ Zipping XCFramework..."
( cd "$BUILD_DIR" && zip -qr "FilerCryptoFFI.xcframework.zip" "FilerCryptoFFI.xcframework" )

SHA256="$(shasum -a 256 "$XCFRAMEWORK_ZIP" | awk '{print $1}')"

echo
echo "✓ XCFramework built."
echo "  Path:     $XCFRAMEWORK_ZIP"
echo "  sha256:   $SHA256"
```

- [ ] **Step 2: Create `scripts/release-notes.sh`**

```bash
#!/usr/bin/env bash
#
# Emit the GitHub Release body for a filer-crypto tag.
#
# Usage: ./scripts/release-notes.sh <sha256>
#
# Reads $GITHUB_REF_NAME from the environment (set by GitHub Actions
# on tag pushes); falls back to `git describe` for manual invocation.
#
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <sha256>" >&2
    exit 2
fi

SHA256="$1"
TAG="${GITHUB_REF_NAME:-$(git describe --tags --abbrev=0 2>/dev/null || echo "vX.Y.Z")}"

cat <<EOF
## filer-crypto $TAG

Pre-built XCFramework for iOS device + simulator.

### Consume via Swift Package Manager

\`\`\`swift
.binaryTarget(
    name: "FilerCryptoFFI",
    url: "https://github.com/CorvidSoft/filer-crypto/releases/download/$TAG/FilerCryptoFFI.xcframework.zip",
    checksum: "$SHA256"
)
\`\`\`

### Artifact

- \`FilerCryptoFFI.xcframework.zip\`
- sha256: \`$SHA256\`

See [\`docs/VERSIONING.md\`](https://github.com/CorvidSoft/filer-crypto/blob/main/docs/VERSIONING.md) for the semver policy.
EOF
```

- [ ] **Step 3: Make both scripts executable**

```bash
chmod +x scripts/build-xcframework.sh scripts/release-notes.sh
```

- [ ] **Step 4: Verify `release-notes.sh` formats correctly**

Run: `./scripts/release-notes.sh deadbeef | head -20`
Expected: prints a markdown body containing `checksum: "deadbeef"`.

Run: `./scripts/release-notes.sh deadbeef | grep -q 'checksum: "deadbeef"' && echo OK`
Expected: prints `OK`.

- [ ] **Step 5: Verify `build-xcframework.sh` runs to completion (macOS only)**

Run: `./scripts/build-xcframework.sh`
Expected: exits 0, prints final sha256 line. May take several minutes on first run (downloads rustup targets).

Run: `test -f build/FilerCryptoFFI.xcframework.zip && lipo -info build/ios-sim-universal/libfiler_crypto.a`
Expected: zip exists, `lipo -info` reports `arm64 x86_64` for the simulator slice.

Run: `ls build/FilerCryptoFFI.xcframework/`
Expected: `Info.plist`, `ios-arm64/`, `ios-arm64_x86_64-simulator/`.

If on non-macOS, this step is deferred to the release CI run in Task 3.

- [ ] **Step 6: Add `build/` to `.gitignore`**

Edit `.gitignore` to add `build/` so the generated XCFramework + zip are not committed.

```bash
grep -qxF 'build/' .gitignore || echo 'build/' >> .gitignore
```

- [ ] **Step 7: Commit**

```bash
git add scripts/build-xcframework.sh scripts/release-notes.sh .gitignore
git commit -m "feat(scripts): add build-xcframework.sh and release-notes.sh

Cross-compiles filer-crypto-uniffi to ios-arm64, ios-arm64-sim, and
ios-x86_64-sim, lipos the simulator slices into a universal archive,
and assembles a FilerCryptoFFI.xcframework with the C header and
modulemap. release-notes.sh emits the GitHub Release body with the
.binaryTarget snippet pre-filled.

Includes a bindings-drift guard: if the freshly generated Swift
bindings differ from what is committed in Sources/FilerCrypto/, the
script aborts before producing the XCFramework."
```

---

## Task 3: Release CI workflow

**Goal:** Tag-triggered workflow that invokes `build-xcframework.sh`, validates the tag matches the workspace version, and creates a GitHub Release with the XCFramework artifact.

**Files:**
- Create: `.github/workflows/release.yml`

**Acceptance Criteria:**
- [ ] Workflow triggers on `push.tags: ['v*']`
- [ ] Runs on `macos-latest`
- [ ] Has `contents: write` permission for `gh release create`
- [ ] Validates that the tag (stripped of leading `v`) matches `Cargo.toml` workspace version; fails the workflow if they differ
- [ ] Invokes `./scripts/build-xcframework.sh`
- [ ] Computes the sha256 and exports it as a step output
- [ ] Creates a GitHub Release with the XCFramework zip as an asset and the body from `release-notes.sh`
- [ ] `actionlint` or `yamllint` reports no errors

**Verify:**
- `yamllint .github/workflows/release.yml` → no errors (install via `pip install yamllint` if needed)
- The workflow does not actually run during this task — it triggers on tag push, which is Task 8's job.

**Steps:**

- [ ] **Step 1: Create `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

jobs:
  release:
    runs-on: macos-latest
    timeout-minutes: 30
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Add iOS Rust targets
        run: rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

      - name: Verify tag matches workspace version
        run: |
          tag="${GITHUB_REF_NAME#v}"
          # Allow -rcN suffix on the tag, matched against the base workspace version.
          tag_base="${tag%-rc*}"
          ws=$(awk -F'"' '/^version =/ {print $2; exit}' Cargo.toml)
          if [ "$tag_base" != "$ws" ]; then
              echo "Tag $GITHUB_REF_NAME (base $tag_base) != workspace version $ws" >&2
              exit 1
          fi

      - name: Build XCFramework
        run: ./scripts/build-xcframework.sh

      - name: Compute checksum
        id: sum
        run: |
          sha=$(shasum -a 256 build/FilerCryptoFFI.xcframework.zip | awk '{print $1}')
          echo "sha256=$sha" >> "$GITHUB_OUTPUT"
          echo "Computed sha256: $sha"

      - name: Create release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create "$GITHUB_REF_NAME" \
              build/FilerCryptoFFI.xcframework.zip \
              --title "$GITHUB_REF_NAME" \
              --notes "$(./scripts/release-notes.sh ${{ steps.sum.outputs.sha256 }})"
```

- [ ] **Step 2: Validate YAML**

Run: `yamllint .github/workflows/release.yml`
Expected: no errors. If `yamllint` is not installed, alternative: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` should exit 0.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow for tag-triggered XCFramework publication

On v* tag push, the workflow:
1. Verifies the tag matches Cargo.toml workspace version (allowing -rcN
   suffix on top of the base version).
2. Cross-compiles via ./scripts/build-xcframework.sh.
3. Computes the artifact sha256.
4. Creates a GitHub Release with the XCFramework zip and a release body
   containing the .binaryTarget snippet pre-filled."
```

---

## Task 4: Golden fixture generator + checked-in fixtures

**Goal:** A `#[ignore]`-gated Rust test in `crates/filer-crypto/tests/generate_fixtures.rs` produces `Tests/FilerCryptoTests/Fixtures/{blob,metadata,signature}_v1.json` and a fixture-secret sentinel file. The committed JSON files are the wire-format goldens.

**Files:**
- Create: `crates/filer-crypto/tests/generate_fixtures.rs`
- Create: `Tests/FilerCryptoTests/Fixtures/README.md`
- Create: `Tests/FilerCryptoTests/Fixtures/blob_v1.json`
- Create: `Tests/FilerCryptoTests/Fixtures/metadata_v1.json`
- Create: `Tests/FilerCryptoTests/Fixtures/signature_v1.json`
- Modify: `crates/filer-crypto/Cargo.toml` — add `serde` + `serde_json` + `hex` as dev-dependencies (limited to test scope so the production dep tree is unchanged)

**Acceptance Criteria:**
- [ ] `cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture` exits 0 and writes the three JSON files
- [ ] Each JSON file is valid JSON with hex-encoded byte fields
- [ ] `signature_v1.json` is deterministic across regenerations (ed25519 is deterministic for a fixed key+nonce); blob and metadata fixtures vary across runs but always round-trip
- [ ] Running normal `cargo test --workspace` does NOT regenerate the fixtures (they are `#[ignore]`)
- [ ] `Tests/FilerCryptoTests/Fixtures/README.md` documents the all-zero master secret sentinel, that fixtures are committed for the Swift parity tests, and the exact regeneration command

**Verify:**
- `cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture` → exits 0, writes three JSON files into `Tests/FilerCryptoTests/Fixtures/`
- `python3 -c "import json; json.load(open('Tests/FilerCryptoTests/Fixtures/blob_v1.json'))"` → exits 0
- `cargo test --workspace` → 38 tests still pass, no fixture regeneration

**Steps:**

- [ ] **Step 1: Add dev-dependencies to `crates/filer-crypto/Cargo.toml`**

Find the `[dev-dependencies]` section (or create one if absent) and add:

```toml
[dev-dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
```

These are dev-only — they do NOT enter the production dep tree consumed by the Filer iOS app via the UDL. CLAUDE.md invariant #6 (MIT-compatible deps) is satisfied: serde / serde_json / hex are MIT-OR-Apache-2.0.

Per CLAUDE.md invariant #10, run `cargo search serde serde_json hex` to confirm you're picking the current latest. Update the version numbers above to whatever is current at implementation time if they have moved past the values shown.

- [ ] **Step 2: Create `crates/filer-crypto/tests/generate_fixtures.rs`**

```rust
//! Cross-language test-fixture generator.
//!
//! Produces the JSON files in `Tests/FilerCryptoTests/Fixtures/` that the
//! Swift parity tests decrypt and verify. Run with:
//!
//!     cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture
//!
//! Uses an all-zero master secret — the standard "obvious test vector"
//! sentinel. Never use this secret for real keys.
//!
//! Blob / metadata fixtures use random IVs and per-blob data keys, so
//! they will differ byte-for-byte across regenerations. That's fine —
//! the property they encode is "Rust-produced envelope decrypts in
//! Swift", not "byte-identical regeneration." If the wire format ever
//! changes, the OLD committed bytes fail to decrypt and the parity test
//! suite goes red.
//!
//! The signature fixture IS byte-identical across runs because ed25519
//! is deterministic given the same key + nonce.

use std::fs;
use std::path::{Path, PathBuf};

use filer_crypto::{auth, recovery, Vault};
use serde::Serialize;

const FIXTURE_MASTER_SECRET: [u8; 32] = [0u8; 32];

#[derive(Serialize)]
struct BlobFixture {
    note: &'static str,
    plaintext_hex: String,
    blob: BlobBytes,
}

#[derive(Serialize)]
struct BlobBytes {
    ciphertext_hex: String,
    iv_hex: String,
    wrapped_key_hex: String,
}

#[derive(Serialize)]
struct MetadataFixture {
    note: &'static str,
    plaintext_hex: String,
    field: FieldBytes,
}

#[derive(Serialize)]
struct FieldBytes {
    ciphertext_hex: String,
    iv_hex: String,
}

#[derive(Serialize)]
struct SignatureFixture {
    note: &'static str,
    nonce_hex: String,
    public_key_hex: String,
    signature_hex: String,
}

fn fixtures_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/filer-crypto/. Walk up two levels to repo root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Tests")
        .join("FilerCryptoTests")
        .join("Fixtures")
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) {
    let json = serde_json::to_string_pretty(value).expect("serialize");
    fs::write(&path, json + "\n").expect("write fixture");
    eprintln!("wrote {}", path.display());
}

#[test]
#[ignore = "regenerate with: cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture"]
fn regenerate_fixtures() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("mkdir fixtures");

    let vault = Vault::open(&FIXTURE_MASTER_SECRET).expect("open vault");

    // --- Blob fixture ---
    let blob_plaintext = b"filer-crypto v1 blob fixture".to_vec();
    let blob = vault.encrypt_blob(&blob_plaintext).expect("encrypt blob");
    // Round-trip check before we commit the bytes.
    let recovered = vault.decrypt_blob(&blob).expect("decrypt blob");
    assert_eq!(recovered, blob_plaintext);
    write_json(
        dir.join("blob_v1.json"),
        &BlobFixture {
            note: "Rust-produced golden. Decrypt with master_secret = [0u8; 32].",
            plaintext_hex: hex::encode(&blob_plaintext),
            blob: BlobBytes {
                ciphertext_hex: hex::encode(&blob.ciphertext),
                iv_hex: hex::encode(blob.iv),
                wrapped_key_hex: hex::encode(&blob.wrapped_key),
            },
        },
    );

    // --- Metadata field fixture ---
    let field_plaintext = b"filer-crypto v1 metadata fixture".to_vec();
    let field = vault
        .encrypt_metadata_field(&field_plaintext)
        .expect("encrypt metadata");
    let recovered = vault
        .decrypt_metadata_field(&field)
        .expect("decrypt metadata");
    assert_eq!(recovered, field_plaintext);
    write_json(
        dir.join("metadata_v1.json"),
        &MetadataFixture {
            note: "Rust-produced golden. Decrypt with master_secret = [0u8; 32].",
            plaintext_hex: hex::encode(&field_plaintext),
            field: FieldBytes {
                ciphertext_hex: hex::encode(&field.ciphertext),
                iv_hex: hex::encode(field.iv),
            },
        },
    );

    // --- Signature fixture ---
    let nonce = [0u8; 32];
    let signature = vault.sign_challenge(&nonce);
    let public_key = vault.device_public_key();
    auth::verify_signature(&public_key, &nonce, &signature).expect("verify own signature");
    write_json(
        dir.join("signature_v1.json"),
        &SignatureFixture {
            note: "Rust-produced golden. Ed25519 is deterministic given key+nonce.",
            nonce_hex: hex::encode(nonce),
            public_key_hex: hex::encode(public_key),
            signature_hex: hex::encode(signature.bytes),
        },
    );

    // Sanity: BIP39 round-trip from the fixture secret (used in
    // RecoveryPhraseTests on the Swift side as a known-answer check).
    let phrase = recovery::secret_to_phrase(&FIXTURE_MASTER_SECRET).expect("to phrase");
    let back = recovery::phrase_to_secret(&phrase).expect("from phrase");
    assert_eq!(back, FIXTURE_MASTER_SECRET);
    eprintln!("BIP39 phrase for [0u8; 32]: {phrase}");
}
```

Note: this assumes:
- `filer_crypto::Vault::encrypt_blob` takes `&[u8]` and returns `Result<EncryptedBlob, _>`. Confirm against `crates/filer-crypto/src/vault.rs`.
- `filer_crypto::auth::verify_signature` is `pub`. Confirm against `crates/filer-crypto/src/auth.rs`; if it lives elsewhere (e.g. only re-exported through `lib.rs`), adjust the use path.
- `DeviceSignature` exposes `.bytes` as `[u8; 64]`. Confirm against `crates/filer-crypto/src/auth.rs`.

If any path doesn't compile, fix the use path; do not change the public API.

- [ ] **Step 3: Run the regenerator**

```bash
cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture
```

Expected output:
- `wrote .../Tests/FilerCryptoTests/Fixtures/blob_v1.json`
- `wrote .../Tests/FilerCryptoTests/Fixtures/metadata_v1.json`
- `wrote .../Tests/FilerCryptoTests/Fixtures/signature_v1.json`
- `BIP39 phrase for [0u8; 32]: <24-word phrase>`
- `test result: ok. 1 passed; 0 failed; 0 ignored; ...`

- [ ] **Step 4: Confirm the JSON parses**

```bash
python3 -c "import json; [json.load(open(f'Tests/FilerCryptoTests/Fixtures/{n}.json')) for n in ('blob_v1','metadata_v1','signature_v1')] and print('OK')"
```

Expected: prints `OK`.

- [ ] **Step 5: Confirm the existing workspace tests are unaffected**

```bash
cargo test --workspace
```

Expected: 38 tests pass (the `#[ignore]` generator does NOT run here).

- [ ] **Step 6: Create `Tests/FilerCryptoTests/Fixtures/README.md`**

```markdown
# Fixtures

Cross-language test vectors used by `CrossLanguageFixtureTests.swift` to
prove that a Rust-encrypted envelope decrypts correctly through the
Swift bindings.

## Sentinel secret

All fixtures are produced from the all-zero master secret
(`[0u8; 32]`). This is the standard "obvious test vector" sentinel.
**Never use this secret for real keys** — anything encrypted with it is
trivially decryptable by anyone.

The all-zero secret was chosen over a real-looking random one
specifically because a misleading file that *looks* sensitive but is
public would be worse than an obviously-test value.

## Regeneration

```sh
cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture
```

Regenerate fixtures only when:
- The Rust API surface that produces them changes (new fields, renames,
  envelope reshape).
- A test reveals an existing fixture is wrong (which is itself a wire-
  format break — see `docs/VERSIONING.md`).

Regeneration produces NEW random IVs and per-blob keys for the blob /
metadata fixtures, so the bytes change every run. The signature fixture
is byte-identical across runs (ed25519 is deterministic).

After regenerating, commit the updated JSON files. If they fail to
decrypt in Swift after a code change, that's a wire-format break (a
MAJOR per `docs/VERSIONING.md`).
```

- [ ] **Step 7: Commit**

```bash
git add crates/filer-crypto/Cargo.toml \
        crates/filer-crypto/tests/generate_fixtures.rs \
        Tests/FilerCryptoTests/Fixtures/README.md \
        Tests/FilerCryptoTests/Fixtures/blob_v1.json \
        Tests/FilerCryptoTests/Fixtures/metadata_v1.json \
        Tests/FilerCryptoTests/Fixtures/signature_v1.json

git commit -m "test(fixtures): add golden cross-language test vectors

Adds an #[ignore]-gated regenerator in crates/filer-crypto/tests/ that
writes Rust-produced envelopes to Tests/FilerCryptoTests/Fixtures/.

The fixtures pin the wire format: if the AEAD construction, HKDF
context strings, envelope layout, or signing curve ever change, the
committed bytes will fail to decrypt and the Swift parity tests go red.

Uses an all-zero master secret (the standard sentinel) so the fixture
file is obviously a test vector and not real key material."
```

---

## Task 5: Package.swift dual-mode with local-link wiring

**Goal:** `Package.swift` resolves into a local-link mode under `FILER_CRYPTO_LOCAL=1` (which Task 7's CI job uses) and a `.binaryTarget` mode otherwise. The binary URL/checksum start as placeholders (`<X.Y.Z>` / `<sha256>`) and are filled in during Task 8 when the first release is cut.

**Files:**
- Modify: `Package.swift`

**Acceptance Criteria:**
- [ ] `FILER_CRYPTO_LOCAL=1 swift package describe` exits 0 and lists `FilerCrypto` as a library product
- [ ] `FILER_CRYPTO_LOCAL=1 swift build` succeeds after running `./scripts/build.sh debug` (linkage works)
- [ ] `swift package describe` (no env var) parses successfully even though the `.binaryTarget` URL is a placeholder (SPM only fetches the binary target on actual build/test, not on `describe`)
- [ ] The placeholder URL contains `<X.Y.Z>` and the placeholder checksum is the literal string `0000000000000000000000000000000000000000000000000000000000000000`
- [ ] Existing `Tests/FilerCryptoTests/FilerCryptoTests.swift` still parses (no Swift changes required yet — Task 6 replaces it)

**Verify:**
- `FILER_CRYPTO_LOCAL=1 swift package describe | grep -q FilerCrypto` → exits 0
- After `./scripts/build.sh debug`: `FILER_CRYPTO_LOCAL=1 swift build 2>&1 | tail -5` → "Build complete!" (no linker errors)
- `swift package describe` → exits 0

**Steps:**

- [ ] **Step 1: Replace `Package.swift` with the dual-mode form**

```swift
// swift-tools-version:5.9
//
// Dual-mode Package manifest.
//
// Default: consume the pre-built XCFramework from the GitHub Release of
// the tag whose URL is baked in below. The release pipeline (see
// .github/workflows/release.yml) builds the XCFramework on every v*
// tag push.
//
// Local-dev mode: set FILER_CRYPTO_LOCAL=1 before any swift command.
// In this mode, FilerCrypto links against the staticlib produced by
// ./scripts/build.sh (target/{debug,release}/libfiler_crypto.a). The
// profile can be overridden via FILER_CRYPTO_LOCAL_PROFILE; default is
// "debug" because CI uses debug for fast iteration.
//
// Run scripts/build.sh first if you're in local mode — the manifest
// does not invoke cargo on its own.
//
// Why a staticlib not a dylib: linking the .a avoids dyld runtime
// resolution at swift-test time (no @rpath or DYLD_LIBRARY_PATH
// dance). The filer-crypto-uniffi crate declares both crate-types,
// so build.sh produces both.

import PackageDescription
import Foundation

let local = ProcessInfo.processInfo.environment["FILER_CRYPTO_LOCAL"] == "1"
let localProfile = ProcessInfo.processInfo.environment["FILER_CRYPTO_LOCAL_PROFILE"] ?? "debug"

let targets: [Target] = local
    ? [
        .target(
            name: "FilerCrypto",
            path: "Sources/FilerCrypto",
            publicHeadersPath: ".",
            linkerSettings: [
                .unsafeFlags(["-L", "target/\(localProfile)"]),
                .linkedLibrary("filer_crypto"),
                // SecRandomCopyBytes via the getrandom crate on Apple platforms.
                .linkedFramework("Security"),
            ]
        ),
    ]
    : [
        .binaryTarget(
            name: "FilerCryptoFFI",
            // PLACEHOLDER — replaced on each release commit. See docs/VERSIONING.md
            // and the release procedure. The literal <X.Y.Z> here will fail to
            // download if anyone runs `swift build` without FILER_CRYPTO_LOCAL=1
            // before the first release is cut; that's expected.
            url: "https://github.com/CorvidSoft/filer-crypto/releases/download/v<X.Y.Z>/FilerCryptoFFI.xcframework.zip",
            checksum: "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        .target(
            name: "FilerCrypto",
            dependencies: ["FilerCryptoFFI"],
            path: "Sources/FilerCrypto",
            exclude: ["filer_cryptoFFI.h", "filer_cryptoFFI.modulemap"]
        ),
    ]

let package = Package(
    name: "FilerCrypto",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "FilerCrypto",
            targets: ["FilerCrypto"]
        ),
    ],
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

- [ ] **Step 2: Verify `swift package describe` parses in both modes**

```bash
swift package describe | head -20
```

Expected: prints package description showing `FilerCrypto` library and `FilerCryptoFFI` binary target. (The remote URL is not fetched here.)

```bash
FILER_CRYPTO_LOCAL=1 swift package describe | head -20
```

Expected: prints package description with `FilerCrypto` target only (no binary target).

- [ ] **Step 3: Verify local-mode linkage works**

```bash
./scripts/build.sh debug
```

Expected: builds the workspace and regenerates Sources/FilerCrypto/FilerCrypto.swift (idempotent here — should already match committed).

```bash
FILER_CRYPTO_LOCAL=1 swift build 2>&1 | tail -20
```

Expected: ends with `Build complete!`. If the link step fails with `Undefined symbols ... _SecRandomCopyBytes`, that confirms the `Security` framework dependency is needed (already declared in the manifest).

If the build instead fails with unresolved symbols from other RustCrypto deps, run `nm target/debug/libfiler_crypto.a | grep " U " | sort -u | head` to see what's referenced; the manifest may need additional `.linkedFramework` entries (e.g. `CryptoKit`, `CoreFoundation`) — add them.

- [ ] **Step 4: Confirm the existing test target still compiles (placeholder XCTSkip is fine)**

```bash
FILER_CRYPTO_LOCAL=1 swift test --skip-build 2>&1 | head -10
```

If this fails with "test bundle has not been built yet" or similar — that's expected; the next step builds.

```bash
FILER_CRYPTO_LOCAL=1 swift test 2>&1 | tail -20
```

Expected: `testPlaceholder` either passes or skips (the existing `XCTSkip("FFI library not yet linked...")` may or may not still fire depending on conditional compilation; either is acceptable here since Task 6 deletes this file).

- [ ] **Step 5: Commit**

```bash
git add Package.swift
git commit -m "feat(spm): Package.swift dual-mode (FILER_CRYPTO_LOCAL + .binaryTarget)

Default mode points at a GitHub Release XCFramework via .binaryTarget;
URL and checksum are placeholders until v0.0.2-rc1 is cut.

FILER_CRYPTO_LOCAL=1 switches to a source-Swift target that links
against the staticlib produced by ./scripts/build.sh, with explicit
linker settings (-L target/<profile>, -lfiler_crypto, -framework Security).
This is the mode the macOS swift-tests CI job uses, and the only mode
in which 'swift test' can pass before the first release exists."
```

---

## Task 6: Real Swift parity tests

**Goal:** Replace the `XCTSkip` placeholder with five real test files that exercise blob / metadata / signing / recovery round-trips and verify the Rust-produced golden fixtures decrypt correctly through the Swift bindings.

**Files:**
- Delete: `Tests/FilerCryptoTests/FilerCryptoTests.swift`
- Create: `Tests/FilerCryptoTests/BlobRoundTripTests.swift`
- Create: `Tests/FilerCryptoTests/MetadataFieldRoundTripTests.swift`
- Create: `Tests/FilerCryptoTests/SigningTests.swift`
- Create: `Tests/FilerCryptoTests/RecoveryPhraseTests.swift`
- Create: `Tests/FilerCryptoTests/CrossLanguageFixtureTests.swift`

**Acceptance Criteria:**
- [ ] After `./scripts/build.sh debug`, `FILER_CRYPTO_LOCAL=1 swift test` exits 0
- [ ] Each test file contains at least one happy-path test
- [ ] BlobRoundTripTests, MetadataFieldRoundTripTests, SigningTests each include a negative test (tamper / wrong-key / bad-input) that asserts the correct `FilerCryptoError` variant is thrown
- [ ] CrossLanguageFixtureTests successfully decrypts all three committed JSON fixtures
- [ ] RecoveryPhraseTests includes the known-answer check: the BIP39 phrase for `[0u8; 32]` round-trips back to `[0u8; 32]`

**Verify:** `FILER_CRYPTO_LOCAL=1 swift test 2>&1 | tail -15` → "Test Suite ... passed" with all expected test counts; `grep -c testTampered Tests/FilerCryptoTests/*.swift` ≥ 3.

**Steps:**

- [ ] **Step 1: Delete the placeholder test file**

```bash
git rm Tests/FilerCryptoTests/FilerCryptoTests.swift
```

- [ ] **Step 2: Create `Tests/FilerCryptoTests/BlobRoundTripTests.swift`**

```swift
import XCTest
@testable import FilerCrypto

final class BlobRoundTripTests: XCTestCase {
    private func freshVault(secret seed: UInt8 = 0x42) throws -> Vault {
        return try Vault.open(masterSecret: Array(repeating: seed, count: 32))
    }

    func testRoundTripSmallPayload() throws {
        let vault = try freshVault()
        let plaintext = Array("hello filer".utf8)
        let blob = try vault.encryptBlob(plaintext: plaintext)
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripEmptyPayload() throws {
        let vault = try freshVault()
        let blob = try vault.encryptBlob(plaintext: [])
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, [])
    }

    func testRoundTripLargePayload() throws {
        let vault = try freshVault()
        let plaintext = (UInt8(0)...UInt8(255)).flatMap { byte -> [UInt8] in
            Array(repeating: byte, count: 1024)
        }
        XCTAssertEqual(plaintext.count, 256 * 1024)
        let blob = try vault.encryptBlob(plaintext: plaintext)
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, plaintext)
    }

    func testTamperedCiphertextFailsAead() throws {
        let vault = try freshVault()
        let plaintext = Array("hello filer".utf8)
        var blob = try vault.encryptBlob(plaintext: plaintext)
        XCTAssertGreaterThan(blob.ciphertext.count, 0)
        blob.ciphertext[0] ^= 0x01    // flip one bit
        XCTAssertThrowsError(try vault.decryptBlob(blob: blob)) { err in
            XCTAssertEqual(err as? FilerCryptoError, .Aead)
        }
    }

    func testDecryptUnderWrongMasterSecretFails() throws {
        let vault42 = try freshVault(secret: 0x42)
        let blob = try vault42.encryptBlob(plaintext: Array("hello".utf8))
        let vault00 = try freshVault(secret: 0x00)
        XCTAssertThrowsError(try vault00.decryptBlob(blob: blob)) { err in
            XCTAssertEqual(err as? FilerCryptoError, .Aead)
        }
    }
}
```

- [ ] **Step 3: Create `Tests/FilerCryptoTests/MetadataFieldRoundTripTests.swift`**

```swift
import XCTest
@testable import FilerCrypto

final class MetadataFieldRoundTripTests: XCTestCase {
    private func freshVault() throws -> Vault {
        return try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
    }

    func testRoundTrip() throws {
        let vault = try freshVault()
        let plaintext = Array("Project Plan 2026".utf8)
        let field = try vault.encryptMetadataField(plaintext: plaintext)
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripUnicode() throws {
        let vault = try freshVault()
        let plaintext = Array("こんにちは 🌸 filer".utf8)
        let field = try vault.encryptMetadataField(plaintext: plaintext)
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, plaintext)
    }

    func testTamperedIvFails() throws {
        let vault = try freshVault()
        var field = try vault.encryptMetadataField(plaintext: Array("secret".utf8))
        XCTAssertEqual(field.iv.count, 12)
        field.iv[0] ^= 0xFF
        XCTAssertThrowsError(try vault.decryptMetadataField(field: field)) { err in
            XCTAssertEqual(err as? FilerCryptoError, .Aead)
        }
    }
}
```

- [ ] **Step 4: Create `Tests/FilerCryptoTests/SigningTests.swift`**

```swift
import XCTest
@testable import FilerCrypto

final class SigningTests: XCTestCase {
    func testSignVerifyRoundTrip() throws {
        let vault = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let nonce = Array("challenge-nonce".utf8)
        let signature = vault.signChallenge(nonce: nonce)
        let publicKey = vault.devicePublicKey()
        XCTAssertNoThrow(try verifySignature(publicKey: publicKey, nonce: nonce, signature: signature.bytes))
    }

    func testVerifyWithWrongNonceFails() throws {
        let vault = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let signature = vault.signChallenge(nonce: Array("nonce-a".utf8))
        let publicKey = vault.devicePublicKey()
        XCTAssertThrowsError(
            try verifySignature(publicKey: publicKey, nonce: Array("nonce-b".utf8), signature: signature.bytes)
        ) { err in
            XCTAssertEqual(err as? FilerCryptoError, .InvalidSignature)
        }
    }

    func testVerifyWithWrongPublicKeyFails() throws {
        let vaultA = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let vaultB = try Vault.open(masterSecret: Array(repeating: 0x00, count: 32))
        let nonce = Array("challenge".utf8)
        let signatureA = vaultA.signChallenge(nonce: nonce)
        let publicKeyB = vaultB.devicePublicKey()
        XCTAssertThrowsError(
            try verifySignature(publicKey: publicKeyB, nonce: nonce, signature: signatureA.bytes)
        ) { err in
            XCTAssertEqual(err as? FilerCryptoError, .InvalidSignature)
        }
    }

    func testDevicePublicKeyIsStableForSameSecret() throws {
        let v1 = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let v2 = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        XCTAssertEqual(v1.devicePublicKey(), v2.devicePublicKey())
    }
}
```

- [ ] **Step 5: Create `Tests/FilerCryptoTests/RecoveryPhraseTests.swift`**

```swift
import XCTest
@testable import FilerCrypto

final class RecoveryPhraseTests: XCTestCase {
    func testGenerateMasterSecretIs32Bytes() throws {
        let secret = try generateMasterSecret()
        XCTAssertEqual(secret.count, 32)
    }

    func testGenerateMasterSecretIsRandom() throws {
        let a = try generateMasterSecret()
        let b = try generateMasterSecret()
        XCTAssertNotEqual(a, b, "two random secrets should differ")
    }

    func testRoundTripPhrase() throws {
        let secret = try generateMasterSecret()
        let phrase = try secretToPhrase(secret: secret)
        let back = try phraseToSecret(phrase: phrase)
        XCTAssertEqual(back, secret)
    }

    func testPhraseIs24Words() throws {
        let secret = try generateMasterSecret()
        let phrase = try secretToPhrase(secret: secret)
        XCTAssertEqual(phrase.split(separator: " ").count, 24)
    }

    /// Known-answer: the BIP39 phrase for the all-zero secret is the same
    /// canonical phrase ("abandon abandon abandon ... art") regardless of
    /// language binding. This pins the wordlist used by the bip39 crate
    /// against accidental change.
    func testZeroSecretKnownAnswer() throws {
        let zero = Array<UInt8>(repeating: 0, count: 32)
        let phrase = try secretToPhrase(secret: zero)
        XCTAssertTrue(phrase.starts(with: "abandon abandon abandon"))
        XCTAssertTrue(phrase.hasSuffix("art"))
        let back = try phraseToSecret(phrase: phrase)
        XCTAssertEqual(back, zero)
    }

    func testInvalidPhraseRejected() throws {
        XCTAssertThrowsError(try phraseToSecret(phrase: "not a real bip39 phrase at all")) { err in
            XCTAssertEqual(err as? FilerCryptoError, .InvalidPhrase)
        }
    }
}
```

- [ ] **Step 6: Create `Tests/FilerCryptoTests/CrossLanguageFixtureTests.swift`**

```swift
import XCTest
@testable import FilerCrypto

/// Decrypts the Rust-produced golden fixtures committed in Fixtures/.
/// These pin the wire format: any change to AEAD / HKDF / envelope
/// layout / signing curve will make these fail. See docs/VERSIONING.md.
final class CrossLanguageFixtureTests: XCTestCase {
    private static let fixtureMasterSecret: [UInt8] = Array(repeating: 0, count: 32)

    private func loadFixture(_ name: String) throws -> [String: Any] {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            XCTFail("fixture \(name).json not found in test bundle")
            return [:]
        }
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("fixture \(name).json is not a JSON object")
            return [:]
        }
        return obj
    }

    private func hexDecode(_ s: String) throws -> [UInt8] {
        precondition(s.count % 2 == 0, "hex string must have even length")
        var out: [UInt8] = []
        out.reserveCapacity(s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let byte = UInt8(s[idx..<next], radix: 16) else {
                throw NSError(domain: "hex", code: 1)
            }
            out.append(byte)
            idx = next
        }
        return out
    }

    func testBlobFixtureDecrypts() throws {
        let fixture = try loadFixture("blob_v1")
        let plaintext = try hexDecode(fixture["plaintext_hex"] as! String)
        let blobDict = fixture["blob"] as! [String: String]
        let blob = EncryptedBlob(
            ciphertext: try hexDecode(blobDict["ciphertext_hex"]!),
            iv: try hexDecode(blobDict["iv_hex"]!),
            wrappedKey: try hexDecode(blobDict["wrapped_key_hex"]!)
        )
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, plaintext)
    }

    func testMetadataFixtureDecrypts() throws {
        let fixture = try loadFixture("metadata_v1")
        let plaintext = try hexDecode(fixture["plaintext_hex"] as! String)
        let fieldDict = fixture["field"] as! [String: String]
        let field = EncryptedField(
            ciphertext: try hexDecode(fieldDict["ciphertext_hex"]!),
            iv: try hexDecode(fieldDict["iv_hex"]!)
        )
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, plaintext)
    }

    func testSignatureFixtureVerifies() throws {
        let fixture = try loadFixture("signature_v1")
        let nonce = try hexDecode(fixture["nonce_hex"] as! String)
        let publicKey = try hexDecode(fixture["public_key_hex"] as! String)
        let signature = try hexDecode(fixture["signature_hex"] as! String)
        XCTAssertNoThrow(try verifySignature(publicKey: publicKey, nonce: nonce, signature: signature))
    }
}
```

Note: the exact field names (`wrappedKey` vs. `wrapped_key`) follow UniFFI's camelCase convention. If the generated Swift uses different names, adjust the initializer arguments to match what's in `Sources/FilerCrypto/FilerCrypto.swift`. The `.copy("Fixtures")` resource declaration in `Package.swift` is what makes `Bundle.module.url(...)` resolve.

- [ ] **Step 7: Run the test suite**

First ensure the Rust lib is built fresh:

```bash
./scripts/build.sh debug
```

Then run the Swift tests:

```bash
FILER_CRYPTO_LOCAL=1 swift test 2>&1 | tail -30
```

Expected: all tests pass. Count: at least 5 test classes; ≥ 15 individual test methods total.

If the suite fails because `EncryptedBlob` or `EncryptedField` initializers have different signatures than expected, open `Sources/FilerCrypto/FilerCrypto.swift` and adjust the test initializer calls to match. Do NOT change the binding generator.

- [ ] **Step 8: Commit**

```bash
git add Tests/FilerCryptoTests/
git commit -m "test(swift): replace XCTSkip with real parity tests

Five XCTestCase files covering blob / metadata / signing / recovery
round-trips plus a CrossLanguageFixtureTests suite that decrypts the
Rust-produced golden JSON fixtures. Each round-trip file includes a
negative test (tamper or wrong-key) confirming FilerCryptoError
propagates correctly across the FFI boundary."
```

---

## Task 7: macOS `swift-tests` CI job

**Goal:** Add a parallel job to `.github/workflows/ci.yml` that runs `swift test` on `macos-latest` against the local-link mode of `Package.swift`. Also enforces bindings-drift detection at PR time.

**Files:**
- Modify: `.github/workflows/ci.yml`

**Acceptance Criteria:**
- [ ] `ci.yml` declares a `swift-tests` job in addition to the existing `test` job
- [ ] `swift-tests` runs on `macos-latest`
- [ ] Steps include: checkout, Rust toolchain, rust-cache, `./scripts/build.sh debug`, bindings drift `git diff` check, `FILER_CRYPTO_LOCAL=1 swift test`
- [ ] The bindings drift check fails the job if `Sources/FilerCrypto/` has uncommitted changes after `./scripts/build.sh`
- [ ] `yamllint .github/workflows/ci.yml` reports no errors
- [ ] After this lands, opening a PR triggers BOTH the Ubuntu `test` job and the macOS `swift-tests` job

**Verify:**
- `yamllint .github/workflows/ci.yml` → exits 0
- Open a draft PR (or push to a feature branch) and observe both `test` (ubuntu-latest) and `swift-tests` (macos-latest) jobs run to green

**Steps:**

- [ ] **Step 1: Modify `.github/workflows/ci.yml`**

Replace the file's `jobs:` block with the following (keeping `name`, `on`, and `concurrency` unchanged):

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - uses: Swatinem/rust-cache@v2

      - name: Format check
        run: cargo fmt --check

      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings

      - name: Test
        run: cargo test --workspace

  swift-tests:
    runs-on: macos-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Build native Rust dylib + regenerate bindings
        run: ./scripts/build.sh debug

      - name: Verify committed bindings are up to date
        run: |
          if ! git diff --exit-code \
                  Sources/FilerCrypto/FilerCrypto.swift \
                  Sources/FilerCrypto/filer_cryptoFFI.h \
                  Sources/FilerCrypto/filer_cryptoFFI.modulemap; then
              echo "::error::Committed Swift bindings are stale." >&2
              echo "Run ./scripts/build.sh and commit the regenerated files." >&2
              exit 1
          fi

      - name: Swift test (local-link mode)
        env:
          FILER_CRYPTO_LOCAL: "1"
        run: swift test
```

The existing `test` job is preserved unchanged; `swift-tests` runs in parallel.

- [ ] **Step 2: Lint the YAML**

```bash
yamllint .github/workflows/ci.yml
```

Expected: no errors.

If `yamllint` isn't installed:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('OK')"
```

Expected: prints `OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add macOS swift-tests job

Runs swift test on macos-latest against the FILER_CRYPTO_LOCAL=1 mode of
Package.swift, after building the native Rust dylib via scripts/build.sh.

Includes a bindings-drift guard: if Sources/FilerCrypto/ contents
diverge from what current Rust source would regenerate, the job fails
with a clear remediation message.

Runs in parallel with the existing ubuntu-latest cargo job; both gate
PR merges."
```

- [ ] **Step 4: Observe CI on a feature branch**

Open a small PR (or push the branch and trigger CI via `gh workflow run` if applicable). Confirm:
- The `test` job runs on Ubuntu and passes.
- The `swift-tests` job runs on macOS and passes.

If `swift-tests` fails because of a flake or a discovered gap, fix forward; do NOT merge red.

---

## Task 8: First releases — cut `v0.0.2-rc1` then `v0.1.0`

> **USER-ORDERED GATE — NON-SKIPPABLE.** This task was requested by the user in the current conversation. It MUST NOT be closed by walking around it, by declaring it "verified inline", or by substituting a cheaper check. Close only after every item in `acceptanceCriteria` has been re-validated independently, with output captured.

**Goal:** Cut the first XCFramework release on the new pipeline. The `-rc1` exists solely to learn the actual checksum; `v0.1.0` is the first real release that the Filer iOS app consumes via `.binaryTarget`.

This task is user-driven: it requires pushing tags, reviewing the published GitHub Release, and verifying that the closed-source Filer iOS app can consume the package. The agent cannot complete the final verification because the iOS app lives in a private sibling repo on the user's machine.

**Files:**
- Modify: `Cargo.toml` (workspace) — version bump
- Modify: `Package.swift` — substitute real URL + checksum into the `.binaryTarget` placeholders

**Acceptance Criteria:**
- [ ] `Cargo.toml` workspace version bumped to `0.0.2` for the rc1 tag
- [ ] `v0.0.2-rc1` tag exists on GitHub; `release.yml` workflow ran to completion; GitHub Release created with `FilerCryptoFFI.xcframework.zip` attached
- [ ] `Package.swift` updated with the rc1 URL (`v0.0.2-rc1`) and the actual sha256 returned by the rc1 release workflow
- [ ] `FILER_CRYPTO_LOCAL=1 swift test` still passes after the Package.swift update (local mode unchanged)
- [ ] In a scratch consumer project, adding `.package(url:, exact: "v0.0.2-rc1")` and `import FilerCrypto` builds successfully (this exercises the `.binaryTarget` branch with a real URL and checksum)
- [ ] `Cargo.toml` workspace version bumped to `0.1.0` and `Package.swift` URL updated to `v0.1.0`
- [ ] `v0.1.0` tag exists on GitHub; workflow ran; Release created; sha256 matches what's in `Package.swift`
- [ ] **End-to-end:** Filer iOS app (closed-source sibling repo) successfully resolves `https://github.com/CorvidSoft/filer-crypto.git` at `v0.1.0` and builds for a real iOS device (or simulator if no device available)

**Verify:**
- `gh release view v0.0.2-rc1 --json assets --jq '.assets[].name'` → contains `FilerCryptoFFI.xcframework.zip`
- `gh release view v0.0.2-rc1 --json body --jq '.body' | grep -o 'checksum: "[a-f0-9]*"'` → emits the rc1 checksum
- `gh release view v0.1.0 --json assets --jq '.assets[].name'` → contains `FilerCryptoFFI.xcframework.zip`
- `grep -o 'checksum: "[a-f0-9]*"' Package.swift` → matches the published v0.1.0 checksum
- Filer iOS app build log shows successful resolution of filer-crypto and successful link/build for an iOS target (manual verification by the user; capture the log line `Build complete!` or equivalent)

**Steps:**

- [ ] **Step 1: Bump workspace version to `0.0.2`**

Edit `Cargo.toml`:

```toml
[workspace.package]
# ...
version = "0.0.2"
```

Run `cargo build --workspace` to confirm nothing breaks. Run `cargo test --workspace` — all 38 tests + the fixture generator's `#[ignore]` test (which still doesn't run) should pass.

- [ ] **Step 2: Commit and tag `v0.0.2-rc1`**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: release v0.0.2-rc1 (learn-the-checksum dry run)"
git tag v0.0.2-rc1
git push origin main
git push origin v0.0.2-rc1
```

The push of `v0.0.2-rc1` triggers `.github/workflows/release.yml`.

- [ ] **Step 3: Wait for the release workflow to complete**

```bash
gh run watch  # interactive; or:
gh run list --workflow=release.yml --limit 1
```

Expected: the workflow completes with status `success`. If it fails, read the logs (`gh run view --log`) and fix the underlying issue. Common failure modes:
- Tag version mismatch (the awk check in release.yml) — should NOT happen since we just bumped Cargo.toml; if it does, check the regex.
- Missing iOS Rust target — release.yml installs them; if rustup fails, retry.
- Bindings drift detected — re-run `./scripts/build.sh` locally, commit the regenerated bindings, then delete the tag (`git push --delete origin v0.0.2-rc1`), retry.

- [ ] **Step 4: Read the published checksum**

```bash
gh release view v0.0.2-rc1 --json body --jq '.body' | grep -o 'checksum: "[a-f0-9]*"'
```

Capture the hex string (call it `RC1_SHA`).

- [ ] **Step 5: Update `Package.swift` with the rc1 URL + checksum**

Replace the placeholders in `Package.swift`:

```swift
.binaryTarget(
    name: "FilerCryptoFFI",
    url: "https://github.com/CorvidSoft/filer-crypto/releases/download/v0.0.2-rc1/FilerCryptoFFI.xcframework.zip",
    checksum: "<RC1_SHA>"
)
```

(Replace `<RC1_SHA>` with the actual hex from Step 4.)

- [ ] **Step 6: Verify binary-mode resolution in a scratch consumer**

In a temporary directory outside this repo:

```bash
mkdir /tmp/filer-crypto-smoke && cd /tmp/filer-crypto-smoke
cat > Package.swift <<'EOF'
// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "smoke",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.executable(name: "smoke", targets: ["smoke"])],
    dependencies: [
        .package(url: "https://github.com/CorvidSoft/filer-crypto.git", exact: "0.0.2-rc1"),
    ],
    targets: [
        .executableTarget(name: "smoke", dependencies: [.product(name: "FilerCrypto", package: "filer-crypto")])
    ]
)
EOF
mkdir -p Sources/smoke
cat > Sources/smoke/main.swift <<'EOF'
import FilerCrypto
let secret = try generateMasterSecret()
print("ok: \(secret.count) bytes")
EOF
swift build 2>&1 | tail
```

Expected: `Build complete!`. Run the executable: `.build/debug/smoke` → prints `ok: 32 bytes`.

If the checksum is wrong, SPM prints a clear "artifact ... does not match expected checksum" error. Fix `Package.swift` in the filer-crypto repo, commit, delete the rc1 tag + release, re-tag.

- [ ] **Step 7: Verify local mode still passes after the Package.swift edit**

Back in the filer-crypto repo:

```bash
./scripts/build.sh debug
FILER_CRYPTO_LOCAL=1 swift test 2>&1 | tail -10
```

Expected: all tests pass. The Package.swift edit only changed the `.binaryTarget` branch; the local branch is untouched.

- [ ] **Step 8: Commit the Package.swift checksum pin**

```bash
git add Package.swift
git commit -m "chore: pin Package.swift to v0.0.2-rc1 checksum

Empirical sha256 from the release.yml run on v0.0.2-rc1. The local-link
mode (FILER_CRYPTO_LOCAL=1) is unchanged."
git push origin main
```

- [ ] **Step 9: Bump to `0.1.0` and tag**

```bash
# Cargo.toml: workspace.package.version = "0.1.0"
# Package.swift: update url to v0.1.0; leave checksum at <RC1_SHA> for now
git add Cargo.toml Cargo.lock Package.swift
git commit -m "chore: release v0.1.0"
git tag v0.1.0
git push origin main
git push origin v0.1.0
```

Wait for `release.yml` to complete (same as Step 3). When it does, capture the v0.1.0 checksum (`V010_SHA`):

```bash
gh release view v0.1.0 --json body --jq '.body' | grep -o 'checksum: "[a-f0-9]*"'
```

If `V010_SHA` differs from `RC1_SHA`, update `Package.swift`'s checksum to `V010_SHA` and commit (`chore: pin v0.1.0 checksum`). RustCrypto builds on macos-latest should be deterministic enough that they often match, but a mismatch is also non-fatal — just push the corrected checksum.

- [ ] **Step 10: Re-run the scratch consumer against v0.1.0**

Same as Step 6 but with `exact: "0.1.0"`. Confirm `Build complete!` and `.build/debug/smoke` prints `ok: 32 bytes`.

- [ ] **Step 11: End-to-end verification against the closed-source Filer iOS app**

In the sibling Filer iOS app repo, update its SPM dependency on filer-crypto to `exact: "0.1.0"` and build for an iOS target. Capture the build log showing successful resolution and link.

```
filer iOS app:    swift build (or xcodebuild) → "Build succeeded"
filer-crypto:     Package.swift checksum matches v0.1.0 release sha256
```

If the iOS app fails to link (e.g. a missing system framework that's needed in `.binaryTarget` mode but not in local mode), open a fix-forward PR on filer-crypto: add the framework to the XCFramework's headers or as a `.linkedFramework` on the consuming target. Re-cut a `v0.1.1`.

```json:metadata
{"files": ["Cargo.toml", "Package.swift"], "verifyCommand": "gh release view v0.1.0 --json assets --jq '.assets[].name' | grep -q FilerCryptoFFI.xcframework.zip && gh release view v0.1.0 --json body --jq '.body' | grep -q checksum:", "acceptanceCriteria": ["v0.0.2-rc1 release published with XCFramework asset", "Package.swift pinned to v0.0.2-rc1 actual checksum", "scratch consumer builds against v0.0.2-rc1 via .binaryTarget", "v0.1.0 release published with XCFramework asset", "Package.swift pinned to v0.1.0 actual checksum", "Filer iOS app builds against v0.1.0 via SPM"], "userGate": true, "tags": ["user-gate"], "requireEvidenceTokens": [["v0.0.2-rc1", "rc1"], ["v0.1.0"], ["filer-ios", "consumer-build", "Build succeeded", "Build complete"]]}
```

---

## Spec self-review (post-plan)

Cross-checking the plan against `docs/superpowers/specs/2026-05-24-filer-crypto-distribution-design.md`:

| Spec section | Covered by |
|---|---|
| §2.1 in-scope item 1: build-xcframework.sh | Task 2 |
| §2.1 in-scope item 2: release.yml | Task 3 |
| §2.1 in-scope item 3: Package.swift dual-mode | Task 5 (placeholders) + Task 8 (real values) |
| §2.1 in-scope item 4: Swift parity tests + golden fixtures | Task 4 (fixtures) + Task 6 (tests) |
| §2.1 in-scope item 5: macOS swift-tests CI job | Task 7 |
| §2.1 in-scope item 6: docs/VERSIONING.md | Task 1 |
| §3.2 build pipeline (cross-compile, lipo, xcodebuild, drift check) | Task 2 Step 1 |
| §3.3 linker settings + Security framework | Task 5 Step 1 |
| §4.1 release workflow with version-skew guard | Task 3 Step 1 |
| §4.3 release procedure | Task 8 (executed) + Task 1 (documented) |
| §5.1-5.3 test layout and golden fixtures | Tasks 4 + 6 |
| §6 swift-tests job with bindings drift check | Task 7 |
| §7 VERSIONING.md structure | Task 1 |
| §8.1 "what done looks like" | Task 8 acceptance criteria |
| §8.3 rollout order | Task 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 |

No spec requirements without tasks. No placeholder-language ("TBD", "TODO") in the plan body. Type / method name consistency cross-checked between Tasks 4 and 6 (`encryptBlob` / `decryptBlob` / `signChallenge` / `devicePublicKey` match the UniFFI camelCase generated bindings; `FilerCryptoError.Aead` / `.InvalidSignature` / `.InvalidPhrase` variant names match the UDL enum).

---

## Out of scope reminder

These items in issue #3 are deferred per the issue text and the spec; do NOT add tasks for them in this plan:

- Android UniFFI bindings (Filer v2 milestone — separate sibling crate)
- `wasm-bindgen` bindings (post-launch — separate sibling crate)
- `proptest` round-trip property tests (first feature plan)
- `cargo-fuzz` harness (post-launch hardening)
- `subtle` crate re-add (when an actual `ConstantTimeEq` path appears)
- `ios.appleTeamId` (closed-source mobile repo)
