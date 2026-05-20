# filer-crypto Setup — Design

**Date:** 2026-05-20
**Status:** Approved, ready for plan
**Related:** [Filer DESIGN.md §4](https://github.com/CorvidSoft/filer/blob/main/docs/DESIGN.md) (closed-source sibling repo)

## 1. Goal

Stand up the `filer-crypto` Rust crate so the Filer iOS app can consume it via Swift Package Manager. Produce a runnable, tested crate with the v1 primitives in place — blob encryption, metadata field encryption, key derivation, recovery phrase, device challenge signing — and a Swift Package wrapper that the mobile app's `with-crypto-core` config plugin can pick up at `expo prebuild` time.

This spec covers **the crate's structure, public API shape, primitive implementations, and Swift Package wiring**. It is both the design contract for the API and the commitment to ship working primitives behind that API. Property tests, fuzzing, XCFramework distribution, and Android/Wasm bindings are explicitly out of scope (see §2 and §6).

## 2. Scope

### In scope

- Cargo workspace with two crates: `filer-crypto` (pure-Rust core) and `filer-crypto-uniffi` (UniFFI binding layer)
- Public API: a `Vault` object that owns derived keys + stateless free functions for recovery-phrase conversion
- Primitives:
  - AES-256-GCM blob encryption with per-blob random data keys wrapped by the master key
  - Field-level metadata encryption with the same envelope
  - HKDF-SHA256 key derivation from the master secret to subkeys
  - BIP39 24-word recovery phrase ↔ 32-byte master secret (24 words encode 256 bits — matches the 256-bit security baseline used elsewhere in the envelope)
  - Ed25519 device challenge-response signing
- UniFFI 0.29 binding crate (`cdylib` + `staticlib`) with a `.udl` interface
- `Package.swift` at repo root declaring a source-Swift target wrapping the generated bindings
- `Sources/FilerCrypto/FilerCrypto.swift` — the generated binding file, committed to the repo so consumers don't need `uniffi-bindgen` on their machines
- `scripts/build.sh` — regenerates bindings + builds the Rust libs
- GitHub Actions CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` on Linux
- A README that explains: what this crate is, what it's used for, how to build, where to file issues
- A `CLAUDE.md` at the repo root that gives a coding agent the hard invariants and conventions of this repo without re-reading the consumer (Filer) DESIGN.md every session

### Out of scope

- Pre-built XCFramework distribution + release pipeline (defer to the first `0.1.0` tag, when the mobile app needs a real device build)
- Android UniFFI bindings (Filer v2)
- wasm-bindgen for the future web companion (post-launch)
- macOS CI matrix for Swift parity testing (deferred with XCFramework)
- `proptest` round-trip property tests (first feature plan)
- Fuzzing (post-launch)
- Public-key cryptography for share packets (Filer v1.2)
- Re-encryption support for shared/family vaults (Filer v2)

## 3. Repository structure

```
filer-crypto/
├── Cargo.toml                          # workspace root
├── Cargo.lock
├── crates/
│   ├── filer-crypto/                   # pure Rust core (lib)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # re-exports + crate-level docs
│   │       ├── vault.rs                # Vault type: stateful API
│   │       ├── blob.rs                 # blob encryption helpers
│   │       ├── metadata.rs             # field-level metadata encryption
│   │       ├── kdf.rs                  # HKDF-SHA256
│   │       ├── auth.rs                 # Ed25519 device challenge signing
│   │       ├── recovery.rs             # BIP39 ↔ master secret (stateless)
│   │       └── error.rs                # FilerCryptoError enum
│   └── filer-crypto-uniffi/            # UniFFI binding crate (lib + cdylib + staticlib)
│       ├── Cargo.toml
│       ├── build.rs                    # uniffi build setup
│       ├── uniffi.toml
│       └── src/
│           ├── lib.rs                  # wraps core API in UniFFI types
│           └── filer_crypto.udl        # UDL interface definition
├── Package.swift                       # SPM manifest, source-Swift target
├── Sources/
│   └── FilerCrypto/
│       └── FilerCrypto.swift           # generated bindings (committed)
├── Tests/
│   └── FilerCryptoTests/
│       └── FilerCryptoTests.swift      # placeholder parity test
├── scripts/
│   ├── build.sh                        # cargo build + uniffi-bindgen swift
│   └── README.md                       # explains the script
├── .github/
│   └── workflows/
│       └── ci.yml                      # rustfmt + clippy + cargo test
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-05-20-filer-crypto-setup-design.md   # this file
├── CLAUDE.md                           # agent guide (this repo's conventions)
├── README.md                           # public-facing
├── LICENSE                             # MIT, already present
└── .gitignore                          # Rust-flavored, already present
```

## 4. Key design decisions

### 4.1 Two-crate workspace

`filer-crypto` contains the cryptography. It depends on the RustCrypto family + `bip39` + `ed25519-dalek` and has no FFI awareness. It can be audited as a stand-alone library and `cargo test`-ed without UniFFI involvement.

`filer-crypto-uniffi` depends on `filer-crypto` and exposes its API to Swift (and later Kotlin/Wasm) through UniFFI. This crate carries the `cdylib`/`staticlib` outputs and the UDL.

The split serves two goals: (a) the open-source crypto core stays a clean library — a trust signal per DESIGN.md §8 — and (b) future binding crates (Android, web) are additive, not invasive.

### 4.2 `Vault` is the only stateful public type

Construct via `Vault::open(master_secret: &[u8])` or `Vault::from_recovery_phrase(phrase: &str)`. On construction, the `Vault` runs HKDF-SHA256 to derive the subkeys it needs — a data-key-wrapping key, a metadata-encryption key, an Ed25519 signing key seed. Those subkeys never leave the `Vault`.

Methods:
- `encrypt_blob(plaintext: &[u8]) -> Result<EncryptedBlob>` — generates a random per-blob data key, encrypts with AES-256-GCM and random IV, wraps the data key with the wrapping key
- `decrypt_blob(blob: &EncryptedBlob) -> Result<Vec<u8>>` — inverse
- `encrypt_metadata_field(plaintext: &[u8]) -> Result<EncryptedField>` — same envelope, scoped to metadata key
- `decrypt_metadata_field(field: &EncryptedField) -> Result<Vec<u8>>`
- `sign_challenge(nonce: &[u8]) -> DeviceSignature` — Ed25519 over the nonce (infallible given a valid signing key)
- `device_public_key() -> [u8; 32]` — for backend registration

All `Vault` key-bearing fields are stored in `Zeroizing<[u8; 32]>` so they zeroize automatically on drop. `SigningKey` zeroizes via `ed25519-dalek`'s `zeroize` feature. No manual `Drop` impl is needed for the Vault.

### 4.3 Stateless modules for things that need no key

`recovery::generate_master_secret() -> Result<[u8; 32]>` — system random (returns `Err(Randomness)` if the OS CSPRNG is unavailable)
`recovery::secret_to_phrase(secret: &[u8; 32]) -> Result<String>` — BIP39 24-word
`recovery::phrase_to_secret(phrase: &str) -> Result<[u8; 32]>` — inverse

Note: this differs from the parent DESIGN.md §4.2 (which still says "12-word"). 12 words encodes 128 bits of entropy; the master secret here is 256 bits, requiring 24 words. The parent DESIGN.md should be updated to match when feature work begins on the mobile recovery flow.

These take no `Vault` and own no state, but live in the same crate.

### 4.4 Envelope shapes mirror `@filer/protocol`

`EncryptedBlob { ciphertext: Vec<u8>, iv: [u8; 12], wrapped_key: Vec<u8> }`
`EncryptedField { ciphertext: Vec<u8>, iv: [u8; 12] }`
`Signature { bytes: [u8; 64] }`

These structurally match the TypeScript types in `packages/protocol/src/` (which the mobile and backend both consume). No magic bytes, no version byte yet — add at the first compatibility break.

### 4.5 Single error enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum FilerCryptoError {
    #[error("AEAD operation failed")]
    Aead,
    #[error("invalid recovery phrase")]
    InvalidPhrase,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("randomness source unavailable")]
    Randomness,
}
```

UniFFI maps this enum to a Swift `enum FilerCryptoError: Error`. No nested causes; the variant name carries the diagnostic.

### 4.6 Crypto crate choices

All from the RustCrypto family except `bip39` and `ed25519-dalek`:

- `aes-gcm` ^0.10 — AES-256-GCM
- `hkdf` ^0.12 + `sha2` ^0.10 — HKDF-SHA256
- `ed25519-dalek` ^2.1 — device signing
- `bip39` ^2.0 — recovery phrase
- `zeroize` ^1.7 — secure memory wipe
- `subtle` — constant-time comparison. Not declared as a direct dependency in v0.1.0 because no path currently requires it (the AEAD library handles tag verification in constant time internally). Re-add as a direct dependency when a code path needs to compare derived bytes manually (HMAC tags, custom signature schemes, etc.).
- `rand_core` ^0.6 + `getrandom` ^0.2 — system random
- `thiserror` ^2.0 — error macros
- `uniffi` ^0.29 — bindings (binding crate only)

No `ring`, no OpenSSL, no `rustls` — keep the dependency tree small and audit-friendly.

### 4.7 Source-only Swift Package for v0.1.0

`Package.swift` declares a Swift target that includes the generated bindings file. The Rust libraries are built by SPM via a small build script (a target script or systemLibrary placeholder TBD by the plan — likely a `binaryTarget` block that initially points at a placeholder XCFramework, with a note to switch to a real artifact when the first tag is cut).

Consumers (the mobile app) get the crate by adding the GitHub URL as an SPM dependency. The `with-crypto-core` plugin in the mobile repo handles SPM injection.

When the first device-build milestone arrives, switch `Package.swift` to a `binaryTarget` pointing at a CI-published XCFramework. That's a follow-on plan.

### 4.8 Bindings file is committed

`Sources/FilerCrypto/FilerCrypto.swift` is the output of `uniffi-bindgen swift`. Committing it means:
- Consumers don't need to install `uniffi-bindgen` locally
- Diffs to the binding surface are visible in PRs
- The Swift API is git-blame-able

The `scripts/build.sh` regenerates the file after any UDL change. Pre-commit or CI can guard against drift if needed; for v0.1.0, manual discipline.

### 4.9 CLAUDE.md content plan

Single file at repo root, ~150 lines. Sections in order:

1. **What this is** — one paragraph: open-source crypto core for the Filer iOS app (closed-source sibling repo). Link to that repo's DESIGN.md for product context, but emphasize that an agent working in this repo should NOT need it for day-to-day work.
2. **Hard invariants** — bullets a coding agent must not violate:
   - Never log or print key material, master secrets, or signatures. Not in tests, not in error messages, not in `Debug` impls.
   - Never use `ring`, `openssl`, or any other non-RustCrypto-family crate without explicit justification. The dep tree is intentionally small and audit-friendly.
   - All types holding key material implement `Zeroize` and `Drop`-zeroize their fields. Adding a key-bearing type without this is a bug.
   - Constant-time comparison via `subtle` for any path that compares secrets, MACs, or signature outputs. No `==` on key-derived bytes.
   - No `panic!`, `unwrap()`, or `expect()` on values that come from user input — these are external crate boundaries, return `Result<_, FilerCryptoError>` instead.
   - The MIT license is a contract. Don't add dependencies whose license isn't MIT/Apache-2.0/BSD-compatible.
   - Envelope formats (`EncryptedBlob`, `EncryptedField`) are stable wire format. Changing field names, lengths, or ordering is a major-version compatibility break.
3. **Repo map** — one-line description per top-level directory
4. **Tech stack** — Rust edition, UniFFI version, RustCrypto components, Swift Package version target
5. **Common commands** — `cargo build`, `cargo test --workspace`, `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `scripts/build.sh`, `swift package describe`
6. **Public API surface** — pointer to `Vault` in `crates/filer-crypto/src/vault.rs` and the stateless functions in `recovery.rs`. The contract: "If it isn't `pub` from these two modules, it isn't part of the Swift API."
7. **Adding a new primitive** — short checklist: write the Rust implementation in its own module, add round-trip + KAT tests, expose via `Vault` or as a free function, update the UDL, regenerate bindings via `scripts/build.sh`, commit the regenerated `FilerCrypto.swift`.
8. **What not to add** — no async (UniFFI sync is fine for v1), no custom serialization (envelopes are simple structs), no extra binding targets in this repo (Android lives in its own follow-up).
9. **Security disclosure** — pointer to where to file security issues (placeholder for the plan; not in scaffolding).

## 5. Testing

- **Per-module Rust unit tests**: round-trip tests in each `.rs` file (`encrypt → decrypt → equal`, `phrase → secret → phrase → equal`, etc.)
- **Known-answer tests**: one or two NIST AES-GCM vectors, one or two RFC 5869 HKDF vectors — sanity check, not exhaustive
- **Vault construction tests**: opening with a known master secret produces deterministic subkeys (so we can detect KDF-context drift)
- **Swift parity test placeholder**: a single test in `Tests/FilerCryptoTests/FilerCryptoTests.swift` that opens a Vault and round-trips a small blob. Marked `XCTSkip` if the underlying Rust artifact isn't built. Real parity suite lands with the XCFramework follow-up.

## 6. CI

`.github/workflows/ci.yml`:

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
```

One job, Linux only. macOS Swift parity runs when XCFramework lands.

## 7. Acceptance criteria

The setup is done when:

1. `cargo build --workspace` succeeds from a clean clone
2. `cargo test --workspace` passes (all per-module round-trip tests, plus the KAT sanity checks)
3. `cargo fmt --check` and `cargo clippy --workspace -- -D warnings` both pass
4. `scripts/build.sh` produces `Sources/FilerCrypto/FilerCrypto.swift` without error
5. The `Vault` public API matches §4.2 (method names, signatures, types)
6. The recovery-phrase API matches §4.3 (free functions)
7. `Package.swift` parses with `swift package describe` and lists the `FilerCrypto` target
8. CI workflow passes on a PR
9. The mobile app's `with-crypto-core` plugin (in the sibling repo) stops logging "no Package.swift" and proceeds to SPM injection when `expo prebuild` runs against this repo via the local-path mode (`FILER_CRYPTO_LOCAL=1`)
10. README documents: what the crate is, build commands, where to file security issues
11. CLAUDE.md exists at repo root, covers every section in §4.9, and a fresh agent reading only CLAUDE.md (no consumer DESIGN.md) can answer: what must never appear in logs, which crypto crate family is allowed, what the `Vault` public API contract is

## 8. Open questions

None blocking. Two items to decide during the plan:

1. **`Package.swift` Rust-build mechanism** — SPM doesn't natively know how to run `cargo build`. Options: a `Package.swift` build plugin invoking cargo, a shell script run before `swift build`, or punt and require consumers to have run `scripts/build.sh` first (acceptable for source-only initial release because the mobile app's `with-crypto-core` plugin runs at `expo prebuild` time and we can hook the build there). The plan picks an option; this is a "decide during implementation" matter, not a spec gap.
2. **KDF context strings** — what `info` strings does HKDF use to derive each subkey (wrapping key, metadata key, signing seed)? Cosmetic naming decisions; pick during implementation. The choice is forever once shipped, so document them in `kdf.rs` for the spec record.
