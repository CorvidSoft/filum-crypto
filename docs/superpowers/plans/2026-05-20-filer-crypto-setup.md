# filer-crypto Setup Implementation Plan

> **Historical artifact (2026-05-20).** Tasks 1-8 + 15-17 of this plan were implemented in [PR #1](https://github.com/CorvidSoft/filer-crypto/pull/1). The implemented code diverged from the snippets below in a few places due to PR review (notably: `FilerCryptoError::Decrypt` → `Aead`; `Vault` fields are `Zeroizing<[u8;32]>` with no manual `Drop` impl; `subtle` is not a direct dep). See `git log` for the as-built state. Tasks 9-14 + 18 are deferred to a follow-up plan.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold the `filer-crypto` Rust crate per `docs/superpowers/specs/2026-05-20-filer-crypto-setup-design.md` — Cargo workspace with two crates (pure-Rust core + UniFFI binding layer), the `Vault` public API with five primitives (HKDF, BIP39 24-word recovery, AES-256-GCM blob encryption with key wrapping, AES-256-GCM metadata field encryption, Ed25519 signing), a `Package.swift` wrapper, CI, README, and CLAUDE.md.

**Architecture:** Two-crate Cargo workspace. `crates/filer-crypto` is the pure-Rust core with the `Vault` public type and stateless `recovery` module. `crates/filer-crypto-uniffi` exposes the core via UDL to UniFFI, building as `cdylib`/`staticlib` for Swift consumption. A `Package.swift` at repo root wraps the generated bindings; source-only for v0.1.0, XCFramework deferred to first tagged release.

**Tech Stack:** Rust edition 2024 · aes-gcm 0.10 · hkdf 0.12 · sha2 0.10 · ed25519-dalek 2.1 · bip39 2.0 · zeroize 1.7 · subtle 2.5 · rand_core 0.6 · getrandom 0.2 · thiserror 2.0 · uniffi 0.28 · Swift 5.9.

---

## File Structure

This plan creates the structure below. Each file appears under the task that creates it.

```
filer-crypto/
├── Cargo.toml                                          # Task 1 (workspace root)
├── Cargo.lock                                          # Task 1 (generated)
├── .gitignore                                          # Task 1 (extend existing)
├── crates/
│   ├── filer-crypto/                                   # Task 2 (core crate skeleton)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                                  # Task 2
│   │       ├── error.rs                                # Task 2
│   │       ├── kdf.rs                                  # Task 3
│   │       ├── recovery.rs                             # Task 4
│   │       ├── blob.rs                                 # Task 5
│   │       ├── metadata.rs                             # Task 6
│   │       ├── auth.rs                                 # Task 7
│   │       └── vault.rs                                # Task 8
│   └── filer-crypto-uniffi/                            # Tasks 9-10
│       ├── Cargo.toml
│       ├── build.rs
│       ├── uniffi.toml
│       └── src/
│           ├── lib.rs
│           ├── filer_crypto.udl
│           └── bin/
│               └── uniffi-bindgen.rs
├── Package.swift                                       # Task 13
├── Sources/
│   └── FilerCrypto/
│       └── FilerCrypto.swift                           # Task 12 (generated, committed)
├── Tests/
│   └── FilerCryptoTests/
│       └── FilerCryptoTests.swift                      # Task 14
├── scripts/
│   ├── build.sh                                        # Task 11
│   └── README.md                                       # Task 11
├── .github/
│   └── workflows/
│       └── ci.yml                                      # Task 15
├── README.md                                           # Task 16
├── CLAUDE.md                                           # Task 17
├── LICENSE                                             # exists
└── .gitignore                                          # exists, extended in Task 1
```

---

## Task 1: Workspace root

**Files:**
- Create: `Cargo.toml` (workspace root)
- Modify: `.gitignore` (add Swift Package and binding-related ignores)

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "crates/filer-crypto",
    "crates/filer-crypto-uniffi",
]

[workspace.package]
edition = "2024"
license = "MIT"
repository = "https://github.com/CorvidSoft/filer-crypto"
authors = ["CorvidSoft"]
version = "0.0.1"

[workspace.dependencies]
aes-gcm = "0.10"
hkdf = "0.12"
sha2 = "0.10"
ed25519-dalek = { version = "2.1", features = ["rand_core", "zeroize"] }
bip39 = "2.0"
zeroize = { version = "1.7", features = ["zeroize_derive"] }
subtle = "2.5"
rand_core = { version = "0.6", features = ["getrandom"] }
getrandom = "0.2"
thiserror = "2.0"
uniffi = "0.28"
```

- [ ] **Step 2: Extend `.gitignore`**

Append to the existing `.gitignore`:

```
# Generated Swift Package artifacts
.build/
.swiftpm/
*.xcframework/

# Generated UniFFI artifacts
crates/filer-crypto-uniffi/target/
crates/*/target/
```

(The existing `.gitignore` already covers `target/` at the root, but Cargo workspaces have nested targets only if the workspace setup forces it; the extra patterns are defensive.)

- [ ] **Step 3: Verify Cargo accepts the workspace**

Run: `cargo metadata --format-version 1 --no-deps`
Expected: exits 0 with JSON output listing both workspace members (the member crates don't exist yet, so expect a warning or partial output — verify it doesn't crash).

If `cargo metadata` errors because the member crates don't exist yet, that's expected; we'll have a valid workspace after Task 2.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml .gitignore
git commit -m "chore: initialize Cargo workspace"
```

---

## Task 2: Core crate skeleton + error type

**Files:**
- Create: `crates/filer-crypto/Cargo.toml`
- Create: `crates/filer-crypto/src/lib.rs`
- Create: `crates/filer-crypto/src/error.rs`

- [ ] **Step 1: Create `crates/filer-crypto/Cargo.toml`**

```toml
[package]
name = "filer-crypto"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Pure-Rust cryptographic core for the Filer iOS app"

[dependencies]
aes-gcm = { workspace = true }
hkdf = { workspace = true }
sha2 = { workspace = true }
ed25519-dalek = { workspace = true }
bip39 = { workspace = true }
zeroize = { workspace = true }
subtle = { workspace = true }
rand_core = { workspace = true }
getrandom = { workspace = true }
thiserror = { workspace = true }
```

- [ ] **Step 2: Create `crates/filer-crypto/src/error.rs`**

```rust
use thiserror::Error;

/// All errors returned by this crate.
///
/// Variants are intentionally coarse — the variant name carries the diagnostic.
/// We do not expose cause chains or position info because they could leak
/// information about key material or input shape.
#[derive(Debug, Error)]
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

pub type Result<T> = std::result::Result<T, FilerCryptoError>;
```

- [ ] **Step 3: Create `crates/filer-crypto/src/lib.rs` (skeleton only)**

```rust
//! Filer cryptographic core.
//!
//! This crate is the pure-Rust core of `filer-crypto`. It exposes a single
//! stateful type [`Vault`] that owns derived keys and provides envelope
//! encryption + signing, plus stateless functions in the [`recovery`] module
//! for BIP39 phrase ↔ master secret conversion.
//!
//! All other modules are crate-private.

mod error;

pub use error::{FilerCryptoError, Result};
```

- [ ] **Step 4: Verify the crate builds**

Run: `cargo build -p filer-crypto`
Expected: exit 0, downloads + compiles dependencies, no warnings.

- [ ] **Step 5: Verify tests run (no tests yet — should be zero-pass)**

Run: `cargo test -p filer-crypto`
Expected: `running 0 tests` ... `test result: ok. 0 passed`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/filer-crypto
git commit -m "feat(core): scaffold filer-crypto crate with FilerCryptoError"
```

---

## Task 3: KDF module (HKDF-SHA256)

**Files:**
- Create: `crates/filer-crypto/src/kdf.rs`
- Modify: `crates/filer-crypto/src/lib.rs` (declare the module)

The KDF derives crate-internal subkeys from the master secret. Context strings are stable per major version — changing them is a breaking change that invalidates all existing vaults.

- [ ] **Step 1: Write the failing test**

Append to `crates/filer-crypto/src/kdf.rs` (creating the file):

```rust
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{FilerCryptoError, Result};

/// HKDF info string for the data-key-wrapping subkey.
pub(crate) const WRAP_CTX: &[u8] = b"filer-crypto/v1/wrap";

/// HKDF info string for the metadata-encryption subkey.
pub(crate) const METADATA_CTX: &[u8] = b"filer-crypto/v1/metadata";

/// HKDF info string for the device-signing seed.
pub(crate) const SIGN_CTX: &[u8] = b"filer-crypto/v1/sign";

/// Derives a subkey from the master secret using HKDF-SHA256.
///
/// `info` is the context string that domain-separates each derived subkey.
/// The output length is determined by the caller via the `out` slice length;
/// HKDF-SHA256 supports up to 8160 bytes per derivation.
pub(crate) fn derive_subkey(secret: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    hkdf.expand(info, out)
        .map_err(|_| FilerCryptoError::InvalidKeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_subkey_is_deterministic() {
        let secret = [42u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_subkey(&secret, WRAP_CTX, &mut out1).unwrap();
        derive_subkey(&secret, WRAP_CTX, &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_contexts_produce_different_subkeys() {
        let secret = [42u8; 32];
        let mut wrap = [0u8; 32];
        let mut meta = [0u8; 32];
        let mut sign = [0u8; 32];
        derive_subkey(&secret, WRAP_CTX, &mut wrap).unwrap();
        derive_subkey(&secret, METADATA_CTX, &mut meta).unwrap();
        derive_subkey(&secret, SIGN_CTX, &mut sign).unwrap();
        assert_ne!(wrap, meta);
        assert_ne!(wrap, sign);
        assert_ne!(meta, sign);
    }

    #[test]
    fn known_answer_rfc5869_test_case_1() {
        // RFC 5869 §A.1: HKDF-SHA256 test vector
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        // Note: RFC 5869 also defines a salt; our `derive_subkey` uses `None` as
        // the salt (per Hkdf::new). For the RFC test case we need the salt-bearing
        // form, so we call Hkdf directly here.
        let salt = hex_decode("000102030405060708090a0b0c");
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut out = vec![0u8; 42];
        hkdf.expand(&info, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
```

- [ ] **Step 2: Declare the module in `lib.rs`**

Edit `crates/filer-crypto/src/lib.rs`:

```rust
//! Filer cryptographic core.
//!
//! This crate is the pure-Rust core of `filer-crypto`. It exposes a single
//! stateful type [`Vault`] that owns derived keys and provides envelope
//! encryption + signing, plus stateless functions in the [`recovery`] module
//! for BIP39 phrase ↔ master secret conversion.
//!
//! All other modules are crate-private.

mod error;
mod kdf;

pub use error::{FilerCryptoError, Result};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p filer-crypto`
Expected: 3 tests pass — `derive_subkey_is_deterministic`, `different_contexts_produce_different_subkeys`, `known_answer_rfc5869_test_case_1`.

- [ ] **Step 4: Run clippy and fmt**

Run: `cargo clippy -p filer-crypto -- -D warnings && cargo fmt --check`
Expected: both exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/filer-crypto
git commit -m "feat(core): add HKDF-SHA256 subkey derivation"
```

---

## Task 4: Recovery module (BIP39 24-word)

**Files:**
- Create: `crates/filer-crypto/src/recovery.rs`
- Modify: `crates/filer-crypto/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/filer-crypto/src/recovery.rs`:

```rust
//! BIP39 24-word recovery phrase ↔ 32-byte master secret.
//!
//! 24 words = 256 bits of entropy, matching the rest of the crate's 256-bit
//! security baseline. This differs from the parent Filer DESIGN.md §4.2 which
//! still says "12-word" — to be reconciled when the mobile recovery flow is
//! implemented.

use bip39::{Language, Mnemonic};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{FilerCryptoError, Result};

/// Generates a fresh 32-byte master secret from the system CSPRNG.
pub fn generate_master_secret() -> [u8; 32] {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}

/// Encodes a 32-byte master secret as a 24-word BIP39 phrase (English).
pub fn secret_to_phrase(secret: &[u8; 32]) -> Result<String> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, secret)
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    Ok(mnemonic.to_string())
}

/// Decodes a 24-word BIP39 phrase (English) back into a 32-byte master secret.
pub fn phrase_to_secret(phrase: &str) -> Result<[u8; 32]> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|_| FilerCryptoError::InvalidPhrase)?;
    let mut entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        entropy.zeroize();
        return Err(FilerCryptoError::InvalidPhrase);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&entropy);
    entropy.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_secret_phrase() {
        let secret = [42u8; 32];
        let phrase = secret_to_phrase(&secret).unwrap();
        let recovered = phrase_to_secret(&phrase).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn phrase_has_24_words() {
        let secret = [0u8; 32];
        let phrase = secret_to_phrase(&secret).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn invalid_phrase_rejected() {
        let result = phrase_to_secret("not a real phrase");
        assert!(matches!(result, Err(FilerCryptoError::InvalidPhrase)));
    }

    #[test]
    fn twelve_word_phrase_rejected() {
        // A valid 12-word phrase should still be rejected because we mandate 24.
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        let result = phrase_to_secret(twelve);
        assert!(matches!(result, Err(FilerCryptoError::InvalidPhrase)));
    }

    #[test]
    fn generate_master_secret_is_non_zero() {
        let secret = generate_master_secret();
        assert_ne!(secret, [0u8; 32]);
    }

    #[test]
    fn generate_master_secret_is_random() {
        let a = generate_master_secret();
        let b = generate_master_secret();
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 2: Declare the module in `lib.rs`**

Edit `crates/filer-crypto/src/lib.rs`:

```rust
//! Filer cryptographic core.
//!
//! This crate is the pure-Rust core of `filer-crypto`. It exposes a single
//! stateful type [`Vault`] that owns derived keys and provides envelope
//! encryption + signing, plus stateless functions in the [`recovery`] module
//! for BIP39 phrase ↔ master secret conversion.
//!
//! All other modules are crate-private.

mod error;
mod kdf;
pub mod recovery;

pub use error::{FilerCryptoError, Result};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p filer-crypto`
Expected: 9 tests pass (3 kdf + 6 recovery).

- [ ] **Step 4: Lint + format**

Run: `cargo clippy -p filer-crypto -- -D warnings && cargo fmt --check`
Expected: both exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/filer-crypto
git commit -m "feat(core): add BIP39 24-word recovery phrase encoding"
```

---

## Task 5: Blob encryption module

**Files:**
- Create: `crates/filer-crypto/src/blob.rs`
- Modify: `crates/filer-crypto/src/lib.rs`

The blob envelope uses two-stage encryption: a random per-blob 32-byte data key encrypts the plaintext with AES-256-GCM, then the data key is itself encrypted (wrapped) with the wrapping key. This allows future per-blob sharing without re-encrypting the entire vault — we just hand out the wrapped key encrypted under a recipient's key.

- [ ] **Step 1: Write the failing tests + skeleton**

Create `crates/filer-crypto/src/blob.rs`:

```rust
//! AES-256-GCM blob encryption with per-blob random data keys.
//!
//! Each blob has:
//!   - a fresh random 32-byte data key
//!   - a fresh random 12-byte IV
//!   - ciphertext = AES-256-GCM(data_key, iv, plaintext)
//!   - wrapped_key = IV(12) || AES-256-GCM(wrapping_key, wrap_iv, data_key)
//!
//! The wrapped_key field encodes its own 12-byte IV as the first 12 bytes,
//! followed by the GCM ciphertext + tag (48 bytes for a 32-byte key).

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{FilerCryptoError, Result};

/// The encrypted-blob envelope as returned by the crate. Structurally mirrors
/// the `@filer/protocol`'s `EncryptedBlobUpload` shape on the TypeScript side.
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
    /// 12-byte IV || AES-256-GCM ciphertext+tag of the 32-byte data key.
    pub wrapped_key: Vec<u8>,
}

pub(crate) fn encrypt_with_key_wrapping(
    plaintext: &[u8],
    wrapping_key: &[u8; 32],
) -> Result<EncryptedBlob> {
    // 1. Fresh random per-blob data key + IV
    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    // 2. Encrypt plaintext with the data key
    let cipher = Aes256Gcm::new(&data_key.into());
    let ciphertext = cipher
        .encrypt(&iv.into(), plaintext)
        .map_err(|_| FilerCryptoError::Aead)?;

    // 3. Wrap the data key with the wrapping key (also AES-256-GCM)
    let mut wrap_iv = [0u8; 12];
    OsRng.fill_bytes(&mut wrap_iv);
    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let wrapped_key_ct = wrapper
        .encrypt(&wrap_iv.into(), data_key.as_slice())
        .map_err(|_| FilerCryptoError::Aead)?;

    // Wrapped key layout: iv (12 bytes) || ciphertext+tag
    let mut wrapped_key = Vec::with_capacity(12 + wrapped_key_ct.len());
    wrapped_key.extend_from_slice(&wrap_iv);
    wrapped_key.extend_from_slice(&wrapped_key_ct);

    data_key.zeroize();

    Ok(EncryptedBlob {
        ciphertext,
        iv,
        wrapped_key,
    })
}

pub(crate) fn decrypt_with_key_wrapping(
    blob: &EncryptedBlob,
    wrapping_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if blob.wrapped_key.len() < 12 {
        return Err(FilerCryptoError::Aead);
    }
    // Unwrap the data key
    let (wrap_iv_bytes, wrapped_ct) = blob.wrapped_key.split_at(12);
    let mut wrap_iv = [0u8; 12];
    wrap_iv.copy_from_slice(wrap_iv_bytes);

    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let mut data_key_vec = wrapper
        .decrypt(&wrap_iv.into(), wrapped_ct)
        .map_err(|_| FilerCryptoError::Aead)?;

    if data_key_vec.len() != 32 {
        data_key_vec.zeroize();
        return Err(FilerCryptoError::Aead);
    }
    let mut data_key = [0u8; 32];
    data_key.copy_from_slice(&data_key_vec);
    data_key_vec.zeroize();

    // Decrypt the payload
    let cipher = Aes256Gcm::new(&data_key.into());
    let plaintext = cipher
        .decrypt(&blob.iv.into(), blob.ciphertext.as_slice())
        .map_err(|_| FilerCryptoError::Aead);

    data_key.zeroize();
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_blob() {
        let wrapping_key = [42u8; 32];
        let plaintext = b"hello world";
        let blob = encrypt_with_key_wrapping(plaintext, &wrapping_key).unwrap();
        let recovered = decrypt_with_key_wrapping(&blob, &wrapping_key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_blob() {
        let wrapping_key = [42u8; 32];
        let blob = encrypt_with_key_wrapping(&[], &wrapping_key).unwrap();
        let recovered = decrypt_with_key_wrapping(&blob, &wrapping_key).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn round_trip_large_blob() {
        let wrapping_key = [42u8; 32];
        let plaintext = vec![7u8; 1024 * 1024]; // 1 MiB
        let blob = encrypt_with_key_wrapping(&plaintext, &wrapping_key).unwrap();
        let recovered = decrypt_with_key_wrapping(&blob, &wrapping_key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_wrapping_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let blob = encrypt_with_key_wrapping(b"data", &key1).unwrap();
        let result = decrypt_with_key_wrapping(&blob, &key2);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.ciphertext[0] ^= 1;
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn tampered_wrapped_key_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.wrapped_key[15] ^= 1; // flip a bit in the wrapped-key ciphertext
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn nondeterministic_ciphertext_for_same_input() {
        // Per-blob random data key + IV means two encryptions of the same
        // plaintext produce different ciphertexts.
        let key = [42u8; 32];
        let a = encrypt_with_key_wrapping(b"same", &key).unwrap();
        let b = encrypt_with_key_wrapping(b"same", &key).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.iv, b.iv);
        assert_ne!(a.wrapped_key, b.wrapped_key);
    }

    #[test]
    fn truncated_wrapped_key_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.wrapped_key.truncate(5); // shorter than 12-byte IV
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }
}
```

- [ ] **Step 2: Declare the module in `lib.rs`**

Edit `crates/filer-crypto/src/lib.rs`:

```rust
//! Filer cryptographic core.

mod blob;
mod error;
mod kdf;
pub mod recovery;

pub use blob::EncryptedBlob;
pub use error::{FilerCryptoError, Result};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p filer-crypto`
Expected: 17 tests pass (3 kdf + 6 recovery + 8 blob).

- [ ] **Step 4: Lint + format**

Run: `cargo clippy -p filer-crypto -- -D warnings && cargo fmt --check`
Expected: both exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/filer-crypto
git commit -m "feat(core): add AES-256-GCM blob encryption with key wrapping"
```

---

## Task 6: Metadata field encryption module

**Files:**
- Create: `crates/filer-crypto/src/metadata.rs`
- Modify: `crates/filer-crypto/src/lib.rs`

Simpler than blob — no per-field random data key. Just AES-256-GCM with the metadata key directly. The metadata key has already been domain-separated from the wrapping key via HKDF (different `info` strings), so they're cryptographically independent.

- [ ] **Step 1: Write the failing tests + skeleton**

Create `crates/filer-crypto/src/metadata.rs`:

```rust
//! AES-256-GCM field-level metadata encryption.
//!
//! Used to encrypt sensitive SQLite columns (filenames, document types,
//! extracted fields). The metadata key is derived from the master secret
//! via HKDF and is independent of the wrapping key used for blobs.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand_core::{OsRng, RngCore};

use crate::error::{FilerCryptoError, Result};

/// The encrypted-field envelope. Structurally mirrors the `EncryptedSyncRecord`
/// shape on the TypeScript protocol side (ciphertext + iv, no wrapped key).
#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
}

pub(crate) fn encrypt_field(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedField> {
    let cipher = Aes256Gcm::new(key.into());
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let ciphertext = cipher
        .encrypt(&iv.into(), plaintext)
        .map_err(|_| FilerCryptoError::Aead)?;
    Ok(EncryptedField { ciphertext, iv })
}

pub(crate) fn decrypt_field(field: &EncryptedField, key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(&field.iv.into(), field.ciphertext.as_slice())
        .map_err(|_| FilerCryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_field() {
        let key = [7u8; 32];
        let plaintext = b"passport_no:AB1234567";
        let field = encrypt_field(plaintext, &key).unwrap();
        let recovered = decrypt_field(&field, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_field() {
        let key = [7u8; 32];
        let field = encrypt_field(&[], &key).unwrap();
        let recovered = decrypt_field(&field, &key).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [7u8; 32];
        let key2 = [8u8; 32];
        let field = encrypt_field(b"secret", &key1).unwrap();
        let result = decrypt_field(&field, &key2);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [7u8; 32];
        let mut field = encrypt_field(b"secret", &key).unwrap();
        field.ciphertext[0] ^= 1;
        let result = decrypt_field(&field, &key);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn nondeterministic_for_same_input() {
        let key = [7u8; 32];
        let a = encrypt_field(b"same", &key).unwrap();
        let b = encrypt_field(b"same", &key).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.iv, b.iv);
    }
}
```

- [ ] **Step 2: Declare the module in `lib.rs`**

Edit `crates/filer-crypto/src/lib.rs`:

```rust
//! Filer cryptographic core.

mod blob;
mod error;
mod kdf;
mod metadata;
pub mod recovery;

pub use blob::EncryptedBlob;
pub use error::{FilerCryptoError, Result};
pub use metadata::EncryptedField;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p filer-crypto`
Expected: 22 tests pass (3 kdf + 6 recovery + 8 blob + 5 metadata).

- [ ] **Step 4: Lint + format**

Run: `cargo clippy -p filer-crypto -- -D warnings && cargo fmt --check`
Expected: both exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/filer-crypto
git commit -m "feat(core): add AES-256-GCM metadata field encryption"
```

---

## Task 7: Auth signing module (Ed25519)

**Files:**
- Create: `crates/filer-crypto/src/auth.rs`
- Modify: `crates/filer-crypto/src/lib.rs`

The device signs backend-issued challenge nonces with an Ed25519 key whose seed is derived from the master secret via HKDF. The public key is registered with the backend at first device pair-up.

- [ ] **Step 1: Write the failing tests + skeleton**

Create `crates/filer-crypto/src/auth.rs`:

```rust
//! Ed25519 device challenge-response signing.
//!
//! The device's signing key seed is derived from the master secret via HKDF.
//! Same master secret → same signing key → same public key, so the device
//! identity is stable across reinstalls as long as the master secret is
//! recovered.

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::error::{FilerCryptoError, Result};

/// An Ed25519 signature produced by [`Vault::sign_challenge`].
#[derive(Debug, Clone)]
pub struct DeviceSignature {
    pub bytes: [u8; 64],
}

pub(crate) fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub(crate) fn sign_challenge(key: &SigningKey, nonce: &[u8]) -> DeviceSignature {
    let sig = key.sign(nonce);
    DeviceSignature {
        bytes: sig.to_bytes(),
    }
}

pub(crate) fn public_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Verify a signature. Public so tests can use it; in production the backend
/// owns verification.
pub fn verify_signature(public_key: &[u8; 32], nonce: &[u8], signature: &[u8; 64]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| FilerCryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(nonce, &sig)
        .map_err(|_| FilerCryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let nonce = b"backend-issued-nonce";
        let sig = sign_challenge(&key, nonce);
        let pk = public_key_bytes(&key);
        verify_signature(&pk, nonce, &sig.bytes).unwrap();
    }

    #[test]
    fn signature_is_deterministic_for_same_seed_and_nonce() {
        // Ed25519 signatures are deterministic by spec (RFC 8032).
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let nonce = b"nonce";
        let sig1 = sign_challenge(&key, nonce);
        let sig2 = sign_challenge(&key, nonce);
        assert_eq!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn different_seeds_produce_different_public_keys() {
        let key1 = signing_key_from_seed(&[1u8; 32]);
        let key2 = signing_key_from_seed(&[2u8; 32]);
        assert_ne!(public_key_bytes(&key1), public_key_bytes(&key2));
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let sig = sign_challenge(&key, b"nonce");
        let pk = public_key_bytes(&key);
        let result = verify_signature(&pk, b"different", &sig.bytes);
        assert!(matches!(result, Err(FilerCryptoError::InvalidSignature)));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let sig = sign_challenge(&key, b"nonce");
        let pk = public_key_bytes(&key);
        let mut bad = sig.bytes;
        bad[0] ^= 1;
        let result = verify_signature(&pk, b"nonce", &bad);
        assert!(matches!(result, Err(FilerCryptoError::InvalidSignature)));
    }

    #[test]
    fn invalid_public_key_fails_verification() {
        // An all-zeros key is rejected by verify_strict.
        let result = verify_signature(&[0u8; 32], b"nonce", &[0u8; 64]);
        assert!(matches!(result, Err(FilerCryptoError::InvalidSignature)));
    }
}
```

- [ ] **Step 2: Declare the module in `lib.rs`**

Edit `crates/filer-crypto/src/lib.rs`:

```rust
//! Filer cryptographic core.

mod auth;
mod blob;
mod error;
mod kdf;
mod metadata;
pub mod recovery;

pub use auth::{DeviceSignature, verify_signature};
pub use blob::EncryptedBlob;
pub use error::{FilerCryptoError, Result};
pub use metadata::EncryptedField;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p filer-crypto`
Expected: 28 tests pass (3 + 6 + 8 + 5 + 6).

- [ ] **Step 4: Lint + format**

Run: `cargo clippy -p filer-crypto -- -D warnings && cargo fmt --check`
Expected: both exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/filer-crypto
git commit -m "feat(core): add Ed25519 device challenge signing"
```

---

## Task 8: Vault — top-level stateful API

**Files:**
- Create: `crates/filer-crypto/src/vault.rs`
- Modify: `crates/filer-crypto/src/lib.rs`

`Vault` ties together the primitives. Open it with a master secret (or a recovery phrase), get back a handle that owns derived subkeys and exposes the public methods. It zeroizes on drop.

- [ ] **Step 1: Write the failing tests + skeleton**

Create `crates/filer-crypto/src/vault.rs`:

```rust
//! The `Vault` is the top-level stateful API of `filer-crypto`.
//!
//! Construct it with either a 32-byte master secret or a 24-word BIP39
//! recovery phrase. On construction it derives all needed subkeys via HKDF
//! and stores them privately. The subkeys never leave the Vault; callers
//! interact with `Vault` methods that operate on plaintext + the envelope
//! types defined in [`crate::blob`] and [`crate::metadata`].
//!
//! The Vault implements `Drop` to zeroize all key material when it goes
//! out of scope.

use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

use crate::auth::{self, DeviceSignature};
use crate::blob::{self, EncryptedBlob};
use crate::error::Result;
use crate::kdf::{self, METADATA_CTX, SIGN_CTX, WRAP_CTX};
use crate::metadata::{self, EncryptedField};
use crate::recovery;

pub struct Vault {
    wrap_key: [u8; 32],
    metadata_key: [u8; 32],
    signing_key: SigningKey,
}

impl Vault {
    /// Open a Vault from a 32-byte master secret.
    pub fn open(master_secret: &[u8; 32]) -> Result<Self> {
        let mut wrap_key = [0u8; 32];
        kdf::derive_subkey(master_secret, WRAP_CTX, &mut wrap_key)?;

        let mut metadata_key = [0u8; 32];
        kdf::derive_subkey(master_secret, METADATA_CTX, &mut metadata_key)?;

        let mut sign_seed = [0u8; 32];
        kdf::derive_subkey(master_secret, SIGN_CTX, &mut sign_seed)?;
        let signing_key = auth::signing_key_from_seed(&sign_seed);
        sign_seed.zeroize();

        Ok(Self {
            wrap_key,
            metadata_key,
            signing_key,
        })
    }

    /// Open a Vault from a 24-word BIP39 recovery phrase.
    pub fn from_recovery_phrase(phrase: &str) -> Result<Self> {
        let mut secret = recovery::phrase_to_secret(phrase)?;
        let result = Self::open(&secret);
        secret.zeroize();
        result
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<EncryptedBlob> {
        blob::encrypt_with_key_wrapping(plaintext, &self.wrap_key)
    }

    pub fn decrypt_blob(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        blob::decrypt_with_key_wrapping(blob, &self.wrap_key)
    }

    pub fn encrypt_metadata_field(&self, plaintext: &[u8]) -> Result<EncryptedField> {
        metadata::encrypt_field(plaintext, &self.metadata_key)
    }

    pub fn decrypt_metadata_field(&self, field: &EncryptedField) -> Result<Vec<u8>> {
        metadata::decrypt_field(field, &self.metadata_key)
    }

    pub fn sign_challenge(&self, nonce: &[u8]) -> DeviceSignature {
        auth::sign_challenge(&self.signing_key, nonce)
    }

    pub fn device_public_key(&self) -> [u8; 32] {
        auth::public_key_bytes(&self.signing_key)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
        self.metadata_key.zeroize();
        // SigningKey owns its zeroization per ed25519-dalek's zeroize feature.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verify_signature;

    #[test]
    fn vault_blob_round_trip() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let blob = vault.encrypt_blob(b"hello").unwrap();
        let recovered = vault.decrypt_blob(&blob).unwrap();
        assert_eq!(recovered, b"hello");
    }

    #[test]
    fn vault_metadata_round_trip() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let field = vault.encrypt_metadata_field(b"name=Alice").unwrap();
        let recovered = vault.decrypt_metadata_field(&field).unwrap();
        assert_eq!(recovered, b"name=Alice");
    }

    #[test]
    fn vault_sign_and_verify() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let sig = vault.sign_challenge(b"backend-nonce");
        let pk = vault.device_public_key();
        verify_signature(&pk, b"backend-nonce", &sig.bytes).unwrap();
    }

    #[test]
    fn same_secret_produces_same_public_key() {
        let secret = [1u8; 32];
        let v1 = Vault::open(&secret).unwrap();
        let v2 = Vault::open(&secret).unwrap();
        assert_eq!(v1.device_public_key(), v2.device_public_key());
    }

    #[test]
    fn different_secrets_produce_different_public_keys() {
        let v1 = Vault::open(&[1u8; 32]).unwrap();
        let v2 = Vault::open(&[2u8; 32]).unwrap();
        assert_ne!(v1.device_public_key(), v2.device_public_key());
    }

    #[test]
    fn blob_encrypted_by_one_vault_decrypts_with_same_secret() {
        let secret = [42u8; 32];
        let blob = {
            let v = Vault::open(&secret).unwrap();
            v.encrypt_blob(b"persistent").unwrap()
        };
        let v2 = Vault::open(&secret).unwrap();
        assert_eq!(v2.decrypt_blob(&blob).unwrap(), b"persistent");
    }

    #[test]
    fn vault_from_recovery_phrase_matches_open() {
        let secret = [123u8; 32];
        let phrase = recovery::secret_to_phrase(&secret).unwrap();

        let v_open = Vault::open(&secret).unwrap();
        let v_phrase = Vault::from_recovery_phrase(&phrase).unwrap();

        assert_eq!(v_open.device_public_key(), v_phrase.device_public_key());
    }

    #[test]
    fn vault_from_invalid_phrase_fails() {
        let result = Vault::from_recovery_phrase("not a real phrase");
        assert!(matches!(result, Err(crate::FilerCryptoError::InvalidPhrase)));
    }
}
```

- [ ] **Step 2: Declare the module in `lib.rs`**

Edit `crates/filer-crypto/src/lib.rs`:

```rust
//! Filer cryptographic core.
//!
//! This crate is the pure-Rust core of `filer-crypto`. It exposes a single
//! stateful type [`Vault`] that owns derived keys and provides envelope
//! encryption + signing, plus stateless functions in the [`recovery`] module
//! for BIP39 phrase ↔ master secret conversion.
//!
//! All other modules are crate-private.

mod auth;
mod blob;
mod error;
mod kdf;
mod metadata;
pub mod recovery;
mod vault;

pub use auth::{DeviceSignature, verify_signature};
pub use blob::EncryptedBlob;
pub use error::{FilerCryptoError, Result};
pub use metadata::EncryptedField;
pub use vault::Vault;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p filer-crypto`
Expected: 36 tests pass (3 + 6 + 8 + 5 + 6 + 8).

- [ ] **Step 4: Lint + format**

Run: `cargo clippy -p filer-crypto -- -D warnings && cargo fmt --check`
Expected: both exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/filer-crypto
git commit -m "feat(core): add Vault top-level stateful API"
```

---

## Task 9: UniFFI binding crate scaffold

**Files:**
- Create: `crates/filer-crypto-uniffi/Cargo.toml`
- Create: `crates/filer-crypto-uniffi/build.rs`
- Create: `crates/filer-crypto-uniffi/uniffi.toml`
- Create: `crates/filer-crypto-uniffi/src/lib.rs` (stub)
- Create: `crates/filer-crypto-uniffi/src/bin/uniffi-bindgen.rs`

The binding crate produces `cdylib` and `staticlib` artifacts for Swift to link against, and it embeds the `uniffi-bindgen` CLI so consumers don't need to install it.

- [ ] **Step 1: Create `crates/filer-crypto-uniffi/Cargo.toml`**

```toml
[package]
name = "filer-crypto-uniffi"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "UniFFI bindings for filer-crypto"

[lib]
crate-type = ["cdylib", "staticlib", "rlib"]
name = "filer_crypto"

[[bin]]
name = "uniffi-bindgen"
path = "src/bin/uniffi-bindgen.rs"

[dependencies]
filer-crypto = { path = "../filer-crypto" }
uniffi = { workspace = true, features = ["cli"] }

[build-dependencies]
uniffi = { workspace = true, features = ["build"] }
```

- [ ] **Step 2: Create `crates/filer-crypto-uniffi/build.rs`**

```rust
fn main() {
    uniffi::generate_scaffolding("src/filer_crypto.udl").unwrap();
}
```

- [ ] **Step 3: Create `crates/filer-crypto-uniffi/uniffi.toml`**

```toml
[bindings.swift]
ffi_module_name = "filer_cryptoFFI"
module_name = "FilerCrypto"
generate_module_map = true
```

- [ ] **Step 4: Create `crates/filer-crypto-uniffi/src/bin/uniffi-bindgen.rs`**

```rust
fn main() {
    uniffi::uniffi_bindgen_main();
}
```

- [ ] **Step 5: Create `crates/filer-crypto-uniffi/src/lib.rs` (stub)**

```rust
//! UniFFI binding layer for filer-crypto.
//!
//! Wraps the public API of `filer-crypto` in UniFFI-compatible types and
//! glues them to the UDL definition in `filer_crypto.udl`.

// Empty for now — Task 10 fills this in with the actual wrapper types.
// The UDL file in the same directory has no scaffolding until Task 10 either.

uniffi::include_scaffolding!("filer_crypto");
```

- [ ] **Step 6: Create a minimal UDL placeholder**

Create `crates/filer-crypto-uniffi/src/filer_crypto.udl`:

```
namespace filer_crypto {
};
```

Empty namespace — Task 10 populates it.

- [ ] **Step 7: Verify the binding crate builds**

Run: `cargo build -p filer-crypto-uniffi`
Expected: exits 0. The build will compile uniffi's proc macros and call the build script.

- [ ] **Step 8: Verify the uniffi-bindgen binary builds**

Run: `cargo build -p filer-crypto-uniffi --bin uniffi-bindgen`
Expected: exits 0; binary at `target/debug/uniffi-bindgen`.

- [ ] **Step 9: Commit**

```bash
git add Cargo.lock crates/filer-crypto-uniffi
git commit -m "feat(uniffi): scaffold filer-crypto-uniffi binding crate"
```

---

## Task 10: UDL + UniFFI binding implementation

**Files:**
- Modify: `crates/filer-crypto-uniffi/src/filer_crypto.udl`
- Modify: `crates/filer-crypto-uniffi/src/lib.rs`

Wire the `filer-crypto` public API through to UniFFI types.

- [ ] **Step 1: Write the full UDL**

Replace `crates/filer-crypto-uniffi/src/filer_crypto.udl`:

```
namespace filer_crypto {
    sequence<u8> generate_master_secret();

    [Throws=FilerCryptoError]
    string secret_to_phrase(sequence<u8> secret);

    [Throws=FilerCryptoError]
    sequence<u8> phrase_to_secret(string phrase);

    [Throws=FilerCryptoError]
    void verify_signature(sequence<u8> public_key, sequence<u8> nonce, sequence<u8> signature);
};

[Error]
enum FilerCryptoError {
    "Aead",
    "InvalidPhrase",
    "InvalidKeyLength",
    "InvalidSignature",
    "Randomness",
};

dictionary EncryptedBlob {
    sequence<u8> ciphertext;
    sequence<u8> iv;
    sequence<u8> wrapped_key;
};

dictionary EncryptedField {
    sequence<u8> ciphertext;
    sequence<u8> iv;
};

dictionary DeviceSignature {
    sequence<u8> bytes;
};

interface Vault {
    [Throws=FilerCryptoError, Name=open]
    constructor(sequence<u8> master_secret);

    [Throws=FilerCryptoError, Name=from_recovery_phrase]
    constructor(string phrase);

    [Throws=FilerCryptoError]
    EncryptedBlob encrypt_blob(sequence<u8> plaintext);

    [Throws=FilerCryptoError]
    sequence<u8> decrypt_blob(EncryptedBlob blob);

    [Throws=FilerCryptoError]
    EncryptedField encrypt_metadata_field(sequence<u8> plaintext);

    [Throws=FilerCryptoError]
    sequence<u8> decrypt_metadata_field(EncryptedField field);

    DeviceSignature sign_challenge(sequence<u8> nonce);

    sequence<u8> device_public_key();
};
```

- [ ] **Step 2: Write the lib.rs wrapper**

Replace `crates/filer-crypto-uniffi/src/lib.rs`:

```rust
//! UniFFI binding layer for filer-crypto.
//!
//! Each UDL type is mirrored here as a thin Rust type. The `Vault` interface
//! becomes a struct holding the core `filer_crypto::Vault` behind a Mutex.
//! UniFFI interfaces require `Send + Sync`; the core Vault is already both,
//! but the Mutex insulates us if any future addition to the core introduces
//! interior mutability that breaks Sync. Lock contention is negligible
//! because crypto operations are short.
//!
//! Byte arrays cross the FFI as `Vec<u8>`. We validate fixed-length inputs
//! (32-byte secrets, 32-byte public keys, 64-byte signatures) inside the
//! wrapper and return `FilerCryptoError::InvalidKeyLength` on mismatch.

use std::sync::Mutex;

use filer_crypto::{
    DeviceSignature as CoreDeviceSignature, EncryptedBlob as CoreEncryptedBlob,
    EncryptedField as CoreEncryptedField, FilerCryptoError, Result, Vault as CoreVault, recovery,
};

uniffi::include_scaffolding!("filer_crypto");

// --- top-level functions ---

fn generate_master_secret() -> Vec<u8> {
    recovery::generate_master_secret().to_vec()
}

fn secret_to_phrase(secret: Vec<u8>) -> Result<String> {
    let array: [u8; 32] = secret
        .try_into()
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    recovery::secret_to_phrase(&array)
}

fn phrase_to_secret(phrase: String) -> Result<Vec<u8>> {
    recovery::phrase_to_secret(&phrase).map(|s| s.to_vec())
}

fn verify_signature(public_key: Vec<u8>, nonce: Vec<u8>, signature: Vec<u8>) -> Result<()> {
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    filer_crypto::verify_signature(&pk, &nonce, &sig)
}

// --- envelope dictionaries ---

#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

impl From<CoreEncryptedBlob> for EncryptedBlob {
    fn from(b: CoreEncryptedBlob) -> Self {
        Self {
            ciphertext: b.ciphertext,
            iv: b.iv.to_vec(),
            wrapped_key: b.wrapped_key,
        }
    }
}

impl TryFrom<EncryptedBlob> for CoreEncryptedBlob {
    type Error = FilerCryptoError;
    fn try_from(b: EncryptedBlob) -> Result<Self> {
        let iv: [u8; 12] = b
            .iv
            .try_into()
            .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
        Ok(CoreEncryptedBlob {
            ciphertext: b.ciphertext,
            iv,
            wrapped_key: b.wrapped_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

impl From<CoreEncryptedField> for EncryptedField {
    fn from(f: CoreEncryptedField) -> Self {
        Self {
            ciphertext: f.ciphertext,
            iv: f.iv.to_vec(),
        }
    }
}

impl TryFrom<EncryptedField> for CoreEncryptedField {
    type Error = FilerCryptoError;
    fn try_from(f: EncryptedField) -> Result<Self> {
        let iv: [u8; 12] = f
            .iv
            .try_into()
            .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
        Ok(CoreEncryptedField {
            ciphertext: f.ciphertext,
            iv,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DeviceSignature {
    pub bytes: Vec<u8>,
}

impl From<CoreDeviceSignature> for DeviceSignature {
    fn from(s: CoreDeviceSignature) -> Self {
        Self {
            bytes: s.bytes.to_vec(),
        }
    }
}

// --- Vault interface ---

pub struct Vault {
    inner: Mutex<CoreVault>,
}

impl Vault {
    pub fn open(master_secret: Vec<u8>) -> Result<Self> {
        let array: [u8; 32] = master_secret
            .try_into()
            .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
        let core = CoreVault::open(&array)?;
        Ok(Self {
            inner: Mutex::new(core),
        })
    }

    pub fn from_recovery_phrase(phrase: String) -> Result<Self> {
        let core = CoreVault::from_recovery_phrase(&phrase)?;
        Ok(Self {
            inner: Mutex::new(core),
        })
    }

    pub fn encrypt_blob(&self, plaintext: Vec<u8>) -> Result<EncryptedBlob> {
        let core_blob = self.inner.lock().unwrap().encrypt_blob(&plaintext)?;
        Ok(core_blob.into())
    }

    pub fn decrypt_blob(&self, blob: EncryptedBlob) -> Result<Vec<u8>> {
        let core_blob: CoreEncryptedBlob = blob.try_into()?;
        self.inner.lock().unwrap().decrypt_blob(&core_blob)
    }

    pub fn encrypt_metadata_field(&self, plaintext: Vec<u8>) -> Result<EncryptedField> {
        let core_field = self
            .inner
            .lock()
            .unwrap()
            .encrypt_metadata_field(&plaintext)?;
        Ok(core_field.into())
    }

    pub fn decrypt_metadata_field(&self, field: EncryptedField) -> Result<Vec<u8>> {
        let core_field: CoreEncryptedField = field.try_into()?;
        self.inner.lock().unwrap().decrypt_metadata_field(&core_field)
    }

    pub fn sign_challenge(&self, nonce: Vec<u8>) -> DeviceSignature {
        self.inner.lock().unwrap().sign_challenge(&nonce).into()
    }

    pub fn device_public_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().device_public_key().to_vec()
    }
}
```

- [ ] **Step 3: Build the binding crate**

Run: `cargo build -p filer-crypto-uniffi`
Expected: exits 0. Some warnings about unused imports or types are acceptable on first build — fix only if they're errors.

- [ ] **Step 4: Lint + format**

Run: `cargo clippy -p filer-crypto-uniffi -- -D warnings && cargo fmt --check`
Expected: both exit 0. If clippy flags unused imports, remove them.

- [ ] **Step 5: Verify the whole workspace tests pass**

Run: `cargo test --workspace`
Expected: 36 tests pass (all from `filer-crypto`; the binding crate has no tests yet).

- [ ] **Step 6: Commit**

```bash
git add crates/filer-crypto-uniffi
git commit -m "feat(uniffi): expose Vault and recovery functions via UDL"
```

---

## Task 11: scripts/build.sh

**Files:**
- Create: `scripts/build.sh`
- Create: `scripts/README.md`

The build script compiles the Rust libraries and regenerates `Sources/FilerCrypto/FilerCrypto.swift` from the UDL. It's invoked by the mobile app's `with-crypto-core` plugin when consuming `filer-crypto` via local path (`FILER_CRYPTO_LOCAL=1`).

- [ ] **Step 1: Create `scripts/build.sh`**

```bash
#!/usr/bin/env bash
#
# Build the filer-crypto Rust libraries and regenerate the Swift bindings.
#
# Usage: ./scripts/build.sh [release|debug]   (default: release)
#
# Outputs:
#   - target/{release,debug}/libfiler_crypto.{a,dylib,so}
#   - Sources/FilerCrypto/FilerCrypto.swift  (regenerated)
#
set -euo pipefail

PROFILE="${1:-release}"
if [[ "$PROFILE" != "release" && "$PROFILE" != "debug" ]]; then
    echo "Usage: $0 [release|debug]" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "→ Building Rust libraries ($PROFILE)..."
if [[ "$PROFILE" == "release" ]]; then
    cargo build --release --workspace
    LIB_DIR="$ROOT/target/release"
else
    cargo build --workspace
    LIB_DIR="$ROOT/target/debug"
fi

echo "→ Regenerating Swift bindings..."
mkdir -p Sources/FilerCrypto
cargo run --quiet --package filer-crypto-uniffi --bin uniffi-bindgen -- \
    generate \
    --library "$LIB_DIR/libfiler_crypto.dylib" \
    --language swift \
    --out-dir Sources/FilerCrypto

echo "✓ Build complete."
echo "  Library:  $LIB_DIR/libfiler_crypto.{a,dylib}"
echo "  Bindings: $ROOT/Sources/FilerCrypto/FilerCrypto.swift"
```

Note: on Linux the dylib has `.so` extension; on macOS, `.dylib`. The `--library` flag expects the platform-native shared library. The script uses `.dylib` because development is on macOS. CI runs on Linux but does NOT regenerate bindings — it only runs `cargo test`. Bindings are committed and regenerated by developers manually before pushing.

- [ ] **Step 2: Make the script executable**

Run: `chmod +x scripts/build.sh`

- [ ] **Step 3: Create `scripts/README.md`**

```markdown
# Build scripts

## `build.sh`

Compiles the Rust libraries and regenerates `Sources/FilerCrypto/FilerCrypto.swift`.

Run after any change to:
- `crates/filer-crypto/src/**/*.rs` (core API changes that affect the UDL)
- `crates/filer-crypto-uniffi/src/filer_crypto.udl` (binding surface)
- `crates/filer-crypto-uniffi/src/lib.rs` (binding implementations)

The regenerated `FilerCrypto.swift` should be committed alongside the changes
that triggered the regeneration — diffs in the binding surface are part of
PR review.

```bash
./scripts/build.sh           # release build (default)
./scripts/build.sh debug     # debug build (faster compile, slower runtime)
```
```

- [ ] **Step 4: Run the build script**

Run: `./scripts/build.sh debug`
Expected: builds the workspace, then runs uniffi-bindgen and produces `Sources/FilerCrypto/FilerCrypto.swift` (and probably `filer_cryptoFFI.modulemap` and `filer_cryptoFFI.h` too — the modulemap and header are normal outputs).

Note: if the script fails because the dylib hasn't been built, it's likely a path issue. Inspect the contents of `target/debug/` and ensure `libfiler_crypto.dylib` exists. On Linux you'll need to change `.dylib` → `.so` in the script.

- [ ] **Step 5: Verify the bindings file was produced**

Run: `ls -la Sources/FilerCrypto/`
Expected: at least `FilerCrypto.swift` (and likely a modulemap + header).

- [ ] **Step 6: Commit (without the generated bindings — those land in Task 12)**

```bash
git add scripts/
git commit -m "chore: add build script for Rust libs + Swift bindings"
```

---

## Task 12: Commit generated Swift bindings

**Files:**
- Create: `Sources/FilerCrypto/FilerCrypto.swift` (output of Task 11)
- Possibly create: `Sources/FilerCrypto/filer_cryptoFFI.modulemap`
- Possibly create: `Sources/FilerCrypto/filer_cryptoFFI.h`

- [ ] **Step 1: Re-run the build script to make sure outputs are fresh**

Run: `./scripts/build.sh debug`
Expected: success.

- [ ] **Step 2: Inspect the produced files**

Run: `ls -la Sources/FilerCrypto/`
Expected files:
- `FilerCrypto.swift` (the Swift API)
- `filer_cryptoFFI.modulemap` (Swift module map for the FFI symbols)
- `filer_cryptoFFI.h` (C header)

If any of these are missing, the uniffi-bindgen invocation in `scripts/build.sh` may need adjustment — typically `--language swift` produces all three. Note the deviation in the report if you have to adjust the invocation.

- [ ] **Step 3: Sanity-check the Swift file**

Run: `head -50 Sources/FilerCrypto/FilerCrypto.swift`
Expected: a Swift file that imports `filer_cryptoFFI`, declares `enum FilerCryptoError: Error`, `struct EncryptedBlob`, `struct EncryptedField`, `struct DeviceSignature`, and `class Vault` with the constructors and methods defined in the UDL.

- [ ] **Step 4: Commit**

```bash
git add Sources/
git commit -m "feat(swift): add generated UniFFI bindings"
```

---

## Task 13: Package.swift

**Files:**
- Create: `Package.swift`

The Swift Package manifest. For v0.1.0 this is a source-Swift target that exposes the generated bindings. The actual Rust artifact linking is deferred to the XCFramework follow-up. SPM consumers can `swift package describe` it; they can't `swift build` it until the XCFramework lands.

- [ ] **Step 1: Create `Package.swift`**

```swift
// swift-tools-version:5.9
//
// This Package.swift is intentionally minimal for v0.1.0.
//
// The Swift target wraps the UniFFI-generated bindings in
// Sources/FilerCrypto/FilerCrypto.swift. Linking against the Rust
// shared library (the FFI implementation that the generated bindings
// call into) is NOT wired up here — that happens via a .binaryTarget
// referencing a built XCFramework once we tag the first release.
//
// Consumers who need a working build today should use the mobile app's
// with-crypto-core plugin in local-path mode (FILER_CRYPTO_LOCAL=1),
// which invokes scripts/build.sh and arranges the linking via the Xcode
// project plugin.

import PackageDescription

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
    targets: [
        .target(
            name: "FilerCrypto",
            path: "Sources/FilerCrypto",
            // The generated FilerCrypto.swift imports `filer_cryptoFFI` (the
            // C-callable shim). The modulemap + header in this directory
            // declare that module; SPM picks them up via publicHeadersPath.
            publicHeadersPath: "."
        ),
        .testTarget(
            name: "FilerCryptoTests",
            dependencies: ["FilerCrypto"],
            path: "Tests/FilerCryptoTests"
        ),
    ]
)
```

- [ ] **Step 2: Verify SPM can parse and describe it**

Run: `swift package describe`
Expected: output lists the `FilerCrypto` library product, the `FilerCrypto` target, and the `FilerCryptoTests` test target.

If it errors complaining about missing files, the issue is most likely the `publicHeadersPath` or the absence of the modulemap that uniffi-bindgen should have produced in Task 11. Verify those files exist in `Sources/FilerCrypto/`. If they don't, regenerate via `./scripts/build.sh debug` and re-run.

- [ ] **Step 3: Commit**

```bash
git add Package.swift
git commit -m "feat(swift): add Package.swift manifest"
```

---

## Task 14: Tests/FilerCryptoTests placeholder

**Files:**
- Create: `Tests/FilerCryptoTests/FilerCryptoTests.swift`

The Swift test target exists so SPM treats the package as testable. It's a single placeholder test that skips itself when the underlying FFI artifact isn't built. The real parity suite lands with the XCFramework follow-up.

- [ ] **Step 1: Create the placeholder test**

```swift
import XCTest
@testable import FilerCrypto

final class FilerCryptoTests: XCTestCase {
    /// Placeholder test for v0.1.0 scaffolding. The FFI shared library is not
    /// linked through SPM yet — see Package.swift and CLAUDE.md. When the
    /// XCFramework follow-up lands, this skip goes away and real parity tests
    /// replace it.
    func testPlaceholder() throws {
        throw XCTSkip("FFI library not yet wired through SPM; real tests land with XCFramework")
    }
}
```

- [ ] **Step 2: Verify SPM sees the test target**

Run: `swift package describe | grep -A2 FilerCryptoTests`
Expected: test target appears in the output.

(Don't run `swift test` — it will fail at link time because the FFI lib isn't wired through SPM yet. That's expected and explicitly out of scope for this scaffolding pass.)

- [ ] **Step 3: Commit**

```bash
git add Tests/
git commit -m "test(swift): add placeholder FilerCryptoTests target"
```

---

## Task 15: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

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
```

- [ ] **Step 2: Verify locally**

Run, in order:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
Expected: each exits 0.

- [ ] **Step 3: Commit**

```bash
git add .github
git commit -m "ci: run fmt, clippy, and tests on push and PR"
```

---

## Task 16: README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create `README.md`**

```markdown
# filer-crypto

Open-source cryptographic core for [Filer](https://github.com/CorvidSoft/filer)
— a zero-knowledge document vault for iPhone.

MIT-licensed. Pure Rust. Auditable in isolation from the rest of the app.

## What this crate provides

- **Envelope encryption** for documents (AES-256-GCM with per-blob random data
  keys, wrapped under a master key derived from a 256-bit secret)
- **Field-level metadata encryption** (AES-256-GCM, used for sensitive SQLite
  columns on the device)
- **Key derivation** (HKDF-SHA256 from a 32-byte master secret to all subkeys)
- **24-word BIP39 recovery phrase** ↔ master secret
- **Ed25519 device challenge-response signing** for backend authentication

The public API is a single `Vault` type plus a few stateless functions in
the `recovery` module. See [`crates/filer-crypto/src/lib.rs`](crates/filer-crypto/src/lib.rs).

## Building

```bash
cargo build --workspace
cargo test --workspace
```

To regenerate the Swift bindings after a UDL or binding-layer change:

```bash
./scripts/build.sh
```

This produces `Sources/FilerCrypto/FilerCrypto.swift` from the UDL definition
in `crates/filer-crypto-uniffi/src/filer_crypto.udl`. The regenerated file is
committed alongside the change that triggered it.

## Consuming from Swift

The repo is shaped as a Swift Package. For v0.1.0 the package is
source-only — there is no pre-built XCFramework yet. The mobile app
that consumes this crate handles linking via an Expo config plugin
(`with-crypto-core` in the closed-source Filer mobile repo).

When the first device-build milestone arrives, this repo will publish a
pre-built XCFramework as an SPM `.binaryTarget` so external consumers can
link without a Rust toolchain.

## Architecture notes

See [docs/superpowers/specs/](docs/superpowers/specs/) for the design
that drove this crate's structure.

The architectural commitment is described in the
[parent Filer DESIGN.md §4](https://github.com/CorvidSoft/filer/blob/main/docs/DESIGN.md):
documents never leave the user's device in plaintext, and the backend
never possesses key material. This crate is the structural guard of that
commitment.

## Reporting security issues

Email security@corvid.boo. Do not file public GitHub issues for security
matters.

## License

MIT — see [LICENSE](LICENSE).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```

---

## Task 17: CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

Implements spec §4.9.

- [ ] **Step 1: Create `CLAUDE.md`**

```markdown
# filer-crypto — agent guide

`filer-crypto` is the open-source cryptographic core for [Filer](https://github.com/CorvidSoft/filer) — an iOS zero-knowledge document vault. This crate ships envelope encryption, key derivation, recovery-phrase encoding, and device signing primitives that the Filer iOS app links against via a Swift Package.

Most day-to-day work in this repo does NOT require reading the parent Filer DESIGN.md. The invariants and contracts below are enough.

## Hard invariants — do not violate

1. **Never log key material, master secrets, or signatures.** Not in `println!`, not in test assertions, not in error messages, not in `Debug` impls of structs that hold key material. The `FilerCryptoError` variants are intentionally coarse to prevent leakage.

2. **Stay in the RustCrypto family.** No `ring`, no `openssl`, no `rustls`. The dependency tree is intentionally small and audit-friendly. Adding a non-RustCrypto crypto dep requires explicit justification (open an issue first).

3. **Key-bearing types zeroize on drop.** Any new type that holds key material or master secrets must `Zeroize` its fields in `Drop`. The `Vault` is the canonical example. Adding such a type without `Drop`-zeroize is a bug.

4. **Constant-time comparisons for secrets.** Use the `subtle` crate's `ConstantTimeEq` (or just rely on AES-GCM's tag verification, which is constant-time) when comparing MAC tags, signatures, or anything else where a timing side channel would leak information.

5. **No `panic!`/`unwrap()`/`expect()` on external input.** Functions exposed at the FFI boundary (anything in `filer-crypto-uniffi` or the `pub` surface of `filer-crypto`) must return `Result<_, FilerCryptoError>` on bad input. Internal helpers may unwrap when the invariant is provable from the immediate caller.

6. **MIT-compatible deps only.** The crate is MIT. New deps must be MIT, Apache-2.0, BSD, or compatible. No GPL.

7. **Envelope formats are stable wire format.** `EncryptedBlob` and `EncryptedField` structs are part of the contract with the consuming Filer app. Changing field names, lengths, ordering, or the wrapped-key layout is a major-version compatibility break — every existing user's vault becomes undecryptable.

## Repo map

- `crates/filer-crypto/` — pure-Rust core. Public API is `Vault` in `vault.rs` + stateless functions in `recovery.rs`.
- `crates/filer-crypto-uniffi/` — UniFFI binding layer. Thin wrappers over the core that the Swift package consumes.
- `Package.swift` + `Sources/FilerCrypto/` — Swift Package manifest + UniFFI-generated Swift bindings (regenerated by `scripts/build.sh`).
- `Tests/FilerCryptoTests/` — Swift parity test placeholder. Real tests land with the XCFramework follow-up.
- `scripts/build.sh` — builds the Rust libs and regenerates the Swift bindings.
- `docs/superpowers/` — design specs and implementation plans.

## Tech stack

- Rust edition 2024
- RustCrypto: `aes-gcm` 0.10, `hkdf` 0.12, `sha2` 0.10
- `ed25519-dalek` 2.1 (signing)
- `bip39` 2.0 (recovery phrase)
- `zeroize` 1.7, `subtle` 2.5
- `thiserror` 2.0
- UniFFI 0.28
- Swift 5.9+ (Swift Package consumers)

## Common commands

\`\`\`bash
cargo build --workspace
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
./scripts/build.sh             # rebuild Rust libs + regenerate Swift bindings
./scripts/build.sh debug       # same, debug profile
swift package describe         # verify Package.swift parses
\`\`\`

## Public API surface

The Filer iOS app sees exactly:

- `filer_crypto::Vault` (and its methods)
- `filer_crypto::recovery::{generate_master_secret, secret_to_phrase, phrase_to_secret}`
- The envelope structs `EncryptedBlob`, `EncryptedField`, `DeviceSignature`
- `FilerCryptoError`

If a symbol isn't `pub` from `crates/filer-crypto/src/lib.rs`, it isn't part of the Swift API. The UDL in `crates/filer-crypto-uniffi/src/filer_crypto.udl` mirrors this surface and is the source of truth for what's actually exposed.

## Adding a new primitive

1. Implement in its own module under `crates/filer-crypto/src/`.
2. Add round-trip tests + a known-answer test if standard vectors exist.
3. Expose via `Vault` methods (preferred) or as a free function in `recovery.rs` (only if it's stateless and key-free).
4. Update `crates/filer-crypto-uniffi/src/filer_crypto.udl` and `lib.rs` to mirror the new surface.
5. Regenerate bindings: `./scripts/build.sh`.
6. Commit the regenerated `Sources/FilerCrypto/FilerCrypto.swift` alongside the Rust changes.

## What not to add

- **No async.** UniFFI sync is fine for v1; async adds FFI complexity for no payoff in our use cases (encrypt/decrypt are fast).
- **No custom serialization formats.** Envelopes are simple structs of `Vec<u8>` + fixed-size byte arrays. Don't add CBOR, protobuf, or anything else.
- **No extra binding targets in this repo.** Android and Wasm bindings, if/when needed, live in separate crates added to the workspace. The core crate stays binding-agnostic.
- **No panicking on user input.** See invariant #5.

## Reporting security issues

Email security@corvid.boo. Do not file public GitHub issues for security matters.
```

(Note: the code block above uses escaped backticks. When you create the file, use real backticks.)

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add CLAUDE.md agent guide"
```

---

## Task 18: Acceptance verification

Walk through every acceptance criterion from spec §7 and confirm it passes. Fix anything that fails and commit fixes before moving on.

- [ ] **Step 1: AC #1 — `cargo build --workspace` from clean clone**

```bash
cargo clean
cargo build --workspace
```
Expected: succeeds, no errors.

- [ ] **Step 2: AC #2 — `cargo test --workspace`**

Run: `cargo test --workspace`
Expected: all tests in `filer-crypto` pass (36 total: 3 kdf + 6 recovery + 8 blob + 5 metadata + 6 auth + 8 vault). `filer-crypto-uniffi` has no tests, that's fine.

- [ ] **Step 3: AC #3 — `cargo fmt --check` and `cargo clippy`**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: both exit 0.

- [ ] **Step 4: AC #4 — `scripts/build.sh` produces the bindings**

```bash
rm -rf Sources/FilerCrypto/*.swift Sources/FilerCrypto/*.modulemap Sources/FilerCrypto/*.h
./scripts/build.sh debug
ls Sources/FilerCrypto/
```
Expected: `FilerCrypto.swift` (and modulemap + header) are recreated.

- [ ] **Step 5: AC #5 + #6 — Vault and recovery API surface match the spec**

Run: `grep -E "pub (fn|struct|enum|impl)" crates/filer-crypto/src/lib.rs crates/filer-crypto/src/vault.rs crates/filer-crypto/src/recovery.rs`
Expected output includes:
- `pub struct Vault`
- `pub fn open` on Vault
- `pub fn from_recovery_phrase` on Vault
- `pub fn encrypt_blob`, `decrypt_blob`, `encrypt_metadata_field`, `decrypt_metadata_field`, `sign_challenge`, `device_public_key`
- `pub fn generate_master_secret`, `pub fn secret_to_phrase`, `pub fn phrase_to_secret`

- [ ] **Step 6: AC #7 — `swift package describe` works**

Run: `swift package describe`
Expected: lists `FilerCrypto` library and target.

- [ ] **Step 7: AC #8 — CI workflow passes**

Push the branch and open a PR; wait for the CI job to go green.

If CI fails: most likely cause is a Linux-specific issue (e.g., `.dylib` vs `.so` in the build script — though the script isn't run in CI, so this is fine). Investigate the actual error and fix.

- [ ] **Step 8: AC #9 — mobile app's `with-crypto-core` plugin stops skipping**

This is a sibling-repo check. With this scaffolding in place:

1. The crypto core repo at `../filer-crypto` now has a `Package.swift`.
2. In the mobile repo, run: `FILER_CRYPTO_LOCAL=1 pnpm --filter @filer/mobile native:prebuild:clean`
3. Expected: the `with-crypto-core` plugin no longer logs the "no Package.swift" warning. Whether the actual SPM injection succeeds is the next phase; this AC only requires the skip branch to stop triggering.

Note: this is a manual cross-repo check. If the mobile repo isn't readily available, mark this AC as "deferred to first cross-repo integration" and proceed.

- [ ] **Step 9: AC #10 — README documents what's required**

Read `README.md`. Confirm it covers:
- What the crate is
- Build commands (`cargo build`, `cargo test`, `scripts/build.sh`)
- Where to file security issues

If anything is missing, fix and re-commit.

- [ ] **Step 10: AC #11 — CLAUDE.md acid test**

Read only `CLAUDE.md` (no spec, no DESIGN.md). Confirm you can answer:
- What must never appear in logs? → Key material, master secrets, signatures.
- Which crypto crate family is allowed? → RustCrypto family (no `ring`/`openssl`/`rustls`).
- What's the `Vault` public API contract? → Two constructors (`open` from secret, `from_recovery_phrase`), four encrypt/decrypt methods (blob/metadata bidirectional), `sign_challenge`, `device_public_key`.

If any answer is unclear from CLAUDE.md alone, edit it.

- [ ] **Step 11: Final commit (if any fixes were needed)**

```bash
git add -A
git commit -m "chore: address acceptance verification findings"
```

- [ ] **Step 12: Mark plan complete**

The scaffolding is done. Push the branch:

```bash
git push -u origin feat/crate-scaffolding
```

Open a PR and let CI run.

---

## Notes for the executing agent

- **TDD discipline matters here more than usual.** This is cryptographic code; correctness is the product. Every primitive gets round-trip tests, every encryption gets tamper-detection tests, every KDF call gets determinism tests. Don't shortcut.

- **The `.dylib`/`.so` difference between macOS and Linux** affects `scripts/build.sh` only. CI doesn't run that script; it only runs `cargo test`. Developers running the script need to be on macOS or adapt the extension.

- **`scripts/build.sh debug` first.** The release profile takes much longer for the first build. Use debug while iterating, release before committing the generated `FilerCrypto.swift` if you want to verify it matches what release would produce.

- **`cargo run --bin uniffi-bindgen` is the recommended invocation.** UniFFI 0.28 ships its own bindgen as a library; embedding it in `crates/filer-crypto-uniffi/src/bin/uniffi-bindgen.rs` means consumers never need `cargo install uniffi-bindgen`.

- **The `Mutex` around `CoreVault` in the binding layer is a UniFFI requirement.** UniFFI interfaces must be `Send + Sync`; `CoreVault` is `Send` but not `Sync` because of the SigningKey internals. The Mutex is the standard workaround.

- **If a test seems "too obvious" — write it anyway.** "encrypt then decrypt equals original" is the cheapest, most valuable test in this crate.
