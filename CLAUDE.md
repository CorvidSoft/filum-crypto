# filer-crypto — agent guide

`filer-crypto` is the open-source cryptographic core for [Filer](https://github.com/CorvidSoft/filer) — an iOS zero-knowledge document vault. This crate ships envelope encryption, key derivation, recovery-phrase encoding, and device signing primitives. The Filer iOS app will eventually link against it via a Swift Package (binding layer still to land).

Most day-to-day work in this repo does NOT require reading the parent Filer DESIGN.md. The invariants and contracts below are enough.

## Hard invariants — do not violate

1. **Never log key material, master secrets, or signatures.** Not in `println!`, not in test assertions, not in error messages, not in `Debug` impls of structs that hold key material. The `FilerCryptoError` variants are intentionally coarse to prevent leakage.

2. **Stay in the RustCrypto family.** No `ring`, no `openssl`, no `rustls`. The dependency tree is intentionally small and audit-friendly. Adding a non-RustCrypto crypto dep requires explicit justification (open an issue first).

3. **Key-bearing values zeroize on drop.** Any `[u8; 32]` (or larger) that holds key material, master secret, or intermediate derivation output is wrapped in `zeroize::Zeroizing<_>` (the RAII guard) so it wipes on any return path, not just the happy path. Adding a key-bearing local without `Zeroizing` is a bug. `Vault`'s `wrap_key` and `metadata_key` fields are themselves `Zeroizing<[u8; 32]>`, which makes them non-`Copy` and auto-wipes on `Vault` drop without needing a manual `Drop` impl. `SigningKey` zeroizes via `ed25519-dalek`'s `zeroize` feature.

4. **Constant-time comparisons for secrets.** When comparing MAC tags, signatures, or any key-derived bytes, never use `==` — use `subtle::ConstantTimeEq` (the `subtle` crate is intentionally removed from deps until a path actually needs it; re-add then). AEAD tag verification is constant-time inside `aes-gcm`, so we rely on the AEAD API rather than manual tag comparison.

5. **No `panic!`/`unwrap()`/`expect()` on external input.** Functions exposed at the FFI boundary (the future `filer-crypto-uniffi` crate or the `pub` surface of `filer-crypto`) must return `Result<_, FilerCryptoError>` on bad input. Internal helpers may unwrap when the invariant is provable from the immediate caller. Randomness failures are propagated as `FilerCryptoError::Randomness` via `OsRng.try_fill_bytes`, not as panics.

6. **MIT-compatible deps only.** The crate is MIT. New deps must be MIT, Apache-2.0, BSD, or compatible. No GPL.

7. **Envelope formats are stable wire format.** `EncryptedBlob` and `EncryptedField` structs are part of the contract with the consuming Filer app. Changing field names, lengths, ordering, or the wrapped-key layout (currently `IV(12) || GCM ciphertext+tag`) is a major-version compatibility break — every existing user's vault becomes undecryptable.

8. **HKDF context strings are wire format too.** `WRAP_CTX`, `METADATA_CTX`, `SIGN_CTX` in `kdf.rs` are `filer-crypto/v1/{wrap,metadata,sign}`. Changing the bytes of any context string is equivalent to changing the master secret — all existing vaults become undecryptable. The `v1` segment exists so we can add `v2` context strings later without rotating the v1 ones.

## Repo map

- `crates/filer-crypto/` — pure-Rust core. Public API is `Vault` in `vault.rs` + stateless functions in `recovery.rs`.
- `crates/filer-crypto-uniffi/` — UniFFI binding layer. Currently a placeholder; full implementation lands in a follow-up PR.
- `docs/superpowers/` — design specs and implementation plans.
- `LICENSE` — MIT.

Files that will land in the follow-up PR: `Package.swift`, `Sources/FilerCrypto/`, `Tests/FilerCryptoTests/`, `scripts/build.sh`.

## Tech stack

- Rust edition 2024
- RustCrypto: `aes-gcm` 0.10, `hkdf` 0.12, `sha2` 0.10
- `ed25519-dalek` 2.1 (signing)
- `bip39` 2.0 (recovery phrase)
- `zeroize` 1.7
- `thiserror` 2.0
- UniFFI 0.29 (binding crate)
- Swift 5.9+ target (Swift Package consumers, follow-up)

## Common commands

```bash
cargo build --workspace
cargo test --workspace                                  # 39 tests pass at HEAD
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Public API surface

The Filer iOS app will see exactly:

- `filer_crypto::Vault` (and its methods: `open`, `from_recovery_phrase`, `encrypt_blob`, `decrypt_blob`, `encrypt_metadata_field`, `decrypt_metadata_field`, `sign_challenge`, `device_public_key`)
- `filer_crypto::recovery::{generate_master_secret, secret_to_phrase, phrase_to_secret}`
- The envelope structs `EncryptedBlob`, `EncryptedField`, `DeviceSignature`
- `FilerCryptoError`
- `verify_signature` (so the backend can also use the same verification path)

If a symbol isn't `pub` from `crates/filer-crypto/src/lib.rs`, it isn't part of the Swift API. When the UDL lands in the follow-up PR, it will mirror this surface and become the source of truth for what's actually exposed.

## Adding a new primitive

1. Implement in its own module under `crates/filer-crypto/src/`.
2. Add round-trip tests + a known-answer test if standard vectors exist.
3. Expose via `Vault` methods (preferred) or as a free function in `recovery.rs` (only if it's stateless and key-free).
4. (Follow-up PR will add) update the UDL and regenerate Swift bindings.

## What not to add

- **No async.** UniFFI sync is fine for v1; async adds FFI complexity for no payoff in our use cases (encrypt/decrypt are fast).
- **No custom serialization formats.** Envelopes are simple structs of `Vec<u8>` + fixed-size byte arrays. Don't add CBOR, protobuf, or anything else.
- **No extra binding targets in this repo.** Android and Wasm bindings, if/when needed, live in separate crates added to the workspace. The core crate stays binding-agnostic.
- **No panicking on user input.** See invariant #5.

## Reporting security issues

Email security@corvid.boo. Do not file public GitHub issues for security matters.
