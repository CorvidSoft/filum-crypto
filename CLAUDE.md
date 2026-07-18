# filum-crypto — agent guide

`filum-crypto` is the open-source cryptographic core for [Filum](https://github.com/CorvidSoft/filum) — an iOS zero-knowledge document vault. This crate ships envelope encryption, key derivation, recovery-phrase encoding, and device signing primitives, exposed to Swift via a UniFFI binding crate and packaged as a Swift Package.

Most day-to-day work in this repo does NOT require reading the parent Filum DESIGN.md. The invariants and contracts below are enough.

## Hard invariants — do not violate

1. **Never log key material, master secrets, or signatures.** Not in `println!`, not in test assertions, not in error messages, not in `Debug` impls of structs that hold key material. The `FilumCryptoError` variants are intentionally coarse to prevent leakage.

2. **Stay in the RustCrypto family.** No `ring`, no `openssl`, no `rustls`. The dependency tree is intentionally small and audit-friendly. Adding a non-RustCrypto crypto dep requires explicit justification (open an issue first).

3. **Key-bearing values zeroize on drop.** Any `[u8; 32]` (or larger) that holds key material, master secret, or intermediate derivation output is wrapped in `zeroize::Zeroizing<_>` (the RAII guard) so it wipes on any return path, not just the happy path. Adding a key-bearing local without `Zeroizing` is a bug. `Vault`'s `wrap_key` and `metadata_key` fields are themselves `Zeroizing<[u8; 32]>`, which makes them non-`Copy` and auto-wipes on `Vault` drop without needing a manual `Drop` impl. `SigningKey` zeroizes via `ed25519-dalek`'s `zeroize` feature.

4. **Constant-time comparisons for secrets.** When comparing MAC tags, signatures, or any key-derived bytes, never use `==` — use `subtle::ConstantTimeEq` (the `subtle` crate is intentionally removed from deps until a path actually needs it; re-add then). AEAD tag verification is constant-time inside `aes-gcm`, so we rely on the AEAD API rather than manual tag comparison.

5. **No `panic!`/`unwrap()`/`expect()` on external input.** Functions exposed at the FFI boundary (`filum-crypto-uniffi` and the `pub` surface of `filum-crypto`) must return `Result<_, FilumCryptoError>` on bad input. Internal helpers may unwrap when the invariant is provable from the immediate caller. Randomness failures are propagated as `FilumCryptoError::Randomness` via `OsRng.try_fill_bytes`, not as panics — this applies all the way through the FFI: `generate_master_secret` in the UDL is `[Throws=FilumCryptoError]` and Swift callers must handle the throw.

6. **MIT-compatible deps only.** The crate is MIT. New deps must be MIT, Apache-2.0, BSD, or compatible. No GPL.

7. **Envelope formats are stable wire format.** The chunked blob envelope (framed bytes, header layout in `blob.rs`) and the `EncryptedField` struct are part of the contract with the consuming Filum app. Changing field names, lengths, ordering, or the wrapped-key layout (currently `IV(12) || GCM ciphertext+tag`) is a major-version compatibility break — every existing user's vault becomes undecryptable. Since v0.4.0 every envelope is also bound to caller-supplied context ids via AAD; the domain strings and canonical encoding in `aad.rs` are wire format under the same rule.

8. **HKDF context strings are wire format too.** `WRAP_CTX`, `METADATA_CTX`, `SIGN_CTX` in `kdf.rs` are frozen byte literals (see `kdf.rs` for the exact bytes — the `…-crypto/v1/{wrap,metadata,sign}` prefix is a permanent wire constant and is intentionally NOT rebranded; renaming it re-derives every key and bricks all vaults). Changing the bytes of any context string is equivalent to changing the master secret — all existing vaults become undecryptable. The `v1` segment exists so we can add `v2` context strings later without rotating the v1 ones.

9. **Binding crate stays on Rust edition 2021.** UniFFI's `udl_derive` generates blanket impls (`impl<UT> Lower<UT> for ...`) that violate Rust 2024's tightened orphan rules. The core crate stays on 2024; only the binding glue is downgraded. Don't try to "fix" this without a UniFFI release that supports edition 2024.

10. **New dependencies pin to the latest stable release.** When adding a dep (or accepting a transitive one as a workspace dep), check `cargo search <crate>` or crates.io first and use the latest. Don't copy the version from a plan, an example, or an existing Cargo.toml — those drift. Old versions sometimes hide bugs you'd otherwise hit, and the longer the lag, the bigger the surprise when you finally bump. This applies in both directions: bumping an existing dep also means picking the current latest, not the next minor up.

## Repo map

- `crates/filum-crypto/` — pure-Rust core. Public API is `Vault` in `vault.rs` + stateless functions in `recovery.rs`.
- `crates/filum-crypto-uniffi/` — UniFFI binding layer. UDL in `src/filum_crypto.udl`; Rust wrappers in `src/lib.rs`; embedded `uniffi-bindgen` CLI in `src/bin/`.
- `Sources/FilumCrypto/` — generated Swift bindings + C header + module map. Regenerated by `scripts/build.sh`; committed.
- `Package.swift` — Swift Package manifest. `swift package describe` works; `swift build` / `swift test` will fail at link time until the XCFramework follow-up lands (see [issue #3](https://github.com/CorvidSoft/filum-crypto/issues/3)).
- `Tests/FilumCryptoTests/` — Swift test target. Currently a single `XCTSkip` placeholder.
- `scripts/build.sh` — builds the workspace and regenerates Swift bindings via uniffi-bindgen.
- `docs/superpowers/` — design specs and implementation plans.
- `LICENSE` — MIT.

## Tech stack

- Rust edition 2024 (core) / edition 2021 (binding crate, per invariant #9)
- RustCrypto: `aes-gcm` 0.10, `hkdf` 0.13, `sha2` 0.11
- `ed25519-dalek` 2.1 (signing)
- `bip39` 2.0 (recovery phrase)
- `zeroize` 1.8
- `thiserror` 2.0
- UniFFI 0.31
- Swift 5.9+ (Swift Package consumers)

## Common commands

```bash
cargo build --workspace
cargo test --workspace                                  # 62 tests pass at HEAD
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
./scripts/build.sh           # rebuild Rust libs + regenerate Swift bindings (release)
./scripts/build.sh debug     # same, debug profile
swift package describe       # verify Package.swift parses
```

## Public API surface

The Filum iOS app sees exactly:

- `filum_crypto::Vault` (methods: `open`, `from_recovery_phrase`, `encrypt_blob(pt, blob_id)`, `decrypt_blob(framed, blob_id)`, `encrypt_file_to_blob(in, out, blob_id)`, `decrypt_blob_to_file(in, out, blob_id)`, `encrypt_metadata_field(pt, record_id, field_name)`, `decrypt_metadata_field(field, record_id, field_name)`, `sign_challenge`, `device_public_key`). The context ids are bound into the envelopes as AAD (format v2) — decryption under a different id fails as `Aead`.
- `filum_crypto::recovery::{generate_master_secret, secret_to_phrase, phrase_to_secret}`
- Envelope structs `EncryptedField`, `DeviceSignature`
- `FilumCryptoError`
- `verify_signature` (so the backend can use the same verification path)

If a symbol isn't `pub` from `crates/filum-crypto/src/lib.rs`, it isn't part of the Swift API. The UDL at `crates/filum-crypto-uniffi/src/filum_crypto.udl` is the source of truth for what's actually exposed across the FFI boundary.

## Adding a new primitive

1. Implement in its own module under `crates/filum-crypto/src/`.
2. Add round-trip tests + a known-answer test if standard vectors exist.
3. Expose via `Vault` methods (preferred) or as a free function in `recovery.rs` (only if it's stateless and key-free).
4. Update `crates/filum-crypto-uniffi/src/filum_crypto.udl` and `lib.rs` to mirror the new surface.
5. Regenerate Swift bindings: `./scripts/build.sh`.
6. Commit the regenerated `Sources/FilumCrypto/*` alongside the Rust changes.

## What not to add

- **No async.** UniFFI sync is fine for v1; async adds FFI complexity for no payoff in our use cases (encrypt/decrypt are fast).
- **No custom serialization formats.** Envelopes are simple structs of `Vec<u8>` + fixed-size byte arrays. Don't add CBOR, protobuf, or anything else.
- **No extra binding targets in this repo.** Android and Wasm bindings, when needed, live in separate sibling crates added to the workspace. The core crate stays binding-agnostic. See [issue #3](https://github.com/CorvidSoft/filum-crypto/issues/3).
- **No panicking on user input.** See invariant #5.

## What's still ahead

See [issue #3](https://github.com/CorvidSoft/filum-crypto/issues/3) for the tracked work — pre-built XCFramework distribution, real Swift parity tests, Android/Wasm bindings, fuzzing.

## Reporting security issues

Email security@corvid.boo. Do not file public GitHub issues for security matters.
