# filer-crypto

Open-source cryptographic core for [Filer](https://github.com/CorvidSoft/filer) — a zero-knowledge document vault for iPhone.

MIT-licensed. Pure Rust. Auditable in isolation from the rest of the app.

## What this crate provides

- **Envelope encryption** for documents — AES-256-GCM with per-blob random data keys, wrapped under a master key derived from a 256-bit secret
- **Field-level metadata encryption** — AES-256-GCM, used for sensitive SQLite columns on the device
- **Key derivation** — HKDF-SHA256 from a 32-byte master secret to all subkeys
- **24-word BIP39 recovery phrase** ↔ master secret
- **Ed25519 device challenge-response signing** for backend authentication

The public API is a single `Vault` type plus a few stateless functions in the `recovery` module. See [`crates/filer-crypto/src/lib.rs`](crates/filer-crypto/src/lib.rs).

## Status

The crate is **functionally complete** for v0.1.0:

- `crates/filer-crypto/` — pure-Rust core, 38 tests passing
- `crates/filer-crypto-uniffi/` — UniFFI binding crate
- `Package.swift` + `Sources/FilerCrypto/` — Swift Package manifest + generated bindings
- `Tests/FilerCryptoTests/` — Swift test target (currently a single `XCTSkip` placeholder)

What's still ahead — pre-built XCFramework distribution, real Swift parity tests, Android/Wasm bindings — is tracked in [issue #3](https://github.com/CorvidSoft/filer-crypto/issues/3). Until the XCFramework lands, `swift build`/`swift test` will fail at link time; consumers wanting a working build should use the mobile app's `with-crypto-core` plugin in local-path mode.

## Building

```bash
cargo build --workspace
cargo test --workspace
```

To regenerate the Swift bindings after a UDL or binding-layer change:

```bash
./scripts/build.sh
```

This produces `Sources/FilerCrypto/FilerCrypto.swift` (and the matching `filer_cryptoFFI.h` + `.modulemap`) from the UDL definition in `crates/filer-crypto-uniffi/src/filer_crypto.udl`. The regenerated files are committed alongside the change that triggered them.

## Consuming from Swift

This repo is shaped as a Swift Package — `swift package describe` lists the `FilerCrypto` library product. SPM consumers will be able to add it as a dependency once the XCFramework release pipeline lands (see [issue #3](https://github.com/CorvidSoft/filer-crypto/issues/3)).

The closed-source Filer mobile app consumes this repo via an Expo config plugin (`with-crypto-core`) which handles the cross-repo SPM linking.

## Architecture notes

See [docs/superpowers/specs/](docs/superpowers/specs/) for the design that drove this crate's structure.

The architectural commitment is described in the [parent Filer DESIGN.md §4](https://github.com/CorvidSoft/filer/blob/main/docs/DESIGN.md): documents never leave the user's device in plaintext, and the backend never possesses key material. This crate is the structural guard of that commitment.

## Reporting security issues

Email security@corvid.boo. Do not file public GitHub issues for security matters.

## License

MIT — see [LICENSE](LICENSE).
