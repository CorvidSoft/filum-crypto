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

This repository is in early development. The pure-Rust core (`crates/filer-crypto/`) is complete and tested. The UniFFI binding layer + Swift Package wrapper are scaffolded but not yet implemented — see [docs/superpowers/plans/](docs/superpowers/plans/).

## Building

```bash
cargo build --workspace
cargo test --workspace
```

## Consuming from Swift

This repo will be consumed as a Swift Package once the `Package.swift` manifest, UniFFI binding crate, and generated Swift bindings land in a follow-up PR. Right now, only the pure-Rust core is shipped — there is no SPM target to add yet.

When the binding layer ships, the mobile app will consume this repo via SPM. Its Expo config plugin (`with-crypto-core` in the closed-source Filer mobile repo) handles linking.

## Architecture notes

See [docs/superpowers/specs/](docs/superpowers/specs/) for the design that drove this crate's structure.

The architectural commitment is described in the [parent Filer DESIGN.md §4](https://github.com/CorvidSoft/filer/blob/main/docs/DESIGN.md): documents never leave the user's device in plaintext, and the backend never possesses key material. This crate is the structural guard of that commitment.

## Reporting security issues

Email security@corvid.boo. Do not file public GitHub issues for security matters.

## License

MIT — see [LICENSE](LICENSE).
