# Build scripts

## `build.sh`

Compiles the Rust libraries and regenerates `Sources/FilumCrypto/FilumCrypto.swift`.

Run after any change to:
- `crates/filum-crypto/src/**/*.rs` (core API changes that affect the UDL)
- `crates/filum-crypto-uniffi/src/filum_crypto.udl` (binding surface)
- `crates/filum-crypto-uniffi/src/lib.rs` (binding implementations)

The regenerated `FilumCrypto.swift` should be committed alongside the changes
that triggered the regeneration — diffs in the binding surface are part of
PR review.

```bash
./scripts/build.sh           # release build (default)
./scripts/build.sh debug     # debug build (faster compile, slower runtime)
```
