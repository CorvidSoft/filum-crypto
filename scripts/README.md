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
