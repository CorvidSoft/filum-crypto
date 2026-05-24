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
