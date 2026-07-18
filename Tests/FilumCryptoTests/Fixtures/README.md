# Fixtures

Cross-language test vectors used by `CrossLanguageFixtureTests.swift` to
prove that a Rust-encrypted envelope decrypts correctly through the
Swift bindings — and that retired-format ciphertexts are rejected.

## Sentinel secret

All fixtures are produced from the all-zero master secret
(`[0u8; 32]`). This is the standard "obvious test vector" sentinel.
**Never use this secret for real keys** — anything encrypted with it is
trivially decryptable by anyone.

The all-zero secret was chosen over a real-looking random one
specifically because a misleading file that *looks* sensitive but is
public would be worse than an obviously-test value.

## Format-v2 fixtures (current)

`blob_v2.json` and `metadata_v2.json` carry the context ids they were
encrypted under — `blob_id` for the blob, `record_id` + `field_name`
for the metadata field (AAD context binding, format v2). The Swift
tests decrypt with exactly the ids embedded in the JSON; decrypting
under any other id must fail with `Aead`.

`signature_v1.json` is version-agnostic: signing is unchanged by the
v2 cutover, so the file keeps its original name.

## Format-v1 fixtures (frozen must-fail vectors)

`blob_v1.json` and `metadata_v1.json` are frozen v0.3.x ciphertexts
kept to prove the v1→v2 format cutover: v0.4.0 must REJECT them with
`Aead` (the v1 blob has version byte 1; the v1 field was encrypted
without the v2 AAD). They are must-fail vectors — **never regenerate,
overwrite, or delete them**. The generator intentionally writes only
the `*_v2.json` files (plus `signature_v1.json`).

## Regeneration

```sh
cargo test -p filum-crypto --test generate_fixtures -- --ignored --nocapture
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
