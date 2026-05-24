# Versioning

filer-crypto follows semver (MAJOR.MINOR.PATCH).

## The one rule that overrides everything else

Anything that changes the bytes a consumer's existing vault depends on
is a MAJOR bump. Existing vaults stop decrypting on a MAJOR bump — that
is the entire reason MAJOR exists in this crate.

## Classification

### MAJOR — existing vaults stop decrypting

- Envelope struct changes: field name / order / length in `EncryptedBlob`,
  `EncryptedField`, or `DeviceSignature`.
- Wrapped-key layout change (currently `IV(12) || GCM ciphertext+tag`).
- HKDF context strings (`WRAP_CTX`, `METADATA_CTX`, `SIGN_CTX` in `kdf.rs`).
  The `v1` in `filer-crypto/v1/...` exists so that v2 context strings can
  be added later without rotating the v1 ones — but adding a v2 context
  that an existing `Vault` produces is itself a MAJOR change to the
  produced envelopes. See `CLAUDE.md` invariant #8.
- Switching AEAD, KDF, signature scheme, or recovery-phrase wordlist.
- Removing or renaming any `pub` method on `Vault` or any `pub` free
  function exported through the UDL.

### MINOR — additive only

- New methods on `Vault` that don't change the meaning of existing ones.
- New free functions in `recovery.rs` or new modules.
- New error variants on `FilerCryptoError`. Adding variants is
  source-breaking for `match` consumers without a wildcard; we tolerate
  this as MINOR because the variants are intentionally coarse and
  external matchers should use a wildcard.
- New UDL surface that exposes already-public Rust API to Swift.

### PATCH — internal only

- Bug fixes that don't change envelope bytes or the public API.
- Dependency bumps within semver-compatible ranges.
- Documentation, CI, test-only changes.
- Performance improvements with byte-for-byte equivalent output.

## XCFramework + Swift Package versioning

The Swift Package version tracks the Rust crate version. A `v0.2.0` tag
produces a `v0.2.0` GitHub Release with an XCFramework artifact;
`Package.swift`'s `.binaryTarget` URL on `main` points at the latest
published release.

A pre-1.0 MAJOR bump (e.g. `0.1.0 → 0.2.0`) carries the same
break-the-vault implications as a post-1.0 MAJOR. Pre-1.0 does not mean
"we can break vaults silently" — it means "we haven't promised forward
compatibility yet."

## Release procedure

Releases are dispatched via GitHub Actions. The workflow builds the
XCFramework, computes the sha256, pins `Package.swift` to that value,
commits the pin, creates the tag, and publishes the GitHub Release —
all in one atomic run. The maintainer never touches `Package.swift`'s
URL or checksum directly; the tag always points at a commit whose
`Package.swift` matches the published artifact.

1. Open a PR that bumps `workspace.package.version` in `Cargo.toml`.
   Get it merged to `main`.
2. In the GitHub UI: **Actions → Release → Run workflow**. Enter the
   version (e.g. `0.1.1`) matching the `Cargo.toml` you just merged.
3. Wait for the workflow to complete (~10 min). It will:
   - Verify the input version matches `Cargo.toml`.
   - Verify the tag doesn't already exist.
   - Build the XCFramework on `macos-latest`.
   - Compute the sha256.
   - Update `Package.swift`'s `.binaryTarget` URL + checksum.
   - Commit (`chore: release v<X.Y.Z>`) to `main`.
   - Tag the commit and push.
   - Create the GitHub Release with the artifact.

### Why this flow

The XCFramework build is not byte-reproducible across CI runs (zip
embeds file mtimes that differ each checkout, xcodebuild's `Info.plist`
includes per-build metadata). That makes the "pre-compute the
checksum locally, embed it, tag, push" pattern unreliable — CI's
rebuild produces a different sha than the local pre-compute, and the
tag ends up with a Package.swift checksum that doesn't match the
published artifact.

By inverting the order — build first, then pin Package.swift to the
artifact's actual sha, then tag — the chicken-and-egg goes away
entirely.

### If the workflow fails partway through

The workflow runner is ephemeral, so only state pushed to `origin`
persists. The recovery table describes the **remote** state after each
failure point.

| Failed at | Remote state | Recovery |
|---|---|---|
| Build / checksum | No commit, no tag, no release published | Re-run the workflow |
| `git push origin HEAD:main` | No commit, no tag, no release published | Re-run; idempotent |
| `git push origin v<X.Y.Z>` | Pin commit on `main`, no tag, no release | Manually `git tag v<X.Y.Z> <pin-commit-sha>` and `git push origin v<X.Y.Z>`, then `gh release create v<X.Y.Z> --notes ...` with the artifact rebuilt locally, OR revert the pin commit and re-run the workflow |
| `gh release create` | Pin commit on `main`, tag exists, no release | Manually `gh release create v<X.Y.Z> build/...zip --notes "$(./scripts/release-notes.sh <sha256>)"` with a locally rebuilt artifact |

Branch-protection caveat: if `main` requires PR review, the workflow's
direct push will fail. Either configure the GitHub Actions bot to
bypass branch protection for this workflow, or move releases to a
dedicated `releases/*` branch.

## When in doubt

If a change *might* alter envelope bytes for any plausible input, run
the cross-language fixture tests (`Tests/FilerCryptoTests/Fixtures/`).
If they fail after your change, that's a MAJOR.
