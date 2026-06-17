#!/usr/bin/env bash
#
# Emit the GitHub Release body for a filum-crypto tag.
#
# Usage: ./scripts/release-notes.sh <xcframework-sha256> [filumcrypto-swift-sha256]
#
# The second argument is optional: when supplied, the Artifacts section also
# lists the standalone FilumCrypto.swift asset (the generated high-level Swift
# API) with its download URL + sha256. The release workflow always supplies it;
# manual recovery invocations may pass only the XCFramework sha.
#
# Reads $GITHUB_REF_NAME from the environment (set by GitHub Actions
# on tag pushes); falls back to `git describe` for manual invocation.
#
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <xcframework-sha256> [filumcrypto-swift-sha256]" >&2
    exit 2
fi

SHA256="$1"
SWIFT_SHA256="${2:-}"
TAG="${GITHUB_REF_NAME:-$(git describe --tags --abbrev=0 2>/dev/null || echo "vX.Y.Z")}"

INTRO="Pre-built XCFramework for iOS device + simulator."
ARTIFACTS="- \`FilumCryptoFFI.xcframework.zip\` — compiled core + bundled C header & modulemap
  - sha256: \`$SHA256\`"

if [[ -n "$SWIFT_SHA256" ]]; then
    INTRO="Pre-built XCFramework for iOS device + simulator, plus the generated high-level Swift API."
    ARTIFACTS="$ARTIFACTS
- \`FilumCrypto.swift\` — generated high-level Swift API; download alongside the XCFramework
  - url: \`https://github.com/CorvidSoft/filum-crypto/releases/download/$TAG/FilumCrypto.swift\`
  - sha256: \`$SWIFT_SHA256\`"
fi

cat <<EOF
## filum-crypto $TAG

$INTRO

### Consume via Swift Package Manager

\`\`\`swift
.binaryTarget(
    name: "FilumCryptoFFI",
    url: "https://github.com/CorvidSoft/filum-crypto/releases/download/$TAG/FilumCryptoFFI.xcframework.zip",
    checksum: "$SHA256"
)
\`\`\`

### Artifacts

$ARTIFACTS

See [\`docs/VERSIONING.md\`](https://github.com/CorvidSoft/filum-crypto/blob/main/docs/VERSIONING.md) for the semver policy.
EOF
