#!/usr/bin/env bash
#
# Emit the GitHub Release body for a filer-crypto tag.
#
# Usage: ./scripts/release-notes.sh <sha256>
#
# Reads $GITHUB_REF_NAME from the environment (set by GitHub Actions
# on tag pushes); falls back to `git describe` for manual invocation.
#
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <sha256>" >&2
    exit 2
fi

SHA256="$1"
TAG="${GITHUB_REF_NAME:-$(git describe --tags --abbrev=0 2>/dev/null || echo "vX.Y.Z")}"

cat <<EOF
## filer-crypto $TAG

Pre-built XCFramework for iOS device + simulator.

### Consume via Swift Package Manager

\`\`\`swift
.binaryTarget(
    name: "FilerCryptoFFI",
    url: "https://github.com/CorvidSoft/filer-crypto/releases/download/$TAG/FilerCryptoFFI.xcframework.zip",
    checksum: "$SHA256"
)
\`\`\`

### Artifact

- \`FilerCryptoFFI.xcframework.zip\`
- sha256: \`$SHA256\`

See [\`docs/VERSIONING.md\`](https://github.com/CorvidSoft/filer-crypto/blob/main/docs/VERSIONING.md) for the semver policy.
EOF
