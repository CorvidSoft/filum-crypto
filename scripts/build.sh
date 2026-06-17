#!/usr/bin/env bash
#
# Build the filum-crypto Rust libraries and regenerate the Swift bindings.
#
# Usage: ./scripts/build.sh [release|debug]   (default: release)
#
# Outputs:
#   - target/{release,debug}/libfilum_crypto.{a,dylib,so}
#   - Sources/FilumCrypto/FilumCrypto.swift  (regenerated)
#
set -euo pipefail

PROFILE="${1:-release}"
if [[ "$PROFILE" != "release" && "$PROFILE" != "debug" ]]; then
    echo "Usage: $0 [release|debug]" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "→ Building Rust libraries ($PROFILE)..."
if [[ "$PROFILE" == "release" ]]; then
    cargo build --release --workspace
    LIB_DIR="$ROOT/target/release"
else
    cargo build --workspace
    LIB_DIR="$ROOT/target/debug"
fi

# Determine the platform-native shared library extension
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_EXT="so"
else
    echo "Unsupported OS: $OSTYPE" >&2
    exit 3
fi

LIB_FILE="$LIB_DIR/libfilum_crypto.$LIB_EXT"
if [[ ! -f "$LIB_FILE" ]]; then
    echo "Expected library not found: $LIB_FILE" >&2
    exit 4
fi

echo "→ Regenerating Swift bindings..."
mkdir -p Sources/FilumCrypto
cargo run --quiet --package filum-crypto-uniffi --bin uniffi-bindgen -- \
    generate \
    --library \
    --language swift \
    --out-dir Sources/FilumCrypto \
    "$LIB_FILE"

echo "✓ Build complete."
echo "  Library:  $LIB_FILE"
echo "  Bindings: $ROOT/Sources/FilumCrypto/FilumCrypto.swift"
