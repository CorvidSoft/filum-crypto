#!/usr/bin/env bash
#
# Cross-compile filer-crypto-uniffi to the iOS targets, assemble an
# XCFramework, zip it, and emit a sha256. Output ends up under build/.
#
# This script is macOS-only — lipo + xcodebuild are not available
# elsewhere. Release CI runs on macos-latest; local dev needs Xcode + the
# three Rust iOS targets installed.
#
set -euo pipefail

if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "build-xcframework.sh requires macOS (xcodebuild + lipo)" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/build"
SIM_UNIVERSAL_DIR="$BUILD_DIR/ios-sim-universal"
HEADERS_DIR="$BUILD_DIR/headers"
XCFRAMEWORK="$BUILD_DIR/FilerCryptoFFI.xcframework"
XCFRAMEWORK_ZIP="$BUILD_DIR/FilerCryptoFFI.xcframework.zip"

# Clean previous output so stale slices can't contaminate the new framework.
rm -rf "$BUILD_DIR"
mkdir -p "$SIM_UNIVERSAL_DIR" "$HEADERS_DIR"

echo "→ Installing iOS Rust targets if missing..."
rustup target add \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    x86_64-apple-ios

echo "→ Building for aarch64-apple-ios (device)..."
cargo build --release --target aarch64-apple-ios --package filer-crypto-uniffi

echo "→ Building for aarch64-apple-ios-sim (Apple Silicon simulator)..."
cargo build --release --target aarch64-apple-ios-sim --package filer-crypto-uniffi

echo "→ Building for x86_64-apple-ios (Intel simulator)..."
cargo build --release --target x86_64-apple-ios --package filer-crypto-uniffi

echo "→ lipo simulator slices into a universal archive..."
# arm64 listed first so lipo reports "arm64 x86_64" in the fat header.
lipo -create \
    "$ROOT/target/aarch64-apple-ios-sim/release/libfiler_crypto.a" \
    "$ROOT/target/x86_64-apple-ios/release/libfiler_crypto.a" \
    -output "$SIM_UNIVERSAL_DIR/libfiler_crypto.a"

# Sanity check: both archs must be present (order in the fat header varies).
LIPO_INFO="$(lipo -info "$SIM_UNIVERSAL_DIR/libfiler_crypto.a")"
if ! echo "$LIPO_INFO" | grep -q "arm64" || ! echo "$LIPO_INFO" | grep -q "x86_64"; then
    echo "ERROR: simulator universal slice missing an arch:" >&2
    echo "$LIPO_INFO" >&2
    exit 3
fi

echo "→ Staging C header + modulemap..."
cp "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.h"        "$HEADERS_DIR/filer_cryptoFFI.h"
cp "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.modulemap" "$HEADERS_DIR/module.modulemap"

echo "→ Bindings drift check..."
# Regenerate bindings into a temp dir and diff against committed.
TMP_BINDINGS="$(mktemp -d)"
trap 'rm -rf "$TMP_BINDINGS"' EXIT
# Use the device staticlib as the input library for bindgen (any slice works;
# they all carry the same UDL-generated metadata).
cargo run --quiet --package filer-crypto-uniffi --bin uniffi-bindgen -- \
    generate \
    --library \
    --language swift \
    --out-dir "$TMP_BINDINGS" \
    "$ROOT/target/aarch64-apple-ios/release/libfiler_crypto.a"

if ! diff -q "$TMP_BINDINGS/FilerCrypto.swift"        "$ROOT/Sources/FilerCrypto/FilerCrypto.swift" \
  || ! diff -q "$TMP_BINDINGS/filer_cryptoFFI.h"      "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.h" \
  || ! diff -q "$TMP_BINDINGS/filer_cryptoFFI.modulemap" "$ROOT/Sources/FilerCrypto/filer_cryptoFFI.modulemap"; then
    echo "ERROR: committed Swift bindings differ from what current Rust source would generate." >&2
    echo "Run ./scripts/build.sh and commit the regenerated files." >&2
    exit 4
fi

echo "→ Assembling XCFramework..."
xcodebuild -create-xcframework \
    -library "$ROOT/target/aarch64-apple-ios/release/libfiler_crypto.a" -headers "$HEADERS_DIR" \
    -library "$SIM_UNIVERSAL_DIR/libfiler_crypto.a"                    -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK"

echo "→ Zipping XCFramework..."
( cd "$BUILD_DIR" && zip -qr "FilerCryptoFFI.xcframework.zip" "FilerCryptoFFI.xcframework" )

SHA256="$(shasum -a 256 "$XCFRAMEWORK_ZIP" | awk '{print $1}')"

echo
echo "✓ XCFramework built."
echo "  Path:     $XCFRAMEWORK_ZIP"
echo "  sha256:   $SHA256"
