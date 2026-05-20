// swift-tools-version:5.9
//
// This Package.swift is intentionally minimal for v0.1.0.
//
// The Swift target wraps the UniFFI-generated bindings in
// Sources/FilerCrypto/FilerCrypto.swift. Linking against the Rust
// shared library (the FFI implementation that the generated bindings
// call into) is NOT wired up here — that happens via a .binaryTarget
// referencing a built XCFramework once we tag the first release.
//
// Consumers who need a working build today should use the mobile app's
// with-crypto-core plugin in local-path mode (FILER_CRYPTO_LOCAL=1),
// which invokes scripts/build.sh and arranges the linking via the Xcode
// project plugin.

import PackageDescription

let package = Package(
    name: "FilerCrypto",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "FilerCrypto",
            targets: ["FilerCrypto"]
        ),
    ],
    targets: [
        .target(
            name: "FilerCrypto",
            path: "Sources/FilerCrypto",
            // The generated FilerCrypto.swift imports `filer_cryptoFFI` (the
            // C-callable shim). The modulemap + header in this directory
            // declare that module; SPM picks them up via publicHeadersPath.
            publicHeadersPath: "."
        ),
        .testTarget(
            name: "FilerCryptoTests",
            dependencies: ["FilerCrypto"],
            path: "Tests/FilerCryptoTests"
        ),
    ]
)
