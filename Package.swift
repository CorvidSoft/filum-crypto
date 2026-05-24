// swift-tools-version:5.9
//
// Dual-mode Package manifest.
//
// Default: consume the pre-built XCFramework from the GitHub Release of
// the tag whose URL is baked in below. The release pipeline (see
// .github/workflows/release.yml) builds the XCFramework on every v*
// tag push.
//
// Local-dev mode: set FILER_CRYPTO_LOCAL=1 before any swift command.
// In this mode, FilerCrypto links against the staticlib produced by
// ./scripts/build.sh (target/{debug,release}/libfiler_crypto.a). The
// profile can be overridden via FILER_CRYPTO_LOCAL_PROFILE; default is
// "debug" because CI uses debug for fast iteration.
//
// Run scripts/build.sh first if you're in local mode — the manifest
// does not invoke cargo on its own.
//
// Why a staticlib not a dylib: linking the .a avoids dyld runtime
// resolution at swift-test time (no @rpath or DYLD_LIBRARY_PATH
// dance). The filer-crypto-uniffi crate declares both crate-types,
// so build.sh produces both.

import PackageDescription
import Foundation

let local = ProcessInfo.processInfo.environment["FILER_CRYPTO_LOCAL"] == "1"
let localProfile = ProcessInfo.processInfo.environment["FILER_CRYPTO_LOCAL_PROFILE"] ?? "debug"

// Absolute path to the package root, computed from the manifest file's own
// location. Used in local mode to pass absolute -I / -fmodule-map-file flags.
let pkgRoot = URL(fileURLWithPath: #file).deletingLastPathComponent().path

// filer_cryptoFFI.modulemap is not named module.modulemap, so Swift's
// -I auto-discovery won't find it. Both the library target and the test
// target need this flag so that `canImport(filer_cryptoFFI)` returns true
// and the C FFI types are in scope for FilerCrypto.swift.
let localSwiftSettings: [SwiftSetting] = [
    .unsafeFlags([
        "-Xcc", "-fmodule-map-file=\(pkgRoot)/Sources/FilerCrypto/filer_cryptoFFI.modulemap",
        // Use -Ipath (no space) so SPM can't inject flags between -I and the path
        // when composing the FilerCryptoPackageTests runner command (Swift 6.3+ issue).
        "-I\(pkgRoot)/Sources/FilerCrypto",
    ]),
]

let targets: [Target] = local
    ? [
        .target(
            name: "FilerCrypto",
            path: "Sources/FilerCrypto",
            publicHeadersPath: ".",
            swiftSettings: localSwiftSettings,
            linkerSettings: [
                .unsafeFlags(["-L", "\(pkgRoot)/target/\(localProfile)"]),
                .linkedLibrary("filer_crypto"),
                // SecRandomCopyBytes via the getrandom crate on Apple platforms.
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "FilerCryptoTests",
            dependencies: ["FilerCrypto"],
            path: "Tests/FilerCryptoTests",
            resources: [.copy("Fixtures")],
            swiftSettings: localSwiftSettings
        ),
    ]
    : [
        .binaryTarget(
            name: "FilerCryptoFFI",
            // PLACEHOLDER — replaced on each release commit. See docs/VERSIONING.md
            // and the release procedure. The literal <X.Y.Z> here will fail to
            // download if anyone runs `swift build` without FILER_CRYPTO_LOCAL=1
            // before the first release is cut; that's expected.
            url: "https://github.com/CorvidSoft/filer-crypto/releases/download/v<X.Y.Z>/FilerCryptoFFI.xcframework.zip",
            checksum: "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        .target(
            name: "FilerCrypto",
            dependencies: ["FilerCryptoFFI"],
            path: "Sources/FilerCrypto",
            exclude: ["filer_cryptoFFI.h", "filer_cryptoFFI.modulemap"]
        ),
        .testTarget(
            name: "FilerCryptoTests",
            dependencies: ["FilerCrypto"],
            path: "Tests/FilerCryptoTests",
            resources: [.copy("Fixtures")]
        ),
    ]

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
    targets: targets
)
