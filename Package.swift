// swift-tools-version:5.9
//
// Dual-mode Package manifest.
//
// Default: consume the pre-built XCFramework from the GitHub Release of
// the tag whose URL is baked in below. The release pipeline (see
// .github/workflows/release.yml) builds the XCFramework on every v*
// tag push.
//
// Local-dev mode: set FILUM_CRYPTO_LOCAL=1 before any swift command.
// In this mode, FilumCrypto links against the staticlib produced by
// ./scripts/build.sh (target/{debug,release}/libfilum_crypto.a). The
// profile can be overridden via FILUM_CRYPTO_LOCAL_PROFILE; default is
// "debug" because CI uses debug for fast iteration.
//
// Run scripts/build.sh first if you're in local mode — the manifest
// does not invoke cargo on its own.
//
// Why a staticlib not a dylib: linking the .a avoids dyld runtime
// resolution at swift-test time (no @rpath or DYLD_LIBRARY_PATH
// dance). The filum-crypto-uniffi crate declares both crate-types,
// so build.sh produces both.

import Foundation
import PackageDescription

let local = ProcessInfo.processInfo.environment["FILUM_CRYPTO_LOCAL"] == "1"
let localProfile = ProcessInfo.processInfo.environment["FILUM_CRYPTO_LOCAL_PROFILE"] ?? "debug"

// Absolute path to the package root, computed from the manifest file's own
// location. Used in local mode to pass absolute -I / -fmodule-map-file flags.
let pkgRoot = URL(fileURLWithPath: #file).deletingLastPathComponent().path

// filum_cryptoFFI.modulemap is not named module.modulemap, so Swift's
// -I auto-discovery won't find it. Both the library target and the test
// target need this flag so that `canImport(filum_cryptoFFI)` returns true
// and the C FFI types are in scope for FilumCrypto.swift.
let localSwiftSettings: [SwiftSetting] = [
    .unsafeFlags([
        "-Xcc", "-fmodule-map-file=\(pkgRoot)/Sources/FilumCrypto/filum_cryptoFFI.modulemap",
        // Use -Ipath (no space) so SPM can't inject flags between -I and the path
        // when composing the FilumCryptoPackageTests runner command (Swift 6.3+ issue).
        "-I\(pkgRoot)/Sources/FilumCrypto",
    ])
]

let targets: [Target] =
    local
    ? [
        .target(
            name: "FilumCrypto",
            path: "Sources/FilumCrypto",
            publicHeadersPath: ".",
            swiftSettings: localSwiftSettings,
            linkerSettings: [
                .unsafeFlags(["-L", "\(pkgRoot)/target/\(localProfile)"]),
                .linkedLibrary("filum_crypto"),
                // SecRandomCopyBytes via the getrandom crate on Apple platforms.
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "FilumCryptoTests",
            dependencies: ["FilumCrypto"],
            path: "Tests/FilumCryptoTests",
            resources: [.copy("Fixtures")],
            swiftSettings: localSwiftSettings
        ),
    ]
    : [
        .binaryTarget(
            name: "FilumCryptoFFI",
            // PLACEHOLDER — replaced on each release commit. See docs/VERSIONING.md
            // and the release procedure. The literal <X.Y.Z> here will fail to
            // download if anyone runs `swift build` without FILUM_CRYPTO_LOCAL=1
            // before the first release is cut; that's expected.
            url:
                "https://github.com/CorvidSoft/filer-crypto/releases/download/v0.3.0/FilerCryptoFFI.xcframework.zip",
            checksum: "ee846a2346b8ee32325ee46d288925331f855be36a7c128a06bc33a86d0e3888"
        ),
        .target(
            name: "FilumCrypto",
            dependencies: ["FilumCryptoFFI"],
            path: "Sources/FilumCrypto",
            exclude: ["filum_cryptoFFI.h", "filum_cryptoFFI.modulemap"]
        ),
        .testTarget(
            name: "FilumCryptoTests",
            dependencies: ["FilumCrypto"],
            path: "Tests/FilumCryptoTests",
            resources: [.copy("Fixtures")]
        ),
    ]

let package = Package(
    name: "FilumCrypto",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "FilumCrypto",
            targets: ["FilumCrypto"]
        )
    ],
    targets: targets
)
