// Placeholder Swift test target for v0.1.0.
//
// Currently a no-op: `swift test` against this package fails at link time
// (the Rust FFI library is not yet wired through SPM — that lands when the
// XCFramework distribution pipeline ships, tracked in issue #3). Until then
// the only thing this file provides is a parseable test target so
// `swift package describe` lists `FilerCryptoTests`. The XCTSkip body below
// is unreachable today; the file is preserved so the test target structure
// stays in place for when linking is fixed.
//
// `#if canImport(filer_cryptoFFI)` would let us turn this off cleanly, but
// the module is declared via the modulemap in Sources/FilerCrypto and so
// always appears importable to SPM's resolver — the failure happens at
// link time, not import time. Hence the comment-only approach.

import XCTest

@testable import FilerCrypto

final class FilerCryptoTests: XCTestCase {
    func testPlaceholder() throws {
        throw XCTSkip(
            "FFI library not yet linked through SPM; real parity tests land with the XCFramework follow-up (see issue #3)"
        )
    }
}
