import XCTest
@testable import FilerCrypto

final class BlobRoundTripTests: XCTestCase {
    /// Chunked-codec header length (version + wrapped key + nonce prefix +
    /// chunk_size): 1 + 60 + 7 + 4 = 72 bytes. Body bytes start here.
    private static let headerLen = 72

    private func freshVault(secret seed: UInt8 = 0x42) throws -> Vault {
        return try Vault.open(masterSecret: Array(repeating: seed, count: 32))
    }

    func testRoundTripSmallPayload() throws {
        let vault = try freshVault()
        let plaintext = Data("hello filer".utf8)
        let framed = try vault.encryptBlob(plaintext: plaintext)
        let recovered = try vault.decryptBlob(framed: framed)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripEmptyPayload() throws {
        let vault = try freshVault()
        let framed = try vault.encryptBlob(plaintext: Data())
        let recovered = try vault.decryptBlob(framed: framed)
        XCTAssertEqual(recovered, Data())
    }

    func testRoundTripMultiMiBPayload() throws {
        let vault = try freshVault()
        // ~3.5 MiB: spans several 1 MiB chunks plus a partial final chunk.
        let chunk = 1024 * 1024
        let plaintext = Data((0..<(chunk * 3 + 7)).map { UInt8($0 % 251) })
        let framed = try vault.encryptBlob(plaintext: plaintext)
        let recovered = try vault.decryptBlob(framed: framed)
        XCTAssertEqual(recovered, plaintext)
    }

    func testTamperedBodyByteFailsAead() throws {
        let vault = try freshVault()
        // A payload larger than one chunk so the body is unambiguously past the
        // header and we have real ciphertext to corrupt.
        let plaintext = Data((0..<(1024 * 1024 + 100)).map { UInt8($0 % 251) })
        var framed = try vault.encryptBlob(plaintext: plaintext)
        XCTAssertGreaterThan(framed.count, Self.headerLen)
        // Flip a byte well inside the body (past the 72-byte header).
        let idx = framed.startIndex + Self.headerLen + 10
        framed[idx] ^= 0x01
        XCTAssertThrowsError(try vault.decryptBlob(framed: framed)) { err in
            guard case FilerCryptoError.Aead = err else {
                XCTFail("expected FilerCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    func testDecryptUnderWrongMasterSecretFails() throws {
        let vault42 = try freshVault(secret: 0x42)
        let framed = try vault42.encryptBlob(plaintext: Data("hello".utf8))
        let vault00 = try freshVault(secret: 0x00)
        XCTAssertThrowsError(try vault00.decryptBlob(framed: framed)) { err in
            guard case FilerCryptoError.Aead = err else {
                XCTFail("expected FilerCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    func testFileRoundTrip() throws {
        let vault = try freshVault()
        let tmp = FileManager.default.temporaryDirectory
        let base = UUID().uuidString
        let plainURL = tmp.appendingPathComponent("\(base).plain")
        let encURL = tmp.appendingPathComponent("\(base).enc")
        let decURL = tmp.appendingPathComponent("\(base).dec")
        defer {
            try? FileManager.default.removeItem(at: plainURL)
            try? FileManager.default.removeItem(at: encURL)
            try? FileManager.default.removeItem(at: decURL)
        }

        // ~2.5 MiB so the file streamer crosses chunk boundaries.
        let plaintext = Data((0..<(1024 * 1024 * 2 + 12345)).map { UInt8($0 % 251) })
        try plaintext.write(to: plainURL)

        try vault.encryptFileToBlob(inPath: plainURL.path, outPath: encURL.path)
        try vault.decryptBlobToFile(inPath: encURL.path, outPath: decURL.path)

        let recovered = try Data(contentsOf: decURL)
        XCTAssertEqual(recovered, plaintext)
    }

    func testDecryptBlobToFileMissingInputThrowsIo() throws {
        let vault = try freshVault()
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).dec")
        defer { try? FileManager.default.removeItem(at: outURL) }
        // A nonexistent input file must surface as FilerCryptoError.Io across the FFI,
        // not crash the boundary.
        XCTAssertThrowsError(
            try vault.decryptBlobToFile(inPath: "/nonexistent/filer-missing.enc", outPath: outURL.path)
        ) { err in
            guard case FilerCryptoError.Io = err else {
                XCTFail("expected FilerCryptoError.Io, got \(err)")
                return
            }
        }
    }
}
