import XCTest
@testable import FilerCrypto

final class BlobRoundTripTests: XCTestCase {
    private func freshVault(secret seed: UInt8 = 0x42) throws -> Vault {
        return try Vault.open(masterSecret: Array(repeating: seed, count: 32))
    }

    func testRoundTripSmallPayload() throws {
        let vault = try freshVault()
        let plaintext = Array("hello filer".utf8)
        let blob = try vault.encryptBlob(plaintext: plaintext)
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripEmptyPayload() throws {
        let vault = try freshVault()
        let blob = try vault.encryptBlob(plaintext: [])
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, [])
    }

    func testRoundTripLargePayload() throws {
        let vault = try freshVault()
        let plaintext = (UInt8(0)...UInt8(255)).flatMap { byte -> [UInt8] in
            Array(repeating: byte, count: 1024)
        }
        XCTAssertEqual(plaintext.count, 256 * 1024)
        let blob = try vault.encryptBlob(plaintext: plaintext)
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, plaintext)
    }

    func testTamperedCiphertextFailsAead() throws {
        let vault = try freshVault()
        let plaintext = Array("hello filer".utf8)
        let blob = try vault.encryptBlob(plaintext: plaintext)
        XCTAssertGreaterThan(blob.ciphertext.count, 0)
        var tamperedCiphertext = blob.ciphertext
        tamperedCiphertext[0] ^= 0x01
        let tamperedBlob = EncryptedBlob(
            ciphertext: tamperedCiphertext,
            iv: blob.iv,
            wrappedKey: blob.wrappedKey
        )
        XCTAssertThrowsError(try vault.decryptBlob(blob: tamperedBlob)) { err in
            guard case FilerCryptoError.Aead = err else {
                XCTFail("expected FilerCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    func testDecryptUnderWrongMasterSecretFails() throws {
        let vault42 = try freshVault(secret: 0x42)
        let blob = try vault42.encryptBlob(plaintext: Array("hello".utf8))
        let vault00 = try freshVault(secret: 0x00)
        XCTAssertThrowsError(try vault00.decryptBlob(blob: blob)) { err in
            guard case FilerCryptoError.Aead = err else {
                XCTFail("expected FilerCryptoError.Aead, got \(err)")
                return
            }
        }
    }
}
