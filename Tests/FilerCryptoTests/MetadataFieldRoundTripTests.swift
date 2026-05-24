import XCTest
@testable import FilerCrypto

final class MetadataFieldRoundTripTests: XCTestCase {
    private func freshVault() throws -> Vault {
        return try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
    }

    func testRoundTrip() throws {
        let vault = try freshVault()
        let plaintext = Array("Project Plan 2026".utf8)
        let field = try vault.encryptMetadataField(plaintext: plaintext)
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripUnicode() throws {
        let vault = try freshVault()
        let plaintext = Array("こんにちは 🌸 filer".utf8)
        let field = try vault.encryptMetadataField(plaintext: plaintext)
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripEmptyField() throws {
        let vault = try freshVault()
        let field = try vault.encryptMetadataField(plaintext: [])
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, [])
    }

    func testTamperedIvFails() throws {
        let vault = try freshVault()
        let field = try vault.encryptMetadataField(plaintext: Array("secret".utf8))
        XCTAssertEqual(field.iv.count, 12)
        var tamperedIv = field.iv
        tamperedIv[0] ^= 0xFF
        let tamperedField = EncryptedField(ciphertext: field.ciphertext, iv: tamperedIv)
        XCTAssertThrowsError(try vault.decryptMetadataField(field: tamperedField)) { err in
            guard case FilerCryptoError.Aead = err else {
                XCTFail("expected FilerCryptoError.Aead, got \(err)")
                return
            }
        }
    }
}
