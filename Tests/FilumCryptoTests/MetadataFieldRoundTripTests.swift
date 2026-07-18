import XCTest
@testable import FilumCrypto

final class MetadataFieldRoundTripTests: XCTestCase {
    private static let recordId = "test-record-id"
    /// Mirrors the app's single metadata field name.
    private static let fieldName = "document-record"

    private func freshVault() throws -> Vault {
        return try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
    }

    func testRoundTrip() throws {
        let vault = try freshVault()
        let plaintext = Data("Project Plan 2026".utf8)
        let field = try vault.encryptMetadataField(
            plaintext: plaintext, recordId: Self.recordId, fieldName: Self.fieldName)
        let recovered = try vault.decryptMetadataField(
            field: field, recordId: Self.recordId, fieldName: Self.fieldName)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripUnicode() throws {
        let vault = try freshVault()
        let plaintext = Data("こんにちは 🌸 filer".utf8)
        let field = try vault.encryptMetadataField(
            plaintext: plaintext, recordId: Self.recordId, fieldName: Self.fieldName)
        let recovered = try vault.decryptMetadataField(
            field: field, recordId: Self.recordId, fieldName: Self.fieldName)
        XCTAssertEqual(recovered, plaintext)
    }

    func testRoundTripEmptyField() throws {
        let vault = try freshVault()
        let field = try vault.encryptMetadataField(
            plaintext: Data(), recordId: Self.recordId, fieldName: Self.fieldName)
        let recovered = try vault.decryptMetadataField(
            field: field, recordId: Self.recordId, fieldName: Self.fieldName)
        XCTAssertEqual(recovered, Data())
    }

    func testTamperedIvFails() throws {
        let vault = try freshVault()
        let field = try vault.encryptMetadataField(
            plaintext: Data("secret".utf8), recordId: Self.recordId, fieldName: Self.fieldName)
        XCTAssertEqual(field.iv.count, 12)
        var tamperedIv = field.iv
        tamperedIv[tamperedIv.startIndex] ^= 0xFF
        let tamperedField = EncryptedField(ciphertext: field.ciphertext, iv: tamperedIv)
        XCTAssertThrowsError(
            try vault.decryptMetadataField(
                field: tamperedField, recordId: Self.recordId, fieldName: Self.fieldName)
        ) { err in
            guard case FilumCryptoError.Aead = err else {
                XCTFail("expected FilumCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    /// Context binding (v2): a field encrypted under record A must not decrypt
    /// under record B — the sync_records swap attack from filum#113.
    func testWrongRecordIdFailsAead() throws {
        let vault = try freshVault()
        let field = try vault.encryptMetadataField(
            plaintext: Data("bound".utf8), recordId: "record-a", fieldName: Self.fieldName)
        XCTAssertThrowsError(
            try vault.decryptMetadataField(
                field: field, recordId: "record-b", fieldName: Self.fieldName)
        ) { err in
            guard case FilumCryptoError.Aead = err else {
                XCTFail("expected FilumCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    /// Context binding (v2): same record, different field name → Aead.
    func testWrongFieldNameFailsAead() throws {
        let vault = try freshVault()
        let field = try vault.encryptMetadataField(
            plaintext: Data("bound".utf8), recordId: Self.recordId, fieldName: "field-x")
        XCTAssertThrowsError(
            try vault.decryptMetadataField(
                field: field, recordId: Self.recordId, fieldName: "field-y")
        ) { err in
            guard case FilumCryptoError.Aead = err else {
                XCTFail("expected FilumCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    /// An empty record id would silently produce an unbound ciphertext, so the
    /// crate rejects it up front with InvalidContext (not Aead).
    func testEmptyRecordIdThrowsInvalidContext() throws {
        let vault = try freshVault()
        XCTAssertThrowsError(
            try vault.encryptMetadataField(
                plaintext: Data("x".utf8), recordId: "", fieldName: Self.fieldName)
        ) { err in
            guard case FilumCryptoError.InvalidContext = err else {
                XCTFail("expected FilumCryptoError.InvalidContext, got \(err)")
                return
            }
        }
    }

    /// Same guard for the field name: both context components must be non-empty.
    func testEmptyFieldNameThrowsInvalidContext() throws {
        let vault = try freshVault()
        XCTAssertThrowsError(
            try vault.encryptMetadataField(
                plaintext: Data("x".utf8), recordId: Self.recordId, fieldName: "")
        ) { err in
            guard case FilumCryptoError.InvalidContext = err else {
                XCTFail("expected FilumCryptoError.InvalidContext, got \(err)")
                return
            }
        }
    }
}
