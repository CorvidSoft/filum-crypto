import XCTest
@testable import FilumCrypto

/// Decrypts the Rust-produced golden fixtures committed in Fixtures/.
/// These pin the wire format: any change to AEAD / HKDF / envelope
/// layout / signing curve will make these fail.
///
/// The `*_v2` fixtures embed the context ids they were encrypted under
/// (AAD context binding, format v2) and must decrypt with exactly those
/// ids. The frozen `blob_v1` / `metadata_v1` fixtures are v0.3.x
/// must-fail vectors: the v2 format cutover must REJECT them with Aead.
final class CrossLanguageFixtureTests: XCTestCase {
    // All fixtures were produced with master_secret = [0u8; 32].
    private static let fixtureMasterSecret: [UInt8] = Array(repeating: 0, count: 32)

    private func loadFixture(_ name: String) throws -> [String: Any] {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"),
            "fixture \(name).json not found in test bundle (subdirectory: Fixtures)"
        )
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any],
            "fixture \(name).json is not a JSON object"
        )
    }

    private func hexDecode(_ s: String) throws -> [UInt8] {
        guard s.count % 2 == 0 else {
            throw NSError(domain: "hex", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "odd-length hex string: \(s)"])
        }
        var out: [UInt8] = []
        out.reserveCapacity(s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let byte = UInt8(s[idx..<next], radix: 16) else {
                throw NSError(domain: "hex", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "invalid hex byte: \(s[idx..<next])"])
            }
            out.append(byte)
            idx = next
        }
        return out
    }

    private func loadField(_ fixture: [String: Any]) throws -> EncryptedField {
        let fieldDict = try XCTUnwrap(fixture["field"] as? [String: String])
        return EncryptedField(
            ciphertext: Data(try hexDecode(try XCTUnwrap(fieldDict["ciphertext_hex"]))),
            iv: Data(try hexDecode(try XCTUnwrap(fieldDict["iv_hex"])))
        )
    }

    // MARK: - v2 fixtures (must decrypt with the ids embedded in the JSON)

    func testBlobV2FixtureDecrypts() throws {
        let fixture = try loadFixture("blob_v2")
        let blobId = try XCTUnwrap(fixture["blob_id"] as? String)
        let plaintext = try hexDecode(try XCTUnwrap(fixture["plaintext_hex"] as? String))
        let framed = Data(try hexDecode(try XCTUnwrap(fixture["framed_hex"] as? String)))
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        let recovered = try vault.decryptBlob(framed: framed, blobId: blobId)
        XCTAssertEqual(recovered, Data(plaintext))
    }

    func testMetadataV2FixtureDecrypts() throws {
        let fixture = try loadFixture("metadata_v2")
        let recordId = try XCTUnwrap(fixture["record_id"] as? String)
        let fieldName = try XCTUnwrap(fixture["field_name"] as? String)
        let plaintext = try hexDecode(try XCTUnwrap(fixture["plaintext_hex"] as? String))
        let field = try loadField(fixture)
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        let recovered = try vault.decryptMetadataField(
            field: field, recordId: recordId, fieldName: fieldName)
        XCTAssertEqual(recovered, Data(plaintext))
    }

    // MARK: - v1 fixtures (frozen must-fail vectors: format cutover rejects them)

    func testBlobV1FixtureFailsForAnyBlobId() throws {
        let fixture = try loadFixture("blob_v1")
        let framed = Data(try hexDecode(try XCTUnwrap(fixture["framed_hex"] as? String)))
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        // No blob id can rescue a version-1 envelope — the version byte is
        // rejected before unwrap. Representative ids, not an exhaustive set.
        for blobId in ["fixture-blob-id", "any-other-id"] {
            XCTAssertThrowsError(
                try vault.decryptBlob(framed: framed, blobId: blobId),
                "v1 blob must not decrypt under blobId \(blobId)"
            ) { err in
                guard case FilumCryptoError.Aead = err else {
                    XCTFail("expected FilumCryptoError.Aead for blobId \(blobId), got \(err)")
                    return
                }
            }
        }
    }

    func testMetadataV1FixtureFailsAead() throws {
        let fixture = try loadFixture("metadata_v1")
        let field = try loadField(fixture)
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        // The v1 field was encrypted without the v2 AAD, so it fails the tag
        // check no matter which context ids are supplied.
        XCTAssertThrowsError(
            try vault.decryptMetadataField(
                field: field, recordId: "fixture-record-id", fieldName: "document-record")
        ) { err in
            guard case FilumCryptoError.Aead = err else {
                XCTFail("expected FilumCryptoError.Aead, got \(err)")
                return
            }
        }
    }

    // MARK: - Signing (version-agnostic; unchanged by the v2 cutover)

    func testSignatureFixtureVerifies() throws {
        let fixture = try loadFixture("signature_v1")
        let nonce = try hexDecode(try XCTUnwrap(fixture["nonce_hex"] as? String))
        let publicKey = try hexDecode(try XCTUnwrap(fixture["public_key_hex"] as? String))
        let signature = try hexDecode(try XCTUnwrap(fixture["signature_hex"] as? String))
        XCTAssertNoThrow(try verifySignature(publicKey: publicKey, nonce: nonce, signature: signature))
    }
}
