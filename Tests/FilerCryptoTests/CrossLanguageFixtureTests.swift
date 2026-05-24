import XCTest
@testable import FilerCrypto

/// Decrypts the Rust-produced golden fixtures committed in Fixtures/.
/// These pin the wire format: any change to AEAD / HKDF / envelope
/// layout / signing curve will make these fail.
final class CrossLanguageFixtureTests: XCTestCase {
    // All three fixtures were produced with master_secret = [0u8; 32].
    private static let fixtureMasterSecret: [UInt8] = Array(repeating: 0, count: 32)

    private func loadFixture(_ name: String) throws -> [String: Any] {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            XCTFail("fixture \(name).json not found in test bundle (subdirectory: Fixtures)")
            return [:]
        }
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("fixture \(name).json is not a JSON object")
            return [:]
        }
        return obj
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

    func testBlobFixtureDecrypts() throws {
        let fixture = try loadFixture("blob_v1")
        let plaintext = try hexDecode(fixture["plaintext_hex"] as! String)
        let blobDict = fixture["blob"] as! [String: String]
        let blob = EncryptedBlob(
            ciphertext: try hexDecode(blobDict["ciphertext_hex"]!),
            iv: try hexDecode(blobDict["iv_hex"]!),
            wrappedKey: try hexDecode(blobDict["wrapped_key_hex"]!)
        )
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        let recovered = try vault.decryptBlob(blob: blob)
        XCTAssertEqual(recovered, plaintext)
    }

    func testMetadataFixtureDecrypts() throws {
        let fixture = try loadFixture("metadata_v1")
        let plaintext = try hexDecode(fixture["plaintext_hex"] as! String)
        let fieldDict = fixture["field"] as! [String: String]
        let field = EncryptedField(
            ciphertext: try hexDecode(fieldDict["ciphertext_hex"]!),
            iv: try hexDecode(fieldDict["iv_hex"]!)
        )
        let vault = try Vault.open(masterSecret: Self.fixtureMasterSecret)
        let recovered = try vault.decryptMetadataField(field: field)
        XCTAssertEqual(recovered, plaintext)
    }

    func testSignatureFixtureVerifies() throws {
        let fixture = try loadFixture("signature_v1")
        let nonce = try hexDecode(fixture["nonce_hex"] as! String)
        let publicKey = try hexDecode(fixture["public_key_hex"] as! String)
        let signature = try hexDecode(fixture["signature_hex"] as! String)
        XCTAssertNoThrow(try verifySignature(publicKey: publicKey, nonce: nonce, signature: signature))
    }
}
