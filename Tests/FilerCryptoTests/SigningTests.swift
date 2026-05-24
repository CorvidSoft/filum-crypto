import XCTest
@testable import FilerCrypto

final class SigningTests: XCTestCase {
    func testSignVerifyRoundTrip() throws {
        let vault = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let nonce = Array("challenge-nonce".utf8)
        let signature = vault.signChallenge(nonce: nonce)
        let publicKey = vault.devicePublicKey()
        XCTAssertNoThrow(try verifySignature(publicKey: publicKey, nonce: nonce, signature: signature.bytes))
    }

    func testVerifyWithWrongNonceFails() throws {
        let vault = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let signature = vault.signChallenge(nonce: Array("nonce-a".utf8))
        let publicKey = vault.devicePublicKey()
        XCTAssertThrowsError(
            try verifySignature(publicKey: publicKey, nonce: Array("nonce-b".utf8), signature: signature.bytes)
        ) { err in
            guard case FilerCryptoError.InvalidSignature = err else {
                XCTFail("expected FilerCryptoError.InvalidSignature, got \(err)")
                return
            }
        }
    }

    func testVerifyWithWrongPublicKeyFails() throws {
        let vaultA = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let vaultB = try Vault.open(masterSecret: Array(repeating: 0x00, count: 32))
        let nonce = Array("challenge".utf8)
        let signatureA = vaultA.signChallenge(nonce: nonce)
        let publicKeyB = vaultB.devicePublicKey()
        XCTAssertThrowsError(
            try verifySignature(publicKey: publicKeyB, nonce: nonce, signature: signatureA.bytes)
        ) { err in
            guard case FilerCryptoError.InvalidSignature = err else {
                XCTFail("expected FilerCryptoError.InvalidSignature, got \(err)")
                return
            }
        }
    }

    func testDevicePublicKeyIsStableForSameSecret() throws {
        let v1 = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let v2 = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        XCTAssertEqual(v1.devicePublicKey(), v2.devicePublicKey())
    }

    func testDevicePublicKeyDiffersForDifferentSecret() throws {
        let v1 = try Vault.open(masterSecret: Array(repeating: 0x42, count: 32))
        let v2 = try Vault.open(masterSecret: Array(repeating: 0x00, count: 32))
        XCTAssertNotEqual(v1.devicePublicKey(), v2.devicePublicKey())
    }
}
