import XCTest
@testable import FilerCrypto

final class RecoveryPhraseTests: XCTestCase {
    func testGenerateMasterSecretIs32Bytes() throws {
        let secret = try generateMasterSecret()
        XCTAssertEqual(secret.count, 32)
    }

    func testGenerateMasterSecretIsRandom() throws {
        let a = try generateMasterSecret()
        let b = try generateMasterSecret()
        XCTAssertNotEqual(a, b, "two random secrets should differ")
    }

    func testRoundTripPhrase() throws {
        let secret = try generateMasterSecret()
        let phrase = try secretToPhrase(secret: secret)
        let back = try phraseToSecret(phrase: phrase)
        XCTAssertEqual(back, secret)
    }

    func testPhraseIs24Words() throws {
        let secret = try generateMasterSecret()
        let phrase = try secretToPhrase(secret: secret)
        XCTAssertEqual(phrase.split(separator: " ").count, 24)
    }

    /// The BIP39 phrase for [0u8; 32] starts with "abandon abandon abandon"
    /// and ends with "art". This is a known answer that pins the BIP39 wordlist.
    func testZeroSecretKnownAnswer() throws {
        let zero = Array<UInt8>(repeating: 0, count: 32)
        let phrase = try secretToPhrase(secret: zero)
        XCTAssertTrue(
            phrase.starts(with: "abandon abandon abandon"),
            "phrase for all-zero secret should start with 'abandon abandon abandon', got: \(phrase)"
        )
        XCTAssertTrue(
            phrase.hasSuffix("art"),
            "phrase for all-zero secret should end with 'art', got: \(phrase)"
        )
        let back = try phraseToSecret(phrase: phrase)
        XCTAssertEqual(back, zero)
    }

    func testInvalidPhraseRejected() throws {
        XCTAssertThrowsError(try phraseToSecret(phrase: "not a real bip39 phrase at all")) { err in
            guard case FilerCryptoError.InvalidPhrase = err else {
                XCTFail("expected FilerCryptoError.InvalidPhrase, got \(err)")
                return
            }
        }
    }
}
