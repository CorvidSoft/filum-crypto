//! BIP39 24-word recovery phrase ↔ 32-byte master secret.
//!
//! 24 words = 256 bits of entropy, matching the rest of the crate's 256-bit
//! security baseline. This differs from the parent Filer DESIGN.md §4.2 which
//! still says "12-word" — to be reconciled when the mobile recovery flow is
//! implemented.

use bip39::{Language, Mnemonic};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{FilerCryptoError, Result};

/// Generates a fresh 32-byte master secret from the system CSPRNG.
///
/// Returns `Err(FilerCryptoError::Randomness)` if the OS entropy source is
/// unavailable (e.g. sandbox restrictions on iOS).
pub fn generate_master_secret() -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| FilerCryptoError::Randomness)?;
    Ok(out)
}

/// Encodes a 32-byte master secret as a 24-word BIP39 phrase (English).
pub fn secret_to_phrase(secret: &[u8; 32]) -> Result<String> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, secret)
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    Ok(mnemonic.to_string())
}

/// Decodes a 24-word BIP39 phrase (English) back into a 32-byte master secret.
pub fn phrase_to_secret(phrase: &str) -> Result<[u8; 32]> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|_| FilerCryptoError::InvalidPhrase)?;
    let mut entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        entropy.zeroize();
        return Err(FilerCryptoError::InvalidPhrase);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&entropy);
    entropy.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_secret_phrase() {
        let secret = [42u8; 32];
        let phrase = secret_to_phrase(&secret).unwrap();
        let recovered = phrase_to_secret(&phrase).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn phrase_has_24_words() {
        let secret = [0u8; 32];
        let phrase = secret_to_phrase(&secret).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn invalid_phrase_rejected() {
        let result = phrase_to_secret("not a real phrase");
        assert!(matches!(result, Err(FilerCryptoError::InvalidPhrase)));
    }

    #[test]
    fn twelve_word_phrase_rejected() {
        // A valid 12-word phrase should still be rejected because we mandate 24.
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        let result = phrase_to_secret(twelve);
        assert!(matches!(result, Err(FilerCryptoError::InvalidPhrase)));
    }

    #[test]
    fn generate_master_secret_succeeds() {
        // We only assert successful generation — the entropy/distribution
        // properties of OsRng are not our responsibility to test here.
        generate_master_secret().unwrap();
    }
}
