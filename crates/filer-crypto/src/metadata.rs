//! AES-256-GCM field-level metadata encryption.
//!
//! Used to encrypt sensitive SQLite columns (filenames, document types,
//! extracted fields). The metadata key is derived from the master secret
//! via HKDF and is independent of the wrapping key used for blobs.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand_core::{OsRng, RngCore};

use crate::error::{FilerCryptoError, Result};

/// The encrypted-field envelope. Structurally mirrors the `EncryptedSyncRecord`
/// shape on the TypeScript protocol side (ciphertext + iv, no wrapped key).
#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
}

pub(crate) fn encrypt_field(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedField> {
    let cipher = Aes256Gcm::new(key.into());
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let ciphertext = cipher
        .encrypt(&iv.into(), plaintext)
        .map_err(|_| FilerCryptoError::Decrypt)?;
    Ok(EncryptedField { ciphertext, iv })
}

pub(crate) fn decrypt_field(field: &EncryptedField, key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(&field.iv.into(), field.ciphertext.as_slice())
        .map_err(|_| FilerCryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_field() {
        let key = [7u8; 32];
        let plaintext = b"passport_no:AB1234567";
        let field = encrypt_field(plaintext, &key).unwrap();
        let recovered = decrypt_field(&field, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_field() {
        let key = [7u8; 32];
        let field = encrypt_field(&[], &key).unwrap();
        let recovered = decrypt_field(&field, &key).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [7u8; 32];
        let key2 = [8u8; 32];
        let field = encrypt_field(b"secret", &key1).unwrap();
        let result = decrypt_field(&field, &key2);
        assert!(matches!(result, Err(FilerCryptoError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [7u8; 32];
        let mut field = encrypt_field(b"secret", &key).unwrap();
        field.ciphertext[0] ^= 1;
        let result = decrypt_field(&field, &key);
        assert!(matches!(result, Err(FilerCryptoError::Decrypt)));
    }

    #[test]
    fn nondeterministic_for_same_input() {
        let key = [7u8; 32];
        let a = encrypt_field(b"same", &key).unwrap();
        let b = encrypt_field(b"same", &key).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.iv, b.iv);
    }
}
