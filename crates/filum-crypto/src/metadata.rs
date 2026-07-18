//! AES-256-GCM field-level metadata encryption (format v2).
//!
//! Used to encrypt sensitive SQLite columns (filenames, document types,
//! extracted fields). The metadata key is derived from the master secret
//! via HKDF and is independent of the wrapping key used for blobs.
//!
//! Every field is bound to its sync record and field name via AAD
//! ([`crate::aad::field_aad`]): a ciphertext transplanted to a different
//! record id or field name fails authentication with
//! [`FilumCryptoError::Aead`]. The [`EncryptedField`] envelope itself is
//! unchanged from v1 (no version byte); a v1 ciphertext simply fails AEAD
//! under the new AAD.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use rand_core::{OsRng, RngCore};

use crate::aad;
use crate::error::{FilumCryptoError, Result};

/// The encrypted-field envelope. Structurally mirrors the `EncryptedSyncRecord`
/// shape on the TypeScript protocol side (ciphertext + iv, no wrapped key).
#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
}

pub(crate) fn encrypt_field(
    plaintext: &[u8],
    key: &[u8; 32],
    record_id: &str,
    field_name: &str,
) -> Result<EncryptedField> {
    // Context validation happens before any randomness or cipher work.
    let aad = aad::field_aad(record_id, field_name)?;
    let cipher = Aes256Gcm::new(key.into());
    let mut iv = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|_| FilumCryptoError::Randomness)?;
    let ciphertext = cipher
        .encrypt(
            &iv.into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| FilumCryptoError::Aead)?;
    Ok(EncryptedField { ciphertext, iv })
}

pub(crate) fn decrypt_field(
    field: &EncryptedField,
    key: &[u8; 32],
    record_id: &str,
    field_name: &str,
) -> Result<Vec<u8>> {
    let aad = aad::field_aad(record_id, field_name)?;
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            &field.iv.into(),
            Payload {
                msg: field.ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| FilumCryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_field() {
        let key = [7u8; 32];
        let plaintext = b"passport_no:AB1234567";
        let field = encrypt_field(plaintext, &key, "rec-1", "name").unwrap();
        let recovered = decrypt_field(&field, &key, "rec-1", "name").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_field() {
        let key = [7u8; 32];
        let field = encrypt_field(&[], &key, "rec-1", "name").unwrap();
        let recovered = decrypt_field(&field, &key, "rec-1", "name").unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [7u8; 32];
        let key2 = [8u8; 32];
        let field = encrypt_field(b"secret", &key1, "rec-1", "name").unwrap();
        let result = decrypt_field(&field, &key2, "rec-1", "name");
        assert!(matches!(result, Err(FilumCryptoError::Aead)));
    }

    #[test]
    fn wrong_record_id_fails() {
        // Transplant defense: a field encrypted for record A must not decrypt
        // when presented as belonging to record B.
        let key = [7u8; 32];
        let field = encrypt_field(b"secret", &key, "rec-a", "name").unwrap();
        let result = decrypt_field(&field, &key, "rec-b", "name");
        assert!(matches!(result, Err(FilumCryptoError::Aead)));
    }

    #[test]
    fn wrong_field_name_fails() {
        let key = [7u8; 32];
        let field = encrypt_field(b"secret", &key, "rec-a", "name").unwrap();
        let result = decrypt_field(&field, &key, "rec-a", "other");
        assert!(matches!(result, Err(FilumCryptoError::Aead)));
    }

    #[test]
    fn empty_identifiers_are_invalid_context_on_encrypt() {
        let key = [7u8; 32];
        assert!(matches!(
            encrypt_field(b"x", &key, "", "name"),
            Err(FilumCryptoError::InvalidContext)
        ));
        assert!(matches!(
            encrypt_field(b"x", &key, "rec-1", ""),
            Err(FilumCryptoError::InvalidContext)
        ));
    }

    #[test]
    fn empty_identifiers_are_invalid_context_on_decrypt() {
        let key = [7u8; 32];
        let field = encrypt_field(b"x", &key, "rec-1", "name").unwrap();
        assert!(matches!(
            decrypt_field(&field, &key, "", "name"),
            Err(FilumCryptoError::InvalidContext)
        ));
        assert!(matches!(
            decrypt_field(&field, &key, "rec-1", ""),
            Err(FilumCryptoError::InvalidContext)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [7u8; 32];
        let mut field = encrypt_field(b"secret", &key, "rec-1", "name").unwrap();
        field.ciphertext[0] ^= 1;
        let result = decrypt_field(&field, &key, "rec-1", "name");
        assert!(matches!(result, Err(FilumCryptoError::Aead)));
    }

    #[test]
    fn iv_is_fresh_per_encryption() {
        // Defense against accidental IV caching — each encryption MUST pull
        // fresh randomness. IV reuse under the same AES-GCM key is a
        // catastrophic failure (allows plaintext recovery). See the matching
        // test in blob.rs for the flake-probability discussion.
        let key = [7u8; 32];
        let a = encrypt_field(b"same", &key, "rec-1", "name").unwrap();
        let b = encrypt_field(b"same", &key, "rec-1", "name").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.iv, b.iv);
    }
}
