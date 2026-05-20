//! The `Vault` is the top-level stateful API of `filer-crypto`.
//!
//! Construct it with either a 32-byte master secret or a 24-word BIP39
//! recovery phrase. On construction it derives all needed subkeys via HKDF
//! and stores them privately. The subkeys never leave the Vault; callers
//! interact with `Vault` methods that operate on plaintext + the envelope
//! types defined in [`crate::blob`] and [`crate::metadata`].
//!
//! The Vault implements `Drop` to zeroize all key material when it goes
//! out of scope.

use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

use crate::auth::{self, DeviceSignature};
use crate::blob::{self, EncryptedBlob};
use crate::error::Result;
use crate::kdf::{self, METADATA_CTX, SIGN_CTX, WRAP_CTX};
use crate::metadata::{self, EncryptedField};
use crate::recovery;

pub struct Vault {
    wrap_key: [u8; 32],
    metadata_key: [u8; 32],
    signing_key: SigningKey,
}

impl Vault {
    /// Open a Vault from a 32-byte master secret.
    pub fn open(master_secret: &[u8; 32]) -> Result<Self> {
        let mut wrap_key = [0u8; 32];
        kdf::derive_subkey(master_secret, WRAP_CTX, &mut wrap_key)?;

        let mut metadata_key = [0u8; 32];
        kdf::derive_subkey(master_secret, METADATA_CTX, &mut metadata_key)?;

        let mut sign_seed = [0u8; 32];
        kdf::derive_subkey(master_secret, SIGN_CTX, &mut sign_seed)?;
        let signing_key = auth::signing_key_from_seed(&sign_seed);
        sign_seed.zeroize();

        Ok(Self {
            wrap_key,
            metadata_key,
            signing_key,
        })
    }

    /// Open a Vault from a 24-word BIP39 recovery phrase.
    pub fn from_recovery_phrase(phrase: &str) -> Result<Self> {
        let mut secret = recovery::phrase_to_secret(phrase)?;
        let result = Self::open(&secret);
        secret.zeroize();
        result
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<EncryptedBlob> {
        blob::encrypt_with_key_wrapping(plaintext, &self.wrap_key)
    }

    pub fn decrypt_blob(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        blob::decrypt_with_key_wrapping(blob, &self.wrap_key)
    }

    pub fn encrypt_metadata_field(&self, plaintext: &[u8]) -> Result<EncryptedField> {
        metadata::encrypt_field(plaintext, &self.metadata_key)
    }

    pub fn decrypt_metadata_field(&self, field: &EncryptedField) -> Result<Vec<u8>> {
        metadata::decrypt_field(field, &self.metadata_key)
    }

    pub fn sign_challenge(&self, nonce: &[u8]) -> DeviceSignature {
        auth::sign_challenge(&self.signing_key, nonce)
    }

    pub fn device_public_key(&self) -> [u8; 32] {
        auth::public_key_bytes(&self.signing_key)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
        self.metadata_key.zeroize();
        // SigningKey owns its zeroization per ed25519-dalek's zeroize feature.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verify_signature;

    #[test]
    fn vault_blob_round_trip() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let blob = vault.encrypt_blob(b"hello").unwrap();
        let recovered = vault.decrypt_blob(&blob).unwrap();
        assert_eq!(recovered, b"hello");
    }

    #[test]
    fn vault_metadata_round_trip() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let field = vault.encrypt_metadata_field(b"name=Alice").unwrap();
        let recovered = vault.decrypt_metadata_field(&field).unwrap();
        assert_eq!(recovered, b"name=Alice");
    }

    #[test]
    fn vault_sign_and_verify() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let sig = vault.sign_challenge(b"backend-nonce");
        let pk = vault.device_public_key();
        verify_signature(&pk, b"backend-nonce", &sig.bytes).unwrap();
    }

    #[test]
    fn same_secret_produces_same_public_key() {
        let secret = [1u8; 32];
        let v1 = Vault::open(&secret).unwrap();
        let v2 = Vault::open(&secret).unwrap();
        assert_eq!(v1.device_public_key(), v2.device_public_key());
    }

    #[test]
    fn different_secrets_produce_different_public_keys() {
        let v1 = Vault::open(&[1u8; 32]).unwrap();
        let v2 = Vault::open(&[2u8; 32]).unwrap();
        assert_ne!(v1.device_public_key(), v2.device_public_key());
    }

    #[test]
    fn blob_encrypted_by_one_vault_decrypts_with_same_secret() {
        let secret = [42u8; 32];
        let blob = {
            let v = Vault::open(&secret).unwrap();
            v.encrypt_blob(b"persistent").unwrap()
        };
        let v2 = Vault::open(&secret).unwrap();
        assert_eq!(v2.decrypt_blob(&blob).unwrap(), b"persistent");
    }

    #[test]
    fn vault_from_recovery_phrase_matches_open() {
        let secret = [123u8; 32];
        let phrase = recovery::secret_to_phrase(&secret).unwrap();

        let v_open = Vault::open(&secret).unwrap();
        let v_phrase = Vault::from_recovery_phrase(&phrase).unwrap();

        assert_eq!(v_open.device_public_key(), v_phrase.device_public_key());
    }

    #[test]
    fn vault_from_invalid_phrase_fails() {
        let result = Vault::from_recovery_phrase("not a real phrase");
        assert!(matches!(
            result,
            Err(crate::FilerCryptoError::InvalidPhrase)
        ));
    }
}
