//! The `Vault` is the top-level stateful API of `filer-crypto`.
//!
//! Construct it with either a 32-byte master secret or a 24-word BIP39
//! recovery phrase. On construction it derives all needed subkeys via HKDF
//! and stores them privately. The subkeys never leave the Vault; callers
//! interact with `Vault` methods that operate on plaintext + the envelope
//! types defined in [`crate::blob`] and [`crate::metadata`].
//!
//! Both subkey fields are wrapped in `Zeroizing<[u8; 32]>`, which means:
//! - they are not `Copy` (so moving them into `Self` doesn't leave duplicate
//!   stack copies of the bytes), and
//! - they zeroize on `Drop` automatically, including on any `?` return from
//!   constructors. No manual `Drop` impl is needed for them.
//!
//! `SigningKey` owns its zeroization via the `zeroize` feature of
//! `ed25519-dalek`.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::auth::{self, DeviceSignature};
use crate::blob;
use crate::error::Result;
use crate::kdf::{self, METADATA_CTX, SIGN_CTX, WRAP_CTX};
use crate::metadata::{self, EncryptedField};
use crate::recovery;

pub struct Vault {
    wrap_key: Zeroizing<[u8; 32]>,
    metadata_key: Zeroizing<[u8; 32]>,
    signing_key: SigningKey,
}

impl Vault {
    /// Open a Vault from a 32-byte master secret.
    pub fn open(master_secret: &[u8; 32]) -> Result<Self> {
        // All intermediates are wrapped in Zeroizing from the start so they
        // wipe on any early `?` return.
        let mut wrap_key = Zeroizing::new([0u8; 32]);
        kdf::derive_subkey(master_secret, WRAP_CTX, &mut *wrap_key)?;

        let mut metadata_key = Zeroizing::new([0u8; 32]);
        kdf::derive_subkey(master_secret, METADATA_CTX, &mut *metadata_key)?;

        let mut sign_seed = Zeroizing::new([0u8; 32]);
        kdf::derive_subkey(master_secret, SIGN_CTX, &mut *sign_seed)?;
        let signing_key = auth::signing_key_from_seed(&sign_seed);
        // sign_seed zeroizes on drop at end of scope.

        Ok(Self {
            wrap_key,
            metadata_key,
            signing_key,
        })
    }

    /// Open a Vault from a 24-word BIP39 recovery phrase.
    pub fn from_recovery_phrase(phrase: &str) -> Result<Self> {
        let secret = Zeroizing::new(recovery::phrase_to_secret(phrase)?);
        Self::open(&secret)
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        blob::encrypt_chunked(plaintext, &self.wrap_key)
    }

    pub fn decrypt_blob(&self, framed: &[u8]) -> Result<Vec<u8>> {
        blob::decrypt_chunked(framed, &self.wrap_key)
    }

    pub fn encrypt_file_to_blob(&self, in_path: &str, out_path: &str) -> Result<()> {
        blob::encrypt_file_chunked(in_path.as_ref(), out_path.as_ref(), &self.wrap_key)
    }

    pub fn decrypt_blob_to_file(&self, in_path: &str, out_path: &str) -> Result<()> {
        blob::decrypt_file_chunked(in_path.as_ref(), out_path.as_ref(), &self.wrap_key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verify_signature;

    #[test]
    fn vault_blob_round_trip() {
        let secret = [42u8; 32];
        let vault = Vault::open(&secret).unwrap();
        let framed = vault.encrypt_blob(b"hello").unwrap();
        let recovered = vault.decrypt_blob(&framed).unwrap();
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
        let framed = {
            let v = Vault::open(&secret).unwrap();
            v.encrypt_blob(b"persistent").unwrap()
        };
        let v2 = Vault::open(&secret).unwrap();
        assert_eq!(v2.decrypt_blob(&framed).unwrap(), b"persistent");
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

    #[test]
    fn blob_from_one_vault_cannot_be_decrypted_by_different_vault() {
        let secret_a = [42u8; 32];
        let secret_b = [99u8; 32];
        let vault_a = Vault::open(&secret_a).unwrap();
        let vault_b = Vault::open(&secret_b).unwrap();

        let framed = vault_a.encrypt_blob(b"secret data").unwrap();
        let result = vault_b.decrypt_blob(&framed);
        assert!(matches!(result, Err(crate::FilerCryptoError::Aead)));
    }

    #[test]
    fn metadata_from_one_vault_cannot_be_decrypted_by_different_vault() {
        let vault_a = Vault::open(&[42u8; 32]).unwrap();
        let vault_b = Vault::open(&[99u8; 32]).unwrap();

        let field = vault_a.encrypt_metadata_field(b"name").unwrap();
        let result = vault_b.decrypt_metadata_field(&field);
        assert!(matches!(result, Err(crate::FilerCryptoError::Aead)));
    }
}
