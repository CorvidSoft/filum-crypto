#![allow(dead_code)]
//! AES-256-GCM blob encryption with per-blob random data keys.
//!
//! Each blob has:
//!   - a fresh random 32-byte data key
//!   - a fresh random 12-byte IV
//!   - ciphertext = AES-256-GCM(data_key, iv, plaintext)
//!   - wrapped_key = IV(12) || AES-256-GCM(wrapping_key, wrap_iv, data_key)
//!
//! The wrapped_key field encodes its own 12-byte IV as the first 12 bytes,
//! followed by the GCM ciphertext + tag (48 bytes for a 32-byte key).

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{FilerCryptoError, Result};

/// The encrypted-blob envelope as returned by the crate. Structurally mirrors
/// the `@filer/protocol`'s `EncryptedBlobUpload` shape on the TypeScript side.
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
    /// 12-byte IV || AES-256-GCM ciphertext+tag of the 32-byte data key.
    pub wrapped_key: Vec<u8>,
}

pub(crate) fn encrypt_with_key_wrapping(
    plaintext: &[u8],
    wrapping_key: &[u8; 32],
) -> Result<EncryptedBlob> {
    // 1. Fresh random per-blob data key + IV
    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    // 2. Encrypt plaintext with the data key
    let cipher = Aes256Gcm::new(&data_key.into());
    let ciphertext = cipher
        .encrypt(&iv.into(), plaintext)
        .map_err(|_| FilerCryptoError::Decrypt)?;

    // 3. Wrap the data key with the wrapping key (also AES-256-GCM)
    let mut wrap_iv = [0u8; 12];
    OsRng.fill_bytes(&mut wrap_iv);
    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let wrapped_key_ct = wrapper
        .encrypt(&wrap_iv.into(), data_key.as_slice())
        .map_err(|_| FilerCryptoError::Decrypt)?;

    // Wrapped key layout: iv (12 bytes) || ciphertext+tag
    let mut wrapped_key = Vec::with_capacity(12 + wrapped_key_ct.len());
    wrapped_key.extend_from_slice(&wrap_iv);
    wrapped_key.extend_from_slice(&wrapped_key_ct);

    data_key.zeroize();

    Ok(EncryptedBlob {
        ciphertext,
        iv,
        wrapped_key,
    })
}

pub(crate) fn decrypt_with_key_wrapping(
    blob: &EncryptedBlob,
    wrapping_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if blob.wrapped_key.len() < 12 {
        return Err(FilerCryptoError::Decrypt);
    }
    // Unwrap the data key
    let (wrap_iv_bytes, wrapped_ct) = blob.wrapped_key.split_at(12);
    let mut wrap_iv = [0u8; 12];
    wrap_iv.copy_from_slice(wrap_iv_bytes);

    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let mut data_key_vec = wrapper
        .decrypt(&wrap_iv.into(), wrapped_ct)
        .map_err(|_| FilerCryptoError::Decrypt)?;

    if data_key_vec.len() != 32 {
        data_key_vec.zeroize();
        return Err(FilerCryptoError::Decrypt);
    }
    let mut data_key = [0u8; 32];
    data_key.copy_from_slice(&data_key_vec);
    data_key_vec.zeroize();

    // Decrypt the payload
    let cipher = Aes256Gcm::new(&data_key.into());
    let plaintext = cipher
        .decrypt(&blob.iv.into(), blob.ciphertext.as_slice())
        .map_err(|_| FilerCryptoError::Decrypt);

    data_key.zeroize();
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_blob() {
        let wrapping_key = [42u8; 32];
        let plaintext = b"hello world";
        let blob = encrypt_with_key_wrapping(plaintext, &wrapping_key).unwrap();
        let recovered = decrypt_with_key_wrapping(&blob, &wrapping_key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_blob() {
        let wrapping_key = [42u8; 32];
        let blob = encrypt_with_key_wrapping(&[], &wrapping_key).unwrap();
        let recovered = decrypt_with_key_wrapping(&blob, &wrapping_key).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn round_trip_large_blob() {
        let wrapping_key = [42u8; 32];
        let plaintext = vec![7u8; 1024 * 1024]; // 1 MiB
        let blob = encrypt_with_key_wrapping(&plaintext, &wrapping_key).unwrap();
        let recovered = decrypt_with_key_wrapping(&blob, &wrapping_key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_wrapping_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let blob = encrypt_with_key_wrapping(b"data", &key1).unwrap();
        let result = decrypt_with_key_wrapping(&blob, &key2);
        assert!(matches!(result, Err(FilerCryptoError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.ciphertext[0] ^= 1;
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Decrypt)));
    }

    #[test]
    fn tampered_wrapped_key_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.wrapped_key[15] ^= 1; // flip a bit in the wrapped-key ciphertext
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Decrypt)));
    }

    #[test]
    fn nondeterministic_ciphertext_for_same_input() {
        // Per-blob random data key + IV means two encryptions of the same
        // plaintext produce different ciphertexts.
        let key = [42u8; 32];
        let a = encrypt_with_key_wrapping(b"same", &key).unwrap();
        let b = encrypt_with_key_wrapping(b"same", &key).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.iv, b.iv);
        assert_ne!(a.wrapped_key, b.wrapped_key);
    }

    #[test]
    fn truncated_wrapped_key_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.wrapped_key.truncate(5); // shorter than 12-byte IV
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Decrypt)));
    }
}
