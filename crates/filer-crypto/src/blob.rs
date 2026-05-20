//! AES-256-GCM blob encryption with per-blob random data keys.
//!
//! Each blob carries TWO independent 12-byte IVs:
//!   - `iv` (the EncryptedBlob.iv field) — used to encrypt the payload
//!   - `wrap_iv` — used to encrypt the data key
//!
//! The wrap_iv is embedded as the first 12 bytes of `wrapped_key`; `iv` is
//! a separate field on EncryptedBlob.
//!
//! Layout:
//!   - `data_key`    = random 32 bytes
//!   - `iv`          = random 12 bytes
//!   - `wrap_iv`     = random 12 bytes
//!   - `ciphertext`  = AES-256-GCM(`data_key`, `iv`, plaintext)
//!   - `wrapped_key` = `wrap_iv` (12 bytes) followed by AES-256-GCM(`wrapping_key`,
//!     `wrap_iv`, `data_key`) which is 48 bytes (32-byte key + 16-byte GCM tag)

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

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
    let mut data_key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut data_key[..])
        .map_err(|_| FilerCryptoError::Randomness)?;
    let mut iv = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|_| FilerCryptoError::Randomness)?;

    // 2. Encrypt plaintext with the data key
    let cipher = Aes256Gcm::new((&*data_key).into());
    let ciphertext = cipher
        .encrypt(&iv.into(), plaintext)
        .map_err(|_| FilerCryptoError::Aead)?;

    // 3. Wrap the data key with the wrapping key (also AES-256-GCM)
    let mut wrap_iv = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut wrap_iv)
        .map_err(|_| FilerCryptoError::Randomness)?;
    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let wrapped_key_ct = wrapper
        .encrypt(&wrap_iv.into(), data_key.as_slice())
        .map_err(|_| FilerCryptoError::Aead)?;

    // Wrapped key layout: iv (12 bytes) || ciphertext+tag
    let mut wrapped_key = Vec::with_capacity(12 + wrapped_key_ct.len());
    wrapped_key.extend_from_slice(&wrap_iv);
    wrapped_key.extend_from_slice(&wrapped_key_ct);

    // data_key is zeroized on Drop via Zeroizing<[u8; 32]>

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
        return Err(FilerCryptoError::Aead);
    }
    // Unwrap the data key
    let (wrap_iv_bytes, wrapped_ct) = blob.wrapped_key.split_at(12);
    let mut wrap_iv = [0u8; 12];
    wrap_iv.copy_from_slice(wrap_iv_bytes);

    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let data_key_vec = Zeroizing::new(
        wrapper
            .decrypt(&wrap_iv.into(), wrapped_ct)
            .map_err(|_| FilerCryptoError::Aead)?,
    );

    if data_key_vec.len() != 32 {
        return Err(FilerCryptoError::Aead);
    }
    let mut data_key = Zeroizing::new([0u8; 32]);
    data_key.copy_from_slice(&data_key_vec);
    // data_key_vec is zeroized on Drop via Zeroizing<Vec<u8>>

    // Decrypt the payload
    let cipher = Aes256Gcm::new((&*data_key).into());
    cipher
        .decrypt(&blob.iv.into(), blob.ciphertext.as_slice())
        .map_err(|_| FilerCryptoError::Aead)
    // data_key is zeroized on Drop via Zeroizing<[u8; 32]>
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
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.ciphertext[0] ^= 1;
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn tampered_wrapped_key_fails() {
        let key = [42u8; 32];
        let mut blob = encrypt_with_key_wrapping(b"data", &key).unwrap();
        blob.wrapped_key[15] ^= 1; // flip a bit in the wrapped-key ciphertext
        let result = decrypt_with_key_wrapping(&blob, &key);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn iv_and_data_key_are_fresh_per_encryption() {
        // Defense against accidental IV/key caching: each encryption MUST pull
        // fresh randomness for the data key and both IVs. A refactor that
        // memoized any of these would produce identical envelopes here and
        // catastrophically break the AES-GCM contract.
        //
        // Technically probabilistic — the test would pass falsely if OsRng
        // returned the same 12-byte IV twice in a row (collision probability
        // 2^-96) — but that's well below the cosmic-ray bit-flip threshold
        // and not worth defending against with an injected RNG.
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
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn aes_gcm_nist_known_answer() {
        // NIST SP 800-38D, AES-256-GCM, empty plaintext
        // Key: 32 bytes of 0x00, IV: 12 bytes of 0x00, no AAD
        // Expected output is just the 16-byte authentication tag.
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let cipher = Aes256Gcm::new(&key.into());
        let ct = cipher.encrypt(&iv.into(), b"".as_ref()).unwrap();
        // Empty plaintext means ct is just the 16-byte tag
        assert_eq!(hex_to_vec("530f8afbc74536b9a963b4f1c4cb738b"), ct);
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
