#![allow(dead_code)]

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{FilerCryptoError, Result};

/// HKDF info string for the data-key-wrapping subkey.
pub(crate) const WRAP_CTX: &[u8] = b"filer-crypto/v1/wrap";

/// HKDF info string for the metadata-encryption subkey.
pub(crate) const METADATA_CTX: &[u8] = b"filer-crypto/v1/metadata";

/// HKDF info string for the device-signing seed.
pub(crate) const SIGN_CTX: &[u8] = b"filer-crypto/v1/sign";

/// Derives a subkey from the master secret using HKDF-SHA256.
///
/// `info` is the context string that domain-separates each derived subkey.
/// The output length is determined by the caller via the `out` slice length;
/// HKDF-SHA256 supports up to 8160 bytes per derivation.
pub(crate) fn derive_subkey(secret: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    hkdf.expand(info, out)
        .map_err(|_| FilerCryptoError::InvalidKeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_subkey_is_deterministic() {
        let secret = [42u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_subkey(&secret, WRAP_CTX, &mut out1).unwrap();
        derive_subkey(&secret, WRAP_CTX, &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_contexts_produce_different_subkeys() {
        let secret = [42u8; 32];
        let mut wrap = [0u8; 32];
        let mut meta = [0u8; 32];
        let mut sign = [0u8; 32];
        derive_subkey(&secret, WRAP_CTX, &mut wrap).unwrap();
        derive_subkey(&secret, METADATA_CTX, &mut meta).unwrap();
        derive_subkey(&secret, SIGN_CTX, &mut sign).unwrap();
        assert_ne!(wrap, meta);
        assert_ne!(wrap, sign);
        assert_ne!(meta, sign);
    }

    #[test]
    fn known_answer_rfc5869_test_case_1() {
        // RFC 5869 §A.1: HKDF-SHA256 test vector
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        // Note: RFC 5869 also defines a salt; our `derive_subkey` uses `None` as
        // the salt (per Hkdf::new). For the RFC test case we need the salt-bearing
        // form, so we call Hkdf directly here.
        let salt = hex_decode("000102030405060708090a0b0c");
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut out = vec![0u8; 42];
        hkdf.expand(&info, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
