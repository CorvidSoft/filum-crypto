//! Ed25519 device challenge-response signing.
//!
//! The device's signing key seed is derived from the master secret via HKDF.
//! Same master secret → same signing key → same public key, so the device
//! identity is stable across reinstalls as long as the master secret is
//! recovered.

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::error::{FilerCryptoError, Result};

/// An Ed25519 signature produced by [`Vault::sign_challenge`].
///
/// `Debug` is implemented manually to redact the raw signature bytes — signatures
/// are sensitive cryptographic material and must never appear in logs or panic
/// messages.
#[derive(Clone)]
pub struct DeviceSignature {
    pub bytes: [u8; 64],
}

impl core::fmt::Debug for DeviceSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceSignature")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

pub(crate) fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub(crate) fn sign_challenge(key: &SigningKey, nonce: &[u8]) -> DeviceSignature {
    let sig = key.sign(nonce);
    DeviceSignature {
        bytes: sig.to_bytes(),
    }
}

pub(crate) fn public_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Verify a signature. Public so tests can use it; in production the backend
/// owns verification.
pub fn verify_signature(public_key: &[u8; 32], nonce: &[u8], signature: &[u8; 64]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| FilerCryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(nonce, &sig)
        .map_err(|_| FilerCryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let nonce = b"backend-issued-nonce";
        let sig = sign_challenge(&key, nonce);
        let pk = public_key_bytes(&key);
        verify_signature(&pk, nonce, &sig.bytes).unwrap();
    }

    #[test]
    fn signature_is_deterministic_for_same_seed_and_nonce() {
        // Ed25519 signatures are deterministic by spec (RFC 8032).
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let nonce = b"nonce";
        let sig1 = sign_challenge(&key, nonce);
        let sig2 = sign_challenge(&key, nonce);
        assert_eq!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn different_seeds_produce_different_public_keys() {
        let key1 = signing_key_from_seed(&[1u8; 32]);
        let key2 = signing_key_from_seed(&[2u8; 32]);
        assert_ne!(public_key_bytes(&key1), public_key_bytes(&key2));
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let sig = sign_challenge(&key, b"nonce");
        let pk = public_key_bytes(&key);
        let result = verify_signature(&pk, b"different", &sig.bytes);
        assert!(matches!(result, Err(FilerCryptoError::InvalidSignature)));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let sig = sign_challenge(&key, b"nonce");
        let pk = public_key_bytes(&key);
        let mut bad = sig.bytes;
        bad[0] ^= 1;
        let result = verify_signature(&pk, b"nonce", &bad);
        assert!(matches!(result, Err(FilerCryptoError::InvalidSignature)));
    }

    #[test]
    fn invalid_public_key_fails_verification() {
        // An all-zeros key is rejected by verify_strict.
        let result = verify_signature(&[0u8; 32], b"nonce", &[0u8; 64]);
        assert!(matches!(result, Err(FilerCryptoError::InvalidSignature)));
    }
}
