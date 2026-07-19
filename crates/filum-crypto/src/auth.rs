//! Ed25519 device challenge-response signing.
//!
//! The device's signing key seed is derived from the master secret via HKDF.
//! Same master secret → same signing key → same public key, so the device
//! identity is stable across reinstalls as long as the master secret is
//! recovered.

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::error::{FilumCryptoError, Result};

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

/// Domain-separation tag prepended to the attestation message before it is
/// signed by the master-derived account identity key (#115).
///
/// Signing `ATTEST_DOMAIN || message` — never the raw caller bytes —
/// structurally binds every signature this key produces to the attestation
/// purpose. A signature can't be replayed as a differently-framed protocol
/// message, and a future flow that ever signs server-chosen bytes must use a
/// *different* domain tag to be verifiable, so a malicious server cannot craft
/// a "challenge" whose signature also validates as an attestation.
///
/// WIRE FORMAT (major-version stable, per CLAUDE.md invariant 7): the backend
/// Ed25519 verifier MUST prepend these identical bytes before `verify_strict`.
pub const ATTEST_DOMAIN: &[u8] = b"filum-crypto/v1/attest";

fn domain_separated(message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ATTEST_DOMAIN.len() + message.len());
    buf.extend_from_slice(ATTEST_DOMAIN);
    buf.extend_from_slice(message);
    buf
}

pub(crate) fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub(crate) fn sign_challenge(key: &SigningKey, message: &[u8]) -> DeviceSignature {
    let sig = key.sign(&domain_separated(message));
    DeviceSignature {
        bytes: sig.to_bytes(),
    }
}

pub(crate) fn public_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Verify an attestation signature over `ATTEST_DOMAIN || message`. Public so
/// tests can use it; in production the backend owns verification and must apply
/// the same domain prefix.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| FilumCryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(&domain_separated(message), &sig)
        .map_err(|_| FilumCryptoError::InvalidSignature)
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
    fn signature_is_over_the_domain_separated_message() {
        // Prove the domain tag is actually prepended (#115): the signature must
        // verify against ATTEST_DOMAIN || message but NOT against the bare
        // message. A verifier (or replay) that forgets the prefix is rejected.
        let seed = [9u8; 32];
        let key = signing_key_from_seed(&seed);
        let message = b"backend-issued-nonce";
        let sig = sign_challenge(&key, message);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes(&key)).unwrap();
        let signature = Signature::from_bytes(&sig.bytes);

        // Bare message: MUST fail.
        assert!(vk.verify_strict(message, &signature).is_err());
        // Domain-separated message: MUST succeed.
        let mut expected = ATTEST_DOMAIN.to_vec();
        expected.extend_from_slice(message);
        assert!(vk.verify_strict(&expected, &signature).is_ok());
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
        assert!(matches!(result, Err(FilumCryptoError::InvalidSignature)));
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
        assert!(matches!(result, Err(FilumCryptoError::InvalidSignature)));
    }

    #[test]
    fn invalid_public_key_fails_verification() {
        // An all-zeros key is rejected by verify_strict.
        let result = verify_signature(&[0u8; 32], b"nonce", &[0u8; 64]);
        assert!(matches!(result, Err(FilumCryptoError::InvalidSignature)));
    }
}
