//! UniFFI binding layer for filer-crypto.
//!
//! Each UDL type is mirrored here as a thin Rust type.
//!
//! `Vault` holds the core `filer_crypto::Vault` directly (no `Mutex`).
//! UniFFI interface types must be `Send + Sync`; `CoreVault` satisfies both
//! because all its fields (`Zeroizing<[u8; 32]>`, `Zeroizing<[u8; 32]>`,
//! `SigningKey`) are themselves `Send + Sync`. None of the core's methods
//! take `&mut self`, so no interior mutability is required either. Avoiding
//! the `Mutex` also avoids needing to handle `PoisonError` at the FFI
//! boundary, which would violate the no-panic-on-FFI invariant.
//!
//! Byte arrays cross the FFI as `Vec<u8>`. We validate fixed-length inputs
//! (32-byte secrets, 32-byte public keys, 64-byte signatures) inside the
//! wrapper and return `FilerCryptoError::InvalidKeyLength` on mismatch.
//!
//! Secret material (master secrets) is wrapped in `Zeroizing` for the
//! lifetime it sits in this layer. The incoming `Vec<u8>` from UniFFI's
//! marshaling is taken by value; we wrap it in `Zeroizing` immediately so
//! the heap allocation wipes on drop regardless of return path.

use filer_crypto::{
    recovery, DeviceSignature as CoreDeviceSignature, EncryptedField as CoreEncryptedField,
    FilerCryptoError as CoreError, Vault as CoreVault,
};
use zeroize::Zeroizing;

// ---- Error type -------------------------------------------------------
//
// FilerCryptoError is declared HERE (not imported from the core crate) so
// that `uniffi::include_scaffolding!` can apply `udl_derive(Error)` to the
// local type name without violating Rust's orphan rules.

/// All errors returned across the FFI boundary.
///
/// Variants mirror `filer_crypto::FilerCryptoError` exactly, so a
/// `From` impl can convert with no loss of information.
#[derive(Debug, thiserror::Error)]
pub enum FilerCryptoError {
    #[error("AEAD operation failed")]
    Aead,
    #[error("invalid recovery phrase")]
    InvalidPhrase,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("randomness source unavailable")]
    Randomness,
    #[error("I/O error")]
    Io,
}

impl From<CoreError> for FilerCryptoError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Aead => Self::Aead,
            CoreError::InvalidPhrase => Self::InvalidPhrase,
            CoreError::InvalidKeyLength => Self::InvalidKeyLength,
            CoreError::InvalidSignature => Self::InvalidSignature,
            CoreError::Randomness => Self::Randomness,
            CoreError::Io => Self::Io,
        }
    }
}

type Result<T> = std::result::Result<T, FilerCryptoError>;

// ---- Dictionary types -------------------------------------------------
//
// EncryptedField and DeviceSignature are declared here so that
// include_scaffolding! can apply udl_derive(Record) to the local names.
// We keep the iv field as Vec<u8> at the FFI boundary (UDL bytes)
// and validate the fixed 12-byte length when converting back to core types.

#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

impl From<CoreEncryptedField> for EncryptedField {
    fn from(f: CoreEncryptedField) -> Self {
        Self {
            ciphertext: f.ciphertext,
            iv: f.iv.to_vec(),
        }
    }
}

impl TryFrom<EncryptedField> for CoreEncryptedField {
    type Error = FilerCryptoError;
    fn try_from(f: EncryptedField) -> Result<Self> {
        let iv: [u8; 12] =
            f.iv.try_into()
                .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
        Ok(CoreEncryptedField {
            ciphertext: f.ciphertext,
            iv,
        })
    }
}

/// An Ed25519 signature produced by `Vault::sign_challenge`.
///
/// No `Debug` derive: the bytes are raw signature material that we
/// intentionally never print.
#[derive(Clone)]
pub struct DeviceSignature {
    pub bytes: Vec<u8>,
}

impl From<CoreDeviceSignature> for DeviceSignature {
    fn from(s: CoreDeviceSignature) -> Self {
        Self {
            bytes: s.bytes.to_vec(),
        }
    }
}

// ---- Vault interface --------------------------------------------------
//
// `Vault` is declared here so include_scaffolding! can apply udl_derive(Object)
// to the local type. Holds CoreVault directly — see module docs for why no
// Mutex is needed.

pub struct Vault {
    inner: CoreVault,
}

// ---- Include scaffolding ----------------------------------------------
//
// MUST come after all type declarations above; the scaffolding's
// #[udl_derive(...)] macros reference the names declared above.

uniffi::include_scaffolding!("filer_crypto");

// ---- Helpers ----------------------------------------------------------

/// Convert a `Vec<u8>` carrying secret material into a `Zeroizing<[u8; 32]>`,
/// wiping the original Vec's allocation on drop. Returns
/// `InvalidKeyLength` if the input isn't 32 bytes.
fn vec_to_secret_array(bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != 32 {
        return Err(FilerCryptoError::InvalidKeyLength);
    }
    let mut array = Zeroizing::new([0u8; 32]);
    array.copy_from_slice(&bytes);
    Ok(array)
}

// ---- Top-level function implementations -------------------------------

fn generate_master_secret() -> Result<Vec<u8>> {
    let secret = recovery::generate_master_secret().map_err(FilerCryptoError::from)?;
    // Wrap in Zeroizing so the [u8;32] wipes when this scope ends; the
    // returned Vec is a fresh allocation owned by UniFFI's marshaler.
    let secret = Zeroizing::new(secret);
    Ok(secret.to_vec())
}

fn secret_to_phrase(secret: Vec<u8>) -> Result<String> {
    let array = vec_to_secret_array(secret)?;
    recovery::secret_to_phrase(&array).map_err(Into::into)
}

fn phrase_to_secret(phrase: String) -> Result<Vec<u8>> {
    let secret = recovery::phrase_to_secret(&phrase).map_err(FilerCryptoError::from)?;
    let secret = Zeroizing::new(secret);
    Ok(secret.to_vec())
}

fn verify_signature(public_key: Vec<u8>, nonce: Vec<u8>, signature: Vec<u8>) -> Result<()> {
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| FilerCryptoError::InvalidKeyLength)?;
    filer_crypto::verify_signature(&pk, &nonce, &sig).map_err(Into::into)
}

// ---- Vault method implementations -------------------------------------

impl Vault {
    pub fn open(master_secret: Vec<u8>) -> Result<Self> {
        let array = vec_to_secret_array(master_secret)?;
        let core = CoreVault::open(&array).map_err(FilerCryptoError::from)?;
        Ok(Self { inner: core })
    }

    pub fn from_recovery_phrase(phrase: String) -> Result<Self> {
        let core = CoreVault::from_recovery_phrase(&phrase).map_err(FilerCryptoError::from)?;
        Ok(Self { inner: core })
    }

    pub fn encrypt_blob(&self, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        self.inner.encrypt_blob(&plaintext).map_err(Into::into)
    }

    pub fn decrypt_blob(&self, framed: Vec<u8>) -> Result<Vec<u8>> {
        self.inner.decrypt_blob(&framed).map_err(Into::into)
    }

    pub fn encrypt_file_to_blob(&self, in_path: String, out_path: String) -> Result<()> {
        self.inner
            .encrypt_file_to_blob(&in_path, &out_path)
            .map_err(Into::into)
    }

    pub fn decrypt_blob_to_file(&self, in_path: String, out_path: String) -> Result<()> {
        self.inner
            .decrypt_blob_to_file(&in_path, &out_path)
            .map_err(Into::into)
    }

    pub fn encrypt_metadata_field(&self, plaintext: Vec<u8>) -> Result<EncryptedField> {
        let core_field = self
            .inner
            .encrypt_metadata_field(&plaintext)
            .map_err(FilerCryptoError::from)?;
        Ok(core_field.into())
    }

    pub fn decrypt_metadata_field(&self, field: EncryptedField) -> Result<Vec<u8>> {
        let core_field: CoreEncryptedField = field.try_into()?;
        self.inner
            .decrypt_metadata_field(&core_field)
            .map_err(FilerCryptoError::from)
    }

    pub fn sign_challenge(&self, nonce: Vec<u8>) -> DeviceSignature {
        self.inner.sign_challenge(&nonce).into()
    }

    pub fn device_public_key(&self) -> Vec<u8> {
        self.inner.device_public_key().to_vec()
    }
}
