//! Filer cryptographic core.
//!
//! This crate is the pure-Rust core of `filer-crypto`. It exposes a single
//! stateful type [`Vault`] that owns derived keys and provides envelope
//! encryption + signing, plus stateless functions in the [`recovery`] module
//! for BIP39 phrase ↔ master secret conversion.
//!
//! All other modules are crate-private.

mod auth;
mod blob;
mod error;
mod kdf;
mod metadata;
pub mod recovery;
mod vault;

pub use auth::{DeviceSignature, verify_signature};
pub use blob::{
    CHUNK_SIZE, decrypt_chunked, decrypt_file_chunked, encrypt_chunked, encrypt_file_chunked,
};
pub use error::{FilerCryptoError, Result};
pub use metadata::EncryptedField;
pub use vault::Vault;
