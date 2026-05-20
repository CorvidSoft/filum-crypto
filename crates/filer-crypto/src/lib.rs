//! Filer cryptographic core.
//!
//! This crate is the pure-Rust core of `filer-crypto`. It exposes a single
//! stateful type [`Vault`] that owns derived keys and provides envelope
//! encryption + signing, plus stateless functions in the [`recovery`] module
//! for BIP39 phrase ↔ master secret conversion.
//!
//! All other modules are crate-private.

mod error;
mod kdf;

pub use error::{FilerCryptoError, Result};
