//! Canonical AAD construction for format v2.
//!
//! Every AAD byte string is built here and nowhere else, so the encoding
//! cannot drift between call sites (or across the FFI — callers pass plain
//! identifiers, never AAD bytes). All variable-length components are
//! u32-big-endian length-prefixed, which makes the encoding canonical and
//! unambiguous: no concatenation of distinct inputs can collide.

use crate::error::{FilumCryptoError, Result};

/// Domain-separation prefix for all blob AAD.
pub(crate) const BLOB_DOMAIN: &[u8] = b"filum-crypto/v2/blob";

/// AAD applied to every STREAM segment of a blob:
/// `BLOB_DOMAIN || u32_be(len(blob_id)) || blob_id`.
///
/// Empty `blob_id` is rejected with [`FilumCryptoError::InvalidContext`] —
/// an empty id would silently produce an unbound ciphertext.
///
/// [`FilumCryptoError::InvalidContext`]: crate::FilumCryptoError::InvalidContext
pub(crate) fn blob_segment_aad(blob_id: &str) -> Result<Vec<u8>> {
    let id = blob_id.as_bytes();
    if id.is_empty() {
        return Err(FilumCryptoError::InvalidContext);
    }
    let len = u32::try_from(id.len()).map_err(|_| FilumCryptoError::InvalidContext)?;
    let mut aad = Vec::with_capacity(BLOB_DOMAIN.len() + 4 + id.len());
    aad.extend_from_slice(BLOB_DOMAIN);
    aad.extend_from_slice(&len.to_be_bytes());
    aad.extend_from_slice(id);
    Ok(aad)
}

/// Domain-separation prefix for all metadata-field AAD.
pub(crate) const FIELD_DOMAIN: &[u8] = b"filum-crypto/v2/field";

/// AAD applied to a metadata field:
/// `FIELD_DOMAIN || u32_be(len(record_id)) || record_id ||
/// u32_be(len(field_name)) || field_name`.
///
/// Empty `record_id` or `field_name` is rejected with
/// [`FilumCryptoError::InvalidContext`] — an empty identifier would silently
/// produce an unbound ciphertext.
///
/// [`FilumCryptoError::InvalidContext`]: crate::FilumCryptoError::InvalidContext
pub(crate) fn field_aad(record_id: &str, field_name: &str) -> Result<Vec<u8>> {
    let record = record_id.as_bytes();
    let field = field_name.as_bytes();
    if record.is_empty() || field.is_empty() {
        return Err(FilumCryptoError::InvalidContext);
    }
    let record_len = u32::try_from(record.len()).map_err(|_| FilumCryptoError::InvalidContext)?;
    let field_len = u32::try_from(field.len()).map_err(|_| FilumCryptoError::InvalidContext)?;
    let mut aad = Vec::with_capacity(FIELD_DOMAIN.len() + 4 + record.len() + 4 + field.len());
    aad.extend_from_slice(FIELD_DOMAIN);
    aad.extend_from_slice(&record_len.to_be_bytes());
    aad.extend_from_slice(record);
    aad.extend_from_slice(&field_len.to_be_bytes());
    aad.extend_from_slice(field);
    Ok(aad)
}

/// AAD applied to the data-key wrap: [`blob_segment_aad`] followed by every
/// non-key header field — `version || nonce_prefix || chunk_size_be`.
/// Authenticates the header: transplant or header tamper fails at unwrap.
pub(crate) fn blob_wrap_aad(
    blob_id: &str,
    version: u8,
    nonce_prefix: &[u8; 7],
    chunk_size_be: [u8; 4],
) -> Result<Vec<u8>> {
    let mut aad = blob_segment_aad(blob_id)?;
    aad.reserve(1 + nonce_prefix.len() + chunk_size_be.len());
    aad.push(version);
    aad.extend_from_slice(nonce_prefix);
    aad.extend_from_slice(&chunk_size_be);
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FilumCryptoError;

    #[test]
    fn blob_segment_aad_golden_bytes() {
        let aad = blob_segment_aad("abc").unwrap();
        let mut expected = b"filum-crypto/v2/blob".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"abc");
        assert_eq!(aad, expected);
    }

    #[test]
    fn blob_segment_aad_length_prefix_counts_bytes_not_chars() {
        // "é" is one char but two UTF-8 bytes; the prefix must say 2.
        let aad = blob_segment_aad("é").unwrap();
        let mut expected = b"filum-crypto/v2/blob".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 2]);
        expected.extend_from_slice("é".as_bytes());
        assert_eq!(aad, expected);
    }

    #[test]
    fn blob_wrap_aad_golden_bytes() {
        let aad = blob_wrap_aad("abc", 2, &[1, 2, 3, 4, 5, 6, 7], [0, 16, 0, 0]).unwrap();
        let mut expected = b"filum-crypto/v2/blob".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"abc");
        expected.push(2);
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        expected.extend_from_slice(&[0, 16, 0, 0]);
        assert_eq!(aad, expected);
    }

    #[test]
    fn empty_blob_id_is_invalid_context() {
        assert!(matches!(
            blob_segment_aad(""),
            Err(FilumCryptoError::InvalidContext)
        ));
        assert!(matches!(
            blob_wrap_aad("", 2, &[0u8; 7], [0u8; 4]),
            Err(FilumCryptoError::InvalidContext)
        ));
    }

    #[test]
    fn field_aad_golden_bytes() {
        let aad = field_aad("rec-1", "name").unwrap();
        let mut expected = b"filum-crypto/v2/field".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"rec-1");
        expected.extend_from_slice(&[0, 0, 0, 4]);
        expected.extend_from_slice(b"name");
        assert_eq!(aad, expected);
    }

    #[test]
    fn field_aad_length_prefixes_prevent_boundary_ambiguity() {
        // Without length prefixes ("ab","c") and ("a","bc") would concatenate
        // to identical bytes; the prefixes must keep them distinct.
        let ab_c = field_aad("ab", "c").unwrap();
        let a_bc = field_aad("a", "bc").unwrap();
        assert_ne!(ab_c, a_bc);
    }

    #[test]
    fn empty_field_identifiers_are_invalid_context() {
        assert!(matches!(
            field_aad("", "name"),
            Err(FilumCryptoError::InvalidContext)
        ));
        assert!(matches!(
            field_aad("rec-1", ""),
            Err(FilumCryptoError::InvalidContext)
        ));
        assert!(matches!(
            field_aad("", ""),
            Err(FilumCryptoError::InvalidContext)
        ));
    }
}
