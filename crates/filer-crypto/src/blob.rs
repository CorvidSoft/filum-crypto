//! AES-256-GCM chunked blob encryption.
//!
//! The **chunked STREAM codec** (`encrypt_chunked` / `decrypt_chunked` plus the
//! file-streaming `encrypt_file_chunked` / `decrypt_file_chunked`) is the only
//! blob format the app ships. It uses the audited `aead::stream` STREAM
//! construction (`EncryptorBE32` / `DecryptorBE32`) so decryption processes one
//! ~1 MiB chunk at a time — bounded memory, which the iOS FileProvider
//! extension (hard 20 MB limit) requires. A random per-blob 32-byte data key is
//! wrapped under the vault wrapping key and carried in a fixed 72-byte header.
//!
//! Header layout (72 bytes): version `u8` = 1, then a 60-byte wrapped data key,
//! then a 7-byte nonce prefix, then `chunk_size` as a big-endian `u32`. Body: a
//! sequence of STREAM segments; every segment but the last is `chunk_size + 16`
//! bytes (chunk + GCM tag), the last is `<= chunk_size + 16`.

use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand_core::{OsRng, RngCore};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::{FilerCryptoError, Result};

const VERSION: u8 = 1;
/// `wrap_iv` (12 bytes) || AES-256-GCM(wrapping_key, wrap_iv, 32-byte data_key)
/// where the ciphertext+tag is 48 bytes → 60 bytes total.
const WRAPPED_KEY_LEN: usize = 60;
/// `Aes256Gcm` has a 12-byte nonce; `StreamBE32` reserves 5 bytes (4-byte
/// big-endian block counter + 1-byte last-block flag), leaving a 7-byte prefix.
const NONCE_PREFIX_LEN: usize = 7;
const HEADER_LEN: usize = 1 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN + 4; // 72
/// Plaintext chunk size. Decryption holds at most one ciphertext chunk
/// (`CHUNK_SIZE + 16`) plus its plaintext at a time.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Wrap a 32-byte data key under `wrapping_key`.
///
/// Layout: `wrap_iv` (12 random bytes) || AES-256-GCM(wrapping_key, wrap_iv,
/// data_key). The ciphertext+tag is 48 bytes, so the result is exactly
/// [`WRAPPED_KEY_LEN`] (60) bytes.
fn wrap_data_key(data_key: &[u8; 32], wrapping_key: &[u8; 32]) -> Result<[u8; WRAPPED_KEY_LEN]> {
    let mut wrap_iv = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut wrap_iv)
        .map_err(|_| FilerCryptoError::Randomness)?;

    let wrapper = Aes256Gcm::new(wrapping_key.into());
    let wrapped_key_ct = wrapper
        .encrypt(&wrap_iv.into(), data_key.as_slice())
        .map_err(|_| FilerCryptoError::Aead)?;

    // 12-byte IV + 48-byte ciphertext+tag = 60 bytes.
    if wrapped_key_ct.len() != WRAPPED_KEY_LEN - 12 {
        return Err(FilerCryptoError::Aead);
    }
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out[..12].copy_from_slice(&wrap_iv);
    out[12..].copy_from_slice(&wrapped_key_ct);
    Ok(out)
}

/// Unwrap a [`WRAPPED_KEY_LEN`]-byte wrapped key, returning the recovered
/// 32-byte data key. The result zeroizes on drop.
fn unwrap_data_key(wrapped: &[u8], wrapping_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(FilerCryptoError::Aead);
    }
    let (wrap_iv_bytes, wrapped_ct) = wrapped.split_at(12);
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
    Ok(data_key)
}

fn write_header(
    out: &mut Vec<u8>,
    wrapped_key: &[u8; WRAPPED_KEY_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) {
    out.push(VERSION);
    out.extend_from_slice(wrapped_key);
    out.extend_from_slice(nonce_prefix);
    out.extend_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
}

/// Encrypt `plaintext` into the chunked framed format in memory.
pub fn encrypt_chunked(plaintext: &[u8], wrapping_key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut data_key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut data_key[..])
        .map_err(|_| FilerCryptoError::Randomness)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_prefix)
        .map_err(|_| FilerCryptoError::Randomness)?;
    let wrapped = wrap_data_key(&data_key, wrapping_key)?;

    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 64);
    write_header(&mut out, &wrapped, &nonce_prefix);

    let cipher = Aes256Gcm::new((&*data_key).into());
    let mut enc = EncryptorBE32::from_aead(cipher, (&nonce_prefix).into());

    // Framing must be byte-identical to `encrypt_file_chunked`, which decides
    // "last" by reading a short (`< CHUNK_SIZE`) read. So: every full
    // `CHUNK_SIZE`-byte prefix chunk is an `encrypt_next`, and a single final
    // `encrypt_last` covers the trailing remainder `[full * CHUNK_SIZE..]`.
    // That remainder is EMPTY when `plaintext` is empty or an exact nonzero
    // multiple of `CHUNK_SIZE` — in which case the file streamer also emits a
    // trailing empty last segment. (Marking a full final chunk as
    // `encrypt_last` would desync the two codecs at exact multiples.)
    let full_chunks = plaintext.len() / CHUNK_SIZE;
    for i in 0..full_chunks {
        let start = i * CHUNK_SIZE;
        out.extend_from_slice(
            &enc.encrypt_next(&plaintext[start..start + CHUNK_SIZE])
                .map_err(|_| FilerCryptoError::Aead)?,
        );
    }
    out.extend_from_slice(
        &enc.encrypt_last(&plaintext[full_chunks * CHUNK_SIZE..])
            .map_err(|_| FilerCryptoError::Aead)?,
    );
    Ok(out)
}

/// Decrypt a chunked framed blob in memory.
pub fn decrypt_chunked(framed: &[u8], wrapping_key: &[u8; 32]) -> Result<Vec<u8>> {
    if framed.len() < HEADER_LEN || framed[0] != VERSION {
        return Err(FilerCryptoError::Aead);
    }
    let data_key = unwrap_data_key(&framed[1..1 + WRAPPED_KEY_LEN], wrapping_key)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix
        .copy_from_slice(&framed[1 + WRAPPED_KEY_LEN..1 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN]);
    let cs_off = 1 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN;
    let chunk_size = u32::from_be_bytes(framed[cs_off..cs_off + 4].try_into().unwrap()) as usize;
    // `chunk_size` lives in the UNAUTHENTICATED header. The encoder always writes
    // `CHUNK_SIZE`, so reject anything else rather than trust an attacker-controlled
    // size to drive allocations/work — a tampered blob from an untrusted backend
    // could otherwise demand a huge buffer (fatal under the extension's 20 MB cap).
    if chunk_size != CHUNK_SIZE {
        return Err(FilerCryptoError::Aead);
    }
    let ct_chunk = chunk_size + 16;

    let cipher = Aes256Gcm::new((&*data_key).into());
    let mut dec = DecryptorBE32::from_aead(cipher, (&nonce_prefix).into());

    let body = &framed[HEADER_LEN..];
    let mut out = Vec::with_capacity(body.len());
    let mut it = body.chunks(ct_chunk).peekable();
    if it.peek().is_none() {
        // Body must contain at least the final (>= 16-byte tag) segment.
        return Err(FilerCryptoError::Aead);
    }
    while let Some(chunk) = it.next() {
        if it.peek().is_some() {
            out.extend_from_slice(
                &dec.decrypt_next(chunk)
                    .map_err(|_| FilerCryptoError::Aead)?,
            );
        } else {
            // `decrypt_last` consumes `dec`; this is necessarily the terminal
            // iteration, so break (the borrow checker can't infer that the
            // peeked-`None` else-arm runs exactly once).
            out.extend_from_slice(
                &dec.decrypt_last(chunk)
                    .map_err(|_| FilerCryptoError::Aead)?,
            );
            break;
        }
    }
    Ok(out)
}

/// Read into `buf` until it is full or EOF, looping over short reads.
/// Returns the number of bytes actually read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r
            .read(&mut buf[filled..])
            .map_err(|_| FilerCryptoError::Io)?
        {
            0 => break,
            k => filled += k,
        }
    }
    Ok(filled)
}

/// Encrypt `input` to `output` in the chunked framed format, streaming a single
/// chunk through memory at a time.
pub fn encrypt_file_chunked(input: &Path, output: &Path, wrapping_key: &[u8; 32]) -> Result<()> {
    let mut data_key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut data_key[..])
        .map_err(|_| FilerCryptoError::Randomness)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_prefix)
        .map_err(|_| FilerCryptoError::Randomness)?;
    let wrapped = wrap_data_key(&data_key, wrapping_key)?;

    let mut fin =
        std::io::BufReader::new(std::fs::File::open(input).map_err(|_| FilerCryptoError::Io)?);
    let mut fout =
        std::io::BufWriter::new(std::fs::File::create(output).map_err(|_| FilerCryptoError::Io)?);

    let mut header = Vec::with_capacity(HEADER_LEN);
    write_header(&mut header, &wrapped, &nonce_prefix);
    fout.write_all(&header).map_err(|_| FilerCryptoError::Io)?;

    let cipher = Aes256Gcm::new((&*data_key).into());
    let mut enc = EncryptorBE32::from_aead(cipher, (&nonce_prefix).into());

    let mut buf = vec![0u8; CHUNK_SIZE];
    // We hold the previous full chunk so we know when we've reached the last
    // one (a chunk is "last" only once we read a short/empty read after it).
    let mut pending: Option<Vec<u8>> = None;
    loop {
        let n = read_full(&mut fin, &mut buf)?;
        if let Some(prev) = pending.take() {
            fout.write_all(
                &enc.encrypt_next(&prev[..])
                    .map_err(|_| FilerCryptoError::Aead)?,
            )
            .map_err(|_| FilerCryptoError::Io)?;
        }
        if n < CHUNK_SIZE {
            fout.write_all(
                &enc.encrypt_last(&buf[..n])
                    .map_err(|_| FilerCryptoError::Aead)?,
            )
            .map_err(|_| FilerCryptoError::Io)?;
            break;
        }
        pending = Some(buf[..n].to_vec());
    }
    fout.flush().map_err(|_| FilerCryptoError::Io)?;
    Ok(())
}

/// Decrypt a chunked framed file `input` to `output`, streaming a single
/// ciphertext chunk through memory at a time.
pub fn decrypt_file_chunked(input: &Path, output: &Path, wrapping_key: &[u8; 32]) -> Result<()> {
    let mut fin =
        std::io::BufReader::new(std::fs::File::open(input).map_err(|_| FilerCryptoError::Io)?);
    let mut header = [0u8; HEADER_LEN];
    fin.read_exact(&mut header)
        .map_err(|_| FilerCryptoError::Io)?;
    if header[0] != VERSION {
        return Err(FilerCryptoError::Aead);
    }
    let data_key = unwrap_data_key(&header[1..1 + WRAPPED_KEY_LEN], wrapping_key)?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix
        .copy_from_slice(&header[1 + WRAPPED_KEY_LEN..1 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN]);
    let cs_off = 1 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN;
    let chunk_size = u32::from_be_bytes(header[cs_off..cs_off + 4].try_into().unwrap()) as usize;
    // Reject an attacker-controlled chunk_size from the unauthenticated header
    // before it sizes the read buffer below (see decrypt_chunked for rationale).
    if chunk_size != CHUNK_SIZE {
        return Err(FilerCryptoError::Aead);
    }
    let ct_chunk = chunk_size + 16;

    let cipher = Aes256Gcm::new((&*data_key).into());
    let mut dec = DecryptorBE32::from_aead(cipher, (&nonce_prefix).into());

    let mut fout =
        std::io::BufWriter::new(std::fs::File::create(output).map_err(|_| FilerCryptoError::Io)?);

    let mut buf = vec![0u8; ct_chunk];
    let mut pending: Option<Vec<u8>> = None;
    loop {
        let n = read_full(&mut fin, &mut buf)?;
        if let Some(prev) = pending.take() {
            fout.write_all(
                &dec.decrypt_next(&prev[..])
                    .map_err(|_| FilerCryptoError::Aead)?,
            )
            .map_err(|_| FilerCryptoError::Io)?;
        }
        if n < ct_chunk {
            fout.write_all(
                &dec.decrypt_last(&buf[..n])
                    .map_err(|_| FilerCryptoError::Aead)?,
            )
            .map_err(|_| FilerCryptoError::Io)?;
            break;
        }
        pending = Some(buf[..n].to_vec());
    }
    fout.flush().map_err(|_| FilerCryptoError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZES: &[usize] = &[
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        3 * CHUNK_SIZE + 7,
    ];

    /// Deterministic-but-varied plaintext so swapped/reordered chunks differ.
    fn make_plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn chunked_in_memory_round_trip_all_sizes() {
        let key = [42u8; 32];
        for &len in SIZES {
            let pt = make_plaintext(len);
            let framed = encrypt_chunked(&pt, &key).unwrap();
            let recovered = decrypt_chunked(&framed, &key).unwrap();
            assert_eq!(recovered, pt, "size {len} round-trip mismatch");
        }
    }

    #[test]
    fn chunked_file_round_trip_all_sizes() {
        let key = [42u8; 32];
        for &len in SIZES {
            let pt = make_plaintext(len);

            let src = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(src.path(), &pt).unwrap();
            let enc = tempfile::NamedTempFile::new().unwrap();
            let dec = tempfile::NamedTempFile::new().unwrap();

            encrypt_file_chunked(src.path(), enc.path(), &key).unwrap();
            decrypt_file_chunked(enc.path(), dec.path(), &key).unwrap();

            let recovered = std::fs::read(dec.path()).unwrap();
            assert_eq!(recovered, pt, "size {len} file round-trip mismatch");
        }
    }

    #[test]
    fn in_memory_and_file_formats_are_interchangeable() {
        let key = [42u8; 32];
        for &len in SIZES {
            let pt = make_plaintext(len);

            // (a) in-memory encrypt → decrypt via file path.
            {
                let framed = encrypt_chunked(&pt, &key).unwrap();
                let enc = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(enc.path(), &framed).unwrap();
                let dec = tempfile::NamedTempFile::new().unwrap();
                decrypt_file_chunked(enc.path(), dec.path(), &key).unwrap();
                let recovered = std::fs::read(dec.path()).unwrap();
                assert_eq!(recovered, pt, "size {len} mem-enc/file-dec mismatch");
            }

            // (b) file encrypt → decrypt the produced bytes in memory.
            {
                let src = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(src.path(), &pt).unwrap();
                let enc = tempfile::NamedTempFile::new().unwrap();
                encrypt_file_chunked(src.path(), enc.path(), &key).unwrap();
                let framed = std::fs::read(enc.path()).unwrap();
                let recovered = decrypt_chunked(&framed, &key).unwrap();
                assert_eq!(recovered, pt, "size {len} file-enc/mem-dec mismatch");
            }
        }
    }

    #[test]
    fn chunked_flipped_body_byte_fails() {
        let key = [42u8; 32];
        let pt = make_plaintext(CHUNK_SIZE + 100);
        let mut framed = encrypt_chunked(&pt, &key).unwrap();
        // Flip a byte well inside the body (past the 72-byte header).
        framed[HEADER_LEN + 10] ^= 1;
        assert!(matches!(
            decrypt_chunked(&framed, &key),
            Err(FilerCryptoError::Aead)
        ));
    }

    #[test]
    fn chunked_truncation_fails() {
        let key = [42u8; 32];
        let pt = make_plaintext(CHUNK_SIZE + 100);
        let mut framed = encrypt_chunked(&pt, &key).unwrap();
        framed.truncate(framed.len() - 20);
        assert!(matches!(
            decrypt_chunked(&framed, &key),
            Err(FilerCryptoError::Aead)
        ));
    }

    #[test]
    fn chunked_swapped_chunks_fail() {
        let key = [42u8; 32];
        // >= 3 chunks so we have at least two full ct_chunk-sized blocks to swap.
        let pt = make_plaintext(3 * CHUNK_SIZE + 7);
        let framed = encrypt_chunked(&pt, &key).unwrap();

        let ct_chunk = CHUNK_SIZE + 16;
        let body_start = HEADER_LEN;
        let mut tampered = framed.clone();
        // Swap the first and second full ciphertext chunks in the body.
        let first = body_start;
        let second = body_start + ct_chunk;
        let (a, b) = tampered.split_at_mut(second);
        a[first..first + ct_chunk].swap_with_slice(&mut b[..ct_chunk]);

        assert!(matches!(
            decrypt_chunked(&tampered, &key),
            Err(FilerCryptoError::Aead)
        ));
    }

    #[test]
    fn chunked_wrong_wrapping_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let framed = encrypt_chunked(b"some data", &key1).unwrap();
        let result = decrypt_chunked(&framed, &key2);
        assert!(matches!(result, Err(FilerCryptoError::Aead)));
    }

    #[test]
    fn chunked_tampered_chunk_size_header_rejected() {
        // The chunk_size field (header offset 68..72) is unauthenticated. A tampered
        // value must be rejected BEFORE it sizes any allocation — guard against a
        // malicious/huge size (DoS) rather than attempting a giant buffer.
        let key = [42u8; 32];
        let framed = encrypt_chunked(b"some data", &key).unwrap();
        let cs_off = 1 + WRAPPED_KEY_LEN + NONCE_PREFIX_LEN;
        let mut tampered = framed.clone();
        tampered[cs_off..cs_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert!(matches!(
            decrypt_chunked(&tampered, &key),
            Err(FilerCryptoError::Aead)
        ));
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
