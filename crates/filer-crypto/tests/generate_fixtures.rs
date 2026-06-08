//! Cross-language test-fixture generator.
//!
//! Produces the JSON files in `Tests/FilerCryptoTests/Fixtures/` that the
//! Swift parity tests decrypt and verify. Run with:
//!
//!     cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture
//!
//! Uses an all-zero master secret — the standard "obvious test vector"
//! sentinel. Never use this secret for real keys.
//!
//! Blob / metadata fixtures use random nonces and per-blob data keys, so
//! they will differ byte-for-byte across regenerations. That's fine —
//! the property they encode is "Rust-produced envelope decrypts in
//! Swift", not "byte-identical regeneration." If the wire format ever
//! changes, the OLD committed bytes fail to decrypt and the parity test
//! suite goes red. The blob fixture stores the full framed bytes of the
//! chunked codec; Swift asserts `decryptBlob(framed:)` returns the plaintext.
//!
//! The signature fixture IS byte-identical across runs because ed25519
//! is deterministic given the same key + nonce.

use std::fs;
use std::path::{Path, PathBuf};

use filer_crypto::{Vault, recovery, verify_signature};
use serde::Serialize;

const FIXTURE_MASTER_SECRET: [u8; 32] = [0u8; 32];

#[derive(Serialize)]
struct BlobFixture {
    note: &'static str,
    plaintext_hex: String,
    /// Full framed bytes of the chunked STREAM codec (72-byte header + body).
    framed_hex: String,
}

#[derive(Serialize)]
struct MetadataFixture {
    note: &'static str,
    plaintext_hex: String,
    field: FieldBytes,
}

#[derive(Serialize)]
struct FieldBytes {
    ciphertext_hex: String,
    iv_hex: String,
}

#[derive(Serialize)]
struct SignatureFixture {
    note: &'static str,
    nonce_hex: String,
    public_key_hex: String,
    signature_hex: String,
}

fn fixtures_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/filer-crypto/. Walk up two levels to repo root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Tests")
        .join("FilerCryptoTests")
        .join("Fixtures")
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) {
    let json = serde_json::to_string_pretty(value).expect("serialize");
    fs::write(&path, json + "\n").expect("write fixture");
    eprintln!("wrote {}", path.display());
}

#[test]
#[ignore = "regenerate with: cargo test -p filer-crypto --test generate_fixtures -- --ignored --nocapture"]
fn regenerate_fixtures() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("mkdir fixtures");

    let vault = Vault::open(&FIXTURE_MASTER_SECRET).expect("open vault");

    // --- Blob fixture ---
    let blob_plaintext = b"filer-crypto v1 blob fixture".to_vec();
    let framed = vault.encrypt_blob(&blob_plaintext).expect("encrypt blob");
    // Round-trip check before we commit the bytes.
    let recovered = vault.decrypt_blob(&framed).expect("decrypt blob");
    assert_eq!(recovered, blob_plaintext);
    write_json(
        dir.join("blob_v1.json"),
        &BlobFixture {
            note: "Rust-produced golden. Decrypt with master_secret = [0u8; 32].",
            plaintext_hex: hex::encode(&blob_plaintext),
            framed_hex: hex::encode(&framed),
        },
    );

    // --- Metadata field fixture ---
    let field_plaintext = b"filer-crypto v1 metadata fixture".to_vec();
    let field = vault
        .encrypt_metadata_field(&field_plaintext)
        .expect("encrypt metadata");
    let recovered = vault
        .decrypt_metadata_field(&field)
        .expect("decrypt metadata");
    assert_eq!(recovered, field_plaintext);
    write_json(
        dir.join("metadata_v1.json"),
        &MetadataFixture {
            note: "Rust-produced golden. Decrypt with master_secret = [0u8; 32].",
            plaintext_hex: hex::encode(&field_plaintext),
            field: FieldBytes {
                ciphertext_hex: hex::encode(&field.ciphertext),
                iv_hex: hex::encode(field.iv),
            },
        },
    );

    // --- Signature fixture ---
    let nonce = [0u8; 32];
    let signature = vault.sign_challenge(&nonce);
    let public_key = vault.device_public_key();
    verify_signature(&public_key, &nonce, &signature.bytes).expect("verify own signature");
    write_json(
        dir.join("signature_v1.json"),
        &SignatureFixture {
            note: "Rust-produced golden. Ed25519 is deterministic given key+nonce.",
            nonce_hex: hex::encode(nonce),
            public_key_hex: hex::encode(public_key),
            signature_hex: hex::encode(signature.bytes),
        },
    );

    // Sanity: BIP39 round-trip from the fixture secret (used in
    // RecoveryPhraseTests on the Swift side as a known-answer check).
    let phrase = recovery::secret_to_phrase(&FIXTURE_MASTER_SECRET).expect("to phrase");
    let back = recovery::phrase_to_secret(&phrase).expect("from phrase");
    assert_eq!(back, FIXTURE_MASTER_SECRET);
    eprintln!("BIP39 phrase for [0u8; 32]: {phrase}");
}
