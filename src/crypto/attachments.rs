//! Deterministic attachment encryption using a streaming AEAD
//! (libsodium's `crypto_secretstream_xchacha20poly1305`).
//!
//! Port of `libsession-util/src/attachments.cpp` and
//! `libsession-util/include/session/attachments.hpp`.
//!
//! Key features:
//! - Deterministic: same seed + data always produces the same ciphertext
//! - Streaming: data is chunked into 32 KiB blocks with per-block authentication tags
//! - Padded: ciphertext is padded to hide exact size

use crate::crypto::types::{CryptoError, CryptoResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of chunks that we encrypt at a time.
pub const ENCRYPT_CHUNK_SIZE: usize = 32_768;

/// Size of the initial encryption header
/// (`crypto_secretstream_xchacha20poly1305_HEADERBYTES`).
pub const ENCRYPT_HEADER: usize = 24;

/// Overhead of the mac+tag added to each chunk
/// (`crypto_secretstream_xchacha20poly1305_ABYTES`).
pub const ENCRYPT_CHUNK_OVERHEAD: usize = 17;

/// Encryption key size
/// (`crypto_secretstream_xchacha20poly1305_KEYBYTES`).
pub const ENCRYPT_KEY_SIZE: usize = 32;

/// Total size of one encrypted chunk (data + overhead).
pub const ENCRYPTED_CHUNK_TOTAL: usize = ENCRYPT_CHUNK_SIZE + ENCRYPT_CHUNK_OVERHEAD;

/// The maximum file size that may be encrypted (unless passing `allow_large`).
/// This is the largest unencrypted data size whose padded+encrypted size equals
/// that of a 10_000_000-byte file (10_218_286 input == 10_223_616 encrypted).
pub const MAX_REGULAR_SIZE: usize = 10_218_286;

// ---------------------------------------------------------------------------
// Domain enum
// ---------------------------------------------------------------------------

/// Domain separators used to differentiate key/nonce generation for different
/// attachment types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Generic attachment (file sent between users).
    Attachment = 0x00,
    /// Profile picture.
    ProfilePic = 0x01,
}

// ---------------------------------------------------------------------------
// Secretstream (minimal reimplementation)
// ---------------------------------------------------------------------------
//
// This is a faithful reimplementation of libsodium's
// `crypto_secretstream_xchacha20poly1305` using only:
//   - `chacha20::hchacha` (HChaCha20 key derivation)
//   - `chacha20::ChaCha20` (IETF stream cipher for keystream & encryption)
//   - `poly1305::Poly1305` (one-time MAC)
//
// The internal state mirrors libsodium's:
//   k      [32]  – derived subkey
//   nonce  [12]  – 4-byte LE counter (starts at 1) || 8-byte inonce

/// Tag byte: regular (non-final) message chunk.
const TAG_MESSAGE: u8 = 0;
/// Tag byte: final message chunk.
const TAG_FINAL: u8 = 3;

/// Minimal secretstream state (push + pull).
struct SecretStream {
    /// Derived 32-byte subkey.
    key: [u8; 32],
    /// 12-byte nonce: first 4 bytes are a little-endian counter (starts at 1),
    /// next 8 bytes are the "inner nonce" derived from the header.
    nonce: [u8; 12],
}

impl SecretStream {
    /// Initialise for **push** (encryption) with an explicit nonce/header.
    ///
    /// This mirrors libsodium's custom `init_push_with_nonce`: it writes the
    /// full 24-byte header into `header_out` and returns the initialised state.
    fn init_push(
        header_out: &mut [u8; ENCRYPT_HEADER],
        key: &[u8; ENCRYPT_KEY_SIZE],
        nonce_bytes: &[u8; ENCRYPT_HEADER],
    ) -> Self {
        use chacha20::R20;
        use chacha20::hchacha;

        header_out.copy_from_slice(nonce_bytes);

        // Derive subkey via HChaCha20(key, header[0..16])
        let hchacha_input: [u8; 16] = header_out[..16].try_into().unwrap();
        let subkey = hchacha::<R20>(&(*key).into(), &hchacha_input.into());

        let mut k = [0u8; 32];
        k.copy_from_slice(subkey.as_slice());

        // nonce = counter(4 bytes, LE, starting at 1) || inonce(8 bytes from header[16..24])
        let mut nonce = [0u8; 12];
        nonce[0] = 1; // counter = 1
        nonce[4..12].copy_from_slice(&header_out[16..24]);

        SecretStream { key: k, nonce }
    }

    /// Initialise for **pull** (decryption) from the header bytes.
    fn init_pull(header: &[u8; ENCRYPT_HEADER], key: &[u8; ENCRYPT_KEY_SIZE]) -> Self {
        use chacha20::R20;
        use chacha20::hchacha;

        let hchacha_input: [u8; 16] = header[..16].try_into().unwrap();
        let subkey = hchacha::<R20>(&(*key).into(), &hchacha_input.into());

        let mut k = [0u8; 32];
        k.copy_from_slice(subkey.as_slice());

        let mut nonce = [0u8; 12];
        nonce[0] = 1;
        nonce[4..12].copy_from_slice(&header[16..24]);

        SecretStream { key: k, nonce }
    }

    /// Encrypt a chunk (push) using libsodium secretstream wire semantics.
    fn push(&mut self, plaintext: &[u8], tag: u8) -> Vec<u8> {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        let mlen = plaintext.len();
        let mut out = vec![0u8; 1 + mlen + 16];

        // Counter 0 supplies the one-time Poly1305 key.
        let mut block0 = [0u8; 64];
        let mut chacha = ChaCha20::new(&self.key.into(), &self.nonce.into());
        chacha.apply_keystream(&mut block0);
        let poly_key: [u8; 32] = block0[..32].try_into().unwrap();

        // Counter 1 encrypts a 64-byte tag block; its first byte is the
        // encrypted tag and the remainder is also authenticated.
        let mut tag_block = [0u8; 64];
        tag_block[0] = tag;
        chacha.apply_keystream(&mut tag_block);
        out[0] = tag_block[0];

        // Counter 2 and onward encrypt the actual chunk data.
        out[1..1 + mlen].copy_from_slice(plaintext);
        chacha.apply_keystream(&mut out[1..1 + mlen]);

        let mac_tag = Self::compute_mac(&poly_key, &tag_block, &out[1..1 + mlen]);
        out[1 + mlen..].copy_from_slice(&mac_tag);

        self.update_state(&mac_tag, tag);
        out
    }

    /// Decrypt a chunk (pull) using libsodium secretstream wire semantics.
    fn pull(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, u8), ()> {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        if ciphertext.len() < ENCRYPT_CHUNK_OVERHEAD {
            return Err(());
        }
        let mlen = ciphertext.len() - ENCRYPT_CHUNK_OVERHEAD;

        // Counter 0 supplies the Poly1305 key; counter 1 reconstructs the
        // authenticated tag block; counter 2 decrypts the actual message.
        let mut block0 = [0u8; 64];
        let mut chacha = ChaCha20::new(&self.key.into(), &self.nonce.into());
        chacha.apply_keystream(&mut block0);
        let poly_key: [u8; 32] = block0[..32].try_into().unwrap();

        let mut tag_block = [0u8; 64];
        tag_block[0] = ciphertext[0];
        chacha.apply_keystream(&mut tag_block);
        let tag = tag_block[0];
        tag_block[0] = ciphertext[0];

        let message_ciphertext = &ciphertext[1..1 + mlen];
        let expected_mac = &ciphertext[1 + mlen..];
        let computed_mac = Self::compute_mac(&poly_key, &tag_block, message_ciphertext);
        if computed_mac.as_slice() != expected_mac {
            return Err(());
        }

        let mut plaintext = message_ciphertext.to_vec();
        chacha.apply_keystream(&mut plaintext);
        self.update_state(&computed_mac, tag);
        Ok((plaintext, tag))
    }

    /// Compute the exact Poly1305 input used by libsodium secretstream.
    /// libsodium's historical padding expression pads by `mlen % 16` bytes
    /// after the ciphertext (rather than the complementary amount); keep this
    /// quirk for wire compatibility.
    fn compute_mac(poly_key: &[u8; 32], tag_block: &[u8; 64], ciphertext: &[u8]) -> [u8; 16] {
        use poly1305::Poly1305;
        use poly1305::universal_hash::{KeyInit, UniversalHash};

        let mut mac = Poly1305::new(&(*poly_key).into());
        mac.update_padded(tag_block);

        let mut full_blocks = ciphertext.chunks_exact(16);
        for block in &mut full_blocks {
            mac.update(core::slice::from_ref(poly1305::Block::from_slice(block)));
        }

        let remainder = full_blocks.remainder();
        let padding = ciphertext.len() & 0x0f;
        let size_offset = remainder.len() + padding;
        let mut tail = [0u8; 48];
        tail[..remainder.len()].copy_from_slice(remainder);

        let mut sizes = [0u8; 16];
        sizes[8..].copy_from_slice(&((64 + ciphertext.len()) as u64).to_le_bytes());
        tail[size_offset..size_offset + sizes.len()].copy_from_slice(&sizes);

        mac.compute_unpadded(&tail[..size_offset + sizes.len()])
            .into()
    }

    /// Apply the authenticated nonce update, advance the per-message counter,
    /// then rekey for FINAL/REKEY tags as libsodium does.
    fn update_state(&mut self, mac_tag: &[u8; 16], tag: u8) {
        for (nonce_byte, mac_byte) in self.nonce[4..12].iter_mut().zip(&mac_tag[..8]) {
            *nonce_byte ^= *mac_byte;
        }

        self.increment_counter();
        if tag & 0x02 != 0 || self.nonce[..4] == [0u8; 4] {
            self.rekey();
        }
    }

    /// Increment the 4-byte little-endian counter in nonce[0..4].
    fn increment_counter(&mut self) {
        let mut counter = u32::from_le_bytes(self.nonce[..4].try_into().unwrap());
        counter = counter.wrapping_add(1);
        self.nonce[..4].copy_from_slice(&counter.to_le_bytes());
    }

    /// Rekey the stream (called after TAG_FINAL or TAG_REKEY).
    fn rekey(&mut self) {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        // Rekey by XORing the current key and inonce with 40 bytes of stream.
        let mut material = [0u8; 40];
        material[..32].copy_from_slice(&self.key);
        material[32..].copy_from_slice(&self.nonce[4..12]);
        let mut chacha = ChaCha20::new(&self.key.into(), &self.nonce.into());
        chacha.apply_keystream(&mut material);

        self.key.copy_from_slice(&material[..32]);
        self.nonce[4..12].copy_from_slice(&material[32..]);
        self.nonce[..4].copy_from_slice(&1u32.to_le_bytes());
        material.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Padding calculation
// ---------------------------------------------------------------------------

/// Compute the largest power of 2 that is <= x. Returns 0 for x == 0.
/// Equivalent to C++20 `std::bit_floor`.
fn bit_floor(x: usize) -> usize {
    if x == 0 {
        return 0;
    }
    1usize << (usize::BITS - 1 - x.leading_zeros())
}

/// Returns the amount of padding to add to an attachment of `data_size` bytes
/// to obfuscate its true size, given secretstream encryption with a 32 KiB
/// chunk size.
pub fn encrypted_padding(data_size: usize) -> usize {
    const PREFIX_SIZE: usize = 1 + ENCRYPT_HEADER;
    const MIN_PADDING: usize = 1;

    // Number of mac+tag values embedded every 32 KiB in the data stream:
    let stream_chunks = data_size.div_ceil(ENCRYPT_CHUNK_SIZE);

    let enc_size = data_size + PREFIX_SIZE + MIN_PADDING + stream_chunks * ENCRYPT_CHUNK_OVERHEAD;

    let pad_factor = bit_floor(enc_size.max(131072)) >> 5;

    // Round up to next multiple of pad_factor:
    let padded_size = enc_size.div_ceil(pad_factor) * pad_factor;

    let mut padding = padded_size - enc_size + MIN_PADDING;

    // For every complete ENCRYPT_CHUNK_SIZE padding that we add we implicitly
    // also add a stream tag, and so we want to subtract one tag per
    // (ENCRYPT_CHUNK_SIZE + ENCRYPT_CHUNK_OVERHEAD) bytes of padding to
    // compensate:
    let mut implicit_padding = 0usize;
    if padding >= ENCRYPTED_CHUNK_TOTAL {
        implicit_padding = (padding / ENCRYPTED_CHUNK_TOTAL) * ENCRYPT_CHUNK_OVERHEAD;
    }

    // After accounting for the full stream + tag blocks above, we might still
    // have enough to spill over the stream into the next chunk:
    let free_padding = stream_chunks * ENCRYPT_CHUNK_SIZE - data_size;
    if padding % ENCRYPTED_CHUNK_TOTAL > free_padding {
        implicit_padding += ENCRYPT_CHUNK_OVERHEAD;
    }

    padding -= implicit_padding;

    padding
}

/// Returns the exact final encrypted size (including overhead and padding) of
/// an input of `plaintext_size` bytes.
pub fn encrypted_size(plaintext_size: usize) -> usize {
    let padding = encrypted_padding(plaintext_size);
    let padded_size = plaintext_size + padding;
    let tags_size = padded_size.div_ceil(ENCRYPT_CHUNK_SIZE) * ENCRYPT_CHUNK_OVERHEAD;

    1 /* 'S' identifier */ + ENCRYPT_HEADER + plaintext_size + padding + tags_size
}

/// Returns the maximum possible decrypted size of encrypted data of length
/// `enc_size`. The actual size can be (and usually is) less than this because
/// of padding. Returns `None` if the input is too small to be a valid
/// encrypted attachment.
pub fn decrypted_max_size(enc_size: usize) -> Option<usize> {
    // Minimum valid encrypted attachment: 1 ('S') + ENCRYPT_HEADER + 1 (min padding) + ENCRYPT_CHUNK_OVERHEAD
    let min_size = 1 + ENCRYPT_HEADER + 1 + ENCRYPT_CHUNK_OVERHEAD;
    if enc_size < min_size {
        return None;
    }

    let sz = enc_size - 1 /* 'S' */ - 1 /* minimum padding */ - ENCRYPT_HEADER;

    // Figure out how many 17-byte overheads are present:
    let overhead = sz.div_ceil(ENCRYPTED_CHUNK_TOTAL) * ENCRYPT_CHUNK_OVERHEAD;

    let result = sz.checked_sub(overhead)?;
    // Overflow check (matching C++ `sz > encrypted_size`)
    if result > enc_size {
        return None;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Key / nonce derivation
// ---------------------------------------------------------------------------

/// Derives the 56-byte nonce+key from seed, data, and domain.
/// First 24 bytes = nonce/header, last 32 bytes = encryption key.
fn derive_nonce_key(
    seed: &[u8],
    data: &[u8],
    domain: Domain,
) -> [u8; ENCRYPT_HEADER + ENCRYPT_KEY_SIZE] {
    let mut result = [0u8; ENCRYPT_HEADER + ENCRYPT_KEY_SIZE];
    let domain_byte = domain as u8;

    let mut params = blake2b_simd::Params::new();
    params.hash_length(result.len());
    params.key(&[domain_byte]);

    let mut state = params.to_state();
    state.update(&seed[..32]);
    state.update(data);

    let hash = state.finalize();
    result.copy_from_slice(hash.as_bytes());
    result
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt an attachment for storage on the file server using deterministic
/// encryption.
///
/// The key is deterministic from `seed + data + domain`, so the same inputs
/// always produce the same ciphertext (allowing deduplication on the server).
///
/// Returns `(ciphertext, encryption_key)`.
///
/// If `allow_large` is false (the default), data larger than
/// [`MAX_REGULAR_SIZE`] will be rejected.
pub fn encrypt(
    seed: &[u8],
    data: &[u8],
    domain: Domain,
    allow_large: bool,
) -> CryptoResult<(Vec<u8>, [u8; ENCRYPT_KEY_SIZE])> {
    if seed.len() < 32 {
        return Err(CryptoError::InvalidInput(
            "attachment::encrypt requires a 32-byte uploader seed".into(),
        ));
    }

    if data.len() > MAX_REGULAR_SIZE && !allow_large {
        return Err(CryptoError::InvalidInput(
            "data to encrypt is too large".into(),
        ));
    }

    let nonce_key = derive_nonce_key(seed, data, domain);
    let nonce: [u8; ENCRYPT_HEADER] = nonce_key[..ENCRYPT_HEADER].try_into().unwrap();
    let enc_key: [u8; ENCRYPT_KEY_SIZE] = nonce_key[ENCRYPT_HEADER..].try_into().unwrap();

    let padding = encrypted_padding(data.len());
    debug_assert!(padding >= 1);

    let total_size = encrypted_size(data.len());
    let mut out = Vec::with_capacity(total_size);

    // 1. Write 'S' prefix
    out.push(b'S');

    // 2. Init secretstream with deterministic nonce
    let mut header_buf = [0u8; ENCRYPT_HEADER];
    let mut stream = SecretStream::init_push(&mut header_buf, &enc_key, &nonce);

    // 3. Write header
    out.extend_from_slice(&header_buf);

    // 4. Encrypt padding + data in chunks
    let mut data_pos = 0usize;
    let mut padding_remaining = padding;

    // First: handle padding chunks
    while padding_remaining > 0 {
        let mut buf: Vec<u8>;

        if padding_remaining > ENCRYPT_CHUNK_SIZE {
            // Full chunk of 0x00 padding
            buf = vec![0u8; ENCRYPT_CHUNK_SIZE];
            padding_remaining -= ENCRYPT_CHUNK_SIZE;
        } else {
            // Last padding chunk: (padding_remaining - 1) zero bytes + 0x01 terminator
            buf = vec![0u8; padding_remaining]; // padding_remaining bytes of zeros
            buf[padding_remaining - 1] = 0x01; // last byte is the terminator

            // Fill rest of chunk with data
            let space = ENCRYPT_CHUNK_SIZE - padding_remaining;
            let data_to_copy = space.min(data.len() - data_pos);
            if data_to_copy > 0 {
                buf.extend_from_slice(&data[data_pos..data_pos + data_to_copy]);
                data_pos += data_to_copy;
            }
            padding_remaining = 0;
        }

        let tag = if data_pos >= data.len() && padding_remaining == 0 {
            TAG_FINAL
        } else {
            TAG_MESSAGE
        };

        let encrypted_chunk = stream.push(&buf, tag);
        out.extend_from_slice(&encrypted_chunk);
    }

    // 5. Encrypt remaining data chunks
    while data_pos < data.len() {
        let chunk_end = (data_pos + ENCRYPT_CHUNK_SIZE).min(data.len());
        let chunk = &data[data_pos..chunk_end];
        data_pos = chunk_end;

        let tag = if data_pos >= data.len() {
            TAG_FINAL
        } else {
            TAG_MESSAGE
        };

        let encrypted_chunk = stream.push(chunk, tag);
        out.extend_from_slice(&encrypted_chunk);
    }

    debug_assert_eq!(out.len(), total_size);

    Ok((out, enc_key))
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt an attachment produced by [`encrypt`].
///
/// Returns the decrypted, de-padded data.
pub fn decrypt(ciphertext: &[u8], key: &[u8; ENCRYPT_KEY_SIZE]) -> CryptoResult<Vec<u8>> {
    let max_size = decrypted_max_size(ciphertext.len()).ok_or_else(|| {
        CryptoError::DecryptionFailed(
            "Attachment decryption failed: encrypted data too short".into(),
        )
    })?;

    if ciphertext.is_empty() || ciphertext[0] != b'S' {
        return Err(CryptoError::DecryptionFailed(format!(
            "Attachment decryption failed: unknown encryption type 0x{:02x}; expected 0x53 (S)",
            if ciphertext.is_empty() {
                0u8
            } else {
                ciphertext[0]
            }
        )));
    }

    // Extract header
    let header: [u8; ENCRYPT_HEADER] = ciphertext[1..1 + ENCRYPT_HEADER].try_into().unwrap();
    let mut stream = SecretStream::init_pull(&header, key);

    let enc_data = &ciphertext[1 + ENCRYPT_HEADER..];
    let mut pos = 0usize;
    let mut result = Vec::with_capacity(max_size);
    let mut depadded = false;
    let mut done = false;

    let fail = || -> CryptoError {
        CryptoError::DecryptionFailed(
            "Attachment decryption failed: invalid key or corrupted data".into(),
        )
    };

    while !done {
        if pos + ENCRYPT_CHUNK_OVERHEAD > enc_data.len() {
            return Err(CryptoError::DecryptionFailed(
                "Attachment decryption failed: data ended before end of stream".into(),
            ));
        }

        // Determine chunk size: either a full chunk or the remaining data
        let remaining = enc_data.len() - pos;
        let chunk_total = remaining.min(ENCRYPTED_CHUNK_TOTAL);
        let chunk_data = &enc_data[pos..pos + chunk_total];
        pos += chunk_total;

        let (plaintext, tag) = stream.pull(chunk_data).map_err(|_| fail())?;

        if !depadded {
            // Look for the 0x01 padding terminator
            let pad_end = plaintext.iter().position(|&b| b != 0x00);

            if let Some(idx) = pad_end {
                if plaintext[idx] != 0x01 {
                    return Err(CryptoError::DecryptionFailed(
                        "Attachment decryption failed: invalid padding".into(),
                    ));
                }
                depadded = true;
                // Data starts after the 0x01 byte
                if idx + 1 < plaintext.len() {
                    result.extend_from_slice(&plaintext[idx + 1..]);
                }
            }
            // If pad_end is None, the entire chunk is padding (all zeros)
        } else {
            result.extend_from_slice(&plaintext);
        }

        if tag == TAG_FINAL {
            if pos != enc_data.len() {
                return Err(CryptoError::DecryptionFailed(
                    "Attachment decryption failed: FINAL tag before end of the encrypted data"
                        .into(),
                ));
            }
            done = true;
        } else if pos == enc_data.len() {
            return Err(CryptoError::DecryptionFailed(
                "Attachment decryption failed: end of data without FINAL tag".into(),
            ));
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Generate deterministic test data: byte i = (i * 7) % 256
    fn make_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 7) % 256) as u8).collect()
    }

    #[test]
    fn test_bit_floor() {
        assert_eq!(bit_floor(0), 0);
        assert_eq!(bit_floor(1), 1);
        assert_eq!(bit_floor(2), 2);
        assert_eq!(bit_floor(3), 2);
        assert_eq!(bit_floor(4), 4);
        assert_eq!(bit_floor(5), 4);
        assert_eq!(bit_floor(7), 4);
        assert_eq!(bit_floor(8), 8);
        assert_eq!(bit_floor(131072), 131072);
        assert_eq!(bit_floor(1_000_528), 524288);
    }

    #[test]
    fn test_encrypted_padding_sizes() {
        // From the C++ test: expected encrypted sizes for various data sizes
        let test_cases: Vec<(usize, usize)> = vec![
            (0, 4096),
            (1, 4096),
            (2, 4096),
            (10, 4096),
            (100, 4096),
            (1000, 4096),
            (2000, 4096),
            (4000, 4096),
            (4053, 4096),
            (4054, 8192),
            (8149, 8192),
            (8150, 12288),
            (33333, 36864),
            (261982, 262144),
            (261983, 270336),
            (523990, 524288),
            (523991, 540672),
            (6543210, 6553600),
            (10218286, 10223616),
        ];

        for (data_size, expected_enc_size) in test_cases {
            let actual = encrypted_size(data_size);
            assert_eq!(
                actual, expected_enc_size,
                "encrypted_size({}) = {} (expected {})",
                data_size, actual, expected_enc_size
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seed = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let data_sizes = [
            0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 8149, 8150, 33333, 261982, 261983,
            523990, 523991,
        ];

        for &data_size in &data_sizes {
            let data = make_data(data_size);

            let (enc, key) = encrypt(&seed, &data, Domain::Attachment, false).unwrap();

            let expected_size_val = encrypted_size(data_size);
            assert_eq!(
                enc.len(),
                expected_size_val,
                "data_size={}: enc.len()={} expected={}",
                data_size,
                enc.len(),
                expected_size_val,
            );

            let decr = decrypt(&enc, &key).unwrap();
            assert_eq!(decr, data, "data_size={}: roundtrip mismatch", data_size);
        }
    }

    #[test]
    fn test_encrypt_deterministic() {
        let seed = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        for data_size in [0, 1, 100, 1000, 33333] {
            let data = make_data(data_size);

            let (enc1, key1) = encrypt(&seed, &data, Domain::Attachment, false).unwrap();
            let (enc2, key2) = encrypt(&seed, &data, Domain::Attachment, false).unwrap();

            assert_eq!(key1, key2, "data_size={}: keys differ", data_size);
            assert_eq!(enc1, enc2, "data_size={}: ciphertexts differ", data_size);
        }
    }

    #[test]
    fn test_key_separation_different_seeds() {
        let seed1 = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let seed2 = hex!("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        for data_size in [0, 20, 100, 1000, 33333] {
            let data = make_data(data_size);

            let (enc1, key1) = encrypt(&seed1, &data, Domain::Attachment, false).unwrap();
            let (enc2, key2) = encrypt(&seed2, &data, Domain::Attachment, false).unwrap();

            assert_ne!(key1, key2);
            assert_ne!(enc1, enc2);

            // Decrypting with wrong key must fail
            assert!(decrypt(&enc1, &key2).is_err());
            assert!(decrypt(&enc2, &key1).is_err());
        }
    }

    #[test]
    fn test_domain_separation() {
        let seed = hex!("2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        for data_size in [0, 20, 100, 1000, 33333] {
            let data = make_data(data_size);

            let (enc1, key1) = encrypt(&seed, &data, Domain::Attachment, false).unwrap();
            let (enc2, key2) = encrypt(&seed, &data, Domain::ProfilePic, false).unwrap();

            assert_ne!(key1, key2);
            assert_ne!(enc1, enc2);

            assert!(decrypt(&enc1, &key2).is_err());
            assert!(decrypt(&enc2, &key1).is_err());
        }
    }

    #[test]
    fn test_content_separation() {
        let seed = hex!("3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let data = make_data(50000);
        let mut data2 = data.clone();
        data2[43210] = 0x42;

        let (enc1, key1) = encrypt(&seed, &data, Domain::Attachment, false).unwrap();
        let (enc2, key2) = encrypt(&seed, &data2, Domain::Attachment, false).unwrap();

        assert_ne!(key1, key2);
        assert_eq!(enc1.len(), enc2.len());
        assert_ne!(enc1, enc2);

        assert!(decrypt(&enc1, &key2).is_err());
        assert!(decrypt(&enc2, &key1).is_err());
    }

    #[test]
    fn test_too_large_rejected() {
        let seed = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let data = vec![0u8; MAX_REGULAR_SIZE + 1];

        assert!(encrypt(&seed, &data, Domain::Attachment, false).is_err());
        // With allow_large, it should succeed
        let result = encrypt(&seed, &data, Domain::Attachment, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_seed_too_short() {
        let seed = [0u8; 16];
        let data = [0u8; 10];

        assert!(encrypt(&seed, &data, Domain::Attachment, false).is_err());
    }

    #[test]
    fn test_decrypted_max_size() {
        // For encrypted_size(0) = 4096, decrypted_max_size should return Some(...)
        let enc = encrypted_size(0);
        let max = decrypted_max_size(enc);
        assert!(max.is_some());
        assert!(max.is_some());

        // Too small
        assert!(decrypted_max_size(0).is_none());
        assert!(decrypted_max_size(1).is_none());
        assert!(decrypted_max_size(10).is_none());
    }

    #[test]
    fn test_large_roundtrip() {
        let seed = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        for data_size in [6543210] {
            let data = make_data(data_size);
            let (enc, key) = encrypt(&seed, &data, Domain::Attachment, true).unwrap();

            let expected = encrypted_size(data_size);
            assert_eq!(enc.len(), expected);

            let decr = decrypt(&enc, &key).unwrap();
            assert_eq!(decr, data);
        }
    }
}
