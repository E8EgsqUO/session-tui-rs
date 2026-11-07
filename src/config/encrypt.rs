//! Config message encryption and decryption using XChaCha20-Poly1305.
//!
//! Port of `libsession-util/src/config/encrypt.cpp`. Uses deterministic nonces
//! derived from the plaintext via BLAKE2b keyed hashing, so that identical
//! messages encrypt to identical ciphertext (enabling server-side dedup).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

/// Poly1305 authentication tag size (16 bytes) + XChaCha20 nonce size (24 bytes).
pub const ENCRYPT_DATA_OVERHEAD: usize = 40;

/// Maximum length of the domain string parameter.
const DOMAIN_MAX_SIZE: usize = 24;

/// Prefix used when deriving the nonce via BLAKE2b keyed hash.
const NONCE_KEY_PREFIX: &str = "libsessionutil-config-encrypted-";

/// Error type for config decryption failures.
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("Decryption failed: ciphertext is too short")]
    CiphertextTooShort,
    #[error("Message decryption failed")]
    DecryptionFailed,
}

/// Derives the XChaCha20-Poly1305 encryption key.
///
/// The C++ implementation uses unkeyed BLAKE2b (no personalization key) with 32-byte output,
/// hashing: `key_base || big_endian_u64(message_size) || domain`.
///
/// This incorporates the domain and message size into the key so that even with a
/// deterministic nonce, nonce reuse only happens for identical-size messages in the
/// same domain.
fn make_encrypt_key(
    key_base: &[u8; 32],
    message_size: u64,
    domain: &str,
) -> Result<[u8; 32], &'static str> {
    if domain.is_empty() || domain.len() > DOMAIN_MAX_SIZE {
        return Err("encrypt called with domain size not in [1, 24]");
    }

    // BLAKE2b with no key, 32-byte output.
    // Feed: key_base || big_endian(message_size) || domain
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    state.update(key_base);
    state.update(&message_size.to_be_bytes());
    state.update(domain.as_bytes());
    let hash = state.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    Ok(key)
}

/// Derives a deterministic 24-byte nonce from the plaintext using BLAKE2b keyed hash.
///
/// The key is `"libsessionutil-config-encrypted-" + domain`, and the input is the message.
fn make_nonce(message: &[u8], domain: &str) -> [u8; 24] {
    let mut nonce_key = String::with_capacity(NONCE_KEY_PREFIX.len() + domain.len());
    nonce_key.push_str(NONCE_KEY_PREFIX);
    nonce_key.push_str(domain);

    let hash = blake2b_simd::Params::new()
        .hash_length(24)
        .key(nonce_key.as_bytes())
        .hash(message);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(hash.as_bytes());
    nonce
}

/// Encrypts a config message using XChaCha20-Poly1305 with deterministic nonce.
///
/// The returned ciphertext consists of: `encrypted_data(len + 16) || nonce(24)`.
///
/// `key_base` is a 32-byte shared key. `domain` is a short string (1-24 chars)
/// identifying the config type (e.g. `"contacts"`, `"closed-group"`).
///
/// # Panics
///
/// Panics if `domain` is empty or longer than 24 characters.
pub fn config_encrypt(message: &[u8], key_base: &[u8; 32], domain: &str) -> Vec<u8> {
    let key = make_encrypt_key(key_base, message.len() as u64, domain)
        .expect("invalid domain for config_encrypt");

    let nonce_bytes = make_nonce(message, domain);
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut ciphertext = cipher
        .encrypt(&nonce, message)
        .expect("XChaCha20-Poly1305 encryption should not fail");

    // Append the nonce (24 bytes) after the ciphertext+tag
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext
}

/// Decrypts a config message previously encrypted with [`config_encrypt`].
///
/// The input must be at least [`ENCRYPT_DATA_OVERHEAD`] bytes. The last 24 bytes are the
/// nonce; the preceding bytes are ciphertext + Poly1305 tag.
pub fn config_decrypt(
    ciphertext: &[u8],
    key_base: &[u8; 32],
    domain: &str,
) -> Result<Vec<u8>, DecryptError> {
    if ciphertext.len() < ENCRYPT_DATA_OVERHEAD {
        return Err(DecryptError::CiphertextTooShort);
    }

    let message_len = ciphertext.len() - ENCRYPT_DATA_OVERHEAD;

    // Extract nonce from the last 24 bytes
    let nonce_bytes: [u8; 24] = ciphertext[ciphertext.len() - 24..]
        .try_into()
        .unwrap();
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);

    // The ciphertext+tag portion (excluding the appended nonce)
    let ct_with_tag = &ciphertext[..ciphertext.len() - 24];

    let key = make_encrypt_key(key_base, message_len as u64, domain)
        .map_err(|_| DecryptError::DecryptionFailed)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(&nonce, ct_with_tag)
        .map_err(|_| DecryptError::DecryptionFailed)
}

/// Returns the target size of a message with padding, assuming `overhead` additional bytes
/// will be appended (e.g. from encryption).
///
/// Padding increments:
/// - 256-byte chunks up to 5120 total
/// - 1024-byte chunks up to 20480 total
/// - 2048-byte chunks up to 40960 total
/// - 5120-byte chunks from there up
///
/// Always returns a value >= `s + overhead` (minus `overhead`, since the caller will add it).
pub const fn config_padded_size(s: usize, overhead: usize) -> usize {
    let s2 = s + overhead;
    let chunk = if s2 < 5120 {
        256
    } else if s2 < 20480 {
        1024
    } else if s2 < 40960 {
        2048
    } else {
        5120
    };
    s2.div_ceil(chunk) * chunk - overhead
}

/// Inserts null-byte padding at the beginning of `data` to reach the target padded size.
///
/// The padding is prepended so that the total message size (after encryption overhead)
/// lands on a granular boundary. See [`config_padded_size`] for the bucket sizes.
pub fn pad_message(data: &mut Vec<u8>, overhead: usize) {
    let target_size = config_padded_size(data.len(), overhead);
    if target_size > data.len() {
        let pad_count = target_size - data.len();
        data.splice(0..0, std::iter::repeat_n(0u8, pad_count));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_encrypt_known_vector() {
        // Test vector from C++ test suite: test_encrypt.cpp
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let enc = config_encrypt(message, &key1, "test-suite1");
        assert_eq!(
            hex::encode(&enc),
            "f14f242a26638f3305707d1035e734577f943cd7d28af58e32637e\
             0966dcaf2f4860cb4d0f8ba7e09d29e31f5e4a18f65847287a54a0"
        );
    }

    #[test]
    fn test_nonce_from_known_vector() {
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let enc = config_encrypt(message, &key1, "test-suite1");
        // Last 24 bytes are the nonce
        let nonce = &enc[enc.len() - 24..];
        assert_eq!(
            hex::encode(nonce),
            "af2f4860cb4d0f8ba7e09d29e31f5e4a18f65847287a54a0"
        );
    }

    #[test]
    fn test_different_domain_different_ciphertext() {
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let enc1 = config_encrypt(message, &key1, "test-suite1");
        let enc2 = config_encrypt(message, &key1, "test-suite2");
        assert_ne!(hex::encode(&enc1), hex::encode(&enc2));

        // Nonce differs with different domain
        let nonce2 = &enc2[enc2.len() - 24..];
        assert_eq!(
            hex::encode(nonce2),
            "277e639d36ba46470dfff509a68cb73d9a96386c51739bdd"
        );
    }

    #[test]
    fn test_different_key_same_nonce() {
        // Different key_base produces the same nonce (nonce only depends on message + domain)
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let key2 = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let enc1 = config_encrypt(message, &key1, "test-suite1");
        let enc3 = config_encrypt(message, &key2, "test-suite1");
        assert_ne!(hex::encode(&enc1), hex::encode(&enc3));

        let nonce1 = &enc1[enc1.len() - 24..];
        let nonce3 = &enc3[enc3.len() - 24..];
        assert_eq!(hex::encode(nonce1), hex::encode(nonce3));
    }

    #[test]
    fn test_roundtrip() {
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let enc = config_encrypt(message, &key1, "test-suite1");
        let dec = config_decrypt(&enc, &key1, "test-suite1").unwrap();
        assert_eq!(dec, message);
    }

    #[test]
    fn test_decrypt_wrong_domain() {
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let enc = config_encrypt(message, &key1, "test-suite1");
        assert!(config_decrypt(&enc, &key1, "test-suite2").is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let key2 = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let enc = config_encrypt(message, &key1, "test-suite1");
        assert!(config_decrypt(&enc, &key2, "test-suite1").is_err());
    }

    #[test]
    fn test_decrypt_corrupted() {
        let message = b"some message 1";
        let key1 = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        let mut enc = config_encrypt(message, &key1, "test-suite1");
        enc[3] = 0x42;
        assert!(config_decrypt(&enc, &key1, "test-suite1").is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let short = vec![0u8; ENCRYPT_DATA_OVERHEAD - 1];
        assert!(matches!(
            config_decrypt(&short, &key, "test"),
            Err(DecryptError::CiphertextTooShort)
        ));
    }

    #[test]
    fn test_padded_size() {
        assert_eq!(config_padded_size(1, 0), 256);
        assert_eq!(config_padded_size(1, 10), 256 - 10);
        assert_eq!(config_padded_size(246, 10), 256 - 10);
        assert_eq!(config_padded_size(247, 10), 512 - 10);
        assert_eq!(config_padded_size(247, 256), 256);
        assert_eq!(config_padded_size(3839, 96), 4000);
        assert_eq!(config_padded_size(3744, 96), 3744);
        assert_eq!(config_padded_size(3745, 96), 4000);
        assert_eq!(config_padded_size(4864, 0), 4864);
        assert_eq!(config_padded_size(4865, 0), 5120);
        assert_eq!(config_padded_size(5120 + 1, 0), 6144);
        assert_eq!(config_padded_size(9 * 1024, 0), 9 * 1024);
        assert_eq!(config_padded_size(9 * 1024 + 1, 0), 10 * 1024);
        assert_eq!(config_padded_size(10 * 1024 + 1, 0), 11 * 1024);
        assert_eq!(config_padded_size(20 * 1024, 0), 20 * 1024);
        assert_eq!(config_padded_size(20 * 1024 + 1, 0), 22 * 1024);
        assert_eq!(config_padded_size(38 * 1024, 0), 38 * 1024);
        assert_eq!(config_padded_size(38 * 1024 + 1, 0), 40 * 1024);
        assert_eq!(config_padded_size(40 * 1024 + 1, 0), 45 * 1024);
        assert_eq!(config_padded_size(45 * 1024 + 1, 0), 50 * 1024);
        assert_eq!(config_padded_size(70 * 1024, 0), 70 * 1024);
        assert_eq!(config_padded_size(70 * 1024 + 1, 0), 75 * 1024);
        assert_eq!(config_padded_size(75 * 1024, 0), 75 * 1024);
        assert_eq!(config_padded_size(75 * 1024 - 24, 24), 75 * 1024 - 24);
    }

    #[test]
    fn test_pad_message() {
        let mut data = vec![1u8, 2, 3];
        pad_message(&mut data, ENCRYPT_DATA_OVERHEAD);
        // 3 + 40 = 43 => rounds up to 256 => target = 256 - 40 = 216
        assert_eq!(data.len(), 216);
        // Padding is prepended as null bytes
        assert!(data[..213].iter().all(|&b| b == 0));
        assert_eq!(&data[213..], &[1, 2, 3]);
    }

    #[test]
    fn test_overhead_constant() {
        // XChaCha20-Poly1305 tag (16) + nonce (24) = 40
        assert_eq!(ENCRYPT_DATA_OVERHEAD, 40);
    }
}
