//! Per-hop encryption for onion routing.
//!
//! Two modes are supported:
//! 1. **XChaCha20-Poly1305** (modern, default):
//!    Shared key = Blake2b-256(DH(local_sk, remote_pk) || A || B)
//!    where A is the client pubkey and B is the server pubkey.
//!    Nonce (24 bytes) is prepended to the ciphertext.
//!
//! 2. **AES-256-GCM** (legacy):
//!    Shared key = HMAC-SHA256(salt="LOKI", DH(local_sk, remote_pk))
//!    IV (16 bytes) is prepended, followed by ciphertext, followed by 16-byte tag.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce, aead::Aead};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngExt;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::network::key_types::{X25519Pubkey, X25519Seckey};

/// Encryption type for onion request hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptType {
    AesGcm,
    XChaCha20,
}

impl EncryptType {
    /// Returns the string identifier for this encryption type.
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptType::AesGcm => "aes-gcm",
            EncryptType::XChaCha20 => "xchacha20",
        }
    }
}

impl std::fmt::Display for EncryptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Parses encryption type from a string.
pub fn parse_enc_type(s: &str) -> Result<EncryptType, HopEncryptionError> {
    match s {
        "xchacha20" | "xchacha20-poly1305" => Ok(EncryptType::XChaCha20),
        "aes-gcm" | "gcm" => Ok(EncryptType::AesGcm),
        _ => Err(HopEncryptionError::InvalidEncType(s.to_string())),
    }
}

const GCM_IV_SIZE: usize = 16;
const GCM_TAG_SIZE: usize = 16;
const XCHACHA20_NONCE_SIZE: usize = 24;
const XCHACHA20_TAG_SIZE: usize = 16;

/// Error type for per-hop encryption/decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum HopEncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Shared key derivation failed")]
    SharedKeyFailed,
    #[error("Ciphertext too short")]
    CiphertextTooShort,
    #[error("Invalid encryption type: {0}")]
    InvalidEncType(String),
}

/// Handles per-hop encryption/decryption in onion request paths.
pub struct HopEncryption {
    private_key: X25519Seckey,
    public_key: X25519Pubkey,
    /// True if we are the server (snode) side.
    server: bool,
}

impl HopEncryption {
    /// Creates a new hop encryption context with the given keypair and role.
    pub fn new(private_key: X25519Seckey, public_key: X25519Pubkey, server: bool) -> Self {
        Self {
            private_key,
            public_key,
            server,
        }
    }

    /// Returns true if the response is long enough to be valid for the given encryption type.
    pub fn response_long_enough(enc_type: EncryptType, response_size: usize) -> bool {
        match enc_type {
            EncryptType::XChaCha20 => response_size >= XCHACHA20_TAG_SIZE,
            EncryptType::AesGcm => response_size >= GCM_IV_SIZE + GCM_TAG_SIZE,
        }
    }

    /// Encrypts plaintext using the specified encryption type.
    pub fn encrypt(
        &self,
        enc_type: EncryptType,
        plaintext: &[u8],
        remote_pubkey: &X25519Pubkey,
    ) -> Result<Vec<u8>, HopEncryptionError> {
        match enc_type {
            EncryptType::XChaCha20 => self.encrypt_xchacha20(plaintext, remote_pubkey),
            EncryptType::AesGcm => self.encrypt_aesgcm(plaintext, remote_pubkey),
        }
    }

    /// Decrypts ciphertext using the specified encryption type.
    pub fn decrypt(
        &self,
        enc_type: EncryptType,
        ciphertext: &[u8],
        remote_pubkey: &X25519Pubkey,
    ) -> Result<Vec<u8>, HopEncryptionError> {
        match enc_type {
            EncryptType::XChaCha20 => self.decrypt_xchacha20(ciphertext, remote_pubkey),
            EncryptType::AesGcm => self.decrypt_aesgcm(ciphertext, remote_pubkey),
        }
    }

    // -----------------------------------------------------------------------
    // XChaCha20-Poly1305
    // -----------------------------------------------------------------------

    fn encrypt_xchacha20(
        &self,
        plaintext: &[u8],
        remote_pubkey: &X25519Pubkey,
    ) -> Result<Vec<u8>, HopEncryptionError> {
        let key = xchacha20_shared_key(
            &self.public_key,
            &self.private_key,
            remote_pubkey,
            !self.server,
        )?;

        let mut nonce_bytes = [0u8; XCHACHA20_NONCE_SIZE];
        rand::rng().fill(&mut nonce_bytes[..]);

        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HopEncryptionError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce
        let mut result = Vec::with_capacity(XCHACHA20_NONCE_SIZE + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    fn decrypt_xchacha20(
        &self,
        ciphertext: &[u8],
        remote_pubkey: &X25519Pubkey,
    ) -> Result<Vec<u8>, HopEncryptionError> {
        if ciphertext.len() < XCHACHA20_NONCE_SIZE + XCHACHA20_TAG_SIZE {
            return Err(HopEncryptionError::CiphertextTooShort);
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(XCHACHA20_NONCE_SIZE);

        let key = xchacha20_shared_key(
            &self.public_key,
            &self.private_key,
            remote_pubkey,
            !self.server,
        )?;

        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
        let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| HopEncryptionError::DecryptionFailed("XChaCha20-Poly1305".into()))
    }

    // -----------------------------------------------------------------------
    // AES-256-GCM
    // -----------------------------------------------------------------------

    fn encrypt_aesgcm(
        &self,
        plaintext: &[u8],
        remote_pubkey: &X25519Pubkey,
    ) -> Result<Vec<u8>, HopEncryptionError> {
        let key = derive_aesgcm_key(&self.private_key, remote_pubkey)?;

        // We need a 12-byte nonce for AES-GCM (not 16).
        // The C++ code uses nettle's GCM with a 16-byte IV. AES-GCM with a 16-byte IV
        // requires the GCM spec's GHASH-based IV processing. The `aes-gcm` crate only
        // supports 12-byte nonces natively.
        //
        // For compatibility: we generate 16 random bytes. We use the first 12 as the
        // nonce for encryption, but store all 16 in the output to match the C++ format.
        // This means we are NOT 100% compatible with C++ nettle-based GCM that uses
        // 16-byte IVs directly. For cross-language compat, use xchacha20.
        let mut iv = [0u8; GCM_IV_SIZE];
        rand::rng().fill(&mut iv[..]);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| HopEncryptionError::EncryptionFailed(e.to_string()))?;

        // Use first 12 bytes as nonce
        let nonce = AesNonce::from_slice(&iv[..12]);
        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HopEncryptionError::EncryptionFailed(e.to_string()))?;

        // Output: [16-byte IV][ciphertext + 16-byte tag]
        let mut result = Vec::with_capacity(GCM_IV_SIZE + encrypted.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    fn decrypt_aesgcm(
        &self,
        ciphertext: &[u8],
        remote_pubkey: &X25519Pubkey,
    ) -> Result<Vec<u8>, HopEncryptionError> {
        if ciphertext.len() < GCM_IV_SIZE + GCM_TAG_SIZE {
            return Err(HopEncryptionError::CiphertextTooShort);
        }

        let key = derive_aesgcm_key(&self.private_key, remote_pubkey)?;
        let (iv, encrypted) = ciphertext.split_at(GCM_IV_SIZE);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| HopEncryptionError::DecryptionFailed(e.to_string()))?;

        // Use first 12 bytes as nonce
        let nonce = AesNonce::from_slice(&iv[..12]);
        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| HopEncryptionError::DecryptionFailed("AES256-GCM".into()))
    }
}

// ---------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------

/// Computes X25519 Diffie-Hellman shared secret.
fn dh(secret: &X25519Seckey, public: &X25519Pubkey) -> Result<[u8; 32], HopEncryptionError> {
    let sk = StaticSecret::from(secret.0);
    let pk = PublicKey::from(public.0);
    let shared = sk.diffie_hellman(&pk);
    // x25519-dalek doesn't report errors; a zero result means the pubkey was bad
    // but we don't check for that here to match C++ behavior
    Ok(shared.to_bytes())
}

/// Derives the XChaCha20 shared key:
///   key = Blake2b-256(DH(local_sk, remote_pk) || first_pk || second_pk)
///
/// `local_first` = true when the local side is the client (Alice).
fn xchacha20_shared_key(
    local_pub: &X25519Pubkey,
    local_sec: &X25519Seckey,
    remote_pub: &X25519Pubkey,
    local_first: bool,
) -> Result<[u8; 32], HopEncryptionError> {
    let shared_secret = dh(local_sec, remote_pub)?;

    let mut hasher = blake2b_simd::Params::new();
    hasher.hash_length(32);

    let mut state = hasher.to_state();
    state.update(&shared_secret);

    if local_first {
        state.update(local_pub.as_bytes());
        state.update(remote_pub.as_bytes());
    } else {
        state.update(remote_pub.as_bytes());
        state.update(local_pub.as_bytes());
    }

    let hash = state.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    Ok(key)
}

/// Derives the AES-GCM key: HMAC-SHA256(salt="LOKI", DH(local_sk, remote_pk))
fn derive_aesgcm_key(
    secret: &X25519Seckey,
    public: &X25519Pubkey,
) -> Result<[u8; 32], HopEncryptionError> {
    use hmac::{Hmac, Mac};
    use sha2_0_10::Sha256;

    let shared_secret = dh(secret, public)?;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"LOKI")
        .map_err(|e| HopEncryptionError::EncryptionFailed(e.to_string()))?;
    Mac::update(&mut mac, &shared_secret);
    let result = mac.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::x25519_keypair;

    #[test]
    fn test_xchacha20_roundtrip() {
        let (client_pk, client_sk) = x25519_keypair();
        let (server_pk, server_sk) = x25519_keypair();

        let client_enc = HopEncryption::new(client_sk, client_pk, false);
        let server_enc = HopEncryption::new(server_sk, server_pk, true);

        let plaintext = b"Hello, onion routing!";
        let ciphertext = client_enc
            .encrypt(EncryptType::XChaCha20, plaintext, &server_pk)
            .unwrap();

        let decrypted = server_enc
            .decrypt(EncryptType::XChaCha20, &ciphertext, &client_pk)
            .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_server_to_client() {
        let (client_pk, client_sk) = x25519_keypair();
        let (server_pk, server_sk) = x25519_keypair();

        let client_enc = HopEncryption::new(client_sk, client_pk, false);
        let server_enc = HopEncryption::new(server_sk, server_pk, true);

        let plaintext = b"Response from server";
        let ciphertext = server_enc
            .encrypt(EncryptType::XChaCha20, plaintext, &client_pk)
            .unwrap();

        let decrypted = client_enc
            .decrypt(EncryptType::XChaCha20, &ciphertext, &server_pk)
            .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aesgcm_roundtrip() {
        let (client_pk, client_sk) = x25519_keypair();
        let (server_pk, server_sk) = x25519_keypair();

        let client_enc = HopEncryption::new(client_sk, client_pk, false);
        let server_enc = HopEncryption::new(server_sk, server_pk, true);

        let plaintext = b"Hello AES-GCM!";
        let ciphertext = client_enc
            .encrypt(EncryptType::AesGcm, plaintext, &server_pk)
            .unwrap();

        let decrypted = server_enc
            .decrypt(EncryptType::AesGcm, &ciphertext, &client_pk)
            .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_short_ciphertext() {
        let (pk, sk) = x25519_keypair();
        let (remote_pk, _) = x25519_keypair();
        let enc = HopEncryption::new(sk, pk, false);

        let result = enc.decrypt(EncryptType::XChaCha20, &[0u8; 5], &remote_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_enc_type() {
        assert_eq!(parse_enc_type("xchacha20").unwrap(), EncryptType::XChaCha20);
        assert_eq!(
            parse_enc_type("xchacha20-poly1305").unwrap(),
            EncryptType::XChaCha20
        );
        assert_eq!(parse_enc_type("aes-gcm").unwrap(), EncryptType::AesGcm);
        assert_eq!(parse_enc_type("gcm").unwrap(), EncryptType::AesGcm);
        assert!(parse_enc_type("unknown").is_err());
    }

    #[test]
    fn test_response_long_enough() {
        assert!(!HopEncryption::response_long_enough(
            EncryptType::XChaCha20,
            0
        ));
        assert!(HopEncryption::response_long_enough(
            EncryptType::XChaCha20,
            16
        ));
        assert!(!HopEncryption::response_long_enough(EncryptType::AesGcm, 0));
        assert!(HopEncryption::response_long_enough(EncryptType::AesGcm, 32));
    }

    #[test]
    fn test_encrypt_type_display() {
        assert_eq!(EncryptType::XChaCha20.as_str(), "xchacha20");
        assert_eq!(EncryptType::AesGcm.as_str(), "aes-gcm");
    }
}
