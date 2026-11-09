//! Server-side onion request parser.
//!
//! Decrypts the first layer of an incoming onion request, extracting the payload
//! for this hop.
//!
//! Port of `session::onionreq::OnionReqParser` from the C++ code.

use crate::network::key_types::{X25519Keypair, X25519Pubkey, X25519Seckey};
use crate::network::onionreq::hop_encryption::{
    EncryptType, HopEncryption, HopEncryptionError, parse_enc_type,
};

/// Maximum size of an onion request accepted by default (10 MiB).
pub const DEFAULT_MAX_SIZE: usize = 10_485_760;

/// Error type for onion request parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    #[error("Request data too small")]
    TooSmall,
    #[error("Request data too big")]
    TooBig,
    #[error("Encrypted segment too small")]
    SegmentTooSmall,
    #[error("Metadata missing ephemeral_key")]
    MissingEphemeralKey,
    #[error("JSON parse error: {0}")]
    JsonError(String),
    #[error("Key error: {0}")]
    KeyError(#[from] crate::network::key_types::KeyError),
    #[error("Decryption error: {0}")]
    DecryptionError(#[from] HopEncryptionError),
}

/// Parses an incoming onion request, decrypting the first layer.
pub struct OnionReqParser {
    #[allow(dead_code)]
    keys: X25519Keypair,
    enc: HopEncryption,
    enc_type: EncryptType,
    remote_pk: X25519Pubkey,
    payload: Vec<u8>,
}

impl OnionReqParser {
    /// Constructs a parser, parsing and decrypting the given request.
    ///
    /// # Arguments
    /// * `x25519_pubkey` - Our X25519 public key (32 bytes)
    /// * `x25519_privkey` - Our X25519 private key (32 bytes)
    /// * `req` - The raw request data
    /// * `max_size` - Maximum allowed size (default: 10 MiB)
    pub fn new(
        x25519_pubkey: &[u8],
        x25519_privkey: &[u8],
        req: &[u8],
        max_size: usize,
    ) -> Result<Self, ParserError> {
        let pk = X25519Pubkey::from_bytes(x25519_pubkey)?;
        let sk = X25519Seckey::from_bytes(x25519_privkey)?;
        let enc = HopEncryption::new(sk.clone(), pk, true);

        if req.len() < 4 {
            return Err(ParserError::TooSmall);
        }
        if req.len() > max_size {
            return Err(ParserError::TooBig);
        }

        // Read 4-byte little-endian size
        let size = u32::from_le_bytes([req[0], req[1], req[2], req[3]]) as usize;
        let data = &req[4..];

        if data.len() < size {
            return Err(ParserError::SegmentTooSmall);
        }

        let ciphertext = &data[..size];
        let metadata_bytes = &data[size..];

        let metadata: serde_json::Value = serde_json::from_slice(metadata_bytes)
            .map_err(|e| ParserError::JsonError(e.to_string()))?;

        // Parse encryption type (default to AES-GCM for backwards compat)
        let enc_type = if let Some(et) = metadata.get("enc_type").and_then(|v| v.as_str()) {
            parse_enc_type(et)?
        } else {
            EncryptType::AesGcm
        };

        // Parse ephemeral key
        let eph_key_str = metadata
            .get("ephemeral_key")
            .and_then(|v| v.as_str())
            .ok_or(ParserError::MissingEphemeralKey)?;

        let remote_pk = crate::network::key_types::parse_x25519_pubkey(eph_key_str)?;

        // Decrypt the payload
        let payload = enc.decrypt(enc_type, ciphertext, &remote_pk)?;

        Ok(Self {
            keys: (pk, sk),
            enc,
            enc_type,
            remote_pk,
            payload,
        })
    }

    /// Returns the decrypted payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Moves the payload out of this parser.
    pub fn move_payload(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.payload)
    }

    /// Returns the remote (ephemeral) public key.
    pub fn remote_pubkey(&self) -> &X25519Pubkey {
        &self.remote_pk
    }

    /// Encrypts a reply using the appropriate encryption for this request.
    pub fn encrypt_reply(&self, reply: &[u8]) -> Result<Vec<u8>, HopEncryptionError> {
        self.enc.encrypt(self.enc_type, reply, &self.remote_pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::x25519_keypair;
    use crate::network::onionreq::hop_encryption::HopEncryption;

    #[test]
    fn test_parser_roundtrip() {
        let (server_pk, server_sk) = x25519_keypair();
        let (client_pk, client_sk) = x25519_keypair();

        let plaintext = b"Hello from client";

        // Client encrypts
        let client_enc = HopEncryption::new(client_sk, client_pk, false);
        let ciphertext = client_enc
            .encrypt(EncryptType::XChaCha20, plaintext, &server_pk)
            .unwrap();

        // Build the request envelope
        let metadata = serde_json::json!({
            "ephemeral_key": client_pk.hex(),
            "enc_type": "xchacha20",
        });
        let metadata_bytes = metadata.to_string().into_bytes();
        let size_bytes = (ciphertext.len() as u32).to_le_bytes();

        let mut req = Vec::new();
        req.extend_from_slice(&size_bytes);
        req.extend_from_slice(&ciphertext);
        req.extend_from_slice(&metadata_bytes);

        // Server parses
        let parser = OnionReqParser::new(
            server_pk.as_bytes(),
            server_sk.as_bytes(),
            &req,
            DEFAULT_MAX_SIZE,
        )
        .unwrap();

        assert_eq!(parser.payload(), plaintext);
    }

    #[test]
    fn test_parser_too_small() {
        let (pk, sk) = x25519_keypair();
        let result = OnionReqParser::new(pk.as_bytes(), sk.as_bytes(), &[0, 0], DEFAULT_MAX_SIZE);
        assert!(result.is_err());
    }
}
