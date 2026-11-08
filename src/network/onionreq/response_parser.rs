//! Client-side response parser for onion request responses.
//!
//! Decrypts the response from the final destination, handling both V3 (JSON-wrapped
//! base64) and V4 (raw bencoded) response formats.
//!
//! Port of `session::onionreq::ResponseParser` from the C++ code.

use crate::network::key_types::{X25519Keypair, X25519Pubkey};
use crate::network::onionreq::builder::Builder;
use crate::network::onionreq::hop_encryption::{EncryptType, HopEncryption};

/// Error message returned when both encryption modes fail to decrypt a response.
pub const DECRYPTION_FAILED_ERROR: &str =
    "Decryption failed (both XChaCha20-Poly1305 and AES256-GCM)";

/// Decrypted response from an onion request.
#[derive(Debug, Clone)]
pub struct DecryptedResponse {
    pub status_code: i16,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// Decrypted response body bytes, preserving binary file-server payloads.
    pub body_bytes: Option<Vec<u8>>,
}

/// Error type for onion response parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum ResponseParserError {
    #[error("Builder does not contain destination x25519 public key")]
    MissingDestinationKey,
    #[error("Builder does not contain final keypair")]
    MissingFinalKeypair,
    #[error("Response too short")]
    ResponseTooShort,
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid response format: {0}")]
    InvalidFormat(String),
    #[error("JSON parse error: {0}")]
    JsonError(String),
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
}

/// Parser for decrypting onion request responses on the client side.
pub struct ResponseParser {
    destination_x25519_pubkey: X25519Pubkey,
    x25519_keypair: X25519Keypair,
    enc_type: EncryptType,
    v4_request: bool,
}

impl ResponseParser {
    /// Creates a parser from a completed builder.
    pub fn from_builder(builder: &Builder) -> Result<Self, ResponseParserError> {
        let dest_pk = builder
            .destination_x25519_public_key()
            .ok_or(ResponseParserError::MissingDestinationKey)?;

        let keypair = builder
            .final_hop_x25519_keypair
            .as_ref()
            .ok_or(ResponseParserError::MissingFinalKeypair)?;

        Ok(Self {
            destination_x25519_pubkey: *dest_pk,
            x25519_keypair: keypair.clone(),
            enc_type: builder.enc_type(),
            v4_request: builder.is_v4_request(),
        })
    }

    /// Creates a parser with explicit parameters.
    pub fn new(
        destination_x25519_pubkey: X25519Pubkey,
        x25519_keypair: X25519Keypair,
        enc_type: EncryptType,
        v4_request: bool,
    ) -> Self {
        Self {
            destination_x25519_pubkey,
            x25519_keypair,
            enc_type,
            v4_request,
        }
    }

    /// Checks if the response is long enough for the given encryption type.
    pub fn response_long_enough(enc_type: EncryptType, response_size: usize) -> bool {
        HopEncryption::response_long_enough(enc_type, response_size)
    }

    /// Decrypts raw ciphertext from an onion response.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ResponseParserError> {
        let dec = HopEncryption::new(
            self.x25519_keypair.1.clone(),
            self.x25519_keypair.0,
            false,
        );

        // Try primary encryption type first
        match dec.decrypt(self.enc_type, ciphertext, &self.destination_x25519_pubkey) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => {
                // Fallback: if xchacha20 fails, try aes_gcm (legacy PN server compat)
                if self.enc_type == EncryptType::XChaCha20 {
                    dec.decrypt(
                        EncryptType::AesGcm,
                        ciphertext,
                        &self.destination_x25519_pubkey,
                    )
                    .map_err(|_| {
                        ResponseParserError::DecryptionFailed(
                            DECRYPTION_FAILED_ERROR.into(),
                        )
                    })
                } else {
                    Err(ResponseParserError::DecryptionFailed(
                        "Decryption failed".into(),
                    ))
                }
            }
        }
    }

    /// Decrypts and parses a full onion response (handling V3/V4 format).
    pub fn decrypted_response(
        &self,
        encrypted_response: &str,
    ) -> Result<DecryptedResponse, ResponseParserError> {
        self.decrypted_response_bytes(encrypted_response.as_bytes())
    }

    /// Decrypts an onion response from raw bytes, preserving binary response bodies.
    pub fn decrypted_response_bytes(
        &self,
        encrypted_response: &[u8],
    ) -> Result<DecryptedResponse, ResponseParserError> {
        if !Self::response_long_enough(self.enc_type, encrypted_response.len()) {
            return Err(ResponseParserError::ResponseTooShort);
        }

        if self.v4_request {
            self.decrypt_v4_response(encrypted_response)
        } else {
            let response = std::str::from_utf8(encrypted_response).map_err(|_| {
                ResponseParserError::InvalidFormat("response body is not UTF-8".into())
            })?;
            self.decrypt_v3_response(response)
        }
    }

    /// V3 response: JSON-wrapped, base64-encoded ciphertext.
    fn decrypt_v3_response(
        &self,
        response: &str,
    ) -> Result<DecryptedResponse, ResponseParserError> {
        // Try to parse as JSON with "result" field, fall back to raw string
        let base64_data = if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
            if let Some(result) = json.get("result").and_then(|v| v.as_str()) {
                result.to_string()
            } else {
                response.to_string()
            }
        } else {
            response.to_string()
        };

        use base64::Engine;
        let iv_and_ciphertext =
            base64::engine::general_purpose::STANDARD
                .decode(&base64_data)
                .map_err(|e| ResponseParserError::Base64Error(e.to_string()))?;

        let decrypted = self.decrypt(&iv_and_ciphertext)?;

        let result_json: serde_json::Value = serde_json::from_slice(&decrypted)
            .map_err(|e| ResponseParserError::JsonError(e.to_string()))?;

        // Extract status code
        let status_code = result_json
            .get("status_code")
            .and_then(|v| v.as_i64())
            .or_else(|| result_json.get("status").and_then(|v| v.as_i64()))
            .ok_or_else(|| {
                ResponseParserError::InvalidFormat(
                    "Missing required status_code field".into(),
                )
            })? as i16;

        // Extract headers
        let mut headers = Vec::new();
        if let Some(header_obj) = result_json.get("headers").and_then(|v| v.as_object()) {
            for (key, value) in header_obj {
                if let Some(val_str) = value.as_str() {
                    headers.push((key.clone(), val_str.to_string()));
                }
            }
        }

        // Extract body
        let body = if let Some(b) = result_json.get("body").and_then(|v| v.as_str()) {
            Some(b.to_string())
        } else {
            Some(result_json.to_string())
        };

        let body_bytes = body.as_ref().map(|value| value.as_bytes().to_vec());
        Ok(DecryptedResponse {
            status_code,
            headers,
            body,
            body_bytes,
        })
    }

    /// V4 response: raw encrypted bytes, bencoded response inside.
    fn decrypt_v4_response(
        &self,
        response_data: &[u8],
    ) -> Result<DecryptedResponse, ResponseParserError> {
        let decrypted = self.decrypt(response_data)?;

        // Parse bencoded list: l<string1><string2>e
        // First string is response info JSON, second (optional) is body
        let parsed = parse_bencode_list(&decrypted)
            .map_err(|e| ResponseParserError::InvalidFormat(e))?;

        if parsed.is_empty() {
            return Err(ResponseParserError::InvalidFormat(
                "Empty bencoded response".into(),
            ));
        }

        let response_info: serde_json::Value =
            serde_json::from_slice(&parsed[0])
                .map_err(|e| ResponseParserError::JsonError(e.to_string()))?;

        let status_code = response_info
            .get("code")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                ResponseParserError::InvalidFormat("Missing required code field".into())
            })? as i16;

        let mut headers = Vec::new();
        if let Some(header_obj) = response_info.get("headers").and_then(|v| v.as_object()) {
            for (key, value) in header_obj {
                if let Some(val_str) = value.as_str() {
                    headers.push((key.clone(), val_str.to_string()));
                }
            }
        }

        let body_bytes = parsed.get(1).cloned();
        let body = body_bytes
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string());

        Ok(DecryptedResponse {
            status_code,
            headers,
            body,
            body_bytes,
        })
    }
}

/// Minimal bencode list parser that extracts string elements from a bencoded list.
fn parse_bencode_list(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if data.is_empty() || data[0] != b'l' {
        return Err("Expected bencoded list".into());
    }

    let mut pos = 1;
    let mut items = Vec::new();

    while pos < data.len() && data[pos] != b'e' {
        // Parse string: <length>:<data>
        let colon_pos = data[pos..]
            .iter()
            .position(|&b| b == b':')
            .ok_or("Missing ':' in bencode string")?
            + pos;

        let len_str = std::str::from_utf8(&data[pos..colon_pos])
            .map_err(|_| "Invalid length in bencode string")?;
        let len: usize = len_str
            .parse()
            .map_err(|_| "Invalid length number in bencode string")?;

        let str_start = colon_pos + 1;
        let str_end = str_start
            .checked_add(len)
            .filter(|end| *end <= data.len())
            .ok_or("Bencode string extends past data")?;

        items.push(data[str_start..str_end].to_vec());
        pos = str_end;
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::x25519_keypair;

    #[test]
    fn test_parse_bencode_list() {
        let data = b"l5:hello5:worlde";
        let items = parse_bencode_list(data).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], b"hello");
        assert_eq!(items[1], b"world");
    }

    #[test]
    fn test_parse_bencode_list_empty() {
        let data = b"le";
        let items = parse_bencode_list(data).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_parse_bencode_list_single() {
        let data = b"l3:fooe";
        let items = parse_bencode_list(data).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], b"foo");
    }

    #[test]
    fn test_response_parser_v3() {
        let (dest_pk, dest_sk) = x25519_keypair();
        let (client_pk, client_sk) = x25519_keypair();

        // Server encrypts a response
        let response_json = serde_json::json!({
            "status_code": 200,
            "body": "ok",
        });
        let response_bytes = response_json.to_string().into_bytes();

        let server_enc = HopEncryption::new(dest_sk.clone(), dest_pk, true);
        let encrypted = server_enc
            .encrypt(EncryptType::XChaCha20, &response_bytes, &client_pk)
            .unwrap();

        // Base64 encode
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        let wrapped = serde_json::json!({"result": b64}).to_string();

        // Client decrypts
        let parser = ResponseParser::new(dest_pk, (client_pk, client_sk), EncryptType::XChaCha20, false);
        let resp = parser.decrypted_response(&wrapped).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body.as_deref(), Some("ok"));
    }

    #[test]
    fn test_response_long_enough() {
        assert!(!ResponseParser::response_long_enough(
            EncryptType::XChaCha20,
            5
        ));
        assert!(ResponseParser::response_long_enough(
            EncryptType::XChaCha20,
            100
        ));
    }
}
