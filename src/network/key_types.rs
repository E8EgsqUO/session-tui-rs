//! Typed key wrappers for Ed25519 and X25519 keys used in the network layer.
//!
//! These types provide safe wrappers around raw byte arrays with hex encoding,
//! base32z encoding, validation, and conversion utilities. Secret keys are
//! zeroized on drop.

use std::fmt;

use crate::crypto::curve25519::to_curve25519_pubkey;
use zeroize::Zeroize;

/// Error type for key operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid hex: {0}")]
    InvalidHex(String),
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("Key conversion failed: {0}")]
    ConversionFailed(String),
}

/// Result type alias for key operations.
pub type KeyResult<T> = Result<T, KeyError>;

// ---------------------------------------------------------------------------
// Ed25519Pubkey
// ---------------------------------------------------------------------------

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519Pubkey(pub [u8; 32]);

impl Ed25519Pubkey {
    /// Key length in bytes.
    pub const LEN: usize = 32;

    /// Parses from a 64-character hex string.
    pub fn from_hex(hex: &str) -> KeyResult<Self> {
        if hex.len() != 64 {
            return Err(KeyError::InvalidLength {
                expected: 64,
                got: hex.len(),
            });
        }
        let bytes = hex::decode(hex).map_err(|e| KeyError::InvalidHex(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Constructs from a 32-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> KeyResult<Self> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Returns the hex-encoded string representation.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if all bytes are zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Returns the `{base32z}.snode` representation of this pubkey.
    pub fn snode_address(&self) -> String {
        let encoded = base32z_encode(&self.0);
        format!("{}.snode", encoded)
    }
}

impl fmt::Debug for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Pubkey({})", self.hex())
    }
}

impl fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

// ---------------------------------------------------------------------------
// X25519Pubkey
// ---------------------------------------------------------------------------

/// An X25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X25519Pubkey(pub [u8; 32]);

impl X25519Pubkey {
    /// Key length in bytes.
    pub const LEN: usize = 32;

    /// Parses from a 64-character hex string.
    pub fn from_hex(hex: &str) -> KeyResult<Self> {
        if hex.len() != 64 {
            return Err(KeyError::InvalidLength {
                expected: 64,
                got: hex.len(),
            });
        }
        let bytes = hex::decode(hex).map_err(|e| KeyError::InvalidHex(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Constructs from a 32-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> KeyResult<Self> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Returns the hex-encoded string representation.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if all bytes are zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for X25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Pubkey({})", self.hex())
    }
}

impl fmt::Display for X25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

// ---------------------------------------------------------------------------
// Ed25519Seckey (64 bytes: seed || pubkey, libsodium format)
// ---------------------------------------------------------------------------

/// An Ed25519 secret key in libsodium format (64 bytes: seed || pubkey).
///
/// Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Ed25519Seckey(pub [u8; 64]);

impl Ed25519Seckey {
    /// Key length in bytes (seed + pubkey).
    pub const LEN: usize = 64;

    /// Constructs from a 64-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> KeyResult<Self> {
        if bytes.len() != 64 {
            return Err(KeyError::InvalidLength {
                expected: 64,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Returns a reference to the underlying 64-byte array.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Extracts the Ed25519 public key from this secret key.
    /// The pubkey is stored in the last 32 bytes of the 64-byte libsodium format.
    pub fn pubkey(&self) -> Ed25519Pubkey {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&self.0[32..64]);
        Ed25519Pubkey(pk)
    }
}

impl fmt::Debug for Ed25519Seckey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Seckey([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// X25519Seckey (32 bytes)
// ---------------------------------------------------------------------------

/// An X25519 secret key (32 bytes).
///
/// Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct X25519Seckey(pub [u8; 32]);

impl X25519Seckey {
    /// Key length in bytes.
    pub const LEN: usize = 32;

    /// Constructs from a 32-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> KeyResult<Self> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the corresponding X25519 public key via scalar multiplication on the base point.
    pub fn pubkey(&self) -> X25519Pubkey {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        let public = x25519_dalek::PublicKey::from(&secret);
        X25519Pubkey(public.to_bytes())
    }
}

impl fmt::Debug for X25519Seckey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Seckey([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// Keypair type aliases
// ---------------------------------------------------------------------------

/// An Ed25519 keypair (public key, secret key).
pub type Ed25519Keypair = (Ed25519Pubkey, Ed25519Seckey);
/// An X25519 keypair (public key, secret key).
pub type X25519Keypair = (X25519Pubkey, X25519Seckey);

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// Converts an Ed25519 public key to an X25519 public key.
pub fn compute_x25519_pubkey(ed25519_pk: &Ed25519Pubkey) -> KeyResult<X25519Pubkey> {
    let x_pk = to_curve25519_pubkey(ed25519_pk.as_bytes()).map_err(|e| {
        KeyError::ConversionFailed(format!(
            "Failed to convert Ed25519 pubkey to X25519: {}",
            e
        ))
    })?;
    Ok(X25519Pubkey(x_pk))
}

/// Converts an Ed25519 public key given as a byte slice to an X25519 public key.
pub fn compute_x25519_pubkey_from_bytes(ed25519_pk: &[u8]) -> KeyResult<X25519Pubkey> {
    let pk = Ed25519Pubkey::from_bytes(ed25519_pk)?;
    compute_x25519_pubkey(&pk)
}

/// Parses a public key from hex, base32z, base64, or raw bytes (32 bytes).
pub fn parse_x25519_pubkey(input: &str) -> KeyResult<X25519Pubkey> {
    let bytes = input.as_bytes();

    if bytes.len() == 32 {
        // Raw bytes
        return X25519Pubkey::from_bytes(bytes);
    }

    if bytes.len() == 64 {
        // Hex
        if let Ok(pk) = X25519Pubkey::from_hex(input) {
            return Ok(pk);
        }
    }

    if bytes.len() == 52 {
        // Base32z
        if let Some(decoded) = base32z_decode(input) {
            if decoded.len() == 32 {
                return X25519Pubkey::from_bytes(&decoded);
            }
        }
    }

    if (bytes.len() == 43 || (bytes.len() == 44 && bytes[43] == b'='))
        && base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input).is_ok()
    {
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input).unwrap();
        if decoded.len() == 32 {
            return X25519Pubkey::from_bytes(&decoded);
        }
    }

    Err(KeyError::InvalidHex(format!(
        "Could not parse pubkey from input of length {}",
        input.len()
    )))
}

// ---------------------------------------------------------------------------
// Base32z encoding/decoding (compatible with oxenc::base32z)
// ---------------------------------------------------------------------------

const BASE32Z_CHARS: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

fn base32z_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut num_bits = 0;

    for &byte in data {
        bits = (bits << 8) | byte as u64;
        num_bits += 8;
        while num_bits >= 5 {
            num_bits -= 5;
            let idx = ((bits >> num_bits) & 0x1f) as usize;
            result.push(BASE32Z_CHARS[idx] as char);
        }
    }

    if num_bits > 0 {
        let idx = ((bits << (5 - num_bits)) & 0x1f) as usize;
        result.push(BASE32Z_CHARS[idx] as char);
    }

    result
}

fn base32z_decode(input: &str) -> Option<Vec<u8>> {
    let mut lookup = [255u8; 128];
    for (i, &c) in BASE32Z_CHARS.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let mut bits: u64 = 0;
    let mut num_bits = 0;
    let mut result = Vec::new();

    for &ch in input.as_bytes() {
        if ch >= 128 || lookup[ch as usize] == 255 {
            return None;
        }
        bits = (bits << 5) | lookup[ch as usize] as u64;
        num_bits += 5;
        if num_bits >= 8 {
            num_bits -= 8;
            result.push((bits >> num_bits) as u8);
        }
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Generate X25519 keypair
// ---------------------------------------------------------------------------

/// Generates a random X25519 keypair.
pub fn x25519_keypair() -> X25519Keypair {
    let (pk, sk) = crate::crypto::curve25519::curve25519_key_pair();
    (X25519Pubkey(pk), X25519Seckey(sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ed25519_pubkey_hex_roundtrip() {
        let pk_hex = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7";
        let pk = Ed25519Pubkey::from_hex(pk_hex).unwrap();
        assert_eq!(pk.hex(), pk_hex);
        assert!(!pk.is_zero());
    }

    #[test]
    fn test_ed25519_pubkey_from_bytes() {
        let bytes =
            hex!("4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
        let pk = Ed25519Pubkey::from_bytes(&bytes).unwrap();
        assert_eq!(
            pk.hex(),
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"
        );
    }

    #[test]
    fn test_x25519_pubkey_hex_roundtrip() {
        let pk_hex = "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72";
        let pk = X25519Pubkey::from_hex(pk_hex).unwrap();
        assert_eq!(pk.hex(), pk_hex);
    }

    #[test]
    fn test_compute_x25519_pubkey() {
        let ed_pk = Ed25519Pubkey::from_hex(
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7",
        )
        .unwrap();
        let x_pk = compute_x25519_pubkey(&ed_pk).unwrap();
        assert_eq!(
            x_pk.hex(),
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );
    }

    #[test]
    fn test_x25519_seckey_pubkey() {
        let (pk, sk) = x25519_keypair();
        let derived_pk = sk.pubkey();
        assert_eq!(pk, derived_pk);
    }

    #[test]
    fn test_ed25519_pubkey_zero() {
        let pk = Ed25519Pubkey([0u8; 32]);
        assert!(pk.is_zero());
    }

    #[test]
    fn test_snode_address() {
        // Just test that it produces a base32z string ending in .snode
        let pk = Ed25519Pubkey::from_hex(
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7",
        )
        .unwrap();
        let addr = pk.snode_address();
        assert!(addr.ends_with(".snode"));
        assert!(addr.len() > 6);
    }

    #[test]
    fn test_invalid_hex_length() {
        assert!(Ed25519Pubkey::from_hex("abcd").is_err());
    }

    #[test]
    fn test_invalid_hex_chars() {
        let invalid = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(Ed25519Pubkey::from_hex(invalid).is_err());
    }

    #[test]
    fn test_base32z_roundtrip() {
        let data = hex!("4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
        let encoded = base32z_encode(&data);
        let decoded = base32z_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
