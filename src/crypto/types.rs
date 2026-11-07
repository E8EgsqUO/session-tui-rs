//! Shared cryptographic types: error definitions, Session ID prefixes, and platform identifiers.

use thiserror::Error;

/// Error type for cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected} bytes, got {got}")]
    InvalidKeySize { expected: usize, got: usize },
    #[error("Invalid signature size: expected 64 bytes, got {0}")]
    InvalidSignatureSize(usize),
    #[error("Invalid seed size: expected 32 bytes, got {0}")]
    InvalidSeedSize(usize),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key conversion failed: {0}")]
    KeyConversionFailed(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Result type alias for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Session ID prefix bytes as used in the C++ `SessionIDPrefix` enum.
///
/// Note: these are the enum discriminant values from the C++ code, not necessarily
/// the literal prefix bytes used on the wire. For example, `Standard = 0x00` but
/// standard session IDs on the wire use `0x05` as their prefix byte.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIdPrefix {
    Standard = 0x00,
    Group = 0x03,
    CommunityBlindedLegacy = 0x05,
    CommunityBlinded = 0x15,
    VersionBlinded = 0x25,
    Unblinded = 0x07,
}

/// Client platform identifier used in protocol version strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Android,
    Desktop,
    Ios,
}

/// Result of decrypting a group message, containing the sender and plaintext.
#[derive(Debug, Clone)]
pub struct DecryptGroupMessage {
    pub index: usize,
    pub session_id: String,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_prefix_values() {
        assert_eq!(SessionIdPrefix::Standard as u8, 0x00);
        assert_eq!(SessionIdPrefix::Group as u8, 0x03);
        assert_eq!(SessionIdPrefix::CommunityBlindedLegacy as u8, 0x05);
        assert_eq!(SessionIdPrefix::CommunityBlinded as u8, 0x15);
        assert_eq!(SessionIdPrefix::VersionBlinded as u8, 0x25);
        assert_eq!(SessionIdPrefix::Unblinded as u8, 0x07);
    }

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::InvalidKeySize {
            expected: 32,
            got: 16,
        };
        assert_eq!(
            err.to_string(),
            "Invalid key size: expected 32 bytes, got 16"
        );

        let err = CryptoError::InvalidSignatureSize(48);
        assert_eq!(
            err.to_string(),
            "Invalid signature size: expected 64 bytes, got 48"
        );

        let err = CryptoError::VerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");
    }

    #[test]
    fn test_platform_equality() {
        assert_eq!(Platform::Android, Platform::Android);
        assert_ne!(Platform::Android, Platform::Ios);
        assert_ne!(Platform::Desktop, Platform::Ios);
    }

    #[test]
    fn test_decrypt_group_message() {
        let msg = DecryptGroupMessage {
            index: 42,
            session_id: "05abcdef".to_string(),
            data: vec![1, 2, 3],
        };
        assert_eq!(msg.index, 42);
        assert_eq!(msg.session_id, "05abcdef");
        assert_eq!(msg.data, vec![1, 2, 3]);
    }
}
