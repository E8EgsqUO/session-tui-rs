//! Cryptographic primitives and message encryption for Session.
//!
//! Provides Ed25519/X25519 key generation, sealed-box and group encryption,
//! identity blinding for communities, multi-recipient encryption, attachment
//! encryption, BLAKE2b hashing, and key conversion utilities.

/// Deterministic attachment encryption using XChaCha20-Poly1305 with padding.
pub mod attachments;
/// Blind15/Blind25 identity hiding for community messaging.
pub mod blinding;
/// X25519 key pair generation and Ed25519-to-Curve25519 conversion.
pub mod curve25519;
/// Ed25519 key pair generation, signing, and signature verification.
pub mod ed25519;
/// BLAKE2b hashing with configurable output size and optional key.
pub mod hash;
/// Encrypt a single message for multiple recipients.
pub mod multi_encrypt;
/// Cryptographically secure random byte generation.
pub mod random;
/// Sealed-box, group, and blinded message encryption/decryption.
pub mod session_encrypt;
/// Shared types: error definitions, Session ID prefixes, platform enum.
pub mod types;
/// XEd25519 operations for converting between Ed25519 and X25519 signatures.
pub mod xed25519;
