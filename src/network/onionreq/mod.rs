//! Onion request construction, parsing, and response decryption.
//!
//! Implements layered encryption for 3-hop onion routing through the Session
//! service node network. Supports both XChaCha20-Poly1305 and AES-256-GCM
//! encryption modes.

/// Per-hop encryption/decryption using XChaCha20-Poly1305 or AES-256-GCM.
pub mod hop_encryption;
/// Onion request payload builder with layered encryption.
pub mod builder;
/// Server-side onion request parser for decrypting incoming requests.
pub mod parser;
/// Client-side response parser for decrypting onion-routed responses.
pub mod response_parser;
