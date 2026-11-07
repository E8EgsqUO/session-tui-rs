//! # libsession
//!
//! Rust implementation of the Session messenger core library.
//!
//! Provides cryptography, distributed configuration management, onion-routed
//! networking, and protocol definitions used by Session clients (iOS, Android, Desktop).
//!
//! ## Modules
//!
//! - [`crypto`] -- Cryptographic primitives: key generation, message encryption,
//!   blinding, hashing, and key conversion.
//! - [`config`] -- Distributed configuration management with merge-based conflict
//!   resolution for multi-device sync.
//! - [`network`] -- Onion-routed communication through the Session service node network.
//! - [`protocol`] -- Protocol constants, Session Pro proof types, and message padding.
//! - [`proto`] -- Generated protobuf bindings for Session message envelopes.
//! - [`util`] -- Shared utilities: bencode, compression, validation, logging.

/// Cryptographic primitives and message encryption.
pub mod crypto;
/// Shared utilities: bencode, compression, Session ID validation, logging.
pub mod util;
/// Generated protobuf bindings for Session message envelopes and WebSocket messages.
pub mod proto;
/// Protocol constants, Session Pro proof types, and message padding.
pub mod protocol;
/// Distributed configuration management for multi-device sync.
pub mod config;
/// Onion-routed networking through the Session service node network.
pub mod network;
