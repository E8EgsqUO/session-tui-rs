//! Shared utilities for Session.
//!
//! Provides bencode serialization, zstd compression, Session ID validation,
//! URL parsing, UTF-8 truncation, and logging setup.

/// Bencode encoding, decoding, and merge operations.
pub mod bencode;
/// Logging initialization and log level configuration.
pub mod logging;
/// Session ID validation, URL parsing, UTF-8 truncation, and string splitting.
pub mod types;
/// Zstandard compression and decompression.
pub mod zstd_compress;
