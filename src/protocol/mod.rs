//! Session protocol constants, Pro proof types, and message padding.
//!
//! Ported from `libsession-util` C++ headers and sources. Includes character
//! limits, BLAKE2b personalisation strings, protocol URL bundles, Pro payment
//! proof verification, and envelope flag definitions.

/// Protocol constants, Pro proof types, envelope flags, and message padding.
pub mod protocol;
pub use protocol::*;
