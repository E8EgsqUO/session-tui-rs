//! Request routing strategies for the Session network.
//!
//! Provides onion request routing (3-hop encrypted paths) and direct routing
//! (unencrypted, for testing/development).

/// Direct (non-onion) router for testing and development.
pub mod direct;
/// Onion request router with path building and rotation.
pub mod onion_request;
/// Per-category onion-path pool and rotation.
pub mod path_manager;
/// Abstract router trait and path management.
pub mod router;
