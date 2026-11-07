//! Request routing strategies for the Session network.
//!
//! Provides onion request routing (3-hop encrypted paths) and direct routing
//! (unencrypted, for testing/development).

/// Abstract router trait and path management.
pub mod router;
/// Onion request router with path building and rotation.
pub mod onion_request;
/// Direct (non-onion) router for testing and development.
pub mod direct;
/// Per-category onion-path pool and rotation.
pub mod path_manager;
