//! Distributed configuration management for multi-device sync.
//!
//! Each config type supports merge-based conflict resolution, encrypted push/pull
//! to the Session swarm, and dirty-state tracking. Config data is serialized using
//! bencode and protected with BLAKE2b hashing.

/// Community (open group) configuration.
pub mod community;
/// Generic config wrapper with lifecycle state tracking (Clean/Dirty/Waiting).
pub mod config_base;
/// Core merge-capable config message types with bencode serialization.
pub mod config_message;
/// Contact list with approval states and profile data.
pub mod contacts;
/// Volatile conversation metadata: mute, pin, read position.
pub mod convo_info_volatile;
/// Config encryption/decryption for swarm storage.
pub mod encrypt;
/// Config error codes mirroring the C enum.
pub mod error;
/// Message expiry types and configuration.
pub mod expiring;
/// Group-specific config: info, members, and key rotation.
pub mod groups;
/// Device-local settings (not synced to swarm).
pub mod local;
/// Namespace identifiers for Session config and message storage.
pub mod namespaces;
/// Notification mode and content types.
pub mod notify;
/// Profile picture URL and key management.
pub mod profile_pic;
/// User's group and community memberships.
pub mod user_groups;
/// User profile: display name, avatar, settings.
pub mod user_profile;
