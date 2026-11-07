//! Group config types: Info, Members, Keys.
//!
//! These are distinct from `user_groups` (which tracks the *user's* group memberships).
//! These config types manage the *group's own* shared state:
//! - `Info`: group name, description, profile pic, expiry, destroy flag
//! - `Members`: member list with admin/invite/promotion status
//! - `Keys`: encryption key rotation (special, not ConfigBase-based)

/// Group name, description, profile picture, expiry, and destroy flag.
pub mod info;
/// Group encryption key rotation and distribution.
pub mod keys;
/// Group member list with admin, invite, and promotion status.
pub mod members;
