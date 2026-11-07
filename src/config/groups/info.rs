//! Group Info config type.
//!
//! Port of `libsession-util/include/session/config/groups/info.hpp` and
//! `src/config/groups/info.cpp`.
//!
//! Config keys:
//!   ! - destroyed flag (set to 1 if group is permanently deleted)
//!   c - creation unix timestamp (seconds)
//!   d - delete before timestamp (seconds)
//!   D - delete attachments before timestamp (seconds)
//!   E - disappearing message timer (seconds) for delete-after-send
//!   n - group name (utf8, max 100 bytes)
//!   o - group description (utf8, max 600 bytes)
//!   p - group profile pic URL
//!   q - group profile pic decryption key (32 bytes)

use crate::config::config_base::field_helpers::*;
use crate::config::config_base::ConfigType;
use crate::config::config_message::ConfigData;
use crate::config::namespaces::Namespace;
use crate::config::profile_pic::ProfilePic;

/// Maximum group name length in bytes.
pub const NAME_MAX_LENGTH: usize = 100;
/// Maximum group description length in bytes.
pub const DESCRIPTION_MAX_LENGTH: usize = 600;

/// Group info configuration (shared state managed by admins).
#[derive(Debug, Clone, Default)]
pub struct GroupInfo {
    /// Group name.
    pub name: Option<String>,
    /// Group description.
    pub description: Option<String>,
    /// Group profile picture.
    pub profile_pic: ProfilePic,
    /// Unix timestamp (seconds) when the group was created.
    pub created: Option<i64>,
    /// Disappearing messages timer (seconds). None = disabled.
    pub expiry_timer: Option<u32>,
    /// Delete-before timestamp (seconds): delete all messages older than this.
    pub delete_before: Option<i64>,
    /// Delete-attachments-before timestamp (seconds).
    pub delete_attach_before: Option<i64>,
    /// Whether the group has been permanently destroyed.
    pub destroyed: bool,
}

impl GroupInfo {
    /// Sets the group name. Returns an error if too long.
    pub fn set_name(&mut self, name: &str) -> Result<(), String> {
        if name.len() > NAME_MAX_LENGTH {
            return Err("Invalid group name: exceeds maximum length".into());
        }
        self.name = if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        };
        Ok(())
    }

    /// Sets the group description. Returns an error if too long.
    pub fn set_description(&mut self, desc: &str) -> Result<(), String> {
        if desc.len() > DESCRIPTION_MAX_LENGTH {
            return Err("Invalid group description: exceeds maximum length".into());
        }
        self.description = if desc.is_empty() {
            None
        } else {
            Some(desc.to_string())
        };
        Ok(())
    }

    /// Permanently destroys the group. This cannot be undone.
    pub fn destroy_group(&mut self) {
        self.destroyed = true;
    }

    /// Returns true if the group has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    /// Sets the expiry timer. 0 or None disables it.
    pub fn set_expiry_timer(&mut self, seconds: Option<u32>) {
        self.expiry_timer = seconds.filter(|&s| s > 0);
    }

    /// Sets the created timestamp.
    pub fn set_created(&mut self, timestamp: i64) {
        if timestamp > 0 {
            self.created = Some(timestamp);
        }
    }

    /// Sets the delete-before timestamp.
    pub fn set_delete_before(&mut self, timestamp: i64) {
        self.delete_before = if timestamp > 0 {
            Some(timestamp)
        } else {
            None
        };
    }

    /// Sets the delete-attachments-before timestamp.
    pub fn set_delete_attach_before(&mut self, timestamp: i64) {
        self.delete_attach_before = if timestamp > 0 {
            Some(timestamp)
        } else {
            None
        };
    }
}

impl ConfigType for GroupInfo {
    fn namespace() -> Namespace {
        Namespace::GroupInfo
    }

    fn encryption_domain() -> &'static str {
        "groups::Info"
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        self.name = get_string(data, b"n");
        self.description = get_string(data, b"o");

        self.profile_pic = ProfilePic::default();
        if let Some(url) = get_string(data, b"p") {
            self.profile_pic.url = url;
        }
        if let Some(key) = get_bytes(data, b"q")
            && key.len() == 32 {
                self.profile_pic.key = key;
            }

        self.created = get_int(data, b"c").filter(|&v| v > 0);

        self.expiry_timer = get_int(data, b"E")
            .filter(|&v| v > 0)
            .map(|v| v as u32);

        self.delete_before = get_int(data, b"d").filter(|&v| v > 0);
        self.delete_attach_before = get_int(data, b"D").filter(|&v| v > 0);
        self.destroyed = get_int_or_zero(data, b"!") != 0;
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        if let Some(ref name) = self.name {
            set_nonempty_str(data, b"n", name);
        } else {
            data.remove(b"n".as_ref());
        }

        if let Some(ref desc) = self.description {
            set_nonempty_str(data, b"o", desc);
        } else {
            data.remove(b"o".as_ref());
        }

        if !self.profile_pic.url.is_empty() && self.profile_pic.key.len() == 32 {
            set_nonempty_str(data, b"p", &self.profile_pic.url);
            set_nonempty_bytes(data, b"q", &self.profile_pic.key);
        } else {
            data.remove(b"p".as_ref());
            data.remove(b"q".as_ref());
        }

        if let Some(created) = self.created {
            set_positive_int(data, b"c", created);
        } else {
            data.remove(b"c".as_ref());
        }

        if let Some(timer) = self.expiry_timer {
            set_positive_int(data, b"E", timer as i64);
        } else {
            data.remove(b"E".as_ref());
        }

        if let Some(ts) = self.delete_before {
            set_positive_int(data, b"d", ts);
        } else {
            data.remove(b"d".as_ref());
        }

        if let Some(ts) = self.delete_attach_before {
            set_positive_int(data, b"D", ts);
        } else {
            data.remove(b"D".as_ref());
        }

        set_flag(data, b"!", self.destroyed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_group_info() {
        let info = GroupInfo::default();
        assert!(info.name.is_none());
        assert!(info.description.is_none());
        assert!(info.profile_pic.is_empty());
        assert!(info.created.is_none());
        assert!(info.expiry_timer.is_none());
        assert!(!info.destroyed);
    }

    #[test]
    fn test_set_name_valid() {
        let mut info = GroupInfo::default();
        info.set_name("My Group").unwrap();
        assert_eq!(info.name.as_deref(), Some("My Group"));
    }

    #[test]
    fn test_set_name_too_long() {
        let mut info = GroupInfo::default();
        let long = "x".repeat(NAME_MAX_LENGTH + 1);
        assert!(info.set_name(&long).is_err());
    }

    #[test]
    fn test_set_description_valid() {
        let mut info = GroupInfo::default();
        info.set_description("A test group").unwrap();
        assert_eq!(info.description.as_deref(), Some("A test group"));
    }

    #[test]
    fn test_set_description_too_long() {
        let mut info = GroupInfo::default();
        let long = "x".repeat(DESCRIPTION_MAX_LENGTH + 1);
        assert!(info.set_description(&long).is_err());
    }

    #[test]
    fn test_destroy_group() {
        let mut info = GroupInfo::default();
        assert!(!info.is_destroyed());
        info.destroy_group();
        assert!(info.is_destroyed());
    }

    #[test]
    fn test_roundtrip() {
        let mut info = GroupInfo::default();
        info.set_name("Test Group").unwrap();
        info.set_description("A description").unwrap();
        info.set_created(1700000000);
        info.set_expiry_timer(Some(86400));
        info.set_delete_before(1699000000);

        let mut data = ConfigData::new();
        info.store_to_data(&mut data);

        let mut loaded = GroupInfo::default();
        loaded.load_from_data(&data);

        assert_eq!(loaded.name.as_deref(), Some("Test Group"));
        assert_eq!(loaded.description.as_deref(), Some("A description"));
        assert_eq!(loaded.created, Some(1700000000));
        assert_eq!(loaded.expiry_timer, Some(86400));
        assert_eq!(loaded.delete_before, Some(1699000000));
    }
}
