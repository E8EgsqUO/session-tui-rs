//! UserProfile config type.
//!
//! Port of `libsession-util/include/session/config/user_profile.hpp` and
//! `src/config/user_profile.cpp`.
//!
//! Config keys:
//!   n - user profile name
//!   p - profile pic URL
//!   q - profile pic decryption key (32 bytes)
//!   + - Note-to-Self priority (>0 pinned, -1 hidden, omitted=0=unpinned)
//!   e - Note-to-Self expiry timer (seconds, omitted if 0)
//!   M - blinded message requests (1=enabled, 0=disabled, omitted=default)
//!   f - pro profile features bitset (set of int64)
//!   t - profile updated timestamp (seconds)
//!   E - pro access expiry (milliseconds)
//!   P - re-uploaded profile pic URL
//!   Q - re-uploaded profile pic key
//!   T - re-uploaded profile pic timestamp (seconds)

use crate::config::config_base::field_helpers::*;
use crate::config::config_base::ConfigType;
use crate::config::config_message::{ConfigData, ConfigValue, ScalarValue};
use crate::config::namespaces::Namespace;
use crate::config::profile_pic::ProfilePic;

/// Maximum length for a user/contact display name, in bytes.
pub const MAX_NAME_LENGTH: usize = 100;

/// User profile configuration.
#[derive(Debug, Clone, Default)]
pub struct UserProfile {
    /// User's display name.
    pub name: Option<String>,
    /// User's profile picture (URL + key).
    pub profile_pic: ProfilePic,
    /// Re-uploaded profile picture (URL + key), takes precedence if its timestamp is newer.
    pub reupload_pic: ProfilePic,
    /// Note-to-Self priority: -1=hidden, 0=unpinned, >0=pinned.
    pub nts_priority: i32,
    /// Note-to-Self disappearing message timer, in seconds. 0 = disabled.
    pub nts_expiry: u32,
    /// Blinded message requests: None=default, Some(true)=enabled, Some(false)=disabled.
    pub blinded_msgreqs: Option<bool>,
    /// Pro profile features bitset.
    pub profile_bitset: u64,
    /// Profile updated timestamp (unix seconds).
    pub profile_updated: i64,
    /// Re-uploaded profile pic timestamp (unix seconds).
    pub reupload_updated: i64,
    /// Pro access expiry (unix milliseconds).
    pub pro_access_expiry_ms: Option<i64>,
}

impl UserProfile {
    /// Sets the user's display name. Returns an error if too long.
    pub fn set_name(&mut self, name: &str) -> Result<(), String> {
        if name.len() > MAX_NAME_LENGTH {
            return Err("Invalid profile name: exceeds maximum length".into());
        }
        self.name = if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        };
        Ok(())
    }

    /// Returns the effective profile pic (considering re-upload timestamps).
    pub fn get_profile_pic(&self) -> &ProfilePic {
        if self.reupload_updated > self.profile_updated && !self.reupload_pic.is_empty() {
            &self.reupload_pic
        } else {
            &self.profile_pic
        }
    }

    /// Returns the effective profile updated timestamp.
    pub fn get_profile_updated(&self) -> i64 {
        std::cmp::max(self.profile_updated, self.reupload_updated)
    }

    /// Returns the NTS expiry as an Option (None if disabled).
    pub fn get_nts_expiry(&self) -> Option<u32> {
        if self.nts_expiry > 0 {
            Some(self.nts_expiry)
        } else {
            None
        }
    }

    /// Sets the NTS expiry timer. 0 disables it.
    pub fn set_nts_expiry(&mut self, seconds: u32) {
        self.nts_expiry = seconds;
    }
}

impl ConfigType for UserProfile {
    fn namespace() -> Namespace {
        Namespace::UserProfile
    }

    fn encryption_domain() -> &'static str {
        "UserProfile"
    }

    fn accepts_protobuf() -> bool {
        true
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        self.name = get_string(data, b"n");

        // Profile pic: use p/q or P/Q depending on timestamps
        let t = get_int_or_zero(data, b"t");
        let t_reupload = get_int_or_zero(data, b"T");

        // Load primary profile pic
        self.profile_pic = ProfilePic::default();
        if let Some(url) = get_string(data, b"p") {
            self.profile_pic.url = url;
        }
        if let Some(key) = get_bytes(data, b"q")
            && key.len() == 32 {
                self.profile_pic.key = key;
            }

        // Load re-upload profile pic
        self.reupload_pic = ProfilePic::default();
        if let Some(url) = get_string(data, b"P") {
            self.reupload_pic.url = url;
        }
        if let Some(key) = get_bytes(data, b"Q")
            && key.len() == 32 {
                self.reupload_pic.key = key;
            }

        self.profile_updated = t;
        self.reupload_updated = t_reupload;

        self.nts_priority = get_int_or_zero(data, b"+") as i32;
        self.nts_expiry = {
            let e = get_int_or_zero(data, b"e");
            if e > 0 { e as u32 } else { 0 }
        };

        // Blinded msgreqs
        self.blinded_msgreqs = get_int(data, b"M").map(|v| v != 0);

        // Pro features bitset (stored as a set of int64 values)
        self.profile_bitset = match data.get(b"f".as_ref()) {
            Some(ConfigValue::Set(items)) => {
                let mut bits = 0u64;
                for item in items {
                    if let ScalarValue::Integer(v) = item
                        && *v >= 0 && *v < 64 {
                            bits |= 1 << *v;
                        }
                }
                bits
            }
            _ => 0,
        };

        // Pro access expiry
        self.pro_access_expiry_ms = get_int(data, b"E");
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        // Name
        if let Some(ref name) = self.name {
            set_nonempty_str(data, b"n", name);
        } else {
            data.remove(b"n".as_ref());
        }

        // Primary profile pic
        if !self.profile_pic.url.is_empty() && self.profile_pic.key.len() == 32 {
            set_nonempty_str(data, b"p", &self.profile_pic.url);
            set_nonempty_bytes(data, b"q", &self.profile_pic.key);
        } else {
            data.remove(b"p".as_ref());
            data.remove(b"q".as_ref());
        }

        // Re-upload profile pic
        if !self.reupload_pic.url.is_empty() && self.reupload_pic.key.len() == 32 {
            set_nonempty_str(data, b"P", &self.reupload_pic.url);
            set_nonempty_bytes(data, b"Q", &self.reupload_pic.key);
        } else {
            data.remove(b"P".as_ref());
            data.remove(b"Q".as_ref());
        }

        // Timestamps
        set_positive_int(data, b"t", self.profile_updated);
        set_positive_int(data, b"T", self.reupload_updated);

        // NTS priority
        set_nonzero_int(data, b"+", self.nts_priority as i64);

        // NTS expiry
        set_positive_int(data, b"e", self.nts_expiry as i64);

        // Blinded msgreqs
        match self.blinded_msgreqs {
            Some(v) => {
                data.insert(b"M".to_vec(), ConfigValue::Integer(v as i64));
            }
            None => {
                data.remove(b"M".as_ref());
            }
        }

        // Pro features bitset
        if self.profile_bitset != 0 {
            let mut items = Vec::new();
            for bit in 0..64u64 {
                if self.profile_bitset & (1 << bit) != 0 {
                    items.push(ScalarValue::Integer(bit as i64));
                }
            }
            items.sort();
            data.insert(b"f".to_vec(), ConfigValue::Set(items));
        } else {
            data.remove(b"f".as_ref());
        }

        // Pro access expiry
        if let Some(expiry) = self.pro_access_expiry_ms {
            data.insert(b"E".to_vec(), ConfigValue::Integer(expiry));
        } else {
            data.remove(b"E".as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config_base::ConfigBase;

    #[test]
    fn test_default_user_profile() {
        let profile = UserProfile::default();
        assert!(profile.name.is_none());
        assert!(profile.profile_pic.is_empty());
        assert_eq!(profile.nts_priority, 0);
        assert_eq!(profile.nts_expiry, 0);
        assert!(profile.blinded_msgreqs.is_none());
    }

    #[test]
    fn test_set_name_valid() {
        let mut profile = UserProfile::default();
        profile.set_name("Alice").unwrap();
        assert_eq!(profile.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_set_name_too_long() {
        let mut profile = UserProfile::default();
        let long_name = "x".repeat(MAX_NAME_LENGTH + 1);
        assert!(profile.set_name(&long_name).is_err());
    }

    #[test]
    fn test_set_name_empty_clears() {
        let mut profile = UserProfile::default();
        profile.set_name("Alice").unwrap();
        profile.set_name("").unwrap();
        assert!(profile.name.is_none());
    }

    #[test]
    fn test_roundtrip_serialization() {
        let mut profile = UserProfile::default();
        profile.set_name("Test User").unwrap();
        profile.nts_priority = 5;
        profile.nts_expiry = 3600;
        profile.blinded_msgreqs = Some(true);
        profile.profile_bitset = 0b101;
        profile.profile_updated = 1700000000;

        let mut data = ConfigData::new();
        profile.store_to_data(&mut data);

        let mut loaded = UserProfile::default();
        loaded.load_from_data(&data);

        assert_eq!(loaded.name.as_deref(), Some("Test User"));
        assert_eq!(loaded.nts_priority, 5);
        assert_eq!(loaded.nts_expiry, 3600);
        assert_eq!(loaded.blinded_msgreqs, Some(true));
        assert_eq!(loaded.profile_bitset, 0b101);
        assert_eq!(loaded.profile_updated, 1700000000);
    }

    #[test]
    fn test_profile_pic_timestamp_precedence() {
        let mut profile = UserProfile::default();
        profile.profile_pic = ProfilePic {
            url: "https://example.com/old.jpg".into(),
            key: vec![0xAA; 32],
        };
        profile.profile_updated = 1000;

        profile.reupload_pic = ProfilePic {
            url: "https://example.com/new.jpg".into(),
            key: vec![0xBB; 32],
        };
        profile.reupload_updated = 2000;

        // Re-upload is newer, so it should be returned
        let pic = profile.get_profile_pic();
        assert_eq!(pic.url, "https://example.com/new.jpg");
    }

    #[test]
    fn test_config_base_with_user_profile() {
        let seed = hex_literal::hex!(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000"
        );
        let base: ConfigBase<UserProfile> = ConfigBase::new(&seed, None).unwrap();
        assert!(base.get().name.is_none());
        assert!(!base.needs_push());
    }

    #[test]
    fn test_config_base_set_and_push() {
        let seed = hex_literal::hex!(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000"
        );
        let mut base: ConfigBase<UserProfile> = ConfigBase::new(&seed, None).unwrap();
        base.get_mut().set_name("Test").unwrap();
        assert!(base.needs_push());

        let push_data = base.push();
        assert_eq!(push_data.seqno, base.seqno());
        assert!(!push_data.messages.is_empty());
    }
}
