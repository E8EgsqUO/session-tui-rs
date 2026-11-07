//! Contacts config type.
//!
//! Port of `libsession-util/include/session/config/contacts.hpp` and
//! `src/config/contacts.cpp`.
//!
//! Config structure:
//!   c - dict of contacts keyed by session pubkey (binary, 33 bytes)
//!       n - name (always serialized, even if empty)
//!       N - nickname
//!       p - profile url
//!       q - profile key (32 bytes)
//!       a - approved (1 if true)
//!       A - approved_me (1 if true)
//!       b - blocked (1 if true)
//!       @ - notification mode
//!       ! - mute until timestamp (seconds)
//!       + - priority
//!       e - expiry type (1=after-send, 2=after-read)
//!       E - expiry timer (seconds)
//!       j - created timestamp (seconds)
//!       t - profile_updated timestamp (seconds)
//!       f - pro profile features bitset

use std::collections::BTreeMap;

use crate::config::config_base::field_helpers::*;
use crate::config::config_base::ConfigType;
use crate::config::config_message::{ConfigData, ConfigValue, ScalarValue};
use crate::config::expiring::ExpiryType;
use crate::config::namespaces::Namespace;
use crate::config::notify::NotifyMode;
use crate::config::profile_pic::ProfilePic;

/// Maximum name length in bytes.
pub const MAX_NAME_LENGTH: usize = 100;

/// Information about a single contact.
#[derive(Debug, Clone)]
pub struct ContactInfo {
    /// Session ID in hex (66 characters, starting with "05").
    pub session_id: String,
    /// Contact's display name.
    pub name: String,
    /// Contact's nickname (local override).
    pub nickname: String,
    /// Contact's profile picture.
    pub profile_pic: ProfilePic,
    /// Whether we have approved this contact (allowing them to send messages to us).
    pub approved: bool,
    /// Whether this contact has approved us (so we can send to them).
    pub approved_me: bool,
    /// Whether this contact is blocked.
    pub blocked: bool,
    /// Notification mode for this contact's messages.
    pub notifications: NotifyMode,
    /// Unix timestamp (seconds) until which notifications are muted.
    pub mute_until: i64,
    /// Conversation priority: -1=hidden, 0=unpinned, >0=pinned.
    pub priority: i32,
    /// Disappearing messages expiry type.
    pub expiry_type: ExpiryType,
    /// Disappearing messages timer in seconds.
    pub expiry_timer: u32,
    /// Unix timestamp (seconds) when this contact was created/added.
    pub created: i64,
    /// Unix timestamp (seconds) when this contact's profile was last updated.
    pub profile_updated: i64,
    /// Pro profile features bitset.
    pub profile_bitset: u64,
}

impl ContactInfo {
    /// Creates a new ContactInfo with the given session ID and all fields defaulted.
    pub fn new(session_id: &str) -> Self {
        ContactInfo {
            session_id: session_id.to_string(),
            name: String::new(),
            nickname: String::new(),
            profile_pic: ProfilePic::default(),
            approved: false,
            approved_me: false,
            blocked: false,
            notifications: NotifyMode::Default,
            mute_until: 0,
            priority: 0,
            expiry_type: ExpiryType::None,
            expiry_timer: 0,
            created: 0,
            profile_updated: 0,
            profile_bitset: 0,
        }
    }

    /// Sets the name, returning an error if it exceeds MAX_NAME_LENGTH.
    pub fn set_name(&mut self, name: &str) -> Result<(), String> {
        if name.len() > MAX_NAME_LENGTH {
            return Err("Invalid contact name: exceeds maximum length".into());
        }
        self.name = name.to_string();
        Ok(())
    }

    /// Sets the nickname, returning an error if it exceeds MAX_NAME_LENGTH.
    pub fn set_nickname(&mut self, nickname: &str) -> Result<(), String> {
        if nickname.len() > MAX_NAME_LENGTH {
            return Err("Invalid contact nickname: exceeds maximum length".into());
        }
        self.nickname = nickname.to_string();
        Ok(())
    }

    /// Loads contact fields from a config sub-dict.
    fn load_from_dict(&mut self, dict: &ConfigData) {
        self.name = get_string(dict, b"n").unwrap_or_default();
        self.nickname = get_string(dict, b"N").unwrap_or_default();

        self.profile_pic = ProfilePic::default();
        if let Some(url) = get_string(dict, b"p") {
            self.profile_pic.url = url;
        }
        if let Some(key) = get_bytes(dict, b"q")
            && key.len() == 32 {
                self.profile_pic.key = key;
            }

        self.approved = get_int_or_zero(dict, b"a") != 0;
        self.approved_me = get_int_or_zero(dict, b"A") != 0;
        self.blocked = get_int_or_zero(dict, b"b") != 0;
        self.notifications = NotifyMode::from_raw(get_int_or_zero(dict, b"@") as i32);
        self.mute_until = get_int_or_zero(dict, b"!");
        self.priority = get_int_or_zero(dict, b"+") as i32;
        self.expiry_type = ExpiryType::from_raw(get_int_or_zero(dict, b"e") as i8);
        self.expiry_timer = {
            let e = get_int_or_zero(dict, b"E");
            if e > 0 { e as u32 } else { 0 }
        };
        self.created = get_int_or_zero(dict, b"j");
        self.profile_updated = get_int_or_zero(dict, b"t");

        // Pro profile features bitset
        self.profile_bitset = match dict.get(b"f".as_ref()) {
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
    }

    /// Stores contact fields into a config sub-dict.
    fn store_to_dict(&self) -> ConfigData {
        let mut dict = ConfigData::new();

        // Name is always set (even if empty) to keep the dict alive
        set_str_always(&mut dict, b"n", &self.name);

        set_nonempty_str(&mut dict, b"N", &self.nickname);

        if !self.profile_pic.url.is_empty() && self.profile_pic.key.len() == 32 {
            set_nonempty_str(&mut dict, b"p", &self.profile_pic.url);
            set_nonempty_bytes(&mut dict, b"q", &self.profile_pic.key);
        }

        set_flag(&mut dict, b"a", self.approved);
        set_flag(&mut dict, b"A", self.approved_me);
        set_flag(&mut dict, b"b", self.blocked);
        set_nonzero_int(&mut dict, b"@", self.notifications as i32 as i64);
        set_positive_int(&mut dict, b"!", self.mute_until);
        set_nonzero_int(&mut dict, b"+", self.priority as i64);

        if self.expiry_type != ExpiryType::None {
            dict.insert(
                b"e".to_vec(),
                ConfigValue::Integer(self.expiry_type as i64),
            );
            set_positive_int(&mut dict, b"E", self.expiry_timer as i64);
        }

        set_positive_int(&mut dict, b"j", self.created);
        set_positive_int(&mut dict, b"t", self.profile_updated);

        if self.profile_bitset != 0 {
            let mut items = Vec::new();
            for bit in 0..64u64 {
                if self.profile_bitset & (1 << bit) != 0 {
                    items.push(ScalarValue::Integer(bit as i64));
                }
            }
            items.sort();
            dict.insert(b"f".to_vec(), ConfigValue::Set(items));
        }

        dict
    }
}

/// The Contacts config type, holding a list of contacts.
#[derive(Debug, Clone, Default)]
pub struct Contacts {
    contacts: BTreeMap<String, ContactInfo>,
}

impl Contacts {
    /// Gets a contact by session ID.
    pub fn get(&self, session_id: &str) -> Option<&ContactInfo> {
        self.contacts.get(session_id)
    }

    /// Gets a contact by session ID, or constructs a new default one if not found.
    pub fn get_or_construct(&self, session_id: &str) -> ContactInfo {
        self.contacts
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| ContactInfo::new(session_id))
    }

    /// Sets (inserts or updates) a contact.
    pub fn set(&mut self, contact: ContactInfo) {
        self.contacts
            .insert(contact.session_id.clone(), contact);
    }

    /// Removes a contact by session ID. Returns true if it existed.
    pub fn erase(&mut self, session_id: &str) -> bool {
        self.contacts.remove(session_id).is_some()
    }

    /// Returns the number of contacts.
    pub fn size(&self) -> usize {
        self.contacts.len()
    }

    /// Returns true if there are no contacts.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Iterates over all contacts in sorted order by session ID.
    pub fn iter(&self) -> impl Iterator<Item = &ContactInfo> {
        self.contacts.values()
    }

    /// Returns all contacts as a Vec.
    pub fn all(&self) -> Vec<&ContactInfo> {
        self.contacts.values().collect()
    }
}

impl ConfigType for Contacts {
    fn namespace() -> Namespace {
        Namespace::Contacts
    }

    fn encryption_domain() -> &'static str {
        "Contacts"
    }

    fn accepts_protobuf() -> bool {
        true
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        self.contacts.clear();

        if let Some(ConfigValue::Dict(contacts_dict)) = data.get(b"c".as_ref()) {
            for (key, value) in contacts_dict {
                if let ConfigValue::Dict(contact_data) = value {
                    // Key is the binary session pubkey (33 bytes) -- convert to hex
                    let session_id = hex::encode(key);
                    let mut contact = ContactInfo::new(&session_id);
                    contact.load_from_dict(contact_data);
                    self.contacts.insert(session_id, contact);
                }
            }
        }
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        if self.contacts.is_empty() {
            data.remove(b"c".as_ref());
            return;
        }

        let mut contacts_dict = ConfigData::new();
        for (session_id, contact) in &self.contacts {
            // Convert hex session ID back to binary key
            if let Ok(key_bytes) = hex::decode(session_id) {
                contacts_dict.insert(key_bytes, ConfigValue::Dict(contact.store_to_dict()));
            }
        }
        data.insert(b"c".to_vec(), ConfigValue::Dict(contacts_dict));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config_base::ConfigBase;

    #[test]
    fn test_contact_info_new() {
        let contact = ContactInfo::new("0500000000000000000000000000000000000000000000000000000000000000ff");
        assert!(!contact.approved);
        assert!(!contact.blocked);
        assert_eq!(contact.priority, 0);
    }

    #[test]
    fn test_contact_set_name() {
        let mut contact = ContactInfo::new("05abc");
        contact.set_name("Alice").unwrap();
        assert_eq!(contact.name, "Alice");
    }

    #[test]
    fn test_contact_name_too_long() {
        let mut contact = ContactInfo::new("05abc");
        let long_name = "x".repeat(MAX_NAME_LENGTH + 1);
        assert!(contact.set_name(&long_name).is_err());
    }

    #[test]
    fn test_contacts_crud() {
        let mut contacts = Contacts::default();
        assert!(contacts.is_empty());

        let mut c = ContactInfo::new("05aaaa");
        c.set_name("Alice").unwrap();
        c.approved = true;
        contacts.set(c);

        assert_eq!(contacts.size(), 1);
        assert_eq!(contacts.get("05aaaa").unwrap().name, "Alice");

        contacts.erase("05aaaa");
        assert!(contacts.is_empty());
    }

    #[test]
    fn test_contacts_roundtrip() {
        let mut contacts = Contacts::default();

        let mut c = ContactInfo::new("050000000000000000000000000000000000000000000000000000000000000000");
        c.name = "TestUser".to_string();
        c.approved = true;
        c.blocked = false;
        c.priority = 3;
        c.expiry_type = ExpiryType::AfterSend;
        c.expiry_timer = 3600;
        contacts.set(c);

        let mut data = ConfigData::new();
        contacts.store_to_data(&mut data);

        let mut loaded = Contacts::default();
        loaded.load_from_data(&data);

        let loaded_contact = loaded.get("050000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(loaded_contact.name, "TestUser");
        assert!(loaded_contact.approved);
        assert_eq!(loaded_contact.priority, 3);
        assert_eq!(loaded_contact.expiry_type, ExpiryType::AfterSend);
        assert_eq!(loaded_contact.expiry_timer, 3600);
    }

    #[test]
    fn test_contacts_config_base() {
        let seed = hex_literal::hex!(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000"
        );
        let base: ConfigBase<Contacts> = ConfigBase::new(&seed, None).unwrap();
        assert!(base.get().is_empty());
    }
}
