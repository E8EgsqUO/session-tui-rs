//! UserGroups config type.
//!
//! Port of `libsession-util/include/session/config/user_groups.hpp` and
//! `src/config/user_groups.cpp`.
//!
//! Config keys:
//!   g - dict of new-style groups (keyed by the 33-byte "03" + group pubkey)
//!       K - group seed (32 bytes, admin only)
//!       s - auth signature (100 bytes, non-admin)
//!       n - room name (from invitation)
//!       r - removed_status
//!       @, !, +, i, j - common fields
//!
//!   o - dict of communities (nested: base_url -> # + R -> room -> {n, @, !, +, i, j})
//!
//!   C - dict of legacy groups (keyed by 33-byte group pubkey)
//!       n - name (always set)
//!       k - encryption public key (32 bytes)
//!       K - encryption secret key (32 bytes)
//!       m - set of member session ids (33 bytes each)
//!       a - set of admin session ids (33 bytes each)
//!       E - disappearing messages duration (seconds)
//!       @, !, +, i, j - common fields

use std::collections::BTreeMap;

use crate::config::config_base::ConfigType;
use crate::config::config_base::field_helpers::*;
use crate::config::config_message::{ConfigData, ConfigValue, ScalarValue};
use crate::config::namespaces::Namespace;
use crate::config::notify::NotifyMode;

/// Maximum name length for groups.
pub const NAME_MAX_LENGTH: usize = 100;

/// Removal status constants.
pub const NOT_REMOVED: i32 = 0;
pub const KICKED_FROM_GROUP: i32 = 1;
pub const GROUP_DESTROYED: i32 = 2;

/// Base fields shared by all group types.
#[derive(Debug, Clone, Default)]
pub struct BaseGroupInfo {
    /// Conversation priority: -1=hidden, 0=unpinned, >0=pinned.
    pub priority: i32,
    /// Unix timestamp (seconds) when the group was joined.
    pub joined_at: i64,
    /// Notification mode.
    pub notifications: NotifyMode,
    /// Unix timestamp (seconds) until which notifications are muted.
    pub mute_until: i64,
    /// Display name.
    pub name: String,
    /// Whether this is a pending invite (not yet joined).
    pub invited: bool,
}

impl BaseGroupInfo {
    fn load_common(&mut self, dict: &ConfigData) {
        self.priority = get_int_or_zero(dict, b"+") as i32;
        self.joined_at = get_int_or_zero(dict, b"j");
        self.notifications = NotifyMode::from_raw(get_int_or_zero(dict, b"@") as i32);
        self.mute_until = get_int_or_zero(dict, b"!");
        self.name = get_string(dict, b"n").unwrap_or_default();
        self.invited = get_int_or_zero(dict, b"i") != 0;
    }

    fn store_common(&self, dict: &mut ConfigData) {
        set_nonzero_int(dict, b"+", self.priority as i64);
        set_positive_int(dict, b"j", self.joined_at);
        set_nonzero_int(dict, b"@", self.notifications as i32 as i64);
        set_positive_int(dict, b"!", self.mute_until);
        // name is stored differently per type (always vs. nonempty)
        set_flag(dict, b"i", self.invited);
    }
}

/// New-style group info.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    /// Group ID: "03" + hex pubkey (66 hex chars).
    pub id: String,
    /// Group seed (32 bytes); only known by admins.
    pub secretkey: Vec<u8>,
    /// Authentication data (100 bytes); used by non-admins.
    pub auth_data: Vec<u8>,
    /// Removal status: NOT_REMOVED, KICKED_FROM_GROUP, or GROUP_DESTROYED.
    pub removed_status: i32,
    /// Base group fields.
    pub base: BaseGroupInfo,
}

impl GroupInfo {
    /// Creates a new GroupInfo with the given ID.
    pub fn new(id: &str) -> Self {
        GroupInfo {
            id: id.to_string(),
            secretkey: Vec::new(),
            auth_data: Vec::new(),
            removed_status: NOT_REMOVED,
            base: BaseGroupInfo::default(),
        }
    }

    /// Returns true if we don't have room access (kicked with no keys).
    pub fn kicked(&self) -> bool {
        self.removed_status == KICKED_FROM_GROUP
            && self.secretkey.is_empty()
            && self.auth_data.is_empty()
    }

    /// Returns true if the group was destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.removed_status == GROUP_DESTROYED
    }

    /// Marks the group as kicked.
    pub fn mark_kicked(&mut self) {
        self.removed_status = KICKED_FROM_GROUP;
        self.secretkey.clear();
        self.auth_data.clear();
    }

    /// Marks the group as destroyed.
    pub fn mark_destroyed(&mut self) {
        self.removed_status = GROUP_DESTROYED;
        self.secretkey.clear();
        self.auth_data.clear();
    }

    fn load(&mut self, dict: &ConfigData) {
        self.base.load_common(dict);

        self.secretkey = get_bytes(dict, b"K").unwrap_or_default();
        self.auth_data = get_bytes(dict, b"s").unwrap_or_default();
        self.removed_status = get_int_or_zero(dict, b"r") as i32;
    }

    fn store(&self) -> ConfigData {
        let mut dict = ConfigData::new();
        self.base.store_common(&mut dict);

        // Name for new groups is set only before joining (from invitation)
        set_nonempty_str(&mut dict, b"n", &self.base.name);

        set_nonempty_bytes(&mut dict, b"K", &self.secretkey);
        // Only store auth_data if we don't have the seed
        if self.secretkey.is_empty() {
            set_nonempty_bytes(&mut dict, b"s", &self.auth_data);
        }
        set_nonzero_int(&mut dict, b"r", self.removed_status as i64);

        dict
    }
}

/// Legacy group info.
#[derive(Debug, Clone)]
pub struct LegacyGroupInfo {
    /// The legacy group "session id" (hex, 66 chars).
    pub session_id: String,
    /// Encryption public key (32 bytes or empty).
    pub enc_pubkey: Vec<u8>,
    /// Encryption secret key (32 bytes or empty).
    pub enc_seckey: Vec<u8>,
    /// Disappearing messages timer (seconds, 0 = disabled).
    pub disappearing_timer: u32,
    /// Members: session_id -> is_admin.
    pub members: BTreeMap<String, bool>,
    /// Base group fields.
    pub base: BaseGroupInfo,
}

impl LegacyGroupInfo {
    /// Creates a new LegacyGroupInfo with the given session ID.
    pub fn new(session_id: &str) -> Self {
        LegacyGroupInfo {
            session_id: session_id.to_string(),
            enc_pubkey: Vec::new(),
            enc_seckey: Vec::new(),
            disappearing_timer: 0,
            members: BTreeMap::new(),
            base: BaseGroupInfo::default(),
        }
    }

    /// Adds a member. Returns true if the member was inserted or changed.
    pub fn insert_member(&mut self, session_id: String, admin: bool) -> bool {
        let old = self.members.insert(session_id, admin);
        old.is_none() || old != Some(admin)
    }

    /// Removes a member. Returns true if the member was found and removed.
    pub fn erase_member(&mut self, session_id: &str) -> bool {
        self.members.remove(session_id).is_some()
    }

    /// Returns (admin_count, member_count).
    pub fn counts(&self) -> (usize, usize) {
        let admins = self.members.values().filter(|&&v| v).count();
        let regular = self.members.len() - admins;
        (admins, regular)
    }

    fn load(&mut self, dict: &ConfigData) {
        self.base.load_common(dict);

        self.enc_pubkey = get_bytes(dict, b"k").unwrap_or_default();
        self.enc_seckey = get_bytes(dict, b"K").unwrap_or_default();

        let e = get_int_or_zero(dict, b"E");
        self.disappearing_timer = if e > 0 { e as u32 } else { 0 };

        // Members "m" (set of 33-byte session ids)
        self.members.clear();
        if let Some(ConfigValue::Set(members)) = dict.get(b"m".as_ref()) {
            for item in members {
                if let ScalarValue::String(sid_bytes) = item {
                    let sid_hex = hex::encode(sid_bytes);
                    self.members.insert(sid_hex, false);
                }
            }
        }

        // Admins "a" (set of 33-byte session ids)
        if let Some(ConfigValue::Set(admins)) = dict.get(b"a".as_ref()) {
            for item in admins {
                if let ScalarValue::String(sid_bytes) = item {
                    let sid_hex = hex::encode(sid_bytes);
                    self.members.insert(sid_hex, true);
                }
            }
        }
    }

    fn store(&self) -> ConfigData {
        let mut dict = ConfigData::new();
        self.base.store_common(&mut dict);

        // Name is always set for legacy groups
        set_str_always(&mut dict, b"n", &self.base.name);

        set_nonempty_bytes(&mut dict, b"k", &self.enc_pubkey);
        set_nonempty_bytes(&mut dict, b"K", &self.enc_seckey);
        set_positive_int(&mut dict, b"E", self.disappearing_timer as i64);

        // Members (non-admin)
        let mut member_set: Vec<ScalarValue> = Vec::new();
        let mut admin_set: Vec<ScalarValue> = Vec::new();

        for (sid, is_admin) in &self.members {
            if let Ok(bytes) = hex::decode(sid) {
                if *is_admin {
                    admin_set.push(ScalarValue::String(bytes));
                } else {
                    member_set.push(ScalarValue::String(bytes));
                }
            }
        }

        member_set.sort();
        admin_set.sort();

        if !member_set.is_empty() {
            dict.insert(b"m".to_vec(), ConfigValue::Set(member_set));
        }
        if !admin_set.is_empty() {
            dict.insert(b"a".to_vec(), ConfigValue::Set(admin_set));
        }

        dict
    }
}

/// Community info within user groups.
#[derive(Debug, Clone)]
pub struct CommunityInfo {
    /// Canonical base URL.
    pub base_url: String,
    /// Room name.
    pub room: String,
    /// Server public key (32 bytes).
    pub pubkey: [u8; 32],
    /// Base group fields.
    pub base: BaseGroupInfo,
}

impl CommunityInfo {
    /// Creates a new CommunityInfo.
    pub fn new(base_url: &str, room: &str, pubkey: &[u8; 32]) -> Self {
        CommunityInfo {
            base_url: base_url.to_string(),
            room: room.to_string(),
            pubkey: *pubkey,
            base: BaseGroupInfo::default(),
        }
    }
}

/// The UserGroups config type.
#[derive(Debug, Clone, Default)]
pub struct UserGroups {
    /// New-style groups (keyed by hex group ID).
    groups: BTreeMap<String, GroupInfo>,
    /// Legacy groups (keyed by hex session ID).
    legacy_groups: BTreeMap<String, LegacyGroupInfo>,
    /// Communities.
    communities: Vec<CommunityInfo>,
}

impl UserGroups {
    // ── New groups ──

    /// Gets a group by ID.
    pub fn get_group(&self, id: &str) -> Option<&GroupInfo> {
        self.groups.get(id)
    }

    /// Gets a mutable group by ID.
    pub fn get_group_mut(&mut self, id: &str) -> Option<&mut GroupInfo> {
        self.groups.get_mut(id)
    }

    /// Sets (inserts or updates) a group.
    pub fn set_group(&mut self, group: GroupInfo) {
        self.groups.insert(group.id.clone(), group);
    }

    /// Erases a group. Returns true if found.
    pub fn erase_group(&mut self, id: &str) -> bool {
        self.groups.remove(id).is_some()
    }

    /// Iterates over all groups.
    pub fn iter_groups(&self) -> impl Iterator<Item = &GroupInfo> {
        self.groups.values()
    }

    // ── Legacy groups ──

    /// Gets a legacy group by session ID.
    pub fn get_legacy_group(&self, session_id: &str) -> Option<&LegacyGroupInfo> {
        self.legacy_groups.get(session_id)
    }

    /// Gets a mutable legacy group by session ID.
    pub fn get_legacy_group_mut(&mut self, session_id: &str) -> Option<&mut LegacyGroupInfo> {
        self.legacy_groups.get_mut(session_id)
    }

    /// Sets a legacy group.
    pub fn set_legacy_group(&mut self, group: LegacyGroupInfo) {
        self.legacy_groups.insert(group.session_id.clone(), group);
    }

    /// Erases a legacy group. Returns true if found.
    pub fn erase_legacy_group(&mut self, session_id: &str) -> bool {
        self.legacy_groups.remove(session_id).is_some()
    }

    /// Iterates over all legacy groups.
    pub fn iter_legacy_groups(&self) -> impl Iterator<Item = &LegacyGroupInfo> {
        self.legacy_groups.values()
    }

    // ── Communities ──

    /// Gets a community by base URL and room.
    pub fn get_community(&self, base_url: &str, room: &str) -> Option<&CommunityInfo> {
        let room_lower = room.to_ascii_lowercase();
        self.communities
            .iter()
            .find(|c| c.base_url == base_url && c.room.to_ascii_lowercase() == room_lower)
    }

    /// Sets a community.
    pub fn set_community(&mut self, comm: CommunityInfo) {
        let room_lower = comm.room.to_ascii_lowercase();
        if let Some(existing) = self
            .communities
            .iter_mut()
            .find(|c| c.base_url == comm.base_url && c.room.to_ascii_lowercase() == room_lower)
        {
            *existing = comm;
        } else {
            self.communities.push(comm);
        }
    }

    /// Erases a community. Returns true if found.
    pub fn erase_community(&mut self, base_url: &str, room: &str) -> bool {
        let room_lower = room.to_ascii_lowercase();
        let before = self.communities.len();
        self.communities
            .retain(|c| !(c.base_url == base_url && c.room.to_ascii_lowercase() == room_lower));
        self.communities.len() < before
    }

    /// Iterates over all communities.
    pub fn iter_communities(&self) -> impl Iterator<Item = &CommunityInfo> {
        self.communities.iter()
    }

    /// Total size across all group types.
    pub fn size(&self) -> usize {
        self.groups.len() + self.legacy_groups.len() + self.communities.len()
    }
}

impl ConfigType for UserGroups {
    fn namespace() -> Namespace {
        Namespace::UserGroups
    }

    fn encryption_domain() -> &'static str {
        "UserGroups"
    }

    fn accepts_protobuf() -> bool {
        true
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        self.groups.clear();
        self.legacy_groups.clear();
        self.communities.clear();

        // New groups "g"
        if let Some(ConfigValue::Dict(groups_dict)) = data.get(b"g".as_ref()) {
            for (key, value) in groups_dict {
                if let ConfigValue::Dict(group_dict) = value {
                    // Session stores the full 33-byte group ID as the key. Accept
                    // older/unprefixed 32-byte keys too, but do not duplicate "03".
                    let id = if key.len() == 33 && key[0] == 0x03 {
                        hex::encode(key)
                    } else {
                        format!("03{}", hex::encode(key))
                    };
                    let mut group = GroupInfo::new(&id);
                    group.load(group_dict);
                    self.groups.insert(id, group);
                }
            }
        }

        // Legacy groups "C"
        if let Some(ConfigValue::Dict(legacy_dict)) = data.get(b"C".as_ref()) {
            for (key, value) in legacy_dict {
                if let ConfigValue::Dict(group_dict) = value {
                    let session_id = hex::encode(key);
                    let mut group = LegacyGroupInfo::new(&session_id);
                    group.load(group_dict);
                    self.legacy_groups.insert(session_id, group);
                }
            }
        }

        // Communities "o"
        if let Some(ConfigValue::Dict(servers)) = data.get(b"o".as_ref()) {
            for (url_key, server_val) in servers {
                if let ConfigValue::Dict(server_dict) = server_val {
                    let base_url = String::from_utf8_lossy(url_key).to_string();

                    let pubkey = match server_dict.get(b"#".as_ref()) {
                        Some(ConfigValue::String(pk)) if pk.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(pk);
                            arr
                        }
                        _ => continue,
                    };

                    if let Some(ConfigValue::Dict(rooms)) = server_dict.get(b"R".as_ref()) {
                        for (room_key, room_val) in rooms {
                            if let ConfigValue::Dict(room_dict) = room_val {
                                let room = String::from_utf8_lossy(room_key).to_string();
                                let mut base = BaseGroupInfo::default();
                                base.load_common(room_dict);

                                // Room name "n" within the room dict is the display name
                                base.name =
                                    get_string(room_dict, b"n").unwrap_or_else(|| room.clone());

                                self.communities.push(CommunityInfo {
                                    base_url: base_url.clone(),
                                    room,
                                    pubkey,
                                    base,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        // New groups "g"
        if self.groups.is_empty() {
            data.remove(b"g".as_ref());
        } else {
            let mut groups_dict = ConfigData::new();
            for (id, group) in &self.groups {
                // Store the complete 33-byte group ID, including its 03 prefix.
                if id.len() == 66
                    && id.starts_with("03")
                    && let Ok(key_bytes) = hex::decode(id)
                    && key_bytes.len() == 33
                {
                    groups_dict.insert(key_bytes, ConfigValue::Dict(group.store()));
                }
            }
            data.insert(b"g".to_vec(), ConfigValue::Dict(groups_dict));
        }

        // Legacy groups "C"
        if self.legacy_groups.is_empty() {
            data.remove(b"C".as_ref());
        } else {
            let mut legacy_dict = ConfigData::new();
            for (session_id, group) in &self.legacy_groups {
                if let Ok(key_bytes) = hex::decode(session_id) {
                    legacy_dict.insert(key_bytes, ConfigValue::Dict(group.store()));
                }
            }
            data.insert(b"C".to_vec(), ConfigValue::Dict(legacy_dict));
        }

        // Communities "o"
        if self.communities.is_empty() {
            data.remove(b"o".as_ref());
        } else {
            let mut servers: ConfigData = ConfigData::new();
            for comm in &self.communities {
                let url_key = comm.base_url.as_bytes().to_vec();
                let server_dict = servers
                    .entry(url_key)
                    .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
                if let ConfigValue::Dict(sd) = server_dict {
                    sd.insert(b"#".to_vec(), ConfigValue::String(comm.pubkey.to_vec()));

                    let rooms = sd
                        .entry(b"R".to_vec())
                        .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
                    if let ConfigValue::Dict(rd) = rooms {
                        let mut room_dict = ConfigData::new();
                        comm.base.store_common(&mut room_dict);
                        // Always store the room display name
                        set_str_always(&mut room_dict, b"n", &comm.base.name);
                        rd.insert(comm.room.as_bytes().to_vec(), ConfigValue::Dict(room_dict));
                    }
                }
            }
            data.insert(b"o".to_vec(), ConfigValue::Dict(servers));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config_base::ConfigBase;

    #[test]
    fn test_default_empty() {
        let ug = UserGroups::default();
        assert_eq!(ug.size(), 0);
    }

    #[test]
    fn test_new_group_crud() {
        let mut ug = UserGroups::default();

        let mut g =
            GroupInfo::new("0300000000000000000000000000000000000000000000000000000000000000aa");
        g.base.name = "Test Group".into();
        g.secretkey = vec![0xAA; 32];
        ug.set_group(g);

        assert_eq!(ug.size(), 1);
        let found = ug
            .get_group("0300000000000000000000000000000000000000000000000000000000000000aa")
            .unwrap();
        assert_eq!(found.base.name, "Test Group");
    }

    #[test]
    fn test_legacy_group_members() {
        let mut lg = LegacyGroupInfo::new("05aabb");
        lg.insert_member("05member1".to_string(), false);
        lg.insert_member("05admin1".to_string(), true);

        let (admins, regular) = lg.counts();
        assert_eq!(admins, 1);
        assert_eq!(regular, 1);
    }

    #[test]
    fn test_community_crud() {
        let mut ug = UserGroups::default();
        let pk = [0xABu8; 32];
        let mut comm = CommunityInfo::new("https://example.com", "testroom", &pk);
        comm.base.name = "Test Room".into();
        ug.set_community(comm);

        assert_eq!(ug.size(), 1);
        let found = ug.get_community("https://example.com", "testroom").unwrap();
        assert_eq!(found.base.name, "Test Room");
    }

    #[test]
    fn test_roundtrip() {
        let mut ug = UserGroups::default();

        let mut g =
            GroupInfo::new("0300000000000000000000000000000000000000000000000000000000000000bb");
        g.base.name = "My Group".into();
        g.base.priority = 5;
        ug.set_group(g);

        let mut data = ConfigData::new();
        ug.store_to_data(&mut data);

        let mut loaded = UserGroups::default();
        loaded.load_from_data(&data);

        let found = loaded
            .get_group("0300000000000000000000000000000000000000000000000000000000000000bb")
            .unwrap();
        assert_eq!(found.base.name, "My Group");
        assert_eq!(found.base.priority, 5);
    }

    #[test]
    fn test_config_base() {
        let seed =
            hex_literal::hex!("0123456789abcdef0123456789abcdef00000000000000000000000000000000");
        let base: ConfigBase<UserGroups> = ConfigBase::new(&seed, None).unwrap();
        assert_eq!(base.get().size(), 0);
    }
}
