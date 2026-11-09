//! ConvoInfoVolatile config type.
//!
//! Port of `libsession-util/include/session/config/convo_info_volatile.hpp` and
//! `src/config/convo_info_volatile.cpp`.
//!
//! High-frequency config for volatile conversation properties (last-read timestamps,
//! unread flags). Not for permanent data.
//!
//! Config keys:
//!   1 - dict of one-to-one conversations (keyed by hex session ID)
//!       r - last_read timestamp (ms)
//!       u - unread flag
//!   o - community conversations (nested: base_url -> # + R -> room -> {r, u})
//!   g - group conversations (keyed by hex group ID starting with "03")
//!       r - last_read timestamp (ms)
//!       u - unread flag
//!   C - legacy group conversations (keyed by hex group ID)
//!       r - last_read timestamp (ms)
//!       u - unread flag
//!   b - blinded one-to-one conversations (keyed by blinded session ID)
//!       r - last_read timestamp (ms)
//!       u - unread flag
//!       y - legacy blinding flag

use std::collections::BTreeMap;

use crate::config::config_base::ConfigType;
use crate::config::config_base::field_helpers::*;
use crate::config::config_message::{ConfigData, ConfigValue};
use crate::config::namespaces::Namespace;

/// Base conversation info shared by all conversation types.
#[derive(Debug, Clone, Default)]
pub struct ConvoBase {
    /// Timestamp (unix milliseconds) of the last-read message.
    pub last_read: i64,
    /// Whether this conversation is marked as unread.
    pub unread: bool,
}

/// One-to-one conversation volatile info.
#[derive(Debug, Clone)]
pub struct ConvoOneToOne {
    /// Session ID (hex, 66 chars starting with "05").
    pub session_id: String,
    /// Base conversation info.
    pub base: ConvoBase,
}

/// Community conversation volatile info.
#[derive(Debug, Clone)]
pub struct ConvoCommunity {
    /// Canonical community base URL.
    pub base_url: String,
    /// Room name (canonical, lower-cased).
    pub room: String,
    /// Server public key (32 bytes).
    pub pubkey: [u8; 32],
    /// Base conversation info.
    pub base: ConvoBase,
}

/// New-style group conversation volatile info.
#[derive(Debug, Clone)]
pub struct ConvoGroup {
    /// Group ID (hex, 66 chars starting with "03").
    pub id: String,
    /// Base conversation info.
    pub base: ConvoBase,
}

/// Legacy group conversation volatile info.
#[derive(Debug, Clone)]
pub struct ConvoLegacyGroup {
    /// Group ID (hex, looks like a session ID).
    pub id: String,
    /// Base conversation info.
    pub base: ConvoBase,
}

/// Blinded one-to-one conversation volatile info.
#[derive(Debug, Clone)]
pub struct ConvoBlindedOneToOne {
    /// Blinded session ID (hex).
    pub blinded_session_id: String,
    /// Whether this uses legacy blinding.
    pub legacy_blinding: bool,
    /// Base conversation info.
    pub base: ConvoBase,
}

/// All conversation types.
#[derive(Debug, Clone)]
pub enum ConvoInfo {
    OneToOne(ConvoOneToOne),
    Community(ConvoCommunity),
    Group(ConvoGroup),
    LegacyGroup(ConvoLegacyGroup),
    BlindedOneToOne(ConvoBlindedOneToOne),
}

/// The ConvoInfoVolatile config type.
#[derive(Debug, Clone, Default)]
pub struct ConvoInfoVolatile {
    one_to_one: BTreeMap<String, ConvoOneToOne>,
    communities: Vec<ConvoCommunity>,
    groups: BTreeMap<String, ConvoGroup>,
    legacy_groups: BTreeMap<String, ConvoLegacyGroup>,
    blinded: BTreeMap<String, ConvoBlindedOneToOne>,
}

impl ConvoInfoVolatile {
    // ── One-to-one ──

    /// Gets one-to-one conversation info by session ID.
    pub fn get_1to1(&self, session_id: &str) -> Option<&ConvoOneToOne> {
        self.one_to_one.get(session_id)
    }

    /// Sets one-to-one conversation info.
    pub fn set_1to1(&mut self, convo: ConvoOneToOne) {
        self.one_to_one.insert(convo.session_id.clone(), convo);
    }

    /// Erases one-to-one conversation info.
    pub fn erase_1to1(&mut self, session_id: &str) -> bool {
        self.one_to_one.remove(session_id).is_some()
    }

    /// Iterates over all one-to-one conversations.
    pub fn iter_1to1(&self) -> impl Iterator<Item = &ConvoOneToOne> {
        self.one_to_one.values()
    }

    // ── Community ──

    /// Gets community conversation info by base_url and room.
    pub fn get_community(&self, base_url: &str, room: &str) -> Option<&ConvoCommunity> {
        let room_lower = room.to_ascii_lowercase();
        self.communities
            .iter()
            .find(|c| c.base_url == base_url && c.room == room_lower)
    }

    /// Sets community conversation info.
    pub fn set_community(&mut self, convo: ConvoCommunity) {
        if let Some(existing) = self
            .communities
            .iter_mut()
            .find(|c| c.base_url == convo.base_url && c.room == convo.room)
        {
            *existing = convo;
        } else {
            self.communities.push(convo);
        }
    }

    /// Erases community conversation info.
    pub fn erase_community(&mut self, base_url: &str, room: &str) -> bool {
        let room_lower = room.to_ascii_lowercase();
        let before = self.communities.len();
        self.communities
            .retain(|c| !(c.base_url == base_url && c.room == room_lower));
        self.communities.len() < before
    }

    // ── Group ──

    /// Gets group conversation info by group ID.
    pub fn get_group(&self, group_id: &str) -> Option<&ConvoGroup> {
        self.groups.get(group_id)
    }

    /// Sets group conversation info.
    pub fn set_group(&mut self, convo: ConvoGroup) {
        self.groups.insert(convo.id.clone(), convo);
    }

    /// Erases group conversation info.
    pub fn erase_group(&mut self, group_id: &str) -> bool {
        self.groups.remove(group_id).is_some()
    }

    // ── Legacy group ──

    /// Gets legacy group conversation info by group ID.
    pub fn get_legacy_group(&self, group_id: &str) -> Option<&ConvoLegacyGroup> {
        self.legacy_groups.get(group_id)
    }

    /// Sets legacy group conversation info.
    pub fn set_legacy_group(&mut self, convo: ConvoLegacyGroup) {
        self.legacy_groups.insert(convo.id.clone(), convo);
    }

    /// Erases legacy group conversation info.
    pub fn erase_legacy_group(&mut self, group_id: &str) -> bool {
        self.legacy_groups.remove(group_id).is_some()
    }

    // ── Blinded ──

    /// Gets blinded one-to-one info by blinded session ID.
    pub fn get_blinded(&self, blinded_id: &str) -> Option<&ConvoBlindedOneToOne> {
        self.blinded.get(blinded_id)
    }

    /// Sets blinded one-to-one info.
    pub fn set_blinded(&mut self, convo: ConvoBlindedOneToOne) {
        self.blinded.insert(convo.blinded_session_id.clone(), convo);
    }

    /// Erases blinded one-to-one info.
    pub fn erase_blinded(&mut self, blinded_id: &str) -> bool {
        self.blinded.remove(blinded_id).is_some()
    }

    /// Returns total conversation count across all types.
    pub fn size(&self) -> usize {
        self.one_to_one.len()
            + self.communities.len()
            + self.groups.len()
            + self.legacy_groups.len()
            + self.blinded.len()
    }
}

/// Helpers for loading/storing ConvoBase from/to a config dict.
fn load_convo_base(dict: &ConfigData) -> ConvoBase {
    ConvoBase {
        last_read: get_int_or_zero(dict, b"r"),
        unread: get_int_or_zero(dict, b"u") != 0,
    }
}

fn store_convo_base(dict: &mut ConfigData, base: &ConvoBase) {
    // last_read is always stored (even if 0)
    dict.insert(b"r".to_vec(), ConfigValue::Integer(base.last_read));
    set_flag(dict, b"u", base.unread);
}

impl ConfigType for ConvoInfoVolatile {
    fn namespace() -> Namespace {
        Namespace::ConvoInfoVolatile
    }

    fn encryption_domain() -> &'static str {
        "ConvoInfoVolatile"
    }

    fn accepts_protobuf() -> bool {
        true
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        self.one_to_one.clear();
        self.communities.clear();
        self.groups.clear();
        self.legacy_groups.clear();
        self.blinded.clear();

        // One-to-one conversations "1"
        if let Some(ConfigValue::Dict(dict)) = data.get(b"1".as_ref()) {
            for (key, value) in dict {
                if let ConfigValue::Dict(convo_dict) = value {
                    let session_id = hex::encode(key);
                    self.one_to_one.insert(
                        session_id.clone(),
                        ConvoOneToOne {
                            session_id,
                            base: load_convo_base(convo_dict),
                        },
                    );
                }
            }
        }

        // Community conversations "o" (nested: base_url -> {#, R -> {room -> {r, u}}})
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
                                self.communities.push(ConvoCommunity {
                                    base_url: base_url.clone(),
                                    room,
                                    pubkey,
                                    base: load_convo_base(room_dict),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Group conversations "g"
        if let Some(ConfigValue::Dict(dict)) = data.get(b"g".as_ref()) {
            for (key, value) in dict {
                if let ConfigValue::Dict(convo_dict) = value {
                    // Key is binary pubkey (without 03 prefix)
                    let id = format!("03{}", hex::encode(key));
                    self.groups.insert(
                        id.clone(),
                        ConvoGroup {
                            id,
                            base: load_convo_base(convo_dict),
                        },
                    );
                }
            }
        }

        // Legacy group conversations "C"
        if let Some(ConfigValue::Dict(dict)) = data.get(b"C".as_ref()) {
            for (key, value) in dict {
                if let ConfigValue::Dict(convo_dict) = value {
                    let id = hex::encode(key);
                    self.legacy_groups.insert(
                        id.clone(),
                        ConvoLegacyGroup {
                            id,
                            base: load_convo_base(convo_dict),
                        },
                    );
                }
            }
        }

        // Blinded one-to-one conversations "b"
        if let Some(ConfigValue::Dict(dict)) = data.get(b"b".as_ref()) {
            for (key, value) in dict {
                if let ConfigValue::Dict(convo_dict) = value {
                    let blinded_id = hex::encode(key);
                    let legacy_blinding = get_int_or_zero(convo_dict, b"y") != 0;
                    self.blinded.insert(
                        blinded_id.clone(),
                        ConvoBlindedOneToOne {
                            blinded_session_id: blinded_id,
                            legacy_blinding,
                            base: load_convo_base(convo_dict),
                        },
                    );
                }
            }
        }
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        // One-to-one "1"
        if self.one_to_one.is_empty() {
            data.remove(b"1".as_ref());
        } else {
            let mut dict = ConfigData::new();
            for (session_id, convo) in &self.one_to_one {
                if let Ok(key_bytes) = hex::decode(session_id) {
                    let mut convo_dict = ConfigData::new();
                    store_convo_base(&mut convo_dict, &convo.base);
                    dict.insert(key_bytes, ConfigValue::Dict(convo_dict));
                }
            }
            data.insert(b"1".to_vec(), ConfigValue::Dict(dict));
        }

        // Community "o"
        if self.communities.is_empty() {
            data.remove(b"o".as_ref());
        } else {
            let mut servers: ConfigData = ConfigData::new();
            for convo in &self.communities {
                let url_key = convo.base_url.as_bytes().to_vec();
                let server_dict = servers
                    .entry(url_key)
                    .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
                if let ConfigValue::Dict(sd) = server_dict {
                    // Set pubkey
                    sd.insert(b"#".to_vec(), ConfigValue::String(convo.pubkey.to_vec()));

                    // Get or create rooms dict
                    let rooms = sd
                        .entry(b"R".to_vec())
                        .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
                    if let ConfigValue::Dict(rd) = rooms {
                        let mut room_dict = ConfigData::new();
                        store_convo_base(&mut room_dict, &convo.base);
                        rd.insert(convo.room.as_bytes().to_vec(), ConfigValue::Dict(room_dict));
                    }
                }
            }
            data.insert(b"o".to_vec(), ConfigValue::Dict(servers));
        }

        // Group "g"
        if self.groups.is_empty() {
            data.remove(b"g".as_ref());
        } else {
            let mut dict = ConfigData::new();
            for (id, convo) in &self.groups {
                // Strip "03" prefix for key
                if id.len() == 66
                    && id.starts_with("03")
                    && let Ok(key_bytes) = hex::decode(&id[2..])
                {
                    let mut convo_dict = ConfigData::new();
                    store_convo_base(&mut convo_dict, &convo.base);
                    dict.insert(key_bytes, ConfigValue::Dict(convo_dict));
                }
            }
            data.insert(b"g".to_vec(), ConfigValue::Dict(dict));
        }

        // Legacy group "C"
        if self.legacy_groups.is_empty() {
            data.remove(b"C".as_ref());
        } else {
            let mut dict = ConfigData::new();
            for (id, convo) in &self.legacy_groups {
                if let Ok(key_bytes) = hex::decode(id) {
                    let mut convo_dict = ConfigData::new();
                    store_convo_base(&mut convo_dict, &convo.base);
                    dict.insert(key_bytes, ConfigValue::Dict(convo_dict));
                }
            }
            data.insert(b"C".to_vec(), ConfigValue::Dict(dict));
        }

        // Blinded "b"
        if self.blinded.is_empty() {
            data.remove(b"b".as_ref());
        } else {
            let mut dict = ConfigData::new();
            for (blinded_id, convo) in &self.blinded {
                if let Ok(key_bytes) = hex::decode(blinded_id) {
                    let mut convo_dict = ConfigData::new();
                    store_convo_base(&mut convo_dict, &convo.base);
                    set_flag(&mut convo_dict, b"y", convo.legacy_blinding);
                    dict.insert(key_bytes, ConfigValue::Dict(convo_dict));
                }
            }
            data.insert(b"b".to_vec(), ConfigValue::Dict(dict));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config_base::ConfigBase;

    #[test]
    fn test_default_empty() {
        let civ = ConvoInfoVolatile::default();
        assert_eq!(civ.size(), 0);
    }

    #[test]
    fn test_1to1_crud() {
        let mut civ = ConvoInfoVolatile::default();

        civ.set_1to1(ConvoOneToOne {
            session_id: "05abcdef".to_string(),
            base: ConvoBase {
                last_read: 1700000000000,
                unread: false,
            },
        });
        assert_eq!(civ.size(), 1);
        assert_eq!(
            civ.get_1to1("05abcdef").unwrap().base.last_read,
            1700000000000
        );

        civ.erase_1to1("05abcdef");
        assert_eq!(civ.size(), 0);
    }

    #[test]
    fn test_group_crud() {
        let mut civ = ConvoInfoVolatile::default();

        civ.set_group(ConvoGroup {
            id: "03aabbccdd".to_string(),
            base: ConvoBase {
                last_read: 5000,
                unread: true,
            },
        });
        assert_eq!(civ.get_group("03aabbccdd").unwrap().base.unread, true);
    }

    #[test]
    fn test_roundtrip() {
        let mut civ = ConvoInfoVolatile::default();

        civ.set_1to1(ConvoOneToOne {
            session_id: "05aabb".to_string(),
            base: ConvoBase {
                last_read: 12345,
                unread: true,
            },
        });

        let mut data = ConfigData::new();
        civ.store_to_data(&mut data);

        let mut loaded = ConvoInfoVolatile::default();
        loaded.load_from_data(&data);

        let c = loaded.get_1to1("05aabb").unwrap();
        assert_eq!(c.base.last_read, 12345);
        assert!(c.base.unread);
    }

    #[test]
    fn test_config_base() {
        let seed =
            hex_literal::hex!("0123456789abcdef0123456789abcdef00000000000000000000000000000000");
        let base: ConfigBase<ConvoInfoVolatile> = ConfigBase::new(&seed, None).unwrap();
        assert_eq!(base.get().size(), 0);
    }
}
