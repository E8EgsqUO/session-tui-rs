//! Account data shared between this account's devices through the user
//! config namespaces: profile (2), contacts (3), conversation read state
//! (4) and groups (5).
//!
//! Local changes are applied by editing only the specific keys involved in
//! the raw config data, so fields that this client does not model (written
//! by newer Session clients) are carried over untouched.

use libsession::config::{
    config_base::ConfigBase,
    config_message::{ConfigData, ConfigValue},
    contacts::Contacts,
    convo_info_volatile::ConvoInfoVolatile,
    user_groups::UserGroups,
    user_profile::UserProfile,
};
use serde::{Deserialize, Serialize};

/// A local change waiting to be written to the account's config.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AccountChange {
    ProfileName(String),
    /// We talk to this person: mark them approved (as Session does when you
    /// message someone) and record their display name.
    ApproveContact {
        id: String,
        name: Option<String>,
    },
    SetBlocked {
        id: String,
        blocked: bool,
    },
    /// Chat deleted: hide it on all devices (priority -1, as Session does).
    HideContact {
        id: String,
    },
    /// Contact deleted from the account.
    RemoveContact {
        id: String,
    },
    /// Disappearing setting for a 1:1 chat: (`Content` kind 1 = after read,
    /// 2 = after send, seconds) or `None` for off.
    ContactExpiry {
        id: String,
        expiry: Option<(i32, u32)>,
    },
    /// Everything up to this timestamp (ms) was read on this device.
    ReadUpTo {
        conversation: String,
        timestamp_ms: i64,
    },
    /// A group joined from an invite.
    JoinGroup {
        id: String,
        name: String,
        auth_data: Vec<u8>,
    },
    /// Remove a group from the account (deleted or left on this device).
    LeaveGroup {
        id: String,
    },
}

impl AccountChange {
    /// Add `change` to `pending`, replacing an older change it supersedes.
    pub fn queue(pending: &mut Vec<AccountChange>, change: AccountChange) {
        use AccountChange::*;
        pending.retain(|old| match (old, &change) {
            (ProfileName(_), ProfileName(_)) => false,
            (SetBlocked { id: a, .. }, SetBlocked { id: b, .. })
            | (ContactExpiry { id: a, .. }, ContactExpiry { id: b, .. })
            | (JoinGroup { id: a, .. }, JoinGroup { id: b, .. }) => a != b,
            (JoinGroup { id: a, .. } | LeaveGroup { id: a }, LeaveGroup { id: b })
            | (LeaveGroup { id: a }, JoinGroup { id: b, .. }) => a != b,
            (ApproveContact { id: a, .. }, ApproveContact { id: b, .. })
            | (HideContact { id: a }, HideContact { id: b })
            | (HideContact { id: a }, ApproveContact { id: b, .. })
            | (ApproveContact { id: a, .. }, HideContact { id: b }) => a != b,
            // Removing a contact makes earlier changes to it pointless.
            (
                ApproveContact { id: a, .. }
                | HideContact { id: a }
                | SetBlocked { id: a, .. }
                | ContactExpiry { id: a, .. }
                | RemoveContact { id: a },
                RemoveContact { id: b },
            ) => a != b,
            (
                ReadUpTo {
                    conversation: a,
                    timestamp_ms: old_ts,
                },
                ReadUpTo {
                    conversation: b,
                    timestamp_ms: new_ts,
                },
            ) => a != b || old_ts > new_ts,
            _ => true,
        });
        let superseded = pending.iter().any(|old| matches!(
            (old, &change),
            (ReadUpTo { conversation: a, timestamp_ms: old_ts }, ReadUpTo { conversation: b, timestamp_ms: new_ts })
                if a == b && old_ts > new_ts
        ));
        if !superseded {
            pending.push(change);
        }
    }
}

/// Account state read back from the merged configs.
#[derive(Default, Debug)]
pub struct AccountState {
    pub profile_name: Option<String>,
    pub contacts: Vec<ContactState>,
    /// (conversation id, last read timestamp ms)
    pub last_read: Vec<(String, i64)>,
}

#[derive(Debug, Clone)]
pub struct ContactState {
    pub id: String,
    /// Nickname if set, else the contact's own display name.
    pub name: Option<String>,
    pub approved: bool,
    /// The chat was deleted (priority -1); the contact stays.
    pub hidden: bool,
    pub blocked: bool,
    /// Same encoding as [`AccountChange::ContactExpiry`].
    pub expiry: Option<(i32, u32)>,
}

pub struct AccountConfigs {
    pub profile: ConfigBase<UserProfile>,
    pub contacts: ConfigBase<Contacts>,
    pub convos: ConfigBase<ConvoInfoVolatile>,
    pub groups: ConfigBase<UserGroups>,
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn dict<'a>(data: &'a mut ConfigData, key: &[u8]) -> &'a mut ConfigData {
    let entry = data
        .entry(key.to_vec())
        .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
    if !matches!(entry, ConfigValue::Dict(_)) {
        *entry = ConfigValue::Dict(ConfigData::new());
    }
    match entry {
        ConfigValue::Dict(d) => d,
        _ => unreachable!(),
    }
}

fn get_int(data: &ConfigData, key: &[u8]) -> i64 {
    match data.get(key) {
        Some(ConfigValue::Integer(v)) => *v,
        _ => 0,
    }
}

fn get_str(data: &ConfigData, key: &[u8]) -> Option<String> {
    match data.get(key) {
        Some(ConfigValue::String(v)) => String::from_utf8(v.clone()).ok(),
        _ => None,
    }
}

fn set_int(data: &mut ConfigData, key: &[u8], value: i64) {
    if value == 0 {
        data.remove(key);
    } else {
        data.insert(key.to_vec(), ConfigValue::Integer(value));
    }
}

fn set_str(data: &mut ConfigData, key: &[u8], value: &str) {
    if value.is_empty() {
        data.remove(key);
    } else {
        data.insert(key.to_vec(), ConfigValue::String(value.as_bytes().to_vec()));
    }
}

/// 33-byte binary key (with its 05/03 prefix) of a hex Session/group ID.
fn id_key(id: &str) -> Option<Vec<u8>> {
    hex::decode(id).ok().filter(|key| key.len() == 33)
}

impl AccountConfigs {
    pub fn new(ed_secret: &[u8], dumps: &[Option<Vec<u8>>; 4]) -> Result<Self, String> {
        Ok(Self {
            profile: ConfigBase::new(ed_secret, dumps[0].as_deref())?,
            contacts: ConfigBase::new(ed_secret, dumps[1].as_deref())?,
            convos: ConfigBase::new(ed_secret, dumps[2].as_deref())?,
            groups: ConfigBase::new(ed_secret, dumps[3].as_deref())?,
        })
    }

    pub fn dumps(&mut self) -> [Vec<u8>; 4] {
        [
            self.profile.dump(),
            self.contacts.dump(),
            self.convos.dump(),
            self.groups.dump(),
        ]
    }

    /// Apply one local change; returns false when nothing needed changing
    /// (so no new config version is created for it).
    pub fn apply(&mut self, change: &AccountChange) -> bool {
        match change {
            AccountChange::ProfileName(name) => {
                if get_str(self.profile.data(), b"n").as_deref() == Some(name.as_str()) {
                    return false;
                }
                self.profile.edit_data(|data| {
                    set_str(data, b"n", name);
                    // libsession: bump whichever of t/T is current.
                    let key: &[u8] = if get_int(data, b"t") >= get_int(data, b"T") {
                        b"t"
                    } else {
                        b"T"
                    };
                    set_int(data, key, now_seconds());
                });
                true
            }
            AccountChange::ApproveContact { id, name } => {
                let Some(key) = id_key(id) else { return false };
                let current = match self.contacts.data().get(b"c".as_slice()) {
                    Some(ConfigValue::Dict(c)) => match c.get(&key) {
                        Some(ConfigValue::Dict(entry)) => Some(entry.clone()),
                        _ => None,
                    },
                    _ => None,
                };
                let approved = current.as_ref().is_some_and(|e| get_int(e, b"a") != 0);
                let has_name = current.as_ref().and_then(|e| get_str(e, b"n")).is_some();
                let hidden = current.as_ref().is_some_and(|e| get_int(e, b"+") < 0);
                if approved && !hidden && (has_name || name.is_none()) {
                    return false;
                }
                self.contacts.edit_data(|data| {
                    let entry = dict(dict(data, b"c"), &key);
                    entry.insert(b"a".to_vec(), ConfigValue::Integer(1));
                    // Talking to a hidden (deleted) chat shows it again.
                    if get_int(entry, b"+") < 0 {
                        entry.remove(b"+".as_slice());
                    }
                    if get_int(entry, b"j") == 0 {
                        entry.insert(b"j".to_vec(), ConfigValue::Integer(now_seconds()));
                    }
                    if let Some(name) = name
                        && get_str(entry, b"n").is_none()
                    {
                        set_str(entry, b"n", name);
                    }
                    // libsession always writes "n", even when empty.
                    entry
                        .entry(b"n".to_vec())
                        .or_insert_with(|| ConfigValue::String(Vec::new()));
                });
                true
            }
            AccountChange::SetBlocked { id, blocked } => {
                let Some(key) = id_key(id) else { return false };
                self.contacts.edit_data(|data| {
                    let entry = dict(dict(data, b"c"), &key);
                    set_int(entry, b"b", i64::from(*blocked));
                    entry
                        .entry(b"n".to_vec())
                        .or_insert_with(|| ConfigValue::String(Vec::new()));
                });
                true
            }
            AccountChange::HideContact { id } => {
                let Some(key) = id_key(id) else { return false };
                let exists = matches!(
                    self.contacts.data().get(b"c".as_slice()),
                    Some(ConfigValue::Dict(c)) if matches!(
                        c.get(&key), Some(ConfigValue::Dict(e)) if get_int(e, b"+") >= 0
                    )
                );
                if !exists {
                    return false;
                }
                self.contacts.edit_data(|data| {
                    set_int(dict(dict(data, b"c"), &key), b"+", -1);
                });
                true
            }
            AccountChange::RemoveContact { id } => {
                let Some(key) = id_key(id) else { return false };
                let exists = matches!(
                    self.contacts.data().get(b"c".as_slice()),
                    Some(ConfigValue::Dict(c)) if c.contains_key(&key)
                );
                if !exists {
                    return false;
                }
                self.contacts.edit_data(|data| {
                    dict(data, b"c").remove(&key);
                });
                true
            }
            AccountChange::LeaveGroup { id } => {
                let Some(key) = id_key(id) else { return false };
                let exists = matches!(
                    self.groups.data().get(b"g".as_slice()),
                    Some(ConfigValue::Dict(g)) if g.contains_key(&key)
                );
                if !exists {
                    return false;
                }
                self.groups.edit_data(|data| {
                    dict(data, b"g").remove(&key);
                });
                true
            }
            AccountChange::ContactExpiry { id, expiry } => {
                let Some(key) = id_key(id) else { return false };
                self.contacts.edit_data(|data| {
                    let entry = dict(dict(data, b"c"), &key);
                    match expiry {
                        // Config encoding: 1 = after send, 2 = after read
                        // (the reverse of Content.expirationType).
                        Some((kind, seconds)) => {
                            set_int(entry, b"e", if *kind == 1 { 2 } else { 1 });
                            set_int(entry, b"E", i64::from(*seconds));
                        }
                        None => {
                            entry.remove(b"e".as_slice());
                            entry.remove(b"E".as_slice());
                        }
                    }
                    entry
                        .entry(b"n".to_vec())
                        .or_insert_with(|| ConfigValue::String(Vec::new()));
                });
                true
            }
            AccountChange::ReadUpTo {
                conversation,
                timestamp_ms,
            } => {
                let Some(key) = id_key(conversation) else {
                    return false;
                };
                let section: &[u8] = if conversation.starts_with("03") {
                    b"g"
                } else {
                    b"1"
                };
                let current = match self.convos.data().get(section) {
                    Some(ConfigValue::Dict(d)) => match d.get(&key) {
                        Some(ConfigValue::Dict(entry)) => get_int(entry, b"r"),
                        _ => 0,
                    },
                    _ => 0,
                };
                if current >= *timestamp_ms {
                    return false;
                }
                self.convos.edit_data(|data| {
                    let entry = dict(dict(data, section), &key);
                    entry.insert(b"r".to_vec(), ConfigValue::Integer(*timestamp_ms));
                    entry.remove(b"u".as_slice());
                });
                true
            }
            AccountChange::JoinGroup {
                id,
                name,
                auth_data,
            } => {
                let Some(key) = id_key(id) else { return false };
                let exists = matches!(
                    self.groups.data().get(b"g".as_slice()),
                    Some(ConfigValue::Dict(g)) if g.contains_key(&key)
                );
                self.groups.edit_data(|data| {
                    let entry = dict(dict(data, b"g"), &key);
                    if !exists {
                        set_str(entry, b"n", name);
                        set_int(entry, b"j", now_seconds());
                    }
                    if !auth_data.is_empty() && get_str(entry, b"K").is_none() {
                        entry.insert(b"s".to_vec(), ConfigValue::String(auth_data.clone()));
                    }
                    entry.remove(b"i".as_slice()); // no longer just "invited"
                });
                true
            }
        }
    }

    pub fn state(&self) -> AccountState {
        let profile_name = get_str(self.profile.data(), b"n");
        let mut contacts = Vec::new();
        if let Some(ConfigValue::Dict(entries)) = self.contacts.data().get(b"c".as_slice()) {
            for (key, value) in entries {
                let ConfigValue::Dict(entry) = value else {
                    continue;
                };
                if key.len() != 33 || key[0] != 0x05 {
                    continue;
                }
                let name = get_str(entry, b"N")
                    .filter(|n| !n.is_empty())
                    .or_else(|| get_str(entry, b"n").filter(|n| !n.is_empty()));
                let expiry = match (get_int(entry, b"e"), get_int(entry, b"E")) {
                    (1, seconds) if seconds > 0 => Some((2, seconds as u32)),
                    (2, seconds) if seconds > 0 => Some((1, seconds as u32)),
                    _ => None,
                };
                contacts.push(ContactState {
                    id: hex::encode(key),
                    name,
                    approved: get_int(entry, b"a") != 0,
                    hidden: get_int(entry, b"+") < 0,
                    blocked: get_int(entry, b"b") != 0,
                    expiry,
                });
            }
        }
        let mut last_read = Vec::new();
        for section in [b"1".as_slice(), b"g".as_slice()] {
            if let Some(ConfigValue::Dict(entries)) = self.convos.data().get(section) {
                for (key, value) in entries {
                    if let ConfigValue::Dict(entry) = value
                        && key.len() == 33
                    {
                        let read = get_int(entry, b"r");
                        if read > 0 {
                            last_read.push((hex::encode(key), read));
                        }
                    }
                }
            }
        }
        AccountState {
            profile_name,
            contacts,
            last_read,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; 64] {
        let seed = [3u8; 32];
        let (_, sk) = libsession::crypto::ed25519::ed25519_key_pair_from_seed(&seed).unwrap();
        sk
    }

    fn peer() -> String {
        "05".to_owned() + &"ab".repeat(32)
    }

    /// Simulate the phone: write a contact with a field this client does not
    /// know about, push it, and let our side merge it.
    #[test]
    fn edits_keep_unknown_fields_and_bump_seqno() {
        let sk = secret();
        let mut phone = ConfigBase::<Contacts>::new(&sk, None).unwrap();
        phone.edit_data(|data| {
            let entry = dict(dict(data, b"c"), &id_key(&peer()).unwrap());
            set_str(entry, b"n", "Alice");
            entry.insert(b"Z".to_vec(), ConfigValue::Integer(42)); // unknown field
        });
        let pushed = phone.push();
        let phone_seqno = pushed.seqno;

        let mut configs = AccountConfigs::new(&sk, &[None, None, None, None]).unwrap();
        configs
            .contacts
            .merge(&[("h1", pushed.messages[0].as_slice())])
            .unwrap();
        assert_eq!(configs.state().contacts[0].name.as_deref(), Some("Alice"));

        assert!(configs.apply(&AccountChange::ApproveContact {
            id: peer(),
            name: None
        }));
        assert!(configs.contacts.needs_push());
        let ours = configs.contacts.push();
        assert!(
            ours.seqno > phone_seqno,
            "a local edit must create a new version"
        );

        // The phone merges our push and still has its unknown field.
        phone.merge(&[("h2", ours.messages[0].as_slice())]).unwrap();
        let ConfigValue::Dict(c) = &phone.data()[b"c".as_slice()] else {
            panic!()
        };
        let ConfigValue::Dict(entry) = &c[&id_key(&peer()).unwrap()] else {
            panic!()
        };
        assert_eq!(get_int(entry, b"Z"), 42);
        assert_eq!(get_int(entry, b"a"), 1);
        assert_eq!(get_str(entry, b"n").as_deref(), Some("Alice"));
    }

    #[test]
    fn unchanged_values_do_not_create_versions() {
        let sk = secret();
        let mut configs = AccountConfigs::new(&sk, &[None, None, None, None]).unwrap();
        assert!(configs.apply(&AccountChange::ProfileName("Bian".into())));
        let pushed = configs.profile.push();
        configs.profile.confirm_pushed(pushed.seqno, "hash");
        assert!(!configs.apply(&AccountChange::ProfileName("Bian".into())));
        assert!(!configs.profile.needs_push());
        assert_eq!(configs.state().profile_name.as_deref(), Some("Bian"));

        let read = AccountChange::ReadUpTo {
            conversation: peer(),
            timestamp_ms: 500,
        };
        assert!(configs.apply(&read));
        assert!(!configs.apply(&AccountChange::ReadUpTo {
            conversation: peer(),
            timestamp_ms: 400
        }));
        assert_eq!(configs.state().last_read, vec![(peer(), 500)]);
    }

    #[test]
    fn expiry_uses_config_encoding_and_round_trips() {
        let sk = secret();
        let mut configs = AccountConfigs::new(&sk, &[None, None, None, None]).unwrap();
        configs.apply(&AccountChange::ContactExpiry {
            id: peer(),
            expiry: Some((1, 3600)), // Content: after read
        });
        let ConfigValue::Dict(c) = &configs.contacts.data()[b"c".as_slice()] else {
            panic!()
        };
        let ConfigValue::Dict(entry) = &c[&id_key(&peer()).unwrap()] else {
            panic!()
        };
        assert_eq!(get_int(entry, b"e"), 2); // config: after read
        assert_eq!(configs.state().contacts[0].expiry, Some((1, 3600)));
    }

    #[test]
    fn dumps_restore_state() {
        let sk = secret();
        let mut configs = AccountConfigs::new(&sk, &[None, None, None, None]).unwrap();
        configs.apply(&AccountChange::JoinGroup {
            id: "03".to_owned() + &"cd".repeat(32),
            name: "Team".into(),
            auth_data: vec![1; 100],
        });
        let dumps = configs.dumps();
        let restored = AccountConfigs::new(&sk, &dumps.clone().map(Some)).unwrap();
        let groups: Vec<_> = restored.groups.get().iter_groups().cloned().collect();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].base.name, "Team");
        assert_eq!(groups[0].auth_data, vec![1; 100]);
        let mut configs = AccountConfigs::new(&sk, &dumps.map(Some)).unwrap();
        configs.apply(&AccountChange::LeaveGroup {
            id: "03".to_owned() + &"cd".repeat(32),
        });
        assert_eq!(configs.groups.get().iter_groups().count(), 0);
    }

    #[test]
    fn queue_supersedes_older_changes() {
        let mut pending = Vec::new();
        AccountChange::queue(&mut pending, AccountChange::ProfileName("a".into()));
        AccountChange::queue(&mut pending, AccountChange::ProfileName("b".into()));
        let read = |ts| AccountChange::ReadUpTo {
            conversation: peer(),
            timestamp_ms: ts,
        };
        AccountChange::queue(&mut pending, read(5));
        AccountChange::queue(&mut pending, read(9));
        AccountChange::queue(&mut pending, read(7));
        assert_eq!(
            pending,
            vec![AccountChange::ProfileName("b".into()), read(9)]
        );
    }
}
