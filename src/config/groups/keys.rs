//! Group Keys management.
//!
//! Port of `libsession-util/include/session/config/groups/keys.hpp` and
//! `src/config/groups/keys.cpp`.
//!
//! This is a special config type that does NOT follow the standard ConfigBase pattern.
//! Unlike other config types, group keys:
//! - Don't encrypt the outer message (but contain encrypted elements within)
//! - Don't merge (conflicts are resolved by rekeying)
//! - Have their own concept of generation numbers instead of seqno
//! - Messages expire based on age, not update
//! - The internal state isn't fully serialized when pushing
//!
//! Config message fields:
//!   # - 24-byte nonce
//!   G - generation counter (monotonically increasing)
//!   K - encrypted key for admins (omitted for supplemental messages)
//!   k - packed encrypted keys for members (each 48 bytes)
//!   + - supplemental encrypted key info list
//!   ~ - Ed25519 signature
//!
//! Dump fields:
//!   A - active config messages list
//!   L - list of all known keys
//!   P - pending key config

use std::collections::BTreeMap;

/// Padding multiple for member key lists.
pub const MESSAGE_KEY_MULTIPLE: usize = 45;

/// How long to keep old keys after they've been superseded (in seconds).
pub const KEY_EXPIRY_SECS: i64 = 30 * 24 * 3600; // 30 days

/// Information about an encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The 32-byte encryption key.
    pub key: [u8; 32],
    /// When this key was stored (unix milliseconds).
    pub timestamp_ms: i64,
    /// The generation number of this key.
    pub generation: i64,
}

impl PartialOrd for KeyInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.generation
            .cmp(&other.generation)
            .then(self.timestamp_ms.cmp(&other.timestamp_ms))
            .then(self.key.cmp(&other.key))
    }
}

/// Group Keys state (special, not ConfigBase-based).
#[derive(Debug, Clone)]
pub struct GroupKeys {
    /// The group's Ed25519 public key (32 bytes).
    pub group_ed25519_pubkey: [u8; 32],

    /// The user's Ed25519 secret key (for decrypting member keys).
    /// Used when processing incoming key messages (key exchange not yet fully implemented).
    #[allow(dead_code)]
    user_ed25519_sk: Vec<u8>,

    /// Known encryption keys, sorted by generation/timestamp/key.
    keys: Vec<KeyInfo>,

    /// Hashes of successfully parsed messages, grouped by generation.
    active_msgs: BTreeMap<i64, Vec<String>>,

    /// Pending key data (if a rekey is in progress).
    pending_key: Option<[u8; 32]>,
    pending_key_config: Option<Vec<u8>>,
    pending_generation: i64,

    /// Whether the state has changed and needs dumping.
    needs_dump: bool,
}

impl GroupKeys {
    /// Creates a new GroupKeys instance.
    ///
    /// - `group_ed25519_pubkey`: the group's 32-byte Ed25519 public key
    /// - `user_ed25519_sk`: the user's Ed25519 secret key (32 or 64 bytes)
    /// - `group_ed25519_secretkey`: the group's Ed25519 secret key (only if admin)
    /// - `dump`: optional previous dump data to restore from
    pub fn new(
        group_ed25519_pubkey: [u8; 32],
        user_ed25519_sk: &[u8],
        _group_ed25519_secretkey: Option<&[u8]>,
        dump: Option<&[u8]>,
    ) -> Result<Self, String> {
        let mut gk = GroupKeys {
            group_ed25519_pubkey,
            user_ed25519_sk: user_ed25519_sk.to_vec(),
            keys: Vec::new(),
            active_msgs: BTreeMap::new(),
            pending_key: None,
            pending_key_config: None,
            pending_generation: -1,
            needs_dump: false,
        };

        if let Some(dump_data) = dump {
            gk.load_dump(dump_data)?;
        }

        Ok(gk)
    }

    /// Returns the current (latest) group encryption key, if any.
    pub fn current_key(&self) -> Option<&[u8; 32]> {
        self.keys.last().map(|ki| &ki.key)
    }

    /// Returns the current generation number.
    pub fn current_generation(&self) -> i64 {
        self.keys.last().map(|ki| ki.generation).unwrap_or(-1)
    }

    /// Returns all known encryption keys (newest first for decryption priority).
    pub fn all_keys(&self) -> &[KeyInfo] {
        &self.keys
    }

    /// Returns the number of known keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether the state needs dumping.
    pub fn needs_dump(&self) -> bool {
        self.needs_dump
    }

    /// Returns whether a pending key config exists (needs pushing).
    pub fn needs_push(&self) -> bool {
        self.pending_key_config.is_some()
    }

    /// Returns the pending key config message, if any, for pushing.
    pub fn pending_config(&self) -> Option<&[u8]> {
        self.pending_key_config.as_deref()
    }

    /// Inserts a key into the sorted keys list.
    pub fn insert_key(&mut self, key: KeyInfo) {
        let pos = self.keys.binary_search(&key).unwrap_or_else(|p| p);
        self.keys.insert(pos, key);
        self.needs_dump = true;
    }

    /// Removes expired keys (keys that have been superseded for longer than KEY_EXPIRY_SECS).
    pub fn remove_expired(&mut self) {
        if self.keys.len() <= 1 {
            return;
        }

        let latest_gen = self.current_generation();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let expiry_ms = KEY_EXPIRY_SECS * 1000;
        let before = self.keys.len();

        self.keys.retain(|ki| {
            // Keep the latest generation's keys
            ki.generation == latest_gen
                // Keep keys that haven't expired
                || (now_ms - ki.timestamp_ms) < expiry_ms
        });

        if self.keys.len() != before {
            self.needs_dump = true;
        }
    }

    /// Produces a dump of the current keys state for persistence.
    pub fn dump(&mut self) -> Vec<u8> {
        use crate::util::bencode::{self, BtValue};
        self.needs_dump = false;

        let mut dump_dict = std::collections::BTreeMap::new();

        // "A" - active messages
        if !self.active_msgs.is_empty() {
            let mut active_list = Vec::new();
            for (generation, hashes) in &self.active_msgs {
                let mut entry = Vec::new();
                entry.push(BtValue::Integer(*generation));
                for h in hashes {
                    entry.push(BtValue::String(h.as_bytes().to_vec()));
                }
                active_list.push(BtValue::List(entry));
            }
            dump_dict.insert(b"A".to_vec(), BtValue::List(active_list));
        }

        // "L" - list of keys
        if !self.keys.is_empty() {
            let mut keys_list = Vec::new();
            for ki in &self.keys {
                let mut key_dict = std::collections::BTreeMap::new();
                key_dict.insert(b"g".to_vec(), BtValue::Integer(ki.generation));
                key_dict.insert(b"k".to_vec(), BtValue::String(ki.key.to_vec()));
                key_dict.insert(b"t".to_vec(), BtValue::Integer(ki.timestamp_ms));
                keys_list.push(BtValue::Dict(key_dict));
            }
            dump_dict.insert(b"L".to_vec(), BtValue::List(keys_list));
        }

        // "P" - pending key
        if let Some(ref config) = self.pending_key_config {
            let mut pending_dict = std::collections::BTreeMap::new();
            pending_dict.insert(b"c".to_vec(), BtValue::String(config.clone()));
            pending_dict.insert(b"g".to_vec(), BtValue::Integer(self.pending_generation));
            if let Some(ref key) = self.pending_key {
                pending_dict.insert(b"k".to_vec(), BtValue::String(key.to_vec()));
            }
            dump_dict.insert(b"P".to_vec(), BtValue::Dict(pending_dict));
        }

        bencode::encode(&BtValue::Dict(dump_dict))
    }

    /// Loads keys state from a dump.
    fn load_dump(&mut self, dump_data: &[u8]) -> Result<(), String> {
        use crate::util::bencode::{self, BtValue};

        let top = bencode::decode(dump_data).map_err(|e| format!("Invalid keys dump: {}", e))?;
        let dict = match &top {
            BtValue::Dict(d) => d,
            _ => return Err("Keys dump must be a bencode dict".into()),
        };

        // Load active messages "A"
        if let Some(BtValue::List(active)) = dict.get(b"A".as_ref()) {
            for entry in active {
                if let BtValue::List(items) = entry {
                    if items.is_empty() {
                        continue;
                    }
                    if let BtValue::Integer(generation) = &items[0] {
                        let mut hashes = Vec::new();
                        for item in &items[1..] {
                            if let BtValue::String(h) = item
                                && let Ok(s) = String::from_utf8(h.clone()) {
                                    hashes.push(s);
                                }
                        }
                        self.active_msgs.insert(*generation, hashes);
                    }
                }
            }
        }

        // Load keys "L"
        if let Some(BtValue::List(keys)) = dict.get(b"L".as_ref()) {
            for key_entry in keys {
                if let BtValue::Dict(kd) = key_entry {
                    let generation = match kd.get(b"g".as_ref()) {
                        Some(BtValue::Integer(g)) => *g,
                        _ => continue,
                    };
                    let key_bytes = match kd.get(b"k".as_ref()) {
                        Some(BtValue::String(k)) if k.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(k);
                            arr
                        }
                        _ => continue,
                    };
                    let timestamp_ms = match kd.get(b"t".as_ref()) {
                        Some(BtValue::Integer(t)) => *t,
                        _ => 0,
                    };

                    self.keys.push(KeyInfo {
                        key: key_bytes,
                        timestamp_ms,
                        generation,
                    });
                }
            }
            self.keys.sort();
        }

        // Load pending key "P"
        if let Some(BtValue::Dict(pd)) = dict.get(b"P".as_ref()) {
            if let Some(BtValue::String(config)) = pd.get(b"c".as_ref()) {
                self.pending_key_config = Some(config.clone());
            }
            if let Some(BtValue::Integer(generation)) = pd.get(b"g".as_ref()) {
                self.pending_generation = *generation;
            }
            if let Some(BtValue::String(k)) = pd.get(b"k".as_ref())
                && k.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(k);
                    self.pending_key = Some(arr);
                }
        }

        Ok(())
    }

    /// Confirms that a key message was successfully pushed.
    pub fn confirm_pushed(&mut self, msg_hash: &str) {
        if let Some(ref key) = self.pending_key {
            // Move pending key to active keys
            let ki = KeyInfo {
                key: *key,
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
                generation: self.pending_generation,
            };
            self.insert_key(ki);

            // Track the hash
            self.active_msgs
                .entry(self.pending_generation)
                .or_default()
                .push(msg_hash.to_string());
        }

        self.pending_key = None;
        self.pending_key_config = None;
        self.pending_generation = -1;
        self.needs_dump = true;
    }
}

impl Default for GroupKeys {
    fn default() -> Self {
        GroupKeys {
            group_ed25519_pubkey: [0u8; 32],
            user_ed25519_sk: Vec::new(),
            keys: Vec::new(),
            active_msgs: BTreeMap::new(),
            pending_key: None,
            pending_key_config: None,
            pending_generation: -1,
            needs_dump: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_group_keys() {
        let gk = GroupKeys::default();
        assert_eq!(gk.key_count(), 0);
        assert!(gk.current_key().is_none());
        assert_eq!(gk.current_generation(), -1);
        assert!(!gk.needs_push());
        assert!(!gk.needs_dump());
    }

    #[test]
    fn test_insert_key() {
        let mut gk = GroupKeys::default();

        gk.insert_key(KeyInfo {
            key: [1u8; 32],
            timestamp_ms: 1000,
            generation: 0,
        });
        assert_eq!(gk.key_count(), 1);
        assert_eq!(gk.current_generation(), 0);
        assert_eq!(*gk.current_key().unwrap(), [1u8; 32]);

        gk.insert_key(KeyInfo {
            key: [2u8; 32],
            timestamp_ms: 2000,
            generation: 1,
        });
        assert_eq!(gk.key_count(), 2);
        assert_eq!(gk.current_generation(), 1);
        assert_eq!(*gk.current_key().unwrap(), [2u8; 32]);
    }

    #[test]
    fn test_key_ordering() {
        let k1 = KeyInfo {
            key: [1u8; 32],
            timestamp_ms: 1000,
            generation: 0,
        };
        let k2 = KeyInfo {
            key: [2u8; 32],
            timestamp_ms: 2000,
            generation: 1,
        };
        assert!(k1 < k2);
    }

    #[test]
    fn test_dump_and_load() {
        let mut gk = GroupKeys::default();
        gk.insert_key(KeyInfo {
            key: [0xAAu8; 32],
            timestamp_ms: 5000,
            generation: 0,
        });
        gk.insert_key(KeyInfo {
            key: [0xBBu8; 32],
            timestamp_ms: 10000,
            generation: 1,
        });

        let dump = gk.dump();

        let mut loaded = GroupKeys::default();
        loaded.load_dump(&dump).unwrap();

        assert_eq!(loaded.key_count(), 2);
        assert_eq!(loaded.current_generation(), 1);
        assert_eq!(*loaded.current_key().unwrap(), [0xBBu8; 32]);
    }

    #[test]
    fn test_new_group_keys() {
        let pubkey = [0xAA; 32];
        let user_sk = [0xBB; 64];
        let gk = GroupKeys::new(pubkey, &user_sk, None, None).unwrap();
        assert_eq!(gk.group_ed25519_pubkey, pubkey);
        assert_eq!(gk.key_count(), 0);
    }
}
