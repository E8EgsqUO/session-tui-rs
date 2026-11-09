//! ConfigBase: lifecycle management (push/merge/confirm/dump/load) around ConfigMessage.
//!
//! Port of `libsession-util/include/session/config/base.hpp` and `src/config/base.cpp`.
//!
//! This provides the generic config wrapper that adds:
//! - Config state tracking: Clean, Dirty, Waiting
//! - Encryption with per-namespace keys
//! - Dump/load for persistence
//! - Push produces encrypted messages for swarm upload
//! - Confirm acknowledges successful upload
//! - Merge integrates incoming messages from other clients

use std::collections::HashSet;

use crate::util::bencode::{self, BtValue};

use crate::config::config_message::{
    ConfigData, ConfigValue, MutableConfigMessage, SignCallable, VerifyCallable,
};
use crate::config::encrypt::{ENCRYPT_DATA_OVERHEAD, config_decrypt, config_encrypt, pad_message};
use crate::config::namespaces::Namespace;

// ── Config state ────────────────────────────────────────────────────────────

/// Current config lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigState {
    /// Config is confirmed stored on the server and we haven't changed anything.
    Clean = 0,
    /// We have local changes that haven't been serialized yet for sending to the server.
    Dirty = 1,
    /// The caller has serialized the data, but hasn't yet reported back that it has been
    /// stored, *and* we haven't made any changes since serialization.
    Waiting = 2,
}

// ── ConfigType trait ────────────────────────────────────────────────────────

/// Trait that each config sub-type must implement to define its namespace and encryption domain.
pub trait ConfigType: Default {
    /// The storage namespace for this config type.
    fn namespace() -> Namespace;

    /// The encryption domain string (e.g., "UserProfile", "Contacts").
    fn encryption_domain() -> &'static str;

    /// Number of lagged diffs to keep (default: 5).
    fn config_lags() -> i64 {
        5
    }

    /// Whether this config type accepts protobuf-wrapped messages (legacy types).
    fn accepts_protobuf() -> bool {
        false
    }

    /// Whether this config type is read-only (cannot push changes).
    fn is_readonly() -> bool {
        false
    }

    /// Extract this config type's fields from the shared ConfigData.
    fn load_from_data(&mut self, data: &ConfigData);

    /// Store this config type's fields into ConfigData.
    fn store_to_data(&self, data: &mut ConfigData);
}

// ── PushData ────────────────────────────────────────────────────────────────

/// Data returned from a push() call, ready for upload to the swarm.
#[derive(Debug, Clone)]
pub struct PushData {
    /// Sequence number of the pushed config.
    pub seqno: i64,
    /// Encrypted messages to upload (usually one, but can be multiple for large configs).
    pub messages: Vec<Vec<u8>>,
    /// Obsolete message hashes that should be deleted from the server.
    pub obsolete_hashes: Vec<String>,
}

// ── ConfigBase ──────────────────────────────────────────────────────────────

/// Generic config wrapper providing lifecycle management around a config type.
///
/// This handles encryption, push/merge/confirm, and persistence (dump/load).
pub struct ConfigBase<T: ConfigType> {
    /// The specific config type (UserProfile, Contacts, etc.).
    pub config_type: T,

    /// The underlying mutable config message holding the key-value data.
    message: MutableConfigMessage,

    /// Encryption keys. The first key is used for encrypting new messages.
    /// All keys are tried when decrypting.
    keys: Vec<[u8; 32]>,

    /// Current lifecycle state.
    state: ConfigState,

    /// Whether a dump is needed (any mutation since last dump).
    needs_dump: bool,

    /// Currently active message hashes (from the last successful push/confirm).
    curr_hashes: HashSet<String>,

    /// Obsolete message hashes to be deleted on next push.
    old_hashes: HashSet<String>,

    /// Verifier callback for incoming signatures.
    verifier: Option<VerifyCallable>,

    /// Signer callback for outgoing signatures.
    signer: Option<SignCallable>,

    /// `config_type` was changed through `get_mut()` and must be written
    /// back into the message data. Without this, re-serialising the typed
    /// view would silently drop fields the Rust types do not model.
    type_modified: bool,
}

impl<T: ConfigType> ConfigBase<T> {
    /// Creates a new config from an Ed25519 secret key and optional dump data.
    ///
    /// The secret key is used to derive the encryption key for this namespace.
    /// If `dump` is provided, previous state is restored from it.
    pub fn new(secret_key: &[u8], dump: Option<&[u8]>) -> Result<Self, String> {
        let enc_key = derive_enc_key(secret_key)?;

        let mut base = ConfigBase {
            config_type: T::default(),
            message: MutableConfigMessage::new_empty(),
            keys: vec![enc_key],
            state: ConfigState::Clean,
            needs_dump: false,
            curr_hashes: HashSet::new(),
            old_hashes: HashSet::new(),
            verifier: None,
            signer: None,
            type_modified: false,
        };

        if let Some(dump_data) = dump {
            base.load_dump(dump_data)?;
        }

        // Load the config type's fields from the message data
        let data = base.message.data().clone();
        base.config_type.load_from_data(&data);

        Ok(base)
    }

    /// Creates a new config with explicit public key and optional secret key.
    /// Used for group configs where admin status determines write access.
    pub fn new_group(
        ed25519_pubkey: &[u8; 32],
        ed25519_secretkey: Option<&[u8]>,
        dump: Option<&[u8]>,
    ) -> Result<Self, String> {
        let mut base = ConfigBase {
            config_type: T::default(),
            message: MutableConfigMessage::new_empty(),
            keys: Vec::new(),
            state: ConfigState::Clean,
            needs_dump: false,
            curr_hashes: HashSet::new(),
            old_hashes: HashSet::new(),
            verifier: None,
            signer: None,
            type_modified: false,
        };

        // Set up signature verification with the group's public key
        let pubkey = *ed25519_pubkey;
        base.verifier = Some(std::sync::Arc::new(move |data: &[u8], sig: &[u8]| {
            if sig.len() != 64 {
                return false;
            }
            crate::crypto::ed25519::verify(sig, &pubkey, data).unwrap_or(false)
        }));

        // If we have the secret key, set up signing
        if let Some(sk) = ed25519_secretkey {
            let sk_owned: Vec<u8> = sk.to_vec();
            base.signer = Some(std::sync::Arc::new(move |data: &[u8]| {
                crate::crypto::ed25519::sign(&sk_owned, data)
                    .expect("ed25519 signing failed")
                    .to_vec()
            }));
        }

        if let Some(dump_data) = dump {
            base.load_dump(dump_data)?;
        }

        let data = base.message.data().clone();
        base.config_type.load_from_data(&data);

        Ok(base)
    }

    /// Adds an encryption key. The first key added is used for encryption;
    /// all keys are tried for decryption.
    pub fn add_key(&mut self, key: [u8; 32], high_priority: bool) {
        if high_priority {
            self.keys.insert(0, key);
        } else {
            self.keys.push(key);
        }
    }

    /// Clears all encryption keys.
    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    /// Returns the number of encryption keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if there are local changes that need pushing.
    pub fn needs_push(&self) -> bool {
        if T::is_readonly() {
            return false;
        }
        self.state == ConfigState::Dirty
    }

    /// Returns true if the config state has changed and needs to be dumped for persistence.
    pub fn needs_dump(&self) -> bool {
        self.needs_dump
    }

    /// Returns the current state.
    pub fn state(&self) -> ConfigState {
        self.state
    }

    /// Returns true if the config is dirty (has local changes).
    pub fn is_dirty(&self) -> bool {
        self.state == ConfigState::Dirty
    }

    /// Returns the current sequence number.
    pub fn seqno(&self) -> i64 {
        self.message.seqno()
    }

    /// Returns the currently known message hashes.
    pub fn current_hashes(&self) -> Vec<String> {
        self.curr_hashes.iter().cloned().collect()
    }

    /// Returns the obsolete message hashes that should be deleted.
    pub fn old_hashes(&self) -> Vec<String> {
        self.old_hashes.iter().cloned().collect()
    }

    /// Direct read access to the underlying config data.
    pub fn data(&self) -> &ConfigData {
        self.message.data()
    }

    /// Returns a mutable reference to the underlying config message data.
    /// This marks the config as dirty.
    pub fn dirty_data(&mut self) -> &mut ConfigData {
        self.mark_dirty();
        self.message.data_mut()
    }

    /// Marks the config as dirty, indicating local changes.
    fn mark_dirty(&mut self) {
        if self.state != ConfigState::Dirty {
            // Like C++ `ConfigBase::dirty()`: a new local change starts a new
            // config version (seqno + 1, current diff moved into the lagged
            // diffs). Without this a push would reuse the seqno other clients
            // already have and be treated as stale or conflicting.
            self.message = self.message.increment();
            self.set_state(ConfigState::Dirty);
        }
    }

    /// Edit the raw config data in place (only the keys the closure touches
    /// change), then refresh the typed view from it.
    pub fn edit_data<R>(&mut self, edit: impl FnOnce(&mut ConfigData) -> R) -> R {
        self.sync_to_message();
        self.mark_dirty();
        let result = edit(self.message.data_mut());
        let data = self.message.data().clone();
        self.config_type = T::default();
        self.config_type.load_from_data(&data);
        result
    }

    /// Sets the config state, tracking old hashes.
    fn set_state(&mut self, s: ConfigState) {
        if s == ConfigState::Dirty
            && self.state == ConfigState::Clean
            && !self.curr_hashes.is_empty()
        {
            // Move current hashes to old hashes when transitioning clean -> dirty
            for h in self.curr_hashes.drain() {
                self.old_hashes.insert(h);
            }
        }
        self.state = s;
        self.needs_dump = true;
    }

    /// Applies config type changes to the message data before pushing.
    fn sync_to_message(&mut self) {
        if !self.type_modified {
            return;
        }
        self.type_modified = false;
        let mut data = self.message.data().clone();
        self.config_type.store_to_data(&mut data);
        *self.message.data_mut() = data;
    }

    /// Serializes the current config, encrypts it, and returns data for pushing to the swarm.
    ///
    /// After calling this, the config enters the Waiting state (unless it was already clean).
    pub fn push(&mut self) -> PushData {
        if T::is_readonly() {
            return PushData {
                seqno: 0,
                messages: vec![],
                obsolete_hashes: vec![],
            };
        }

        // Sync config_type changes into the message
        self.sync_to_message();

        let seqno = self.message.seqno();

        // Serialize and encrypt
        let serialized = self.message.serialize();
        let mut padded = serialized;
        pad_message(&mut padded, ENCRYPT_DATA_OVERHEAD);

        let encrypted = if let Some(key) = self.keys.first() {
            config_encrypt(&padded, key, T::encryption_domain())
        } else {
            padded
        };

        let obsolete: Vec<String> = self.old_hashes.drain().collect();

        if self.state == ConfigState::Dirty {
            self.set_state(ConfigState::Waiting);
        }

        PushData {
            seqno,
            messages: vec![encrypted],
            obsolete_hashes: obsolete,
        }
    }

    /// Confirms that a push was successfully stored on the server.
    ///
    /// `seqno` should match the seqno returned by push(). `msg_hash` is the server-assigned
    /// message hash.
    pub fn confirm_pushed(&mut self, seqno: i64, msg_hash: &str) {
        // Only confirm if seqno matches and we're in Waiting state
        if seqno == self.message.seqno() && self.state == ConfigState::Waiting {
            self.curr_hashes.clear();
            self.curr_hashes.insert(msg_hash.to_string());
            self.state = ConfigState::Clean;
            self.needs_dump = true;
        }
    }

    /// Merges incoming config messages from other clients.
    ///
    /// `messages` is a list of (hash, encrypted_data) pairs.
    /// Returns the hashes that were successfully processed.
    pub fn merge(&mut self, messages: &[(&str, &[u8])]) -> Result<Vec<String>, String> {
        if self.keys.is_empty() {
            return Err("Cannot merge configs without any decryption keys".into());
        }

        let mut good_hashes = Vec::new();
        let mut decrypted_messages: Vec<Vec<u8>> = Vec::new();
        let mut decrypted_hashes: Vec<String> = Vec::new();

        // Decrypt each incoming message
        for (hash, encrypted) in messages {
            let mut decrypted = None;
            for key in &self.keys {
                match config_decrypt(encrypted, key, T::encryption_domain()) {
                    Ok(plain) => {
                        decrypted = Some(plain);
                        break;
                    }
                    Err(_) => continue,
                }
            }

            if let Some(mut plain) = decrypted {
                // Strip null-byte padding from the beginning
                if let Some(pos) = plain.iter().position(|&b| b != 0)
                    && pos > 0
                {
                    plain = plain[pos..].to_vec();
                }

                if plain.is_empty() {
                    continue;
                }

                // Config messages may be zstd-compressed by newer Session clients. The
                // compression marker is retained inside the encrypted payload.
                if plain.first() == Some(&b'z') {
                    let Some(decompressed) =
                        crate::util::zstd_compress::decompress(&plain[1..], 1_000_000)
                    else {
                        continue;
                    };
                    plain = decompressed;
                }

                // Check for bencode dict marker 'd'
                if plain.first() == Some(&b'd') {
                    good_hashes.push(hash.to_string());
                    decrypted_hashes.push(hash.to_string());
                    decrypted_messages.push(plain);
                }
            }
        }

        if decrypted_messages.is_empty() {
            return Ok(good_hashes);
        }

        // Include our current config in the merge
        let mine = self.message.serialize();
        let old_seqno = self.message.seqno();

        let mut all_configs: Vec<&[u8]> = Vec::new();
        all_configs.push(&mine);
        for msg in &decrypted_messages {
            all_configs.push(msg);
        }

        // Build verifier/signer for merging
        let verifier_for_merge = self.verifier.clone();
        let signer_for_merge = self.signer.clone();

        // Merge using ConfigMessage
        match MutableConfigMessage::from_multiple(
            &all_configs,
            verifier_for_merge,
            signer_for_merge,
            T::config_lags(),
            Some(&|_i, _e| {
                // Error handler for individual message parse failures -- just skip
            }),
        ) {
            Ok(new_msg) => {
                let merged = new_msg.merged();
                let new_seqno = new_msg.seqno();

                // Track which hashes are now obsolete
                for hash in &decrypted_hashes {
                    self.old_hashes.insert(hash.clone());
                }

                self.message = new_msg;

                if new_seqno != old_seqno {
                    if merged {
                        // Merge conflict resolution -- mark dirty
                        self.set_state(ConfigState::Dirty);
                    } else {
                        // Remote was newer, we adopted it
                        self.state = ConfigState::Clean;
                        self.needs_dump = true;
                    }
                } else {
                    self.needs_dump = true;
                }

                // Reload config type from updated data
                let data = self.message.data().clone();
                self.config_type.load_from_data(&data);
            }
            Err(e) => {
                return Err(format!("Merge failed: {}", e));
            }
        }

        Ok(good_hashes)
    }

    /// Produces a dump of the current config state for persistence.
    ///
    /// The dump includes the serialized config message and metadata (hashes, state, etc.).
    pub fn dump(&mut self) -> Vec<u8> {
        self.sync_to_message();
        self.needs_dump = false;

        let serialized = self.message.serialize();

        // Build dump as a bencode dict
        let mut dump_dict = std::collections::BTreeMap::new();

        // "!" = body (the serialized config message)
        dump_dict.insert(b"!".to_vec(), BtValue::String(serialized));

        // "+" = current hashes
        if !self.curr_hashes.is_empty() {
            let hash_list: Vec<BtValue> = self
                .curr_hashes
                .iter()
                .map(|h| BtValue::String(h.as_bytes().to_vec()))
                .collect();
            dump_dict.insert(b"+".to_vec(), BtValue::List(hash_list));
        }

        // "-" = old hashes
        if !self.old_hashes.is_empty() {
            let hash_list: Vec<BtValue> = self
                .old_hashes
                .iter()
                .map(|h| BtValue::String(h.as_bytes().to_vec()))
                .collect();
            dump_dict.insert(b"-".to_vec(), BtValue::List(hash_list));
        }

        bencode::encode(&BtValue::Dict(dump_dict))
    }

    /// Restores config state from a dump.
    fn load_dump(&mut self, dump_data: &[u8]) -> Result<(), String> {
        let top = bencode::decode(dump_data).map_err(|e| format!("Invalid dump: {}", e))?;

        let dict = match &top {
            BtValue::Dict(d) => d,
            _ => return Err("Dump must be a bencode dict".into()),
        };

        // Load body "!"
        if let Some(BtValue::String(body)) = dict.get(b"!".as_ref()) {
            let verifier = self.verifier.clone();
            let signer = self.signer.clone();

            match MutableConfigMessage::from_bytes(body, verifier, signer, T::config_lags()) {
                Ok(msg) => {
                    self.message = msg;
                }
                Err(e) => {
                    return Err(format!("Failed to parse dump body: {}", e));
                }
            }
        }

        // Load current hashes "+"
        if let Some(BtValue::List(hashes)) = dict.get(b"+".as_ref()) {
            for h in hashes {
                if let BtValue::String(s) = h
                    && let Ok(hash_str) = String::from_utf8(s.clone())
                {
                    self.curr_hashes.insert(hash_str);
                }
            }
        }

        // Load old hashes "-"
        if let Some(BtValue::List(hashes)) = dict.get(b"-".as_ref()) {
            for h in hashes {
                if let BtValue::String(s) = h
                    && let Ok(hash_str) = String::from_utf8(s.clone())
                {
                    self.old_hashes.insert(hash_str);
                }
            }
        }

        Ok(())
    }

    /// Direct access to the config type.
    pub fn get(&self) -> &T {
        &self.config_type
    }

    /// Direct mutable access to the config type. Marks the config as dirty.
    pub fn get_mut(&mut self) -> &mut T {
        self.mark_dirty();
        self.type_modified = true;
        &mut self.config_type
    }
}

// ── Helper: config data field accessors ─────────────────────────────────────

/// Helper functions for reading and writing individual fields within ConfigData.
/// These mirror the C++ set_nonempty_str, set_nonzero_int, set_flag, etc.
pub mod field_helpers {
    use super::*;

    /// Gets a string value from config data at the given key path.
    pub fn get_string(data: &ConfigData, key: &[u8]) -> Option<String> {
        match data.get(key) {
            Some(ConfigValue::String(s)) => {
                if s.is_empty() {
                    None
                } else {
                    String::from_utf8(s.clone()).ok()
                }
            }
            _ => None,
        }
    }

    /// Gets a byte-string value from config data at the given key.
    pub fn get_bytes(data: &ConfigData, key: &[u8]) -> Option<Vec<u8>> {
        match data.get(key) {
            Some(ConfigValue::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    /// Gets an integer value from config data at the given key.
    pub fn get_int(data: &ConfigData, key: &[u8]) -> Option<i64> {
        match data.get(key) {
            Some(ConfigValue::Integer(n)) => Some(*n),
            _ => None,
        }
    }

    /// Gets an integer, returning 0 if not present.
    pub fn get_int_or_zero(data: &ConfigData, key: &[u8]) -> i64 {
        get_int(data, key).unwrap_or(0)
    }

    /// Gets a nested dict from config data.
    pub fn get_dict<'a>(data: &'a ConfigData, key: &[u8]) -> Option<&'a ConfigData> {
        match data.get(key) {
            Some(ConfigValue::Dict(d)) => Some(d),
            _ => None,
        }
    }

    /// Gets or creates a nested dict.
    pub fn get_or_create_dict<'a>(data: &'a mut ConfigData, key: &[u8]) -> &'a mut ConfigData {
        data.entry(key.to_vec())
            .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
        match data.get_mut(key) {
            Some(ConfigValue::Dict(d)) => d,
            _ => unreachable!(),
        }
    }

    /// Sets a string value, or removes the key if the string is empty.
    pub fn set_nonempty_str(data: &mut ConfigData, key: &[u8], val: &str) {
        if val.is_empty() {
            data.remove(key);
        } else {
            data.insert(key.to_vec(), ConfigValue::String(val.as_bytes().to_vec()));
        }
    }

    /// Sets a string value (always, even if empty, to keep dict alive).
    pub fn set_str_always(data: &mut ConfigData, key: &[u8], val: &str) {
        data.insert(key.to_vec(), ConfigValue::String(val.as_bytes().to_vec()));
    }

    /// Sets a byte-string value, or removes the key if empty.
    pub fn set_nonempty_bytes(data: &mut ConfigData, key: &[u8], val: &[u8]) {
        if val.is_empty() {
            data.remove(key);
        } else {
            data.insert(key.to_vec(), ConfigValue::String(val.to_vec()));
        }
    }

    /// Sets an integer value, or removes the key if zero.
    pub fn set_nonzero_int(data: &mut ConfigData, key: &[u8], val: i64) {
        if val == 0 {
            data.remove(key);
        } else {
            data.insert(key.to_vec(), ConfigValue::Integer(val));
        }
    }

    /// Sets an integer value, or removes the key if non-positive.
    pub fn set_positive_int(data: &mut ConfigData, key: &[u8], val: i64) {
        if val <= 0 {
            data.remove(key);
        } else {
            data.insert(key.to_vec(), ConfigValue::Integer(val));
        }
    }

    /// Sets a flag (1 if true, removes if false).
    pub fn set_flag(data: &mut ConfigData, key: &[u8], val: bool) {
        if val {
            data.insert(key.to_vec(), ConfigValue::Integer(1));
        } else {
            data.remove(key);
        }
    }

    /// Sets a pair of fields if a condition is met, removes both otherwise.
    pub fn set_pair_if(
        data: &mut ConfigData,
        condition: bool,
        key1: &[u8],
        val1: &[u8],
        key2: &[u8],
        val2: &[u8],
    ) {
        if condition {
            data.insert(key1.to_vec(), ConfigValue::String(val1.to_vec()));
            data.insert(key2.to_vec(), ConfigValue::String(val2.to_vec()));
        } else {
            data.remove(key1);
            data.remove(key2);
        }
    }
}

// ── Key derivation ──────────────────────────────────────────────────────────

/// Extracts the config encryption key from an Ed25519 secret key.
///
/// Session uses the first 32 bytes (the Ed25519 seed) directly as the config key.
fn derive_enc_key(secret_key: &[u8]) -> Result<[u8; 32], String> {
    let seed = if secret_key.len() == 64 {
        &secret_key[..32]
    } else if secret_key.len() == 32 {
        secret_key
    } else {
        return Err(format!(
            "Invalid secret key length: expected 32 or 64, got {}",
            secret_key.len()
        ));
    };

    let mut key = [0u8; 32];
    key.copy_from_slice(seed);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal test config type
    #[derive(Default)]
    struct TestConfig {
        name: Option<String>,
    }

    impl ConfigType for TestConfig {
        fn namespace() -> Namespace {
            Namespace::UserProfile
        }
        fn encryption_domain() -> &'static str {
            "UserProfile"
        }
        fn load_from_data(&mut self, data: &ConfigData) {
            self.name = field_helpers::get_string(data, b"n");
        }
        fn store_to_data(&self, data: &mut ConfigData) {
            if let Some(ref name) = self.name {
                field_helpers::set_nonempty_str(data, b"n", name);
            }
        }
    }

    #[test]
    fn test_new_config_is_clean() {
        let seed = [0u8; 32];
        let base: ConfigBase<TestConfig> = ConfigBase::new(&seed, None).unwrap();
        assert_eq!(base.state(), ConfigState::Clean);
        assert!(!base.needs_push());
        assert!(!base.needs_dump());
    }

    #[test]
    fn test_dirty_after_mutation() {
        let seed = [0u8; 32];
        let mut base: ConfigBase<TestConfig> = ConfigBase::new(&seed, None).unwrap();
        base.get_mut().name = Some("Test".to_string());
        assert_eq!(base.state(), ConfigState::Dirty);
        assert!(base.needs_push());
        assert!(base.needs_dump());
    }

    #[test]
    fn test_push_transitions_to_waiting() {
        let seed = [0u8; 32];
        let mut base: ConfigBase<TestConfig> = ConfigBase::new(&seed, None).unwrap();
        base.get_mut().name = Some("Test".to_string());
        let push_data = base.push();
        assert_eq!(base.state(), ConfigState::Waiting);
        assert!(push_data.seqno > 0 || push_data.seqno == 0);
        assert!(!push_data.messages.is_empty());
    }

    #[test]
    fn test_confirm_transitions_to_clean() {
        let seed = [0u8; 32];
        let mut base: ConfigBase<TestConfig> = ConfigBase::new(&seed, None).unwrap();
        base.get_mut().name = Some("Test".to_string());
        let push_data = base.push();
        base.confirm_pushed(push_data.seqno, "abc123");
        assert_eq!(base.state(), ConfigState::Clean);
        assert_eq!(base.current_hashes(), vec!["abc123"]);
    }

    #[test]
    fn test_dump_and_load_roundtrip() {
        let seed = [0u8; 32];
        let mut base: ConfigBase<TestConfig> = ConfigBase::new(&seed, None).unwrap();
        base.get_mut().name = Some("Test User".to_string());
        let push_data = base.push();
        base.confirm_pushed(push_data.seqno, "hash1");

        let dump = base.dump();
        assert!(!dump.is_empty());

        // Load from dump
        let base2: ConfigBase<TestConfig> = ConfigBase::new(&seed, Some(&dump)).unwrap();
        assert_eq!(base2.get().name.as_deref(), Some("Test User"));
    }

    #[test]
    fn test_derive_enc_key_deterministic() {
        let seed1 = [1u8; 32];
        let key1 = derive_enc_key(&seed1).unwrap();
        let key2 = derive_enc_key(&seed1).unwrap();
        assert_eq!(key1, key2);

        let seed2 = [2u8; 32];
        let key3 = derive_enc_key(&seed2).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_derive_enc_key_from_64_byte_key() {
        let seed = [1u8; 32];
        let mut full_key = [0u8; 64];
        full_key[..32].copy_from_slice(&seed);
        full_key[32..].copy_from_slice(&[2u8; 32]); // pubkey portion

        let key_from_seed = derive_enc_key(&seed).unwrap();
        let key_from_full = derive_enc_key(&full_key).unwrap();
        assert_eq!(key_from_seed, key_from_full);
    }

    #[test]
    fn test_field_helpers() {
        let mut data = ConfigData::new();

        field_helpers::set_nonempty_str(&mut data, b"n", "Alice");
        assert_eq!(field_helpers::get_string(&data, b"n"), Some("Alice".into()));

        field_helpers::set_nonempty_str(&mut data, b"n", "");
        assert_eq!(field_helpers::get_string(&data, b"n"), None);

        field_helpers::set_nonzero_int(&mut data, b"x", 42);
        assert_eq!(field_helpers::get_int(&data, b"x"), Some(42));

        field_helpers::set_nonzero_int(&mut data, b"x", 0);
        assert_eq!(field_helpers::get_int(&data, b"x"), None);

        field_helpers::set_flag(&mut data, b"f", true);
        assert_eq!(field_helpers::get_int(&data, b"f"), Some(1));

        field_helpers::set_flag(&mut data, b"f", false);
        assert_eq!(field_helpers::get_int(&data, b"f"), None);
    }
}
