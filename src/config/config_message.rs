//! ConfigMessage and MutableConfigMessage: the core merge-capable config data types.
//!
//! These types represent Session config messages that can be serialized to/from bencode,
//! merged with other messages to resolve conflicts, and optionally signed with Ed25519.
//!
//! The merge algorithm is deterministic: given the same set of input messages, any client
//! will arrive at the same merged result.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::util::bencode::{self, BtValue};

// ── Config data types ────────────────────────────────────────────────────────

/// Application-level config data: a sorted map of byte-string keys to `ConfigValue`.
pub type ConfigData = BTreeMap<Vec<u8>, ConfigValue>;

/// A 32-byte BLAKE2b hash identifying a config message.
pub type HashT = [u8; 32];

/// A (seqno, hash) pair that uniquely identifies a config message version.
pub type SeqnoHash = (i64, HashT);

/// Diff type: raw bencode dict used for recording changes between versions.
pub type DiffData = BTreeMap<Vec<u8>, BtValue>;

/// Lagged diffs: indexed by (seqno, hash), each mapping to a diff dict.
pub type LaggedDiffs = BTreeMap<SeqnoHash, DiffData>;

/// Values that can appear in config data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    /// A signed 64-bit integer.
    Integer(i64),
    /// A byte string (not necessarily UTF-8).
    String(Vec<u8>),
    /// A sorted set of scalars (integers and/or strings).
    /// Integers sort before strings; within each type, natural ordering.
    Set(Vec<ScalarValue>),
    /// A nested dictionary.
    Dict(ConfigData),
}

/// Scalar values that can appear in sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalarValue {
    Integer(i64),
    String(Vec<u8>),
}

impl PartialOrd for ScalarValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScalarValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (ScalarValue::Integer(a), ScalarValue::Integer(b)) => a.cmp(b),
            (ScalarValue::String(a), ScalarValue::String(b)) => a.cmp(b),
            (ScalarValue::Integer(_), ScalarValue::String(_)) => std::cmp::Ordering::Less,
            (ScalarValue::String(_), ScalarValue::Integer(_)) => std::cmp::Ordering::Greater,
        }
    }
}

// ── Error types ──────────────────────────────────────────────────────────────

/// Errors that can occur during config message operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Config parse error: {0}")]
    ParseError(std::string::String),
    #[error("Config signature error: {0}")]
    SignatureError(std::string::String),
    #[error("Config signature is missing")]
    MissingSignature,
    #[error("Config value error: {0}")]
    ValueError(std::string::String),
    #[error("Config initialization failed: {0}")]
    InitError(std::string::String),
    #[error("Bencode error: {0}")]
    BencodeError(#[from] bencode::BencodeError),
}

// ── Signing/verification callbacks ───────────────────────────────────────────

/// Signature verification callback: given (data, 64-byte-signature), returns true if valid.
pub type VerifyCallable = Arc<dyn Fn(&[u8], &[u8]) -> bool + Send + Sync>;
/// Signing callback: given data-to-sign, returns a 64-byte signature.
pub type SignCallable = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

// ── ConfigMessage ────────────────────────────────────────────────────────────

/// Default number of lagged diffs to carry.
pub const DEFAULT_DIFF_LAGS: i64 = 5;

/// An immutable, parsed config message.
pub struct ConfigMessage {
    data: ConfigData,
    diff: DiffData,
    lagged_diffs: LaggedDiffs,
    seqno_hash: SeqnoHash,
    verified_signature: Option<[u8; 64]>,
    /// Verification function (optional).
    pub verifier: Option<VerifyCallable>,
    /// Signing function (optional).
    pub signer: Option<SignCallable>,
    /// How many lagged diffs to keep.
    pub lag: i64,
    /// After loading multiple configs: None means we merged, Some(i) means we used config i.
    unmerged: Option<usize>,
}

impl ConfigMessage {
    /// Creates a new, empty config message (seqno 0, empty data).
    pub fn new() -> Self {
        let mut msg = ConfigMessage {
            data: ConfigData::new(),
            diff: DiffData::new(),
            lagged_diffs: LaggedDiffs::new(),
            seqno_hash: (0, [0u8; 32]),
            verified_signature: None,
            verifier: None,
            signer: None,
            lag: DEFAULT_DIFF_LAGS,
            unmerged: None,
        };
        let serialized = msg.serialize_impl(&DiffData::new(), false);
        msg.seqno_hash.1 = hash_msg(&serialized);
        msg
    }

    /// Parses a single serialized config message.
    pub fn from_bytes(
        serialized: &[u8],
        verifier: Option<VerifyCallable>,
        signer: Option<SignCallable>,
        lag: i64,
        trust_signature: bool,
    ) -> Result<Self, ConfigError> {
        let hash = hash_msg(serialized);

        let top = bencode::decode(serialized)?;
        let top_dict = match &top {
            BtValue::Dict(d) => d,
            _ => return Err(ConfigError::ParseError("config must be a dict".into())),
        };

        if let Some(first_key) = top_dict.keys().next()
            && first_key.as_slice() < b"#".as_slice()
        {
            return Err(ConfigError::ParseError(
                "config has keys before '#' indicating incompatible version".into(),
            ));
        }

        let seqno = match top_dict.get(b"#".as_ref()) {
            Some(BtValue::Integer(n)) => *n,
            _ => {
                return Err(ConfigError::ParseError(
                    "first key must be \"#\" with integer value".into(),
                ));
            }
        };

        let data = match top_dict.get(b"&".as_ref()) {
            Some(BtValue::Dict(d)) => parse_config_data(d, true)?,
            _ => return Err(ConfigError::ParseError("\"&\" data dict not found".into())),
        };

        let mut lagged_diffs = LaggedDiffs::new();
        if let Some(BtValue::List(lags)) = top_dict.get(b"<".as_ref()) {
            parse_lagged_diffs(&mut lagged_diffs, lags, seqno, lag)?;
        }

        let diff = match top_dict.get(b"=".as_ref()) {
            Some(BtValue::Dict(d)) => load_diff(d)?,
            _ => DiffData::new(),
        };

        let mut verified_signature = None;
        verify_config_sig(
            serialized,
            top_dict,
            &verifier,
            &mut verified_signature,
            trust_signature,
        )?;

        Ok(ConfigMessage {
            data,
            diff,
            lagged_diffs,
            seqno_hash: (seqno, hash),
            verified_signature,
            verifier,
            signer,
            lag,
            unmerged: None,
        })
    }

    /// Constructs a new ConfigMessage by loading and merging multiple serialized configs.
    pub fn from_multiple(
        configs: &[&[u8]],
        verifier: Option<VerifyCallable>,
        signer: Option<SignCallable>,
        lag: i64,
        error_handler: Option<&dyn Fn(usize, &ConfigError)>,
    ) -> Result<Self, ConfigError> {
        let mut parsed: Vec<(ConfigMessage, bool)> = Vec::new();
        for (i, data) in configs.iter().enumerate() {
            let v = verifier.clone();
            let s = signer.clone();
            match ConfigMessage::from_bytes(data, v, s, lag, false) {
                Ok(m) => parsed.push((m, false)),
                Err(e) => {
                    if let Some(handler) = error_handler {
                        handler(i, &e);
                    }
                    continue;
                }
            }
        }

        if parsed.is_empty() {
            return Err(ConfigError::InitError(
                "no valid config messages given".into(),
            ));
        }

        Self::merge_parsed(parsed, verifier, signer, lag)
    }

    /// Internal merge logic shared by ConfigMessage and MutableConfigMessage construction.
    fn merge_parsed(
        mut parsed: Vec<(ConfigMessage, bool)>,
        verifier: Option<VerifyCallable>,
        signer: Option<SignCallable>,
        lag: i64,
    ) -> Result<Self, ConfigError> {
        let mut max_seqno = i64::MIN;
        for (conf, _) in &parsed {
            if conf.seqno() > max_seqno {
                max_seqno = conf.seqno();
            }
        }

        // Prune redundant messages
        let n = parsed.len();
        for i in 0..n {
            if parsed[i].1 {
                continue;
            }
            for j in 0..n {
                if i == j || parsed[i].1 {
                    continue;
                }
                let conf_sh = parsed[i].0.seqno_hash;
                if parsed[j].0.lagged_diffs.contains_key(&conf_sh) {
                    parsed[i].1 = true;
                } else if j < i && parsed[j].0.seqno_hash == conf_sh {
                    parsed[i].1 = true;
                }
            }
        }

        // Prune too-old messages
        for (conf, redundant) in &mut parsed {
            if conf.seqno() + lag <= max_seqno {
                *redundant = true;
            }
        }

        let curr_confs = parsed.iter().filter(|(_, r)| !*r).count();
        assert!(curr_confs >= 1);

        if curr_confs == 1 {
            for (i, (_, redundant)) in parsed.iter().enumerate() {
                if !*redundant {
                    let (conf, _) = parsed.into_iter().nth(i).unwrap();
                    return Ok(ConfigMessage {
                        data: conf.data,
                        diff: conf.diff,
                        lagged_diffs: conf.lagged_diffs,
                        seqno_hash: conf.seqno_hash,
                        verified_signature: conf.verified_signature,
                        verifier,
                        signer,
                        lag,
                        unmerged: Some(i),
                    });
                }
            }
            unreachable!();
        }

        // Multiple non-redundant configs: need to merge.

        // If we require signature verification but can't sign, keep the best one
        if verifier.is_some() && signer.is_none() {
            let mut best_idx = 0;
            let mut best_sh: SeqnoHash = (i64::MIN, [0u8; 32]);
            let mut best_redundant = true;
            for (i, (conf, redundant)) in parsed.iter().enumerate() {
                let is_better = if *redundant != best_redundant {
                    !*redundant
                } else {
                    conf.seqno_hash > best_sh
                };
                if is_better {
                    best_idx = i;
                    best_sh = conf.seqno_hash;
                    best_redundant = *redundant;
                }
            }
            let (best_conf, _) = parsed.into_iter().nth(best_idx).unwrap();
            return Ok(ConfigMessage {
                data: best_conf.data,
                diff: best_conf.diff,
                lagged_diffs: best_conf.lagged_diffs,
                seqno_hash: best_conf.seqno_hash,
                verified_signature: best_conf.verified_signature,
                verifier,
                signer: None,
                lag,
                unmerged: Some(best_idx),
            });
        }

        // Remove redundant
        let mut non_redundant: Vec<ConfigMessage> = parsed
            .into_iter()
            .filter(|(_, r)| !*r)
            .map(|(c, _)| c)
            .collect();

        // Sort descending by seqno/hash
        non_redundant.sort_by(|a, b| b.seqno_hash.cmp(&a.seqno_hash));

        let new_seqno = max_seqno + 1;
        let mut merged_data = non_redundant[0].data.clone();

        // Build replay set
        let mut replay: BTreeMap<SeqnoHash, (usize, DiffData)> = BTreeMap::new();
        for (idx, conf) in non_redundant.iter().enumerate() {
            replay
                .entry(conf.seqno_hash)
                .or_insert_with(|| (idx, conf.diff.clone()));
            for (s_h, diff) in &conf.lagged_diffs {
                replay.entry(*s_h).or_insert_with(|| (idx, diff.clone()));
            }
        }

        // Apply diffs in ascending order
        let mut new_lagged = LaggedDiffs::new();
        for (seqno_hash, (source_idx, diff)) in &replay {
            apply_diff(&mut merged_data, diff, &non_redundant[*source_idx].data);
            new_lagged.insert(*seqno_hash, diff.clone());
        }

        prune_data(&mut merged_data);

        let empty_diff = DiffData::new();
        let mut msg = ConfigMessage {
            data: merged_data,
            diff: DiffData::new(),
            lagged_diffs: new_lagged,
            seqno_hash: (new_seqno, [0u8; 32]),
            verified_signature: None,
            verifier,
            signer,
            lag,
            unmerged: None,
        };

        let serialized = msg.serialize_impl(&empty_diff, false);
        msg.seqno_hash.1 = hash_msg(&serialized);

        Ok(msg)
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Returns a reference to the config data map.
    pub fn data(&self) -> &ConfigData {
        &self.data
    }

    /// Returns the current sequence number.
    pub fn seqno(&self) -> i64 {
        self.seqno_hash.0
    }

    /// Returns the BLAKE2b hash of the serialized message.
    pub fn hash(&self) -> HashT {
        self.seqno_hash.1
    }

    /// Returns the (seqno, hash) pair.
    pub fn seqno_hash(&self) -> &SeqnoHash {
        &self.seqno_hash
    }

    /// Returns `true` if this message has been successfully merged.
    pub fn merged(&self) -> bool {
        self.unmerged.is_none()
    }

    /// Returns the index within the unmerged set, or `None` if merged.
    pub fn unmerged_index(&self) -> Option<usize> {
        self.unmerged
    }

    /// Returns the verified Ed25519 signature, if present.
    pub fn verified_signature(&self) -> Option<&[u8; 64]> {
        self.verified_signature.as_ref()
    }

    /// Returns a reference to the current diff data.
    pub fn diff(&self) -> &DiffData {
        &self.diff
    }

    /// Returns a reference to the lagged diffs from previous sequence numbers.
    pub fn lagged_diffs(&self) -> &LaggedDiffs {
        &self.lagged_diffs
    }

    // ── Serialization ────────────────────────────────────────────────────

    /// Serializes this message to bencode bytes, including the signature if present.
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_impl(&self.diff, true)
    }

    /// Serializes this message to bencode bytes without a signature.
    pub fn serialize_unsigned(&self) -> Vec<u8> {
        self.serialize_impl(&self.diff, false)
    }

    fn serialize_impl(&self, curr_diff: &DiffData, enable_signing: bool) -> Vec<u8> {
        let mut outer = BTreeMap::new();

        outer.insert(b"#".to_vec(), BtValue::Integer(self.seqno_hash.0));
        outer.insert(b"&".to_vec(), config_data_to_bt(&self.data));

        let mut lags_list = Vec::new();
        for ((lag_seqno, lag_hash), lag_data) in &self.lagged_diffs {
            if *lag_seqno <= self.seqno() - self.lag || *lag_seqno >= self.seqno() {
                continue;
            }
            lags_list.push(BtValue::List(vec![
                BtValue::Integer(*lag_seqno),
                BtValue::String(lag_hash.to_vec()),
                diff_to_bt(lag_data),
            ]));
        }
        outer.insert(b"<".to_vec(), BtValue::List(lags_list));
        outer.insert(b"=".to_vec(), diff_to_bt(curr_diff));

        let mut encoded = bencode::encode(&BtValue::Dict(outer));

        if let Some(sig) = &self.verified_signature {
            encoded.pop(); // remove trailing 'e'
            encoded.extend_from_slice(b"1:~64:");
            encoded.extend_from_slice(sig);
            encoded.push(b'e');
        } else if enable_signing && let Some(signer_fn) = &self.signer {
            let data_to_sign = &encoded[..encoded.len() - 1];
            let sig = signer_fn(data_to_sign);
            assert!(sig.len() == 64, "signing function must return 64 bytes");
            encoded.pop();
            encoded.extend_from_slice(b"1:~64:");
            encoded.extend_from_slice(&sig);
            encoded.push(b'e');
        }

        encoded
    }

    /// Creates a MutableConfigMessage by incrementing this message's seqno.
    pub fn increment(&self) -> MutableConfigMessage {
        MutableConfigMessage::from_config_increment(self)
    }
}

// ── MutableConfigMessage ─────────────────────────────────────────────────────

/// A mutable config message that tracks changes for diff computation.
pub struct MutableConfigMessage {
    inner: ConfigMessage,
    orig_data: ConfigData,
}

impl MutableConfigMessage {
    /// Creates a new empty mutable config message.
    pub fn new_empty() -> Self {
        let msg = ConfigMessage::new();
        let orig = msg.data.clone();
        MutableConfigMessage {
            inner: msg,
            orig_data: orig,
        }
    }

    /// Creates a new mutable config message with the given seqno and lag.
    pub fn new(seqno: i64, lag: i64) -> Self {
        let mut msg = ConfigMessage::new();
        msg.seqno_hash.0 = seqno;
        msg.lag = lag;
        let serialized = msg.serialize_impl(&DiffData::new(), false);
        msg.seqno_hash.1 = hash_msg(&serialized);
        let orig = msg.data.clone();
        MutableConfigMessage {
            inner: msg,
            orig_data: orig,
        }
    }

    /// Creates a MutableConfigMessage by loading a single serialized message.
    pub fn from_bytes(
        serialized: &[u8],
        verifier: Option<VerifyCallable>,
        signer: Option<SignCallable>,
        lag: i64,
    ) -> Result<Self, ConfigError> {
        Self::from_multiple(&[serialized], verifier, signer, lag, None)
    }

    /// Creates a MutableConfigMessage by loading and merging multiple serialized messages.
    pub fn from_multiple(
        configs: &[&[u8]],
        verifier: Option<VerifyCallable>,
        signer: Option<SignCallable>,
        lag: i64,
        error_handler: Option<&dyn Fn(usize, &ConfigError)>,
    ) -> Result<Self, ConfigError> {
        let mut parsed: Vec<(ConfigMessage, bool)> = Vec::new();
        for (i, data) in configs.iter().enumerate() {
            let v = verifier.clone();
            let s = signer.clone();
            match ConfigMessage::from_bytes(data, v, s, lag, false) {
                Ok(m) => parsed.push((m, false)),
                Err(e) => {
                    if let Some(handler) = error_handler {
                        handler(i, &e);
                    }
                    continue;
                }
            }
        }

        if parsed.is_empty() {
            return Err(ConfigError::InitError(
                "no valid config messages given".into(),
            ));
        }

        let base = ConfigMessage::merge_parsed(parsed, verifier, signer, lag)?;
        let was_merged = base.merged();

        let orig = base.data.clone();
        let mut result = MutableConfigMessage {
            inner: base,
            orig_data: orig,
        };

        if !was_merged {
            result.increment_impl();
        }

        Ok(result)
    }

    fn from_config_increment(source: &ConfigMessage) -> Self {
        let mut result = MutableConfigMessage {
            inner: ConfigMessage {
                data: source.data.clone(),
                diff: source.diff.clone(),
                lagged_diffs: source.lagged_diffs.clone(),
                seqno_hash: source.seqno_hash,
                verified_signature: source.verified_signature,
                verifier: source.verifier.clone(),
                signer: source.signer.clone(),
                lag: source.lag,
                unmerged: None,
            },
            orig_data: source.data.clone(),
        };
        result.increment_impl();
        result
    }

    fn from_mutable_increment(source: &MutableConfigMessage) -> Self {
        // Compute the diff and hash of the source
        let mut source_data_pruned = source.inner.data.clone();
        prune_data(&mut source_data_pruned);
        let source_diff = compute_diff_data(&source.orig_data, &source_data_pruned);

        // Serialize to compute hash (must include signing to match C++ behavior)
        let temp_msg = ConfigMessage {
            data: source_data_pruned.clone(),
            diff: source_diff.clone(),
            lagged_diffs: source.inner.lagged_diffs.clone(),
            seqno_hash: source.inner.seqno_hash,
            verified_signature: source.inner.verified_signature,
            verifier: source.inner.verifier.clone(),
            signer: source.inner.signer.clone(),
            lag: source.inner.lag,
            unmerged: None,
        };
        let serialized = temp_msg.serialize();
        let source_hash = hash_msg(&serialized);

        let mut result = MutableConfigMessage {
            inner: ConfigMessage {
                data: source_data_pruned,
                diff: source_diff,
                lagged_diffs: source.inner.lagged_diffs.clone(),
                seqno_hash: (source.inner.seqno_hash.0, source_hash),
                verified_signature: source.inner.verified_signature,
                verifier: source.inner.verifier.clone(),
                signer: source.inner.signer.clone(),
                lag: source.inner.lag,
                unmerged: None,
            },
            orig_data: source_data_pruned_placeholder(),
        };
        // Set orig_data to current data (the pre-increment snapshot)
        result.orig_data = result.inner.data.clone();

        result.increment_impl();
        result
    }

    fn increment_impl(&mut self) {
        self.orig_data = self.inner.data.clone();

        let lag = self.inner.lag;
        let seqno = self.inner.seqno_hash.0;

        // Remove too-old lagged diffs
        let keys_to_remove: Vec<SeqnoHash> = self
            .inner
            .lagged_diffs
            .keys()
            .filter(|(s, _)| *s <= seqno - lag)
            .copied()
            .collect();
        for k in keys_to_remove {
            self.inner.lagged_diffs.remove(&k);
        }

        // Remove any future lagged diffs
        let keys_future: Vec<SeqnoHash> = self
            .inner
            .lagged_diffs
            .keys()
            .filter(|(s, _)| *s >= seqno)
            .copied()
            .collect();
        for k in keys_future {
            self.inner.lagged_diffs.remove(&k);
        }

        // Append the current diff to lagged diffs
        let source_diff = std::mem::take(&mut self.inner.diff);
        self.inner
            .lagged_diffs
            .insert(self.inner.seqno_hash, source_diff);

        self.inner.seqno_hash.0 += 1;
        self.inner.seqno_hash.1 = [0u8; 32];
        self.inner.verified_signature = None;
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Returns a reference to the config data map.
    pub fn data(&self) -> &ConfigData {
        &self.inner.data
    }

    /// Returns a mutable reference to the config data map, clearing any verified signature.
    pub fn data_mut(&mut self) -> &mut ConfigData {
        self.inner.verified_signature = None;
        &mut self.inner.data
    }

    /// Returns the current sequence number.
    pub fn seqno(&self) -> i64 {
        self.inner.seqno_hash.0
    }

    /// Sets the sequence number.
    pub fn set_seqno(&mut self, seqno: i64) {
        self.inner.seqno_hash.0 = seqno;
    }

    /// Returns `true` if the inner message has been successfully merged.
    pub fn merged(&self) -> bool {
        self.inner.merged()
    }

    /// Returns the verified Ed25519 signature, if present.
    pub fn verified_signature(&self) -> Option<&[u8; 64]> {
        self.inner.verified_signature()
    }

    /// Returns the current lag value.
    pub fn lag(&self) -> i64 {
        self.inner.lag
    }

    /// Sets or clears the signing callback used for producing signatures.
    pub fn set_signer(&mut self, signer: Option<SignCallable>) {
        self.inner.signer = signer;
    }

    /// Prunes empty dicts and sets from data. Returns true if anything was changed.
    pub fn prune(&mut self) -> bool {
        prune_data(&mut self.inner.data)
    }

    /// Computes the diff from orig_data to current data.
    pub fn diff(&mut self) -> DiffData {
        self.inner.verified_signature = None;
        self.prune();
        compute_diff_data(&self.orig_data, &self.inner.data)
    }

    /// Computes and returns the hash of the current message state.
    pub fn hash(&mut self) -> HashT {
        let serialized = self.serialize();
        let h = hash_msg(&serialized);
        self.inner.seqno_hash.1 = h;
        h
    }

    /// Serializes this mutable config message.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data_copy = self.inner.data.clone();
        prune_data(&mut data_copy);
        let diff = compute_diff_data(&self.orig_data, &data_copy);

        let msg_for_ser = ConfigMessage {
            data: data_copy,
            diff,
            lagged_diffs: self.inner.lagged_diffs.clone(),
            seqno_hash: self.inner.seqno_hash,
            verified_signature: self.inner.verified_signature,
            verifier: self.inner.verifier.clone(),
            signer: self.inner.signer.clone(),
            lag: self.inner.lag,
            unmerged: self.inner.unmerged,
        };
        msg_for_ser.serialize()
    }

    /// Serializes without signing.
    pub fn serialize_unsigned(&self) -> Vec<u8> {
        let mut data_copy = self.inner.data.clone();
        prune_data(&mut data_copy);
        let diff = compute_diff_data(&self.orig_data, &data_copy);

        let msg_for_ser = ConfigMessage {
            data: data_copy,
            diff,
            lagged_diffs: self.inner.lagged_diffs.clone(),
            seqno_hash: self.inner.seqno_hash,
            verified_signature: None,
            verifier: None,
            signer: None,
            lag: self.inner.lag,
            unmerged: self.inner.unmerged,
        };
        msg_for_ser.serialize()
    }

    /// Creates a new MutableConfigMessage by incrementing this one.
    pub fn increment(&self) -> MutableConfigMessage {
        MutableConfigMessage::from_mutable_increment(self)
    }
}

/// Placeholder function to avoid uninitialized data (replaced immediately after construction).
fn source_data_pruned_placeholder() -> ConfigData {
    ConfigData::new()
}

// ── Helper functions ─────────────────────────────────────────────────────────

fn hash_msg(data: &[u8]) -> HashT {
    let h = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(h.as_bytes());
    result
}

fn config_data_to_bt(data: &ConfigData) -> BtValue {
    let mut dict = BTreeMap::new();
    for (key, value) in data {
        dict.insert(key.clone(), config_value_to_bt(value));
    }
    BtValue::Dict(dict)
}

fn config_value_to_bt(value: &ConfigValue) -> BtValue {
    match value {
        ConfigValue::Integer(n) => BtValue::Integer(*n),
        ConfigValue::String(s) => BtValue::String(s.clone()),
        ConfigValue::Set(items) => {
            let list: Vec<BtValue> = items.iter().map(scalar_to_bt).collect();
            BtValue::List(list)
        }
        ConfigValue::Dict(d) => config_data_to_bt(d),
    }
}

fn diff_to_bt(diff: &DiffData) -> BtValue {
    let mut dict = BTreeMap::new();
    for (key, value) in diff {
        dict.insert(key.clone(), value.clone());
    }
    BtValue::Dict(dict)
}

fn parse_config_data(
    dict: &BTreeMap<Vec<u8>, BtValue>,
    top_level: bool,
) -> Result<ConfigData, ConfigError> {
    if !top_level && dict.is_empty() {
        return Err(ConfigError::ParseError(
            "Data contains an unpruned, empty dict".into(),
        ));
    }
    let mut result = ConfigData::new();
    for (key, value) in dict {
        let cv = match value {
            BtValue::Integer(n) => ConfigValue::Integer(*n),
            BtValue::String(s) => ConfigValue::String(s.clone()),
            BtValue::Dict(d) => ConfigValue::Dict(parse_config_data(d, false)?),
            BtValue::List(l) => ConfigValue::Set(parse_config_set(l)?),
        };
        result.insert(key.clone(), cv);
    }
    Ok(result)
}

fn parse_config_set(list: &[BtValue]) -> Result<Vec<ScalarValue>, ConfigError> {
    if list.is_empty() {
        return Err(ConfigError::ParseError(
            "Data contains an unpruned, empty set".into(),
        ));
    }
    let mut result = Vec::new();
    for item in list {
        let scalar = match item {
            BtValue::Integer(n) => ScalarValue::Integer(*n),
            BtValue::String(s) => ScalarValue::String(s.clone()),
            _ => {
                return Err(ConfigError::ParseError(
                    "set contains non-scalar value".into(),
                ));
            }
        };
        if let Some(last) = result.last()
            && scalar <= *last
        {
            return Err(ConfigError::ParseError(
                "set elements are not properly sorted or contain duplicates".into(),
            ));
        }
        result.push(scalar);
    }
    Ok(result)
}

fn load_diff(dict: &BTreeMap<Vec<u8>, BtValue>) -> Result<DiffData, ConfigError> {
    let mut result = DiffData::new();
    for (key, value) in dict {
        match value {
            BtValue::String(s) => {
                if s.as_slice() != b"" && s.as_slice() != b"-" {
                    return Err(ConfigError::ParseError(format!(
                        "config diff contains invalid dict pair {}={}",
                        std::string::String::from_utf8_lossy(key),
                        std::string::String::from_utf8_lossy(s)
                    )));
                }
                result.insert(key.clone(), value.clone());
            }
            BtValue::List(l) => {
                if l.len() != 2 {
                    return Err(ConfigError::ParseError(format!(
                        "config diff contains invalid set at {}: expected 2 elements",
                        std::string::String::from_utf8_lossy(key)
                    )));
                }
                for sublist in l {
                    if !matches!(sublist, BtValue::List(_)) {
                        return Err(ConfigError::ParseError(format!(
                            "config diff contains invalid set at {}: expected 2 sub-lists",
                            std::string::String::from_utf8_lossy(key)
                        )));
                    }
                }
                result.insert(key.clone(), value.clone());
            }
            BtValue::Dict(d) => {
                let sub_diff = load_diff(d)?;
                result.insert(key.clone(), diff_to_bt(&sub_diff));
            }
            BtValue::Integer(_) => {
                return Err(ConfigError::ParseError("unexpected integer in diff".into()));
            }
        }
    }
    Ok(result)
}

fn parse_lagged_diffs(
    lagged_diffs: &mut LaggedDiffs,
    list: &[BtValue],
    curr_seqno: i64,
    lag: i64,
) -> Result<(), ConfigError> {
    for item in list {
        let tuple = match item {
            BtValue::List(l) => l,
            _ => {
                return Err(ConfigError::ParseError(
                    "lagged diff entry must be a list".into(),
                ));
            }
        };
        if tuple.len() != 3 {
            return Err(ConfigError::ParseError(
                "lagged diff tuple must have 3 elements".into(),
            ));
        }
        let seqno = match &tuple[0] {
            BtValue::Integer(n) => *n,
            _ => {
                return Err(ConfigError::ParseError(
                    "lagged diff seqno must be integer".into(),
                ));
            }
        };
        if seqno >= curr_seqno {
            return Err(ConfigError::ParseError(
                "lagged seqno >= current seqno".into(),
            ));
        }
        if seqno <= curr_seqno - lag {
            continue;
        }
        let hash_bytes = match &tuple[1] {
            BtValue::String(s) if s.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(s);
                h
            }
            _ => {
                return Err(ConfigError::ParseError(
                    "lagged diff hash must be 32 bytes".into(),
                ));
            }
        };
        let seqno_hash: SeqnoHash = (seqno, hash_bytes);
        if let Some(last) = lagged_diffs.keys().last()
            && seqno_hash <= *last
        {
            return Err(ConfigError::ParseError(
                "lagged diffs are not properly sorted or contain duplicates".into(),
            ));
        }
        let diff = match &tuple[2] {
            BtValue::Dict(d) => load_diff(d)?,
            _ => {
                return Err(ConfigError::ParseError(
                    "lagged diff data must be a dict".into(),
                ));
            }
        };
        lagged_diffs.insert(seqno_hash, diff);
    }
    Ok(())
}

fn verify_config_sig(
    serialized: &[u8],
    dict: &BTreeMap<Vec<u8>, BtValue>,
    verifier: &Option<VerifyCallable>,
    verified_signature: &mut Option<[u8; 64]>,
    trust_signature: bool,
) -> Result<(), ConfigError> {
    if let Some(BtValue::String(sig_bytes)) = dict.get(b"~".as_ref()) {
        if sig_bytes.len() != 64 {
            return Err(ConfigError::SignatureError(
                "Config signature is invalid (not 64B)".into(),
            ));
        }
        let sig_key_marker = b"1:~64:";
        if let Some(pos) = find_last_occurrence(serialized, sig_key_marker) {
            let data_to_verify = &serialized[..pos];
            if let Some(verifier_fn) = verifier {
                if !verifier_fn(data_to_verify, sig_bytes) {
                    return Err(ConfigError::SignatureError(
                        "Config signature failed verification".into(),
                    ));
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(sig_bytes);
                *verified_signature = Some(sig);
            } else if trust_signature {
                let mut sig = [0u8; 64];
                sig.copy_from_slice(sig_bytes);
                *verified_signature = Some(sig);
            }
        }
    } else if verifier.is_some() {
        return Err(ConfigError::MissingSignature);
    }
    Ok(())
}

fn find_last_occurrence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    for i in (0..=haystack.len() - needle.len()).rev() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

fn apply_diff(data: &mut ConfigData, diff: &DiffData, source: &ConfigData) {
    for (k, v) in diff {
        let source_it = source.get(k);
        let scalar_diff = match v {
            BtValue::String(s) => Some(s.as_slice()),
            _ => None,
        };
        let set_diff = matches!(v, BtValue::List(_));
        let dict_diff = matches!(v, BtValue::Dict(_));

        let type_mismatch = match source_it {
            None => true,
            Some(sv) => {
                (scalar_diff.is_some()
                    && !matches!(sv, ConfigValue::Integer(_) | ConfigValue::String(_)))
                    || (set_diff && !matches!(sv, ConfigValue::Set(_)))
                    || (dict_diff && !matches!(sv, ConfigValue::Dict(_)))
            }
        };

        if type_mismatch {
            data.remove(k);
            continue;
        }

        let source_val = source_it.unwrap();

        if let Some(s) = scalar_diff {
            if s == b"-" {
                data.remove(k);
            } else if s == b"" {
                data.insert(k.clone(), source_val.clone());
            }
        } else if dict_diff {
            if let (BtValue::Dict(dd), ConfigValue::Dict(source_dict)) = (v, source_val) {
                let sub_diff = match load_diff(dd) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let entry = data
                    .entry(k.clone())
                    .or_insert_with(|| ConfigValue::Dict(ConfigData::new()));
                if !matches!(entry, ConfigValue::Dict(_)) {
                    *entry = ConfigValue::Dict(ConfigData::new());
                }
                if let ConfigValue::Dict(sub_data) = entry {
                    apply_diff(sub_data, &sub_diff, source_dict);
                }
            }
        } else if set_diff && let BtValue::List(sl) = v {
            let entry = data
                .entry(k.clone())
                .or_insert_with(|| ConfigValue::Set(Vec::new()));
            if !matches!(entry, ConfigValue::Set(_)) {
                *entry = ConfigValue::Set(Vec::new());
            }
            if let ConfigValue::Set(subset) = entry {
                if let Some(BtValue::List(added)) = sl.first() {
                    for item in added {
                        let scalar = match item {
                            BtValue::Integer(n) => ScalarValue::Integer(*n),
                            BtValue::String(s) => ScalarValue::String(s.clone()),
                            _ => continue,
                        };
                        if let Err(pos) = subset.binary_search(&scalar) {
                            subset.insert(pos, scalar);
                        }
                    }
                }
                if let Some(BtValue::List(removed)) = sl.get(1) {
                    for item in removed {
                        let scalar = match item {
                            BtValue::Integer(n) => ScalarValue::Integer(*n),
                            BtValue::String(s) => ScalarValue::String(s.clone()),
                            _ => continue,
                        };
                        if let Ok(pos) = subset.binary_search(&scalar) {
                            subset.remove(pos);
                        }
                    }
                }
            }
        }
    }
}

fn prune_data(data: &mut ConfigData) -> bool {
    let mut changed = false;
    let keys: Vec<Vec<u8>> = data.keys().cloned().collect();
    for key in keys {
        let should_remove = match data.get_mut(&key) {
            Some(ConfigValue::Dict(d)) => {
                if prune_data(d) {
                    changed = true;
                }
                d.is_empty()
            }
            Some(ConfigValue::Set(s)) => s.is_empty(),
            _ => false,
        };
        if should_remove {
            data.remove(&key);
            changed = true;
        }
    }
    changed
}

fn compute_diff_data(old: &ConfigData, new: &ConfigData) -> DiffData {
    let mut result = DiffData::new();
    let mut old_it = old.iter().peekable();
    let mut new_it = new.iter().peekable();

    loop {
        match (old_it.peek(), new_it.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                let (key, old_val) = old_it.next().unwrap();
                diff_removal(&mut result, key, old_val);
            }
            (None, Some(_)) => {
                let (key, new_val) = new_it.next().unwrap();
                diff_addition(&mut result, key, new_val);
            }
            (Some((old_key, _)), Some((new_key, _))) => match old_key.cmp(new_key) {
                std::cmp::Ordering::Less => {
                    let (key, old_val) = old_it.next().unwrap();
                    diff_removal(&mut result, key, old_val);
                }
                std::cmp::Ordering::Greater => {
                    let (key, new_val) = new_it.next().unwrap();
                    diff_addition(&mut result, key, new_val);
                }
                std::cmp::Ordering::Equal => {
                    let (key, old_val) = old_it.next().unwrap();
                    let (_, new_val) = new_it.next().unwrap();
                    diff_change(&mut result, key, old_val, new_val);
                }
            },
        }
    }

    result
}

fn diff_removal(result: &mut DiffData, key: &[u8], old_val: &ConfigValue) {
    match old_val {
        ConfigValue::Integer(_) | ConfigValue::String(_) => {
            result.insert(key.to_vec(), BtValue::String(b"-".to_vec()));
        }
        ConfigValue::Set(items) => {
            let removed_list: Vec<BtValue> = items.iter().map(scalar_to_bt).collect();
            result.insert(
                key.to_vec(),
                BtValue::List(vec![BtValue::List(vec![]), BtValue::List(removed_list)]),
            );
        }
        ConfigValue::Dict(d) => {
            let sub_diff = compute_diff_data(d, &ConfigData::new());
            if !sub_diff.is_empty() {
                result.insert(key.to_vec(), diff_to_bt(&sub_diff));
            }
        }
    }
}

fn diff_addition(result: &mut DiffData, key: &[u8], new_val: &ConfigValue) {
    match new_val {
        ConfigValue::Integer(_) | ConfigValue::String(_) => {
            result.insert(key.to_vec(), BtValue::String(b"".to_vec()));
        }
        ConfigValue::Set(items) => {
            let added_list: Vec<BtValue> = items.iter().map(scalar_to_bt).collect();
            result.insert(
                key.to_vec(),
                BtValue::List(vec![BtValue::List(added_list), BtValue::List(vec![])]),
            );
        }
        ConfigValue::Dict(d) => {
            let sub_diff = compute_diff_data(&ConfigData::new(), d);
            if !sub_diff.is_empty() {
                result.insert(key.to_vec(), diff_to_bt(&sub_diff));
            }
        }
    }
}

fn diff_change(result: &mut DiffData, key: &[u8], old_val: &ConfigValue, new_val: &ConfigValue) {
    let same_type = matches!(
        (old_val, new_val),
        (ConfigValue::Integer(_), ConfigValue::Integer(_))
            | (ConfigValue::String(_), ConfigValue::String(_))
            | (ConfigValue::Set(_), ConfigValue::Set(_))
            | (ConfigValue::Dict(_), ConfigValue::Dict(_))
            | (ConfigValue::Integer(_), ConfigValue::String(_))
            | (ConfigValue::String(_), ConfigValue::Integer(_))
    );

    if !same_type {
        diff_addition(result, key, new_val);
        return;
    }

    match (old_val, new_val) {
        (ConfigValue::Integer(a), ConfigValue::Integer(b)) => {
            if a != b {
                result.insert(key.to_vec(), BtValue::String(b"".to_vec()));
            }
        }
        (ConfigValue::String(a), ConfigValue::String(b)) => {
            if a != b {
                result.insert(key.to_vec(), BtValue::String(b"".to_vec()));
            }
        }
        (ConfigValue::Integer(_), ConfigValue::String(_))
        | (ConfigValue::String(_), ConfigValue::Integer(_)) => {
            result.insert(key.to_vec(), BtValue::String(b"".to_vec()));
        }
        (ConfigValue::Set(old_set), ConfigValue::Set(new_set)) => {
            if let Some(diff) = diff_sets(old_set, new_set) {
                result.insert(key.to_vec(), diff);
            }
        }
        (ConfigValue::Dict(old_dict), ConfigValue::Dict(new_dict)) => {
            let sub_diff = compute_diff_data(old_dict, new_dict);
            if !sub_diff.is_empty() {
                result.insert(key.to_vec(), diff_to_bt(&sub_diff));
            }
        }
        _ => unreachable!(),
    }
}

fn diff_sets(old: &[ScalarValue], new: &[ScalarValue]) -> Option<BtValue> {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut old_it = old.iter().peekable();
    let mut new_it = new.iter().peekable();

    loop {
        match (old_it.peek(), new_it.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                removed.push(scalar_to_bt(old_it.next().unwrap()));
            }
            (None, Some(_)) => {
                added.push(scalar_to_bt(new_it.next().unwrap()));
            }
            (Some(o), Some(n)) => match o.cmp(n) {
                std::cmp::Ordering::Less => {
                    removed.push(scalar_to_bt(old_it.next().unwrap()));
                }
                std::cmp::Ordering::Greater => {
                    added.push(scalar_to_bt(new_it.next().unwrap()));
                }
                std::cmp::Ordering::Equal => {
                    old_it.next();
                    new_it.next();
                }
            },
        }
    }

    if added.is_empty() && removed.is_empty() {
        None
    } else {
        Some(BtValue::List(vec![
            BtValue::List(added),
            BtValue::List(removed),
        ]))
    }
}

fn scalar_to_bt(s: &ScalarValue) -> BtValue {
    match s {
        ScalarValue::Integer(n) => BtValue::Integer(*n),
        ScalarValue::String(s) => BtValue::String(s.clone()),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex_str(data: &[u8]) -> std::string::String {
        hex::encode(data)
    }

    fn cv_dict(pairs: Vec<(&[u8], ConfigValue)>) -> ConfigValue {
        let mut d = ConfigData::new();
        for (k, v) in pairs {
            d.insert(k.to_vec(), v);
        }
        ConfigValue::Dict(d)
    }

    fn cv_set(items: Vec<ScalarValue>) -> ConfigValue {
        ConfigValue::Set(items)
    }

    fn sv_int(n: i64) -> ScalarValue {
        ScalarValue::Integer(n)
    }

    fn sv_str(s: &[u8]) -> ScalarValue {
        ScalarValue::String(s.to_vec())
    }

    #[test]
    fn test_config_pruning() {
        let mut m = MutableConfigMessage::new_empty();
        m.data_mut()
            .insert(b"a".to_vec(), ConfigValue::Integer(123));
        assert_eq!(m.data().len(), 1);
        m.prune();
        assert_eq!(m.data().len(), 1);

        m.data_mut()
            .insert(b"b".to_vec(), ConfigValue::Dict(ConfigData::new()));
        m.prune();
        assert_eq!(m.data().len(), 1);

        m.data_mut()
            .insert(b"b".to_vec(), ConfigValue::Dict(ConfigData::new()));
        m.data_mut().insert(
            b"c".to_vec(),
            cv_dict(vec![(b"a", ConfigValue::Integer(1))]),
        );
        m.data_mut().insert(b"d".to_vec(), cv_set(vec![sv_int(42)]));
        m.data_mut()
            .insert(b"e".to_vec(), ConfigValue::Set(Vec::new()));
        m.prune();
        assert_eq!(m.data().len(), 3);
    }

    #[test]
    fn test_config_diff() {
        let mut m = MutableConfigMessage::new_empty();
        m.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));
        m.data_mut()
            .insert(b"empty".to_vec(), ConfigValue::Set(Vec::new()));
        m.data_mut()
            .insert(b"empty2".to_vec(), ConfigValue::Dict(ConfigData::new()));

        let mut bar_dict = ConfigData::new();
        bar_dict.insert(b"asdf".to_vec(), ConfigValue::Integer(123));
        bar_dict.insert(b"xyz".to_vec(), ConfigValue::String(b"abc".to_vec()));
        bar_dict.insert(
            b"".to_vec(),
            cv_set(vec![sv_int(42), sv_str(b"a"), sv_str(b"b")]),
        );
        m.data_mut()
            .insert(b"bar".to_vec(), ConfigValue::Dict(bar_dict));

        assert_eq!(m.seqno(), 0);
        let diff = m.diff();
        assert_eq!(diff.len(), 2);
        assert!(diff.contains_key(b"foo".as_ref()));
        assert!(diff.contains_key(b"bar".as_ref()));
    }

    #[test]
    fn test_config_serialization() {
        let mut m = MutableConfigMessage::new(10, DEFAULT_DIFF_LAGS);
        m.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));

        let mut bar_dict = ConfigData::new();
        bar_dict.insert(b"asdf".to_vec(), ConfigValue::Integer(123));
        bar_dict.insert(b"xyz".to_vec(), ConfigValue::String(b"abc".to_vec()));
        bar_dict.insert(
            b"".to_vec(),
            cv_set(vec![sv_int(42), sv_str(b"a"), sv_str(b"b")]),
        );
        m.data_mut()
            .insert(b"bar".to_vec(), ConfigValue::Dict(bar_dict));

        let expected = concat!(
            "d",
            "1:#",
            "i10e",
            "1:&",
            "d",
            "3:bar",
            "d",
            "0:",
            "li42e1:a1:be",
            "4:asdf",
            "i123e",
            "3:xyz",
            "3:abc",
            "e",
            "3:foo",
            "i123e",
            "e",
            "1:<",
            "le",
            "1:=",
            "d",
            "3:bar",
            "d",
            "0:",
            "lli42e1:a1:belee",
            "4:asdf",
            "0:",
            "3:xyz",
            "0:",
            "e",
            "3:foo",
            "0:",
            "e",
            "e"
        );

        let serialized = m.serialize();
        assert_eq!(std::string::String::from_utf8_lossy(&serialized), expected,);

        let hash0_hex = "d65738bba88b0f3455cef20fe09a7b4b10f25f9db82be24a6ce1bd06da197526";
        assert_eq!(to_hex_str(&m.hash()), hash0_hex);
    }

    #[test]
    fn test_config_increment_chain() {
        let mut m = MutableConfigMessage::new(10, DEFAULT_DIFF_LAGS);
        m.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));

        let mut bar_dict = ConfigData::new();
        bar_dict.insert(b"asdf".to_vec(), ConfigValue::Integer(123));
        bar_dict.insert(b"xyz".to_vec(), ConfigValue::String(b"abc".to_vec()));
        bar_dict.insert(
            b"".to_vec(),
            cv_set(vec![sv_int(42), sv_str(b"a"), sv_str(b"b")]),
        );
        m.data_mut()
            .insert(b"bar".to_vec(), ConfigValue::Dict(bar_dict));

        let hash0_hex = "d65738bba88b0f3455cef20fe09a7b4b10f25f9db82be24a6ce1bd06da197526";
        assert_eq!(to_hex_str(&m.hash()), hash0_hex);

        let mut m1 = m.increment();
        assert_eq!(m1.seqno(), 11);
        assert!(m1.diff().is_empty());
        m1.data_mut().remove(b"foo".as_ref());

        let diff = m1.diff();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[b"foo".as_ref()], BtValue::String(b"-".to_vec()));

        let hash1_hex = "5b30b4abf4cba71db25dbc0d977cc25df1d0a8a87cad7f561cdec2b8caf65f5e";
        assert_eq!(to_hex_str(&m1.hash()), hash1_hex);

        let mut m2 = m1.increment();
        assert_eq!(m2.seqno(), 12);
        assert!(m2.diff().is_empty());

        m2.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));
        if let Some(ConfigValue::Dict(bar)) = m2.data_mut().get_mut(b"bar".as_ref()) {
            bar.insert(b"xyz".to_vec(), ConfigValue::Integer(42));
            bar.insert(b"a".to_vec(), ConfigValue::Integer(42));
            if let Some(ConfigValue::Set(s)) = bar.get_mut(b"".as_ref()) {
                if let Err(pos) = s.binary_search(&sv_str(b"c")) {
                    s.insert(pos, sv_str(b"c"));
                }
                if let Err(pos) = s.binary_search(&sv_int(99)) {
                    s.insert(pos, sv_int(99));
                }
                if let Ok(pos) = s.binary_search(&sv_str(b"b")) {
                    s.remove(pos);
                }
            }
        }

        let hash2_hex = "027552203cf669070d3ecbeecfa65c65497d59aa4da490e0f68f8131ce081320";
        assert_eq!(to_hex_str(&m2.hash()), hash2_hex);
    }

    #[test]
    fn test_config_increment_five() {
        let mut m = MutableConfigMessage::new(10, DEFAULT_DIFF_LAGS);
        m.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));

        let mut bar_dict = ConfigData::new();
        bar_dict.insert(b"asdf".to_vec(), ConfigValue::Integer(123));
        bar_dict.insert(b"xyz".to_vec(), ConfigValue::String(b"abc".to_vec()));
        bar_dict.insert(
            b"".to_vec(),
            cv_set(vec![sv_int(42), sv_str(b"a"), sv_str(b"b")]),
        );
        m.data_mut()
            .insert(b"bar".to_vec(), ConfigValue::Dict(bar_dict));

        let mut m1 = m.increment();
        m1.data_mut().remove(b"foo".as_ref());

        let mut m2 = m1.increment();
        m2.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));
        if let Some(ConfigValue::Dict(bar)) = m2.data_mut().get_mut(b"bar".as_ref()) {
            bar.insert(b"xyz".to_vec(), ConfigValue::Integer(42));
            bar.insert(b"a".to_vec(), ConfigValue::Integer(42));
            if let Some(ConfigValue::Set(s)) = bar.get_mut(b"".as_ref()) {
                if let Err(pos) = s.binary_search(&sv_str(b"c")) {
                    s.insert(pos, sv_str(b"c"));
                }
                if let Err(pos) = s.binary_search(&sv_int(99)) {
                    s.insert(pos, sv_int(99));
                }
                if let Ok(pos) = s.binary_search(&sv_str(b"b")) {
                    s.remove(pos);
                }
            }
        }

        let mut m3 = m2.increment();
        let mut m4 = m3.increment();
        let mut m5 = m4.increment();

        assert_eq!(
            to_hex_str(&m3.hash()),
            "b83871ea06587f9254cdf2b2af8daff19bd7fb550fb90d5f8f9f546464c08bc5"
        );
        assert_eq!(
            to_hex_str(&m4.hash()),
            "c30e2cfa7ec93c64a1ab6420c9bccfb63da8e4c2940ed6509ffb64f3f0131860"
        );
        assert_eq!(
            to_hex_str(&m5.hash()),
            "3234eb7da8cf4b79b9eec2a144247279d10f6f118184f82429a42c5996bea60c"
        );
    }

    fn data118() -> ConfigData {
        let mut d = ConfigData::new();
        d.insert(
            b"dictB".to_vec(),
            cv_dict(vec![
                (b"changed", ConfigValue::Integer(-1)),
                (b"foo", ConfigValue::Integer(123)),
                (b"removed", ConfigValue::String(b"x".to_vec())),
                (b"removed2", ConfigValue::String(b"y".to_vec())),
            ]),
        );
        d.insert(
            b"dictC".to_vec(),
            cv_dict(vec![(b"x", cv_dict(vec![(b"y", ConfigValue::Integer(1))]))]),
        );
        d.insert(
            b"good".to_vec(),
            cv_set(vec![sv_int(99), sv_int(456), sv_str(b"bar")]),
        );
        d.insert(b"great".to_vec(), cv_set(vec![sv_int(-42), sv_str(b"omg")]));
        d.insert(b"int0".to_vec(), ConfigValue::Integer(-9999));
        d.insert(b"int1".to_vec(), ConfigValue::Integer(100));
        d.insert(b"string1".to_vec(), ConfigValue::String(b"hello".to_vec()));
        d.insert(
            b"string2".to_vec(),
            ConfigValue::String(b"goodbye".to_vec()),
        );
        d
    }

    #[test]
    fn test_config_example1_ordinary_update() {
        let mut m118 = MutableConfigMessage::new(118, 5);
        *m118.data_mut() = data118();

        let mut m = m118.increment();
        assert_eq!(m.seqno(), 119);
        assert_eq!(
            to_hex_str(&m.hash()),
            "43094f68c1faa37eff79e1c2f3973ffd5f9d6423b00ccda306fc6e7dac5f0c44"
        );

        m = m.increment();
        assert_eq!(m.seqno(), 120);
        assert_eq!(
            to_hex_str(&m.hash()),
            "e3a237f91014d31e4d30569c4a8bfcd72157804f99b8732c611c48bf126432b5"
        );

        m = m.increment();
        assert_eq!(m.seqno(), 121);
        assert_eq!(
            to_hex_str(&m.hash()),
            "1a7f602055124deaf21175ef3f32983dee7c9de570e5d9c9a0bbc2db71dcb97f"
        );

        m = m.increment();
        assert_eq!(m.seqno(), 122);
        assert_eq!(
            to_hex_str(&m.hash()),
            "46560604fe352101bb869435260d7100ccfe007be5f741c7e96303f02f394e8a"
        );

        m = m.increment();
        assert_eq!(m.seqno(), 123);

        m.data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(1));
        m.data_mut()
            .insert(b"int2".to_vec(), ConfigValue::Integer(2));
        m.data_mut().remove(b"int0".as_ref());
        m.data_mut()
            .insert(b"string1".to_vec(), ConfigValue::String(b"hello".to_vec()));

        assert_eq!(
            to_hex_str(&m.hash()),
            "d9398c597b058ac7e28e3febb76ed68eb8c5b6c369610562ab5f2b596775d73c"
        );
    }

    #[test]
    fn test_config_deserialization() {
        // Build m123
        let mut m118 = MutableConfigMessage::new(118, 5);
        *m118.data_mut() = data118();
        let mut m = m118.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m.data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(1));
        m.data_mut()
            .insert(b"int2".to_vec(), ConfigValue::Integer(2));
        m.data_mut().remove(b"int0".as_ref());
        m.data_mut()
            .insert(b"string1".to_vec(), ConfigValue::String(b"hello".to_vec()));

        let m123_serialized = m.serialize();

        // Deserialize as immutable
        let parsed = ConfigMessage::from_bytes(&m123_serialized, None, None, 5, false).unwrap();
        assert_eq!(parsed.seqno(), 123);
        assert_eq!(
            to_hex_str(&parsed.hash()),
            "d9398c597b058ac7e28e3febb76ed68eb8c5b6c369610562ab5f2b596775d73c"
        );

        let diff = parsed.diff();
        assert_eq!(diff.len(), 3);
        assert_eq!(diff[b"int0".as_ref()], BtValue::String(b"-".to_vec()));
        assert_eq!(diff[b"int1".as_ref()], BtValue::String(b"".to_vec()));
        assert_eq!(diff[b"int2".as_ref()], BtValue::String(b"".to_vec()));

        let mut expected_data = data118();
        expected_data.insert(b"int1".to_vec(), ConfigValue::Integer(1));
        expected_data.remove(b"int0".as_ref());
        expected_data.insert(b"int2".to_vec(), ConfigValue::Integer(2));
        assert_eq!(*parsed.data(), expected_data);

        // Deserialize as mutable
        let mut_parsed = MutableConfigMessage::from_bytes(&m123_serialized, None, None, 5).unwrap();
        assert_eq!(mut_parsed.seqno(), 124);
        assert!(!mut_parsed.merged());
    }

    #[test]
    fn test_config_empty_set_dict_rejection() {
        let has_empty_set = b"d1:#i0e1:&d0:lee1:<le1:=dee";
        assert!(MutableConfigMessage::from_bytes(has_empty_set, None, None, 5).is_err());

        let has_empty_dict = b"d1:#i0e1:&d0:dee1:<le1:=dee";
        assert!(MutableConfigMessage::from_bytes(has_empty_dict, None, None, 5).is_err());
    }

    fn apply_updates_124(m: &mut MutableConfigMessage) {
        let mut dict_a = ConfigData::new();
        dict_a.insert(b"hello".to_vec(), ConfigValue::Integer(123));
        dict_a.insert(b"goodbye".to_vec(), cv_set(vec![sv_int(123), sv_int(456)]));
        m.data_mut()
            .insert(b"dictA".to_vec(), ConfigValue::Dict(dict_a));

        if let Some(ConfigValue::Dict(dictb)) = m.data_mut().get_mut(b"dictB".as_ref()) {
            dictb.insert(b"changed".to_vec(), ConfigValue::Integer(1));
            dictb.insert(b"added".to_vec(), ConfigValue::Integer(9999));
            let mut nested = ConfigData::new();
            nested.insert(b"a".to_vec(), ConfigValue::Integer(1));
            dictb.insert(b"nested".to_vec(), ConfigValue::Dict(nested));
            dictb.remove(b"removed".as_ref());
            dictb.remove(b"removed2".as_ref());
        }

        m.data_mut().remove(b"dictC".as_ref());

        if let Some(ConfigValue::Set(s)) = m.data_mut().get_mut(b"good".as_ref()) {
            if let Err(pos) = s.binary_search(&sv_str(b"Foo")) {
                s.insert(pos, sv_str(b"Foo"));
            }
            if let Ok(pos) = s.binary_search(&sv_int(456)) {
                s.remove(pos);
            }
            if let Err(pos) = s.binary_search(&sv_int(123)) {
                s.insert(pos, sv_int(123));
            }
        }

        m.data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(42));
        m.data_mut().remove(b"string1".as_ref());
        m.data_mut()
            .insert(b"string2".to_vec(), ConfigValue::String(b"hello".to_vec()));
        m.data_mut()
            .insert(b"string3".to_vec(), ConfigValue::String(b"omg".to_vec()));
        m.data_mut().remove(b"great".as_ref());
    }

    #[test]
    fn test_config_example2_large_update() {
        let mut m118 = MutableConfigMessage::new(118, 5);
        *m118.data_mut() = data118();

        let mut m = m118.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m.data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(1));
        m.data_mut()
            .insert(b"int2".to_vec(), ConfigValue::Integer(2));
        m.data_mut().remove(b"int0".as_ref());
        m.data_mut()
            .insert(b"string1".to_vec(), ConfigValue::String(b"hello".to_vec()));

        let m123_serialized = m.serialize();

        let mut m124 = MutableConfigMessage::from_bytes(&m123_serialized, None, None, 5).unwrap();
        assert_eq!(m124.seqno(), 124);

        apply_updates_124(&mut m124);

        assert_eq!(
            to_hex_str(&m124.hash()),
            "8b73f316178765b9b3b37168e865c84bb5a78610cbb59b84d0fa4d3b4b3c102b"
        );
    }

    #[test]
    fn test_config_example3_simple_conflict() {
        let mut m118 = MutableConfigMessage::new(118, 5);
        *m118.data_mut() = data118();
        let mut m = m118.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m.data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(1));
        m.data_mut()
            .insert(b"int2".to_vec(), ConfigValue::Integer(2));
        m.data_mut().remove(b"int0".as_ref());
        m.data_mut()
            .insert(b"string1".to_vec(), ConfigValue::String(b"hello".to_vec()));

        let m123_serialized = m.serialize();

        let mut m124 = MutableConfigMessage::from_bytes(&m123_serialized, None, None, 5).unwrap();
        apply_updates_124(&mut m124);
        assert_eq!(
            to_hex_str(&m124.hash()),
            "8b73f316178765b9b3b37168e865c84bb5a78610cbb59b84d0fa4d3b4b3c102b"
        );

        let mut m125_a = m124.increment();
        if let Some(ConfigValue::Dict(dictb)) = m125_a.data_mut().get_mut(b"dictB".as_ref()) {
            dictb.remove(b"foo".as_ref());
        }

        let mut m125_b = m124.increment();
        m125_b
            .data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(5));

        assert_eq!(
            to_hex_str(&m125_a.hash()),
            "80f229c3667de6d0fa6f96b53118e097fbda82db3ca1aea221a3db91ea9c45fb"
        );
        assert_eq!(
            to_hex_str(&m125_b.hash()),
            "ab12f0efe9a9ed00db6b17b44ae0ff36b9f49094077fb114f415522f2a0e98de"
        );
        assert!(m125_a.hash() < m125_b.hash());

        let ser_a = m125_a.serialize();
        let ser_b = m125_b.serialize();
        let merged = ConfigMessage::from_multiple(&[&ser_a, &ser_b], None, None, 5, None).unwrap();

        assert!(merged.merged());
        assert_eq!(merged.seqno(), 126);

        let expected_data = {
            let mut d = ConfigData::new();
            let mut dict_a = ConfigData::new();
            dict_a.insert(b"goodbye".to_vec(), cv_set(vec![sv_int(123), sv_int(456)]));
            dict_a.insert(b"hello".to_vec(), ConfigValue::Integer(123));
            d.insert(b"dictA".to_vec(), ConfigValue::Dict(dict_a));

            let mut dict_b = ConfigData::new();
            dict_b.insert(b"added".to_vec(), ConfigValue::Integer(9999));
            dict_b.insert(b"changed".to_vec(), ConfigValue::Integer(1));
            let mut nested = ConfigData::new();
            nested.insert(b"a".to_vec(), ConfigValue::Integer(1));
            dict_b.insert(b"nested".to_vec(), ConfigValue::Dict(nested));
            d.insert(b"dictB".to_vec(), ConfigValue::Dict(dict_b));

            d.insert(
                b"good".to_vec(),
                cv_set(vec![
                    sv_int(99),
                    sv_int(123),
                    sv_str(b"Foo"),
                    sv_str(b"bar"),
                ]),
            );
            d.insert(b"int1".to_vec(), ConfigValue::Integer(5));
            d.insert(b"int2".to_vec(), ConfigValue::Integer(2));
            d.insert(b"string2".to_vec(), ConfigValue::String(b"hello".to_vec()));
            d.insert(b"string3".to_vec(), ConfigValue::String(b"omg".to_vec()));
            d
        };

        assert_eq!(*merged.data(), expected_data);

        // Opposite order should give same result
        let merged_alt =
            ConfigMessage::from_multiple(&[&ser_b, &ser_a], None, None, 5, None).unwrap();
        assert_eq!(merged.serialize(), merged_alt.serialize());

        // Already-included message shouldn't matter
        let ser_124 = m124.serialize();
        let merged_alt2 =
            ConfigMessage::from_multiple(&[&ser_124, &ser_b, &ser_a], None, None, 5, None).unwrap();
        assert_eq!(merged.serialize(), merged_alt2.serialize());

        // Too-old message should get dropped
        let mut m120b = MutableConfigMessage::new(118, 5).increment().increment();
        m120b.data_mut().insert(
            b"too old".to_vec(),
            ConfigValue::String(b"won't see".to_vec()),
        );
        let ser_120b = m120b.serialize();
        let merged_alt4 =
            ConfigMessage::from_multiple(&[&ser_b, &ser_120b, &ser_a], None, None, 5, None)
                .unwrap();
        assert_eq!(merged.serialize(), merged_alt4.serialize());
    }

    #[test]
    fn test_config_example4_complex_conflict() {
        let mut m118 = MutableConfigMessage::new(118, 5);
        *m118.data_mut() = data118();
        let mut m = m118.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m = m.increment();
        m.data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(1));
        m.data_mut()
            .insert(b"int2".to_vec(), ConfigValue::Integer(2));
        m.data_mut().remove(b"int0".as_ref());
        m.data_mut()
            .insert(b"string1".to_vec(), ConfigValue::String(b"hello".to_vec()));

        let m123_serialized = m.serialize();
        let m123_parsed =
            ConfigMessage::from_bytes(&m123_serialized, None, None, 5, false).unwrap();

        let mut m124a = m123_parsed.increment();
        if let Some(ConfigValue::Dict(dictb)) = m124a.data_mut().get_mut(b"dictB".as_ref()) {
            dictb.insert(b"foo".to_vec(), ConfigValue::Integer(66));
            dictb.insert(b"answer".to_vec(), ConfigValue::Integer(42));
        }

        let mut m124b = m123_parsed.increment();
        apply_updates_124(&mut m124b);
        assert_eq!(
            to_hex_str(&m124b.hash()),
            "8b73f316178765b9b3b37168e865c84bb5a78610cbb59b84d0fa4d3b4b3c102b"
        );

        let mut m125a = m124b.increment();
        if let Some(ConfigValue::Dict(dictb)) = m125a.data_mut().get_mut(b"dictB".as_ref()) {
            dictb.remove(b"foo".as_ref());
        }

        let mut m125b = m124b.increment();
        m125b
            .data_mut()
            .insert(b"int1".to_vec(), ConfigValue::Integer(5));

        let ser_125a = m125a.serialize();
        let ser_125b = m125b.serialize();
        let m126a =
            ConfigMessage::from_multiple(&[&ser_125a, &ser_125b], None, None, 5, None).unwrap();

        let mut m120b = MutableConfigMessage::new(118, 5).increment().increment();
        m120b.data_mut().insert(
            b"too old".to_vec(),
            ConfigValue::String(b"won't see".to_vec()),
        );
        let ser_120b = m120b.serialize();

        let ser_124a = m124a.serialize();
        let m126b = ConfigMessage::from_multiple(
            &[&ser_125b, &ser_124a, &ser_125a, &m123_serialized, &ser_120b],
            None,
            None,
            5,
            None,
        )
        .unwrap();

        assert!(m124a.hash() < m124b.hash());
        assert!(m125a.hash() < m125b.hash());
        assert!(m126a.hash() < m126b.hash());

        let ser_126a = m126a.serialize();
        let ser_126b = m126b.serialize();
        let mut m127 =
            MutableConfigMessage::from_multiple(&[&ser_126a, &ser_126b], None, None, 5, None)
                .unwrap();

        if let Some(ConfigValue::Dict(dict_a)) = m127.data_mut().get_mut(b"dictA".as_ref()) {
            if let Some(ConfigValue::Set(goodbye)) = dict_a.get_mut(b"goodbye".as_ref()) {
                if let Err(pos) = goodbye.binary_search(&sv_int(789)) {
                    goodbye.insert(pos, sv_int(789));
                }
            }
        }

        assert_eq!(m127.seqno(), 127);

        let expected_data = {
            let mut d = ConfigData::new();
            let mut dict_a = ConfigData::new();
            dict_a.insert(
                b"goodbye".to_vec(),
                cv_set(vec![sv_int(123), sv_int(456), sv_int(789)]),
            );
            dict_a.insert(b"hello".to_vec(), ConfigValue::Integer(123));
            d.insert(b"dictA".to_vec(), ConfigValue::Dict(dict_a));

            let mut dict_b = ConfigData::new();
            dict_b.insert(b"added".to_vec(), ConfigValue::Integer(9999));
            dict_b.insert(b"answer".to_vec(), ConfigValue::Integer(42));
            dict_b.insert(b"changed".to_vec(), ConfigValue::Integer(1));
            let mut nested = ConfigData::new();
            nested.insert(b"a".to_vec(), ConfigValue::Integer(1));
            dict_b.insert(b"nested".to_vec(), ConfigValue::Dict(nested));
            d.insert(b"dictB".to_vec(), ConfigValue::Dict(dict_b));

            d.insert(
                b"good".to_vec(),
                cv_set(vec![
                    sv_int(99),
                    sv_int(123),
                    sv_str(b"Foo"),
                    sv_str(b"bar"),
                ]),
            );
            d.insert(b"int1".to_vec(), ConfigValue::Integer(5));
            d.insert(b"int2".to_vec(), ConfigValue::Integer(2));
            d.insert(b"string2".to_vec(), ConfigValue::String(b"hello".to_vec()));
            d.insert(b"string3".to_vec(), ConfigValue::String(b"omg".to_vec()));
            d
        };

        assert_eq!(*m127.data(), expected_data);

        // Verify stability with different input order
        let m127_ser = m127.serialize();
        let m_alt1 =
            ConfigMessage::from_multiple(&[&m127_ser, &ser_125a, &ser_126b], None, None, 5, None)
                .unwrap();
        assert_eq!(m_alt1.seqno(), 127);
        assert_eq!(m_alt1.hash(), m127.hash());
    }

    #[test]
    fn test_config_signature() {
        let mut m = MutableConfigMessage::new(10, DEFAULT_DIFF_LAGS);
        m.data_mut()
            .insert(b"foo".to_vec(), ConfigValue::Integer(123));

        let mut bar_dict = ConfigData::new();
        bar_dict.insert(b"asdf".to_vec(), ConfigValue::Integer(123));
        bar_dict.insert(b"xyz".to_vec(), ConfigValue::String(b"abc".to_vec()));
        bar_dict.insert(
            b"".to_vec(),
            cv_set(vec![sv_int(42), sv_str(b"a"), sv_str(b"b")]),
        );
        m.data_mut()
            .insert(b"bar".to_vec(), ConfigValue::Dict(bar_dict));

        let secret_key = hex::decode(
            "79f530dbf3d81aecc04072933c1b3e3edc0b7d91f2dcc2f7756f2611886cca5f\
             4384261cdd338f5820ca9cbbe3fc72ac8944ee60d3b795b797fbbf5597b09f17",
        )
        .unwrap();
        let pubkey =
            hex::decode("4384261cdd338f5820ca9cbbe3fc72ac8944ee60d3b795b797fbbf5597b09f17")
                .unwrap();

        let sk_clone = secret_key.clone();
        m.set_signer(Some(Arc::new(move |data: &[u8]| {
            crate::crypto::ed25519::sign(&sk_clone, data)
                .unwrap()
                .to_vec()
        })));

        let serialized = m.serialize();

        let expected_sig_hex = "77267f4de7701ae348eba0ef73175281512ba3f1051cfed22dc3e31b9c699330\
             2938863e09bc8b33638161071bd8dc397d5c1d3f674120d08fbb9c64dde2e907";
        let expected_sig = hex::decode(expected_sig_hex).unwrap();

        let sig_marker = b"1:~64:";
        let sig_pos = find_last_occurrence(&serialized, sig_marker).unwrap();
        let sig_start = sig_pos + sig_marker.len();
        let sig_bytes = &serialized[sig_start..sig_start + 64];
        assert_eq!(sig_bytes, expected_sig.as_slice());

        // Verify deserialization with signature verification
        let pk_clone = pubkey.clone();
        let verifier: VerifyCallable = Arc::new(move |data: &[u8], sig: &[u8]| {
            crate::crypto::ed25519::verify(sig, &pk_clone, data).unwrap_or(false)
        });
        let sk_clone2 = secret_key.clone();
        let signer: SignCallable = Arc::new(move |data: &[u8]| {
            crate::crypto::ed25519::sign(&sk_clone2, data)
                .unwrap()
                .to_vec()
        });

        let msg = ConfigMessage::from_bytes(
            &serialized,
            Some(verifier.clone()),
            Some(signer.clone()),
            5,
            false,
        )
        .unwrap();
        assert!(msg.verified_signature().is_some());
        assert_eq!(msg.hash(), m.hash());
        assert_eq!(msg.serialize(), serialized);

        // Break the signature - modify the second-to-last byte of the serialized message
        // (last byte is 'e' closing the dict, second-to-last is the last byte of the signature)
        let mut broken = serialized.clone();
        let broken_byte_pos = broken.len() - 2;
        assert_eq!(broken[broken_byte_pos], 0x07);
        broken[broken_byte_pos] = 0x17;

        assert!(
            ConfigMessage::from_bytes(&broken, Some(verifier.clone()), None, 5, false).is_err()
        );

        // Unsigned message should fail with verifier
        let unsigned = m.serialize_unsigned();
        assert!(
            ConfigMessage::from_bytes(&unsigned, Some(verifier.clone()), None, 5, false).is_err()
        );
    }
}
