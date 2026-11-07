//! Typed helpers that build the JSON `params` bodies for Session snode RPCs.
//!
//! Each builder produces a `serde_json::Value` in the **exact** shape expected
//! by the snode network — matching the iOS (`SessionNetworkingKit`) and
//! Android (`session-android/api/snode`) reference implementations 1:1.
//!
//! The outer envelope (`{"method": "...", "params": {...}}`) is not wrapped
//! here — callers assemble that themselves for each onion/batch context.
//!
//! All timestamps are **milliseconds since the Unix epoch**.
//! All public keys are **hex strings** (no `0x` prefix).
//! All signatures are **standard, padded, base64** strings.

use serde_json::{Value, json};

use crate::network::auth::{self, AuthError};

/// Default TTL for messages in milliseconds (14 days).
///
/// Matches the `Namespace::CLOSED_GROUP_MESSAGES` / user default used by the
/// native clients.
pub const DEFAULT_MESSAGE_TTL_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Namespaces the snode network recognises — re-exported for ergonomics.
pub use crate::network::auth::namespace;

/// Method name for a `store` RPC.
pub const METHOD_STORE: &str = "store";
/// Method name for a `retrieve` RPC.
pub const METHOD_RETRIEVE: &str = "retrieve";
/// Method name for a `get_snodes_for_pubkey` RPC.
pub const METHOD_GET_SWARM: &str = "get_snodes_for_pubkey";
/// Method name for an `oxend_request` wrapper.
pub const METHOD_OXEND_REQUEST: &str = "oxend_request";
/// Method name for the seed-node bootstrap RPC — returns the active snode list.
pub const METHOD_GET_N_SERVICE_NODES: &str = "get_n_service_nodes";

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

/// Input for [`build_store_params`].
#[derive(Clone, Debug)]
pub struct StoreParams<'a> {
    /// Recipient Session id (user `05...` or group `03...`), as lowercase hex.
    pub pubkey: &'a str,
    /// Sender's Ed25519 public key, lowercase hex. Required only for
    /// authenticated stores (group/admin messages).
    pub pubkey_ed25519: Option<&'a str>,
    /// Message namespace. Omitted from JSON when `0`.
    pub namespace: i32,
    /// Current unix time in ms. Used for both `timestamp` and `sig_timestamp`.
    pub timestamp_ms: u64,
    /// Message TTL in ms.
    pub ttl_ms: u64,
    /// The base64-encoded envelope payload (already encrypted and serialized).
    pub data_base64: &'a str,
    /// Optional signing key — when supplied, the params are authenticated with
    /// a `signature` field.
    pub signing_key: Option<&'a [u8]>,
}

/// Builds the `params` body for a `store` RPC, matching the native clients.
///
/// * Unauthenticated stores only include `{pubkey, data, ttl, timestamp}`.
/// * Authenticated stores additionally include
///   `{pubkey_ed25519, sig_timestamp, namespace?, signature}`.
pub fn build_store_params(p: &StoreParams<'_>) -> Result<Value, AuthError> {
    let mut m = serde_json::Map::new();
    m.insert("pubkey".to_string(), json!(p.pubkey));
    m.insert("data".to_string(), json!(p.data_base64));
    m.insert("ttl".to_string(), json!(p.ttl_ms));
    m.insert("timestamp".to_string(), json!(p.timestamp_ms));

    if let Some(sk) = p.signing_key {
        let sig = auth::sign_request_b64(METHOD_STORE, p.namespace, p.timestamp_ms, sk)?;
        if let Some(pk_ed) = p.pubkey_ed25519 {
            m.insert("pubkey_ed25519".to_string(), json!(pk_ed));
        }
        m.insert("sig_timestamp".to_string(), json!(p.timestamp_ms));
        if p.namespace != 0 {
            m.insert("namespace".to_string(), json!(p.namespace));
        }
        m.insert("signature".to_string(), json!(sig));
    } else if p.namespace != 0 {
        // Snodes accept namespaced, unauthenticated writes for the default
        // user namespace only — but we still pass the field through so the
        // caller's intent is preserved (the snode will reject if auth is
        // required).
        m.insert("namespace".to_string(), json!(p.namespace));
    }

    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------
// retrieve
// ---------------------------------------------------------------------------

/// Input for [`build_retrieve_params`].
#[derive(Clone, Debug)]
pub struct RetrieveParams<'a> {
    /// Owner Session id (the swarm the snode hosts). Hex.
    pub pubkey: &'a str,
    /// Owner's Ed25519 public key, lowercase hex.
    pub pubkey_ed25519: &'a str,
    /// Namespace to fetch from. Omitted from JSON when `0`.
    pub namespace: i32,
    /// Current unix time in ms.
    pub timestamp_ms: u64,
    /// Last message hash seen; when set, snode returns only newer messages.
    pub last_hash: Option<&'a str>,
    /// Maximum response body size (bytes).
    pub max_size: Option<u32>,
    /// Ed25519 signing key (32-byte seed or 64-byte libsodium secret).
    pub signing_key: &'a [u8],
}

/// Builds the `params` body for an authenticated `retrieve` RPC.
pub fn build_retrieve_params(p: &RetrieveParams<'_>) -> Result<Value, AuthError> {
    let sig = auth::sign_request_b64(METHOD_RETRIEVE, p.namespace, p.timestamp_ms, p.signing_key)?;

    let mut m = serde_json::Map::new();
    m.insert("pubkey".to_string(), json!(p.pubkey));
    m.insert("pubkey_ed25519".to_string(), json!(p.pubkey_ed25519));
    m.insert("timestamp".to_string(), json!(p.timestamp_ms));
    if p.namespace != 0 {
        m.insert("namespace".to_string(), json!(p.namespace));
    }
    if let Some(h) = p.last_hash {
        m.insert("last_hash".to_string(), json!(h));
    }
    if let Some(n) = p.max_size {
        m.insert("max_size".to_string(), json!(n));
    }
    m.insert("signature".to_string(), json!(sig));
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------
// get_snodes_for_pubkey (swarm lookup)
// ---------------------------------------------------------------------------

/// Builds the `params` body for `get_snodes_for_pubkey`.
///
/// This call is unauthenticated. `pubkey` is the target Session id (hex).
pub fn build_get_swarm_params(pubkey: &str) -> Value {
    json!({ "pubkey": pubkey })
}

// ---------------------------------------------------------------------------
// oxend_request (seed-node / daemon wrapper)
// ---------------------------------------------------------------------------

/// Builds the `params` body for `oxend_request`, wrapping an oxend daemon
/// endpoint plus its nested params.
pub fn build_oxend_request(endpoint: &str, inner: Value) -> Value {
    json!({
        "endpoint": endpoint,
        "params": inner,
    })
}

/// Builds the `params` body for `get_n_service_nodes` — the top-level seed
/// and refresh RPC that returns the active snode list.
///
/// Matches Android `ListSnodeApi.buildRequestJson` (fields array, not object):
/// `{"active_only": true, "fields": ["public_ip","storage_port","pubkey_x25519","pubkey_ed25519"]}`.
pub fn build_get_n_service_nodes_params() -> Value {
    json!({
        "active_only": true,
        "fields": [
            "public_ip",
            "storage_port",
            "storage_lmq_port",
            "pubkey_x25519",
            "pubkey_ed25519",
            "swarm_id",
            "storage_server_version",
        ],
    })
}

/// Build the outer envelope `{"method":"...", "params":{...}}` that snodes
/// expect when the request is sent over HTTP (not batched).
pub fn wrap_rpc_envelope(method: &str, params: Value) -> Value {
    json!({ "method": method, "params": params })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn test_store_params_unauthenticated_shape() {
        let v = build_store_params(&StoreParams {
            pubkey: "05aaaa",
            pubkey_ed25519: None,
            namespace: 0,
            timestamp_ms: 1_700_000_000_000,
            ttl_ms: DEFAULT_MESSAGE_TTL_MS,
            data_base64: "AAAA",
            signing_key: None,
        })
        .unwrap();

        assert_eq!(v["pubkey"], "05aaaa");
        assert_eq!(v["data"], "AAAA");
        assert_eq!(v["ttl"], DEFAULT_MESSAGE_TTL_MS);
        assert_eq!(v["timestamp"], 1_700_000_000_000u64);
        assert!(v.get("signature").is_none());
        assert!(v.get("sig_timestamp").is_none());
        assert!(v.get("namespace").is_none());
    }

    #[test]
    fn test_store_params_authenticated_shape() {
        let seed = sk();
        let v = build_store_params(&StoreParams {
            pubkey: "03bbbb",
            pubkey_ed25519: Some("ffff"),
            namespace: 11,
            timestamp_ms: 1_700_000_000_000,
            ttl_ms: 60_000,
            data_base64: "ZZZZ",
            signing_key: Some(&seed),
        })
        .unwrap();

        assert_eq!(v["pubkey"], "03bbbb");
        assert_eq!(v["pubkey_ed25519"], "ffff");
        assert_eq!(v["data"], "ZZZZ");
        assert_eq!(v["ttl"], 60_000u64);
        assert_eq!(v["timestamp"], 1_700_000_000_000u64);
        assert_eq!(v["sig_timestamp"], 1_700_000_000_000u64);
        assert_eq!(v["namespace"], 11);
        assert!(v["signature"].is_string());
    }

    #[test]
    fn test_store_params_auth_omits_namespace_when_zero() {
        let seed = sk();
        let v = build_store_params(&StoreParams {
            pubkey: "05aaaa",
            pubkey_ed25519: Some("ffff"),
            namespace: 0,
            timestamp_ms: 1,
            ttl_ms: 1,
            data_base64: "X",
            signing_key: Some(&seed),
        })
        .unwrap();
        assert!(v.get("namespace").is_none());
        assert!(v["signature"].is_string());
    }

    #[test]
    fn test_retrieve_params_shape() {
        let seed = sk();
        let v = build_retrieve_params(&RetrieveParams {
            pubkey: "05cccc",
            pubkey_ed25519: "dddd",
            namespace: 0,
            timestamp_ms: 1_700_000_000_000,
            last_hash: Some("lastHashValue"),
            max_size: Some(409_600),
            signing_key: &seed,
        })
        .unwrap();

        assert_eq!(v["pubkey"], "05cccc");
        assert_eq!(v["pubkey_ed25519"], "dddd");
        assert_eq!(v["timestamp"], 1_700_000_000_000u64);
        assert_eq!(v["last_hash"], "lastHashValue");
        assert_eq!(v["max_size"], 409_600);
        assert!(v.get("namespace").is_none());
        assert!(v["signature"].is_string());
    }

    #[test]
    fn test_retrieve_params_with_namespace() {
        let seed = sk();
        let v = build_retrieve_params(&RetrieveParams {
            pubkey: "03eeee",
            pubkey_ed25519: "ffff",
            namespace: -10,
            timestamp_ms: 1,
            last_hash: None,
            max_size: None,
            signing_key: &seed,
        })
        .unwrap();
        assert_eq!(v["namespace"], -10);
        assert!(v.get("last_hash").is_none());
        assert!(v.get("max_size").is_none());
    }

    #[test]
    fn test_get_swarm_params_shape() {
        let v = build_get_swarm_params("05deadbeef");
        assert_eq!(v, json!({ "pubkey": "05deadbeef" }));
    }

    #[test]
    fn test_oxend_request_wraps_params() {
        let v = build_oxend_request("ons_resolve", json!({"type": 0, "name_hash": "abc"}));
        assert_eq!(v["endpoint"], "ons_resolve");
        assert_eq!(v["params"]["type"], 0);
        assert_eq!(v["params"]["name_hash"], "abc");
    }

    #[test]
    fn test_get_n_service_nodes_params_shape() {
        let v = build_get_n_service_nodes_params();
        assert_eq!(v["active_only"], true);
        let fields = v["fields"].as_array().unwrap();
        assert!(
            fields
                .iter()
                .any(|f| f.as_str() == Some("public_ip"))
        );
        assert!(
            fields
                .iter()
                .any(|f| f.as_str() == Some("pubkey_ed25519"))
        );
        assert!(
            fields
                .iter()
                .any(|f| f.as_str() == Some("pubkey_x25519"))
        );
        assert!(
            fields
                .iter()
                .any(|f| f.as_str() == Some("storage_port"))
        );
    }

    #[test]
    fn test_wrap_rpc_envelope_shape() {
        let v = wrap_rpc_envelope("store", json!({"pubkey": "05x"}));
        assert_eq!(v["method"], "store");
        assert_eq!(v["params"]["pubkey"], "05x");
    }
}
