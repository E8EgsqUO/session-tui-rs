//! Authenticated request signing for snode RPCs.
//!
//! Session snodes authenticate `store` / `retrieve` / `delete` requests by
//! signing a short canonical string with the caller's Ed25519 key.
//!
//! Canonical signature string: `"{method}{namespace}{timestamp_ms}"` where
//! - `method` is the literal RPC method name (e.g. `"retrieve"`, `"store"`)
//! - `namespace` is the base-10 integer (including negatives); for the default
//!   namespace (`0`) this segment is EMPTY
//! - `timestamp_ms` is the current unix time in milliseconds, base-10
//!
//! The raw 64-byte signature is then **standard, padded** base64-encoded for
//! the JSON body.
//!
//! This matches the iOS (`SessionNetworkingKit`), Android
//! (`session-android/api/snode`) and C++ (`libsession-util` swarm-auth)
//! implementations 1:1.

use serde_json::{Map, Value, json};

use crate::crypto::ed25519;
use crate::crypto::types::CryptoError;

/// Auth-layer error returned when a request cannot be signed.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Underlying Ed25519 signing failed (bad key size, etc.).
    #[error("sign failed: {0}")]
    Sign(#[from] CryptoError),
}

type AuthResult<T> = Result<T, AuthError>;

/// Namespaces commonly used on the snode network.
#[allow(missing_docs)]
pub mod namespace {
    pub const DEFAULT: i32 = 0;
    pub const USER_PROFILE: i32 = 2;
    pub const USER_CONTACTS: i32 = 3;
    pub const USER_GROUPS: i32 = 5;
    pub const CONVO_INFO_VOLATILE: i32 = 4;
    /// Group messages — closed-group messages live here.
    pub const CLOSED_GROUP_MESSAGES: i32 = -10;
    pub const GROUP_MESSAGES: i32 = 11;
    pub const GROUP_KEYS: i32 = 12;
    pub const GROUP_INFO: i32 = 13;
    pub const GROUP_MEMBERS: i32 = 14;
    pub const REVOKED_RETRIEVABLE_GROUP_MESSAGES: i32 = -11;
    pub const CONFIG_PUSH_NOTIFICATIONS: i32 = -12;
}

/// Format the namespace fragment used inside the signed canonical string.
///
/// * `namespace == 0` → empty string (omitted).
/// * any other value → base-10 representation (including the minus sign).
pub fn namespace_signature_fragment(namespace: i32) -> String {
    if namespace == 0 {
        String::new()
    } else {
        namespace.to_string()
    }
}

/// Returns the canonical string signed for a given RPC method + namespace +
/// timestamp.
///
/// `method` is the lowercase RPC name (`"retrieve"`, `"store"`, `"delete"`,
/// `"expire"` etc.); the full string is `"{method}{ns}{ts_ms}"`.
pub fn canonical_sign_string(method: &str, namespace: i32, timestamp_ms: u64) -> String {
    format!(
        "{}{}{}",
        method,
        namespace_signature_fragment(namespace),
        timestamp_ms
    )
}

/// Signs the canonical string with the caller's Ed25519 private key and
/// returns the base64-encoded (standard, padded) signature.
///
/// `privkey` may be either a 32-byte seed or a 64-byte libsodium-style secret
/// key (`seed || pubkey`) — both are accepted by [`crate::crypto::ed25519::sign`].
pub fn sign_request_b64(
    method: &str,
    namespace: i32,
    timestamp_ms: u64,
    privkey: &[u8],
) -> AuthResult<String> {
    let msg = canonical_sign_string(method, namespace, timestamp_ms);
    let sig = ed25519::sign(privkey, msg.as_bytes())?;
    Ok(base64_standard(&sig))
}

/// Builds the `pubkey`, `pubkey_ed25519`, `namespace`, `timestamp` and
/// `signature` JSON fields for a standard (non-subaccount) authenticated
/// request. Caller merges the returned map into its own `params` object.
///
/// * `pubkey_05` — the user's Session id (`05...`), or a group id (`03...`).
///   Hex, no spaces. Length must be 66 hex chars.
/// * `pubkey_ed` — the caller's Ed25519 public key, hex. 64 hex chars.
/// * `namespace` — namespace integer; omitted from the JSON when `0`.
/// * `timestamp_ms` — same value used to build the signature.
/// * `privkey` — Ed25519 signing key.
pub fn build_auth_fields(
    method: &str,
    pubkey_05: &str,
    pubkey_ed: &str,
    namespace: i32,
    timestamp_ms: u64,
    privkey: &[u8],
) -> AuthResult<Map<String, Value>> {
    let sig_b64 = sign_request_b64(method, namespace, timestamp_ms, privkey)?;

    let mut m = Map::new();
    m.insert("pubkey".to_string(), json!(pubkey_05));
    m.insert("pubkey_ed25519".to_string(), json!(pubkey_ed));
    m.insert("timestamp".to_string(), json!(timestamp_ms));
    if namespace != 0 {
        m.insert("namespace".to_string(), json!(namespace));
    }
    m.insert("signature".to_string(), json!(sig_b64));
    Ok(m)
}

/// Current unix time in milliseconds.
pub fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_namespace_fragment_zero_is_empty() {
        assert_eq!(namespace_signature_fragment(0), "");
    }

    #[test]
    fn test_namespace_fragment_positive() {
        assert_eq!(namespace_signature_fragment(11), "11");
        assert_eq!(namespace_signature_fragment(999), "999");
    }

    #[test]
    fn test_namespace_fragment_negative() {
        assert_eq!(namespace_signature_fragment(-10), "-10");
        assert_eq!(namespace_signature_fragment(-11), "-11");
    }

    #[test]
    fn test_canonical_string_shape() {
        assert_eq!(
            canonical_sign_string("retrieve", 0, 1_700_000_000_000),
            "retrieve1700000000000"
        );
        assert_eq!(
            canonical_sign_string("retrieve", 11, 1_700_000_000_000),
            "retrieve111700000000000"
        );
        assert_eq!(
            canonical_sign_string("store", -10, 1_700_000_000_000),
            "store-101700000000000"
        );
    }

    #[test]
    fn test_sign_is_deterministic_for_same_inputs() {
        let seed = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let a = sign_request_b64("retrieve", 11, 1_700_000_000_000, &seed).unwrap();
        let b = sign_request_b64("retrieve", 11, 1_700_000_000_000, &seed).unwrap();
        assert_eq!(a, b);

        // Base64-decodes to exactly 64 bytes.
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&a)
            .unwrap();
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn test_sign_differs_on_namespace() {
        let seed = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let a = sign_request_b64("retrieve", 0, 1_700_000_000_000, &seed).unwrap();
        let b = sign_request_b64("retrieve", 11, 1_700_000_000_000, &seed).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_sign_round_trips_with_verify() {
        let seed = hex!("1111111111111111111111111111111111111111111111111111111111111111");
        let (pk, _sk) = ed25519::ed25519_key_pair_from_seed(&seed).unwrap();
        let msg = canonical_sign_string("retrieve", 11, 1_700_000_000_000);
        let sig_b64 = sign_request_b64("retrieve", 11, 1_700_000_000_000, &seed).unwrap();

        use base64::Engine;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        assert!(ed25519::verify(&sig, &pk, msg.as_bytes()).unwrap());
    }

    #[test]
    fn test_build_auth_fields_omits_namespace_when_zero() {
        let seed = [7u8; 32];
        let m = build_auth_fields(
            "retrieve",
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            0,
            1_700_000_000_000,
            &seed,
        )
        .unwrap();

        assert_eq!(m.get("pubkey").unwrap().as_str().unwrap().len(), 66);
        assert!(m.contains_key("pubkey_ed25519"));
        assert!(m.contains_key("signature"));
        assert!(m.contains_key("timestamp"));
        assert!(!m.contains_key("namespace"));
    }

    #[test]
    fn test_build_auth_fields_includes_namespace_when_nonzero() {
        let seed = [7u8; 32];
        let m = build_auth_fields(
            "retrieve",
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            -10,
            1_700_000_000_000,
            &seed,
        )
        .unwrap();
        assert_eq!(m.get("namespace").unwrap().as_i64().unwrap(), -10);
    }
}
