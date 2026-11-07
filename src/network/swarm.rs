//! Swarm ID computation and closest-swarm lookup.
//!
//! Maps public keys into swarm space via XOR-folding and finds the closest
//! swarm on the ID ring using wrapping distance.

use std::collections::HashMap;

use crate::network::key_types::X25519Pubkey;
use crate::network::service_node::ServiceNode;

/// Swarm identifier type (u64).
pub type SwarmId = u64;
/// Sentinel value indicating an invalid or unassigned swarm ID.
pub const INVALID_SWARM_ID: SwarmId = u64::MAX;

/// Maps a public key into swarm ID space by XOR-folding the 32 bytes into 8 bytes,
/// then interpreting as big-endian u64.
///
/// Mirrors `session::network::swarm::pubkey_to_swarm_space` from the C++ code.
pub fn pubkey_to_swarm_space(pk: &X25519Pubkey) -> SwarmId {
    let bytes = pk.as_bytes();
    let mut result: u64 = 0;

    // XOR four 8-byte chunks together
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        // In the C++ code, the bytes are memcpy'd into a u64 (native endian),
        // then after XOR the result is big_to_host. Since we read as native-endian
        // and then convert, we replicate by reading as little-endian on all platforms
        // and then at the end treating the result as big-endian.
        result ^= u64::from_ne_bytes(buf);
    }

    // The C++ does big_to_host_inplace on the XOR result
    u64::from_be(result)
}

/// Groups service nodes by their swarm_id and returns a sorted list of
/// (swarm_id, nodes) pairs.
pub fn generate_swarms(nodes: &[ServiceNode]) -> Vec<(SwarmId, Vec<ServiceNode>)> {
    let mut grouped: HashMap<SwarmId, Vec<ServiceNode>> = HashMap::new();

    for node in nodes {
        grouped.entry(node.swarm_id).or_default().push(node.clone());
    }

    let mut result: Vec<(SwarmId, Vec<ServiceNode>)> = grouped.into_iter().collect();
    result.sort_by_key(|(id, _)| *id);
    result
}

/// Finds the closest swarm to the given pubkey using the swarm ID ring.
///
/// Uses wrapping arithmetic distance, matching the C++ implementation.
pub fn get_swarm(
    swarm_pubkey: &X25519Pubkey,
    all_swarms: &[(SwarmId, Vec<ServiceNode>)],
) -> Option<(SwarmId, Vec<ServiceNode>)> {
    if all_swarms.is_empty() {
        return None;
    }

    if all_swarms.len() == 1 {
        return Some(all_swarms[0].clone());
    }

    let swarm_id = pubkey_to_swarm_space(swarm_pubkey);

    // Find the first swarm with id >= swarm_id (right boundary)
    let right_idx = all_swarms
        .iter()
        .position(|(id, _)| *id >= swarm_id);

    let right_idx = right_idx.unwrap_or(0); // wrap around if beyond end

    // Left is the one just before right (with wraparound)
    let left_idx = if right_idx == 0 {
        all_swarms.len() - 1
    } else {
        right_idx - 1
    };

    // Use wrapping distance
    let d_right = all_swarms[right_idx].0.wrapping_sub(swarm_id);
    let d_left = swarm_id.wrapping_sub(all_swarms[left_idx].0);

    let chosen = if d_right < d_left {
        right_idx
    } else {
        left_idx
    };

    Some(all_swarms[chosen].clone())
}

// ---------------------------------------------------------------------------
// Live swarm lookup
// ---------------------------------------------------------------------------

use std::time::Duration;

use crate::network::routing::onion_request::{OnionRequestRouter, OnionRouteError};
use crate::network::routing::path_manager::{PathCategory, PathManager};
use crate::network::rpc;
use crate::network::snode_pool::SnodePool;
use crate::network::transport::{Transport, TransportError, TransportRequest};
use crate::network::types::NetworkDestination;

/// Error from an async swarm fetch.
#[derive(Debug, thiserror::Error)]
pub enum SwarmFetchError {
    /// Transport-level error.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// Snode returned a non-2xx status.
    #[error("snode returned status {0}")]
    BadStatus(u16),
    /// Response was not valid JSON or was malformed.
    #[error("parse: {0}")]
    Parse(String),
    /// The pool had no snodes to ask.
    #[error("snode pool is empty")]
    PoolEmpty,
    /// Onion routing failed while fetching the swarm.
    #[error("onion: {0}")]
    Onion(Box<OnionRouteError>),
}

/// Default request timeout for swarm lookups.
pub const DEFAULT_SWARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Queries a random snode from the pool **directly** for
/// `get_snodes_for_pubkey`.
///
/// `pubkey_hex` is the target Session id (`05...` for users, `03...` for
/// closed groups). Returns the swarm — the list of snodes that host messages
/// for that pubkey.
///
/// # Privacy caveat
///
/// This function hits the snode over plain HTTPS — the contacted snode sees
/// both the caller's IP and the target pubkey. **Production code should use
/// [`fetch_swarm_via_onion`]** so the caller's IP never reaches the snode
/// that answers the swarm query; the direct variant is kept for tooling /
/// integration tests only.
pub async fn fetch_swarm<T: Transport>(
    pool: &SnodePool,
    transport: &T,
    pubkey_hex: &str,
) -> Result<Vec<ServiceNode>, SwarmFetchError> {
    let candidates = pool.get_unused_nodes(1, &[]);
    let snode = candidates
        .into_iter()
        .next()
        .ok_or(SwarmFetchError::PoolEmpty)?;

    // Direct snode RPC goes to /storage_rpc/v1. The /json_rpc path is
    // only used for oxend-style calls (seed bootstrap, pool refresh).
    let url = format!("https://{}/storage_rpc/v1", snode.to_https_string());
    let body = rpc::wrap_rpc_envelope(
        rpc::METHOD_GET_SWARM,
        rpc::build_get_swarm_params(pubkey_hex),
    );
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| SwarmFetchError::Parse(format!("encode request: {e}")))?;

    let req = TransportRequest {
        url,
        method: "POST".to_string(),
        body: body_bytes,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        timeout: DEFAULT_SWARM_REQUEST_TIMEOUT,
        accept_invalid_certs: true,
    };

    let resp = transport.send_request(&req).await?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(SwarmFetchError::BadStatus(resp.status_code));
    }

    parse_swarm_response(&resp.body)
}

/// Parses the response from `get_snodes_for_pubkey`.
///
/// Accepts both shapes seen in the wild:
/// * `{"snodes": [...]}` — direct shape used by snodes
/// * `{"result": {"snodes": [...]}}` — wrapped shape from some paths
fn parse_swarm_response(body: &[u8]) -> Result<Vec<ServiceNode>, SwarmFetchError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| SwarmFetchError::Parse(format!("json: {e}")))?;

    let arr = v
        .get("snodes")
        .or_else(|| v.get("result").and_then(|r| r.get("snodes")))
        .and_then(|s| s.as_array())
        .ok_or_else(|| SwarmFetchError::Parse("missing snodes array".into()))?;

    let mut nodes = Vec::with_capacity(arr.len());
    for entry in arr {
        if let Ok(node) = ServiceNode::from_json(entry) {
            nodes.push(node);
        }
    }

    if nodes.is_empty() {
        return Err(SwarmFetchError::Parse("no parseable snodes".into()));
    }
    Ok(nodes)
}

/// Queries a random snode for `get_snodes_for_pubkey` **over a 3-hop onion
/// path**.
///
/// This is the privacy-preserving variant — matches what
/// `OnionSessionApiExecutor` does in the official Android client. The
/// destination snode sees the pubkey being looked up, but the path's guard
/// is the only node that sees the caller's IP, and the guard only sees
/// encrypted blobs.
///
/// `paths` is used (and mutated) to build or re-use a standard-category
/// onion path. `pool` is sampled to pick a random snode as the onion
/// request's final destination.
pub async fn fetch_swarm_via_onion<T: Transport>(
    router: &OnionRequestRouter,
    transport: &T,
    pool: &SnodePool,
    paths: &mut PathManager,
    pubkey_hex: &str,
) -> Result<Vec<ServiceNode>, SwarmFetchError> {
    // Pick a random snode as the onion request's final destination. The
    // exit hop will deliver the RPC to this snode — it's who answers the
    // `get_snodes_for_pubkey` query. The guard (first hop) sees our IP but
    // not which pubkey we're asking about; the destination sees the pubkey
    // but not our IP. Separation of concerns = privacy.
    let mut candidates = pool.get_unused_nodes(1, &[]);
    let dest_snode = candidates.pop().ok_or(SwarmFetchError::PoolEmpty)?;
    let destination = NetworkDestination::ServiceNode(dest_snode);

    let params = rpc::build_get_swarm_params(pubkey_hex);
    let body_bytes = serde_json::to_vec(&params)
        .map_err(|e| SwarmFetchError::Parse(format!("encode: {e}")))?;

    let resp = router
        .send(
            transport,
            pool,
            paths,
            PathCategory::Standard,
            &destination,
            rpc::METHOD_GET_SWARM,
            &body_bytes,
        )
        .await
        .map_err(|e| SwarmFetchError::Onion(Box::new(e)))?;

    // `resp.status_code` is the snode's HTTP-like status inside the onion
    // response. It's `i16`, so map to u16 for the error variant.
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(SwarmFetchError::BadStatus(resp.status_code.max(0) as u16));
    }

    let body_str = resp.body.as_deref().unwrap_or("");
    parse_swarm_response(body_str.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::Ed25519Pubkey;

    fn make_node(swarm_id: SwarmId, hex_suffix: u8) -> ServiceNode {
        let mut pk_bytes = [0u8; 32];
        pk_bytes[31] = hex_suffix;
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey(pk_bytes),
            ip: [1, 2, 3, 4],
            https_port: 443,
            omq_port: 22000,
            storage_server_version: [2, 11, 0],
            swarm_id,
            requested_unlock_height: 0,
        }
    }

    #[test]
    fn test_generate_swarms() {
        let nodes = vec![
            make_node(100, 1),
            make_node(200, 2),
            make_node(100, 3),
            make_node(300, 4),
        ];

        let swarms = generate_swarms(&nodes);
        assert_eq!(swarms.len(), 3);
        // Should be sorted by swarm_id
        assert_eq!(swarms[0].0, 100);
        assert_eq!(swarms[0].1.len(), 2);
        assert_eq!(swarms[1].0, 200);
        assert_eq!(swarms[1].1.len(), 1);
        assert_eq!(swarms[2].0, 300);
        assert_eq!(swarms[2].1.len(), 1);
    }

    #[test]
    fn test_get_swarm_single() {
        let swarms = vec![(100, vec![make_node(100, 1)])];
        let pk = X25519Pubkey([0u8; 32]);
        let result = get_swarm(&pk, &swarms).unwrap();
        assert_eq!(result.0, 100);
    }

    #[test]
    fn test_get_swarm_empty() {
        let pk = X25519Pubkey([0u8; 32]);
        assert!(get_swarm(&pk, &[]).is_none());
    }

    fn swarm_response_body(ed: &str, ip: &str, port: u16) -> Vec<u8> {
        let body = serde_json::json!({
            "snodes": [{
                "public_ip": ip,
                "storage_port": port,
                "storage_lmq_port": 22000,
                "pubkey_x25519": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pubkey_ed25519": ed,
                "storage_server_version": [2, 11, 0],
                "swarm_id": 12345
            }]
        });
        serde_json::to_vec(&body).unwrap()
    }

    #[tokio::test]
    async fn test_fetch_swarm_returns_snodes() {
        use crate::network::snode_pool::{SnodePool, SnodePoolConfig};
        use crate::network::transport::MockTransport;

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes(vec![make_node(100, 1)]);

        let t = MockTransport::new();
        t.route_ok_json(
            "storage_rpc",
            swarm_response_body(
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                "95.216.33.113",
                22100,
            ),
        );

        let snodes = fetch_swarm(
            &pool,
            &t,
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();

        assert_eq!(snodes.len(), 1);
        assert_eq!(snodes[0].host(), "95.216.33.113");
    }

    #[tokio::test]
    async fn test_fetch_swarm_empty_pool_errors() {
        use crate::network::snode_pool::{SnodePool, SnodePoolConfig};
        use crate::network::transport::MockTransport;

        let pool = SnodePool::new(SnodePoolConfig::default());
        let t = MockTransport::new();
        let r = fetch_swarm(
            &pool,
            &t,
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;
        assert!(matches!(r, Err(SwarmFetchError::PoolEmpty)));
    }

    #[tokio::test]
    async fn test_fetch_swarm_handles_wrapped_result() {
        use crate::network::snode_pool::{SnodePool, SnodePoolConfig};
        use crate::network::transport::MockTransport;

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes(vec![make_node(100, 1)]);

        let t = MockTransport::new();
        let body = serde_json::json!({
            "result": {
                "snodes": [{
                    "public_ip": "95.216.33.113",
                    "storage_port": 22100,
                    "storage_lmq_port": 22000,
                    "pubkey_x25519": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "pubkey_ed25519": "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                    "storage_server_version": [2, 11, 0],
                    "swarm_id": 42
                }]
            }
        });
        t.route_ok_json("storage_rpc", serde_json::to_vec(&body).unwrap());

        let snodes = fetch_swarm(
            &pool,
            &t,
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(snodes.len(), 1);
    }

    // ---------------------------------------------------------------------
    // fetch_swarm_via_onion
    // ---------------------------------------------------------------------

    /// Build a service node with a valid ed25519 curve point — required for
    /// the onion builder which derives x25519 from the ed key.
    fn make_real_node(seed_byte: u8) -> ServiceNode {
        use crate::crypto::ed25519 as ed;
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        if seed_byte == 0 {
            seed[1] = 1;
        }
        let (pk, _sk) = ed::ed25519_key_pair_from_seed(&seed).unwrap();
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey(pk),
            ip: [10, 0, 0, seed_byte],
            https_port: 443,
            omq_port: 22000,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        }
    }

    #[tokio::test]
    async fn test_fetch_swarm_via_onion_pool_empty_errors() {
        use crate::network::routing::onion_request::{
            OnionRequestRouter, OnionRequestRouterConfig,
        };
        use crate::network::routing::path_manager::{PathManager, PathManagerConfig};
        use crate::network::snode_pool::{SnodePool, SnodePoolConfig};
        use crate::network::transport::MockTransport;

        let pool = SnodePool::new(SnodePoolConfig::default());
        let mut paths = PathManager::new(PathManagerConfig::default());
        let router = OnionRequestRouter::new(OnionRequestRouterConfig::default());
        let t = MockTransport::new();

        let r = fetch_swarm_via_onion(
            &router,
            &t,
            &pool,
            &mut paths,
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;
        assert!(matches!(r, Err(SwarmFetchError::PoolEmpty)));
    }

    #[tokio::test]
    async fn test_fetch_swarm_via_onion_guard_502_surfaces_as_onion_error() {
        use crate::network::routing::onion_request::{
            OnionRequestRouter, OnionRequestRouterConfig,
        };
        use crate::network::routing::path_manager::{PathCategory, PathManager, PathManagerConfig};
        use crate::network::snode_pool::{SnodePool, SnodePoolConfig};
        use crate::network::transport::{MockRoute, MockTransport, TransportResponse};

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes((1..=20).map(make_real_node).collect());

        let mut paths = PathManager::new(PathManagerConfig {
            target_paths_per_category: 1,
            path_strike_threshold: 1, // retire on strike
        });
        paths.build_up_to_target(PathCategory::Standard, &pool).unwrap();

        let router = OnionRequestRouter::new(OnionRequestRouterConfig::default());
        let t = MockTransport::new();
        t.route(MockRoute {
            url_contains: "onion_req".into(),
            body_contains: None,
            response: TransportResponse {
                status_code: 502,
                body: b"no".to_vec(),
                headers: Vec::new(),
            },
        });

        let r = fetch_swarm_via_onion(
            &router,
            &t,
            &pool,
            &mut paths,
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;
        assert!(matches!(r, Err(SwarmFetchError::Onion(_))));
    }
}
