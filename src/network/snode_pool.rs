//! Snode pool management: caching, strike tracking, swarm lookups, and disk persistence.
//!
//! Port of `session::network::SnodePool`. Provides both the in-memory cache +
//! strike bookkeeping and the async bootstrap / refresh logic that talks to
//! seed nodes and a quorum of snodes respectively.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::network::key_types::Ed25519Pubkey;
use crate::network::rpc;
use crate::network::service_node::ServiceNode;
use crate::network::swarm::{self, SwarmId};
use crate::network::transport::{Transport, TransportError, TransportRequest};

/// Configuration for the snode pool, extracted from NetworkConfig.
#[derive(Debug, Clone)]
pub struct SnodePoolConfig {
    pub cache_directory: Option<PathBuf>,
    pub fallback_snode_pool_path: Option<PathBuf>,
    pub cache_expiration_secs: u64,
    pub cache_min_lifetime_ms: u64,
    pub enforce_subnet_diversity: bool,
    pub cache_min_size: usize,
    pub cache_min_swarm_size: usize,
    pub cache_num_nodes_to_use_for_refresh: u8,
    pub cache_min_num_refresh_presence_to_include_node: u8,
    pub cache_node_strike_threshold: u16,
}

impl Default for SnodePoolConfig {
    fn default() -> Self {
        Self {
            cache_directory: None,
            fallback_snode_pool_path: None,
            cache_expiration_secs: 2 * 60 * 60,
            cache_min_lifetime_ms: 2000,
            enforce_subnet_diversity: true,
            cache_min_size: 12,
            cache_min_swarm_size: 3,
            cache_num_nodes_to_use_for_refresh: 3,
            cache_min_num_refresh_presence_to_include_node: 2,
            cache_node_strike_threshold: 3,
        }
    }
}

/// The snode pool: maintains a cache of service nodes with strike tracking
/// and swarm caching.
pub struct SnodePool {
    config: SnodePoolConfig,
    snode_cache: Vec<ServiceNode>,
    all_swarms: Vec<(SwarmId, Vec<ServiceNode>)>,
    snode_strikes: HashMap<Ed25519Pubkey, u16>,
    cache_file_path: Option<PathBuf>,
}

impl SnodePool {
    pub fn new(config: SnodePoolConfig) -> Self {
        let cache_file_path = config
            .cache_directory
            .as_ref()
            .map(|dir| dir.join("snode_pool_cache"));

        Self {
            config,
            snode_cache: Vec::new(),
            all_swarms: Vec::new(),
            snode_strikes: HashMap::new(),
            cache_file_path,
        }
    }

    /// Returns the number of nodes in the pool.
    pub fn size(&self) -> usize {
        self.snode_cache.len()
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.snode_cache.is_empty()
    }

    /// Returns a borrowed view of the current cache.
    pub fn snodes(&self) -> &[ServiceNode] {
        &self.snode_cache
    }

    /// Adds nodes to the cache and regenerates swarms.
    pub fn add_nodes(&mut self, nodes: Vec<ServiceNode>) {
        // Deduplicate by pubkey
        for node in nodes {
            if !self
                .snode_cache
                .iter()
                .any(|n| n.ed25519_pubkey == node.ed25519_pubkey)
            {
                self.snode_cache.push(node);
            }
        }
        self.regenerate_swarms();
    }

    /// Replaces the entire cache with the given nodes.
    pub fn set_nodes(&mut self, nodes: Vec<ServiceNode>) {
        self.snode_cache = nodes;
        self.regenerate_swarms();
    }

    /// Clears the cache entirely.
    pub fn clear_cache(&mut self) {
        self.snode_cache.clear();
        self.all_swarms.clear();
    }

    /// Gets random unused nodes from the pool, excluding the given list.
    pub fn get_unused_nodes(&self, count: usize, exclude: &[ServiceNode]) -> Vec<ServiceNode> {
        use rand::seq::SliceRandom;

        let available: Vec<&ServiceNode> = self
            .snode_cache
            .iter()
            .filter(|n| !exclude.iter().any(|e| e.ed25519_pubkey == n.ed25519_pubkey))
            .collect();

        let mut rng = rand::rng();
        let mut shuffled: Vec<&ServiceNode> = available;
        shuffled.shuffle(&mut rng);

        shuffled.into_iter().take(count).cloned().collect()
    }

    /// Gets the swarm for a given pubkey.
    pub fn get_swarm(
        &self,
        swarm_pubkey: &crate::network::key_types::X25519Pubkey,
    ) -> Option<(SwarmId, Vec<ServiceNode>)> {
        if self.all_swarms.is_empty() {
            return None;
        }
        swarm::get_swarm(swarm_pubkey, &self.all_swarms)
    }

    // -----------------------------------------------------------------------
    // Strike tracking
    // -----------------------------------------------------------------------

    /// Records a failure for a node. If `permanent`, removes it from the cache.
    pub fn record_node_failure(&mut self, pubkey: &Ed25519Pubkey, permanent: bool) {
        if permanent {
            self.snode_cache.retain(|n| n.ed25519_pubkey != *pubkey);
            self.snode_strikes.remove(pubkey);
            self.regenerate_swarms();
            return;
        }

        let count = self.snode_strikes.entry(*pubkey).or_insert(0);
        *count += 1;

        if *count >= self.config.cache_node_strike_threshold {
            self.snode_cache.retain(|n| n.ed25519_pubkey != *pubkey);
            self.snode_strikes.remove(pubkey);
            self.regenerate_swarms();
        }
    }

    /// Returns the strike count for a node.
    pub fn node_strike_count(&self, pubkey: &Ed25519Pubkey) -> u16 {
        self.snode_strikes.get(pubkey).copied().unwrap_or(0)
    }

    /// Clears all strike records.
    pub fn clear_node_strikes(&mut self) {
        self.snode_strikes.clear();
    }

    // -----------------------------------------------------------------------
    // Disk persistence
    // -----------------------------------------------------------------------

    /// Saves the cache to disk in pipe-delimited format.
    pub fn save_to_disk(&self) -> std::io::Result<()> {
        let path = match &self.cache_file_path {
            Some(p) => p,
            None => return Ok(()),
        };

        let mut content = String::new();
        for node in &self.snode_cache {
            content.push_str(&node.to_disk());
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Loads the cache from disk.
    pub fn load_from_disk(&mut self) -> std::io::Result<()> {
        let path = match &self.cache_file_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        if !path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&path)?;
        let mut nodes = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match ServiceNode::from_disk(line) {
                Ok(node) => nodes.push(node),
                Err(e) => {
                    tracing::warn!("Failed to parse cached snode: {}", e);
                }
            }
        }

        self.snode_cache = nodes;
        self.regenerate_swarms();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn regenerate_swarms(&mut self) {
        self.all_swarms = swarm::generate_swarms(&self.snode_cache);
    }
}

// ---------------------------------------------------------------------------
// Live networking: seed-node bootstrap + snode quorum refresh
// ---------------------------------------------------------------------------

/// Error produced by the async bootstrap / refresh flows.
#[derive(Debug, thiserror::Error)]
pub enum SnodePoolNetworkError {
    /// Transport-level error reaching a seed or snode.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// Seed / snode returned a non-2xx status.
    #[error("seed returned status {0}")]
    BadStatus(u16),
    /// The response could not be parsed as JSON or the JSON was malformed.
    #[error("parse: {0}")]
    Parse(String),
    /// All known sources returned no usable nodes.
    #[error("all seeds failed")]
    AllSeedsFailed,
    /// Refresh quorum could not be reached (not enough candidates agreed).
    #[error("refresh quorum not reached")]
    NoQuorum,
}

/// Default seed-node HTTPS URLs used for bootstrap. Standard TLS.
pub const DEFAULT_SEED_URLS: &[&str] = &[
    "https://seed1.getsession.org:4443/json_rpc",
    "https://seed2.getsession.org:4443/json_rpc",
    "https://seed3.getsession.org:4443/json_rpc",
];

/// Default request timeout for seed / snode list calls.
pub const DEFAULT_POOL_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Number of snodes queried in parallel during refresh.
const REFRESH_QUORUM_SIZE: u8 = 3;
/// Minimum number of refresh responses a candidate must appear in to be kept.
const REFRESH_MIN_AGREE: u8 = 2;

impl SnodePool {
    /// Bootstraps the pool from a random seed node (TLS-verified).
    ///
    /// Tries each URL in `seed_urls` in a random order until one returns a
    /// usable list. On success, replaces the current cache.
    pub async fn bootstrap_from_seeds<T: Transport>(
        &mut self,
        transport: &T,
        seed_urls: &[&str],
    ) -> Result<usize, SnodePoolNetworkError> {
        use rand::seq::SliceRandom;

        if seed_urls.is_empty() {
            return Err(SnodePoolNetworkError::AllSeedsFailed);
        }

        let mut shuffled: Vec<&&str> = seed_urls.iter().collect();
        let mut rng = rand::rng();
        shuffled.shuffle(&mut rng);

        let mut last_err: Option<SnodePoolNetworkError> = None;
        for url in shuffled {
            match fetch_service_nodes(transport, url, /* accept_invalid_certs */ false).await {
                Ok(nodes) if !nodes.is_empty() => {
                    self.set_nodes(nodes.clone());
                    return Ok(nodes.len());
                }
                Ok(_) => last_err = Some(SnodePoolNetworkError::Parse("empty list".into())),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(SnodePoolNetworkError::AllSeedsFailed))
    }

    /// Refreshes the pool from a quorum of random snodes already in the cache.
    ///
    /// * Picks up to 3 random snodes and asks each for its current active
    ///   service-node list.
    /// * Keeps only nodes seen by ≥ 2 responders.
    ///
    /// Each contacted snode uses `accept_invalid_certs = true` (self-signed).
    ///
    /// On success, replaces the cache with the quorum-agreed set.
    pub async fn refresh<T: Transport>(
        &mut self,
        transport: &T,
    ) -> Result<usize, SnodePoolNetworkError> {
        use rand::seq::SliceRandom;

        if self.snode_cache.is_empty() {
            return Err(SnodePoolNetworkError::NoQuorum);
        }

        let mut candidates: Vec<ServiceNode> = self.snode_cache.clone();
        let mut rng = rand::rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(REFRESH_QUORUM_SIZE as usize);

        let mut responses: Vec<Vec<ServiceNode>> = Vec::new();
        for node in &candidates {
            let url = format!("https://{}/json_rpc", node.to_https_string());
            match fetch_service_nodes(transport, &url, /* self-signed */ true).await {
                Ok(nodes) if !nodes.is_empty() => responses.push(nodes),
                Ok(_) => {}
                Err(_) => {}
            }
        }

        if (responses.len() as u8) < REFRESH_MIN_AGREE {
            return Err(SnodePoolNetworkError::NoQuorum);
        }

        // Tally by ed25519 pubkey across responses (deduplicated within each
        // response set).
        let mut tally: HashMap<Ed25519Pubkey, (ServiceNode, u8)> = HashMap::new();
        for list in &responses {
            let mut seen: std::collections::HashSet<Ed25519Pubkey> = Default::default();
            for node in list {
                if seen.insert(node.ed25519_pubkey) {
                    tally
                        .entry(node.ed25519_pubkey)
                        .and_modify(|e| e.1 += 1)
                        .or_insert_with(|| (node.clone(), 1));
                }
            }
        }

        let agreed: Vec<ServiceNode> = tally
            .into_values()
            .filter(|(_, count)| *count >= REFRESH_MIN_AGREE)
            .map(|(n, _)| n)
            .collect();

        if agreed.is_empty() {
            return Err(SnodePoolNetworkError::NoQuorum);
        }

        let n = agreed.len();
        self.set_nodes(agreed);
        Ok(n)
    }
}

/// POSTs `get_n_service_nodes` to the given URL and parses the returned
/// `result.service_node_states` array into [`ServiceNode`]s.
///
/// Used by both bootstrap (seed URLs, strict TLS) and refresh (snode URLs,
/// self-signed).
async fn fetch_service_nodes<T: Transport>(
    transport: &T,
    url: &str,
    accept_invalid_certs: bool,
) -> Result<Vec<ServiceNode>, SnodePoolNetworkError> {
    let body = rpc::wrap_rpc_envelope(
        rpc::METHOD_GET_N_SERVICE_NODES,
        rpc::build_get_n_service_nodes_params(),
    );
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| SnodePoolNetworkError::Parse(format!("encode request: {e}")))?;

    let req = TransportRequest {
        url: url.to_string(),
        method: "POST".to_string(),
        body: body_bytes,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        timeout: DEFAULT_POOL_REQUEST_TIMEOUT,
        accept_invalid_certs,
    };

    let resp = transport.send_request(&req).await?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(SnodePoolNetworkError::BadStatus(resp.status_code));
    }

    parse_service_node_states(&resp.body)
}

/// Parses the `{"result":{"service_node_states":[...]}}` envelope into
/// [`ServiceNode`]s, silently skipping entries that fail to parse (matching
/// the tolerant behaviour of the Android/iOS clients).
fn parse_service_node_states(body: &[u8]) -> Result<Vec<ServiceNode>, SnodePoolNetworkError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| SnodePoolNetworkError::Parse(format!("json: {e}")))?;

    let states = v
        .get("result")
        .and_then(|r| r.get("service_node_states"))
        .and_then(|s| s.as_array())
        .ok_or_else(|| SnodePoolNetworkError::Parse("missing result.service_node_states".into()))?;

    let mut nodes = Vec::with_capacity(states.len());
    for entry in states {
        if let Ok(node) = ServiceNode::from_json(entry) {
            nodes.push(node);
        }
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::Ed25519Pubkey;

    fn make_node(id: u8, swarm_id: SwarmId) -> ServiceNode {
        let mut pk = [0u8; 32];
        pk[0] = id;
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey(pk),
            ip: [1, 2, 3, id],
            https_port: 443,
            omq_port: 22000,
            storage_server_version: [2, 11, 0],
            swarm_id,
            requested_unlock_height: 0,
        }
    }

    #[test]
    fn test_add_and_size() {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        assert!(pool.is_empty());

        pool.add_nodes(vec![make_node(1, 100), make_node(2, 100)]);
        assert_eq!(pool.size(), 2);

        // Adding duplicate should not increase size
        pool.add_nodes(vec![make_node(1, 100)]);
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_get_unused_nodes() {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes(vec![
            make_node(1, 100),
            make_node(2, 100),
            make_node(3, 200),
        ]);

        let exclude = vec![make_node(1, 100)];
        let unused = pool.get_unused_nodes(10, &exclude);
        assert_eq!(unused.len(), 2);
        assert!(
            unused
                .iter()
                .all(|n| n.ed25519_pubkey != make_node(1, 100).ed25519_pubkey)
        );
    }

    #[test]
    fn test_strike_tracking() {
        let mut pool = SnodePool::new(SnodePoolConfig {
            cache_node_strike_threshold: 3,
            ..Default::default()
        });

        let node = make_node(1, 100);
        pool.add_nodes(vec![node.clone()]);

        pool.record_node_failure(&node.ed25519_pubkey, false);
        assert_eq!(pool.node_strike_count(&node.ed25519_pubkey), 1);
        assert_eq!(pool.size(), 1);

        pool.record_node_failure(&node.ed25519_pubkey, false);
        assert_eq!(pool.node_strike_count(&node.ed25519_pubkey), 2);
        assert_eq!(pool.size(), 1);

        // Third strike removes the node
        pool.record_node_failure(&node.ed25519_pubkey, false);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_permanent_failure() {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        let node = make_node(1, 100);
        pool.add_nodes(vec![node.clone()]);

        pool.record_node_failure(&node.ed25519_pubkey, true);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_clear_cache() {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes(vec![make_node(1, 100), make_node(2, 200)]);
        assert_eq!(pool.size(), 2);

        pool.clear_cache();
        assert!(pool.is_empty());
    }

    fn seed_response_body(ed: &str, x: &str, ip: &str, port: u16) -> Vec<u8> {
        let body = serde_json::json!({
            "result": {
                "service_node_states": [{
                    "public_ip": ip,
                    "storage_port": port,
                    "storage_lmq_port": 22000,
                    "pubkey_x25519": x,
                    "pubkey_ed25519": ed,
                    "storage_server_version": [2, 11, 0],
                    "swarm_id": 12345,
                }]
            }
        });
        serde_json::to_vec(&body).unwrap()
    }

    #[tokio::test]
    async fn test_bootstrap_populates_from_seed_response() {
        use crate::network::transport::MockTransport;

        let t = MockTransport::new();
        t.route_ok_json(
            "seed1",
            seed_response_body(
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "95.216.33.113",
                22100,
            ),
        );

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        let n = pool
            .bootstrap_from_seeds(&t, &["https://seed1.example:4443/json_rpc"])
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(pool.size(), 1);
    }

    #[tokio::test]
    async fn test_bootstrap_falls_back_to_next_seed() {
        use crate::network::transport::{MockRoute, MockTransport, TransportResponse};

        let t = MockTransport::new();
        // seed1 returns 500 → skip, seed2 returns a valid pool.
        t.route(MockRoute {
            url_contains: "seed1".into(),
            body_contains: None,
            response: TransportResponse {
                status_code: 500,
                body: b"oops".to_vec(),
                headers: Vec::new(),
            },
        });
        t.route_ok_json(
            "seed2",
            seed_response_body(
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "95.216.33.113",
                22100,
            ),
        );

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        // Force seed1 first by ordering; shuffle may pick either, so just
        // accept that the call eventually succeeds.
        let n = pool
            .bootstrap_from_seeds(
                &t,
                &[
                    "https://seed1.example:4443/json_rpc",
                    "https://seed2.example:4443/json_rpc",
                ],
            )
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn test_bootstrap_all_fail_returns_error() {
        use crate::network::transport::{MockRoute, MockTransport, TransportResponse};

        let t = MockTransport::new();
        t.route(MockRoute {
            url_contains: "seed".into(),
            body_contains: None,
            response: TransportResponse {
                status_code: 500,
                body: b"oops".to_vec(),
                headers: Vec::new(),
            },
        });

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        let r = pool
            .bootstrap_from_seeds(&t, &["https://seed1.example:4443/json_rpc"])
            .await;
        assert!(matches!(r, Err(SnodePoolNetworkError::BadStatus(500))));
    }

    #[tokio::test]
    async fn test_refresh_quorum_keeps_agreed_nodes() {
        use crate::network::transport::MockTransport;

        // Seed pool with 3 well-known candidates that we will query.
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes(vec![
            make_node(10, 100),
            make_node(20, 100),
            make_node(30, 100),
        ]);

        // All three respond with the same one "good" node — it appears in
        // 3 of 3 responses (≥ 2) so it should survive.
        let t = MockTransport::new();
        let body = seed_response_body(
            "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "95.216.33.113",
            22100,
        );
        // MockTransport matches by URL substring — match any https URL.
        t.route_ok_json("json_rpc", body);

        let n = pool.refresh(&t).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(pool.size(), 1);
    }

    #[tokio::test]
    async fn test_refresh_no_quorum_errors() {
        use crate::network::transport::MockTransport;

        let mut pool = SnodePool::new(SnodePoolConfig::default());
        pool.add_nodes(vec![
            make_node(10, 100),
            make_node(20, 100),
            make_node(30, 100),
        ]);

        // Every snode responds with a DIFFERENT single node, so no entry is
        // seen by ≥2 responders.
        let t = MockTransport::new();
        // The routes below are matched in-order; we hard-code three distinct
        // bodies keyed by the snode IP substring.
        for (id, ip) in [("11", "1.2.3.10"), ("22", "1.2.3.20"), ("33", "1.2.3.30")] {
            let pk = format!(
                "{}00000000000000000000000000000000000000000000000000000000000000",
                id
            );
            t.route_ok_json(
                ip,
                seed_response_body(
                    &pk,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "95.216.33.113",
                    22100,
                ),
            );
        }

        let r = pool.refresh(&t).await;
        assert!(matches!(r, Err(SnodePoolNetworkError::NoQuorum)));
    }

    #[test]
    fn test_clear_strikes() {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        let node = make_node(1, 100);
        pool.add_nodes(vec![node.clone()]);
        pool.record_node_failure(&node.ed25519_pubkey, false);
        assert_eq!(pool.node_strike_count(&node.ed25519_pubkey), 1);

        pool.clear_node_strikes();
        assert_eq!(pool.node_strike_count(&node.ed25519_pubkey), 0);
    }
}
