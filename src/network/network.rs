//! Top-level `Network` facade — single entry point the Flutter bridge calls.
//!
//! Responsibilities:
//!
//! 1. Own the [`SnodePool`][crate::network::snode_pool::SnodePool],
//!    [`PathManager`][crate::network::routing::path_manager::PathManager]
//!    and the [`Transport`][crate::network::transport::Transport].
//! 2. Bootstrap the pool on first use (from seed nodes).
//! 3. Route every snode RPC through a 3-hop onion path.
//! 4. Handle `421 Misdirected` (swarm moved) with a single retry.
//! 5. Handle transient transport / decryption errors with exponential backoff.
//!
//! The facade is `Send + Sync` and internally locks shared state, so callers
//! can stash a single `Arc<Network<T>>` for the app lifetime and call
//! [`Network::send_rpc`] concurrently.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Mutex;

use crate::network::key_types::X25519Pubkey;
use crate::network::onionreq::response_parser::DecryptedResponse;
use crate::network::routing::onion_request::{
    OnionRequestRouter, OnionRequestRouterConfig, OnionRouteError,
};
use crate::network::routing::path_manager::{
    PathCategory, PathManager, PathManagerConfig,
};
use crate::network::rpc;
use crate::network::snode_pool::{
    SnodePool, SnodePoolConfig, SnodePoolNetworkError, DEFAULT_SEED_URLS,
};
use crate::network::transport::Transport;
use crate::network::types::{NetworkDestination, ServerDestination};

/// Top-level configuration for [`Network`]. All fields have sensible
/// defaults — override only when you need to.
#[derive(Clone)]
pub struct NetworkConfig {
    /// Config for the snode pool.
    pub pool: SnodePoolConfig,
    /// Config for the per-category path pool.
    pub paths: PathManagerConfig,
    /// Config for the onion router.
    pub router: OnionRequestRouterConfig,
    /// Seed node URLs used when the pool is empty.
    pub seed_urls: Vec<String>,
    /// Maximum attempts to resend a request on transient failures.
    pub max_attempts: u8,
    /// Base backoff between retries. Doubles on each attempt.
    pub retry_base_delay: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            pool: SnodePoolConfig::default(),
            paths: PathManagerConfig::default(),
            router: OnionRequestRouterConfig::default(),
            seed_urls: DEFAULT_SEED_URLS.iter().map(|s| s.to_string()).collect(),
            max_attempts: 3,
            retry_base_delay: Duration::from_millis(250),
        }
    }
}

/// Errors returned by [`Network::send_rpc`].
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Snode pool bootstrap or refresh failed.
    #[error("pool: {0}")]
    Pool(#[from] SnodePoolNetworkError),
    /// Swarm lookup for the target pubkey failed.
    #[error("swarm: {0}")]
    Swarm(#[from] crate::network::swarm::SwarmFetchError),
    /// Onion routing failed after all retries were exhausted.
    #[error("route: {0}")]
    Route(#[from] OnionRouteError),
    /// Request could not be serialised.
    #[error("encode: {0}")]
    Encode(String),
    /// All retries exhausted.
    #[error("exhausted {0} attempts")]
    Exhausted(u8),
}

/// Top-level network facade. `T` is any [`Transport`] implementation —
/// usually [`HttpTransport`][crate::network::transport::HttpTransport] in
/// production, or `MockTransport` in tests.
pub struct Network<T: Transport + Clone + 'static> {
    config: NetworkConfig,
    transport: T,
    pool: Arc<Mutex<SnodePool>>,
    paths: Arc<Mutex<PathManager>>,
    router: OnionRequestRouter,
}

impl<T: Transport + Clone + 'static> Network<T> {
    /// Creates a new network facade. Nothing is bootstrapped yet; the first
    /// call to [`Network::send_rpc`] (or an explicit
    /// [`Network::ensure_bootstrapped`]) will populate the pool.
    pub fn new(config: NetworkConfig, transport: T) -> Self {
        let pool = SnodePool::new(config.pool.clone());
        let paths = PathManager::new(config.paths.clone());
        let router = OnionRequestRouter::new(config.router.clone());
        Self {
            config,
            transport,
            pool: Arc::new(Mutex::new(pool)),
            paths: Arc::new(Mutex::new(paths)),
            router,
        }
    }

    /// Ensures the snode pool has at least some nodes. Idempotent: if already
    /// bootstrapped, returns immediately.
    pub async fn ensure_bootstrapped(&self) -> Result<(), NetworkError> {
        let mut pool = self.pool.lock().await;
        if !pool.is_empty() {
            return Ok(());
        }
        let seeds: Vec<&str> = self.config.seed_urls.iter().map(|s| s.as_str()).collect();
        pool.bootstrap_from_seeds(&self.transport, &seeds).await?;
        Ok(())
    }

    /// Sends an onion-routed `store` RPC.
    ///
    /// On a `421 Misdirected` the library transparently re-fetches the swarm
    /// and retries once. Other transient failures are retried with
    /// exponential backoff up to [`NetworkConfig::max_attempts`] times.
    pub async fn send_store(
        &self,
        params: &rpc::StoreParams<'_>,
    ) -> Result<DecryptedResponse, NetworkError> {
        let body = rpc::build_store_params(params).map_err(|e| {
            NetworkError::Encode(format!("build store params: {e}"))
        })?;
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| NetworkError::Encode(e.to_string()))?;

        let destination = self.destination_for_swarm(params.pubkey).await?;
        self.send_with_retry(
            PathCategory::Standard,
            &destination,
            rpc::METHOD_STORE,
            &body_bytes,
            Some(params.pubkey),
        )
        .await
    }

    /// Sends an authenticated `retrieve` RPC.
    pub async fn send_retrieve(
        &self,
        params: &rpc::RetrieveParams<'_>,
    ) -> Result<DecryptedResponse, NetworkError> {
        let body = rpc::build_retrieve_params(params).map_err(|e| {
            NetworkError::Encode(format!("build retrieve params: {e}"))
        })?;
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| NetworkError::Encode(e.to_string()))?;

        let destination = self.destination_for_swarm(params.pubkey).await?;
        self.send_with_retry(
            PathCategory::Standard,
            &destination,
            rpc::METHOD_RETRIEVE,
            &body_bytes,
            Some(params.pubkey),
        )
        .await
    }

    /// Sends an onion-routed request to a file server and returns binary-safe response bytes.
    pub async fn send_server_request(
        &self,
        method: &str,
        protocol: &str,
        host: &str,
        port: Option<u16>,
        server_x25519_pubkey_hex: &str,
        endpoint: &str,
        headers: Vec<(String, String)>,
        body: Option<&[u8]>,
    ) -> Result<DecryptedResponse, NetworkError> {
        self.ensure_bootstrapped().await?;
        let x25519_pubkey = X25519Pubkey::from_hex(server_x25519_pubkey_hex)
            .map_err(|e| NetworkError::Encode(format!("invalid file server X25519 key: {e}")))?;
        let destination = NetworkDestination::Server(ServerDestination {
            protocol: protocol.to_owned(),
            host: host.to_owned(),
            x25519_pubkey,
            port,
            headers: Some(headers),
            method: method.to_owned(),
        });
        let body = body.unwrap_or_default();
        self.send_with_retry(PathCategory::File, &destination, endpoint, body, None)
            .await
    }

    /// Arbitrary snode RPC — for callers that need a method outside the typed
    /// helpers. `swarm_pubkey_hex` (if provided) is used to pick the correct
    /// swarm snode as destination and to retry on 421.
    pub async fn send_rpc(
        &self,
        method: &str,
        params: Value,
        swarm_pubkey_hex: Option<&str>,
    ) -> Result<DecryptedResponse, NetworkError> {
        let body_bytes =
            serde_json::to_vec(&params).map_err(|e| NetworkError::Encode(e.to_string()))?;

        let destination = match swarm_pubkey_hex {
            Some(pk) => self.destination_for_swarm(pk).await?,
            None => self.any_snode_destination().await?,
        };

        self.send_with_retry(
            PathCategory::Standard,
            &destination,
            method,
            &body_bytes,
            swarm_pubkey_hex,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn destination_for_swarm(
        &self,
        pubkey_hex: &str,
    ) -> Result<NetworkDestination, NetworkError> {
        self.ensure_bootstrapped().await?;

        // Make sure we have at least one live path for the onion-wrapped
        // swarm lookup. Build lazily under both locks (same pattern as
        // `send_with_retry`).
        {
            let mut paths = self.paths.lock().await;
            let pool = self.pool.lock().await;
            let _ = paths.build_up_to_target(PathCategory::Standard, &pool);
        }

        // Route the `get_snodes_for_pubkey` call over a 3-hop onion path so
        // the answering snode never sees the caller's IP.
        let snodes = {
            let mut paths = self.paths.lock().await;
            let pool = self.pool.lock().await;
            crate::network::swarm::fetch_swarm_via_onion(
                &self.router,
                &self.transport,
                &pool,
                &mut paths,
                pubkey_hex,
            )
            .await?
        };

        let snode = snodes.into_iter().next().ok_or_else(|| {
            NetworkError::Swarm(
                crate::network::swarm::SwarmFetchError::Parse("empty swarm".into()),
            )
        })?;
        Ok(NetworkDestination::ServiceNode(snode))
    }

    async fn any_snode_destination(&self) -> Result<NetworkDestination, NetworkError> {
        self.ensure_bootstrapped().await?;
        let pool = self.pool.lock().await;
        let mut candidates = pool.get_unused_nodes(1, &[]);
        let snode = candidates
            .pop()
            .ok_or(NetworkError::Pool(SnodePoolNetworkError::AllSeedsFailed))?;
        Ok(NetworkDestination::ServiceNode(snode))
    }

    async fn send_with_retry(
        &self,
        category: PathCategory,
        destination: &NetworkDestination,
        endpoint: &str,
        body: &[u8],
        swarm_pubkey_hex: Option<&str>,
    ) -> Result<DecryptedResponse, NetworkError> {
        let mut delay = self.config.retry_base_delay;
        let mut current_dest = destination.clone();

        for attempt in 0..self.config.max_attempts {
            // Make sure we have paths.
            {
                let mut paths = self.paths.lock().await;
                let pool = self.pool.lock().await;
                let _ = paths.build_up_to_target(category, &pool);
            }

            let result = {
                let mut paths = self.paths.lock().await;
                let pool = self.pool.lock().await;
                self.router
                    .send(
                        &self.transport,
                        &pool,
                        &mut paths,
                        category,
                        &current_dest,
                        endpoint,
                        body,
                    )
                    .await
            };

            match result {
                Ok(resp) => {
                    // 421 Misdirected: swarm moved. Re-resolve once then retry.
                    if resp.status_code == 421 {
                        if let Some(pk) = swarm_pubkey_hex {
                            if let Ok(new_dest) = self.destination_for_swarm(pk).await {
                                current_dest = new_dest;
                                continue;
                            }
                        }
                        return Ok(resp);
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if attempt + 1 >= self.config.max_attempts {
                        return Err(NetworkError::Route(e));
                    }
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }

        Err(NetworkError::Exhausted(self.config.max_attempts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::Ed25519Pubkey;
    use crate::network::service_node::ServiceNode;
    use crate::network::swarm::INVALID_SWARM_ID;
    use crate::network::transport::{MockRoute, MockTransport, TransportResponse};
    use crate::crypto::ed25519 as ed;

    fn make_node_with_seed(seed_byte: u8) -> ServiceNode {
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

    fn seed_response_body(nodes: &[ServiceNode]) -> Vec<u8> {
        use serde_json::json;
        let arr: Vec<_> = nodes
            .iter()
            .map(|n| {
                json!({
                    "public_ip": n.host(),
                    "storage_port": n.https_port,
                    "storage_lmq_port": n.omq_port,
                    "pubkey_x25519": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "pubkey_ed25519": n.ed25519_pubkey.hex(),
                    "storage_server_version": [2, 11, 0],
                    "swarm_id": 42,
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "result": { "service_node_states": arr }
        }))
        .unwrap()
    }

    fn swarm_response_body(node: &ServiceNode) -> Vec<u8> {
        use serde_json::json;
        serde_json::to_vec(&json!({
            "snodes": [{
                "public_ip": node.host(),
                "storage_port": node.https_port,
                "storage_lmq_port": node.omq_port,
                "pubkey_x25519": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pubkey_ed25519": node.ed25519_pubkey.hex(),
                "storage_server_version": [2, 11, 0],
                "swarm_id": 42
            }]
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn test_ensure_bootstrapped_loads_from_seeds() {
        let nodes: Vec<ServiceNode> = (1..=12).map(make_node_with_seed).collect();

        let t = MockTransport::new();
        t.route_ok_json("seed1", seed_response_body(&nodes));

        let cfg = NetworkConfig {
            seed_urls: vec!["https://seed1.example:4443/json_rpc".to_string()],
            ..Default::default()
        };
        let net = Network::new(cfg, t);
        net.ensure_bootstrapped().await.unwrap();

        let pool = net.pool.lock().await;
        assert!(pool.size() >= 12);
    }

    /// When the onion pipeline is broken at the guard (502 on every
    /// `/onion_req/v2` hit), `send_rpc` must bubble up an error instead of
    /// hanging or returning a fake success. Because swarm lookup is now
    /// itself onion-wrapped, the very first onion call (the swarm lookup)
    /// is what actually fails here — surfaced as `NetworkError::Swarm`.
    #[tokio::test]
    async fn test_send_rpc_fails_when_onion_pipeline_is_broken() {
        let nodes: Vec<ServiceNode> = (1..=20).map(make_node_with_seed).collect();

        let t = MockTransport::new();
        t.route_ok_json("seed1", seed_response_body(&nodes));
        // Every onion request → 502. Covers both the swarm lookup and any
        // subsequent store/retrieve attempts.
        t.route(MockRoute {
            url_contains: "onion_req".into(),
            body_contains: None,
            response: TransportResponse {
                status_code: 502,
                body: b"no".to_vec(),
                headers: Vec::new(),
            },
        });

        let cfg = NetworkConfig {
            seed_urls: vec!["https://seed1.example:4443/json_rpc".to_string()],
            max_attempts: 2,
            retry_base_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let net = Network::new(cfg, t);

        let r = net
            .send_rpc(
                "retrieve",
                serde_json::json!({"pubkey": "05aaaa"}),
                Some("05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )
            .await;

        // Swarm lookup fails because the guard returns 502; surface as Swarm.
        assert!(matches!(r, Err(NetworkError::Swarm(_))));
    }
}
