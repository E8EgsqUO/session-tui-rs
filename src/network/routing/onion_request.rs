//! 3-hop onion request router.
//!
//! Glues [`PathManager`][crate::network::routing::path_manager::PathManager]
//! + [`Builder`][crate::network::onionreq::builder::Builder]
//! + [`Transport`][crate::network::transport::Transport]
//! + [`ResponseParser`][crate::network::onionreq::response_parser::ResponseParser]
//! together so callers can say "send this body to this destination" and
//! receive a decrypted response. All wire traffic leaves the device as an
//! onion-wrapped blob addressed to the path's guard snode — the direct IP of
//! the final destination never appears.
//!
//! The router is generic over the
//! [`Transport`][crate::network::transport::Transport] so it can be exercised
//! with [`MockTransport`][crate::network::transport::MockTransport] in tests.

use std::time::Duration;

use crate::network::onionreq::builder::{Builder, BuilderError};
use crate::network::onionreq::hop_encryption::EncryptType;
use crate::network::onionreq::response_parser::{
    DecryptedResponse, ResponseParser, ResponseParserError,
};
use crate::network::routing::path_manager::{
    PathCategory, PathManager, PathManagerError, PATH_HOPS,
};
use crate::network::snode_pool::SnodePool;
use crate::network::transport::{Transport, TransportError, TransportRequest};
use crate::network::types::NetworkDestination;

/// Configuration for the onion request router.
#[derive(Debug, Clone)]
pub struct OnionRequestRouterConfig {
    /// Maximum number of strikes before a path is retired.
    pub path_strike_threshold: u8,
    /// Maximum number of path-build attempts before giving up.
    pub path_build_retry_limit: u8,
    /// If true, only one path is maintained per category.
    pub single_path_mode: bool,
    /// If true, paths are not proactively built — each request builds on
    /// demand.
    pub disable_pre_build_paths: bool,
    /// Seconds between path rotations (caller-driven, informational).
    pub path_rotation_frequency_secs: u64,
    /// Timeout for a single guard-hop HTTP request.
    pub request_timeout: Duration,
}

impl Default for OnionRequestRouterConfig {
    fn default() -> Self {
        Self {
            path_strike_threshold: 3,
            path_build_retry_limit: 10,
            single_path_mode: false,
            disable_pre_build_paths: false,
            path_rotation_frequency_secs: 600,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Error returned by [`OnionRequestRouter::send`].
#[derive(Debug, thiserror::Error)]
pub enum OnionRouteError {
    /// Could not obtain a working onion path (pool too small, etc.).
    #[error("path: {0}")]
    Path(#[from] PathManagerError),
    /// The onion-request builder rejected the inputs.
    #[error("builder: {0}")]
    Builder(#[from] BuilderError),
    /// Transport layer error reaching the guard snode.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// Guard snode responded with a non-2xx status.
    #[error("guard returned status {0}: {1}")]
    BadStatus(u16, String),
    /// Response-parser error (decryption / format).
    #[error("response: {0}")]
    Response(#[from] ResponseParserError),
}

/// 3-hop onion request router.
pub struct OnionRequestRouter {
    /// Current router configuration.
    pub config: OnionRequestRouterConfig,
}

impl OnionRequestRouter {
    /// Creates a router with the given configuration.
    pub fn new(config: OnionRequestRouterConfig) -> Self {
        Self { config }
    }

    /// Sends a request to `destination` for the given `endpoint`, transporting
    /// `body_json` onion-wrapped over the path selected from the given path
    /// category.
    ///
    /// The function:
    /// 1. Picks a live path from `paths` (building one if empty).
    /// 2. Constructs the onion blob with [`Builder`].
    /// 3. POSTs it to the guard's `/onion_req/v2` endpoint via `transport`.
    /// 4. Decrypts the response with [`ResponseParser`].
    ///
    /// On transport / parse failure the path guard is struck in `paths` so
    /// the caller can retry with a fresh path.
    pub async fn send<T: Transport>(
        &self,
        transport: &T,
        pool: &SnodePool,
        paths: &mut PathManager,
        category: PathCategory,
        destination: &NetworkDestination,
        endpoint: &str,
        body_json: &[u8],
    ) -> Result<DecryptedResponse, OnionRouteError> {
        let prepared = self.prepare(pool, paths, category, destination, endpoint, body_json)?;
        let result = transport.send_request(&prepared.request).await;
        prepared.finish(result, |guard| paths.record_failure(category, guard))
    }

    /// The part of [`send`](Self::send) that needs the path manager and
    /// pool: pick (or build) a path and build the onion request. The caller
    /// can then release its locks for the network round trip.
    pub fn prepare(
        &self,
        pool: &SnodePool,
        paths: &mut PathManager,
        category: PathCategory,
        destination: &NetworkDestination,
        endpoint: &str,
        body_json: &[u8],
    ) -> Result<PreparedRequest, OnionRouteError> {
        // 1. Pick or build a path.
        let path = match paths.pick_path(category) {
            Some(p) => p,
            None => paths.build_one(category, pool)?,
        };

        // 2. Build the onion blob.
        let mut builder = Builder::make(
            destination,
            endpoint,
            &path.hops,
            EncryptType::XChaCha20,
        )?;
        let blob = builder.generate_onion_blob(Some(body_json))?;

        // 3. Send to the guard snode's /onion_req/v2 endpoint.
        let guard = path.guard();
        let url = format!("https://{}/onion_req/v2", guard.to_https_string());

        let req = TransportRequest {
            url,
            method: "POST".to_string(),
            body: blob,
            headers: Vec::new(),
            timeout: self.config.request_timeout,
            accept_invalid_certs: true,
        };

        let parser = ResponseParser::from_builder(&builder)?;
        Ok(PreparedRequest {
            request: req,
            guard: guard.ed25519_pubkey,
            parser,
        })
    }
}

/// An onion request ready to send, from [`OnionRequestRouter::prepare`].
pub struct PreparedRequest {
    pub request: TransportRequest,
    guard: crate::network::key_types::Ed25519Pubkey,
    parser: ResponseParser,
}

impl PreparedRequest {
    /// Check and decrypt the response. `record_failure` is called with the
    /// guard node when the path failed (the caller takes its lock for it).
    pub fn finish<E: Into<OnionRouteError>>(
        self,
        result: Result<crate::network::transport::TransportResponse, E>,
        record_failure: impl FnOnce(&crate::network::key_types::Ed25519Pubkey),
    ) -> Result<DecryptedResponse, OnionRouteError> {
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                record_failure(&self.guard);
                return Err(e.into());
            }
        };
        if resp.status_code < 200 || resp.status_code >= 300 {
            record_failure(&self.guard);
            let body = String::from_utf8_lossy(&resp.body);
            let detail: String = body.chars().take(512).collect();
            return Err(OnionRouteError::BadStatus(resp.status_code, detail));
        }
        // 4. Decrypt the response.
        Ok(self.parser.decrypted_response_bytes(&resp.body)?)
    }
}

/// Required path length (3 hops). Re-exported so callers don't need to
/// import from
/// [`path_manager`][crate::network::routing::path_manager].
pub const REQUIRED_PATH_HOPS: usize = PATH_HOPS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::routing::path_manager::{PathManager, PathManagerConfig};
    use crate::network::service_node::ServiceNode;
    use crate::network::snode_pool::{SnodePool, SnodePoolConfig};
    use crate::network::transport::{
        MockRoute, MockTransport, TransportResponse,
    };
    use crate::network::types::NetworkDestination;
    use crate::network::swarm::INVALID_SWARM_ID;
    use crate::network::key_types::Ed25519Pubkey;
    use crate::crypto::ed25519 as ed;

    /// Build a `ServiceNode` from a seed that is actually a valid ed25519
    /// point (the Builder needs to compute an X25519 key from it).
    fn make_node(id: u8) -> ServiceNode {
        let mut seed = [0u8; 32];
        seed[0] = id;
        // All-zero is a valid seed; id=0 collides so we just bump the first
        // byte.
        if id == 0 {
            seed[1] = 1;
        }
        let (pk, _sk) = ed::ed25519_key_pair_from_seed(&seed).unwrap();
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey(pk),
            ip: [10, 0, 0, id],
            https_port: 443,
            omq_port: 22000,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        }
    }

    fn pool_with(n: usize) -> SnodePool {
        let mut pool = SnodePool::new(SnodePoolConfig::default());
        let nodes: Vec<ServiceNode> = (1..=n as u8).map(make_node).collect();
        pool.add_nodes(nodes);
        pool
    }

    #[tokio::test]
    async fn test_non_2xx_status_strikes_guard() {
        let pool = pool_with(20);
        let mut mgr = PathManager::new(PathManagerConfig {
            target_paths_per_category: 1,
            path_strike_threshold: 1, // retire immediately on strike
        });
        mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();

        let t = MockTransport::new();
        t.route(MockRoute {
            url_contains: "onion_req".into(),
            body_contains: None,
            response: TransportResponse {
                status_code: 502,
                body: b"bad".to_vec(),
                headers: Vec::new(),
            },
        });

        let router = OnionRequestRouter::new(OnionRequestRouterConfig::default());
        let dest = NetworkDestination::ServiceNode(make_node(99));
        let r = router
            .send(
                &t,
                &pool,
                &mut mgr,
                PathCategory::Standard,
                &dest,
                "retrieve",
                b"{}",
            )
            .await;

        assert!(matches!(r, Err(OnionRouteError::BadStatus(502, _))));
        assert_eq!(mgr.path_count(PathCategory::Standard), 0); // struck out
    }

    #[tokio::test]
    async fn test_transport_failure_strikes_guard() {
        let pool = pool_with(20);
        let mut mgr = PathManager::new(PathManagerConfig {
            target_paths_per_category: 1,
            path_strike_threshold: 1,
        });
        mgr.build_up_to_target(PathCategory::Standard, &pool).unwrap();

        // Empty routes → every request fails with TransportError::Other.
        let t = MockTransport::new();

        let router = OnionRequestRouter::new(OnionRequestRouterConfig::default());
        let dest = NetworkDestination::ServiceNode(make_node(99));
        let r = router
            .send(
                &t,
                &pool,
                &mut mgr,
                PathCategory::Standard,
                &dest,
                "retrieve",
                b"{}",
            )
            .await;

        assert!(matches!(r, Err(OnionRouteError::Transport(_))));
        assert_eq!(mgr.path_count(PathCategory::Standard), 0);
    }
}
