//! Full network configuration for the Session network layer.
//!
//! Provides configuration for network identity, routing strategy, transport,
//! file server, service node pool caching, onion request paths, and QUIC options.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::network::key_types::Ed25519Pubkey;
use crate::network::service_node::ServiceNode;
use crate::network::swarm::INVALID_SWARM_ID;
use crate::network::types::PathCategory;

/// Which network to connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Devnet,
}

impl NetworkId {
    /// Returns the string identifier used in network protocol handshakes.
    pub fn to_string_id(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "session-router",
            NetworkId::Testnet => "testnet",
            NetworkId::Devnet => "devnet",
        }
    }
}

/// How requests are routed through the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterType {
    OnionRequests,
    SessionRouter,
    Direct,
}

/// Transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Quic,
}

/// Retry delay configuration with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryDelay {
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl RetryDelay {
    pub fn new(base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            base_delay,
            max_delay,
        }
    }

    /// Computes exponential backoff delay for a given failure count.
    pub fn exponential(&self, failure_count: i32) -> Duration {
        if failure_count <= 0 {
            return self.base_delay;
        }

        let delay_ms =
            self.base_delay.as_millis() as f64 * 2.0f64.powi(failure_count - 1);
        let final_delay = Duration::from_millis(delay_ms as u64);

        std::cmp::min(final_delay, self.max_delay)
    }
}

impl Default for RetryDelay {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
        }
    }
}

/// Full network configuration, mirroring the C++ `session::network::config::Config`.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub network_id: NetworkId,
    pub router: RouterType,
    pub transport: TransportType,

    // File server options
    pub custom_file_server_scheme: Option<String>,
    pub custom_file_server_host: Option<String>,
    pub custom_file_server_port: Option<u16>,
    pub custom_file_server_pubkey_hex: Option<String>,
    pub custom_file_server_max_file_size: Option<u64>,
    pub file_server_use_stream_encryption: bool,

    // General options
    pub increase_no_file_limit: bool,
    pub path_length: u8,
    pub enforce_subnet_diversity: bool,
    pub redirect_retry_count: u8,
    pub retry_delay: RetryDelay,
    pub num_nodes_to_check_for_network_offset: u8,
    pub min_resume_clock_resync_interval: Duration,

    // Netid options
    pub seed_nodes: Vec<ServiceNode>,

    // Snode pool options
    pub cache_directory: Option<PathBuf>,
    pub fallback_snode_pool_path: Option<PathBuf>,
    pub cache_expiration: Duration,
    pub cache_min_lifetime: Duration,
    pub cache_min_size: usize,
    pub cache_min_swarm_size: usize,
    pub cache_num_nodes_to_use_for_refresh: u8,
    pub cache_min_num_refresh_presence_to_include_node: u8,
    pub cache_node_strike_threshold: u8,

    // Onion request router options
    pub onionreq_path_strike_threshold: u8,
    pub onionreq_path_build_retry_limit: u8,
    pub onionreq_min_path_counts: HashMap<PathCategory, u8>,
    pub onionreq_single_path_mode: bool,
    pub onionreq_disable_pre_build_paths: bool,
    pub onionreq_path_rotation_frequency: Duration,
    pub onionreq_edge_node_cache_duration: Duration,

    // QUIC transport options
    pub quic_handshake_timeout: Duration,
    pub quic_keep_alive: Duration,
    pub quic_disable_mtu_discovery: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        let mut min_path_counts = HashMap::new();
        min_path_counts.insert(PathCategory::Standard, 2);
        min_path_counts.insert(PathCategory::File, 2);

        Self {
            network_id: NetworkId::Mainnet,
            router: RouterType::OnionRequests,
            transport: TransportType::Quic,

            // File server
            custom_file_server_scheme: None,
            custom_file_server_host: None,
            custom_file_server_port: None,
            custom_file_server_pubkey_hex: None,
            custom_file_server_max_file_size: None,
            file_server_use_stream_encryption: false,

            // General
            increase_no_file_limit: false,
            path_length: 3,
            enforce_subnet_diversity: true,
            redirect_retry_count: 1,
            retry_delay: RetryDelay::default(),
            num_nodes_to_check_for_network_offset: 3,
            min_resume_clock_resync_interval: Duration::from_secs(10 * 60),

            // Seed nodes (empty by default, populated via NetworkId)
            seed_nodes: Vec::new(),

            // Snode pool
            cache_directory: None,
            fallback_snode_pool_path: None,
            cache_expiration: Duration::from_secs(2 * 60 * 60),
            cache_min_lifetime: Duration::from_secs(2),
            cache_min_size: 12,
            cache_min_swarm_size: 3,
            cache_num_nodes_to_use_for_refresh: 3,
            cache_min_num_refresh_presence_to_include_node: 2,
            cache_node_strike_threshold: 3,

            // Onion request router
            onionreq_path_strike_threshold: 3,
            onionreq_path_build_retry_limit: 10,
            onionreq_min_path_counts: min_path_counts,
            onionreq_single_path_mode: false,
            onionreq_disable_pre_build_paths: false,
            onionreq_path_rotation_frequency: Duration::from_secs(10 * 60),
            onionreq_edge_node_cache_duration: Duration::from_secs(10 * 24 * 60 * 60),

            // QUIC transport
            quic_handshake_timeout: Duration::from_secs(3),
            quic_keep_alive: Duration::from_secs(10),
            quic_disable_mtu_discovery: false,
        }
    }
}

impl NetworkConfig {
    /// Creates a config with mainnet seed nodes pre-populated.
    pub fn mainnet() -> Self {
        let mut config = Self::default();
        config.network_id = NetworkId::Mainnet;
        config.seed_nodes = mainnet_seed_nodes();
        config
    }

    /// Creates a config for testnet.
    pub fn testnet() -> Self {
        let mut config = Self::default();
        config.network_id = NetworkId::Testnet;
        config.seed_nodes = testnet_seed_nodes();
        config
    }

    /// Creates a config for devnet with custom seed nodes.
    pub fn devnet(seed_nodes: Vec<ServiceNode>) -> Self {
        let mut config = Self::default();
        config.network_id = NetworkId::Devnet;
        config.seed_nodes = seed_nodes;
        config
    }
}

fn mainnet_seed_nodes() -> Vec<ServiceNode> {
    vec![
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey::from_hex(
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
            )
            .unwrap(),
            ip: [95, 216, 33, 113],
            https_port: 22100,
            omq_port: 20200,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        },
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey::from_hex(
                "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce",
            )
            .unwrap(),
            ip: [37, 27, 236, 229],
            https_port: 22101,
            omq_port: 20201,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        },
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey::from_hex(
                "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f",
            )
            .unwrap(),
            ip: [172, 96, 140, 124],
            https_port: 22102,
            omq_port: 20202,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        },
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey::from_hex(
                "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b",
            )
            .unwrap(),
            ip: [208, 73, 207, 54],
            https_port: 22103,
            omq_port: 20203,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        },
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey::from_hex(
                "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0",
            )
            .unwrap(),
            ip: [104, 194, 8, 115],
            https_port: 22104,
            omq_port: 20204,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        },
    ]
}

fn testnet_seed_nodes() -> Vec<ServiceNode> {
    vec![ServiceNode {
        ed25519_pubkey: Ed25519Pubkey::from_hex(
            "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a",
        )
        .unwrap(),
        ip: [23, 88, 6, 250],
        https_port: 35520,
        omq_port: 35420,
        storage_server_version: [2, 10, 0],
        swarm_id: INVALID_SWARM_ID,
        requested_unlock_height: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.network_id, NetworkId::Mainnet);
        assert_eq!(config.router, RouterType::OnionRequests);
        assert_eq!(config.transport, TransportType::Quic);
        assert_eq!(config.path_length, 3);
        assert!(config.enforce_subnet_diversity);
        assert_eq!(config.cache_min_size, 12);
        assert_eq!(config.cache_node_strike_threshold, 3);
    }

    #[test]
    fn test_mainnet_config() {
        let config = NetworkConfig::mainnet();
        assert_eq!(config.seed_nodes.len(), 5);
        assert_eq!(config.network_id, NetworkId::Mainnet);
    }

    #[test]
    fn test_testnet_config() {
        let config = NetworkConfig::testnet();
        assert_eq!(config.seed_nodes.len(), 1);
        assert_eq!(config.network_id, NetworkId::Testnet);
    }

    #[test]
    fn test_retry_delay_exponential() {
        let rd = RetryDelay::new(Duration::from_millis(200), Duration::from_secs(5));
        assert_eq!(rd.exponential(0), Duration::from_millis(200));
        assert_eq!(rd.exponential(1), Duration::from_millis(200));
        assert_eq!(rd.exponential(2), Duration::from_millis(400));
        assert_eq!(rd.exponential(3), Duration::from_millis(800));
        // Should cap at max_delay
        assert!(rd.exponential(100) <= Duration::from_secs(5));
    }

    #[test]
    fn test_network_id_string() {
        assert_eq!(NetworkId::Mainnet.to_string_id(), "session-router");
        assert_eq!(NetworkId::Testnet.to_string_id(), "testnet");
        assert_eq!(NetworkId::Devnet.to_string_id(), "devnet");
    }
}
