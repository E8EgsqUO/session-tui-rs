//! Onion-routed networking through the Session service node network.
//!
//! Provides QUIC-based transport, 3-hop onion request routing, service node pool
//! management, request queuing with retry logic, and backend support for file
//! servers and open group (community) servers.

/// Typed key wrappers for Ed25519 and X25519 keys used in networking.
pub mod key_types;
/// Service node (snode) representation and parsing.
pub mod service_node;
/// Swarm ID computation and closest-swarm lookup.
pub mod swarm;
/// Full network configuration: network ID, routing, transport, caching, and QUIC options.
pub mod network_config;
/// Network types: errors, requests, responses, destinations, and callbacks.
pub mod types;
/// Service node pool management with caching and refresh logic.
pub mod snode_pool;
/// Request scheduling, queuing, and retry logic.
pub mod request_queue;
/// Onion request construction, parsing, and response decryption.
pub mod onionreq;
/// Transport layer implementations.
pub mod transport;
/// Request routing: onion request and direct routers.
pub mod routing;
/// Backend server types: file server and open group server.
pub mod backends;
/// Authenticated request signing (`store`/`retrieve`/`delete` signatures).
pub mod auth;
/// Typed JSON builders for snode RPC params (`store`, `retrieve`, etc.).
pub mod rpc;
/// Top-level `Network` facade — single entry point used by the FFI bridge.
pub mod network;

pub use network::{Network, NetworkConfig, NetworkError};
pub use transport::{HttpTransport, MockTransport, Transport};
