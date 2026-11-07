//! Stub QUIC transport implementation.
//!
//! Full implementation requires live network integration testing with Quinn.
//! This module provides the struct definition and configuration.

use std::time::Duration;

/// Configuration for the QUIC transport layer.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub handshake_timeout: Duration,
    pub keep_alive: Duration,
    pub disable_mtu_discovery: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(3),
            keep_alive: Duration::from_secs(10),
            disable_mtu_discovery: false,
        }
    }
}

/// Stub QUIC transport. Full implementation pending integration testing.
pub struct QuicTransport {
    pub config: QuicConfig,
}

impl QuicTransport {
    pub fn new(config: QuicConfig) -> Self {
        Self { config }
    }
}
