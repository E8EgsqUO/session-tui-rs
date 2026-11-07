//! Stub open group (community) server backend.
//!
//! Full implementation pending.

/// Stub open group server configuration.
#[derive(Debug, Clone)]
pub struct OpenGroupServerConfig {
    pub base_url: String,
    pub room: String,
    pub public_key: String,
}

/// Stub open group server backend.
pub struct OpenGroupServer {
    pub config: OpenGroupServerConfig,
}

impl OpenGroupServer {
    /// Creates a new open group server backend with the given configuration.
    pub fn new(config: OpenGroupServerConfig) -> Self {
        Self { config }
    }
}
