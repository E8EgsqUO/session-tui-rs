//! Router trait definition.
//!
//! Defines the interface for routing requests through the network,
//! handling path selection, onion encryption, and response decryption.

use crate::network::types::{NetworkResponseCallback, Request};

/// Router trait for sending requests through the network.
#[allow(async_fn_in_trait)]
pub trait Router: Send + Sync {
    /// Sends a request through the network using this routing strategy.
    async fn send_request(&self, request: Request, callback: NetworkResponseCallback);

    /// Returns true if the router is ready to send requests.
    fn is_ready(&self) -> bool;

    /// Suspends the router (pauses path building, etc.).
    fn suspend(&self);

    /// Resumes the router after suspension.
    fn resume(&self);
}
