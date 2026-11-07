//! Transport layer trait definition.
//!
//! Abstracts the network layer so that an HTTP-based transport (for use with
//! real snodes) and a mock transport (for unit tests) can be swapped
//! transparently. Matches the Android `createRegularNodeOkHttpClient` /
//! `createSeedSnodeOkHttpClient` distinction — snodes use self-signed
//! certificates which must be accepted; seed nodes use standard TLS.

use std::time::Duration;

/// Request to be sent over the transport.
#[derive(Debug, Clone)]
pub struct TransportRequest {
    /// Full URL (e.g. `https://ip:port/storage_rpc/v1` or
    /// `https://seed1.getsession.org:4443/json_rpc`).
    pub url: String,
    /// HTTP method. Typically `POST`.
    pub method: String,
    /// Raw body bytes.
    pub body: Vec<u8>,
    /// Request headers (e.g. `Content-Type: application/json`).
    pub headers: Vec<(String, String)>,
    /// Timeout for the whole request.
    pub timeout: Duration,
    /// When `true`, accept self-signed TLS certificates. Required for direct
    /// snode connections (snodes use self-signed certs). `false` for seed
    /// nodes or public servers where standard CA validation applies.
    pub accept_invalid_certs: bool,
}

impl TransportRequest {
    /// Convenience constructor for a JSON POST.
    pub fn post_json(url: impl Into<String>, body: Vec<u8>, accept_invalid_certs: bool) -> Self {
        Self {
            url: url.into(),
            method: "POST".to_string(),
            body,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            timeout: Duration::from_secs(15),
            accept_invalid_certs,
        }
    }

    /// Convenience constructor for a raw binary POST (e.g. onion request body
    /// to `/onion_req/v2`).
    pub fn post_bytes(url: impl Into<String>, body: Vec<u8>, accept_invalid_certs: bool) -> Self {
        Self {
            url: url.into(),
            method: "POST".to_string(),
            body,
            headers: Vec::new(),
            timeout: Duration::from_secs(30),
            accept_invalid_certs,
        }
    }
}

/// Response returned from the transport layer.
#[derive(Debug, Clone)]
pub struct TransportResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

/// Transport abstraction: sends a request and returns the response bytes.
///
/// Implementations must be cheaply cloneable (e.g. via `Arc` internally) so
/// the same transport instance can be shared across the network stack.
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    /// Sends a request and returns the response.
    ///
    /// Implementations must honour `request.timeout` and
    /// `request.accept_invalid_certs`.
    async fn send_request(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportResponse, TransportError>;
}

/// Errors that can occur during transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    #[error("Timeout")]
    Timeout,
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("TLS error: {0}")]
    TlsError(String),
    #[error("HTTP {status}: {message}")]
    HttpStatus { status: u16, message: String },
    #[error("{0}")]
    Other(String),
}
