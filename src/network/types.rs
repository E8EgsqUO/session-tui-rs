//! Network types: errors, requests, responses, destinations, and callbacks.
//!
//! Defines the core types used across the network layer including error codes,
//! request/response structures, destination types, and helper functions.

use std::fmt;
use std::time::{Duration, Instant};

use crate::network::key_types::{Ed25519Pubkey, X25519Pubkey};
use crate::network::service_node::ServiceNode;

// ---------------------------------------------------------------------------
// Error codes matching C++ constants
// ---------------------------------------------------------------------------

/// HTTP 400 Bad Request.
pub const ERROR_BAD_REQUEST: i16 = 400;
/// HTTP 406 Not Acceptable.
pub const ERROR_NOT_ACCEPTABLE: i16 = 406;
/// HTTP 408 Request Timeout.
pub const ERROR_REQUEST_TIMEOUT: i16 = 408;
/// HTTP 413 Payload Too Large.
pub const ERROR_PAYLOAD_TOO_LARGE: i16 = 413;
/// HTTP 421 Misdirected Request (wrong snode).
pub const ERROR_MISDIRECTED_REQUEST: i16 = 421;
/// HTTP 425 Too Early.
pub const ERROR_TOO_EARLY: i16 = 425;
/// Internal: network not properly configured.
pub const ERROR_NETWORK_MISCONFIGURED: i16 = -10001;
/// Internal: network operations are suspended.
pub const ERROR_NETWORK_SUSPENDED: i16 = -10002;
/// Internal: no transport layer available.
pub const ERROR_NO_TRANSPORT_LAYER: i16 = -10003;
/// Internal: no routing layer available.
pub const ERROR_NO_ROUTING_LAYER: i16 = -10004;
/// Internal: no service node pool available.
pub const ERROR_NO_SNODE_POOL: i16 = -10005;
/// Internal: connection was closed.
pub const ERROR_CONNECTION_CLOSED: i16 = -10006;
/// Internal: invalid download URL.
pub const ERROR_INVALID_DOWNLOAD_URL: i16 = -10007;
/// Internal: failed to enqueue request.
pub const ERROR_FAILED_TO_QUEUE_REQUEST: i16 = -10008;
/// Internal: invalid destination.
pub const ERROR_INVALID_DESTINATION: i16 = -10009;
/// Internal: failed to generate onion request payload.
pub const ERROR_FAILED_GENERATE_ONION_PAYLOAD: i16 = -10010;
/// Internal: failed to acquire a QUIC stream.
pub const ERROR_FAILED_TO_GET_STREAM: i16 = -10011;
/// Internal: onion path build timed out.
pub const ERROR_BUILD_TIMEOUT: i16 = -10100;
/// Internal: request was cancelled.
pub const ERROR_REQUEST_CANCELLED: i16 = -10200;
/// Internal: unknown error.
pub const ERROR_UNKNOWN: i16 = -11000;

// ---------------------------------------------------------------------------
// Content type constants
// ---------------------------------------------------------------------------

/// Content-Type header for plain text (UTF-8).
pub const CONTENT_TYPE_PLAIN_TEXT: (&str, &str) = ("Content-Type", "text/plain; charset=UTF-8");
/// Content-Type header for JSON.
pub const CONTENT_TYPE_JSON: (&str, &str) = ("Content-Type", "application/json");

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Connection status of the network layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Unknown = 0,
    Connecting = 1,
    Connected = 2,
    Disconnected = 3,
}

/// Request categories that determine path selection and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestCategory {
    Standard = 0,
    StandardSmall = 1,
    File = 2,
    FileSmall = 3,
}

impl fmt::Display for RequestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestCategory::Standard => write!(f, "standard"),
            RequestCategory::StandardSmall => write!(f, "standard_small"),
            RequestCategory::File => write!(f, "file"),
            RequestCategory::FileSmall => write!(f, "file_small"),
        }
    }
}

/// Path categories for onion routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathCategory {
    Standard = 0,
    File = 1,
}

impl fmt::Display for PathCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathCategory::Standard => write!(f, "standard"),
            PathCategory::File => write!(f, "file"),
        }
    }
}

impl PathCategory {
    /// Returns the short prefix string used to identify paths of this category.
    pub fn path_prefix(&self) -> &'static str {
        match self {
            PathCategory::Standard => "SP",
            PathCategory::File => "FP",
        }
    }
}

// ---------------------------------------------------------------------------
// Network error
// ---------------------------------------------------------------------------

/// Comprehensive error type for network operations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Bad request")]
    BadRequest,
    #[error("Not acceptable")]
    NotAcceptable,
    #[error("Request timeout")]
    RequestTimeout,
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Misdirected request (421)")]
    MisdirectedRequest,
    #[error("Too early")]
    TooEarly,
    #[error("Network misconfigured")]
    NetworkMisconfigured,
    #[error("Network suspended")]
    NetworkSuspended,
    #[error("No transport layer")]
    NoTransportLayer,
    #[error("No routing layer")]
    NoRoutingLayer,
    #[error("No snode pool")]
    NoSnodePool,
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Invalid download URL")]
    InvalidDownloadUrl,
    #[error("Failed to queue request")]
    FailedToQueueRequest,
    #[error("Invalid destination")]
    InvalidDestination,
    #[error("Failed to generate onion payload")]
    FailedGenerateOnionPayload,
    #[error("Failed to get stream")]
    FailedToGetStream,
    #[error("Build timeout")]
    BuildTimeout,
    #[error("Request cancelled")]
    RequestCancelled,
    #[error("Unknown error")]
    Unknown,
    #[error("Status code error: {status_code}: {message}")]
    StatusCode {
        status_code: i16,
        message: String,
        headers: Vec<(String, String)>,
    },
    #[error("Cancellation: {0}")]
    Cancellation(String),
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("{0}")]
    Other(String),
}

impl NetworkError {
    /// Returns the numeric status code for this error.
    pub fn status_code(&self) -> i16 {
        match self {
            NetworkError::BadRequest => ERROR_BAD_REQUEST,
            NetworkError::NotAcceptable => ERROR_NOT_ACCEPTABLE,
            NetworkError::RequestTimeout => ERROR_REQUEST_TIMEOUT,
            NetworkError::PayloadTooLarge => ERROR_PAYLOAD_TOO_LARGE,
            NetworkError::MisdirectedRequest => ERROR_MISDIRECTED_REQUEST,
            NetworkError::TooEarly => ERROR_TOO_EARLY,
            NetworkError::NetworkMisconfigured => ERROR_NETWORK_MISCONFIGURED,
            NetworkError::NetworkSuspended => ERROR_NETWORK_SUSPENDED,
            NetworkError::NoTransportLayer => ERROR_NO_TRANSPORT_LAYER,
            NetworkError::NoRoutingLayer => ERROR_NO_ROUTING_LAYER,
            NetworkError::NoSnodePool => ERROR_NO_SNODE_POOL,
            NetworkError::ConnectionClosed => ERROR_CONNECTION_CLOSED,
            NetworkError::InvalidDownloadUrl => ERROR_INVALID_DOWNLOAD_URL,
            NetworkError::FailedToQueueRequest => ERROR_FAILED_TO_QUEUE_REQUEST,
            NetworkError::InvalidDestination => ERROR_INVALID_DESTINATION,
            NetworkError::FailedGenerateOnionPayload => ERROR_FAILED_GENERATE_ONION_PAYLOAD,
            NetworkError::FailedToGetStream => ERROR_FAILED_TO_GET_STREAM,
            NetworkError::BuildTimeout => ERROR_BUILD_TIMEOUT,
            NetworkError::RequestCancelled => ERROR_REQUEST_CANCELLED,
            NetworkError::Unknown => ERROR_UNKNOWN,
            NetworkError::StatusCode { status_code, .. } => *status_code,
            NetworkError::Cancellation(_) => ERROR_REQUEST_CANCELLED,
            NetworkError::InvalidUrl(_) => ERROR_INVALID_DOWNLOAD_URL,
            NetworkError::Other(_) => ERROR_UNKNOWN,
        }
    }
}

// ---------------------------------------------------------------------------
// Destinations
// ---------------------------------------------------------------------------

/// A proxied (non-snode) server destination.
#[derive(Debug, Clone)]
pub struct ServerDestination {
    pub protocol: String,
    pub host: String,
    pub x25519_pubkey: X25519Pubkey,
    pub port: Option<u16>,
    pub headers: Option<Vec<(String, String)>>,
    pub method: String,
}

/// Where a request should be sent.
#[derive(Debug, Clone)]
pub enum NetworkDestination {
    ServiceNode(ServiceNode),
    Server(ServerDestination),
}

// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------

/// Upload metadata.
#[derive(Debug, Clone, Default)]
pub struct UploadInfo {
    pub file_name: Option<String>,
}

/// Extra details that may modify request structure.
#[derive(Debug, Clone)]
pub enum RequestDetails {
    None,
    Upload(UploadInfo),
}

impl Default for RequestDetails {
    fn default() -> Self {
        RequestDetails::None
    }
}

/// A network request.
#[derive(Debug, Clone)]
pub struct Request {
    pub request_id: String,
    pub destination: NetworkDestination,
    pub endpoint: String,
    pub body: Option<Vec<u8>>,
    pub category: RequestCategory,
    pub request_timeout: Duration,
    pub overall_timeout: Option<Duration>,
    pub desired_path_index: Option<u8>,
    pub details: RequestDetails,
    pub creation_time: Instant,
    pub retry_count: i32,
}

impl Request {
    /// Creates a new request with a generated ID and the given parameters.
    pub fn new(
        destination: NetworkDestination,
        endpoint: String,
        body: Option<Vec<u8>>,
        category: RequestCategory,
        request_timeout: Duration,
    ) -> Self {
        Self {
            request_id: generate_request_id(),
            destination,
            endpoint,
            body,
            category,
            request_timeout,
            overall_timeout: None,
            desired_path_index: None,
            details: RequestDetails::None,
            creation_time: Instant::now(),
            retry_count: 0,
        }
    }

    /// Returns the remaining time for this request, considering the overall timeout.
    pub fn time_remaining(&self) -> Duration {
        match self.overall_timeout {
            None => self.request_timeout,
            Some(overall) => {
                let elapsed = self.creation_time.elapsed();
                if elapsed >= overall {
                    Duration::ZERO
                } else {
                    overall - elapsed
                }
            }
        }
    }
}

/// File metadata returned after upload/download.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub id: String,
    pub size: i64,
    pub uploaded: Option<i64>,
    pub expiry: Option<i64>,
}

/// Path metadata for onion routing.
#[derive(Debug, Clone)]
pub enum PathMetadata {
    OnionPath {
        category: PathCategory,
    },
    SessionRouterTunnel {
        destination_pubkey: String,
        destination_snode_address: String,
    },
}

/// Information about a routing path.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub nodes: Vec<ServiceNode>,
    pub metadata: PathMetadata,
}

// ---------------------------------------------------------------------------
// Response parsing helpers
// ---------------------------------------------------------------------------

/// Parses a text error response body into (status_code, is_timeout) if it matches
/// a known error prefix.
pub fn parse_text_error(body: &str) -> Option<(i16, bool)> {
    const ERROR_MAP: &[(&str, i16, bool)] = &[
        ("400 Bad Request", 400, false),
        ("401 Unauthorized", 401, false),
        ("403 Forbidden", 403, false),
        ("404 Not Found", 404, false),
        ("405 Method Not Allowed", 405, false),
        ("406 Not Acceptable", 406, false),
        ("408 Request Timeout", 408, false),
        ("500 Internal Server Error", 500, false),
        ("502 Bad Gateway", 502, false),
        ("503 Service Unavailable", 503, false),
        ("504 Gateway Timeout", 504, true),
    ];

    for &(prefix, code, is_timeout) in ERROR_MAP {
        if body.starts_with(prefix) {
            return Some((code, is_timeout));
        }
    }

    None
}

/// Checks if a JSON batch response has a uniform error code across all results.
pub fn find_uniform_batch_error(body: &str) -> Option<i16> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;

    let results = json.get("results")?.as_array()?;
    if results.is_empty() {
        return None;
    }

    let mut first_code: Option<i16> = None;

    for result in results {
        let code = result.get("code")?.as_i64()? as i16;
        if (200..=299).contains(&code) {
            return None;
        }
        match first_code {
            None => first_code = Some(code),
            Some(fc) if fc != code => return None,
            _ => {}
        }
    }

    first_code
}

/// Node failure reporter callback type.
pub type NodeFailureReporter = Box<dyn Fn(&Ed25519Pubkey, bool) + Send + Sync>;

/// Network response callback type.
pub type NetworkResponseCallback =
    Box<dyn FnOnce(bool, bool, i16, Vec<(String, String)>, Option<String>) + Send + 'static>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_request_id() -> String {
    use rand::RngExt;
    let id: u64 = rand::rng().random();
    format!("R{:x}", id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_status_values() {
        assert_eq!(ConnectionStatus::Unknown as u8, 0);
        assert_eq!(ConnectionStatus::Connecting as u8, 1);
        assert_eq!(ConnectionStatus::Connected as u8, 2);
        assert_eq!(ConnectionStatus::Disconnected as u8, 3);
    }

    #[test]
    fn test_request_category_display() {
        assert_eq!(RequestCategory::Standard.to_string(), "standard");
        assert_eq!(RequestCategory::StandardSmall.to_string(), "standard_small");
        assert_eq!(RequestCategory::File.to_string(), "file");
        assert_eq!(RequestCategory::FileSmall.to_string(), "file_small");
    }

    #[test]
    fn test_path_category_prefix() {
        assert_eq!(PathCategory::Standard.path_prefix(), "SP");
        assert_eq!(PathCategory::File.path_prefix(), "FP");
    }

    #[test]
    fn test_parse_text_error() {
        assert_eq!(parse_text_error("400 Bad Request"), Some((400, false)));
        assert_eq!(
            parse_text_error("504 Gateway Timeout foo"),
            Some((504, true))
        );
        assert_eq!(parse_text_error("something else"), None);
    }

    #[test]
    fn test_find_uniform_batch_error() {
        let body = r#"{"results":[{"code":500},{"code":500}]}"#;
        assert_eq!(find_uniform_batch_error(body), Some(500));

        let body = r#"{"results":[{"code":500},{"code":400}]}"#;
        assert_eq!(find_uniform_batch_error(body), None);

        let body = r#"{"results":[{"code":200},{"code":500}]}"#;
        assert_eq!(find_uniform_batch_error(body), None);

        let body = r#"not json"#;
        assert_eq!(find_uniform_batch_error(body), None);
    }

    #[test]
    fn test_network_error_codes() {
        assert_eq!(NetworkError::BadRequest.status_code(), 400);
        assert_eq!(NetworkError::RequestCancelled.status_code(), -10200);
        assert_eq!(NetworkError::Unknown.status_code(), -11000);
    }

    #[test]
    fn test_request_time_remaining() {
        let dest = NetworkDestination::Server(ServerDestination {
            protocol: "https".into(),
            host: "example.com".into(),
            x25519_pubkey: crate::network::key_types::X25519Pubkey([0u8; 32]),
            port: None,
            headers: None,
            method: "GET".into(),
        });

        let req = Request::new(
            dest,
            "/test".into(),
            None,
            RequestCategory::Standard,
            Duration::from_secs(30),
        );

        // Without overall_timeout, should return request_timeout
        assert_eq!(req.time_remaining(), Duration::from_secs(30));
    }
}
