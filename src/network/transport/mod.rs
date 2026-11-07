//! Transport layer implementations for the Session network.
//!
//! Provides:
//! - abstract [`Transport`] trait + request / response types (see
//!   [`transport`] module).
//! - [`HttpTransport`] — `reqwest`-based HTTP transport that accepts
//!   self-signed snode certificates (matches Android
//!   `createRegularNodeOkHttpClient`).
//! - [`MockTransport`] — test-only mock transport returning canned responses.
//! - `quic` — QUIC transport skeleton (full implementation is future work).

/// Transport trait and request/response types.
pub mod transport;
/// HTTPS transport implementation using `reqwest`.
pub mod http;
/// Mock transport for unit tests.
pub mod mock;
/// QUIC transport implementation using quinn.
pub mod quic;
/// Bundled Session seed-node CA certificates (pinned — implementation detail).
pub(crate) mod seed_certs;

pub use http::HttpTransport;
pub use mock::{MockRoute, MockTransport};
pub use transport::{Transport, TransportError, TransportRequest, TransportResponse};
