//! HTTPS transport using `reqwest` (with an explicit rustls configuration).
//!
//! Maintains three internal clients, selected per-request based on the host
//! and the caller's `accept_invalid_certs` flag:
//!
//! * **`seed_pinned_client`** — used whenever the request host is one of the
//!   three Session seed nodes (`seed{1,2,3}.getsession.org`). Trusts only
//!   the three bundled PEMs (see `seed_certs` sibling module), matched by
//!   exact DER equality. Mirrors Android's `network_security_configuration.xml`
//!   per-domain pinning.
//! * **`trust_all_client`** — accepts any certificate. Used for direct
//!   snode connections, which present self-signed certs (matches the
//!   Android `createRegularNodeOkHttpClient` behaviour).
//! * **`strict_client`** — standard TLS verification against the Mozilla
//!   root CA bundle (via the `webpki-roots` crate). Used for every other
//!   HTTPS endpoint (file servers, open-group servers, etc.).
//!
//! We wire rustls ourselves (via `reqwest::ClientBuilder::use_preconfigured_tls`)
//! rather than relying on reqwest's default provider, so behaviour is
//! identical on every platform — no OS trust store calls, no platform-specific
//! initialisation required for iOS/Android/desktop.

use std::sync::Arc;
use std::sync::Once;

use reqwest::{Client, ClientBuilder};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::{ring as rustls_ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use super::seed_certs;
use super::transport::{Transport, TransportError, TransportRequest, TransportResponse};

/// Default connect timeout applied to every HTTPS connection.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// HTTP transport implementation.
#[derive(Clone)]
pub struct HttpTransport {
    inner: Arc<HttpTransportInner>,
}

struct HttpTransportInner {
    /// Client used for standard TLS-verified endpoints (file servers /
    /// open-group servers with proper Mozilla-rooted certs).
    strict_client: Client,
    /// Client that accepts self-signed certificates. Required for direct
    /// snode connections because snodes do not have publicly trusted certs.
    trust_all_client: Client,
    /// Client used ONLY for the three Session seed nodes
    /// (`seed{1,2,3}.getsession.org`). Trusts only the bundled pinned
    /// certs via [`SessionSeedVerifier`].
    seed_pinned_client: Client,
}

impl HttpTransport {
    /// Creates a new HTTP transport.
    ///
    /// Returns an error if either of the internal `reqwest::Client`
    /// instances cannot be built.
    pub fn new() -> Result<Self, TransportError> {
        install_default_crypto_provider();

        let strict_tls = strict_rustls_config();
        let trust_all_tls = trust_all_rustls_config();
        let seed_pinned_tls = seed_pinned_rustls_config();

        let strict_client = with_https_proxy(Client::builder())?
            .connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .use_preconfigured_tls(strict_tls)
            .build()
            .map_err(|e| TransportError::Other(format!("build strict client: {e}")))?;

        let trust_all_client = with_https_proxy(Client::builder())?
            .connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .use_preconfigured_tls(trust_all_tls)
            .build()
            .map_err(|e| TransportError::Other(format!("build trust-all client: {e}")))?;

        let seed_pinned_client = with_https_proxy(Client::builder())?
            .connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .use_preconfigured_tls(seed_pinned_tls)
            .build()
            .map_err(|e| TransportError::Other(format!("build seed-pinned client: {e}")))?;

        Ok(Self {
            inner: Arc::new(HttpTransportInner {
                strict_client,
                trust_all_client,
                seed_pinned_client,
            }),
        })
    }
}

/// Explicitly honor the conventional lowercase `https_proxy` variable.
/// reqwest's automatic environment handling is platform dependent, so apply
/// it to every client (including the custom TLS clients) when present.
fn with_https_proxy(builder: ClientBuilder) -> Result<ClientBuilder, TransportError> {
    let proxy = std::env::var("https_proxy")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .ok()
        .filter(|value| !value.trim().is_empty());
    match proxy {
        Some(proxy) => {
            let proxy = reqwest::Proxy::https(&proxy)
                .map_err(|e| TransportError::Other(format!("invalid https_proxy: {e}")))?;
            Ok(builder.proxy(proxy))
        }
        None => Ok(builder),
    }
}

/// Returns the host component of `url` in lowercase, or an empty string if
/// the URL is malformed.
pub(crate) fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_ascii_lowercase()))
        .unwrap_or_default()
}

impl Transport for HttpTransport {
    async fn send_request(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportResponse, TransportError> {
        // Route selection:
        //   1. If the host is a known Session seed → seed-pinned client
        //      (trusts only the three bundled certs; ignores the
        //      `accept_invalid_certs` flag — seeds have their own pinning
        //      regime).
        //   2. Else if `accept_invalid_certs` is set → trust-all client
        //      (snodes with self-signed certs).
        //   3. Else → strict client (Mozilla roots).
        let host = host_of(&request.url);
        let client = if seed_certs::is_seed_host(&host) {
            &self.inner.seed_pinned_client
        } else if request.accept_invalid_certs {
            &self.inner.trust_all_client
        } else {
            &self.inner.strict_client
        };

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| TransportError::Other(format!("invalid method: {e}")))?;

        let mut builder = client.request(method, &request.url).timeout(request.timeout);

        for (k, v) in &request.headers {
            builder = builder.header(k, v);
        }

        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }

        let response = match builder.send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Err(TransportError::Timeout),
            Err(e) if e.is_connect() => {
                return Err(TransportError::ConnectionFailed(format_error_chain(&e)))
            }
            Err(e) => return Err(TransportError::SendFailed(format_error_chain(&e))),
        };

        let status_code = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
            .collect();

        // Read at most MAX_RESPONSE_BYTES: attachment URLs come from other
        // people, and a hostile server could otherwise stream without end.
        let mut response = response;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(TransportError::ReceiveFailed("response too large".into()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| TransportError::ReceiveFailed(format_error_chain(&e)))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(TransportError::ReceiveFailed("response too large".into()));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(TransportResponse {
            status_code,
            body,
            headers,
        })
    }
}

/// Largest response body accepted. Session's file server caps uploads at
/// 10 MB; encryption and onion framing add a little on top.
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Installs the `ring` crypto provider as rustls' process-wide default
/// exactly once. Subsequent calls are a no-op.
fn install_default_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // `install_default` returns Err if one is already installed — we
        // swallow that because it's fine either way.
        let _ = rustls_ring::default_provider().install_default();
    });
}

/// Rustls client config that verifies certificates against the bundled
/// Mozilla root CA set (via `webpki-roots`).
fn strict_rustls_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Rustls client config that trusts ONLY the three bundled Session seed
/// certificates, matched by exact DER equality against the bundled pins
/// in the `seed_certs` sibling module.
fn seed_pinned_rustls_config() -> ClientConfig {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SessionSeedVerifier))
        .with_no_client_auth()
}

/// Rustls client config that trusts ANY server certificate. Reserved for
/// direct snode connections (self-signed) — never use this for seed nodes
/// or server endpoints.
fn trust_all_rustls_config() -> ClientConfig {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
        .with_no_client_auth()
}

fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_ring::default_provider())
}

/// Walks `source()` on the error chain and concatenates each layer. Useful
/// for surfacing the underlying rustls / hyper reason that reqwest's
/// top-level `Display` would otherwise swallow.
fn format_error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(next) = cur {
        out.push_str(" | ");
        out.push_str(&next.to_string());
        cur = next.source();
    }
    out
}

/// `ServerCertVerifier` that accepts a presented certificate only if its
/// DER encoding is byte-for-byte identical to one of the three bundled
/// Session seed certs. Used for `seed{1,2,3}.getsession.org` only.
///
/// We don't do chain building or hostname verification here: the caller has
/// already routed by hostname before we ran, and the seed certs are
/// self-signed leaves (no chain to build). Exact pinning is the clearest
/// semantic — match Android's per-domain `<trust-anchors>` behaviour.
#[derive(Debug)]
struct SessionSeedVerifier;

impl ServerCertVerifier for SessionSeedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = end_entity.as_ref();
        for pinned in seed_certs::pinned_certs() {
            if pinned.as_ref() == presented {
                return Ok(ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_of_extracts_lowercase_host() {
        assert_eq!(
            host_of("https://Seed1.GetSession.Org:4443/json_rpc"),
            "seed1.getsession.org"
        );
        assert_eq!(host_of("https://95.216.33.113:22100/x"), "95.216.33.113");
        assert_eq!(host_of("not a url"), "");
    }

    #[test]
    fn test_seed_host_routing_matches_seed_certs() {
        // Lowercase match.
        assert!(seed_certs::is_seed_host(&host_of(
            "https://seed1.getsession.org:4443/json_rpc"
        )));
        // Mixed case match.
        assert!(seed_certs::is_seed_host(&host_of(
            "https://Seed2.GETSESSION.org:4443/x"
        )));
        // Non-seed (random snode by IP) does not route to the pinned client.
        assert!(!seed_certs::is_seed_host(&host_of(
            "https://95.216.33.113:22100/storage_rpc"
        )));
    }
}

/// `ServerCertVerifier` that accepts any presented certificate — used only
/// by the trust-all client for direct snode connections.
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
