//! Mock transport for unit tests.
//!
//! Returns canned responses matched by URL substring and/or request-body
//! predicate. Also records every request sent through it for assertions.

use std::sync::{Arc, Mutex};

use super::transport::{Transport, TransportError, TransportRequest, TransportResponse};

/// A canned response to return when a matcher matches an incoming request.
#[derive(Clone)]
pub struct MockRoute {
    /// Substring that must appear in the request URL. Empty matches any.
    pub url_contains: String,
    /// Optional substring that must appear in the request body (UTF-8 match).
    /// `None` means "don't check body".
    pub body_contains: Option<String>,
    /// Canned response returned when this route matches.
    pub response: TransportResponse,
}

/// Mock transport implementation for tests.
#[derive(Clone, Default)]
pub struct MockTransport {
    routes: Arc<Mutex<Vec<MockRoute>>>,
    sent_requests: Arc<Mutex<Vec<TransportRequest>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a route. Routes are matched in insertion order; the first
    /// matching route wins.
    pub fn route(&self, route: MockRoute) {
        self.routes.lock().unwrap().push(route);
    }

    /// Convenience: registers a route that returns `body` as a JSON response
    /// with status 200, matched by URL substring.
    pub fn route_ok_json(&self, url_contains: impl Into<String>, body: impl Into<Vec<u8>>) {
        self.route(MockRoute {
            url_contains: url_contains.into(),
            body_contains: None,
            response: TransportResponse {
                status_code: 200,
                body: body.into(),
                headers: vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )],
            },
        });
    }

    /// Convenience: registers a route that returns `status` with the given
    /// body.
    pub fn route_status(
        &self,
        url_contains: impl Into<String>,
        status: u16,
        body: impl Into<Vec<u8>>,
    ) {
        self.route(MockRoute {
            url_contains: url_contains.into(),
            body_contains: None,
            response: TransportResponse {
                status_code: status,
                body: body.into(),
                headers: Vec::new(),
            },
        });
    }

    /// Returns a snapshot of every request that was sent.
    pub fn sent_requests(&self) -> Vec<TransportRequest> {
        self.sent_requests.lock().unwrap().clone()
    }

    /// Returns the number of requests sent so far.
    pub fn request_count(&self) -> usize {
        self.sent_requests.lock().unwrap().len()
    }

    /// Clears the recorded request history (but keeps routes).
    pub fn clear_history(&self) {
        self.sent_requests.lock().unwrap().clear();
    }
}

impl Transport for MockTransport {
    async fn send_request(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportResponse, TransportError> {
        self.sent_requests.lock().unwrap().push(request.clone());

        let routes = self.routes.lock().unwrap();
        for route in routes.iter() {
            if !route.url_contains.is_empty() && !request.url.contains(&route.url_contains) {
                continue;
            }
            if let Some(body_needle) = &route.body_contains
                && !body_contains(&request.body, body_needle)
            {
                continue;
            }
            return Ok(route.response.clone());
        }

        Err(TransportError::Other(format!(
            "MockTransport: no route matched URL {}",
            request.url
        )))
    }
}

fn body_contains(body: &[u8], needle: &str) -> bool {
    std::str::from_utf8(body)
        .map(|s| s.contains(needle))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_matches_by_url_and_returns_canned_response() {
        let t = MockTransport::new();
        t.route_ok_json("snode1", br#"{"result":"ok"}"#.to_vec());

        let req = TransportRequest::post_json(
            "https://snode1.example/storage_rpc/v1",
            br#"{"method":"retrieve"}"#.to_vec(),
            true,
        );
        let resp = t.send_request(&req).await.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, br#"{"result":"ok"}"#);
        assert_eq!(t.request_count(), 1);
    }

    #[tokio::test]
    async fn test_no_match_returns_error() {
        let t = MockTransport::new();
        t.route_ok_json("other", b"hi".to_vec());

        let req = TransportRequest {
            url: "https://nope".into(),
            method: "POST".into(),
            body: Vec::new(),
            headers: Vec::new(),
            timeout: Duration::from_secs(1),
            accept_invalid_certs: false,
        };
        assert!(t.send_request(&req).await.is_err());
    }

    #[tokio::test]
    async fn test_body_predicate_filters_matches() {
        let t = MockTransport::new();
        t.route(MockRoute {
            url_contains: "api".into(),
            body_contains: Some("store".into()),
            response: TransportResponse {
                status_code: 200,
                body: b"stored".to_vec(),
                headers: Vec::new(),
            },
        });
        t.route(MockRoute {
            url_contains: "api".into(),
            body_contains: Some("retrieve".into()),
            response: TransportResponse {
                status_code: 200,
                body: b"retrieved".to_vec(),
                headers: Vec::new(),
            },
        });

        let req1 = TransportRequest::post_json(
            "https://api.example",
            br#"{"method":"store"}"#.to_vec(),
            false,
        );
        let req2 = TransportRequest::post_json(
            "https://api.example",
            br#"{"method":"retrieve"}"#.to_vec(),
            false,
        );
        assert_eq!(t.send_request(&req1).await.unwrap().body, b"stored");
        assert_eq!(t.send_request(&req2).await.unwrap().body, b"retrieved");
    }
}
