//! Request queue with deque-based ordering and timeout management.
//!
//! Port of the request queue concepts from the C++ code.

use std::collections::VecDeque;
use std::time::Duration;

use crate::network::types::Request;

/// A queue for managing pending network requests.
pub struct RequestQueue {
    queue: VecDeque<Request>,
}

impl RequestQueue {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Adds a request to the back of the queue.
    pub fn add(&mut self, request: Request) {
        self.queue.push_back(request);
    }

    /// Adds a request to the front of the queue (high priority).
    pub fn add_front(&mut self, request: Request) {
        self.queue.push_front(request);
    }

    /// Removes and returns all requests from the queue.
    pub fn pop_all(&mut self) -> Vec<Request> {
        self.queue.drain(..).collect()
    }

    /// Removes and returns the next request from the front of the queue.
    pub fn pop_front(&mut self) -> Option<Request> {
        self.queue.pop_front()
    }

    /// Returns the number of pending requests.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Removes requests whose overall timeout has expired.
    /// Returns the timed-out requests.
    pub fn remove_expired(&mut self) -> Vec<Request> {
        let mut expired = Vec::new();
        let mut remaining = VecDeque::new();

        while let Some(req) = self.queue.pop_front() {
            if req.time_remaining() == Duration::ZERO {
                expired.push(req);
            } else {
                remaining.push_back(req);
            }
        }

        self.queue = remaining;
        expired
    }

    /// Clears all requests from the queue.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

impl Default for RequestQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::X25519Pubkey;
    use crate::network::types::{NetworkDestination, RequestCategory, ServerDestination};

    fn make_request(id: &str) -> Request {
        Request {
            request_id: id.to_string(),
            destination: NetworkDestination::Server(ServerDestination {
                protocol: "https".into(),
                host: "example.com".into(),
                x25519_pubkey: X25519Pubkey([0u8; 32]),
                port: None,
                headers: None,
                method: "GET".into(),
            }),
            endpoint: "/test".into(),
            body: None,
            category: RequestCategory::Standard,
            request_timeout: Duration::from_secs(30),
            overall_timeout: None,
            desired_path_index: None,
            details: crate::network::types::RequestDetails::None,
            creation_time: std::time::Instant::now(),
            retry_count: 0,
        }
    }

    #[test]
    fn test_add_and_pop() {
        let mut queue = RequestQueue::new();
        assert!(queue.is_empty());

        queue.add(make_request("r1"));
        queue.add(make_request("r2"));
        assert_eq!(queue.len(), 2);

        let req = queue.pop_front().unwrap();
        assert_eq!(req.request_id, "r1");
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_add_front() {
        let mut queue = RequestQueue::new();
        queue.add(make_request("r1"));
        queue.add_front(make_request("r0"));

        let req = queue.pop_front().unwrap();
        assert_eq!(req.request_id, "r0");
    }

    #[test]
    fn test_pop_all() {
        let mut queue = RequestQueue::new();
        queue.add(make_request("r1"));
        queue.add(make_request("r2"));
        queue.add(make_request("r3"));

        let all = queue.pop_all();
        assert_eq!(all.len(), 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut queue = RequestQueue::new();
        queue.add(make_request("r1"));
        queue.add(make_request("r2"));
        queue.clear();
        assert!(queue.is_empty());
    }
}
