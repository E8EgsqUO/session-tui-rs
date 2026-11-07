//! Stub direct router - sends requests without onion routing.

/// Stub direct router. Full implementation pending integration testing.
pub struct DirectRouter;

impl DirectRouter {
    /// Creates a new direct router instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectRouter {
    fn default() -> Self {
        Self::new()
    }
}
