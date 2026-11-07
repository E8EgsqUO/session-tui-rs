use tracing::Level;

/// Log levels mapping to tracing levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Converts to the corresponding `tracing::Level`.
    pub fn to_tracing_level(self) -> Level {
        match self {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        level.to_tracing_level()
    }
}

/// Initializes logging.
///
/// This is a thin wrapper that downstream crates can call. The actual subscriber
/// setup is left to the application binary; this function is a no-op placeholder
/// that libraries can invoke safely.
pub fn init_logging() {
    // Libraries should not install a global subscriber -- that is the
    // responsibility of the final binary. This function exists as a
    // placeholder so callers have a single entry point to call when they
    // eventually wire up a subscriber.
}
