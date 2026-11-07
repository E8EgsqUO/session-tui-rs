//! Message expiration types for Session configs.
//!
//! Port of `libsession-util/include/session/config/expiring.hpp`.

/// Mode of message expiration.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExpiryType {
    /// No expiration.
    #[default]
    None = 0,
    /// Messages expire a fixed duration after being sent.
    AfterSend = 1,
    /// Messages expire a fixed duration after being read.
    AfterRead = 2,
}

impl ExpiryType {
    /// Creates an `ExpiryType` from a raw `i8` value.
    ///
    /// Returns `None` variant for unrecognized values.
    pub fn from_raw(val: i8) -> Self {
        match val {
            1 => ExpiryType::AfterSend,
            2 => ExpiryType::AfterRead,
            _ => ExpiryType::None,
        }
    }
}

/// Combined expiration configuration: mode and timer duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpiryConfig {
    /// The expiration mode.
    pub mode: ExpiryType,
    /// Duration in seconds before the message expires.
    pub timer_seconds: u32,
}

impl ExpiryConfig {
    /// Creates a new expiry config with no expiration.
    pub fn none() -> Self {
        Self::default()
    }

    /// Creates a new "after send" expiry config with the given timer.
    pub fn after_send(timer_seconds: u32) -> Self {
        ExpiryConfig {
            mode: ExpiryType::AfterSend,
            timer_seconds,
        }
    }

    /// Creates a new "after read" expiry config with the given timer.
    pub fn after_read(timer_seconds: u32) -> Self {
        ExpiryConfig {
            mode: ExpiryType::AfterRead,
            timer_seconds,
        }
    }

    /// Returns true if expiration is disabled.
    pub fn is_none(&self) -> bool {
        self.mode == ExpiryType::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expiry_type_repr() {
        assert_eq!(ExpiryType::None as u8, 0);
        assert_eq!(ExpiryType::AfterSend as u8, 1);
        assert_eq!(ExpiryType::AfterRead as u8, 2);
    }

    #[test]
    fn test_expiry_type_from_raw() {
        assert_eq!(ExpiryType::from_raw(0), ExpiryType::None);
        assert_eq!(ExpiryType::from_raw(1), ExpiryType::AfterSend);
        assert_eq!(ExpiryType::from_raw(2), ExpiryType::AfterRead);
        assert_eq!(ExpiryType::from_raw(99), ExpiryType::None);
        assert_eq!(ExpiryType::from_raw(-1), ExpiryType::None);
    }

    #[test]
    fn test_expiry_config_default() {
        let cfg = ExpiryConfig::default();
        assert_eq!(cfg.mode, ExpiryType::None);
        assert_eq!(cfg.timer_seconds, 0);
        assert!(cfg.is_none());
    }

    #[test]
    fn test_expiry_config_after_send() {
        let cfg = ExpiryConfig::after_send(3600);
        assert_eq!(cfg.mode, ExpiryType::AfterSend);
        assert_eq!(cfg.timer_seconds, 3600);
        assert!(!cfg.is_none());
    }

    #[test]
    fn test_expiry_config_after_read() {
        let cfg = ExpiryConfig::after_read(86400);
        assert_eq!(cfg.mode, ExpiryType::AfterRead);
        assert_eq!(cfg.timer_seconds, 86400);
        assert!(!cfg.is_none());
    }
}
