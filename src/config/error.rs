/// Config error codes, mirroring the C enum `config_error` from error.h.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// No error.
    None = 0,
    /// Initialization failed because the dumped data being loaded is invalid.
    InvalidDump = 1,
    /// A bad value was provided, e.g. trying to set something invalid in a config field.
    BadValue = 2,
}

impl ConfigError {
    /// Returns a generic description string for the error code.
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigError::None => "No error",
            ConfigError::InvalidDump => "Invalid config dump",
            ConfigError::BadValue => "Bad config value",
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_repr_values() {
        assert_eq!(ConfigError::None as i32, 0);
        assert_eq!(ConfigError::InvalidDump as i32, 1);
        assert_eq!(ConfigError::BadValue as i32, 2);
    }

    #[test]
    fn test_error_strings() {
        assert_eq!(ConfigError::None.as_str(), "No error");
        assert_eq!(ConfigError::InvalidDump.as_str(), "Invalid config dump");
        assert_eq!(ConfigError::BadValue.as_str(), "Bad config value");
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", ConfigError::None), "No error");
        assert_eq!(format!("{}", ConfigError::BadValue), "Bad config value");
    }
}
