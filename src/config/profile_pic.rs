//! Profile picture type for Session configs.
//!
//! Port of `libsession-util/include/session/config/profile_pic.hpp`.

/// Maximum URL length for a profile picture.
pub const MAX_URL_LENGTH: usize = 223;

/// Profile picture information: a URL and an encryption key.
#[derive(Debug, Clone, Default)]
pub struct ProfilePic {
    /// URL of the profile picture.
    pub url: String,
    /// Encryption key for the profile picture (must be empty or exactly 32 bytes).
    pub key: Vec<u8>,
}

impl ProfilePic {
    /// Creates a new empty profile pic.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a profile pic from a URL and key.
    ///
    /// Returns an error if the key is not empty and not exactly 32 bytes.
    pub fn with_url_and_key(url: impl Into<String>, key: Vec<u8>) -> Result<Self, &'static str> {
        Self::check_key(&key)?;
        Ok(ProfilePic {
            url: url.into(),
            key,
        })
    }

    /// Returns `true` if either the URL or key are missing/invalid,
    /// meaning this profile pic is not usable.
    pub fn is_empty(&self) -> bool {
        self.url.is_empty() || self.key.len() != 32
    }

    /// Clears the URL and key.
    pub fn clear(&mut self) {
        self.url.clear();
        self.key.clear();
    }

    /// Sets and validates the key. The key must be empty or exactly 32 bytes.
    pub fn set_key(&mut self, new_key: Vec<u8>) -> Result<(), &'static str> {
        Self::check_key(&new_key)?;
        self.key = new_key;
        Ok(())
    }

    /// Validates that a key is either empty or exactly 32 bytes.
    fn check_key(key: &[u8]) -> Result<(), &'static str> {
        if !key.is_empty() && key.len() != 32 {
            return Err("Invalid profile pic key: 32 bytes required");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_empty() {
        let pic = ProfilePic::new();
        assert!(pic.is_empty());
        assert!(pic.url.is_empty());
        assert!(pic.key.is_empty());
    }

    #[test]
    fn test_with_url_and_key() {
        let key = vec![0xABu8; 32];
        let pic = ProfilePic::with_url_and_key("https://example.com/pic.jpg", key.clone()).unwrap();
        assert!(!pic.is_empty());
        assert_eq!(pic.url, "https://example.com/pic.jpg");
        assert_eq!(pic.key, key);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = vec![0u8; 16];
        assert!(ProfilePic::with_url_and_key("https://example.com/pic.jpg", key).is_err());
    }

    #[test]
    fn test_empty_key_is_valid() {
        let pic = ProfilePic::with_url_and_key("https://example.com/pic.jpg", vec![]).unwrap();
        assert!(pic.is_empty()); // Empty key means the pic is not usable
    }

    #[test]
    fn test_empty_url_is_empty() {
        let key = vec![0xABu8; 32];
        let pic = ProfilePic::with_url_and_key("", key).unwrap();
        assert!(pic.is_empty()); // Empty URL means the pic is not usable
    }

    #[test]
    fn test_clear() {
        let key = vec![0xABu8; 32];
        let mut pic = ProfilePic::with_url_and_key("https://example.com/pic.jpg", key).unwrap();
        assert!(!pic.is_empty());
        pic.clear();
        assert!(pic.is_empty());
        assert!(pic.url.is_empty());
        assert!(pic.key.is_empty());
    }

    #[test]
    fn test_set_key() {
        let mut pic = ProfilePic::new();
        pic.url = "https://example.com/pic.jpg".to_string();
        let key = vec![0xCDu8; 32];
        pic.set_key(key.clone()).unwrap();
        assert_eq!(pic.key, key);
        assert!(!pic.is_empty());
    }

    #[test]
    fn test_set_key_invalid() {
        let mut pic = ProfilePic::new();
        assert!(pic.set_key(vec![0u8; 10]).is_err());
    }
}
