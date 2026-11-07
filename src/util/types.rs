//! Session ID validation, URL parsing, UTF-8 truncation, and string splitting.

use thiserror::Error;

/// Error type for utility operations.
#[derive(Debug, Error)]
pub enum UtilError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

/// Validates a 66-character hex session ID starting with "05".
///
/// A valid session ID is exactly 66 hex characters long and begins with the prefix "05".
pub fn session_id_is_valid(hex_str: &str) -> bool {
    if hex_str.len() != 66 {
        return false;
    }
    if !hex_str.starts_with("05") {
        return false;
    }
    hex_str[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Truncates a UTF-8 string to at most `max_bytes` bytes without splitting in the middle
/// of a multi-byte codepoint.
///
/// If the cut point falls inside a multi-byte UTF-8 sequence, the entire codepoint is removed.
pub fn utf8_truncate(val: &str, max_bytes: usize) -> &str {
    if val.len() <= max_bytes {
        return val;
    }
    let bytes = val.as_bytes();
    let mut n = max_bytes;
    // Walk backwards past continuation bytes (0b10xxxxxx)
    while n > 0 && (bytes[n] & 0b1100_0000) == 0b1000_0000 {
        n -= 1;
    }
    // At this point bytes[n] is either the start of a multi-byte sequence or an ASCII byte.
    // If it's the start of a multi-byte sequence that got cut, we need to check if the full
    // sequence fits. Actually, the C++ code just resizes to n, which removes the leading byte
    // of the partial sequence as well only if continuation bytes were stripped. Let's match
    // the C++ behavior exactly: after the loop, n points to the first byte of the partial
    // codepoint (or a valid position). The C++ resizes to n, which excludes that byte.
    // Wait -- re-reading the C++ code: it checks val[n] (the byte *at* position n, which is
    // one past the last included byte). So after resizing to n, bytes 0..n are kept.
    // Our loop does the same: we walk n backward while bytes[n] is a continuation byte.
    // When we stop, bytes[n] is the leading byte of the partial codepoint, and we keep 0..n
    // (exclusive), which drops the partial codepoint entirely.
    &val[..n]
}

/// Parses a URL into (protocol, host, port, path).
///
/// - Protocol is normalized to lowercase with "://" suffix (e.g., "http://", "https://").
/// - Host is normalized to lowercase.
/// - Port is None if not present or if it matches the default for the protocol (80 for http, 443 for https).
/// - Path is None if not present or if it's just a single "/".
pub fn parse_url(
    url: &str,
) -> Result<(String, String, Option<u16>, Option<String>), UtilError> {
    let mut remaining = url;

    // Extract protocol
    let proto = if let Some(pos) = remaining.find("://") {
        let proto_name = &remaining[..pos];
        remaining = &remaining[pos + 3..];
        if proto_name.eq_ignore_ascii_case("http") {
            "http://".to_string()
        } else if proto_name.eq_ignore_ascii_case("https") {
            "https://".to_string()
        } else {
            return Err(UtilError::InvalidUrl("invalid/missing protocol://".into()));
        }
    } else {
        return Err(UtilError::InvalidUrl("invalid/missing protocol://".into()));
    };

    // Extract host
    let mut host = String::new();
    let mut next_allow_dot = false;
    let mut has_dot = false;
    let bytes = remaining.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() || c.is_ascii_lowercase() || c == '-' {
            host.push(c);
            next_allow_dot = true;
        } else if c.is_ascii_uppercase() {
            host.push(c.to_ascii_lowercase());
            next_allow_dot = true;
        } else if next_allow_dot && c == '.' {
            host.push('.');
            has_dot = true;
            next_allow_dot = false;
        } else {
            break;
        }
        i += 1;
    }
    remaining = &remaining[i..];

    if host.len() < 4 || !has_dot || host.ends_with('.') {
        return Err(UtilError::InvalidUrl("invalid hostname".into()));
    }

    // Extract port
    let mut port: Option<u16> = None;
    if remaining.starts_with(':') {
        remaining = &remaining[1..];
        // Find the end of the port number
        let port_end = remaining
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remaining.len());
        if port_end == 0 {
            return Err(UtilError::InvalidUrl("invalid port".into()));
        }
        let port_str = &remaining[..port_end];
        let target_port: u16 = port_str
            .parse()
            .map_err(|_| UtilError::InvalidUrl("invalid port".into()))?;
        remaining = &remaining[port_end..];

        // Omit default ports
        let is_default = (target_port == 80 && proto == "http://")
            || (target_port == 443 && proto == "https://");
        if !is_default {
            port = Some(target_port);
        }
    }

    // Extract path
    let path = if remaining.len() > 1 && remaining.starts_with('/') {
        Some(remaining.to_string())
    } else {
        // A single "/" or empty is treated as no path
        None
    };

    Ok((proto, host, port, path))
}

/// Splits a string on a delimiter, returning a vector of substrings.
///
/// - If `delim` is empty, splits on each character boundary.
/// - If `trim` is true, leading and trailing empty values are suppressed.
pub fn split<'a>(s: &'a str, delim: &str, trim: bool) -> Vec<&'a str> {
    // Special case for empty delimiter: splits on each character boundary
    if delim.is_empty() {
        let mut results = Vec::with_capacity(s.len());
        for (i, c) in s.char_indices() {
            results.push(&s[i..i + c.len_utf8()]);
        }
        return results;
    }

    let mut results: Vec<&'a str> = Vec::new();
    let mut remaining = s;

    loop {
        match remaining.find(delim) {
            Some(pos) => {
                if !trim || !results.is_empty() || pos > 0 {
                    results.push(&remaining[..pos]);
                }
                remaining = &remaining[pos + delim.len()..];
            }
            None => {
                if !trim || !remaining.is_empty() {
                    results.push(remaining);
                } else {
                    // trim trailing empties
                    while results.last().is_some_and(|s| s.is_empty()) {
                        results.pop();
                    }
                }
                break;
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_valid() {
        // Valid: 66 chars, starts with 05, rest is hex
        let valid = "0500000000000000000000000000000000000000000000000000000000000000ff";
        assert!(session_id_is_valid(valid));
    }

    #[test]
    fn test_session_id_wrong_prefix() {
        let bad_prefix = "0600000000000000000000000000000000000000000000000000000000000000ff";
        assert!(!session_id_is_valid(bad_prefix));
    }

    #[test]
    fn test_session_id_wrong_length() {
        let short = "05abcdef";
        assert!(!session_id_is_valid(short));
    }

    #[test]
    fn test_session_id_non_hex() {
        let non_hex = "05gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(!session_id_is_valid(non_hex));
    }

    #[test]
    fn test_utf8_truncate_ascii() {
        assert_eq!(utf8_truncate("hello", 10), "hello");
        assert_eq!(utf8_truncate("hello", 5), "hello");
        assert_eq!(utf8_truncate("hello", 3), "hel");
        assert_eq!(utf8_truncate("hello", 0), "");
    }

    #[test]
    fn test_utf8_truncate_multibyte() {
        // "happy 🎂🎂🎂!!" is 20 bytes
        let s = "happy \u{1F382}\u{1F382}\u{1F382}!!";
        assert_eq!(s.len(), 20);
        assert_eq!(utf8_truncate(s, 20), s);
        assert_eq!(utf8_truncate(s, 25), s);
        assert_eq!(utf8_truncate(s, 19), "happy \u{1F382}\u{1F382}\u{1F382}!");
        assert_eq!(utf8_truncate(s, 18), "happy \u{1F382}\u{1F382}\u{1F382}");
        // 17, 16, 15, 14 all truncate to 14 bytes (two cakes)
        assert_eq!(utf8_truncate(s, 17), "happy \u{1F382}\u{1F382}");
        assert_eq!(utf8_truncate(s, 16), "happy \u{1F382}\u{1F382}");
        assert_eq!(utf8_truncate(s, 15), "happy \u{1F382}\u{1F382}");
        assert_eq!(utf8_truncate(s, 14), "happy \u{1F382}\u{1F382}");
        // 13..10 -> one cake
        assert_eq!(utf8_truncate(s, 13), "happy \u{1F382}");
        assert_eq!(utf8_truncate(s, 10), "happy \u{1F382}");
        // 9..6 -> "happy "
        assert_eq!(utf8_truncate(s, 9), "happy ");
        assert_eq!(utf8_truncate(s, 6), "happy ");
        assert_eq!(utf8_truncate(s, 5), "happy");
    }

    #[test]
    fn test_parse_url_basic() {
        let (proto, host, port, path) = parse_url("https://example.com").unwrap();
        assert_eq!(proto, "https://");
        assert_eq!(host, "example.com");
        assert_eq!(port, None);
        assert_eq!(path, None);
    }

    #[test]
    fn test_parse_url_with_port_and_path() {
        let (proto, host, port, path) = parse_url("http://example.com:8080/foo/bar").unwrap();
        assert_eq!(proto, "http://");
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(8080));
        assert_eq!(path, Some("/foo/bar".to_string()));
    }

    #[test]
    fn test_parse_url_default_port_omitted() {
        let (_, _, port, _) = parse_url("http://example.com:80").unwrap();
        assert_eq!(port, None);

        let (_, _, port, _) = parse_url("https://example.com:443").unwrap();
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_url_invalid() {
        assert!(parse_url("ftp://example.com").is_err());
        assert!(parse_url("notaurl").is_err());
        assert!(parse_url("http://ab").is_err()); // hostname too short
    }

    #[test]
    fn test_split_basic() {
        let v = split("ab--c----de", "--", false);
        assert_eq!(v, vec!["ab", "c", "", "de"]);
    }

    #[test]
    fn test_split_no_delim_in_string() {
        let v = split("abc", "x", false);
        assert_eq!(v, vec!["abc"]);
    }

    #[test]
    fn test_split_trailing() {
        let v = split("abc", "c", false);
        assert_eq!(v, vec!["ab", ""]);
    }

    #[test]
    fn test_split_trailing_trim() {
        let v = split("abc", "c", true);
        assert_eq!(v, vec!["ab"]);
    }

    #[test]
    fn test_split_with_trim() {
        let v = split("-a--b--", "-", false);
        assert_eq!(v, vec!["", "a", "", "b", "", ""]);

        let v = split("-a--b--", "-", true);
        assert_eq!(v, vec!["a", "", "b"]);
    }
}
