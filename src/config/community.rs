//! Community (open group) URL parsing and construction.
//!
//! Port of `libsession-util/src/config/community.cpp` and the corresponding
//! `community.hpp` header. Handles parsing, canonicalization, and construction
//! of community URLs in both the legacy format (`https://server/Room?public_key=...`)
//! and the new format (`https://server/r/Room?public_key=...`).

/// Maximum length of a community base URL.
/// 267 = len("https://") + 253 (max valid DNS name) + len(":XXXXX")
pub const BASE_URL_MAX_LENGTH: usize = 267;

/// Maximum length of a community room token.
pub const ROOM_MAX_LENGTH: usize = 64;

/// Query string parameter used for the public key.
const QS_PUBKEY: &str = "?public_key=";

/// Maximum length of a full community URL (including null terminator space).
pub const FULL_URL_MAX_LENGTH: usize =
    BASE_URL_MAX_LENGTH + 3 /* "/r/" */ + ROOM_MAX_LENGTH + QS_PUBKEY.len() + 64 /* pubkey hex */ + 1; /* null terminator */

/// Errors that can occur during community URL parsing.
#[derive(Debug, thiserror::Error)]
pub enum CommunityError {
    #[error("Invalid community URL: invalid/missing protocol://")]
    InvalidProtocol,
    #[error("Invalid community URL: invalid hostname")]
    InvalidHostname,
    #[error("Invalid community URL: invalid port")]
    InvalidPort,
    #[error("Invalid community URL: base URL is too long")]
    BaseUrlTooLong,
    #[error("Invalid community URL: found unexpected trailing value")]
    UnexpectedTrailingValue,
    #[error("Invalid community room: room token is too long")]
    RoomTooLong,
    #[error("Invalid community room: room token cannot be empty")]
    RoomEmpty,
    #[error("Invalid community URL: room token contains invalid characters")]
    RoomInvalidChars,
    #[error("Invalid community URL: no valid server pubkey")]
    MissingPubkey,
    #[error("Invalid encoded pubkey: expected hex, base32z or base64")]
    InvalidPubkey,
}

/// Parsed URL components: (protocol, host, optional port, optional path).
struct ParsedUrl {
    proto: String,
    host: String,
    port: Option<u16>,
    path: Option<String>,
}

/// Parses a URL into protocol, host, port, and path components.
///
/// Protocol and host are normalized to lower-case. Port is `None` if not present
/// or if it matches the default for the protocol (80 for http, 443 for https).
fn parse_url(url: &str) -> Result<ParsedUrl, CommunityError> {
    let (proto, remainder) = if let Some(pos) = url.find("://") {
        let proto_name = &url[..pos];
        let rest = &url[pos + 3..];
        let proto = if proto_name.eq_ignore_ascii_case("http") {
            "http://".to_string()
        } else if proto_name.eq_ignore_ascii_case("https") {
            "https://".to_string()
        } else {
            return Err(CommunityError::InvalidProtocol);
        };
        (proto, rest)
    } else {
        return Err(CommunityError::InvalidProtocol);
    };

    let mut host = String::new();
    let mut has_dot = false;
    let mut next_allow_dot = false;
    let mut chars = remainder.char_indices();
    let mut consumed = 0;

    for (i, c) in &mut chars {
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
            consumed = i;
            break;
        }
        consumed = i + 1;
    }

    // Handle case where we consumed the entire string
    if consumed == remainder.len() || (consumed > 0 && consumed == remainder.len()) {
        // consumed everything
    }

    let rest = &remainder[consumed..];

    if host.len() < 4 || !has_dot || host.ends_with('.') {
        return Err(CommunityError::InvalidHostname);
    }

    let (port, rest) = if let Some(port_str) = rest.strip_prefix(':') {
        let end = port_str
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(port_str.len());
        if end == 0 {
            return Err(CommunityError::InvalidPort);
        }
        let port_val: u16 = port_str[..end]
            .parse()
            .map_err(|_| CommunityError::InvalidPort)?;
        let rest = &port_str[end..];
        // Suppress default ports
        let port = if (port_val == 80 && proto == "http://")
            || (port_val == 443 && proto == "https://")
        {
            None
        } else {
            Some(port_val)
        };
        (port, rest)
    } else {
        (None, rest)
    };

    let path = if rest.len() > 1 && rest.starts_with('/') {
        Some(rest.to_string())
    } else {
        None
    };

    Ok(ParsedUrl {
        proto,
        host,
        port,
        path,
    })
}

/// Returns the canonical form of a community base URL.
///
/// This lower-cases the URL, strips default ports (80 for http, 443 for https),
/// and rejects URLs with trailing paths.
pub fn canonical_url(url: &str) -> Result<String, CommunityError> {
    let parsed = parse_url(url)?;
    if parsed.path.is_some() {
        return Err(CommunityError::UnexpectedTrailingValue);
    }
    let mut result = parsed.proto;
    result.push_str(&parsed.host);
    if let Some(port) = parsed.port {
        result.push(':');
        result.push_str(&port.to_string());
    }
    if result.len() > BASE_URL_MAX_LENGTH {
        return Err(CommunityError::BaseUrlTooLong);
    }
    Ok(result)
}

/// Returns the canonical (lower-cased) form of a community room token.
///
/// Validates that the room contains only `a-z`, `0-9`, `-`, `_` characters
/// and is not empty or too long.
pub fn canonical_room(room: &str) -> Result<String, CommunityError> {
    let r = room.to_ascii_lowercase();
    validate_room(&r)?;
    Ok(r)
}

/// Validates a canonicalized (already lower-cased) room token.
fn validate_room(room: &str) -> Result<(), CommunityError> {
    if room.len() > ROOM_MAX_LENGTH {
        return Err(CommunityError::RoomTooLong);
    }
    if room.is_empty() {
        return Err(CommunityError::RoomEmpty);
    }
    if !room
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(CommunityError::RoomInvalidChars);
    }
    Ok(())
}

/// Decodes a pubkey from hex (64 chars), base64 (43 or 44 chars), or base32z (52 chars).
fn decode_pubkey(pk: &str) -> Result<[u8; 32], CommunityError> {
    let bytes = if pk.len() == 64 {
        // Try hex
        hex::decode(pk).map_err(|_| CommunityError::InvalidPubkey)?
    } else if pk.len() == 43 || (pk.len() == 44 && pk.ends_with('=')) {
        // Try base64
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
        let input = if pk.len() == 44 { &pk[..43] } else { pk };
        engine
            .decode(input)
            .map_err(|_| CommunityError::InvalidPubkey)?
    } else if pk.len() == 52 {
        // Try base32z -- we need a z-base-32 decoder.
        // z-base-32 uses the alphabet: ybndrfg8ejkmcpqxot1uwisza345h769
        zbase32_decode(pk).ok_or(CommunityError::InvalidPubkey)?
    } else {
        return Err(CommunityError::InvalidPubkey);
    };

    if bytes.len() != 32 {
        return Err(CommunityError::InvalidPubkey);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// z-base-32 alphabet used by oxenc/Session.
const ZBASE32_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Decodes a z-base-32 encoded string into bytes.
fn zbase32_decode(input: &str) -> Option<Vec<u8>> {
    let mut lookup = [255u8; 256];
    for (i, &c) in ZBASE32_ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut output = Vec::new();

    for &c in input.as_bytes() {
        let val = lookup[c as usize];
        if val == 255 {
            return None;
        }
        bits = (bits << 5) | val as u64;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    Some(output)
}

/// Parses a full community URL into `(base_url, room, pubkey)`.
///
/// Accepts both new-style (`https://server/r/Room?public_key=...`) and
/// old-style (`https://server/Room?public_key=...`) URLs.
///
/// The returned base URL is canonicalized (lower-cased, cleaned up).
/// The returned room preserves the original case.
pub fn parse_full_url(full_url: &str) -> Result<(String, String, [u8; 32]), CommunityError> {
    let (base, room, maybe_pk) = parse_partial_url(full_url)?;
    match maybe_pk {
        Some(pk) => Ok((base, room, pk)),
        None => Err(CommunityError::MissingPubkey),
    }
}

/// Parses a full or partial community URL into `(base_url, room, Option<pubkey>)`.
///
/// The public key is optional; if missing, the third element is `None`.
pub fn parse_partial_url(
    url: &str,
) -> Result<(String, String, Option<[u8; 32]>), CommunityError> {
    let mut url = url.to_string();
    let mut maybe_pubkey: Option<[u8; 32]> = None;

    // Extract pubkey from query string if present
    if let Some(pos) = url.rfind(QS_PUBKEY) {
        let pk_str = url[pos + QS_PUBKEY.len()..].to_string();
        maybe_pubkey = Some(decode_pubkey(&pk_str)?);
        url.truncate(pos);
    }

    // Extract room token: look for /r/TOKEN or /TOKEN
    let room_token;
    if let Some(pos) = url.rfind("/r/") {
        room_token = url[pos + 3..].to_string();
        url.truncate(pos);
    } else if let Some(pos) = url.rfind('/') {
        room_token = url[pos + 1..].to_string();
        url.truncate(pos);
    } else {
        room_token = String::new();
    }

    let base_url = canonical_url(&url)?;

    Ok((base_url, room_token, maybe_pubkey))
}

/// Constructs a full community URL from base URL, room token, and pubkey.
///
/// The URL format is: `{base_url}/{room}?public_key={hex_pubkey}`
pub fn make_full_url(base_url: &str, room: &str, pubkey: &[u8; 32]) -> String {
    let mut url = String::with_capacity(
        base_url.len() + 1 + room.len() + QS_PUBKEY.len() + 64,
    );
    url.push_str(base_url);
    url.push('/');
    url.push_str(room);
    url.push_str(QS_PUBKEY);
    url.push_str(&hex::encode(pubkey));
    url
}

/// A community (open group) identified by base URL, room token, and server pubkey.
#[derive(Debug, Clone)]
pub struct Community {
    /// Canonical (lower-cased, normalized) base URL.
    base_url: String,
    /// Canonical (lower-cased) room token.
    room: String,
    /// Original-case room token, if available.
    localized_room: Option<String>,
    /// Server public key (32 bytes).
    pubkey: [u8; 32],
}

impl Community {
    /// Creates a new Community from a base URL, room token, and pubkey.
    ///
    /// The base URL will be canonicalized. The room token is validated and stored
    /// in both canonical (lower-case) and original-case forms.
    pub fn new(
        base_url: &str,
        room: &str,
        pubkey: &[u8; 32],
    ) -> Result<Self, CommunityError> {
        let canonical_base = canonical_url(base_url)?;
        let canonical_rm = canonical_room(room)?;
        Ok(Community {
            base_url: canonical_base,
            room: canonical_rm,
            localized_room: Some(room.to_string()),
            pubkey: *pubkey,
        })
    }

    /// Constructs from a full community URL.
    pub fn from_full_url(full_url: &str) -> Result<Self, CommunityError> {
        let (base_url, room_token, pubkey) = parse_full_url(full_url)?;
        let canonical_rm = canonical_room(&room_token)?;
        Ok(Community {
            base_url,
            room: canonical_rm,
            localized_room: Some(room_token),
            pubkey,
        })
    }

    /// Returns the canonical base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the room token, preserving original case if available.
    pub fn room(&self) -> &str {
        self.localized_room.as_deref().unwrap_or(&self.room)
    }

    /// Returns the canonical (lower-cased) room token.
    pub fn room_norm(&self) -> &str {
        &self.room
    }

    /// Returns the server public key (32 bytes).
    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// Returns the server public key as a hex string (64 characters).
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey)
    }

    /// Constructs and returns the full URL for this community.
    pub fn full_url(&self) -> String {
        make_full_url(&self.base_url, self.room(), &self.pubkey)
    }

    /// Sets the base URL (canonicalizing it).
    pub fn set_base_url(&mut self, url: &str) -> Result<(), CommunityError> {
        self.base_url = canonical_url(url)?;
        Ok(())
    }

    /// Sets the room token (validating and storing both canonical and localized forms).
    pub fn set_room(&mut self, room: &str) -> Result<(), CommunityError> {
        self.room = canonical_room(room)?;
        self.localized_room = Some(room.to_string());
        Ok(())
    }

    /// Sets the pubkey from a 32-byte slice.
    pub fn set_pubkey(&mut self, pubkey: &[u8; 32]) {
        self.pubkey = *pubkey;
    }

    /// Sets the pubkey from an encoded string (hex, base64, or base32z).
    pub fn set_pubkey_encoded(&mut self, pubkey: &str) -> Result<(), CommunityError> {
        self.pubkey = decode_pubkey(pubkey)?;
        Ok(())
    }

    /// Returns true if this community has no meaningful data set.
    pub fn is_empty(&self) -> bool {
        self.base_url.is_empty() || self.room.is_empty() || self.pubkey == [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_url_basic() {
        assert_eq!(
            canonical_url("https://example.com").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_url("HTTPS://EXAMPLE.COM").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_url("https://Example.Com").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_canonical_url_default_port_stripped() {
        assert_eq!(
            canonical_url("https://example.com:443").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_url("http://example.com:80").unwrap(),
            "http://example.com"
        );
    }

    #[test]
    fn test_canonical_url_non_default_port_kept() {
        assert_eq!(
            canonical_url("https://example.com:8080").unwrap(),
            "https://example.com:8080"
        );
        assert_eq!(
            canonical_url("http://example.com:8443").unwrap(),
            "http://example.com:8443"
        );
    }

    #[test]
    fn test_canonical_url_invalid() {
        assert!(canonical_url("ftp://example.com").is_err());
        assert!(canonical_url("example.com").is_err());
        assert!(canonical_url("https://x").is_err()); // Too short hostname, no dot
    }

    #[test]
    fn test_canonical_room() {
        assert_eq!(canonical_room("MyRoom").unwrap(), "myroom");
        assert_eq!(canonical_room("test-room_123").unwrap(), "test-room_123");
    }

    #[test]
    fn test_canonical_room_invalid() {
        assert!(canonical_room("").is_err());
        assert!(canonical_room("room with spaces").is_err());
        let long_room = "a".repeat(ROOM_MAX_LENGTH + 1);
        assert!(canonical_room(&long_room).is_err());
    }

    #[test]
    fn test_parse_full_url() {
        let pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let url = format!("https://example.com/r/TestRoom?public_key={}", pubkey_hex);
        let (base, room, pk) = parse_full_url(&url).unwrap();
        assert_eq!(base, "https://example.com");
        assert_eq!(room, "TestRoom");
        assert_eq!(hex::encode(pk), pubkey_hex);
    }

    #[test]
    fn test_parse_full_url_legacy_format() {
        let pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let url = format!("https://example.com/TestRoom?public_key={}", pubkey_hex);
        let (base, room, pk) = parse_full_url(&url).unwrap();
        assert_eq!(base, "https://example.com");
        assert_eq!(room, "TestRoom");
        assert_eq!(hex::encode(pk), pubkey_hex);
    }

    #[test]
    fn test_parse_partial_url_no_pubkey() {
        let (base, room, pk) =
            parse_partial_url("https://example.com/r/TestRoom").unwrap();
        assert_eq!(base, "https://example.com");
        assert_eq!(room, "TestRoom");
        assert!(pk.is_none());
    }

    #[test]
    fn test_make_full_url() {
        let pubkey = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pubkey);
        let url = make_full_url("https://example.com", "TestRoom", &pk);
        assert_eq!(
            url,
            "https://example.com/TestRoom?public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_community_struct() {
        let pubkey = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pubkey);
        let comm = Community::new("https://example.com", "TestRoom", &pk).unwrap();
        assert_eq!(comm.base_url(), "https://example.com");
        assert_eq!(comm.room(), "TestRoom");
        assert_eq!(comm.room_norm(), "testroom");
        assert_eq!(
            comm.pubkey_hex(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_community_from_full_url() {
        let pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let url = format!("https://example.com/r/MyRoom?public_key={}", pubkey_hex);
        let comm = Community::from_full_url(&url).unwrap();
        assert_eq!(comm.base_url(), "https://example.com");
        assert_eq!(comm.room(), "MyRoom");
        assert_eq!(comm.room_norm(), "myroom");
    }
}
