//! File server types and URL parsing.
//!
//! Full port of `session::network::file_server` from the C++ code.

/// File server configuration.
#[derive(Debug, Clone)]
pub struct FileServerConfig {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub pubkey_hex: String,
    pub max_file_size: u64,
    /// Whether to use stream-based attachment encryption.
    pub use_stream_encryption: bool,
}

/// Default file server configuration matching the C++ `DEFAULT_CONFIG`.
pub fn default_config() -> FileServerConfig {
    FileServerConfig {
        scheme: "http".to_string(),
        host: "filev2.getsession.org".to_string(),
        port: 80,
        pubkey_hex: "da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59"
            .to_string(),
        max_file_size: 10_000_000,
        use_stream_encryption: false,
    }
}

/// Known header constants.
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_CONTENT_DISPOSITION: &str = "Content-Disposition";
pub const HEADER_PUBKEY: &str = "X-FS-Pubkey";
/// Header for file server upload timestamp.
pub const HEADER_TIMESTAMP: &str = "X-FS-Timestamp";
/// Header for file server Ed25519 signature.
pub const HEADER_SIGNATURE: &str = "X-FS-Signature";
/// Header for file server time-to-live.
pub const HEADER_TTL: &str = "X-FS-TTL";

/// Endpoint patterns.
pub const ENDPOINT_FILE: &str = "file";
pub const ENDPOINT_FILE_INDIVIDUAL: &str = "file/{}";
pub const ENDPOINT_EXTEND: &str = "file/{}/extend";
/// Legacy endpoint pattern for individual file access.
pub const LEGACY_ENDPOINT_FILE_INDIVIDUAL: &str = "files/{}";

/// Fragment constants.
pub const FRAGMENT_PUBKEY: &str = "p";
pub const FRAGMENT_STREAM_ENCRYPTION: &str = "d";

/// Parsed download URL information.
#[derive(Debug, Clone)]
pub struct DownloadInfo {
    pub scheme: String,
    pub host: String,
    pub file_id: String,
    pub custom_pubkey_hex: Option<String>,
    pub wants_stream_decryption: bool,
}

/// Parses a download URL to extract the information required to download a file.
///
/// Expected format: `{scheme}://{host}/file/{file_id}(#p={customPubkey})(&d)`
///
/// Examples:
///   - `https://example.com/file/abc123`
///   - `https://example.com/file/abc123#p=da21e...&d`
pub fn parse_download_url(url: &str) -> Option<DownloadInfo> {
    // Try matching /file/{id} pattern
    let (base, file_id) = match_file_endpoint(url, "/file/")
        .or_else(|| match_file_endpoint(url, "/files/"))?;

    if file_id.is_empty() {
        return None;
    }

    // Extract scheme and host from base
    let scheme_end = base.find("://")?;
    let scheme = &base[..scheme_end];
    let host = &base[scheme_end + 3..];

    if host.is_empty() {
        return None;
    }

    let mut info = DownloadInfo {
        scheme: scheme.to_string(),
        host: host.to_string(),
        file_id: file_id.to_string(),
        custom_pubkey_hex: None,
        wants_stream_decryption: false,
    };

    // Parse fragments
    if let Some(fragment_pos) = url.find('#') {
        let fragments = &url[fragment_pos + 1..];
        let default_pk = default_config().pubkey_hex;

        for fragment in fragments.split('&') {
            if fragment == FRAGMENT_STREAM_ENCRYPTION {
                info.wants_stream_decryption = true;
            } else if fragment.starts_with(&format!("{}=", FRAGMENT_PUBKEY)) {
                let pk_value = &fragment[2..];
                // Must be 64 hex chars and not the default pubkey
                if pk_value.len() == 64
                    && hex::decode(pk_value).is_ok()
                    && pk_value != default_pk
                {
                    info.custom_pubkey_hex = Some(pk_value.to_string());
                }
            }
        }
    }

    Some(info)
}

/// Generates a download URL for a given file ID and configuration.
pub fn generate_download_url(file_id: &str, config: &FileServerConfig) -> String {
    let default_pk = default_config().pubkey_hex;
    let has_custom_pubkey = config.pubkey_hex != default_pk;

    let mut url = format!("{}://{}/file/{}", config.scheme, config.host, file_id);

    if config.use_stream_encryption || has_custom_pubkey {
        url.push('#');

        if has_custom_pubkey {
            url.push_str(&format!("{}={}", FRAGMENT_PUBKEY, config.pubkey_hex));
        }

        if config.use_stream_encryption {
            if has_custom_pubkey {
                url.push('&');
            }
            url.push_str(FRAGMENT_STREAM_ENCRYPTION);
        }
    }

    url
}

/// File metadata returned by the file server.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub id: String,
    pub size: i64,
    pub uploaded: Option<i64>,
    pub expiry: Option<i64>,
}

/// Parses an upload response JSON into file metadata.
pub fn parse_upload_response(
    body: &str,
    upload_size: usize,
) -> Result<FileMetadata, String> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|e| e.to_string())?;

    let id = json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("Upload response missing required 'id' field")?
        .to_string();

    let mut size = json
        .get("size")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    if size == 0 {
        size = upload_size as i64;
    }

    let uploaded = json
        .get("uploaded")
        .and_then(|v| v.as_i64());

    let expiry = json
        .get("expires")
        .and_then(|v| v.as_i64());

    Ok(FileMetadata {
        id,
        size,
        uploaded,
        expiry,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Matches a URL against a file endpoint pattern like `/file/{id}`.
/// Returns (base_url, file_id) if matched.
fn match_file_endpoint<'a>(url: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let pattern_start = url.find(prefix)?;
    let base = &url[..pattern_start];
    let after_prefix = &url[pattern_start + prefix.len()..];

    // File ID goes until fragment (#) or query (?) or end
    let id_end = after_prefix
        .find(|c: char| c == '#' || c == '?' || c == '/')
        .unwrap_or(after_prefix.len());

    let file_id = &after_prefix[..id_end];
    Some((base, file_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = default_config();
        assert_eq!(config.scheme, "http");
        assert_eq!(config.host, "filev2.getsession.org");
        assert_eq!(config.port, 80);
        assert_eq!(config.max_file_size, 10_000_000);
    }

    #[test]
    fn test_parse_download_url_basic() {
        let url = "https://example.com/file/abc123";
        let info = parse_download_url(url).unwrap();
        assert_eq!(info.scheme, "https");
        assert_eq!(info.host, "example.com");
        assert_eq!(info.file_id, "abc123");
        assert!(info.custom_pubkey_hex.is_none());
        assert!(!info.wants_stream_decryption);
    }

    #[test]
    fn test_parse_download_url_with_custom_pubkey() {
        let url = "https://example.com/file/abc123#p=aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
        let info = parse_download_url(url).unwrap();
        assert_eq!(info.file_id, "abc123");
        assert_eq!(
            info.custom_pubkey_hex.as_deref(),
            Some("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd")
        );
    }

    #[test]
    fn test_parse_download_url_with_stream_decryption() {
        let url = "https://example.com/file/abc123#d";
        let info = parse_download_url(url).unwrap();
        assert!(info.wants_stream_decryption);
    }

    #[test]
    fn test_parse_download_url_with_both_fragments() {
        let url = "https://example.com/file/abc123#p=aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd&d";
        let info = parse_download_url(url).unwrap();
        assert!(info.custom_pubkey_hex.is_some());
        assert!(info.wants_stream_decryption);
    }

    #[test]
    fn test_parse_download_url_legacy() {
        let url = "https://example.com/files/abc123";
        let info = parse_download_url(url).unwrap();
        assert_eq!(info.file_id, "abc123");
    }

    #[test]
    fn test_parse_download_url_invalid() {
        assert!(parse_download_url("not-a-url").is_none());
        assert!(parse_download_url("").is_none());
    }

    #[test]
    fn test_generate_download_url_basic() {
        let config = default_config();
        let url = generate_download_url("abc123", &config);
        assert_eq!(url, "http://filev2.getsession.org/file/abc123");
    }

    #[test]
    fn test_generate_download_url_with_stream_encryption() {
        let mut config = default_config();
        config.use_stream_encryption = true;
        let url = generate_download_url("abc123", &config);
        assert_eq!(url, "http://filev2.getsession.org/file/abc123#d");
    }

    #[test]
    fn test_generate_download_url_with_custom_pubkey() {
        let mut config = default_config();
        config.pubkey_hex = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
            .to_string();
        let url = generate_download_url("abc123", &config);
        assert!(url.contains("#p=aabbccdd"));
    }

    #[test]
    fn test_generate_download_url_with_both() {
        let mut config = default_config();
        config.pubkey_hex = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
            .to_string();
        config.use_stream_encryption = true;
        let url = generate_download_url("abc123", &config);
        assert!(url.contains("#p=aabbccdd"));
        assert!(url.contains("&d"));
    }

    #[test]
    fn test_parse_upload_response() {
        let body = r#"{"id":"file123","size":1024,"uploaded":1700000000,"expires":1700086400}"#;
        let meta = parse_upload_response(body, 0).unwrap();
        assert_eq!(meta.id, "file123");
        assert_eq!(meta.size, 1024);
        assert_eq!(meta.uploaded, Some(1700000000));
        assert_eq!(meta.expiry, Some(1700086400));
    }

    #[test]
    fn test_parse_upload_response_fallback_size() {
        let body = r#"{"id":"file123"}"#;
        let meta = parse_upload_response(body, 500).unwrap();
        assert_eq!(meta.id, "file123");
        assert_eq!(meta.size, 500);
    }

    #[test]
    fn test_parse_upload_response_missing_id() {
        let body = r#"{"size":1024}"#;
        assert!(parse_upload_response(body, 0).is_err());
    }

    #[test]
    fn test_roundtrip_url() {
        let config = default_config();
        let url = generate_download_url("testfile42", &config);
        let parsed = parse_download_url(&url).unwrap();
        assert_eq!(parsed.file_id, "testfile42");
        assert_eq!(parsed.scheme, config.scheme);
        assert_eq!(parsed.host, config.host);
    }
}
