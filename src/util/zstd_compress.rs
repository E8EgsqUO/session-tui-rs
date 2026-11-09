/// Compresses data using ZSTD with the given compression level.
///
/// An optional `prefix` is prepended to the compressed output (useful for adding
/// magic bytes or version headers before the compressed payload).
///
/// # Panics
///
/// Panics if ZSTD compression fails (which should not happen with valid inputs).
pub fn compress(data: &[u8], level: i32, prefix: &[u8]) -> Vec<u8> {
    let compressed = zstd::bulk::compress(data, level).expect("ZSTD compression failed");

    if prefix.is_empty() {
        compressed
    } else {
        let mut result = Vec::with_capacity(prefix.len() + compressed.len());
        result.extend_from_slice(prefix);
        result.extend_from_slice(&compressed);
        result
    }
}

/// Decompresses ZSTD-compressed data.
///
/// Returns `None` if:
/// - Decompression fails (invalid/corrupt data)
/// - The decompressed size would exceed `max_size` (when `max_size > 0`)
///
/// When `max_size` is 0, no size limit is enforced.
pub fn decompress(data: &[u8], max_size: usize) -> Option<Vec<u8>> {
    // If max_size is specified, check the frame content size first when available
    if max_size > 0 {
        // Try to get the decompressed size from the frame header
        if let Ok(Some(size)) = zstd::zstd_safe::get_frame_content_size(data)
            && size as usize > max_size
        {
            return None;
        }
    }

    // Use streaming decompression to handle unknown sizes and enforce limits
    use std::io::Read;
    let mut decoder = zstd::stream::read::Decoder::new(data).ok()?;

    let mut decompressed = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = decoder.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }

        if max_size > 0 && decompressed.len() + n > max_size {
            return None;
        }

        decompressed.extend_from_slice(&buf[..n]);
    }

    Some(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let original = b"Hello, world! This is some test data for ZSTD compression.";
        let compressed = compress(original, 1, &[]);
        let decompressed = decompress(&compressed, 0).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compress_with_prefix() {
        let original = b"test data";
        let prefix = b"PREFIX";
        let result = compress(original, 1, prefix);

        // Result should start with the prefix
        assert!(result.starts_with(prefix));

        // Decompressing the part after the prefix should yield the original
        let decompressed = decompress(&result[prefix.len()..], 0).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_max_size_exceeded() {
        let original = vec![0u8; 10_000];
        let compressed = compress(&original, 1, &[]);

        // Should fail if max_size is smaller than the decompressed data
        let result = decompress(&compressed, 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_decompress_max_size_ok() {
        let original = b"small data";
        let compressed = compress(original, 1, &[]);

        let result = decompress(&compressed, 1_000_000);
        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_decompress_invalid_data() {
        let garbage = b"this is not zstd data at all";
        assert!(decompress(garbage, 0).is_none());
    }

    #[test]
    fn test_compress_empty() {
        let original = b"";
        let compressed = compress(original, 1, &[]);
        let decompressed = decompress(&compressed, 0).unwrap();
        assert_eq!(decompressed, original.as_slice());
    }

    #[test]
    fn test_compress_large_data() {
        // Test with repetitive data that compresses well
        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = compress(&original, 3, &[]);
        assert!(compressed.len() < original.len()); // Should actually compress
        let decompressed = decompress(&compressed, 200_000).unwrap();
        assert_eq!(decompressed, original);
    }
}
