//! BLAKE2b hashing with optional key and variable output size.
//!
//! Port of `libsession-util/src/hash.cpp`. Uses `blake2b_simd` for the
//! underlying BLAKE2b implementation, which natively supports keyed hashing
//! with variable output length.

use crate::crypto::types::{CryptoError, CryptoResult};

/// Computes a BLAKE2b hash of `msg` with variable output `size` and optional `key`.
///
/// - `size` must be in the range 16..=64.
/// - `key`, if provided, must be at most 64 bytes.
pub fn hash(size: usize, msg: &[u8], key: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
    if !(16..=64).contains(&size) {
        return Err(CryptoError::InvalidInput(
            "hash size must be between 16 and 64 bytes (inclusive)".into(),
        ));
    }

    if let Some(k) = key
        && k.len() > 64
    {
        return Err(CryptoError::InvalidInput(
            "key must be less than 65 bytes".into(),
        ));
    }

    let mut params = blake2b_simd::Params::new();
    params.hash_length(size);
    if let Some(k) = key {
        params.key(k);
    }

    let result = params.hash(msg);
    Ok(result.as_bytes()[..size].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_unkeyed_32() {
        let h1 = hash(32, b"TestMessage", None).unwrap();
        let h2 = hash(32, b"TestMessage", None).unwrap();
        assert_eq!(h1.len(), 32);
        assert_eq!(h1, h2);
        assert_eq!(
            hex::encode(&h1),
            "2a48a12262e4548afb97fe2b04a912a02297d451169ee7ef2d01a28ea20286ab"
        );
    }

    #[test]
    fn test_hash_keyed_32() {
        let h3 = hash(32, b"TestMessage", Some(b"TestKey")).unwrap();
        let h4 = hash(32, b"TestMessage", Some(b"TestKey")).unwrap();
        assert_eq!(h3.len(), 32);
        assert_eq!(h3, h4);
        assert_eq!(
            hex::encode(&h3),
            "3d643e479b626bb2907476e32ccf7bdbd1ac3efa0da6e2c335255c48dcc216b6"
        );
    }

    #[test]
    fn test_hash_unkeyed_vs_keyed_differ() {
        let h1 = hash(32, b"TestMessage", None).unwrap();
        let h3 = hash(32, b"TestMessage", Some(b"TestKey")).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hash_unkeyed_64() {
        let h5 = hash(64, b"TestMessage", None).unwrap();
        assert_eq!(h5.len(), 64);
        let expected = "9d9085ac026fe3542abbeb2ea2ec05f5c37aecd7695f6cc41e9ccf39014196a3\
             9c02db69c4416d5c45acc2e9469b7f274992b2858f3bb2746becb48c8b56ce4b";
        assert_eq!(hex::encode(&h5), expected);
    }

    #[test]
    fn test_hash_keyed_64() {
        let h6 = hash(64, b"TestMessage", Some(b"TestKey")).unwrap();
        assert_eq!(h6.len(), 64);
        let expected = "6a2faad89cf9010a4270cba07cc96cfb36688106e080b15fef66bb03c68e8778\
             74c9059edf53d03c1330b2655efdad6e4aa259118b6ea88698ea038efb9d52ce";
        assert_eq!(hex::encode(&h6), expected);
    }

    #[test]
    fn test_hash_32_vs_64_differ() {
        let h1 = hash(32, b"TestMessage", None).unwrap();
        let h5 = hash(64, b"TestMessage", None).unwrap();
        // Different output sizes produce different hashes (not just truncation)
        assert_ne!(&h1[..], &h5[..32]);
    }

    #[test]
    fn test_hash_invalid_size_too_small() {
        assert!(hash(10, b"TestMessage", None).is_err());
    }

    #[test]
    fn test_hash_invalid_size_too_large() {
        assert!(hash(100, b"TestMessage", None).is_err());
    }

    #[test]
    fn test_hash_key_too_long() {
        let long_key =
            b"KeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLong";
        assert!(long_key.len() > 64);
        assert!(hash(32, b"TestMessage", Some(long_key)).is_err());
    }
}
