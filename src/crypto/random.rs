//! Cryptographic random number generation utilities.
//!
//! Port of `libsession-util/src/random.cpp`.

use rand::RngExt;
use std::sync::atomic::{AtomicU32, Ordering};

/// Generates `size` bytes of cryptographically secure random data.
pub fn random(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rand::rng().fill(&mut buf[..]);
    buf
}

const BASE32_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generates a random base32-encoded string of the given length.
///
/// Each character is independently and uniformly chosen from the RFC 4648
/// base32 alphabet (`A-Z`, `2-7`).
pub fn random_base32(size: usize) -> String {
    let mut result = String::with_capacity(size);
    let mut rng = rand::rng();
    while result.len() < size {
        let bits: u64 = rng.random();
        let mut b = bits;
        // 64 bits / 5 bits per char = 12 chars per u64
        for _ in 0..12 {
            if result.len() >= size {
                break;
            }
            result.push(BASE32_CHARSET[(b & 0x1f) as usize] as char);
            b >>= 5;
        }
    }
    result
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Generates a unique identifier string of the form `"{prefix}-{counter}-{random4}"`.
///
/// The counter is a monotonically increasing process-global value. The random
/// suffix is 4 base32 characters.
pub fn unique_id(prefix: &str) -> String {
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", prefix, count, random_base32(4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_length() {
        assert_eq!(random(0).len(), 0);
        assert_eq!(random(1).len(), 1);
        assert_eq!(random(32).len(), 32);
        assert_eq!(random(64).len(), 64);
        assert_eq!(random(1024).len(), 1024);
    }

    #[test]
    fn test_random_not_all_zeros() {
        // With overwhelming probability, 32 random bytes are not all zeros
        let buf = random(32);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_different_each_call() {
        let a = random(32);
        let b = random(32);
        assert_ne!(a, b);
    }

    #[test]
    fn test_random_base32_length() {
        assert_eq!(random_base32(0).len(), 0);
        assert_eq!(random_base32(1).len(), 1);
        assert_eq!(random_base32(4).len(), 4);
        assert_eq!(random_base32(10).len(), 10);
        assert_eq!(random_base32(100).len(), 100);
    }

    #[test]
    fn test_random_base32_valid_chars() {
        let s = random_base32(100);
        for c in s.chars() {
            assert!(
                ('A'..='Z').contains(&c) || ('2'..='7').contains(&c),
                "invalid base32 character: {c}"
            );
        }
    }

    #[test]
    fn test_random_base32_different_each_call() {
        let a = random_base32(20);
        let b = random_base32(20);
        assert_ne!(a, b);
    }

    #[test]
    fn test_unique_id_format() {
        let id = unique_id("test");
        let parts: Vec<&str> = id.splitn(3, '-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "test");
        // parts[1] should be a number
        assert!(parts[1].parse::<u32>().is_ok());
        // parts[2] should be 4 base32 chars
        assert_eq!(parts[2].len(), 4);
        for c in parts[2].chars() {
            assert!(('A'..='Z').contains(&c) || ('2'..='7').contains(&c));
        }
    }

    #[test]
    fn test_unique_id_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| unique_id("test")).collect();
        // All IDs should be unique
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }
    }

    #[test]
    fn test_unique_id_counter_increments() {
        let id1 = unique_id("x");
        let id2 = unique_id("x");
        let n1: u32 = id1.splitn(3, '-').nth(1).unwrap().parse().unwrap();
        let n2: u32 = id2.splitn(3, '-').nth(1).unwrap().parse().unwrap();
        assert!(n2 > n1);
    }
}
