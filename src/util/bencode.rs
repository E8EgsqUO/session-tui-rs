//! Bencode encoding, decoding, and merge operations.
//!
//! Implements the [bencode](https://en.wikipedia.org/wiki/Bencode) serialization
//! format used by Session's config system. Includes merge functions for
//! deterministic conflict resolution.

use std::collections::BTreeMap;
use thiserror::Error;

/// Error type for bencode parsing operations.
#[derive(Debug, Error)]
pub enum BencodeError {
    #[error("Unexpected end of data")]
    UnexpectedEof,
    #[error("Invalid bencode at position {0}: {1}")]
    InvalidData(usize, String),
    #[error("Integer overflow")]
    IntegerOverflow,
}

/// A bencode value.
///
/// Dicts use `Vec<u8>` keys (bencode strings are arbitrary bytes, not necessarily UTF-8).
/// Dict keys are stored in a `BTreeMap` to guarantee sorted order, as required by the
/// bencode specification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BtValue {
    Integer(i64),
    String(Vec<u8>),
    List(Vec<BtValue>),
    Dict(BTreeMap<Vec<u8>, BtValue>),
}

/// Convenience alias for bencode dicts.
pub type BtDict = BTreeMap<Vec<u8>, BtValue>;

/// Convenience alias for bencode lists.
pub type BtList = Vec<BtValue>;

// ── Encoding ──────────────────────────────────────────────────────────────────

/// Encodes a `BtValue` into bencode bytes.
pub fn encode(value: &BtValue) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_into(value, &mut buf);
    buf
}

fn encode_into(value: &BtValue, buf: &mut Vec<u8>) {
    match value {
        BtValue::Integer(n) => {
            buf.push(b'i');
            buf.extend_from_slice(n.to_string().as_bytes());
            buf.push(b'e');
        }
        BtValue::String(s) => {
            buf.extend_from_slice(s.len().to_string().as_bytes());
            buf.push(b':');
            buf.extend_from_slice(s);
        }
        BtValue::List(items) => {
            buf.push(b'l');
            for item in items {
                encode_into(item, buf);
            }
            buf.push(b'e');
        }
        BtValue::Dict(map) => {
            buf.push(b'd');
            // BTreeMap iteration is already sorted by key
            for (key, val) in map {
                // Encode key as a bencode string
                buf.extend_from_slice(key.len().to_string().as_bytes());
                buf.push(b':');
                buf.extend_from_slice(key);
                encode_into(val, buf);
            }
            buf.push(b'e');
        }
    }
}

// ── Decoding ──────────────────────────────────────────────────────────────────

/// Decodes bencode bytes into a `BtValue`.
pub fn decode(data: &[u8]) -> Result<BtValue, BencodeError> {
    let (value, consumed) = decode_value(data, 0, 0)?;
    if consumed != data.len() {
        return Err(BencodeError::InvalidData(
            consumed,
            "trailing data after value".into(),
        ));
    }
    Ok(value)
}

/// Deepest list/dict nesting accepted. Real Session data nests a few levels;
/// the limit stops crafted input from overflowing the stack.
const MAX_DEPTH: usize = 64;

/// Decodes a value starting at position `pos`. Returns (value, new_position).
fn decode_value(data: &[u8], pos: usize, depth: usize) -> Result<(BtValue, usize), BencodeError> {
    if pos >= data.len() {
        return Err(BencodeError::UnexpectedEof);
    }
    if depth > MAX_DEPTH {
        return Err(BencodeError::InvalidData(pos, "nested too deeply".into()));
    }

    match data[pos] {
        b'i' => decode_integer(data, pos),
        b'l' => decode_list(data, pos, depth),
        b'd' => decode_dict(data, pos, depth),
        b'0'..=b'9' => decode_string(data, pos),
        _ => Err(BencodeError::InvalidData(
            pos,
            format!("unexpected byte 0x{:02x}", data[pos]),
        )),
    }
}

fn decode_integer(data: &[u8], pos: usize) -> Result<(BtValue, usize), BencodeError> {
    debug_assert_eq!(data[pos], b'i');
    let start = pos + 1; // skip 'i'
    let end = data[start..]
        .iter()
        .position(|&b| b == b'e')
        .map(|p| start + p)
        .ok_or(BencodeError::UnexpectedEof)?;

    let num_str = std::str::from_utf8(&data[start..end])
        .map_err(|_| BencodeError::InvalidData(start, "invalid integer encoding".into()))?;

    // Validate: no leading zeros (except for "0" itself), no "-0"
    if num_str.is_empty() {
        return Err(BencodeError::InvalidData(start, "empty integer".into()));
    }
    if num_str == "-0" {
        return Err(BencodeError::InvalidData(start, "negative zero".into()));
    }
    if num_str.len() > 1 && num_str.starts_with('0') {
        return Err(BencodeError::InvalidData(start, "leading zero".into()));
    }
    if num_str.len() > 2 && num_str.starts_with("-0") {
        return Err(BencodeError::InvalidData(
            start,
            "leading zero after minus".into(),
        ));
    }

    let n: i64 = num_str.parse().map_err(|_| BencodeError::IntegerOverflow)?;
    Ok((BtValue::Integer(n), end + 1)) // +1 for 'e'
}

fn decode_string(data: &[u8], pos: usize) -> Result<(BtValue, usize), BencodeError> {
    // Read length prefix
    let colon_pos = data[pos..]
        .iter()
        .position(|&b| b == b':')
        .map(|p| pos + p)
        .ok_or(BencodeError::InvalidData(
            pos,
            "missing ':' in string length".into(),
        ))?;

    let len_str = std::str::from_utf8(&data[pos..colon_pos])
        .map_err(|_| BencodeError::InvalidData(pos, "invalid string length".into()))?;
    let len: usize = len_str
        .parse()
        .map_err(|_| BencodeError::InvalidData(pos, "invalid string length number".into()))?;

    let str_start = colon_pos + 1;
    let str_end = str_start
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or(BencodeError::UnexpectedEof)?;

    Ok((BtValue::String(data[str_start..str_end].to_vec()), str_end))
}

fn decode_list(data: &[u8], pos: usize, depth: usize) -> Result<(BtValue, usize), BencodeError> {
    debug_assert_eq!(data[pos], b'l');
    let mut current = pos + 1; // skip 'l'
    let mut items = Vec::new();

    loop {
        if current >= data.len() {
            return Err(BencodeError::UnexpectedEof);
        }
        if data[current] == b'e' {
            return Ok((BtValue::List(items), current + 1));
        }
        let (value, next) = decode_value(data, current, depth + 1)?;
        items.push(value);
        current = next;
    }
}

fn decode_dict(data: &[u8], pos: usize, depth: usize) -> Result<(BtValue, usize), BencodeError> {
    debug_assert_eq!(data[pos], b'd');
    let mut current = pos + 1; // skip 'd'
    let mut map = BTreeMap::new();
    let mut last_key: Option<Vec<u8>> = None;

    loop {
        if current >= data.len() {
            return Err(BencodeError::UnexpectedEof);
        }
        if data[current] == b'e' {
            return Ok((BtValue::Dict(map), current + 1));
        }

        // Keys must be strings
        let (key_value, after_key) = decode_string(data, current)?;
        let key = match key_value {
            BtValue::String(k) => k,
            _ => unreachable!(), // decode_string always returns BtValue::String
        };

        // Verify keys are in sorted order
        if let Some(ref prev) = last_key
            && key <= *prev {
                return Err(BencodeError::InvalidData(
                    current,
                    "dict keys not in sorted order or duplicate key".into(),
                ));
            }
        last_key = Some(key.clone());

        let (val, after_val) = decode_value(data, after_key, depth + 1)?;
        map.insert(key, val);
        current = after_val;
    }
}

// ── Merge ─────────────────────────────────────────────────────────────────────

/// Merges two bencode dicts. Keys present in both dicts take their value from `a`.
/// Keys present in only one dict are included from whichever contains them.
///
/// This is the critical function for Session's config sync: when two config
/// snapshots need to be merged, dict `a` has priority.
pub fn merge_dicts(a: &BtDict, b: &BtDict) -> BtDict {
    let mut result = BTreeMap::new();
    let mut it_a = a.iter().peekable();
    let mut it_b = b.iter().peekable();

    loop {
        match (it_a.peek(), it_b.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                // Remaining from a
                for (k, v) in it_a {
                    result.insert(k.clone(), v.clone());
                }
                break;
            }
            (None, Some(_)) => {
                // Remaining from b
                for (k, v) in it_b {
                    result.insert(k.clone(), v.clone());
                }
                break;
            }
            (Some((ka, _)), Some((kb, _))) => {
                let cmp = ka.cmp(kb);
                match cmp {
                    std::cmp::Ordering::Less => {
                        let (k, v) = it_a.next().unwrap();
                        result.insert(k.clone(), v.clone());
                    }
                    std::cmp::Ordering::Greater => {
                        let (k, v) = it_b.next().unwrap();
                        result.insert(k.clone(), v.clone());
                    }
                    std::cmp::Ordering::Equal => {
                        // Equal keys: take value from a, skip b
                        let (k, v) = it_a.next().unwrap();
                        result.insert(k.clone(), v.clone());
                        it_b.next();
                    }
                }
            }
        }
    }

    result
}

/// Merges two sorted bencode lists. Elements from `a` take priority (duplicates
/// from `b` are skipped by default).
///
/// The comparison uses the derived `Ord` on `BtValue`.
pub fn merge_sorted_lists(a: &[BtValue], b: &[BtValue]) -> Vec<BtValue> {
    let mut result = Vec::new();
    let mut it_a = a.iter().peekable();
    let mut it_b = b.iter().peekable();

    loop {
        match (it_a.peek(), it_b.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                result.extend(it_a.cloned());
                break;
            }
            (None, Some(_)) => {
                result.extend(it_b.cloned());
                break;
            }
            (Some(va), Some(vb)) => {
                match va.cmp(vb) {
                    std::cmp::Ordering::Less => {
                        result.push(it_a.next().unwrap().clone());
                    }
                    std::cmp::Ordering::Greater => {
                        result.push(it_b.next().unwrap().clone());
                    }
                    std::cmp::Ordering::Equal => {
                        // Equal: take from a, skip b
                        result.push(it_a.next().unwrap().clone());
                        it_b.next();
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_integer() {
        assert_eq!(encode(&BtValue::Integer(42)), b"i42e");
        assert_eq!(encode(&BtValue::Integer(0)), b"i0e");
        assert_eq!(encode(&BtValue::Integer(-5)), b"i-5e");
    }

    #[test]
    fn test_encode_string() {
        assert_eq!(
            encode(&BtValue::String(b"spam".to_vec())),
            b"4:spam"
        );
        assert_eq!(encode(&BtValue::String(vec![])), b"0:");
    }

    #[test]
    fn test_encode_list() {
        let list = BtValue::List(vec![
            BtValue::String(b"spam".to_vec()),
            BtValue::Integer(42),
        ]);
        assert_eq!(encode(&list), b"l4:spami42ee");
    }

    #[test]
    fn test_encode_dict() {
        let mut dict = BTreeMap::new();
        dict.insert(b"cow".to_vec(), BtValue::String(b"moo".to_vec()));
        dict.insert(b"spam".to_vec(), BtValue::Integer(3));
        let val = BtValue::Dict(dict);
        assert_eq!(encode(&val), b"d3:cow3:moo4:spami3ee");
    }

    #[test]
    fn test_decode_integer() {
        assert_eq!(decode(b"i42e").unwrap(), BtValue::Integer(42));
        assert_eq!(decode(b"i0e").unwrap(), BtValue::Integer(0));
        assert_eq!(decode(b"i-5e").unwrap(), BtValue::Integer(-5));
    }

    #[test]
    fn test_decode_integer_invalid() {
        assert!(decode(b"i-0e").is_err()); // negative zero
        assert!(decode(b"i03e").is_err()); // leading zero
        assert!(decode(b"ie").is_err()); // empty
    }

    #[test]
    fn test_decode_string() {
        assert_eq!(
            decode(b"4:spam").unwrap(),
            BtValue::String(b"spam".to_vec())
        );
        assert_eq!(decode(b"0:").unwrap(), BtValue::String(vec![]));
    }

    #[test]
    fn test_decode_list() {
        let result = decode(b"l4:spami42ee").unwrap();
        assert_eq!(
            result,
            BtValue::List(vec![
                BtValue::String(b"spam".to_vec()),
                BtValue::Integer(42),
            ])
        );
    }

    #[test]
    fn test_decode_dict() {
        let result = decode(b"d3:cow3:moo4:spami3ee").unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(b"cow".to_vec(), BtValue::String(b"moo".to_vec()));
        expected.insert(b"spam".to_vec(), BtValue::Integer(3));
        assert_eq!(result, BtValue::Dict(expected));
    }

    #[test]
    fn test_decode_rejects_malformed_input_without_panicking() {
        // Length that overflows usize when added to the start offset.
        assert!(decode(format!("{}:x", usize::MAX).as_bytes()).is_err());
        assert!(decode(b"l18446744073709551615:xe").is_err());
        // Length past the end.
        assert!(decode(b"5:abc").is_err());
        // Nesting far beyond anything real.
        let deep = "l".repeat(100_000) + &"e".repeat(100_000);
        assert!(decode(deep.as_bytes()).is_err());
        let ok = "l".repeat(10) + &"e".repeat(10);
        assert!(decode(ok.as_bytes()).is_ok());
    }

    #[test]
    fn test_roundtrip() {
        let mut dict = BTreeMap::new();
        dict.insert(
            b"key1".to_vec(),
            BtValue::List(vec![
                BtValue::Integer(1),
                BtValue::Integer(2),
                BtValue::String(b"three".to_vec()),
            ]),
        );
        dict.insert(b"key2".to_vec(), BtValue::Integer(-100));
        let original = BtValue::Dict(dict);
        let encoded = encode(&original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_merge_dicts_basic() {
        let mut a = BTreeMap::new();
        a.insert(b"x".to_vec(), BtValue::Integer(1));
        a.insert(b"z".to_vec(), BtValue::Integer(3));

        let mut b = BTreeMap::new();
        b.insert(b"x".to_vec(), BtValue::Integer(10)); // conflict: a wins
        b.insert(b"y".to_vec(), BtValue::Integer(2));

        let merged = merge_dicts(&a, &b);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[b"x".as_ref()], BtValue::Integer(1)); // a wins
        assert_eq!(merged[b"y".as_ref()], BtValue::Integer(2)); // from b
        assert_eq!(merged[b"z".as_ref()], BtValue::Integer(3)); // from a
    }

    #[test]
    fn test_merge_dicts_disjoint() {
        let mut a = BTreeMap::new();
        a.insert(b"a".to_vec(), BtValue::Integer(1));

        let mut b = BTreeMap::new();
        b.insert(b"b".to_vec(), BtValue::Integer(2));

        let merged = merge_dicts(&a, &b);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_dicts_empty() {
        let a = BTreeMap::new();
        let mut b = BTreeMap::new();
        b.insert(b"x".to_vec(), BtValue::Integer(1));

        assert_eq!(merge_dicts(&a, &b), b);
        assert_eq!(merge_dicts(&b, &a), b);
    }

    #[test]
    fn test_merge_sorted_lists() {
        let a = vec![BtValue::Integer(1), BtValue::Integer(3), BtValue::Integer(5)];
        let b = vec![BtValue::Integer(2), BtValue::Integer(3), BtValue::Integer(4)];

        let merged = merge_sorted_lists(&a, &b);
        assert_eq!(
            merged,
            vec![
                BtValue::Integer(1),
                BtValue::Integer(2),
                BtValue::Integer(3), // from a, b's duplicate skipped
                BtValue::Integer(4),
                BtValue::Integer(5),
            ]
        );
    }

    #[test]
    fn test_merge_sorted_lists_empty() {
        let a = vec![BtValue::Integer(1)];
        let b = vec![];
        assert_eq!(merge_sorted_lists(&a, &b), a);
        assert_eq!(merge_sorted_lists(&b, &a), a);
    }

    #[test]
    fn test_trailing_data_rejected() {
        assert!(decode(b"i42ei0e").is_err());
    }

    #[test]
    fn test_nested_structure() {
        let mut inner = BTreeMap::new();
        inner.insert(b"nested".to_vec(), BtValue::Integer(99));

        let outer = BtValue::List(vec![
            BtValue::Dict(inner),
            BtValue::String(b"hello".to_vec()),
        ]);

        let encoded = encode(&outer);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, outer);
    }
}
