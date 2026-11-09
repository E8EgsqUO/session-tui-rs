//! Multi-recipient encryption for Session messenger.
//!
//! Port of `libsession-util/src/multi_encrypt.cpp` and
//! `libsession-util/include/session/multi_encrypt.hpp`.
//!
//! Encrypts a message (or messages) for multiple recipients using
//! XChaCha20-Poly1305 with a per-recipient key derived from a DH shared
//! secret and BLAKE2b. A single nonce is shared across all encryptions
//! (safe because keys differ).

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::RngExt;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::curve25519::{to_curve25519_pubkey, to_curve25519_seckey};
use crate::crypto::types::{CryptoError, CryptoResult};

/// Poly1305 tag overhead per encrypted message (16 bytes).
pub const ENCRYPT_MULTIPLE_MESSAGE_OVERHEAD: usize = 16;

/// Derives the per-recipient encryption key.
///
/// 1. DH: `shared = x25519(a, B)`
/// 2. Key: `BLAKE2b(key=domain, data=shared || S || R)` where S/R order
///    depends on `encrypting` flag.
///
/// When encrypting, `a`/`A` is the sender and `B` is the recipient.
/// When decrypting, `a`/`A` is the recipient and `B` is the sender.
/// The hash always uses sender-first ordering (S || R).
pub fn encrypt_multi_key(
    a: &[u8; 32],
    big_a: &[u8; 32],
    big_b: &[u8; 32],
    encrypting: bool,
    domain: &str,
) -> CryptoResult<[u8; 32]> {
    // DH shared secret
    let secret = StaticSecret::from(*a);
    let public = PublicKey::from(*big_b);
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.as_bytes();

    // If encrypting: a/A = sender, B = recipient => S=A, R=B
    // If decrypting: a/A = recipient, B = sender => S=B, R=A
    let (s, r) = if encrypting {
        (big_a.as_slice(), big_b.as_slice())
    } else {
        (big_b.as_slice(), big_a.as_slice())
    };

    // BLAKE2b keyed hash: key=domain (max 64 bytes), data=shared||S||R, output=32
    let domain_bytes = domain.as_bytes();
    let key_len = domain_bytes.len().min(64);
    let mut params = blake2b_simd::Params::new();
    params.hash_length(32);
    params.key(&domain_bytes[..key_len]);
    let mut state = params.to_state();
    state.update(shared_bytes);
    state.update(s);
    state.update(r);
    let hash = state.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.as_bytes()[..32]);
    Ok(key)
}

/// Encrypts a single message with XChaCha20-Poly1305 using the given key and nonce.
fn encrypt_multi_impl(msg: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = chacha20poly1305::XNonce::from(*nonce);
    cipher.encrypt(&xnonce, msg).map_err(|e| {
        CryptoError::EncryptionFailed(format!("XChaCha20-Poly1305 encrypt failed: {e}"))
    })
}

/// Attempts to decrypt a ciphertext with XChaCha20-Poly1305.
/// Returns `None` if decryption fails (wrong key / tampered data).
fn decrypt_multi_impl(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Option<Vec<u8>> {
    if ciphertext.len() < ENCRYPT_MULTIPLE_MESSAGE_OVERHEAD {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = chacha20poly1305::XNonce::from(*nonce);
    cipher.decrypt(&xnonce, ciphertext).ok()
}

/// Encrypts messages for multiple recipients.
///
/// `messages` must be either length 1 (same message for all recipients) or
/// the same length as `recipients` (distinct message per recipient).
///
/// Returns one ciphertext per recipient.
pub fn encrypt_for_multiple(
    messages: &[&[u8]],
    recipients: &[[u8; 32]],
    nonce: &[u8; 24],
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
    domain: &str,
) -> CryptoResult<Vec<Vec<u8>>> {
    if messages.len() != 1 && messages.len() != recipients.len() {
        return Err(CryptoError::InvalidInput(
            "encrypt_for_multiple requires either 1 or recipients.len() messages".into(),
        ));
    }

    let mut result = Vec::with_capacity(recipients.len());
    let mut msg_iter = messages.iter();
    let single_msg = messages.len() == 1;

    for recipient in recipients {
        let msg = if single_msg {
            messages[0]
        } else {
            msg_iter.next().unwrap()
        };

        let key = encrypt_multi_key(privkey, pubkey, recipient, true, domain)?;
        let encrypted = encrypt_multi_impl(msg, &key, nonce)?;
        result.push(encrypted);
    }

    Ok(result)
}

/// Tries to decrypt one of the ciphertexts produced by `encrypt_for_multiple`.
///
/// Iterates through `ciphertexts` and returns the first successful decryption.
/// Returns `None` if none can be decrypted.
pub fn decrypt_for_multiple(
    ciphertexts: &[&[u8]],
    nonce: &[u8; 24],
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
    sender_pubkey: &[u8; 32],
    domain: &str,
) -> Option<Vec<u8>> {
    let key = encrypt_multi_key(privkey, pubkey, sender_pubkey, false, domain).ok()?;

    for ct in ciphertexts {
        if let Some(plaintext) = decrypt_multi_impl(ct, &key, nonce) {
            return Some(plaintext);
        }
    }
    None
}

/// Encrypts messages for multiple recipients and wraps in bencode.
///
/// Output format: `d1:#24:<nonce>1:el<len>:<enc1><len>:<enc2>...ee`
///
/// If `pad > 1` and messages is non-empty, random junk entries are appended
/// until the total count is divisible by `pad`. Junk entries have the same
/// size as the first encrypted message.
pub fn encrypt_for_multiple_simple(
    messages: &[&[u8]],
    recipients: &[[u8; 32]],
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
    domain: &str,
    nonce: Option<&[u8; 24]>,
    pad: i32,
) -> CryptoResult<Vec<u8>> {
    // Generate or use provided nonce
    let random_nonce: [u8; 24];
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let mut buf = [0u8; 24];
            rand::rng().fill(&mut buf);
            random_nonce = buf;
            &random_nonce
        }
    };

    let encrypted = encrypt_for_multiple(messages, recipients, nonce, privkey, pubkey, domain)?;
    let mut msg_count = encrypted.len();

    // Build bencode: d1:#24:<nonce>1:el...ee
    let mut enc_list_items = Vec::new();
    for enc in &encrypted {
        enc_list_items.push(crate::util::bencode::BtValue::String(enc.clone()));
    }

    // Padding with random junk entries
    if pad > 1 && !messages.is_empty() {
        let pad_size = messages[0].len() + ENCRYPT_MULTIPLE_MESSAGE_OVERHEAD;
        let pad = pad as usize;
        while msg_count % pad != 0 {
            let junk: Vec<u8> = {
                let mut buf = vec![0u8; pad_size];
                rand::rng().fill(&mut buf[..]);
                buf
            };
            enc_list_items.push(crate::util::bencode::BtValue::String(junk));
            msg_count += 1;
        }
    }

    let mut dict = std::collections::BTreeMap::new();
    dict.insert(
        b"#".to_vec(),
        crate::util::bencode::BtValue::String(nonce.to_vec()),
    );
    dict.insert(
        b"e".to_vec(),
        crate::util::bencode::BtValue::List(enc_list_items),
    );

    Ok(crate::util::bencode::encode(
        &crate::util::bencode::BtValue::Dict(dict),
    ))
}

/// Ed25519 variant of `encrypt_for_multiple_simple`.
///
/// Converts the 64-byte Ed25519 secret key to X25519 privkey/pubkey, then
/// delegates to the X25519 version.
pub fn encrypt_for_multiple_simple_ed25519(
    messages: &[&[u8]],
    recipients: &[[u8; 32]],
    ed25519_secret_key: &[u8; 64],
    domain: &str,
    nonce: Option<&[u8; 24]>,
    pad: i32,
) -> CryptoResult<Vec<u8>> {
    let x_priv = to_curve25519_seckey(ed25519_secret_key)?;
    let ed_pub: [u8; 32] = ed25519_secret_key[32..].try_into().unwrap();
    let x_pub = to_curve25519_pubkey(&ed_pub)?;

    encrypt_for_multiple_simple(messages, recipients, &x_priv, &x_pub, domain, nonce, pad)
}

/// Decrypts a bencode-encoded multi-recipient message.
///
/// Parses the bencode wrapper, extracts the nonce and encrypted list, then
/// tries to decrypt each entry. Returns the first successful decryption.
pub fn decrypt_for_multiple_simple(
    encoded: &[u8],
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
    sender_pubkey: &[u8; 32],
    domain: &str,
) -> Option<Vec<u8>> {
    let parsed = crate::util::bencode::decode(encoded).ok()?;
    let dict = match &parsed {
        crate::util::bencode::BtValue::Dict(d) => d,
        _ => return None,
    };

    // Extract nonce from key "#"
    let nonce_val = dict.get(b"#".as_ref())?;
    let nonce_bytes = match nonce_val {
        crate::util::bencode::BtValue::String(s) => s,
        _ => return None,
    };
    if nonce_bytes.len() != 24 {
        return None;
    }
    let nonce: [u8; 24] = nonce_bytes.as_slice().try_into().ok()?;

    // Extract encrypted list from key "e"
    let list_val = dict.get(b"e".as_ref())?;
    let list = match list_val {
        crate::util::bencode::BtValue::List(l) => l,
        _ => return None,
    };

    // Build ciphertexts
    let ciphertexts: Vec<&[u8]> = list
        .iter()
        .filter_map(|v| match v {
            crate::util::bencode::BtValue::String(s) => Some(s.as_slice()),
            _ => None,
        })
        .collect();

    decrypt_for_multiple(&ciphertexts, &nonce, privkey, pubkey, sender_pubkey, domain)
}

/// Decrypts with Ed25519 recipient key and X25519 sender key.
///
/// Converts the 64-byte Ed25519 secret key to X25519, then delegates.
pub fn decrypt_for_multiple_simple_from_ed25519(
    encoded: &[u8],
    ed25519_secret_key: &[u8; 64],
    sender_x25519_pubkey: &[u8; 32],
    domain: &str,
) -> Option<Vec<u8>> {
    let x_priv = to_curve25519_seckey(ed25519_secret_key).ok()?;
    let ed_pub: [u8; 32] = ed25519_secret_key[32..].try_into().ok()?;
    let x_pub = to_curve25519_pubkey(&ed_pub).ok()?;

    decrypt_for_multiple_simple(encoded, &x_priv, &x_pub, sender_x25519_pubkey, domain)
}

/// Decrypts with both Ed25519 recipient and Ed25519 sender keys.
///
/// Converts both keys to X25519, then delegates.
pub fn decrypt_for_multiple_simple_ed25519(
    encoded: &[u8],
    ed25519_secret_key: &[u8; 64],
    sender_ed25519_pubkey: &[u8; 32],
    domain: &str,
) -> Option<Vec<u8>> {
    let sender_x25519_pub = to_curve25519_pubkey(sender_ed25519_pubkey).ok()?;
    decrypt_for_multiple_simple_from_ed25519(
        encoded,
        ed25519_secret_key,
        &sender_x25519_pub,
        domain,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::ed25519_key_pair_from_seed;
    use hex_literal::hex;

    /// Helper: derives X25519 (privkey, pubkey) from an Ed25519 seed.
    fn to_x_keys(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let (ed_pk, ed_sk) = ed25519_key_pair_from_seed(seed).unwrap();
        let x_priv = to_curve25519_seckey(&ed_sk).unwrap();
        let x_pub = to_curve25519_pubkey(&ed_pk).unwrap();
        (x_priv, x_pub)
    }

    fn seeds() -> [[u8; 32]; 5] {
        [
            hex!("0123456789abcdef0123456789abcdef00000000000000000000000000000000"),
            hex!("0123456789abcdef000000000000000000000000000000000000000000000000"),
            hex!("0123456789abcdef111111111111111100000000000000000000000000000000"),
            hex!("0123456789abcdef222222222222222200000000000000000000000000000000"),
            hex!("0123456789abcdef333333333333333300000000000000000000000000000000"),
        ]
    }

    fn x_keys() -> [([u8; 32], [u8; 32]); 5] {
        let s = seeds();
        [
            to_x_keys(&s[0]),
            to_x_keys(&s[1]),
            to_x_keys(&s[2]),
            to_x_keys(&s[3]),
            to_x_keys(&s[4]),
        ]
    }

    #[test]
    fn test_derived_x25519_pubkeys() {
        let keys = x_keys();
        assert_eq!(
            hex::encode(keys[0].1),
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );
        assert_eq!(
            hex::encode(keys[1].1),
            "d673a8fb4800d2a252d2fc4e3342a88cdfa9412853934e8993d12d593be13371"
        );
        assert_eq!(
            hex::encode(keys[2].1),
            "afd9716ea69ab8c7f475e1b250c86a6539e260804faecf2a803e9281a4160738"
        );
        assert_eq!(
            hex::encode(keys[3].1),
            "03be14feabd59122349614b88bdc90db1d1af4c230e9a73c898beec833d51f11"
        );
        assert_eq!(
            hex::encode(keys[4].1),
            "27b5c1ea87cef76284c752fa6ee1b9186b1a95e74e8f5b88f8b47e5191ce6f08"
        );
    }

    #[test]
    fn test_encrypt_single_message_for_multiple() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");

        // Recipients 1, 2, 3 (indices in C++ test)
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple(
            &[b"hello"],
            &recipients,
            &nonce,
            &keys[0].0,
            &keys[0].1,
            "test suite",
        )
        .unwrap();

        assert_eq!(encrypted.len(), 3);
        assert_eq!(
            hex::encode(&encrypted[0]),
            "e64937e5ea201b84f4e88a976dad900d91caaf6a17"
        );
        assert_eq!(
            hex::encode(&encrypted[1]),
            "b7a15bcd9f7b09445defcae2f1dc5085dd75cb085b"
        );
        assert_eq!(
            hex::encode(&encrypted[2]),
            "01c4fc2156327735f3fb5063b11ea95f6ebcc5b6cc"
        );
    }

    #[test]
    fn test_decrypt_single_message() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple(
            &[b"hello"],
            &recipients,
            &nonce,
            &keys[0].0,
            &keys[0].1,
            "test suite",
        )
        .unwrap();

        let cts: Vec<&[u8]> = encrypted.iter().map(|v| v.as_slice()).collect();

        // Recipient 1 can decrypt
        let m1 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[1].0,
            &keys[1].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m1.as_deref(), Some(b"hello".as_ref()));

        // Recipient 2 can decrypt
        let m2 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[2].0,
            &keys[2].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m2.as_deref(), Some(b"hello".as_ref()));

        // Recipient 3 can decrypt
        let m3 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m3.as_deref(), Some(b"hello".as_ref()));

        // Wrong domain fails
        let m3b = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "not test suite",
        );
        assert!(m3b.is_none());

        // Non-recipient (key 4) fails
        let m4 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[4].0,
            &keys[4].1,
            &keys[0].1,
            "test suite",
        );
        assert!(m4.is_none());
    }

    #[test]
    fn test_encrypt_multiple_messages() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple(
            &[b"hello", b"cruel", b"world"],
            &recipients,
            &nonce,
            &keys[0].0,
            &keys[0].1,
            "test suite",
        )
        .unwrap();

        assert_eq!(encrypted.len(), 3);
        assert_eq!(
            hex::encode(&encrypted[0]),
            "e64937e5ea201b84f4e88a976dad900d91caaf6a17"
        );
        assert_eq!(
            hex::encode(&encrypted[1]),
            "bcb642c49c6da03f70cdaab2ed6666721318afd631"
        );
        assert_eq!(
            hex::encode(&encrypted[2]),
            "1ecee2215d226817edfdb097f05037eb799309103a"
        );
    }

    #[test]
    fn test_decrypt_multiple_messages() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple(
            &[b"hello", b"cruel", b"world"],
            &recipients,
            &nonce,
            &keys[0].0,
            &keys[0].1,
            "test suite",
        )
        .unwrap();

        let cts: Vec<&[u8]> = encrypted.iter().map(|v| v.as_slice()).collect();

        let m1 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[1].0,
            &keys[1].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m1.as_deref(), Some(b"hello".as_ref()));

        let m2 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[2].0,
            &keys[2].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m2.as_deref(), Some(b"cruel".as_ref()));

        let m3 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m3.as_deref(), Some(b"world".as_ref()));

        let m3b = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "not test suite",
        );
        assert!(m3b.is_none());

        let m4 = decrypt_for_multiple(
            &cts,
            &nonce,
            &keys[4].0,
            &keys[4].1,
            &keys[0].1,
            "test suite",
        );
        assert!(m4.is_none());
    }

    #[test]
    fn test_mismatched_messages_recipients() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        // 2 messages but 3 recipients => error
        let result = encrypt_for_multiple(
            &[b"hello", b"cruel"],
            &recipients,
            &nonce,
            &keys[0].0,
            &keys[0].1,
            "test suite",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_for_multiple_simple_deterministic() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple_simple(
            &[b"hello" as &[u8], b"cruel", b"world"],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            Some(&nonce),
            0,
        )
        .unwrap();

        // Expected bencode: d1:#24:<nonce>1:el21:<enc0>21:<enc1>21:<enc2>ee
        let expected_nonce_hex = "32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49";
        let enc0_hex = "e64937e5ea201b84f4e88a976dad900d91caaf6a17";
        let enc1_hex = "bcb642c49c6da03f70cdaab2ed6666721318afd631";
        let enc2_hex = "1ecee2215d226817edfdb097f05037eb799309103a";

        let expected_nonce = hex::decode(expected_nonce_hex).unwrap();
        let enc0 = hex::decode(enc0_hex).unwrap();
        let enc1 = hex::decode(enc1_hex).unwrap();
        let enc2 = hex::decode(enc2_hex).unwrap();

        // Build expected bencode manually
        let mut expected = Vec::new();
        expected.extend_from_slice(b"d1:#24:");
        expected.extend_from_slice(&expected_nonce);
        expected.extend_from_slice(b"1:el21:");
        expected.extend_from_slice(&enc0);
        expected.extend_from_slice(b"21:");
        expected.extend_from_slice(&enc1);
        expected.extend_from_slice(b"21:");
        expected.extend_from_slice(&enc2);
        expected.extend_from_slice(b"ee");

        assert_eq!(encrypted, expected);
    }

    #[test]
    fn test_encrypt_for_multiple_simple_random_nonce() {
        let keys = x_keys();
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let enc1 = encrypt_for_multiple_simple(
            &[b"hello" as &[u8]],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            None,
            0,
        )
        .unwrap();

        let enc2 = encrypt_for_multiple_simple(
            &[b"hello" as &[u8]],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            None,
            0,
        )
        .unwrap();

        // Different random nonces => different outputs
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_decrypt_for_multiple_simple_single_msg() {
        let keys = x_keys();
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple_simple(
            &[b"hello" as &[u8]],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            None,
            0,
        )
        .unwrap();

        let m1 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[1].0,
            &keys[1].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m1.as_deref(), Some(b"hello".as_ref()));

        let m2 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[2].0,
            &keys[2].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m2.as_deref(), Some(b"hello".as_ref()));

        let m3 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m3.as_deref(), Some(b"hello".as_ref()));

        // Wrong domain
        let m3b = decrypt_for_multiple_simple(
            &encrypted,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "not test suite",
        );
        assert!(m3b.is_none());

        // Non-recipient
        let m4 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[4].0,
            &keys[4].1,
            &keys[0].1,
            "test suite",
        );
        assert!(m4.is_none());
    }

    #[test]
    fn test_decrypt_for_multiple_simple_multi_msg() {
        let keys = x_keys();
        let nonce = hex!("32ab4bb45d6df5cc14e1c330fb1a8b68ea3826a8c2213a49");
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple_simple(
            &[b"hello" as &[u8], b"cruel", b"world"],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            Some(&nonce),
            0,
        )
        .unwrap();

        let m1 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[1].0,
            &keys[1].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m1.as_deref(), Some(b"hello".as_ref()));

        let m2 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[2].0,
            &keys[2].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m2.as_deref(), Some(b"cruel".as_ref()));

        let m3 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m3.as_deref(), Some(b"world".as_ref()));

        let m3b = decrypt_for_multiple_simple(
            &encrypted,
            &keys[3].0,
            &keys[3].1,
            &keys[0].1,
            "not test suite",
        );
        assert!(m3b.is_none());

        let m4 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[4].0,
            &keys[4].1,
            &keys[0].1,
            "test suite",
        );
        assert!(m4.is_none());
    }

    #[test]
    fn test_simple_expected_size() {
        let keys = x_keys();
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        let encrypted = encrypt_for_multiple_simple(
            &[b"hello" as &[u8]],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            None,
            0,
        )
        .unwrap();

        // Expected size: d(1) + 1:#(3) + 24:<nonce>(27) + 1:e(3) + l(1) + 3*(3+21) + e(1) + e(1)
        // = 1 + 3 + 27 + 3 + 1 + 72 + 1 + 1 = 109
        // Actually: "d" + "1:#" + "24:" + nonce(24) + "1:e" + "l" + 3*("21:" + enc(21)) + "e" + "e"
        //         = 1 + 3 + 3 + 24 + 3 + 1 + 3*(3+21) + 1 + 1
        //         = 1 + 3 + 3 + 24 + 3 + 1 + 72 + 1 + 1 = 109
        let expected_size = 2       // d...e (outer dict)
            + 3 + 27               // 1:# 24:<nonce>
            + 3 + 2                // 1:e l...e
            + 3 * (3 + 5 + ENCRYPT_MULTIPLE_MESSAGE_OVERHEAD); // 3 * (XX: + data)
        assert_eq!(encrypted.len(), expected_size);
    }

    #[test]
    fn test_encrypt_decrypt_ed25519_simple() {
        let s = seeds();
        let keys = x_keys();
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        // Build ed25519 secret key for sender (seed 0)
        let (_, ed_sk0) = ed25519_key_pair_from_seed(&s[0]).unwrap();
        let (ed_pk0, _) = ed25519_key_pair_from_seed(&s[0]).unwrap();

        let encrypted = encrypt_for_multiple_simple_ed25519(
            &[b"hello" as &[u8]],
            &recipients,
            &ed_sk0,
            "test suite",
            None,
            0,
        )
        .unwrap();

        // Decrypt with X25519 key
        let m1 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[1].0,
            &keys[1].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m1.as_deref(), Some(b"hello".as_ref()));

        // Decrypt using ed25519 recipient
        let (_, ed_sk1) = ed25519_key_pair_from_seed(&s[1]).unwrap();
        let m1_ed =
            decrypt_for_multiple_simple_from_ed25519(&encrypted, &ed_sk1, &keys[0].1, "test suite");
        assert_eq!(m1_ed.as_deref(), Some(b"hello".as_ref()));

        // Decrypt using ed25519 for both sender and recipient
        let m1_full_ed =
            decrypt_for_multiple_simple_ed25519(&encrypted, &ed_sk1, &ed_pk0, "test suite");
        assert_eq!(m1_full_ed.as_deref(), Some(b"hello".as_ref()));
    }

    #[test]
    fn test_padding() {
        let keys = x_keys();
        let recipients = [keys[1].1, keys[2].1, keys[3].1];

        // 3 recipients, pad to multiples of 4 => should have 4 entries
        let encrypted = encrypt_for_multiple_simple(
            &[b"hello" as &[u8]],
            &recipients,
            &keys[0].0,
            &keys[0].1,
            "test suite",
            None,
            4,
        )
        .unwrap();

        // Parse and check list size
        let parsed = crate::util::bencode::decode(&encrypted).unwrap();
        let dict = match &parsed {
            crate::util::bencode::BtValue::Dict(d) => d,
            _ => panic!("expected dict"),
        };
        let list = match dict.get(b"e".as_ref()).unwrap() {
            crate::util::bencode::BtValue::List(l) => l,
            _ => panic!("expected list"),
        };
        assert_eq!(list.len(), 4); // 3 real + 1 padding

        // Should still decrypt fine
        let m1 = decrypt_for_multiple_simple(
            &encrypted,
            &keys[1].0,
            &keys[1].1,
            &keys[0].1,
            "test suite",
        );
        assert_eq!(m1.as_deref(), Some(b"hello".as_ref()));
    }
}
