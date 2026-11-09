//! Group (v2, `03…`) helpers that the bundled core does not provide yet:
//! subaccount request signing for non-admin members and decryption of the
//! group key messages (namespace 12) from a member's point of view.
//!
//! Ported from libsession-util `src/config/groups/keys.cpp`
//! (`Keys::swarm_subaccount_sign`, `Keys::swarm_verify_subaccount`,
//! `Keys::load_key_message`).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use libsession::util::bencode::{self, BtValue};
use sha2_0_10::{Digest, Sha512};

/// Size of a member's subaccount auth data: prefix/flags (4) || k (32) || admin sig (64).
pub const AUTH_DATA_LEN: usize = 100;

const SUBACC_FLAG_READ: u8 = 0b0001;
const SUBACC_FLAG_WRITE: u8 = 0b0010;
const SUBACC_FLAG_ANY_PREFIX: u8 = 0b1000;

/// Base64 strings for the `subaccount`, `subaccount_sig` and `signature`
/// request parameters.
pub struct SubaccountAuth {
    pub subaccount: String,
    pub subaccount_sig: String,
    pub signature: String,
}

fn blinded_pubkey(user_ed_sk: &[u8; 64], k: &[u8; 32]) -> Result<([u8; 32], bool), String> {
    // T = |S|: the user's Ed25519 pubkey with the sign bit cleared.
    let mut t = [0u8; 32];
    t.copy_from_slice(&user_ed_sk[32..]);
    let negative = t[31] & 0x80 != 0;
    t[31] &= 0x7f;
    let point = CompressedEdwardsY(t)
        .decompress()
        .ok_or("invalid Ed25519 public key")?;
    let k = Scalar::from_bytes_mod_order(*k);
    Ok(((k * point).compress().to_bytes(), negative))
}

/// libsodium `crypto_sign_ed25519_sk_to_curve25519`: clamped SHA-512(seed)[..32].
fn ed_secret_scalar_bytes(user_ed_sk: &[u8; 64]) -> [u8; 32] {
    let hash = Sha512::digest(&user_ed_sk[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&hash[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

/// Sign `msg` (e.g. `"retrieve11<timestamp>"`) as a group member using the
/// subaccount `auth_data` an admin issued for us.
pub fn subaccount_sign(
    user_ed_sk: &[u8; 64],
    auth_data: &[u8],
    msg: &[u8],
) -> Result<SubaccountAuth, String> {
    if auth_data.len() != AUTH_DATA_LEN {
        return Err("invalid group auth data size".into());
    }
    let k: [u8; 32] = auth_data[4..36].try_into().expect("32 bytes");
    let (kt_pub, negative) = blinded_pubkey(user_ed_sk, &k)?;

    let mut token = Vec::with_capacity(36);
    token.extend_from_slice(&auth_data[..4]);
    token.extend_from_slice(&kt_pub);

    // Private scalar kt with t = ±s (negated when S had its sign bit set).
    let s = Scalar::from_bytes_mod_order(ed_secret_scalar_bytes(user_ed_sk));
    let t = if negative { -s } else { s };
    let kt = Scalar::from_bytes_mod_order(k) * t;

    // r = H64(H32(seed, key="SubaccountSeed") || kT || M, key="SubaccountSig") mod L
    let hseed = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"SubaccountSeed")
        .hash(&user_ed_sk[..32]);
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .key(b"SubaccountSig")
        .to_state();
    state.update(hseed.as_bytes());
    state.update(&kt_pub);
    state.update(msg);
    let wide: [u8; 64] = state.finalize().as_bytes().try_into().expect("64 bytes");
    let r = Scalar::from_bytes_mod_order_wide(&wide);

    // R = rB;  S = r + H(R || kT || M)·kt
    let big_r = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(big_r);
    hasher.update(kt_pub);
    hasher.update(msg);
    let hram: [u8; 64] = hasher.finalize().into();
    let big_s = Scalar::from_bytes_mod_order_wide(&hram) * kt + r;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&big_r);
    signature[32..].copy_from_slice(big_s.as_bytes());
    Ok(SubaccountAuth {
        subaccount: STANDARD.encode(&token),
        subaccount_sig: STANDARD.encode(&auth_data[36..]),
        signature: STANDARD.encode(signature),
    })
}

/// Check that `auth_data` was issued by the group's admin for this account
/// and grants read access (and write access when `write` is set).
pub fn verify_subaccount(
    group_pk: &[u8; 32],
    user_ed_sk: &[u8; 64],
    auth_data: &[u8],
    write: bool,
) -> bool {
    if auth_data.len() != AUTH_DATA_LEN {
        return false;
    }
    let (prefix, flags) = (auth_data[0], auth_data[1]);
    if prefix != 0x03 && flags & SUBACC_FLAG_ANY_PREFIX == 0 {
        return false;
    }
    if flags & SUBACC_FLAG_READ == 0 || (write && flags & SUBACC_FLAG_WRITE == 0) {
        return false;
    }
    let k: [u8; 32] = auth_data[4..36].try_into().expect("32 bytes");
    let Ok((kt_pub, _)) = blinded_pubkey(user_ed_sk, &k) else {
        return false;
    };
    let mut to_verify = Vec::with_capacity(36);
    to_verify.extend_from_slice(&auth_data[..4]);
    to_verify.extend_from_slice(&kt_pub);
    libsession::crypto::ed25519::verify(&auth_data[36..], group_pk, &to_verify).unwrap_or(false)
}

/// Can this member write to the group swarm with this auth data?
pub fn subaccount_can_write(auth_data: &[u8]) -> bool {
    auth_data.len() == AUTH_DATA_LEN && auth_data[1] & SUBACC_FLAG_WRITE != 0
}

/// A group encryption key recovered from a key message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupKey {
    pub generation: i64,
    pub key: [u8; 32],
}

fn dict_bytes<'a>(
    dict: &'a std::collections::BTreeMap<Vec<u8>, BtValue>,
    key: &[u8],
) -> Option<&'a [u8]> {
    match dict.get(key) {
        Some(BtValue::String(bytes)) => Some(bytes),
        _ => None,
    }
}

fn dict_int(dict: &std::collections::BTreeMap<Vec<u8>, BtValue>, key: &[u8]) -> Option<i64> {
    match dict.get(key) {
        Some(BtValue::Integer(value)) => Some(*value),
        _ => None,
    }
}

fn dict_list<'a>(
    dict: &'a std::collections::BTreeMap<Vec<u8>, BtValue>,
    key: &[u8],
) -> Option<Vec<&'a [u8]>> {
    match dict.get(key) {
        Some(BtValue::List(items)) => Some(
            items
                .iter()
                .filter_map(|item| match item {
                    BtValue::String(bytes) => Some(bytes.as_slice()),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

/// Decrypt the keys meant for us from one namespace-12 key message.
///
/// * `admin_seed`: the group's 32-byte Ed25519 seed when we are an admin.
/// * otherwise the member path is used: each entry of `k` (full message) or
///   `+` (supplemental message) is tried with our X25519 key.
pub fn decrypt_key_message(
    message: &[u8],
    group_pk: &[u8; 32],
    user_ed_sk: &[u8; 64],
    admin_seed: Option<&[u8]>,
) -> Vec<GroupKey> {
    let Ok(BtValue::Dict(dict)) = bencode::decode(message) else {
        return Vec::new();
    };
    let Some(nonce) = dict_bytes(&dict, b"#").and_then(|n| <[u8; 24]>::try_from(n).ok()) else {
        return Vec::new();
    };

    if let Some(admin_seed) = admin_seed
        && let (Some(generation), Some(encrypted)) =
            (dict_int(&dict, b"G"), dict_bytes(&dict, b"K"))
    {
        let admin_key = blake2b_simd::Params::new()
            .hash_length(32)
            .key(b"SessionGroupKeyAdminKey")
            .hash(admin_seed);
        if let Ok(cipher) = XChaCha20Poly1305::new_from_slice(admin_key.as_bytes())
            && let Ok(plain) = cipher.decrypt(&XNonce::from(nonce), encrypted)
            && let Ok(key) = <[u8; 32]>::try_from(plain.as_slice())
        {
            return vec![GroupKey { generation, key }];
        }
    }

    let (Ok(member_xsk), Ok(member_xpk), Ok(group_xpk)) = (
        libsession::crypto::curve25519::to_curve25519_seckey(user_ed_sk),
        libsession::crypto::curve25519::to_curve25519_pubkey(
            &user_ed_sk[32..].try_into().expect("32 bytes"),
        ),
        libsession::crypto::curve25519::to_curve25519_pubkey(group_pk),
    ) else {
        return Vec::new();
    };
    let decrypt = |ciphertexts: &[&[u8]]| {
        libsession::crypto::multi_encrypt::decrypt_for_multiple(
            ciphertexts,
            &nonce,
            &member_xsk,
            &member_xpk,
            &group_xpk,
            "SessionGroupKeyMemberKey",
        )
    };

    if let Some(supplemental) = dict_list(&dict, b"+") {
        // Supplemental message: a bencoded list of {g, k, t} dicts for us.
        let Some(plain) = decrypt(&supplemental) else {
            return Vec::new();
        };
        let Ok(BtValue::List(infos)) = bencode::decode(&plain) else {
            return Vec::new();
        };
        return infos
            .iter()
            .filter_map(|info| match info {
                BtValue::Dict(info) => Some(GroupKey {
                    generation: dict_int(info, b"g")?,
                    key: dict_bytes(info, b"k")?.try_into().ok()?,
                }),
                _ => None,
            })
            .collect();
    }

    let (Some(generation), Some(members)) = (dict_int(&dict, b"G"), dict_list(&dict, b"k")) else {
        return Vec::new();
    };
    decrypt(&members)
        .and_then(|plain| <[u8; 32]>::try_from(plain.as_slice()).ok())
        .map(|key| vec![GroupKey { generation, key }])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    fn keypair(seed: [u8; 32]) -> [u8; 64] {
        let signing = SigningKey::from_bytes(&seed);
        let mut sk = [0u8; 64];
        sk[..32].copy_from_slice(&seed);
        sk[32..].copy_from_slice(signing.verifying_key().as_bytes());
        sk
    }

    /// Admin side of `Keys::swarm_make_subaccount`, for round-trip tests.
    fn make_auth_data(group_seed: [u8; 32], member_sk: &[u8; 64], flags: u8) -> Vec<u8> {
        let k = Scalar::from_bytes_mod_order([7u8; 32]).to_bytes();
        let (kt, _) = blinded_pubkey(member_sk, &k).unwrap();
        let mut out = vec![0x03, flags, 0, 0];
        out.extend_from_slice(&k);
        let mut to_sign = out[..4].to_vec();
        to_sign.extend_from_slice(&kt);
        let signature = SigningKey::from_bytes(&group_seed).sign(&to_sign);
        out.extend_from_slice(&signature.to_bytes());
        out
    }

    #[test]
    fn subaccount_signature_verifies_like_a_swarm_node() {
        let group_seed = [1u8; 32];
        let group_pk = SigningKey::from_bytes(&group_seed)
            .verifying_key()
            .to_bytes();
        for seed in [[2u8; 32], [3u8; 32], [0x44; 32], [0x91; 32]] {
            let member = keypair(seed);
            let auth = make_auth_data(group_seed, &member, SUBACC_FLAG_READ | SUBACC_FLAG_WRITE);
            assert!(verify_subaccount(&group_pk, &member, &auth, true));

            let msg = b"retrieve111700000000000";
            let signed = subaccount_sign(&member, &auth, msg).unwrap();
            let token = STANDARD.decode(signed.subaccount).unwrap();
            // The node checks the admin signature over `flags || kT`…
            let admin_sig = STANDARD.decode(signed.subaccount_sig).unwrap();
            VerifyingKey::from_bytes(&group_pk)
                .unwrap()
                .verify(&token, &Signature::from_slice(&admin_sig).unwrap())
                .unwrap();
            // …and our request signature with kT as an ordinary Ed25519 key.
            let kt: [u8; 32] = token[4..].try_into().unwrap();
            let sig = STANDARD.decode(signed.signature).unwrap();
            VerifyingKey::from_bytes(&kt)
                .unwrap()
                .verify(msg, &Signature::from_slice(&sig).unwrap())
                .unwrap();
        }
    }

    #[test]
    fn auth_data_for_another_member_is_rejected() {
        let group_seed = [1u8; 32];
        let group_pk = SigningKey::from_bytes(&group_seed)
            .verifying_key()
            .to_bytes();
        let alice = keypair([2u8; 32]);
        let bob = keypair([3u8; 32]);
        let auth = make_auth_data(group_seed, &alice, SUBACC_FLAG_READ);
        assert!(!verify_subaccount(&group_pk, &bob, &auth, false));
        assert!(!verify_subaccount(&group_pk, &alice, &auth, true));
        assert!(verify_subaccount(&group_pk, &alice, &auth, false));
    }

    #[test]
    fn member_can_decrypt_its_key_from_a_full_key_message() {
        let group_seed = [9u8; 32];
        let group_sk = keypair(group_seed);
        let group_pk: [u8; 32] = group_sk[32..].try_into().unwrap();
        let member = keypair([5u8; 32]);
        let other = keypair([6u8; 32]);
        let group_xsk = libsession::crypto::curve25519::to_curve25519_seckey(&group_sk).unwrap();
        let group_xpk = libsession::crypto::curve25519::to_curve25519_pubkey(&group_pk).unwrap();
        let xpk = |sk: &[u8; 64]| {
            libsession::crypto::curve25519::to_curve25519_pubkey(&sk[32..].try_into().unwrap())
                .unwrap()
        };
        let nonce = [4u8; 24];
        let key = [0xab; 32];
        let encrypted = libsession::crypto::multi_encrypt::encrypt_for_multiple(
            &[&key],
            &[xpk(&other), xpk(&member)],
            &nonce,
            &group_xsk,
            &group_xpk,
            "SessionGroupKeyMemberKey",
        )
        .unwrap();
        let mut dict = std::collections::BTreeMap::new();
        dict.insert(b"#".to_vec(), BtValue::String(nonce.to_vec()));
        dict.insert(b"G".to_vec(), BtValue::Integer(3));
        dict.insert(b"K".to_vec(), BtValue::String(vec![0; 48]));
        dict.insert(
            b"k".to_vec(),
            BtValue::List(encrypted.into_iter().map(BtValue::String).collect()),
        );
        let message = bencode::encode(&BtValue::Dict(dict));
        assert_eq!(
            decrypt_key_message(&message, &group_pk, &member, None),
            vec![GroupKey { generation: 3, key }]
        );
        let stranger = keypair([7u8; 32]);
        assert!(decrypt_key_message(&message, &group_pk, &stranger, None).is_empty());
    }
}
