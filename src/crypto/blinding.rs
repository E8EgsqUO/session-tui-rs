//! Blinded key derivation and signing for Session communities.
//!
//! Port of `libsession-util/src/blinding.cpp`. Implements blind15, blind25,
//! and version-blinded key pairs and signatures.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::crypto::types::{CryptoError, CryptoResult, Platform};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derives the Ed25519 private scalar from a libsodium-format secret key.
///
/// This mirrors libsodium's `crypto_sign_ed25519_sk_to_curve25519`:
/// SHA-512(seed)[0..32] then clamp. The result is usable as both an
/// Ed25519 signing scalar and a Curve25519 private key.
fn ed25519_sk_to_scalar(ed25519_sk: &[u8; 64]) -> [u8; 32] {
    let hash: [u8; 64] = Sha512::digest(&ed25519_sk[..32]).into();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    // Clamp
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    scalar_bytes
}

/// Converts an Ed25519 public key to an X25519 (Curve25519/Montgomery) public key.
///
/// Mirrors libsodium's `crypto_sign_ed25519_pk_to_curve25519`.
fn ed25519_pk_to_curve25519(ed_pk: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    let compressed = CompressedEdwardsY(*ed_pk);
    let point = compressed.decompress().ok_or_else(|| {
        CryptoError::KeyConversionFailed(
            "ed25519 pubkey to x25519 pubkey conversion failed".to_string(),
        )
    })?;
    Ok(point.to_montgomery().to_bytes())
}

/// Ensures the ed25519 secret key is 64 bytes (seed || pubkey).
/// If 32 bytes (just seed), derives the full keypair.
fn ensure_64_byte_sk(ed25519_sk: &[u8]) -> CryptoResult<[u8; 64]> {
    match ed25519_sk.len() {
        32 => {
            let (pk, sk) = crate::crypto::ed25519::ed25519_key_pair_from_seed(ed25519_sk)?;
            // ed25519_key_pair_from_seed returns (pk, sk) where sk is already seed||pk
            let _ = pk;
            Ok(sk)
        }
        64 => {
            let mut result = [0u8; 64];
            result.copy_from_slice(ed25519_sk);
            Ok(result)
        }
        _ => Err(CryptoError::InvalidInput(
            "ed25519_sk must be 32 or 64 bytes".to_string(),
        )),
    }
}

/// Performs scalar * point multiplication (no clamping).
/// Returns the compressed bytes of the resulting point.
/// Errors if the result is the identity (point not on main subgroup).
fn scalarmult_ed25519_noclamp(
    scalar_bytes: &[u8; 32],
    point_bytes: &[u8; 32],
) -> CryptoResult<[u8; 32]> {
    let point = CompressedEdwardsY(*point_bytes)
        .decompress()
        .ok_or_else(|| {
            CryptoError::InvalidInput("Cannot blind: invalid point (decompression failed)".into())
        })?;
    let scalar = Scalar::from_bytes_mod_order(*scalar_bytes);
    let result = scalar * point;
    if result == EdwardsPoint::default() {
        return Err(CryptoError::InvalidInput(
            "Cannot blind: invalid session_id (not on main subgroup)".into(),
        ));
    }
    Ok(result.compress().to_bytes())
}

/// Parses a server_pk that can be either 32 raw bytes or 64 hex chars.
fn parse_server_pk(server_pk: &[u8]) -> CryptoResult<[u8; 32]> {
    match server_pk.len() {
        32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(server_pk);
            Ok(out)
        }
        64 => {
            // Check if it's valid hex
            let s = std::str::from_utf8(server_pk).map_err(|_| {
                CryptoError::InvalidInput(
                    "Invalid server_pk: expected 32 bytes or 64 hex".to_string(),
                )
            })?;
            let bytes = hex::decode(s).map_err(|_| {
                CryptoError::InvalidInput(
                    "Invalid server_pk: expected 32 bytes or 64 hex".to_string(),
                )
            })?;
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }
        _ => Err(CryptoError::InvalidInput(
            "Invalid server_pk: expected 32 bytes or 64 hex".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Blinding factors
// ---------------------------------------------------------------------------

/// Computes the blind15 blinding factor from a 32-byte server public key.
///
/// `k = BLAKE2b(server_pk, output=64 bytes) mod L`
pub fn blind15_factor(server_pk: &[u8; 32]) -> [u8; 32] {
    let blind_hash = blake2b_simd::Params::new().hash_length(64).hash(server_pk);

    let mut hash_bytes = [0u8; 64];
    hash_bytes.copy_from_slice(blind_hash.as_bytes());
    Scalar::from_bytes_mod_order_wide(&hash_bytes).to_bytes()
}

/// Computes the blind25 blinding factor from a session ID and server public key.
///
/// `k = BLAKE2b(05 || session_id || server_pk, output=64 bytes) mod L`
///
/// `session_id` can be 32 bytes (unprefixed) or 33 bytes (0x05 prefixed).
pub fn blind25_factor(session_id: &[u8], server_pk: &[u8; 32]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new().hash_length(64).to_state();
    if session_id.len() == 32 {
        state.update(&[0x05]);
    }
    state.update(session_id);
    state.update(server_pk);
    let blind_hash = state.finalize();

    let mut hash_bytes = [0u8; 64];
    hash_bytes.copy_from_slice(blind_hash.as_bytes());
    Scalar::from_bytes_mod_order_wide(&hash_bytes).to_bytes()
}

// ---------------------------------------------------------------------------
// Blinded ID computation (raw bytes)
// ---------------------------------------------------------------------------

/// Internal: compute blind15 ID from session_id bytes and server_pk.
/// Writes 33 bytes (0x15 prefix + 32 bytes blinded pubkey).
fn blind15_id_impl(session_id: &[u8], server_pk: &[u8; 32]) -> CryptoResult<[u8; 33]> {
    let k = blind15_factor(server_pk);
    let x25519_pub = if session_id.len() == 33 {
        &session_id[1..]
    } else {
        session_id
    };
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(x25519_pub);
    let ed_pk = crate::crypto::xed25519::pubkey(&x25519_arr);
    let blinded = scalarmult_ed25519_noclamp(&k, &ed_pk)?;
    let mut result = [0u8; 33];
    result[0] = 0x15;
    result[1..].copy_from_slice(&blinded);
    Ok(result)
}

/// Internal: compute blind25 ID from session_id bytes and server_pk.
/// Writes 33 bytes (0x25 prefix + 32 bytes blinded pubkey).
fn blind25_id_impl(session_id: &[u8], server_pk: &[u8; 32]) -> CryptoResult<[u8; 33]> {
    let k = blind25_factor(session_id, server_pk);
    let x25519_pub = if session_id.len() == 33 {
        &session_id[1..]
    } else {
        session_id
    };
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(x25519_pub);
    let ed_pk = crate::crypto::xed25519::pubkey(&x25519_arr);
    let blinded = scalarmult_ed25519_noclamp(&k, &ed_pk)?;
    let mut result = [0u8; 33];
    result[0] = 0x25;
    result[1..].copy_from_slice(&blinded);
    Ok(result)
}

/// Computes the 15-blinded ID from a session ID and server public key.
///
/// `session_id` can be 32 bytes (raw X25519 pubkey) or 33 bytes (0x05 prefixed).
/// Returns 33 bytes: `0x15 || blinded_pubkey`.
pub fn blind15_id(session_id: &[u8], server_pk: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    let sid = if session_id.len() == 33 {
        if session_id[0] != 0x05 {
            return Err(CryptoError::InvalidInput(
                "blind15_id: session_id must start with 0x05".into(),
            ));
        }
        &session_id[1..]
    } else if session_id.len() == 32 {
        session_id
    } else {
        return Err(CryptoError::InvalidInput(
            "blind15_id: session_id must be 32 or 33 bytes".into(),
        ));
    };

    let result = blind15_id_impl(sid, server_pk)?;
    Ok(result.to_vec())
}

/// Computes the 25-blinded ID from a session ID and server public key.
///
/// `session_id` can be 32 bytes (raw X25519 pubkey) or 33 bytes (0x05 prefixed).
/// Returns 33 bytes: `0x25 || blinded_pubkey`.
pub fn blind25_id(session_id: &[u8], server_pk: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    if session_id.len() == 33 {
        if session_id[0] != 0x05 {
            return Err(CryptoError::InvalidInput(
                "blind25_id: session_id must start with 0x05".into(),
            ));
        }
    } else if session_id.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "blind25_id: session_id must be 32 or 33 bytes".into(),
        ));
    }

    let result = blind25_id_impl(session_id, server_pk)?;
    Ok(result.to_vec())
}

// ---------------------------------------------------------------------------
// Blinded ID computation (hex)
// ---------------------------------------------------------------------------

/// Computes the two possible 15-blinded IDs from hex-encoded session ID and server pubkey.
///
/// Returns `[positive, negative]` where negative has the sign bit flipped.
pub fn blind15_id_hex(session_id: &str, server_pk: &str) -> CryptoResult<[String; 2]> {
    if session_id.len() != 66 || hex::decode(session_id).is_err() {
        return Err(CryptoError::InvalidInput(
            "blind15_id: session_id must be hex (66 digits)".into(),
        ));
    }
    if &session_id[..2] != "05" {
        return Err(CryptoError::InvalidInput(
            "blind15_id: session_id must start with 05".into(),
        ));
    }
    if server_pk.len() != 64 || hex::decode(server_pk).is_err() {
        return Err(CryptoError::InvalidInput(
            "blind15_id: server_pk must be hex (64 digits)".into(),
        ));
    }

    let raw_sid = hex::decode(session_id).unwrap();
    let raw_server_pk_vec = hex::decode(server_pk).unwrap();
    let mut raw_server_pk = [0u8; 32];
    raw_server_pk.copy_from_slice(&raw_server_pk_vec);

    let mut blinded = blind15_id_impl(&raw_sid, &raw_server_pk)?;
    let positive = hex::encode(blinded);
    blinded[32] ^= 0x80;
    let negative = hex::encode(blinded);
    Ok([positive, negative])
}

/// Computes the 25-blinded ID from hex-encoded session ID and server pubkey.
pub fn blind25_id_hex(session_id: &str, server_pk: &str) -> CryptoResult<String> {
    if session_id.len() != 66 || hex::decode(session_id).is_err() {
        return Err(CryptoError::InvalidInput(
            "blind25_id: session_id must be hex (66 digits)".into(),
        ));
    }
    if &session_id[..2] != "05" {
        return Err(CryptoError::InvalidInput(
            "blind25_id: session_id must start with 05".into(),
        ));
    }
    if server_pk.len() != 64 || hex::decode(server_pk).is_err() {
        return Err(CryptoError::InvalidInput(
            "blind25_id: server_pk must be hex (64 digits)".into(),
        ));
    }

    let raw_sid = hex::decode(session_id).unwrap();
    let raw_server_pk_vec = hex::decode(server_pk).unwrap();
    let mut raw_server_pk = [0u8; 32];
    raw_server_pk.copy_from_slice(&raw_server_pk_vec);

    let blinded = blind25_id_impl(&raw_sid, &raw_server_pk)?;
    Ok(hex::encode(blinded))
}

// ---------------------------------------------------------------------------
// Blinded ID from Ed25519 pubkey
// ---------------------------------------------------------------------------

/// Computes the 15-blinded ID from an Ed25519 public key.
///
/// Unlike `blind15_id`, this uses the Ed25519 key directly (no X25519 conversion),
/// so the result is deterministic (no sign ambiguity).
pub fn blinded15_id_from_ed(ed_pubkey: &[u8; 32], server_pk: &[u8; 32]) -> CryptoResult<Vec<u8>> {
    let k = blind15_factor(server_pk);
    let blinded = scalarmult_ed25519_noclamp(&k, ed_pubkey)?;
    let mut result = vec![0x15u8];
    result.extend_from_slice(&blinded);
    Ok(result)
}

/// Computes the 25-blinded ID from an Ed25519 public key.
///
/// Returns `(blinded_id, session_id)` where `session_id` is the 33-byte
/// `0x05 || X25519_pubkey` derived from the Ed25519 key.
pub fn blinded25_id_from_ed(
    ed_pubkey: &[u8; 32],
    server_pk: &[u8; 32],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    // Compute session_id = 0x05 || ed25519_pk_to_curve25519(ed_pubkey)
    let x25519_pub = ed25519_pk_to_curve25519(ed_pubkey)?;
    let mut session_id = vec![0x05u8];
    session_id.extend_from_slice(&x25519_pub);

    let k = blind25_factor(&session_id, server_pk);

    // Blinded25 ids are always constructed using the absolute value of the ed pubkey
    let mut pos_ed_pubkey = *ed_pubkey;
    pos_ed_pubkey[31] &= 0x7f;

    let blinded = scalarmult_ed25519_noclamp(&k, &pos_ed_pubkey)?;
    let mut result = vec![0x25u8];
    result.extend_from_slice(&blinded);
    Ok((result, session_id))
}

// ---------------------------------------------------------------------------
// Blinded key pairs
// ---------------------------------------------------------------------------

/// Computes a 15-blinded key pair.
///
/// Takes the Ed25519 secret key (32-byte seed or 64-byte libsodium format)
/// and the 32-byte server public key.
///
/// Returns `(blinded_pubkey, blinded_seckey)`.
pub fn blind15_key_pair(
    ed25519_sk: &[u8],
    server_pk: &[u8; 32],
) -> CryptoResult<([u8; 32], [u8; 32])> {
    let ed_sk = ensure_64_byte_sk(ed25519_sk)?;

    let k = blind15_factor(server_pk);

    // Extract the private scalar a
    let a_bytes = ed25519_sk_to_scalar(&ed_sk);

    // a_blinded = k * a
    let k_scalar = Scalar::from_bytes_mod_order(k);
    let a_scalar = Scalar::from_bytes_mod_order(a_bytes);
    let blinded_a = k_scalar * a_scalar;

    // A_blinded = a_blinded * G
    let blinded_point = EdwardsPoint::mul_base(&blinded_a);
    let blinded_pk = blinded_point.compress().to_bytes();

    Ok((blinded_pk, blinded_a.to_bytes()))
}

/// Computes a 25-blinded key pair.
///
/// Takes the Ed25519 secret key (32-byte seed or 64-byte libsodium format)
/// and the 32-byte server public key.
///
/// Returns `(blinded_pubkey, blinded_seckey)`.
pub fn blind25_key_pair(
    ed25519_sk: &[u8],
    server_pk: &[u8; 32],
) -> CryptoResult<([u8; 32], [u8; 32])> {
    let ed_sk = ensure_64_byte_sk(ed25519_sk)?;

    // Derive session_id: 0x05 || ed25519_pk_to_curve25519(ed_pk)
    let ed_pk: [u8; 32] = ed_sk[32..].try_into().unwrap();
    let x25519_pub = ed25519_pk_to_curve25519(&ed_pk)?;

    // Compute k from the X25519 pubkey (32 bytes, unprefixed)
    let mut k_prime = blind25_factor(&x25519_pub, server_pk);

    // For a negative pubkey we use k' = -k so that k'A == kA when A is positive
    if ed_sk[63] & 0x80 != 0 {
        let k_scalar = Scalar::from_bytes_mod_order(k_prime);
        k_prime = (-k_scalar).to_bytes();
    }

    // Extract the private scalar a
    let a_bytes = ed25519_sk_to_scalar(&ed_sk);

    // a_blinded = k' * a
    let k_scalar = Scalar::from_bytes_mod_order(k_prime);
    let a_scalar = Scalar::from_bytes_mod_order(a_bytes);
    let blinded_a = k_scalar * a_scalar;

    // A_blinded = a_blinded * G
    let blinded_point = EdwardsPoint::mul_base(&blinded_a);
    let blinded_pk = blinded_point.compress().to_bytes();

    Ok((blinded_pk, blinded_a.to_bytes()))
}

// ---------------------------------------------------------------------------
// Version-blinded key pair
// ---------------------------------------------------------------------------

const VERSION_BLINDING_HASH_KEY_SIG: &[u8] = b"VersionCheckKey_sig";

/// Computes a version-blinded key pair.
///
/// Takes the Ed25519 secret key (32-byte seed or 64-byte libsodium format).
/// Returns `(blinded_pubkey, blinded_seckey_64)` where the secret key is the
/// full 64-byte libsodium format (seed || pubkey).
pub fn blind_version_key_pair(ed25519_sk: &[u8]) -> CryptoResult<([u8; 32], [u8; 64])> {
    if ed25519_sk.len() != 32 && ed25519_sk.len() != 64 {
        return Err(CryptoError::InvalidInput(
            "blind_version_key_pair: ed25519_sk must be 32 or 64 bytes".into(),
        ));
    }

    // blind_seed = BLAKE2b(ed25519_seed, key="VersionCheckKey_sig", output=32)
    let blind_seed_hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(VERSION_BLINDING_HASH_KEY_SIG)
        .hash(&ed25519_sk[..32]);

    let mut blind_seed = [0u8; 32];
    blind_seed.copy_from_slice(blind_seed_hash.as_bytes());

    // Generate keypair from blind_seed
    let (pk, sk) = crate::crypto::ed25519::ed25519_key_pair_from_seed(&blind_seed)?;
    let _ = pk;
    // sk is already seed||pk in libsodium format
    let mut pk_out = [0u8; 32];
    pk_out.copy_from_slice(&sk[32..]);
    Ok((pk_out, sk))
}

// ---------------------------------------------------------------------------
// Blinded signatures
// ---------------------------------------------------------------------------

const HASH_KEY_SEED: &[u8] = b"SessCommBlind25_seed";
const HASH_KEY_SIG: &[u8] = b"SessCommBlind25_sig";

/// Computes a verifiable 25-blinded signature.
///
/// `server_pk` can be 32 raw bytes or 64 hex chars (as bytes).
/// Returns a 64-byte signature.
pub fn blind25_sign(ed25519_sk: &[u8], server_pk: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let ed_sk = ensure_64_byte_sk(ed25519_sk)?;
    let server_pk_bytes = parse_server_pk(server_pk)?;

    let (blinded_pk, blinded_sk) = blind25_key_pair(&ed_sk, &server_pk_bytes)?;

    // seedhash = BLAKE2b(ed25519_seed, key="SessCommBlind25_seed", output=32)
    let seedhash_result = blake2b_simd::Params::new()
        .hash_length(32)
        .key(HASH_KEY_SEED)
        .hash(&ed_sk[..32]);
    let mut seedhash = [0u8; 32];
    seedhash.copy_from_slice(seedhash_result.as_bytes());

    // r_hash = BLAKE2b(key="SessCommBlind25_sig", seedhash || A || message, output=64)
    let r_hash_result = blake2b_simd::Params::new()
        .hash_length(64)
        .key(HASH_KEY_SIG)
        .to_state()
        .update(&seedhash)
        .update(&blinded_pk)
        .update(message)
        .finalize();
    let mut r_hash = [0u8; 64];
    r_hash.copy_from_slice(r_hash_result.as_bytes());

    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    // sig_R = r * G
    let sig_r_point = EdwardsPoint::mul_base(&r);
    let sig_r = sig_r_point.compress().to_bytes();

    // HRAM = SHA-512(R || A || message) mod L
    let mut hasher = Sha512::new();
    hasher.update(sig_r);
    hasher.update(blinded_pk);
    hasher.update(message);
    let hram_hash: [u8; 64] = hasher.finalize().into();
    let hram = Scalar::from_bytes_mod_order_wide(&hram_hash);

    // S = r + HRAM * a
    let a = Scalar::from_bytes_mod_order(blinded_sk);
    let sig_s = r + hram * a;

    let mut result = vec![0u8; 64];
    result[..32].copy_from_slice(&sig_r);
    result[32..].copy_from_slice(&sig_s.to_bytes());
    Ok(result)
}

/// Computes a verifiable 15-blinded signature.
///
/// `server_pk` can be 32 raw bytes or 64 hex chars (as bytes).
/// Returns a 64-byte signature.
pub fn blind15_sign(ed25519_sk: &[u8], server_pk: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let ed_sk = ensure_64_byte_sk(ed25519_sk)?;
    let server_pk_bytes = parse_server_pk(server_pk)?;

    let (blind_15_pk, blind_15_sk) = blind15_key_pair(&ed_sk, &server_pk_bytes)?;

    // H_rh = SHA-512(ed25519_sk_full)
    let mut hrh_hasher = Sha512::new();
    hrh_hasher.update(ed_sk);
    let hrh: [u8; 64] = hrh_hasher.finalize().into();

    // r = SHA-512(H_rh[32..] || kA || message) mod L
    let mut r_hasher = Sha512::new();
    r_hasher.update(&hrh[32..]);
    r_hasher.update(blind_15_pk);
    r_hasher.update(message);
    let r_hash: [u8; 64] = r_hasher.finalize().into();
    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    // sig_R = r * G
    let sig_r_point = EdwardsPoint::mul_base(&r);
    let sig_r = sig_r_point.compress().to_bytes();

    // HRAM = SHA-512(R || kA || message) mod L
    let mut hram_hasher = Sha512::new();
    hram_hasher.update(sig_r);
    hram_hasher.update(blind_15_pk);
    hram_hasher.update(message);
    let hram: [u8; 64] = hram_hasher.finalize().into();
    let hram_scalar = Scalar::from_bytes_mod_order_wide(&hram);

    // S = r + HRAM * ka
    let ka_scalar = Scalar::from_bytes_mod_order(blind_15_sk);
    let sig_s = r + hram_scalar * ka_scalar;

    let mut result = vec![0u8; 64];
    result[..32].copy_from_slice(&sig_r);
    result[32..].copy_from_slice(&sig_s.to_bytes());
    Ok(result)
}

/// Computes a version-blinded signature for a platform version check.
///
/// Signs `TIMESTAMP || "GET" || "/session_version?platform=..."`.
pub fn blind_version_sign(
    ed25519_sk: &[u8],
    platform: Platform,
    timestamp: u64,
) -> CryptoResult<Vec<u8>> {
    let (_, sk) = blind_version_key_pair(ed25519_sk)?;

    let ts_str = timestamp.to_string();
    let method = "GET";
    let url = match platform {
        Platform::Android => "/session_version?platform=android",
        Platform::Desktop => "/session_version?platform=desktop",
        Platform::Ios => "/session_version?platform=ios",
    };

    let mut buf = Vec::with_capacity(ts_str.len() + method.len() + url.len());
    buf.extend_from_slice(ts_str.as_bytes());
    buf.extend_from_slice(method.as_bytes());
    buf.extend_from_slice(url.as_bytes());

    let sig = crate::crypto::ed25519::sign(&sk, &buf)?;
    Ok(sig.to_vec())
}

/// Computes a version-blinded signature for an arbitrary request.
///
/// Signs `TIMESTAMP || METHOD || PATH || BODY`.
pub fn blind_version_sign_request(
    ed25519_sk: &[u8],
    timestamp: u64,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let (_, sk) = blind_version_key_pair(ed25519_sk)?;

    let ts_str = timestamp.to_string();
    let mut buf =
        Vec::with_capacity(ts_str.len() + method.len() + path.len() + body.map_or(0, |b| b.len()));
    buf.extend_from_slice(ts_str.as_bytes());
    buf.extend_from_slice(method.as_bytes());
    buf.extend_from_slice(path.as_bytes());
    if let Some(b) = body {
        buf.extend_from_slice(b);
    }

    let sig = crate::crypto::ed25519::sign(&sk, &buf)?;
    Ok(sig.to_vec())
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Checks whether a session ID matches a blinded ID for a given server.
///
/// All inputs are hex-encoded: session_id (66 chars), blinded_id (66 chars),
/// server_pk (64 chars).
pub fn session_id_matches_blinded_id(
    session_id: &str,
    blinded_id: &str,
    server_pk: &str,
) -> CryptoResult<bool> {
    if session_id.len() != 66 || hex::decode(session_id).is_err() {
        return Err(CryptoError::InvalidInput(
            "session_id_matches_blinded_id: session_id must be hex (66 digits)".into(),
        ));
    }
    if &session_id[..2] != "05" {
        return Err(CryptoError::InvalidInput(
            "session_id_matches_blinded_id: session_id must start with 05".into(),
        ));
    }
    if blinded_id.len() < 2
        || (blinded_id.chars().nth(1) != Some('5'))
        || (!blinded_id.starts_with('1') && !blinded_id.starts_with('2'))
    {
        return Err(CryptoError::InvalidInput(
            "session_id_matches_blinded_id: blinded_id must start with 15 or 25".into(),
        ));
    }
    if server_pk.len() != 64 || hex::decode(server_pk).is_err() {
        return Err(CryptoError::InvalidInput(
            "session_id_matches_blinded_id: server_pk must be hex (64 digits)".into(),
        ));
    }

    match blinded_id.chars().next() {
        Some('1') => {
            let [converted1, converted2] = blind15_id_hex(session_id, server_pk)?;
            Ok(blinded_id == converted1 || blinded_id == converted2)
        }
        Some('2') => {
            let converted = blind25_id_hex(session_id, server_pk)?;
            Ok(blinded_id == converted)
        }
        _ => Err(CryptoError::InvalidInput(
            "Invalid blinded_id: must start with 15 or 25".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test seeds from the C++ test suite (64-byte: seed || ed25519_pubkey)
    const SEED1: [u8; 64] = [
        0xfe, 0xcd, 0x9a, 0x60, 0x34, 0xbc, 0x9a, 0xba, 0x27, 0x39, 0x25, 0xde, 0xe7, 0x06, 0x2b,
        0x12, 0x33, 0x34, 0x58, 0x7c, 0x3c, 0x62, 0x57, 0x34, 0x1a, 0xfa, 0xe2, 0xd7, 0xfe, 0x85,
        0xe1, 0x22, 0xf4, 0xef, 0x87, 0x39, 0x08, 0xf6, 0xa5, 0x37, 0x7b, 0xa3, 0x85, 0x3f, 0x0e,
        0x2f, 0xa3, 0x26, 0xee, 0xd9, 0xe7, 0x41, 0xed, 0xf9, 0xf7, 0xd0, 0x31, 0x1a, 0x3e, 0xcc,
        0x66, 0xa5, 0x7b, 0x32,
    ];

    const SEED2: [u8; 64] = [
        0x86, 0x59, 0xef, 0xdc, 0xbe, 0x09, 0x49, 0xe0, 0xf8, 0x11, 0x41, 0xe6, 0xd3, 0x97, 0xe8,
        0xbe, 0x75, 0xf4, 0x5d, 0x09, 0x26, 0x2f, 0x20, 0x9d, 0x59, 0x50, 0xe9, 0x79, 0x89, 0xeb,
        0x43, 0xc7, 0x35, 0x70, 0xb6, 0x9a, 0x47, 0xdc, 0x09, 0x45, 0x44, 0xc1, 0xc5, 0x08, 0x9c,
        0x40, 0x41, 0x4b, 0xbd, 0xa1, 0xff, 0xdd, 0xe8, 0xaa, 0xb2, 0x61, 0x7f, 0xe9, 0x37, 0xee,
        0x74, 0xa5, 0xee, 0x81,
    ];

    const XPUB1: [u8; 32] = [
        0xfe, 0x94, 0xb7, 0xad, 0x4b, 0x7f, 0x1c, 0xc1, 0xbb, 0x92, 0x67, 0x1f, 0x1f, 0x0d, 0x24,
        0x3f, 0x22, 0x6e, 0x11, 0x5b, 0x33, 0x77, 0x04, 0x65, 0xe8, 0x2b, 0x50, 0x3f, 0xc3, 0xe9,
        0x6e, 0x1f,
    ];

    const XPUB2: [u8; 32] = [
        0x05, 0xc9, 0xa9, 0xbf, 0x17, 0x8f, 0xa6, 0x44, 0xd4, 0x4b, 0xeb, 0xf6, 0x28, 0x71, 0x6d,
        0xc7, 0xf2, 0xdf, 0x3d, 0x08, 0x42, 0xe9, 0x78, 0x81, 0x96, 0x2c, 0x72, 0x36, 0x99, 0x15,
        0x20, 0x73,
    ];

    fn session_id1() -> String {
        format!("05{}", hex::encode(XPUB1))
    }

    fn session_id2() -> String {
        format!("05{}", hex::encode(XPUB2))
    }

    const SERVER_PKS: [&str; 6] = [
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "00cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "999def0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "888def0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "777def0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    ];

    #[test]
    fn test_blind25_id_hex() {
        assert_eq!(
            blind25_id_hex(&session_id1(), SERVER_PKS[0]).unwrap(),
            "253b991dcbba44cfdb45d5b38880d95cff723309e3ece6fd01415ad5fa1dccc7ac"
        );
        assert_eq!(
            blind25_id_hex(&session_id1(), SERVER_PKS[1]).unwrap(),
            "2598589c7885b56cbeae6ab7b4224f202815520a54995872cb1833b44db6401c8d"
        );
        assert_eq!(
            blind25_id_hex(&session_id2(), SERVER_PKS[0]).unwrap(),
            "25a69cc6884530bf8498d22892e563716c4742f2845a7eb608de2aecbe7b6b5996"
        );
    }

    #[test]
    fn test_blind25_id_raw() {
        let sid1_raw = hex::decode(session_id1()).unwrap();
        let server_pk = hex::decode(SERVER_PKS[0]).unwrap();
        let mut spk = [0u8; 32];
        spk.copy_from_slice(&server_pk);

        let result = blind25_id(&sid1_raw, &spk).unwrap();
        assert_eq!(
            hex::encode(&result),
            "253b991dcbba44cfdb45d5b38880d95cff723309e3ece6fd01415ad5fa1dccc7ac"
        );

        // Also test with unprefixed (32 bytes)
        let result2 = blind25_id(&sid1_raw[1..], &spk).unwrap();
        assert_eq!(
            hex::encode(&result2),
            "253b991dcbba44cfdb45d5b38880d95cff723309e3ece6fd01415ad5fa1dccc7ac"
        );
    }

    #[test]
    fn test_blind15_id_raw() {
        let sid1_raw = hex::decode(session_id1()).unwrap();
        let sid2_raw = hex::decode(session_id2()).unwrap();
        let server_pk = hex::decode(SERVER_PKS[0]).unwrap();
        let mut spk = [0u8; 32];
        spk.copy_from_slice(&server_pk);

        assert_eq!(
            hex::encode(blind15_id(&sid1_raw, &spk).unwrap()),
            "15b74ed205f1f931e1bb1291183778a9456b835937d923b0f2e248aa3a44c07844"
        );
        assert_eq!(
            hex::encode(blind15_id(&sid2_raw, &spk).unwrap()),
            "1561e070286ff7a71f167e92b18c709882b148d8238c8872caf414b301ba0564fd"
        );
        // Unprefixed
        assert_eq!(
            hex::encode(blind15_id(&sid1_raw[1..], &spk).unwrap()),
            "15b74ed205f1f931e1bb1291183778a9456b835937d923b0f2e248aa3a44c07844"
        );
    }

    #[test]
    fn test_blind25_sign() {
        let sig1 = blind25_sign(&SEED1, SERVER_PKS[0].as_bytes(), b"hello").unwrap();
        assert_eq!(
            hex::encode(&sig1),
            "e6c57de4ac0cd278abbeef815bd88b163a037085deae789ecaaf4805884c4c3d\
             3db25f3afa856241366cb341a3a4c9bbaa2cda81d028079c956fab16a7fe6206"
        );

        let sig2 = blind25_sign(&SEED1, SERVER_PKS[1].as_bytes(), b"world").unwrap();
        assert_eq!(
            hex::encode(&sig2),
            "4460b606e9f55a7cba0bbe24207fe2859c3422783373788b6b070b2fa62ceba4\
             f2a50749a6cee68e095747a369927f9f4afa86edaf055cad68110e35e8b06607"
        );

        let sig3 = blind25_sign(&SEED2, SERVER_PKS[2].as_bytes(), b"this").unwrap();
        assert_eq!(
            hex::encode(&sig3),
            "57bb2f80c88ce2f677902ee58e02cbd83e4e1ec9e06e1c72a34b4ab76d0f5219\
             cfd141ac5ce7016c73c8382db99df9f317f2bc0af6ca68edac2a9a7670938902"
        );

        let sig4 = blind25_sign(&SEED2, SERVER_PKS[3].as_bytes(), b"is").unwrap();
        assert_eq!(
            hex::encode(&sig4),
            "ecce032b27b09d2d3d6df4ebab8cae86656c64fd1e3e70d6f020cd7e1a8058c5\
             7e3df7b6b01e90ccd592ac4a845dde7a2fdceb1a328a6690686851583133ea0c"
        );

        let sig5 = blind25_sign(&SEED2, SERVER_PKS[4].as_bytes(), b"").unwrap();
        assert_eq!(
            hex::encode(&sig5),
            "bf2fb9a511adbf5827e2e3bcf09f0a1cff80f85556fb76d8001aa8483b5f22e1\
             4539b170eaa0dbfa1489d1b8618ce8b48d7512cb5602c7eb8a05ce330a68350b"
        );

        let sig6 = blind25_sign(&SEED1, SERVER_PKS[5].as_bytes(), b"omg!").unwrap();
        assert_eq!(
            hex::encode(&sig6),
            "322e280fbc3547c6b6512dbea4d60563d32acaa2df10d665c40a336c99fc3b8e\
             4b13a7109dfdeadab2ab58b2cb314eb0510b947f43e5dfb6e0ce5bf1499d240f"
        );

        // Test that it works when given just the seed (32 bytes) instead of the whole sk:
        let sig6b = blind25_sign(&SEED1[..32], SERVER_PKS[5].as_bytes(), b"omg!").unwrap();
        assert_eq!(hex::encode(&sig6b), hex::encode(&sig6));
    }

    #[test]
    fn test_blind15_sign() {
        let sig1 = blind15_sign(&SEED1, SERVER_PKS[0].as_bytes(), b"hello").unwrap();
        assert_eq!(
            hex::encode(&sig1),
            "1a5ade20b43af0e16b3e591d6f86303938d7557c0ac54469dd4f5aea759f82d2\
             2cafa42587251756e133acdddd8cbec2f707a9ce09a49f2193f46a91502c5006"
        );

        let sig2 = blind15_sign(&SEED1, SERVER_PKS[1].as_bytes(), b"world").unwrap();
        assert_eq!(
            hex::encode(&sig2),
            "d357f74c5ec5536840aec575051f71fdb22d70f35ef31db1715f5f694842de3b\
             39aa647c84aa8e28ec56eb762d237c9e030639c83f429826d419ac719cd4df03"
        );

        let sig3 = blind15_sign(&SEED2, SERVER_PKS[2].as_bytes(), b"this").unwrap();
        assert_eq!(
            hex::encode(&sig3),
            "dacf91dfb411e99cd8ef4cb07b195b49289cf1a724fef122c73462818560bc29\
             832a98d870ec4feb79dedca5b59aba6a466d3ce8f3e35adf25a1813f6989fd0a"
        );

        let sig4 = blind15_sign(&SEED2, SERVER_PKS[3].as_bytes(), b"is").unwrap();
        assert_eq!(
            hex::encode(&sig4),
            "8339ea9887d3e44131e33403df160539cdc7a0a8107772172c311e95773660a0\
             d39ed0a6c2b2c794dde1fdc640943e403497aa02c4d1a21a7d9030742beabb05"
        );

        let sig5 = blind15_sign(&SEED2, SERVER_PKS[4].as_bytes(), b"").unwrap();
        assert_eq!(
            hex::encode(&sig5),
            "8b0d6447decff3a21ec1809141580139c4a51e24977b0605fe7984439993f537\
             7ebc9681e4962593108d03cc8b6873c5c5ba8c30287188137d2dee9ab10afd0f"
        );

        let sig6 = blind15_sign(&SEED1, SERVER_PKS[5].as_bytes(), b"omg!").unwrap();
        assert_eq!(
            hex::encode(&sig6),
            "946725055399376ecebb605c79f845fbf689a47f98507c2a1f239516fd9c9104\
             e19fe533631c27ba4e7444574f0e4f0f0d422b7256ed63681a3ab2fe7e040601"
        );

        // Test that it works when given just the seed (32 bytes) instead of the whole sk:
        let sig6b = blind15_sign(&SEED1[..32], SERVER_PKS[5].as_bytes(), b"omg!").unwrap();
        assert_eq!(hex::encode(&sig6b), hex::encode(&sig6));
    }

    #[test]
    fn test_blind_version_key_pair() {
        let (pubkey, seckey) = blind_version_key_pair(&SEED1).unwrap();
        assert_eq!(
            hex::encode(pubkey),
            "88e8adb27e7b8ce776fcc25bc1501fb2888fcac0308e52fb10044f789ae1a8fa"
        );
        // seckey[32..] should equal pubkey
        assert_eq!(hex::encode(&seckey[32..]), hex::encode(pubkey));

        // Verify the seed part of seckey
        assert_eq!(
            hex::encode(&seckey[..32]),
            "91faddc2c36da4f7bcf24fd977d9ca5346ae7489cfd43c58cad9eaaa6ed60f69"
        );

        assert_eq!(
            hex::encode(seckey),
            "91faddc2c36da4f7bcf24fd977d9ca5346ae7489cfd43c58cad9eaaa6ed60f69\
             88e8adb27e7b8ce776fcc25bc1501fb2888fcac0308e52fb10044f789ae1a8fa"
        );
    }

    #[test]
    fn test_blind_version_sign() {
        let signature = blind_version_sign(&SEED1, Platform::Desktop, 1234567890).unwrap();
        assert_eq!(
            hex::encode(&signature),
            "143c2c9828f7680ee81e6247bc7aa4777c4991add87cd724149b00452bed4e92\
             0fa57daf4627c68f43fcbddb2d465d5ea11def523f3befb2bbee39c769676305"
        );
    }

    #[test]
    fn test_blind_version_sign_request() {
        let (pk, _) = blind_version_key_pair(&SEED1).unwrap();
        let timestamp: u64 = 1234567890;
        let method = "GET";
        let path = "/path/to/somewhere";
        let body = b"some body (once told me)";

        // Without body
        let mut full_message_no_body = Vec::new();
        full_message_no_body.extend_from_slice(timestamp.to_string().as_bytes());
        full_message_no_body.extend_from_slice(method.as_bytes());
        full_message_no_body.extend_from_slice(path.as_bytes());

        let req_sig_no_body =
            blind_version_sign_request(&SEED1, timestamp, method, path, None).unwrap();
        assert!(
            crate::crypto::ed25519::verify(&req_sig_no_body, &pk, &full_message_no_body).unwrap()
        );

        // With body
        let mut full_message = full_message_no_body.clone();
        full_message.extend_from_slice(body);

        let req_sig =
            blind_version_sign_request(&SEED1, timestamp, method, path, Some(body)).unwrap();
        assert!(crate::crypto::ed25519::verify(&req_sig, &pk, &full_message).unwrap());
    }

    #[test]
    fn test_session_id_matches_blinded_id_25() {
        let sid1 = session_id1();
        let sid2 = session_id2();

        for (i, spk) in SERVER_PKS.iter().enumerate() {
            let b25 = if i == 0 || i == 1 || i == 5 {
                blind25_id_hex(&sid1, spk).unwrap()
            } else {
                blind25_id_hex(&sid2, spk).unwrap()
            };
            let sid = if i == 0 || i == 1 || i == 5 {
                &sid1
            } else {
                &sid2
            };
            assert!(
                session_id_matches_blinded_id(sid, &b25, spk).unwrap(),
                "blind25 match failed for server_pk index {}",
                i
            );
        }
    }

    #[test]
    fn test_session_id_matches_blinded_id_15() {
        let sid1 = session_id1();
        let sid2 = session_id2();

        // For blind15, session_id2 has a negative key, so we need to use [1] variant
        let b15_1 = blind15_id_hex(&sid1, SERVER_PKS[0]).unwrap()[0].clone();
        let b15_2 = blind15_id_hex(&sid1, SERVER_PKS[1]).unwrap()[0].clone();
        let b15_3 = blind15_id_hex(&sid2, SERVER_PKS[2]).unwrap()[1].clone();
        let b15_4 = blind15_id_hex(&sid2, SERVER_PKS[3]).unwrap()[1].clone();
        let b15_5 = blind15_id_hex(&sid2, SERVER_PKS[4]).unwrap()[1].clone();
        let b15_6 = blind15_id_hex(&sid1, SERVER_PKS[5]).unwrap()[0].clone();

        assert!(session_id_matches_blinded_id(&sid1, &b15_1, SERVER_PKS[0]).unwrap());
        assert!(session_id_matches_blinded_id(&sid1, &b15_2, SERVER_PKS[1]).unwrap());
        assert!(session_id_matches_blinded_id(&sid2, &b15_3, SERVER_PKS[2]).unwrap());
        assert!(session_id_matches_blinded_id(&sid2, &b15_4, SERVER_PKS[3]).unwrap());
        assert!(session_id_matches_blinded_id(&sid2, &b15_5, SERVER_PKS[4]).unwrap());
        assert!(session_id_matches_blinded_id(&sid1, &b15_6, SERVER_PKS[5]).unwrap());
    }

    #[test]
    fn test_session_id_matches_blinded_id_invalid() {
        let sid1 = session_id1();
        let b15_1 = blind15_id_hex(&sid1, SERVER_PKS[0]).unwrap()[0].clone();

        let invalid_session_id = format!("9{}", &sid1[1..]);
        let invalid_blinded_id = format!("9{}", &b15_1[1..]);
        let invalid_server_pk = &SERVER_PKS[0][..60];

        assert!(session_id_matches_blinded_id(&invalid_session_id, &b15_1, SERVER_PKS[0]).is_err());
        assert!(session_id_matches_blinded_id(&sid1, &invalid_blinded_id, SERVER_PKS[0]).is_err());
        assert!(
            session_id_matches_blinded_id(&sid1, &invalid_blinded_id, invalid_server_pk).is_err()
        );
    }

    /// Verify that blind25 signatures are valid ed25519 signatures against the blinded pubkey.
    #[test]
    fn test_blind25_sign_verify() {
        let b25_hex = blind25_id_hex(&session_id1(), SERVER_PKS[0]).unwrap();
        let b25_raw = hex::decode(&b25_hex).unwrap();
        let blinded_pk = &b25_raw[1..]; // skip 0x25 prefix

        let sig = blind25_sign(&SEED1, SERVER_PKS[0].as_bytes(), b"hello").unwrap();
        assert!(crate::crypto::ed25519::verify(&sig, blinded_pk, b"hello").unwrap());
    }

    /// Verify that blind15 signatures are valid ed25519 signatures against the blinded pubkey.
    #[test]
    fn test_blind15_sign_verify() {
        let b15_hex = blind15_id_hex(&session_id1(), SERVER_PKS[0]).unwrap();
        let b15_raw = hex::decode(&b15_hex[0]).unwrap();
        let blinded_pk = &b15_raw[1..]; // skip 0x15 prefix

        let sig = blind15_sign(&SEED1, SERVER_PKS[0].as_bytes(), b"hello").unwrap();
        assert!(crate::crypto::ed25519::verify(&sig, blinded_pk, b"hello").unwrap());
    }
}
