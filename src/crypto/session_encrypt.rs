//! Session protocol encryption and decryption.
//!
//! Port of `libsession-util/src/session_encrypt.cpp`. Implements the Session
//! sealed-box protocol, deterministic encryption, blinded encryption for SOGS,
//! group message encryption, ONS decryption, push notification decryption,
//! and XChaCha20-Poly1305 helpers.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::Digest;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroize;

use crate::crypto::curve25519::{to_curve25519_pubkey, to_curve25519_seckey};
use crate::crypto::ed25519::ed25519_key_pair_from_seed;
use crate::crypto::types::{CryptoError, CryptoResult, DecryptGroupMessage};

/// Version tag prepended to encrypted-for-blinded-user messages.
const BLINDED_ENCRYPT_VERSION: u8 = 0;

/// Maximum plaintext size for group messages (1 MB).
const GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE: usize = 1_000_000;

/// Overhead for group encryption: nonce (24) + poly1305 tag (16).
const GROUPS_ENCRYPT_OVERHEAD: usize = 24 + 16;

/// Key used for deterministic ephemeral seed derivation.
const BOX_HASHKEY: &[u8] = b"SessionBoxEphemeralHashKey";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Expand a 32-byte ed25519 seed into a 64-byte libsodium-style secret key
/// (seed || pubkey). If already 64 bytes, returns as-is.
fn expand_ed25519_privkey(privkey: &[u8]) -> CryptoResult<[u8; 64]> {
    match privkey.len() {
        32 => {
            let (_, sk) = ed25519_key_pair_from_seed(privkey)?;
            Ok(sk)
        }
        64 => {
            let mut out = [0u8; 64];
            out.copy_from_slice(privkey);
            Ok(out)
        }
        _ => Err(CryptoError::InvalidInput(
            "Invalid ed25519_privkey: expected 32 or 64 bytes".into(),
        )),
    }
}

/// Strip the 0x05 prefix from a recipient pubkey if present, returning the 32-byte key.
fn strip_05_prefix(pubkey: &[u8]) -> CryptoResult<&[u8]> {
    if pubkey.len() == 33 && pubkey[0] == 0x05 {
        Ok(&pubkey[1..])
    } else if pubkey.len() == 32 {
        Ok(pubkey)
    } else {
        Err(CryptoError::InvalidInput(
            "Invalid recipient_pubkey: expected 32 bytes (33 with 05 prefix)".into(),
        ))
    }
}

/// Compute an unkeyed BLAKE2b hash of `data` slices with the given output length.
fn blake2b_hash(parts: &[&[u8]], hash_len: usize) -> Vec<u8> {
    let mut state = blake2b_simd::Params::new();
    state.hash_length(hash_len);
    let mut st = state.to_state();
    for part in parts {
        st.update(part);
    }
    st.finalize().as_bytes()[..hash_len].to_vec()
}

/// Compute a keyed BLAKE2b hash.
fn blake2b_keyed_hash(parts: &[&[u8]], key: &[u8], hash_len: usize) -> Vec<u8> {
    let mut params = blake2b_simd::Params::new();
    params.hash_length(hash_len);
    params.key(key);
    let mut st = params.to_state();
    for part in parts {
        st.update(part);
    }
    st.finalize().as_bytes()[..hash_len].to_vec()
}

// ---------------------------------------------------------------------------
// sign_for_recipient
// ---------------------------------------------------------------------------

/// Signs a message for a specific recipient.
///
/// Creates `M || A || SIG` where:
/// - `A` = sender's ed25519 pubkey (32 bytes)
/// - `SIG` = ed25519_sign(M || A || Y) where Y = recipient X25519 pubkey (32 bytes)
///
/// `ed25519_privkey` can be 32 bytes (seed) or 64 bytes (libsodium secret key).
/// `recipient_pubkey` can be 32 bytes or 33 bytes (with 0x05 prefix).
pub fn sign_for_recipient(
    ed25519_privkey: &[u8],
    recipient_pubkey: &[u8],
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    let ed_sk = expand_ed25519_privkey(ed25519_privkey)?;
    let recip_pk = strip_05_prefix(recipient_pubkey)?;

    let sender_ed_pk = &ed_sk[32..]; // pubkey is second half of libsodium key

    // Build M || A || Y for signing
    let mut to_sign = Vec::with_capacity(message.len() + 32 + 32);
    to_sign.extend_from_slice(message);
    to_sign.extend_from_slice(sender_ed_pk);
    to_sign.extend_from_slice(recip_pk);

    // Sign M || A || Y
    let seed: [u8; 32] = ed_sk[..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed);
    let sig = signing_key.sign(&to_sign);

    // Result is M || A || SIG
    let mut result = Vec::with_capacity(message.len() + 32 + 64);
    result.extend_from_slice(message);
    result.extend_from_slice(sender_ed_pk);
    result.extend_from_slice(&sig.to_bytes());

    Ok(result)
}

// ---------------------------------------------------------------------------
// encrypt_for_recipient
// ---------------------------------------------------------------------------

/// Encrypts a message for a specific recipient using a sealed box.
///
/// Signs via `sign_for_recipient`, then encrypts with NaCl `crypto_box_seal`
/// (ephemeral X25519 keypair + XSalsa20-Poly1305).
pub fn encrypt_for_recipient(
    ed25519_privkey: &[u8],
    recipient_pubkey: &[u8],
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    let signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message)?;
    let recip_pk = strip_05_prefix(recipient_pubkey)?;

    let recip_pk_arr: [u8; 32] = recip_pk.try_into().map_err(|_| {
        CryptoError::InvalidInput("recipient pubkey must be 32 bytes".into())
    })?;
    let recip_box_pk = crypto_box::PublicKey::from(recip_pk_arr);

    let ciphertext = recip_box_pk
        .seal(&mut OsRng, &signed_msg)
        .map_err(|e| CryptoError::EncryptionFailed(format!("Sealed box encryption failed: {e}")))?;

    Ok(ciphertext)
}

// ---------------------------------------------------------------------------
// encrypt_for_recipient_deterministic
// ---------------------------------------------------------------------------

/// Encrypts a message for a recipient with a deterministic ephemeral key.
///
/// The ephemeral seed is derived via keyed BLAKE2b:
///   `seed = BLAKE2b(key="SessionBoxEphemeralHashKey", sender_seed || recipient_pk || message)`
///
/// Then constructs a sealed box with that deterministic ephemeral keypair.
pub fn encrypt_for_recipient_deterministic(
    ed25519_privkey: &[u8],
    recipient_pubkey: &[u8],
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    let signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message)?;
    let recip_pk = strip_05_prefix(recipient_pubkey)?;

    // Derive the deterministic ephemeral seed:
    // BLAKE2b(keyed="SessionBoxEphemeralHashKey", sender_seed || recipient_pk || message)
    // crypto_box_SEEDBYTES = 32
    let sender_seed = &ed25519_privkey[..32];
    let mut eph_seed =
        blake2b_keyed_hash(&[sender_seed, recip_pk, message], BOX_HASHKEY, 32);

    // Generate ephemeral keypair from seed using crypto_box_seed_keypair equivalent.
    // In libsodium, crypto_box_seed_keypair hashes the seed with SHA-512 then clamps.
    // The crypto_box crate's SecretKey::from works differently - we need to use the
    // same derivation as libsodium's crypto_box_seed_keypair:
    //   sk = SHA-512(seed)[0..32], clamped
    //   pk = sk * basepoint
    // But actually crypto_box_seed_keypair uses crypto_hash_sha512 then takes the first
    // 32 bytes as the secret key (with no explicit clamping since X25519 clamps internally).
    let eph_hash: [u8; 64] = sha2::Sha512::digest(eph_seed.as_slice()).into();
    let mut eph_sk_bytes = [0u8; 32];
    eph_sk_bytes.copy_from_slice(&eph_hash[..32]);
    eph_seed.zeroize();

    let eph_sk = X25519SecretKey::from(eph_sk_bytes);
    let eph_pk = X25519PublicKey::from(&eph_sk);

    eph_sk_bytes.zeroize();

    // Compute nonce = unkeyed BLAKE2b(eph_pk || recipient_pk), 24 bytes
    // (crypto_box_NONCEBYTES = 24)
    let nonce_bytes = blake2b_hash(&[eph_pk.as_bytes(), recip_pk], 24);

    // Encrypt using crypto_box (NaCl box = X25519 DH + HSalsa20 key derivation + XSalsa20-Poly1305)
    let recip_pk_arr: [u8; 32] = recip_pk.try_into().unwrap();
    let box_recip_pk = crypto_box::PublicKey::from(recip_pk_arr);
    let box_secret = crypto_box::SecretKey::from(eph_sk.to_bytes());
    let salsa_box = crypto_box::SalsaBox::new(&box_recip_pk, &box_secret);

    let nonce_arr: [u8; 24] = nonce_bytes[..24].try_into().unwrap();
    let nonce = crypto_box::Nonce::from(nonce_arr);

    let encrypted = salsa_box
        .encrypt(&nonce, signed_msg.as_slice())
        .map_err(|e| CryptoError::EncryptionFailed(format!("Crypto box encryption failed: {e}")))?;

    // Sealed box format: eph_pk || encrypted
    // crypto_box_SEALBYTES = crypto_box_PUBLICKEYBYTES(32) + crypto_box_MACBYTES(16) = 48
    let mut result = Vec::with_capacity(32 + encrypted.len());
    result.extend_from_slice(eph_pk.as_bytes());
    result.extend_from_slice(&encrypted);

    Ok(result)
}

// ---------------------------------------------------------------------------
// encrypt_for_blinded_recipient
// ---------------------------------------------------------------------------

/// Computes the shared encryption key for blinded messaging.
///
/// This matches the C++ `blinded_shared_secret` function.
///
/// `seed` is the caller's ed25519 private key (32 or 64 bytes).
/// `kA` is the caller's 33-byte blinded id (0x15 or 0x25 prefix).
/// `jB` is the remote party's 33-byte blinded id.
/// `server_pk` is the server's 32-byte pubkey.
/// `sending` is true when we are the sender, false when we are the receiver.
fn blinded_shared_secret(
    seed: &[u8],
    k_a: &[u8],
    j_b: &[u8],
    server_pk: &[u8],
    sending: bool,
) -> CryptoResult<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    if seed.len() != 64 && seed.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid ed25519_privkey: expected 32 or 64 bytes".into(),
        ));
    }
    if server_pk.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid server_pk: expected 32 bytes".into(),
        ));
    }
    if k_a.len() != 33 {
        return Err(CryptoError::InvalidInput(
            "Invalid local blinded id: expected 33 bytes".into(),
        ));
    }
    if j_b.len() != 33 {
        return Err(CryptoError::InvalidInput(
            "Invalid remote blinded id: expected 33 bytes".into(),
        ));
    }

    let blind25 = if k_a[0] == 0x15 && j_b[0] == 0x15 {
        false
    } else if k_a[0] == 0x25 && j_b[0] == 0x25 {
        true
    } else {
        return Err(CryptoError::InvalidInput(
            "Both ids must start with the same 0x15 or 0x25 prefix".into(),
        ));
    };

    // Strip prefixes
    let k_a_raw = &k_a[1..];
    let j_b_raw = &j_b[1..];

    // Compute `a` (the ed25519 scalar / curve25519 secret key)
    // "Not really switching to x25519 here, this is just an easy way to compute `a`"
    // crypto_sign_ed25519_sk_to_curve25519: SHA-512(seed)[0..32], clamped
    let ed_sk = expand_ed25519_privkey(seed)?;
    let hash: [u8; 64] = sha2::Sha512::digest(&ed_sk[..32]).into();
    let mut ka_scalar_bytes = [0u8; 32];
    ka_scalar_bytes.copy_from_slice(&hash[..32]);
    // Clamp
    ka_scalar_bytes[0] &= 248;
    ka_scalar_bytes[31] &= 127;
    ka_scalar_bytes[31] |= 64;

    let mut ka_scalar = Scalar::from_bytes_mod_order(ka_scalar_bytes);
    ka_scalar_bytes.zeroize();

    if blind25 {
        // Multiply a by k, so that we end up computing kajB = kjaB
        // Need to compute the blinding factor k
        let k = blind25_factor(server_pk, &ed_sk)?;
        let k_scalar = Scalar::from_bytes_mod_order(k);
        ka_scalar *= k_scalar;
    }
    // For 15 blinding, leave ka as just a (j=k so no double-blind needed)

    // Decompress jB as an Edwards point and perform scalar multiplication
    let j_b_arr: [u8; 32] = j_b_raw.try_into().unwrap();
    let j_b_compressed = CompressedEdwardsY(j_b_arr);
    let j_b_point = j_b_compressed.decompress().ok_or_else(|| {
        CryptoError::InvalidInput("Failed to decompress blinded pubkey".into())
    })?;

    let shared_point = (ka_scalar * j_b_point).compress();
    let shared_secret_raw = shared_point.to_bytes();

    if shared_secret_raw == [0u8; 32] {
        return Err(CryptoError::EncryptionFailed(
            "Shared secret generation failed".into(),
        ));
    }

    // H(shared_secret || sender || recipient)
    let (sender, recipient) = if sending {
        (k_a_raw, j_b_raw)
    } else {
        (j_b_raw, k_a_raw)
    };

    let hash_result = blake2b_hash(&[&shared_secret_raw, sender, recipient], 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash_result);
    Ok(result)
}

/// Computes the blind25 blinding factor `k` from the server pubkey and ed25519 secret key.
///
/// This is a simplified version that computes:
///   k = BLAKE2b(keyed="25Blind", server_pk || ed_pk)
/// reduced mod the Ed25519 group order.
fn blind25_factor(server_pk: &[u8], ed_sk: &[u8]) -> CryptoResult<[u8; 32]> {
    let ed_pk = if ed_sk.len() == 64 {
        &ed_sk[32..]
    } else {
        let (pk, _) = ed25519_key_pair_from_seed(ed_sk)?;
        return blind25_factor_with_pk(server_pk, &pk);
    };
    blind25_factor_with_pk(server_pk, ed_pk)
}

fn blind25_factor_with_pk(server_pk: &[u8], ed_pk: &[u8]) -> CryptoResult<[u8; 32]> {
    use curve25519_dalek::scalar::Scalar;

    // k = BLAKE2b-64(server_pk || ed_pk, key="25Blind") mod L
    let k_hash = blake2b_keyed_hash(&[server_pk, ed_pk], b"25Blind", 64);
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_hash);
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_wide);
    Ok(k_scalar.to_bytes())
}

/// Encrypts a message for a blinded recipient.
///
/// Uses XChaCha20-Poly1305 with a shared secret derived via the blinding scheme.
/// Format: `\x00 || ciphertext || nonce(24)`
///
/// The inner plaintext is `message || sender_ed_pk`.
pub fn encrypt_for_blinded_recipient(
    ed25519_privkey: &[u8],
    server_pk: &[u8],
    recipient_blinded_id: &[u8],
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    if ed25519_privkey.len() != 64 && ed25519_privkey.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid ed25519_privkey: expected 32 or 64 bytes".into(),
        ));
    }
    if server_pk.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid server_pk: expected 32 bytes".into(),
        ));
    }
    if recipient_blinded_id.len() != 33 {
        return Err(CryptoError::InvalidInput(
            "Invalid recipient_blinded_id: expected 33 bytes".into(),
        ));
    }

    let ed_sk = expand_ed25519_privkey(ed25519_privkey)?;

    // Generate our blinded keypair
    let blinded_pk = match recipient_blinded_id[0] {
        0x15 => blind15_key_pair_pk(&ed_sk, server_pk)?,
        0x25 => blind25_key_pair_pk(&ed_sk, server_pk)?,
        _ => {
            return Err(CryptoError::InvalidInput(
                "Invalid recipient_blinded_id: must start with 0x15 or 0x25".into(),
            ));
        }
    };

    // Build our blinded id (prefix + our blinded pk)
    let mut blinded_id = Vec::with_capacity(33);
    blinded_id.push(recipient_blinded_id[0]);
    blinded_id.extend_from_slice(&blinded_pk);

    let enc_key = blinded_shared_secret(
        ed25519_privkey,
        &blinded_id,
        recipient_blinded_id,
        server_pk,
        true,
    )?;

    // Inner data: msg || A (sender's ed25519 master pubkey)
    let sender_ed_pk = &ed_sk[32..];
    let mut buf = Vec::with_capacity(message.len() + 32);
    buf.extend_from_slice(message);
    buf.extend_from_slice(sender_ed_pk);

    // Encrypt using XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, buf.as_slice())
        .map_err(|e| CryptoError::EncryptionFailed(format!("Crypto aead encryption failed: {e}")))?;

    // Result: version_byte || ciphertext || nonce
    let mut result = Vec::with_capacity(1 + ct.len() + 24);
    result.push(BLINDED_ENCRYPT_VERSION);
    result.extend_from_slice(&ct);
    result.extend_from_slice(&nonce);

    Ok(result)
}

/// Compute blinded15 pubkey from ed25519 secret key and server pubkey.
fn blind15_key_pair_pk(ed_sk: &[u8; 64], server_pk: &[u8]) -> CryptoResult<[u8; 32]> {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;

    // blind15 factor: k = BLAKE2b-32(server_pk, key="15Blind") as a reduced scalar
    // Then: kA = k * A (the ed25519 pubkey)
    // But we need to handle sign-flipping for 15-blinding.

    // k = BLAKE2b-64(server_pk, key="15Blind") mod L
    let k_hash = blake2b_keyed_hash(&[server_pk], b"15Blind", 64);
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_hash);
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_wide);

    let ed_pk_bytes: [u8; 32] = ed_sk[32..].try_into().unwrap();
    let ed_pk_compressed = CompressedEdwardsY(ed_pk_bytes);
    let ed_pk_point: EdwardsPoint = ed_pk_compressed.decompress().ok_or_else(|| {
        CryptoError::KeyConversionFailed("Failed to decompress ed25519 pubkey".into())
    })?;

    let blinded_point = k_scalar * ed_pk_point;
    let blinded_pk = blinded_point.compress().to_bytes();

    // For 15-blinding, we ensure the sign is positive (bit 255 = 0)
    if blinded_pk[31] & 0x80 != 0 {
        // Negate
        let neg_point = -blinded_point;
        Ok(neg_point.compress().to_bytes())
    } else {
        Ok(blinded_pk)
    }
}

/// Compute blinded25 pubkey from ed25519 secret key and server pubkey.
fn blind25_key_pair_pk(ed_sk: &[u8; 64], server_pk: &[u8]) -> CryptoResult<[u8; 32]> {
    use curve25519_dalek::scalar::Scalar;

    let ed_pk_bytes: [u8; 32] = ed_sk[32..].try_into().unwrap();

    // k = BLAKE2b-64(server_pk || ed_pk, key="25Blind") mod L
    let k_hash = blake2b_keyed_hash(&[server_pk, &ed_pk_bytes], b"25Blind", 64);
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_hash);
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_wide);

    // Compute `a` from the seed: SHA-512(seed)[0..32], clamped
    let hash: [u8; 64] = sha2::Sha512::digest(&ed_sk[..32]).into();
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&hash[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a_scalar = Scalar::from_bytes_mod_order(a_bytes);

    // ka = k * a
    let ka_scalar = k_scalar * a_scalar;

    // kA = ka * G
    let blinded_point = curve25519_dalek::EdwardsPoint::mul_base(&ka_scalar);
    Ok(blinded_point.compress().to_bytes())
}

/// Compute blinded15 id from ed25519 pubkey and server pubkey.
fn blinded15_id_from_ed(ed_pk: &[u8], server_pk: &[u8]) -> CryptoResult<Vec<u8>> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let k_hash = blake2b_keyed_hash(&[server_pk], b"15Blind", 64);
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_hash);
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_wide);

    let ed_pk_arr: [u8; 32] = ed_pk.try_into().map_err(|_| {
        CryptoError::InvalidInput("ed_pk must be 32 bytes".into())
    })?;
    let ed_pk_compressed = CompressedEdwardsY(ed_pk_arr);
    let ed_pk_point = ed_pk_compressed.decompress().ok_or_else(|| {
        CryptoError::KeyConversionFailed("Failed to decompress ed25519 pubkey".into())
    })?;

    let blinded_point = k_scalar * ed_pk_point;
    let mut blinded_pk = blinded_point.compress().to_bytes();

    // Ensure sign bit is 0 for 15-blinding
    if blinded_pk[31] & 0x80 != 0 {
        let neg_point = -blinded_point;
        blinded_pk = neg_point.compress().to_bytes();
    }

    let mut result = Vec::with_capacity(33);
    result.push(0x15);
    result.extend_from_slice(&blinded_pk);
    Ok(result)
}

/// Compute blinded25 id from ed25519 pubkey and server pubkey.
fn blinded25_id_from_ed(ed_pk: &[u8], server_pk: &[u8]) -> CryptoResult<Vec<u8>> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let ed_pk_arr: [u8; 32] = ed_pk.try_into().map_err(|_| {
        CryptoError::InvalidInput("ed_pk must be 32 bytes".into())
    })?;

    // k = BLAKE2b-64(server_pk || ed_pk, key="25Blind") mod L
    let k_hash = blake2b_keyed_hash(&[server_pk, &ed_pk_arr], b"25Blind", 64);
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_hash);
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_wide);

    // For id_from_ed, we compute k * A (the pubkey point)
    // Since A = a*G, k*A = k*a*G, which equals the blind25 pubkey ka*G
    let ed_pk_compressed = CompressedEdwardsY(ed_pk_arr);
    let ed_pk_point = ed_pk_compressed.decompress().ok_or_else(|| {
        CryptoError::KeyConversionFailed("Failed to decompress ed25519 pubkey".into())
    })?;

    let blinded_point = k_scalar * ed_pk_point;
    let blinded_pk = blinded_point.compress().to_bytes();

    let mut result = Vec::with_capacity(33);
    result.push(0x25);
    result.extend_from_slice(&blinded_pk);
    Ok(result)
}

// ---------------------------------------------------------------------------
// encrypt_for_group
// ---------------------------------------------------------------------------

/// Encrypts a message for a group.
///
/// The inner format is a bencoded dict:
/// ```text
/// d
///   "" = 1            (version)
///   "a" = sender_ed_pk (32 bytes)
///   "d" = plaintext   (if uncompressed)
///   "s" = signature   (64 bytes, signs plaintext || group_ed25519_pubkey)
///   "z" = compressed  (if compressed)
/// e
/// ```
///
/// Then XChaCha20-Poly1305 encrypted with the group key.
/// Output format: `nonce(24) || ciphertext`.
pub fn encrypt_for_group(
    user_ed25519_privkey: &[u8],
    group_ed25519_pubkey: &[u8],
    group_enc_key: &[u8],
    plaintext: &[u8],
    compress: bool,
    padding: usize,
) -> CryptoResult<Vec<u8>> {
    if plaintext.len() > GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE {
        return Err(CryptoError::EncryptionFailed(
            "Cannot encrypt plaintext: message size is too large".into(),
        ));
    }

    let ed_sk = expand_ed25519_privkey(user_ed25519_privkey)?;

    if group_enc_key.len() != 32 && group_enc_key.len() != 64 {
        return Err(CryptoError::InvalidInput(
            "Invalid group_enc_key: expected 32 or 64 bytes".into(),
        ));
    }
    if group_ed25519_pubkey.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid group_ed25519_pubkey: expected 32 bytes".into(),
        ));
    }

    let sender_ed_pk = &ed_sk[32..];

    // Try compression
    let mut use_compressed = compress;
    let compressed_data;
    let actual_plaintext = if compress {
        compressed_data = crate::util::zstd_compress::compress(plaintext, 1, &[]);
        if compressed_data.len() < plaintext.len() {
            &compressed_data
        } else {
            use_compressed = false;
            plaintext
        }
    } else {
        plaintext
    };

    // Build the bencoded dict
    let mut dict = BTreeMap::new();
    // "" = 1 (version)
    dict.insert(b"".to_vec(), crate::util::bencode::BtValue::Integer(1));
    // "a" = sender ed pubkey
    dict.insert(
        b"a".to_vec(),
        crate::util::bencode::BtValue::String(sender_ed_pk.to_vec()),
    );

    if !use_compressed {
        // "d" = plaintext data
        dict.insert(
            b"d".to_vec(),
            crate::util::bencode::BtValue::String(actual_plaintext.to_vec()),
        );
    }

    // Sign: plaintext || group_ed25519_pubkey
    let mut to_sign = Vec::with_capacity(actual_plaintext.len() + 32);
    to_sign.extend_from_slice(actual_plaintext);
    to_sign.extend_from_slice(group_ed25519_pubkey);

    let seed: [u8; 32] = ed_sk[..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed);
    let sig = signing_key.sign(&to_sign);
    dict.insert(
        b"s".to_vec(),
        crate::util::bencode::BtValue::String(sig.to_bytes().to_vec()),
    );

    if use_compressed {
        // "z" = compressed data
        dict.insert(
            b"z".to_vec(),
            crate::util::bencode::BtValue::String(actual_plaintext.to_vec()),
        );
    }

    let mut encoded = crate::util::bencode::encode(&crate::util::bencode::BtValue::Dict(dict));

    // Apply padding
    let final_len = GROUPS_ENCRYPT_OVERHEAD + encoded.len();
    if padding > 1 && !final_len.is_multiple_of(padding) {
        let to_append = padding - (final_len % padding);
        encoded.resize(encoded.len() + to_append, 0);
    }

    // Encrypt with XChaCha20-Poly1305
    let key: [u8; 32] = group_enc_key[..32].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, encoded.as_slice())
        .map_err(|e| CryptoError::EncryptionFailed(format!("Encryption failed: {e}")))?;

    // Output: nonce || ciphertext
    let mut result = Vec::with_capacity(24 + ct.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ct);
    Ok(result)
}

// ---------------------------------------------------------------------------
// decrypt_incoming
// ---------------------------------------------------------------------------

/// Decrypts an incoming sealed-box message, returning the plaintext and the
/// sender's ed25519 pubkey (32 bytes).
///
/// Uses the ed25519 private key to derive X25519 keys for unsealing.
pub fn decrypt_incoming(
    ed25519_privkey: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let ed_sk = expand_ed25519_privkey(ed25519_privkey)?;

    let x_sec = to_curve25519_seckey(&ed_sk)?;
    let x_pub_sk = X25519SecretKey::from(x_sec);
    let x_pub = X25519PublicKey::from(&x_pub_sk);

    decrypt_incoming_x25519(x_pub.as_bytes(), &x_sec, ciphertext)
}

/// Decrypts an incoming sealed-box message using X25519 keys directly.
///
/// Returns (plaintext, sender_ed25519_pubkey).
pub fn decrypt_incoming_x25519(
    x25519_pubkey: &[u8],
    x25519_seckey: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    // crypto_box_SEALBYTES = 48 (32 eph_pk + 16 MAC)
    const SEAL_BYTES: usize = 48;

    if ciphertext.len() < SEAL_BYTES + 32 + 64 {
        return Err(CryptoError::DecryptionFailed(
            "Invalid incoming message: ciphertext is too small".into(),
        ));
    }

    let outer_size = ciphertext.len() - SEAL_BYTES;
    let msg_size = outer_size - 32 - 64;

    // Unseal using crypto_box
    let pk_arr: [u8; 32] = x25519_pubkey[..32].try_into().unwrap();
    let sk_arr: [u8; 32] = x25519_seckey[..32].try_into().unwrap();

    let _box_pk = crypto_box::PublicKey::from(pk_arr);
    let box_sk = crypto_box::SecretKey::from(sk_arr);

    let buf = box_sk
        .unseal(ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))?;

    if buf.len() != outer_size {
        return Err(CryptoError::DecryptionFailed(
            "Unexpected decrypted size".into(),
        ));
    }

    // buf = M || A(32) || SIG(64)
    let sender_ed_pk = buf[msg_size..msg_size + 32].to_vec();
    let sig_bytes: [u8; 64] = buf[msg_size + 32..msg_size + 32 + 64].try_into().unwrap();

    // Reconstruct M || A || Y for signature verification
    let mut to_verify = Vec::with_capacity(msg_size + 32 + 32);
    to_verify.extend_from_slice(&buf[..msg_size]);
    to_verify.extend_from_slice(&sender_ed_pk);
    to_verify.extend_from_slice(x25519_pubkey);

    // Verify signature
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let pk_arr: [u8; 32] = sender_ed_pk[..32].try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| CryptoError::DecryptionFailed("Invalid sender pubkey".into()))?;
    verifying_key
        .verify(&to_verify, &sig)
        .map_err(|_| CryptoError::DecryptionFailed("Signature verification failed".into()))?;

    // Return just the message
    let plaintext = buf[..msg_size].to_vec();
    Ok((plaintext, sender_ed_pk))
}

// ---------------------------------------------------------------------------
// decrypt_incoming_session_id
// ---------------------------------------------------------------------------

/// Decrypts an incoming message and returns the sender's Session ID (hex string).
///
/// Calls `decrypt_incoming` and converts the sender's ed25519 pubkey to a
/// Session ID with "05" prefix.
pub fn decrypt_incoming_session_id(
    ed25519_privkey: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<(Vec<u8>, String)> {
    let (buf, sender_ed_pk) = decrypt_incoming(ed25519_privkey, ciphertext)?;

    let ed_pk_arr: [u8; 32] = sender_ed_pk[..32].try_into().unwrap();
    let sender_x_pk = to_curve25519_pubkey(&ed_pk_arr)?;

    let mut session_id = String::with_capacity(66);
    session_id.push_str("05");
    session_id.push_str(&hex::encode(sender_x_pk));
    Ok((buf, session_id))
}

/// Decrypts an incoming message using X25519 keys and returns the sender's Session ID.
pub fn decrypt_incoming_session_id_x25519(
    x25519_pubkey: &[u8],
    x25519_seckey: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<(Vec<u8>, String)> {
    let (buf, sender_ed_pk) = decrypt_incoming_x25519(x25519_pubkey, x25519_seckey, ciphertext)?;

    let ed_pk_arr: [u8; 32] = sender_ed_pk[..32].try_into().unwrap();
    let sender_x_pk = to_curve25519_pubkey(&ed_pk_arr)?;

    let mut session_id = String::with_capacity(66);
    session_id.push_str("05");
    session_id.push_str(&hex::encode(sender_x_pk));
    Ok((buf, session_id))
}

// ---------------------------------------------------------------------------
// decrypt_from_blinded_recipient
// ---------------------------------------------------------------------------

/// Decrypts a blinded message and returns the plaintext and sender's Session ID.
pub fn decrypt_from_blinded_recipient(
    ed25519_privkey: &[u8],
    server_pk: &[u8],
    sender_id: &[u8],
    recipient_id: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<(Vec<u8>, String)> {
    let ed_sk = expand_ed25519_privkey(ed25519_privkey)?;
    let ed_pk_from_seed: [u8; 32] = ed_sk[32..].try_into().unwrap();

    if ciphertext.len() < 24 + 1 + 16 {
        return Err(CryptoError::InvalidInput(
            "Invalid ciphertext: too short to contain valid encrypted data".into(),
        ));
    }

    // Compute our blinded id to determine if we are sender or receiver
    let blinded_id = if recipient_id[0] == 0x25 {
        blinded25_id_from_ed(&ed_pk_from_seed, server_pk)?
    } else {
        blinded15_id_from_ed(&ed_pk_from_seed, server_pk)?
    };

    let dec_key = if sender_id == blinded_id.as_slice() {
        blinded_shared_secret(ed25519_privkey, sender_id, recipient_id, server_pk, true)?
    } else {
        blinded_shared_secret(ed25519_privkey, recipient_id, sender_id, server_pk, false)?
    };

    // v, ct, nc = data[0], data[1:-24], data[-24:]
    if ciphertext[0] != BLINDED_ENCRYPT_VERSION {
        return Err(CryptoError::DecryptionFailed(format!(
            "Invalid ciphertext: version is not {}",
            BLINDED_ENCRYPT_VERSION
        )));
    }

    let nonce_start = ciphertext.len() - 24;
    let ct_data = &ciphertext[1..nonce_start];
    let nonce_bytes: [u8; 24] = ciphertext[nonce_start..].try_into().unwrap();
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new((&dec_key).into());
    let buf = cipher
        .decrypt(&nonce, ct_data)
        .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".into()))?;

    if buf.len() < 32 {
        return Err(CryptoError::DecryptionFailed(
            "Invalid ciphertext: innerBytes too short".into(),
        ));
    }

    // Split: last 32 bytes are sender's unblinded ed25519 key
    let msg_len = buf.len() - 32;
    let sender_ed_pk: [u8; 32] = buf[msg_len..].try_into().unwrap();

    // Convert sender_ed_pk to session ID
    let sender_x_pk = to_curve25519_pubkey(&sender_ed_pk)?;

    // Verify that the inner sender_ed_pk yields the same outer blinded ID
    let extracted_sender = if recipient_id[0] == 0x25 {
        blinded25_id_from_ed(&sender_ed_pk, server_pk)?
    } else {
        blinded15_id_from_ed(&sender_ed_pk, server_pk)?
    };

    let mut matched = sender_id == extracted_sender.as_slice();
    if !matched && extracted_sender[0] == 0x15 {
        // With 15-blinding we might need the negative
        let mut flipped = extracted_sender.clone();
        flipped[32] ^= 0x80; // last byte of the 32-byte key (index 32 in the 33-byte array)
        matched = sender_id == flipped.as_slice();
    }
    if !matched {
        return Err(CryptoError::DecryptionFailed(
            "Blinded sender id does not match the actual sender".into(),
        ));
    }

    let plaintext = buf[..msg_len].to_vec();
    let mut session_id = String::with_capacity(66);
    session_id.push_str("05");
    session_id.push_str(&hex::encode(sender_x_pk));

    Ok((plaintext, session_id))
}

// ---------------------------------------------------------------------------
// decrypt_group_message
// ---------------------------------------------------------------------------

/// Decrypts a group message, trying multiple keys.
///
/// The ciphertext format is `nonce(24) || encrypted_data`.
/// The decrypted data is a bencoded dict containing the message, signature, and sender info.
///
/// Returns a `DecryptGroupMessage` with the key index that worked, sender session ID,
/// and decrypted plaintext.
pub fn decrypt_group_message(
    decrypt_keys: &[&[u8]],
    group_ed25519_pubkey: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<DecryptGroupMessage> {
    if ciphertext.len() < GROUPS_ENCRYPT_OVERHEAD {
        return Err(CryptoError::DecryptionFailed(
            "ciphertext is too small to be encrypted data".into(),
        ));
    }
    if group_ed25519_pubkey.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid group_ed25519_pubkey: expected 32 bytes".into(),
        ));
    }

    let nonce_bytes: [u8; 24] = ciphertext[..24].try_into().unwrap();
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ct_data = &ciphertext[24..];

    let mut plain = None;
    let mut found_index = 0usize;

    for (index, key) in decrypt_keys.iter().enumerate() {
        if key.len() != 32 && key.len() != 64 {
            return Err(CryptoError::InvalidInput(
                "Invalid decrypt_ed25519_privkey: expected 32 or 64 bytes".into(),
            ));
        }
        let key_arr: [u8; 32] = key[..32].try_into().unwrap();
        let cipher = XChaCha20Poly1305::new((&key_arr).into());
        if let Ok(decrypted) = cipher.decrypt(&nonce, ct_data) {
            found_index = index;
            plain = Some(decrypted);
            break;
        }
    }

    let mut plain = plain.ok_or_else(|| {
        CryptoError::DecryptionFailed(
            "unable to decrypt ciphertext with any current group keys".into(),
        )
    })?;

    // Remove null padding bytes from the end
    if let Some(pos) = plain.iter().rposition(|&c| c != 0) {
        plain.truncate(pos + 1);
    }

    // Must be a bencoded dict
    if plain.is_empty() || plain[0] != b'd' || plain[plain.len() - 1] != b'e' {
        return Err(CryptoError::DecryptionFailed(
            "decrypted data is not a bencoded dict".into(),
        ));
    }

    // Parse the bencoded dict
    let bt_val = crate::util::bencode::decode(&plain)
        .map_err(|e| CryptoError::DecryptionFailed(format!("bencode decode failed: {e}")))?;

    let dict = match bt_val {
        crate::util::bencode::BtValue::Dict(d) => d,
        _ => {
            return Err(CryptoError::DecryptionFailed(
                "decrypted data is not a bencoded dict".into(),
            ))
        }
    };

    // Check version
    if let Some(crate::util::bencode::BtValue::Integer(v)) = dict.get(b"".as_slice()) {
        if *v != 1 {
            return Err(CryptoError::DecryptionFailed(format!(
                "group message version tag ({v}) is not compatible (we support v1)"
            )));
        }
    } else {
        return Err(CryptoError::DecryptionFailed(
            "group message version tag (\"\") is missing".into(),
        ));
    }

    // Get author pubkey "a"
    let ed_pk = match dict.get(b"a".as_slice()) {
        Some(crate::util::bencode::BtValue::String(s)) if s.len() == 32 => s.clone(),
        Some(crate::util::bencode::BtValue::String(s)) => {
            return Err(CryptoError::DecryptionFailed(format!(
                "message author pubkey size ({}) is invalid",
                s.len()
            )));
        }
        _ => {
            return Err(CryptoError::DecryptionFailed(
                "missing message author pubkey".into(),
            ))
        }
    };

    // Convert to session ID
    let ed_pk_arr: [u8; 32] = ed_pk[..32].try_into().unwrap();
    let x_pk = to_curve25519_pubkey(&ed_pk_arr).map_err(|_| {
        CryptoError::DecryptionFailed(
            "author ed25519 pubkey is invalid (unable to convert it to a session id)".into(),
        )
    })?;

    let mut session_id = String::with_capacity(66);
    session_id.push_str("05");
    session_id.push_str(&hex::encode(x_pk));

    // Get data (uncompressed "d" or compressed "z")
    let raw_data;
    let compressed;

    if let Some(crate::util::bencode::BtValue::String(d)) = dict.get(b"d".as_slice()) {
        if d.is_empty() {
            return Err(CryptoError::DecryptionFailed(
                "uncompressed message data (\"d\") cannot be empty".into(),
            ));
        }
        raw_data = d.clone();
        compressed = false;
    } else if let Some(crate::util::bencode::BtValue::String(z)) = dict.get(b"z".as_slice()) {
        if z.is_empty() {
            return Err(CryptoError::DecryptionFailed(
                "compressed message data (\"z\") cannot be empty".into(),
            ));
        }
        raw_data = z.clone();
        compressed = true;
    } else {
        return Err(CryptoError::DecryptionFailed(
            "message must contain compressed (z) or uncompressed (d) data".into(),
        ));
    }

    // Get signature "s"
    let sig_bytes = match dict.get(b"s".as_slice()) {
        Some(crate::util::bencode::BtValue::String(s)) if s.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(s);
            arr
        }
        Some(crate::util::bencode::BtValue::String(s)) => {
            return Err(CryptoError::DecryptionFailed(format!(
                "message signature size ({}) is invalid",
                s.len()
            )));
        }
        _ => {
            return Err(CryptoError::DecryptionFailed(
                "message signature is missing".into(),
            ))
        }
    };

    // Verify signature over raw_data || group_ed25519_pubkey
    let mut to_verify = Vec::with_capacity(raw_data.len() + 32);
    to_verify.extend_from_slice(&raw_data);
    to_verify.extend_from_slice(group_ed25519_pubkey);

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let verifying_key = VerifyingKey::from_bytes(&ed_pk_arr)
        .map_err(|_| CryptoError::DecryptionFailed("Invalid author pubkey".into()))?;
    verifying_key
        .verify(&to_verify, &sig)
        .map_err(|_| CryptoError::DecryptionFailed("message signature failed validation".into()))?;

    let data = if compressed {
        crate::util::zstd_compress::decompress(&raw_data, GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE)
            .ok_or_else(|| {
                CryptoError::DecryptionFailed("message decompression failed".into())
            })?
    } else {
        raw_data
    };

    // Check that we don't have both "d" and "z"
    if !compressed
        && dict.contains_key(b"z".as_slice())
    {
        return Err(CryptoError::DecryptionFailed(
            "message signature cannot contain both compressed (z) and uncompressed (d) data".into(),
        ));
    }

    Ok(DecryptGroupMessage {
        index: found_index,
        session_id,
        data,
    })
}

// ---------------------------------------------------------------------------
// decrypt_ons_response
// ---------------------------------------------------------------------------

/// Decrypts an ONS (Oxen Name System) response.
///
/// Two modes:
/// - **Old (pre-HF16)**: `nonce` is `None`, uses Argon2id key derivation + crypto_secretbox
///   (XSalsa20-Poly1305)
/// - **New**: `nonce` is provided, uses BLAKE2b key derivation + XChaCha20-Poly1305
///
/// Returns the Session ID as a hex string.
pub fn decrypt_ons_response(
    lowercase_name: &str,
    ciphertext: &[u8],
    nonce: Option<&[u8]>,
) -> CryptoResult<String> {
    match nonce {
        None => {
            // Old Argon2-based encryption
            // crypto_secretbox_MACBYTES = 16
            if ciphertext.len() < 16 {
                return Err(CryptoError::InvalidInput(
                    "Invalid ciphertext: expected to be greater than 16 bytes".into(),
                ));
            }

            // Key derivation: Argon2id with zero salt
            let salt = [0u8; 16]; // crypto_pwhash_SALTBYTES = 16
            let mut key = [0u8; 32];

            // crypto_pwhash_OPSLIMIT_MODERATE = 3, crypto_pwhash_MEMLIMIT_MODERATE = 256MB
            let params = argon2::Params::new(256 * 1024, 3, 1, Some(32))
                .map_err(|e| CryptoError::DecryptionFailed(format!("Failed to create Argon2 params: {e}")))?;
            let argon2_ctx = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            argon2_ctx
                .hash_password_into(lowercase_name.as_bytes(), &salt, &mut key)
                .map_err(|e| {
                    CryptoError::DecryptionFailed(format!("Failed to generate key: {e}"))
                })?;

            // Decrypt with crypto_secretbox (XSalsa20-Poly1305), nonce = zeros
            let secretbox_nonce = [0u8; 24]; // crypto_secretbox_NONCEBYTES = 24
            let secretbox_key = crypto_secretbox::Key::from(key);
            let secretbox_nonce = crypto_secretbox::Nonce::from(secretbox_nonce);

            let plaintext = crypto_secretbox::XSalsa20Poly1305::new(&secretbox_key)
                .decrypt(&secretbox_nonce, ciphertext)
                .map_err(|_| CryptoError::DecryptionFailed("Failed to decrypt".into()))?;

            Ok(hex::encode(plaintext))
        }
        Some(nonce_data) => {
            // New xchacha-based encryption
            if ciphertext.len() < 16 {
                // crypto_aead_xchacha20poly1305_ietf_ABYTES = 16
                return Err(CryptoError::InvalidInput(
                    "Invalid ciphertext: expected to be greater than 16 bytes".into(),
                ));
            }
            if nonce_data.len() != 24 {
                return Err(CryptoError::InvalidInput(
                    "Invalid nonce: expected to be 24 bytes".into(),
                ));
            }

            // key = H(name, key=H(name))
            let name_bytes = lowercase_name.as_bytes();
            let name_hash = blake2b_hash(&[name_bytes], 32);
            let key_bytes = blake2b_keyed_hash(&[name_bytes], &name_hash, 32);

            let key: [u8; 32] = key_bytes[..32].try_into().unwrap();
            let nonce: [u8; 24] = nonce_data[..24].try_into().unwrap();

            let cipher = XChaCha20Poly1305::new((&key).into());
            let nonce = chacha20poly1305::XNonce::from(nonce);
            let buf = cipher
                .decrypt(&nonce, ciphertext)
                .map_err(|_| CryptoError::DecryptionFailed("Failed to decrypt".into()))?;

            if buf.len() != 33 {
                return Err(CryptoError::DecryptionFailed(
                    "Invalid decrypted value: expected to be 33 bytes".into(),
                ));
            }

            Ok(hex::encode(buf))
        }
    }
}

// ---------------------------------------------------------------------------
// decrypt_push_notification
// ---------------------------------------------------------------------------

/// Decrypts a push notification payload.
///
/// Format: `nonce(24) || ciphertext` using XChaCha20-Poly1305.
/// Trailing null bytes are stripped from the decrypted result.
pub fn decrypt_push_notification(payload: &[u8], enc_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if payload.len() < 24 + 16 {
        return Err(CryptoError::InvalidInput(
            "Invalid payload: too short to contain valid encrypted data".into(),
        ));
    }
    if enc_key.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid enc_key: expected 32 bytes".into(),
        ));
    }

    let nonce_bytes: [u8; 24] = payload[..24].try_into().unwrap();
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ct_data = &payload[24..];

    let key: [u8; 32] = enc_key[..32].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut buf = cipher
        .decrypt(&nonce, ct_data)
        .map_err(|_| {
            CryptoError::DecryptionFailed(
                "Failed to decrypt; perhaps the secret key is invalid?".into(),
            )
        })?;

    // Remove trailing null bytes
    if let Some(pos) = buf.iter().rposition(|&c| c != 0) {
        buf.truncate(pos + 1);
    }

    Ok(buf)
}

// ---------------------------------------------------------------------------
// encrypt_xchacha20 / decrypt_xchacha20
// ---------------------------------------------------------------------------

/// Encrypts data with XChaCha20-Poly1305, prepending a random 24-byte nonce.
///
/// Output format: `nonce(24) || ciphertext(input_len + 16)`.
pub fn encrypt_xchacha20(plaintext: &[u8], enc_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if enc_key.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid enc_key: expected 32 bytes".into(),
        ));
    }

    let key: [u8; 32] = enc_key[..32].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("XChaCha20-Poly1305 encrypt failed: {e}")))?;

    let mut result = Vec::with_capacity(24 + ct.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ct);
    Ok(result)
}

/// Decrypts data encrypted with `encrypt_xchacha20`.
///
/// Input format: `nonce(24) || ciphertext`.
pub fn decrypt_xchacha20(ciphertext: &[u8], enc_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if ciphertext.len() < 24 + 16 {
        return Err(CryptoError::InvalidInput(
            "Invalid ciphertext: too short to contain valid encrypted data".into(),
        ));
    }
    if enc_key.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Invalid enc_key: expected 32 bytes".into(),
        ));
    }

    let nonce_bytes: [u8; 24] = ciphertext[..24].try_into().unwrap();
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ct_data = &ciphertext[24..];

    let key: [u8; 32] = enc_key[..32].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new((&key).into());
    let buf = cipher
        .decrypt(&nonce, ct_data)
        .map_err(|_| {
            CryptoError::DecryptionFailed("Could not decrypt (XChaCha20-Poly1305)".into())
        })?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// compute_hash_blake2b_b64
// ---------------------------------------------------------------------------

/// Computes a multi-part BLAKE2b-256 hash and returns it as unpadded base64.
pub fn compute_hash_blake2b_b64(parts: &[&str]) -> String {
    let mut state = blake2b_simd::Params::new();
    state.hash_length(32);
    let mut st = state.to_state();
    for part in parts {
        st.update(part.as_bytes());
    }
    let hash = st.finalize();

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&hash.as_bytes()[..32]);
    // Trim padding
    b64.trim_end_matches('=').to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // Test setup: derive keys from seeds matching the C++ test vectors
    fn setup_keys() -> (
        [u8; 32],  // ed_pk
        [u8; 64],  // ed_sk
        [u8; 32],  // curve_pk
        [u8; 32],  // ed_pk2
        [u8; 64],  // ed_sk2
        [u8; 32],  // curve_pk2
    ) {
        let seed = hex_to_bytes("0123456789abcdef0123456789abcdef00000000000000000000000000000000");
        let (ed_pk, ed_sk) = ed25519_key_pair_from_seed(&seed).unwrap();
        let curve_pk = to_curve25519_pubkey(&ed_pk).unwrap();

        assert_eq!(
            hex::encode(ed_pk),
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"
        );
        assert_eq!(
            hex::encode(curve_pk),
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );

        let seed2 = hex_to_bytes("00112233445566778899aabbccddeeff00000000000000000000000000000000");
        let (ed_pk2, ed_sk2) = ed25519_key_pair_from_seed(&seed2).unwrap();
        let curve_pk2 = to_curve25519_pubkey(&ed_pk2).unwrap();

        assert_eq!(
            hex::encode(ed_pk2),
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"
        );
        assert_eq!(
            hex::encode(curve_pk2),
            "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"
        );

        (ed_pk, ed_sk, curve_pk, ed_pk2, ed_sk2, curve_pk2)
    }

    fn make_sid(curve_pk: &[u8; 32]) -> Vec<u8> {
        let mut sid = vec![0x05];
        sid.extend_from_slice(curve_pk);
        sid
    }

    #[test]
    fn test_encrypt_decrypt_full_secret_prefixed_sid() {
        let (ed_pk, ed_sk, _curve_pk, _ed_pk2, ed_sk2, curve_pk2) = setup_keys();
        let sid_raw2 = make_sid(&curve_pk2);

        let enc = encrypt_for_recipient(&ed_sk, &sid_raw2, b"hello").unwrap();
        assert_ne!(enc, b"hello");

        // Wrong key should fail
        assert!(decrypt_incoming(&ed_sk, &enc).is_err());

        // Right key should work
        let (msg, sender) = decrypt_incoming(&ed_sk2, &enc).unwrap();
        assert_eq!(hex::encode(&sender), hex::encode(ed_pk));
        assert_eq!(msg, b"hello");

        // Tampered ciphertext should fail
        let mut broken = enc.clone();
        broken[2] ^= 0x02;
        assert!(decrypt_incoming(&ed_sk2, &broken).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_seed_only_unprefixed_sid() {
        let (ed_pk, ed_sk, _curve_pk, _ed_pk2, ed_sk2, curve_pk2) = setup_keys();

        let lorem_ipsum =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor \
             incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis \
             nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. \
             Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu \
             fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in \
             culpa qui officia deserunt mollit anim id est laborum.";

        // Use only seed (first 32 bytes) and unprefixed pubkey
        let enc = encrypt_for_recipient(&ed_sk[..32], &curve_pk2, lorem_ipsum.as_bytes()).unwrap();

        // Ensure plaintext is not visible
        assert!(!enc.windows(12).any(|w| w == b"dolore magna"));

        // Wrong key
        assert!(decrypt_incoming(&ed_sk, &enc).is_err());

        // Right key
        let (msg, sender) = decrypt_incoming(&ed_sk2, &enc).unwrap();
        assert_eq!(hex::encode(&sender), hex::encode(ed_pk));
        assert_eq!(std::str::from_utf8(&msg).unwrap(), lorem_ipsum);

        // Tampered
        let mut broken = enc.clone();
        broken[14] ^= 0x80;
        assert!(decrypt_incoming(&ed_sk2, &broken).is_err());
    }

    #[test]
    fn test_deterministic_encryption() {
        let (_ed_pk, ed_sk, _curve_pk, _ed_pk2, ed_sk2, curve_pk2) = setup_keys();
        let sid_raw2 = make_sid(&curve_pk2);

        // Non-deterministic should produce different ciphertexts
        let enc1 = encrypt_for_recipient(&ed_sk, &sid_raw2, b"hello").unwrap();
        let enc2 = encrypt_for_recipient(&ed_sk, &sid_raw2, b"hello").unwrap();
        assert_ne!(enc1, enc2);

        // Deterministic should produce the same ciphertext each time
        let enc_det =
            encrypt_for_recipient_deterministic(&ed_sk, &sid_raw2, b"hello").unwrap();
        let enc_det2 =
            encrypt_for_recipient_deterministic(&ed_sk, &sid_raw2, b"hello").unwrap();
        assert_eq!(enc_det, enc_det2);
        assert_ne!(enc_det, enc1);
        assert_eq!(enc_det.len(), enc1.len());

        // Check exact deterministic output
        assert_eq!(
            hex::encode(&enc_det),
            "208f96785db92319bc7a14afecc01e17bde912d17bbb32834c03ea63b1862c2a\
             1b730e0725ef75b2f1a276db584c59a0ed9b5497bcb9f4effa893b5cb8b04dbe\
             7a6ab457ebf972f03b006dd4572980a725399616d40184b86aa3b7b218bdc6dd\
             7c1adccda8ef4897f0f458492240b39079c27a6c791067ab26a03067a7602b50\
             f0434639906f93e548f909d5286edde365ebddc146"
        );

        // Should decrypt correctly
        let (msg, sender) = decrypt_incoming(&ed_sk2, &enc_det).unwrap();
        assert_eq!(
            hex::encode(&sender),
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"
        );
        assert_eq!(msg, b"hello");
    }

    #[test]
    fn test_decrypt_incoming_session_id() {
        let (_ed_pk, ed_sk, _curve_pk, _ed_pk2, ed_sk2, curve_pk2) = setup_keys();
        let sid_raw2 = make_sid(&curve_pk2);

        let enc = encrypt_for_recipient(&ed_sk, &sid_raw2, b"hello").unwrap();
        let (msg, session_id) = decrypt_incoming_session_id(&ed_sk2, &enc).unwrap();
        assert_eq!(msg, b"hello");
        assert_eq!(
            session_id,
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );
    }

    #[test]
    fn test_decrypt_ons_response_new() {
        let ciphertext = hex_to_bytes(
            "3575802dd9bfea72672a208840f37ca289ceade5d3ffacabe2d231f109d204329fc33e28c33\
             1580d9a8c9b8a64cacfec97",
        );
        let nonce = hex_to_bytes("00112233445566778899aabbccddeeff00ffeeddccbbaa99");

        let result = decrypt_ons_response("test", &ciphertext, Some(&nonce)).unwrap();
        assert_eq!(
            result,
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );
    }

    #[test]
    fn test_decrypt_ons_response_legacy() {
        let ciphertext = hex_to_bytes(
            "dbd4bc89bd2c9e5322fd9f4cadcaa66a0c38f15d0c927a86cc36e895fe1f3c532a3958d972563f52ca858e94eec22dc360",
        );

        let result = decrypt_ons_response("test", &ciphertext, None).unwrap();
        assert_eq!(
            result,
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );
    }

    #[test]
    fn test_decrypt_ons_invalid() {
        let nonce = hex_to_bytes("00112233445566778899aabbccddeeff00ffeeddccbbaa99");
        assert!(decrypt_ons_response("test", b"invalid", Some(&nonce)).is_err());

        let ciphertext = hex_to_bytes(
            "3575802dd9bfea72672a208840f37ca289ceade5d3ffacabe2d231f109d204329fc33e28c33\
             1580d9a8c9b8a64cacfec97",
        );
        assert!(decrypt_ons_response("test", &ciphertext, Some(b"invalid")).is_err());
    }

    #[test]
    fn test_decrypt_push_notification() {
        let payload = hex_to_bytes(
            "00112233445566778899aabbccddeeff00ffeeddccbbaa991bcba42892762dbeecbfb1a375f\
             ab4aca5f0991e99eb0344ceeafa",
        );
        let enc_key =
            hex_to_bytes("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");

        let result = decrypt_push_notification(&payload, &enc_key).unwrap();
        assert_eq!(result, b"TestMessage");
    }

    #[test]
    fn test_decrypt_push_notification_invalid() {
        let enc_key =
            hex_to_bytes("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");
        assert!(decrypt_push_notification(b"invalid", &enc_key).is_err());

        let payload = hex_to_bytes(
            "00112233445566778899aabbccddeeff00ffeeddccbbaa991bcba42892762dbeecbfb1a375f\
             ab4aca5f0991e99eb0344ceeafa",
        );
        assert!(decrypt_push_notification(&payload, b"invalid").is_err());
    }

    #[test]
    fn test_xchacha20_decrypt_known() {
        let payload = hex_to_bytes(
            "da74ac6e96afda1c5a07d5bde1b8b1e1c05be73cb3c84112f31f00369d67154d\
             00ff029090b069b48c3cf603d838d4ef623d54",
        );
        let enc_key =
            hex_to_bytes("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");

        let result = decrypt_xchacha20(&payload, &enc_key).unwrap();
        assert_eq!(result, b"TestMessage");
    }

    #[test]
    fn test_xchacha20_roundtrip() {
        let enc_key =
            hex_to_bytes("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");

        let ciphertext = encrypt_xchacha20(b"TestMessage", &enc_key).unwrap();
        let plaintext = decrypt_xchacha20(&ciphertext, &enc_key).unwrap();
        assert_eq!(plaintext, b"TestMessage");
    }

    #[test]
    fn test_xchacha20_invalid() {
        let enc_key =
            hex_to_bytes("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");
        assert!(decrypt_xchacha20(b"invalid", &enc_key).is_err());
        assert!(decrypt_xchacha20(
            &hex_to_bytes(
                "da74ac6e96afda1c5a07d5bde1b8b1e1c05be73cb3c84112f31f00369d67154d\
                 00ff029090b069b48c3cf603d838d4ef623d54"
            ),
            b"invalid"
        )
        .is_err());
        assert!(encrypt_xchacha20(b"test", b"invalid").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_group_roundtrip() {
        let seed = hex_to_bytes(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
        );
        let (_, ed_sk) = ed25519_key_pair_from_seed(&seed).unwrap();

        // Use a separate group key pair
        let group_seed = hex_to_bytes(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        );
        let (group_pk, _group_sk) = ed25519_key_pair_from_seed(&group_seed).unwrap();
        let group_enc_key =
            hex_to_bytes("fedcba9876543210fedcba98765432100123456789abcdef0123456789abcdef");

        let plaintext = b"Hello, group!";
        let ciphertext = encrypt_for_group(
            &ed_sk,
            &group_pk,
            &group_enc_key,
            plaintext,
            false,
            256,
        )
        .unwrap();

        let keys: Vec<&[u8]> = vec![&group_enc_key];
        let result = decrypt_group_message(&keys, &group_pk, &ciphertext).unwrap();
        assert_eq!(result.data, plaintext);
        assert_eq!(result.index, 0);
        // The session ID should be derived from the sender's ed25519 key
        assert!(result.session_id.starts_with("05"));
    }

    #[test]
    fn test_encrypt_decrypt_group_compressed() {
        let seed = hex_to_bytes(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
        );
        let (_, ed_sk) = ed25519_key_pair_from_seed(&seed).unwrap();

        let group_seed = hex_to_bytes(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        );
        let (group_pk, _) = ed25519_key_pair_from_seed(&group_seed).unwrap();
        let group_enc_key =
            hex_to_bytes("fedcba9876543210fedcba98765432100123456789abcdef0123456789abcdef");

        // Create something compressible
        let plaintext = "Hello! ".repeat(100);
        let ciphertext = encrypt_for_group(
            &ed_sk,
            &group_pk,
            &group_enc_key,
            plaintext.as_bytes(),
            true,
            256,
        )
        .unwrap();

        let keys: Vec<&[u8]> = vec![&group_enc_key];
        let result = decrypt_group_message(&keys, &group_pk, &ciphertext).unwrap();
        assert_eq!(result.data, plaintext.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_group_multiple_keys() {
        let seed = hex_to_bytes(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
        );
        let (_, ed_sk) = ed25519_key_pair_from_seed(&seed).unwrap();

        let group_seed = hex_to_bytes(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        );
        let (group_pk, _) = ed25519_key_pair_from_seed(&group_seed).unwrap();
        let group_enc_key =
            hex_to_bytes("fedcba9876543210fedcba98765432100123456789abcdef0123456789abcdef");
        let wrong_key =
            hex_to_bytes("1111111111111111111111111111111122222222222222222222222222222222");

        let ciphertext = encrypt_for_group(
            &ed_sk,
            &group_pk,
            &group_enc_key,
            b"test",
            false,
            0,
        )
        .unwrap();

        // First key is wrong, second is right
        let keys: Vec<&[u8]> = vec![&wrong_key, &group_enc_key];
        let result = decrypt_group_message(&keys, &group_pk, &ciphertext).unwrap();
        assert_eq!(result.data, b"test");
        assert_eq!(result.index, 1);
    }

    #[test]
    fn test_blinded_encrypt_decrypt_blind15() {
        let (_ed_pk, ed_sk, curve_pk, _ed_pk2, ed_sk2, _curve_pk2) = setup_keys();
        let server_pk =
            hex_to_bytes("1d7e7f92b1ed3643855c98ecac02fc7274033a3467653f047d6e433540c03f17");

        let blind15_pk = blind15_key_pair_pk(
            &ed_sk,
            &server_pk,
        )
        .unwrap();
        let blind15_pk2 = blind15_key_pair_pk(
            &ed_sk2,
            &server_pk,
        )
        .unwrap();

        let mut blind15_pk2_prefixed = vec![0x15];
        blind15_pk2_prefixed.extend_from_slice(&blind15_pk2);

        let mut blind15_pk_prefixed = vec![0x15];
        blind15_pk_prefixed.extend_from_slice(&blind15_pk);

        let enc = encrypt_for_blinded_recipient(
            &ed_sk,
            &server_pk,
            &blind15_pk2_prefixed,
            b"hello",
        )
        .unwrap();

        let sid = format!("05{}", hex::encode(curve_pk));

        // Recipient should be able to decrypt
        let (msg, sender) = decrypt_from_blinded_recipient(
            &ed_sk2,
            &server_pk,
            &blind15_pk_prefixed,
            &blind15_pk2_prefixed,
            &enc,
        )
        .unwrap();
        assert_eq!(sender, sid);
        assert_eq!(msg, b"hello");
    }

    #[test]
    fn test_blinded_encrypt_decrypt_blind25() {
        let (_ed_pk, ed_sk, curve_pk, _ed_pk2, ed_sk2, _curve_pk2) = setup_keys();
        let server_pk =
            hex_to_bytes("1d7e7f92b1ed3643855c98ecac02fc7274033a3467653f047d6e433540c03f17");

        let blind25_pk = blind25_key_pair_pk(
            &ed_sk,
            &server_pk,
        )
        .unwrap();
        let blind25_pk2 = blind25_key_pair_pk(
            &ed_sk2,
            &server_pk,
        )
        .unwrap();

        let mut blind25_pk2_prefixed = vec![0x25];
        blind25_pk2_prefixed.extend_from_slice(&blind25_pk2);

        let mut blind25_pk_prefixed = vec![0x25];
        blind25_pk_prefixed.extend_from_slice(&blind25_pk);

        let enc = encrypt_for_blinded_recipient(
            &ed_sk,
            &server_pk,
            &blind25_pk2_prefixed,
            b"hello",
        )
        .unwrap();

        let sid = format!("05{}", hex::encode(curve_pk));

        // Sender should be able to decrypt their own message
        let (msg, sender) = decrypt_from_blinded_recipient(
            &ed_sk,
            &server_pk,
            &blind25_pk_prefixed,
            &blind25_pk2_prefixed,
            &enc,
        )
        .unwrap();
        assert_eq!(sender, sid);
        assert_eq!(msg, b"hello");

        // Recipient should be able to decrypt
        let (msg2, sender2) = decrypt_from_blinded_recipient(
            &ed_sk2,
            &server_pk,
            &blind25_pk_prefixed,
            &blind25_pk2_prefixed,
            &enc,
        )
        .unwrap();
        assert_eq!(sender2, sid);
        assert_eq!(msg2, b"hello");
    }

    #[test]
    fn test_blinded_encrypt_decrypt_blind25_seed_only() {
        let (_ed_pk, ed_sk, curve_pk, _ed_pk2, ed_sk2, _curve_pk2) = setup_keys();
        let server_pk =
            hex_to_bytes("1d7e7f92b1ed3643855c98ecac02fc7274033a3467653f047d6e433540c03f17");

        let blind25_pk = blind25_key_pair_pk(
            &ed_sk,
            &server_pk,
        )
        .unwrap();
        let blind25_pk2 = blind25_key_pair_pk(
            &ed_sk2,
            &server_pk,
        )
        .unwrap();

        let mut blind25_pk2_prefixed = vec![0x25];
        blind25_pk2_prefixed.extend_from_slice(&blind25_pk2);
        let mut blind25_pk_prefixed = vec![0x25];
        blind25_pk_prefixed.extend_from_slice(&blind25_pk);

        let lorem_ipsum =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor \
             incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis \
             nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. \
             Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu \
             fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in \
             culpa qui officia deserunt mollit anim id est laborum.";

        // Encrypt with seed only
        let enc = encrypt_for_blinded_recipient(
            &ed_sk[..32],
            &server_pk,
            &blind25_pk2_prefixed,
            lorem_ipsum.as_bytes(),
        )
        .unwrap();

        let sid = format!("05{}", hex::encode(curve_pk));

        // Recipient should be able to decrypt using seed only
        let (msg, sender) = decrypt_from_blinded_recipient(
            &ed_sk2[..32],
            &server_pk,
            &blind25_pk_prefixed,
            &blind25_pk2_prefixed,
            &enc,
        )
        .unwrap();
        assert_eq!(sender, sid);
        assert_eq!(std::str::from_utf8(&msg).unwrap(), lorem_ipsum);
    }

    #[test]
    fn test_compute_hash_blake2b_b64() {
        // Simple round-trip test - we just check that it produces a non-empty unpadded base64 string
        let result = compute_hash_blake2b_b64(&["test", "data"]);
        assert!(!result.is_empty());
        assert!(!result.ends_with('='));

        // Same inputs produce same output
        let result2 = compute_hash_blake2b_b64(&["test", "data"]);
        assert_eq!(result, result2);

        // Different inputs produce different output
        let result3 = compute_hash_blake2b_b64(&["different", "input"]);
        assert_ne!(result, result3);
    }

    #[test]
    fn test_sign_for_recipient_format() {
        let (ed_pk, ed_sk, _curve_pk, _ed_pk2, _ed_sk2, curve_pk2) = setup_keys();

        let msg = b"hello";
        let signed = sign_for_recipient(&ed_sk, &curve_pk2, msg).unwrap();

        // Format: M(5) || A(32) || SIG(64) = 101 bytes
        assert_eq!(signed.len(), 5 + 32 + 64);
        assert_eq!(&signed[..5], b"hello");
        assert_eq!(&signed[5..37], &ed_pk);
    }

    #[test]
    fn test_blinded_tampered_ciphertext() {
        let (_ed_pk, ed_sk, _curve_pk, _ed_pk2, ed_sk2, _curve_pk2) = setup_keys();
        let server_pk =
            hex_to_bytes("1d7e7f92b1ed3643855c98ecac02fc7274033a3467653f047d6e433540c03f17");

        let blind25_pk = blind25_key_pair_pk(&ed_sk, &server_pk).unwrap();
        let blind25_pk2 = blind25_key_pair_pk(&ed_sk2, &server_pk).unwrap();

        let mut blind25_pk2_prefixed = vec![0x25];
        blind25_pk2_prefixed.extend_from_slice(&blind25_pk2);
        let mut blind25_pk_prefixed = vec![0x25];
        blind25_pk_prefixed.extend_from_slice(&blind25_pk);

        let enc = encrypt_for_blinded_recipient(
            &ed_sk,
            &server_pk,
            &blind25_pk2_prefixed,
            b"hello",
        )
        .unwrap();

        // Tamper with ciphertext
        let mut broken = enc.clone();
        broken[23] ^= 0x80;
        assert!(decrypt_from_blinded_recipient(
            &ed_sk2,
            &server_pk,
            &blind25_pk_prefixed,
            &blind25_pk2_prefixed,
            &broken,
        )
        .is_err());
    }
}
