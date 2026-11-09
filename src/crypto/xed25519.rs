//! XEd25519: signing with X25519 keys.
//!
//! This module implements the XEd25519 scheme, which allows signing with
//! a Curve25519 (X25519/Montgomery) private key and verifying against the
//! corresponding Edwards (Ed25519) public key.
//!
//! Session's variant uses a personalized BLAKE2b hash for nonce derivation
//! instead of Signal's original custom-prefixed SHA-512 construction.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngExt;
use sha2::{Digest, Sha512};

/// Converts a Curve25519 (Montgomery/X25519) public key to an Ed25519 public key.
///
/// Applies the birational map `y = (u - 1) / (u + 1)` from the Montgomery
/// x-coordinate to the Edwards y-coordinate. The resulting key always has sign
/// bit 0 (positive). If the original Edwards key was "negative" (sign bit 1),
/// the caller may need to set the sign bit manually.
pub fn pubkey(curve25519_pubkey: &[u8; 32]) -> [u8; 32] {
    let mont = MontgomeryPoint(*curve25519_pubkey);
    // to_edwards(0) computes y = (u-1)/(u+1) with sign bit 0.
    // This matches the C++ fe25519_montx_to_edy + fe25519_tobytes which
    // produces the canonical field element encoding (sign bit always 0).
    match mont.to_edwards(0) {
        Some(edwards) => edwards.compress().to_bytes(),
        None => {
            // u = -1 (point on the twist). Return all zeros matching
            // the C++ behaviour where fe25519_tobytes would encode the
            // result of 0/0 (undefined), but practically this key is
            // invalid.
            [0u8; 32]
        }
    }
}

/// Computes the nonce scalar `r` for XEd25519 signing.
///
/// Uses a personalized BLAKE2b hash:
///   `r = scalar_reduce(Blake2b("xed25519signatur", a || msg || random))`
///
/// where `random` is 64 bytes of cryptographic randomness.
fn xed25519_compute_r(a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut random = [0u8; 64];
    rand::rng().fill(&mut random[..]);

    let h = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"xed25519signatur")
        .to_state()
        .update(a)
        .update(msg)
        .update(&random)
        .finalize();

    let mut h_bytes = [0u8; 64];
    h_bytes.copy_from_slice(h.as_bytes());
    Scalar::from_bytes_mod_order_wide(&h_bytes)
}

/// Signs a message using an X25519 private key, producing an Ed25519-compatible signature.
///
/// The resulting 64-byte signature (`R || S`) can be verified against the Ed25519 public
/// key obtained from [`pubkey`] (or via standard Ed25519 verification with the converted key).
///
/// Because the nonce includes random bytes, signing the same message twice produces
/// different (but equally valid) signatures.
pub fn sign(curve25519_privkey: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    // 1. Compute Ed25519 pubkey A from x25519 privkey.
    //    crypto_scalarmult_ed25519_base uses the raw scalar (no additional clamping).
    //    The x25519 privkey is already clamped, and Scalar::from_bytes_mod_order
    //    reduces mod L which is correct since a*B == (a mod L)*B for group order L.
    let a_scalar = Scalar::from_bytes_mod_order(*curve25519_privkey);
    let a_point = EdwardsPoint::mul_base(&a_scalar);
    let mut a_compressed = a_point.compress().to_bytes();

    // 2. Check if sign bit is set (the key is "negative").
    let negative = (a_compressed[31] >> 7) != 0;

    // 3. Clear sign bit to get the "absolute" public key.
    a_compressed[31] &= 0x7f;

    // 4. If negative, negate the scalar so the signature is valid for the
    //    positive public key.
    let a = if negative { -a_scalar } else { a_scalar };

    // 5. Compute nonce r = Blake2b(personality, a || msg || random) mod L
    let r = xed25519_compute_r(&a.to_bytes(), msg);

    // 6. R = r * B (base point multiplication, "noclamp" -- r is already a
    //    proper reduced scalar).
    let r_point = EdwardsPoint::mul_base(&r);
    let r_compressed = r_point.compress().to_bytes();

    // 7-8. HRAM = SHA-512(R || A || msg) mod L  (standard Ed25519 challenge)
    let mut hasher = Sha512::new();
    hasher.update(r_compressed);
    hasher.update(a_compressed);
    hasher.update(msg);
    let hram_hash: [u8; 64] = hasher.finalize().into();
    let hram = Scalar::from_bytes_mod_order_wide(&hram_hash);

    // 9-10. S = HRAM * a + r
    let s = hram * a + r;

    // 11. Return R || S
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_compressed);
    signature[32..].copy_from_slice(&s.to_bytes());
    signature
}

/// Verifies an XEd25519 signature against a Curve25519 public key.
///
/// Internally converts the Curve25519 public key to an Ed25519 public key
/// via [`pubkey`], then performs standard Ed25519 signature verification.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify(signature: &[u8; 64], curve25519_pubkey: &[u8; 32], msg: &[u8]) -> bool {
    let ed_pubkey_bytes = pubkey(curve25519_pubkey);

    // Try with sign bit 0 (positive)
    let sig = Signature::from_bytes(signature);

    if let Ok(vk) = VerifyingKey::from_bytes(&ed_pubkey_bytes)
        && vk.verify_strict(msg, &sig).is_ok()
    {
        return true;
    }

    // Also try with sign bit 1 (negative), since we don't know which
    // sign the original key had and the XEd25519 spec requires trying both.
    let mut neg_pubkey = ed_pubkey_bytes;
    neg_pubkey[31] |= 0x80;
    if let Ok(vk) = VerifyingKey::from_bytes(&neg_pubkey)
        && vk.verify_strict(msg, &sig).is_ok()
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::edwards::CompressedEdwardsY;

    // Test vectors from the C++ test suite.
    // seed1 and seed2 are 64-byte Ed25519 seeds (first 32 = secret scalar, last 32 = public key).
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

    // Ed25519 public keys (last 32 bytes of seeds).
    fn ed_pub1() -> [u8; 32] {
        SEED1[32..].try_into().unwrap()
    }
    fn ed_pub2() -> [u8; 32] {
        SEED2[32..].try_into().unwrap()
    }

    // X25519 (Curve25519) public keys corresponding to the above Ed keys.
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

    // The "absolute" Ed25519 pubkey for seed2 (sign bit cleared).
    const PUB2_ABS: [u8; 32] = [
        0x35, 0x70, 0xb6, 0x9a, 0x47, 0xdc, 0x09, 0x45, 0x44, 0xc1, 0xc5, 0x08, 0x9c, 0x40, 0x41,
        0x4b, 0xbd, 0xa1, 0xff, 0xdd, 0xe8, 0xaa, 0xb2, 0x61, 0x7f, 0xe9, 0x37, 0xee, 0x74, 0xa5,
        0xee, 0x01,
    ];

    /// Derives X25519 private key from an Ed25519 seed.
    ///
    /// Mirrors libsodium's `crypto_sign_ed25519_sk_to_curve25519`:
    /// hash the first 32 bytes of the seed with SHA-512, then clamp the
    /// lower 32 bytes.
    fn ed25519_sk_to_curve25519(seed: &[u8; 64]) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(&seed[..32]);
        let hash: [u8; 64] = hasher.finalize().into();
        let mut x_sk = [0u8; 32];
        x_sk.copy_from_slice(&hash[..32]);
        // Clamp
        x_sk[0] &= 248;
        x_sk[31] &= 127;
        x_sk[31] |= 64;
        x_sk
    }

    /// Derives X25519 public key from an Ed25519 public key.
    ///
    /// Mirrors libsodium's `crypto_sign_ed25519_pk_to_curve25519`:
    /// decompress the Edwards point, then convert to Montgomery.
    fn ed25519_pk_to_curve25519(ed_pk: &[u8; 32]) -> [u8; 32] {
        let compressed = CompressedEdwardsY(*ed_pk);
        let point = compressed.decompress().expect("valid Ed25519 public key");
        point.to_montgomery().to_bytes()
    }

    #[test]
    fn test_pubkey_conversion_roundtrip() {
        // Derive X25519 pubkey from Ed25519 pubkey
        let xpk1 = ed25519_pk_to_curve25519(&ed_pub1());
        assert_eq!(xpk1, XPUB1, "xpub1 derivation mismatch");

        let xpk2 = ed25519_pk_to_curve25519(&ed_pub2());
        assert_eq!(xpk2, XPUB2, "xpub2 derivation mismatch");

        // Convert back: xpub1 -> ed_pub1 should match exactly (sign bit 0)
        let xed1 = pubkey(&XPUB1);
        assert_eq!(
            xed1,
            ed_pub1(),
            "xed25519 pubkey 1 should match ed25519 pubkey 1"
        );

        // xpub2's original Ed key has the sign bit set (negative), so the
        // raw conversion should NOT match
        let xed2 = pubkey(&XPUB2);
        assert_ne!(
            xed2,
            ed_pub2(),
            "xed25519 pubkey 2 should differ from negative ed25519 pubkey 2"
        );

        // After setting the sign bit, it should match
        let mut xed2_neg = xed2;
        xed2_neg[31] |= 0x80;
        assert_eq!(
            xed2_neg,
            ed_pub2(),
            "xed25519 pubkey 2 with sign bit set should match ed25519 pubkey 2"
        );
    }

    #[test]
    fn test_sign_produces_valid_ed25519_signature() {
        let xsk1 = ed25519_sk_to_curve25519(&SEED1);
        let msg = b"hello world";

        let sig = sign(&xsk1, msg);

        // The signature should verify against the (positive) Ed25519 pubkey
        let vk = VerifyingKey::from_bytes(&ed_pub1()).unwrap();
        let ed_sig = Signature::from_bytes(&sig);
        assert!(
            vk.verify_strict(msg.as_slice(), &ed_sig).is_ok(),
            "XEd25519 signature should verify against ed25519 pubkey 1"
        );
    }

    #[test]
    fn test_sign_negative_key() {
        let xsk2 = ed25519_sk_to_curve25519(&SEED2);
        let msg = b"hello world";

        let sig = sign(&xsk2, msg);

        // Signature should NOT verify against the original (negative) pubkey
        let vk_neg = VerifyingKey::from_bytes(&ed_pub2()).unwrap();
        let ed_sig = Signature::from_bytes(&sig);
        assert!(
            vk_neg.verify_strict(msg.as_slice(), &ed_sig).is_err(),
            "XEd25519 signature should NOT verify against negative ed25519 pubkey 2"
        );

        // It SHOULD verify against the "absolute" (positive) pubkey
        let vk_abs = VerifyingKey::from_bytes(&PUB2_ABS).unwrap();
        assert!(
            vk_abs.verify_strict(msg.as_slice(), &ed_sig).is_ok(),
            "XEd25519 signature should verify against absolute ed25519 pubkey 2"
        );
    }

    #[test]
    fn test_verify_with_curve25519_pubkey() {
        let xsk1 = ed25519_sk_to_curve25519(&SEED1);
        let xsk2 = ed25519_sk_to_curve25519(&SEED2);
        let msg = b"hello world";

        let sig1 = sign(&xsk1, msg);
        let sig2 = sign(&xsk2, msg);

        assert!(
            verify(&sig1, &XPUB1, msg),
            "verify should succeed for key pair 1"
        );
        assert!(
            verify(&sig2, &XPUB2, msg),
            "verify should succeed for key pair 2"
        );
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let xsk1 = ed25519_sk_to_curve25519(&SEED1);
        let msg = b"hello world";

        let sig1 = sign(&xsk1, msg);

        // Verify with the wrong public key should fail
        assert!(
            !verify(&sig1, &XPUB2, msg),
            "verify with wrong pubkey should fail"
        );
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let xsk1 = ed25519_sk_to_curve25519(&SEED1);
        let msg = b"hello world";
        let wrong_msg = b"goodbye world";

        let sig1 = sign(&xsk1, msg);

        assert!(
            !verify(&sig1, &XPUB1, wrong_msg),
            "verify with wrong message should fail"
        );
    }

    #[test]
    fn test_sign_is_nondeterministic() {
        let xsk1 = ed25519_sk_to_curve25519(&SEED1);
        let msg = b"hello world";

        let sig_a = sign(&xsk1, msg);
        let sig_b = sign(&xsk1, msg);

        // Due to randomness in the nonce, two signatures of the same
        // message should (with overwhelming probability) differ.
        assert_ne!(
            sig_a, sig_b,
            "two signatures of the same message should differ (randomized nonce)"
        );

        // But both should verify
        assert!(verify(&sig_a, &XPUB1, msg));
        assert!(verify(&sig_b, &XPUB1, msg));
    }
}
