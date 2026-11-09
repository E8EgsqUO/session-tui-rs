//! Curve25519 key generation and Ed25519-to-Curve25519 conversion.
//!
//! Port of `libsession-util/src/curve25519.cpp`. Uses `x25519-dalek` for key
//! generation and `curve25519-dalek` for Ed25519-to-Montgomery point conversion.

use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::RngExt;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::types::{CryptoError, CryptoResult};

/// Generates a random Curve25519 (X25519) key pair.
///
/// Returns `(pubkey_32, secret_key_32)`.
pub fn curve25519_key_pair() -> ([u8; 32], [u8; 32]) {
    let random_bytes: [u8; 32] = rand::rng().random();
    let secret = StaticSecret::from(random_bytes);
    let public = PublicKey::from(&secret);
    (public.to_bytes(), secret.to_bytes())
}

/// Converts an Ed25519 public key to a Curve25519 (X25519) public key.
///
/// This mirrors libsodium's `crypto_sign_ed25519_pk_to_curve25519`: decompress
/// the Edwards point, then convert to Montgomery form.
pub fn to_curve25519_pubkey(ed25519_pubkey: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    let compressed = CompressedEdwardsY(*ed25519_pubkey);
    let point = compressed.decompress().ok_or_else(|| {
        CryptoError::KeyConversionFailed("failed to decompress Ed25519 public key".to_string())
    })?;
    Ok(point.to_montgomery().to_bytes())
}

/// Converts a 64-byte Ed25519 secret key (libsodium format: `seed || pubkey`)
/// to a 32-byte Curve25519 secret key.
///
/// This mirrors libsodium's `crypto_sign_ed25519_sk_to_curve25519`:
/// SHA-512 the seed (first 32 bytes), take the lower 32 bytes, and clamp.
pub fn to_curve25519_seckey(ed25519_seckey: &[u8; 64]) -> CryptoResult<[u8; 32]> {
    let hash: [u8; 64] = Sha512::digest(&ed25519_seckey[..32]).into();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);

    // Clamp
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    Ok(scalar_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_key_pair_random() {
        let (pk1, sk1) = curve25519_key_pair();
        let (pk2, sk2) = curve25519_key_pair();
        assert_eq!(pk1.len(), 32);
        assert_eq!(sk1.len(), 32);
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn test_to_curve25519_pubkey() {
        // These are the same hex values used in the C++ test. The C++ test names
        // them ed_pk1/ed_pk2 and feeds them to `to_curve25519_pubkey`.
        let ed_pk1 = hex!("4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
        let ed_pk2 = hex!("5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");

        let x_pk1 = to_curve25519_pubkey(&ed_pk1).unwrap();
        let x_pk2 = to_curve25519_pubkey(&ed_pk2).unwrap();

        assert_eq!(
            hex::encode(x_pk1),
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"
        );
        assert_eq!(
            hex::encode(x_pk2),
            "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"
        );
    }

    #[test]
    fn test_to_curve25519_seckey() {
        let ed_sk1 = hex!(
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"
            "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"
        );
        let ed_sk2 = hex!(
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"
            "cd83ca3d13ad8a954d5011aa7861abe3a29ac25b70c4ed5234aff74d34ef5786"
        );

        let x_sk1 = to_curve25519_seckey(&ed_sk1).unwrap();
        let x_sk2 = to_curve25519_seckey(&ed_sk2).unwrap();

        assert_eq!(
            hex::encode(x_sk1),
            "207e5d97e761300f96c10adc11efdd6d5c15188a9a7682ec05b30ca017e9b447"
        );
        assert_eq!(
            hex::encode(x_sk2),
            "904943eff27142a8e5cd37c84e2437c9979a560b044bf9a65a8d644b325fe56a"
        );
    }
}
