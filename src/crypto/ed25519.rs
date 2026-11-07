//! Ed25519 key generation, signing, and verification.
//!
//! Port of `libsession-util/src/ed25519.cpp`. Uses `ed25519-dalek` for the
//! core Ed25519 operations and `blake2b_simd` for keyed BLAKE2b hashing in
//! the derived-key helpers.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;

use crate::crypto::types::{CryptoError, CryptoResult};

/// Generates a random Ed25519 key pair.
///
/// Returns `(pubkey_32, secret_key_64)` where the 64-byte secret key is in
/// libsodium format: `seed(32) || pubkey(32)`.
pub fn ed25519_key_pair() -> ([u8; 32], [u8; 64]) {
    let seed: [u8; 32] = rand::rng().random();
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    let sk_bytes = signing_key.to_keypair_bytes();
    (pubkey, sk_bytes)
}

/// Generates an Ed25519 key pair from a 32-byte seed.
///
/// Returns `(pubkey_32, secret_key_64)` where the 64-byte secret key is in
/// libsodium format: `seed(32) || pubkey(32)`.
pub fn ed25519_key_pair_from_seed(seed: &[u8]) -> CryptoResult<([u8; 32], [u8; 64])> {
    if seed.len() != 32 {
        return Err(CryptoError::InvalidSeedSize(seed.len()));
    }
    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed_arr);
    let pubkey = signing_key.verifying_key().to_bytes();
    let sk_bytes = signing_key.to_keypair_bytes();
    Ok((pubkey, sk_bytes))
}

/// Extracts the 32-byte seed from an Ed25519 private key.
///
/// Accepts either a 32-byte seed (returned as-is) or a 64-byte libsodium-style
/// secret key (first 32 bytes are the seed).
pub fn seed_for_ed_privkey(privkey: &[u8]) -> CryptoResult<[u8; 32]> {
    if privkey.len() != 32 && privkey.len() != 64 {
        return Err(CryptoError::InvalidKeySize {
            expected: 32,
            got: privkey.len(),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&privkey[..32]);
    Ok(seed)
}

/// Signs a message with an Ed25519 private key.
///
/// Accepts either a 32-byte seed or a 64-byte libsodium-style secret key
/// (`seed || pubkey`). If a 32-byte seed is provided, the full keypair is
/// derived first.
///
/// Returns a 64-byte detached signature.
pub fn sign(privkey: &[u8], msg: &[u8]) -> CryptoResult<[u8; 64]> {
    let signing_key = match privkey.len() {
        32 => {
            let seed: [u8; 32] = privkey.try_into().unwrap();
            SigningKey::from_bytes(&seed)
        }
        64 => {
            // libsodium format: first 32 bytes are the seed
            let seed: [u8; 32] = privkey[..32].try_into().unwrap();
            SigningKey::from_bytes(&seed)
        }
        _ => {
            return Err(CryptoError::InvalidKeySize {
                expected: 64,
                got: privkey.len(),
            });
        }
    };
    let signature = signing_key.sign(msg);
    Ok(signature.to_bytes())
}

/// Verifies an Ed25519 signature.
///
/// Returns `true` if the signature is valid, `false` otherwise.
/// Returns an error if the signature or pubkey sizes are wrong.
pub fn verify(sig: &[u8], pubkey: &[u8], msg: &[u8]) -> CryptoResult<bool> {
    if sig.len() != 64 {
        return Err(CryptoError::InvalidSignatureSize(sig.len()));
    }
    if pubkey.len() != 32 {
        return Err(CryptoError::InvalidKeySize {
            expected: 32,
            got: pubkey.len(),
        });
    }
    let sig_bytes: [u8; 64] = sig.try_into().unwrap();
    let pk_bytes: [u8; 32] = pubkey.try_into().unwrap();

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(vk) => vk,
        Err(_) => return Ok(false),
    };

    Ok(verifying_key.verify(msg, &signature).is_ok())
}

/// Internal helper: derives an Ed25519 private key from a seed and a string key.
///
/// Computes `new_seed = Blake2b-256(ed25519_seed, key=<key_str>)`, then generates
/// an Ed25519 keypair from that new seed and returns the 64-byte private key.
fn derived_ed25519_privkey(ed25519_seed: &[u8], key_str: &str) -> CryptoResult<[u8; 64]> {
    if ed25519_seed.len() != 32 && ed25519_seed.len() != 64 {
        return Err(CryptoError::InvalidSeedSize(ed25519_seed.len()));
    }

    // new_seed = Blake2b(ed25519_seed, key=key_str, digest_size=32)
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(key_str.as_bytes())
        .hash(ed25519_seed);

    let new_seed: [u8; 32] = hash.as_bytes().try_into().unwrap();
    let (_, sk) = ed25519_key_pair_from_seed(&new_seed)?;
    Ok(sk)
}

/// Derives a "Session Pro" Ed25519 private key from a seed.
///
/// Uses `derived_ed25519_privkey(seed, "SessionProRandom")` internally.
/// Returns a 64-byte private key in libsodium format (`seed || pubkey`).
pub fn ed25519_pro_privkey_for_ed25519_seed(seed: &[u8]) -> CryptoResult<[u8; 64]> {
    derived_ed25519_privkey(seed, "SessionProRandom")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const SEED1: [u8; 32] =
        hex!("4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    const SEED2: [u8; 32] =
        hex!("5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");

    #[test]
    fn test_key_pair_random() {
        let (pk1, sk1) = ed25519_key_pair();
        let (pk2, sk2) = ed25519_key_pair();
        assert_eq!(pk1.len(), 32);
        assert_eq!(sk1.len(), 64);
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn test_key_pair_from_seed() {
        let (pk1, sk1) = ed25519_key_pair_from_seed(&SEED1).unwrap();
        let (pk2, sk2) = ed25519_key_pair_from_seed(&SEED2).unwrap();

        assert_eq!(pk1.len(), 32);
        assert_eq!(sk1.len(), 64);
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);

        assert_eq!(
            hex::encode(pk1),
            "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"
        );
        assert_eq!(
            hex::encode(pk2),
            "cd83ca3d13ad8a954d5011aa7861abe3a29ac25b70c4ed5234aff74d34ef5786"
        );

        let expected_sk1 =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7\
             8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f";
        let expected_sk2 =
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876\
             cd83ca3d13ad8a954d5011aa7861abe3a29ac25b70c4ed5234aff74d34ef5786";
        assert_eq!(hex::encode(sk1), expected_sk1);
        assert_eq!(hex::encode(sk2), expected_sk2);
    }

    #[test]
    fn test_key_pair_from_seed_invalid() {
        let invalid = hex!("010203040506070809");
        assert!(ed25519_key_pair_from_seed(&invalid).is_err());
    }

    #[test]
    fn test_seed_for_ed_privkey() {
        let sk1 = hex!(
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"
            "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"
        );
        let sk2 = hex!("5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");

        let seed1 = seed_for_ed_privkey(&sk1).unwrap();
        let seed2 = seed_for_ed_privkey(&sk2).unwrap();

        assert_eq!(
            hex::encode(seed1),
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"
        );
        assert_eq!(
            hex::encode(seed2),
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"
        );
    }

    #[test]
    fn test_seed_for_ed_privkey_invalid() {
        let invalid = hex!("010203040506070809");
        assert!(seed_for_ed_privkey(&invalid).is_err());
    }

    #[test]
    fn test_sign_and_verify() {
        let (pk, _) = ed25519_key_pair_from_seed(&SEED1).unwrap();

        // Sign with 32-byte seed
        let sig = sign(&SEED1, b"hello").unwrap();
        let expected_sig =
            "e03b6e87a53d83f202f2501e9b52193dbe4a64c6503f88244948dee532718501\
             1574589aa7b59bc9757f9b9c31b7be9c9212b92ac7c81e029ee21c338ee12405";
        assert_eq!(hex::encode(sig), expected_sig);

        assert!(verify(&sig, &pk, b"hello").unwrap());
    }

    #[test]
    fn test_sign_invalid_privkey() {
        let invalid = hex!("010203040506070809");
        assert!(sign(&invalid, b"hello").is_err());
    }

    #[test]
    fn test_verify_invalid_sig_size() {
        let pk = hex!("8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f");
        let invalid = hex!("010203040506070809");
        assert!(verify(&invalid, &pk, b"hello").is_err());
    }

    #[test]
    fn test_verify_invalid_pubkey_size() {
        let sig = [0u8; 64];
        let invalid = hex!("010203040506070809");
        assert!(verify(&sig, &invalid, b"hello").is_err());
    }

    #[test]
    fn test_pro_privkey() {
        let seed1 =
            hex!("e5481635020d6f7b327e94e6d63e33a431fccabc4d2775845c43a8486a9f2884");
        let seed2 =
            hex!("743d646706b6b04b97b752036dd6cf5f2adc4b339fcfdfb4b496f0764bb93a84");

        let sk1 = ed25519_pro_privkey_for_ed25519_seed(&seed1).unwrap();
        let sk2 = ed25519_pro_privkey_for_ed25519_seed(&seed2).unwrap();

        assert_eq!(sk1.len(), 64);
        assert_ne!(sk1, sk2);

        let expected_sk1 =
            "a4ec87e2346b25ee6394211cb682640a09dd8d297016fe241fe5b06fefef416c\
             b6d20c075eddd2edb69d4d7da9b7e580f187ce0537585da2b5e454b77980d0c8";
        let expected_sk2 =
            "7da256ba427cf5419cefea81f8ebb3395c261e4dfc2c91ee4d3ce9def67aa21c\
             539d0a3be9658ebb6ba3ce97b25d4f6b716f7ef6d6ae6343bd0733519f5a51e8";

        assert_eq!(hex::encode(sk1), expected_sk1);
        assert_eq!(hex::encode(sk2), expected_sk2);
    }

    #[test]
    fn test_pro_privkey_invalid_seed() {
        let invalid = hex!("010203040506070809");
        assert!(ed25519_pro_privkey_for_ed25519_seed(&invalid).is_err());
    }
}
