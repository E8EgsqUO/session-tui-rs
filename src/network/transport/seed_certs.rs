//! Bundled Session seed-node CA certificates.
//!
//! Session's three seed nodes (`seed1/2/3.getsession.org`) present
//! self-signed, internally-issued X.509 certs (subject == issuer,
//! CN = `seedN.getsession.org`, issued by "Oxen Privacy Tech Foundation",
//! valid 2023-04-05 → 2033-04-05). Because those certs are also CAs
//! (`basicConstraints.isCA = true`), WebPKI refuses them as end-entity
//! certs and the Mozilla root bundle has no trust anchor for them.
//!
//! The native Android client solves this by bundling the three PEMs as
//! `app/src/main/res/raw/seed{1,2,3}.pem` and pinning them per-domain via
//! `network_security_configuration.xml`. We do the same: the three PEMs
//! live next to this file, are compiled in via [`include_bytes!`], and are
//! used by [`super::http`]'s pinned verifier for exact DER matching.
//!
//! **Private module** — consumers of this library have no reason to see
//! the bundled pins. They're an implementation detail of [`super::http`].

use std::sync::OnceLock;

use rustls::pki_types::CertificateDer;

/// Byte-for-byte identical to `session-android/app/src/main/res/raw/seed1.pem`.
const SEED1_PEM: &[u8] = include_bytes!("seed_certs/seed1.pem");
/// Byte-for-byte identical to `session-android/app/src/main/res/raw/seed2.pem`.
const SEED2_PEM: &[u8] = include_bytes!("seed_certs/seed2.pem");
/// Byte-for-byte identical to `session-android/app/src/main/res/raw/seed3.pem`.
const SEED3_PEM: &[u8] = include_bytes!("seed_certs/seed3.pem");

/// Seed hostnames we pin — anything else must not use
/// [`super::http::seed_pinned_client`].
const SEED_HOSTS: &[&str] = &[
    "seed1.getsession.org",
    "seed2.getsession.org",
    "seed3.getsession.org",
];

/// Returns `true` if `host` is one of Session's three seed-node hostnames.
/// Case-insensitive. Any port suffix in the input is ignored.
pub fn is_seed_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    SEED_HOSTS.iter().any(|s| *s == h)
}

/// Parsed DER form of the bundled seed PEMs. Parsed once, cached for the
/// process lifetime. Order is `[seed1, seed2, seed3]`.
pub fn pinned_certs() -> &'static [CertificateDer<'static>] {
    static CELL: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut out = Vec::with_capacity(3);
        for pem in [SEED1_PEM, SEED2_PEM, SEED3_PEM] {
            let mut cursor = std::io::Cursor::new(pem);
            for item in rustls_pemfile::certs(&mut cursor) {
                let der = item.expect("bundled seed PEM must be valid");
                out.push(der);
            }
        }
        assert_eq!(
            out.len(),
            3,
            "expected exactly 3 bundled seed certs, got {}",
            out.len()
        );
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_three_pems_parse() {
        let certs = pinned_certs();
        assert_eq!(certs.len(), 3);
        for c in certs {
            assert!(!c.as_ref().is_empty());
            // Minimum-plausible DER cert size — real ones are ~1100 bytes.
            assert!(c.as_ref().len() > 200);
        }
        // The three certs must be distinct (one per seed host).
        assert_ne!(certs[0].as_ref(), certs[1].as_ref());
        assert_ne!(certs[1].as_ref(), certs[2].as_ref());
        assert_ne!(certs[0].as_ref(), certs[2].as_ref());
    }

    #[test]
    fn test_is_seed_host_matches_exact() {
        assert!(is_seed_host("seed1.getsession.org"));
        assert!(is_seed_host("seed2.getsession.org"));
        assert!(is_seed_host("seed3.getsession.org"));
    }

    #[test]
    fn test_is_seed_host_is_case_insensitive() {
        assert!(is_seed_host("SEED1.GetSession.org"));
        assert!(is_seed_host("Seed2.getsession.ORG"));
    }

    #[test]
    fn test_is_seed_host_rejects_other_hosts() {
        assert!(!is_seed_host("getsession.org"));
        assert!(!is_seed_host("seed4.getsession.org"));
        assert!(!is_seed_host("seed1.getsession.org.evil.example"));
        assert!(!is_seed_host("evil.example"));
        assert!(!is_seed_host(""));
    }

    #[test]
    fn test_is_seed_host_trims_whitespace() {
        assert!(is_seed_host(" seed1.getsession.org "));
    }
}
