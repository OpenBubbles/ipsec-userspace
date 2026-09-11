//! Algorithm registry: IKEv2 transform id (or carrier-bundle name) -> trait object.
//!
//! The protocol code never names an algorithm; it calls [`cipher`], [`integrity`],
//! [`prf`], [`dh`] with the ids it negotiated (or got from the config), and
//! [`cipher_by_name`] / [`integrity_by_name`] / [`prf_by_name`] to map the loose
//! strings found in carrier bundles (`"AES-256"`, `"SHA2-256"`, `"aes256"`,
//! `"HMAC-SHA2-256"`, ...) to transform ids. Adding an algorithm = implement the
//! trait + add one arm here.

use crate::crypto::aes_cbc::AesCbc;
use crate::crypto::dh_modp::ModpGroup;
use crate::crypto::hmac_sha2::{
    HmacSha256Integ, HmacSha256Prf, HmacSha384Integ, HmacSha384Prf, HmacSha512Integ,
    HmacSha512Prf,
};
use crate::crypto::{Cipher, DhGroup, Integrity, Prf};
use crate::ike::constants::*;
use std::sync::Arc;

/// Cipher by ENCR transform id and key-length attribute (bits). AES-CBC requires
/// the attribute (RFC 7296 §3.3.5); `None` for it, or an unknown id/size, yields `None`.
pub fn cipher(transform_id: u16, key_len_bits: Option<u16>) -> Option<Arc<dyn Cipher>> {
    match (transform_id, key_len_bits) {
        (ENCR_AES_CBC, Some(bits)) => AesCbc::new(bits).map(|c| Arc::new(c) as Arc<dyn Cipher>),
        (ENCR_AES_CBC, None) => {
            log::debug!("registry: ENCR_AES_CBC requested without a key length attribute");
            None
        }
        _ => {
            log::debug!(
                "registry: unsupported cipher {} keylen={:?}",
                transform_name(TT_ENCR, transform_id),
                key_len_bits
            );
            None
        }
    }
}

/// Integrity algorithm by INTEG transform id.
pub fn integrity(transform_id: u16) -> Option<Arc<dyn Integrity>> {
    match transform_id {
        AUTH_HMAC_SHA2_256_128 => Some(Arc::new(HmacSha256Integ)),
        AUTH_HMAC_SHA2_384_192 => Some(Arc::new(HmacSha384Integ)),
        AUTH_HMAC_SHA2_512_256 => Some(Arc::new(HmacSha512Integ)),
        _ => {
            log::debug!("registry: unsupported integrity {}", transform_name(TT_INTEG, transform_id));
            None
        }
    }
}

/// PRF by PRF transform id.
pub fn prf(transform_id: u16) -> Option<Arc<dyn Prf>> {
    match transform_id {
        PRF_HMAC_SHA2_256 => Some(Arc::new(HmacSha256Prf)),
        PRF_HMAC_SHA2_384 => Some(Arc::new(HmacSha384Prf)),
        PRF_HMAC_SHA2_512 => Some(Arc::new(HmacSha512Prf)),
        _ => {
            log::debug!("registry: unsupported prf {}", transform_name(TT_PRF, transform_id));
            None
        }
    }
}

/// Diffie-Hellman group by D-H transform id (MODP 2/5/14/15/16).
pub fn dh(group_id: u16) -> Option<Arc<dyn DhGroup>> {
    match ModpGroup::new(group_id) {
        Some(g) => Some(Arc::new(g)),
        None => {
            log::debug!("registry: unsupported DH group {}", transform_name(TT_DH, group_id));
            None
        }
    }
}

/// Upper-case and strip everything that is not a letter or digit, so that
/// `"AES-256"`, `"aes_256"`, `"AES 256"` and `"Aes256"` all become `"AES256"`.
fn normalize(name: &str) -> String {
    name.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

fn strip_prefixes<'a>(mut s: &'a str, prefixes: &[&str]) -> &'a str {
    let mut changed = true;
    while changed {
        changed = false;
        for p in prefixes {
            if let Some(rest) = s.strip_prefix(p) {
                s = rest;
                changed = true;
            }
        }
    }
    s
}

fn strip_suffixes<'a>(mut s: &'a str, suffixes: &[&str]) -> &'a str {
    let mut changed = true;
    while changed {
        changed = false;
        for p in suffixes {
            if let Some(rest) = s.strip_suffix(p) {
                s = rest;
                changed = true;
            }
        }
    }
    s
}

/// Carrier-bundle cipher name -> (ENCR transform id, key length attribute in bits).
///
/// `"AES-256"` / `"AES256"` / `"AES-CBC-256"` / `"AES-256-CBC"` / `"ENCR_AES_CBC_256"` ->
/// `(ENCR_AES_CBC, Some(256))`; likewise 128/192; `"3DES"` / `"TRIPLE-DES"` / `"DES-EDE3"` ->
/// `(ENCR_3DES, None)`; `"NULL"` -> `(ENCR_NULL, None)`. Case- and punctuation-insensitive.
pub fn cipher_by_name(name: &str) -> Option<(u16, Option<u16>)> {
    let n = normalize(name);
    let n = strip_prefixes(&n, &["ENCR"]);
    match n {
        "3DES" | "TRIPLEDES" | "DESEDE3" | "DESEDE" | "3DESCBC" | "DESEDE3CBC" | "TDES" => {
            return Some((ENCR_3DES, None));
        }
        "NULL" | "ENCRNULL" => return Some((ENCR_NULL, None)),
        "DES" | "DESCBC" => return Some((ENCR_DES, None)),
        _ => {}
    }
    let rest = n.strip_prefix("AES")?;
    // Accept CBC before or after the size; reject other AES modes (GCM/CTR are not CBC).
    let rest = strip_prefixes(rest, &["CBC"]);
    let rest = strip_suffixes(rest, &["CBC", "BIT", "BITS"]);
    let bits: u16 = match rest {
        "128" => 128,
        "192" => 192,
        "256" => 256,
        _ => return None,
    };
    Some((ENCR_AES_CBC, Some(bits)))
}

/// Strip the decorations that show up in bundle/spec names for HMAC-based algorithms
/// and return the bare hash name (`"SHA2256"`, `"SHA1"`, `"MD5"`, ...).
fn hash_core(name: &str, extra_prefixes: &[&str]) -> String {
    let n = normalize(name);
    let mut prefixes: Vec<&str> = vec!["AUTH", "PRF", "HMAC"];
    prefixes.extend_from_slice(extra_prefixes);
    let n = strip_prefixes(&n, &prefixes);
    // "HMAC" may also follow the type prefix ("AUTH_HMAC_..."), so strip once more.
    let n = strip_prefixes(n, &["HMAC"]);
    let mut n = n.to_string();
    // Canonicalise SHA256/SHA-256 -> SHA2256 so that SHA2-256 and SHA256 compare equal.
    for (short, long) in [("SHA256", "SHA2256"), ("SHA384", "SHA2384"), ("SHA512", "SHA2512")] {
        if n.starts_with(short) {
            n = format!("{long}{}", &n[short.len()..]);
        }
    }
    n
}

/// Carrier-bundle integrity name -> INTEG transform id.
///
/// `"SHA2-256"` / `"SHA256"` / `"HMAC-SHA2-256"` / `"HMAC-SHA2-256-128"` / `"AUTH_HMAC_SHA2_256_128"`
/// -> `AUTH_HMAC_SHA2_256_128`; 384 and 512 likewise; `"SHA1"` / `"HMAC-SHA1-96"` ->
/// `AUTH_HMAC_SHA1_96`; `"MD5"` -> `AUTH_HMAC_MD5_96`. The returned id may be one that
/// [`integrity`] does not implement (SHA1, MD5) — the lookup then yields `None`.
pub fn integrity_by_name(name: &str) -> Option<u16> {
    let core = hash_core(name, &["INTEG", "INTEGRITY"]);
    match core.as_str() {
        "SHA2256" | "SHA2256128" => Some(AUTH_HMAC_SHA2_256_128),
        "SHA2384" | "SHA2384192" => Some(AUTH_HMAC_SHA2_384_192),
        "SHA2512" | "SHA2512256" => Some(AUTH_HMAC_SHA2_512_256),
        "SHA1" | "SHA196" | "SHA" => Some(AUTH_HMAC_SHA1_96),
        "MD5" | "MD596" => Some(AUTH_HMAC_MD5_96),
        "AESXCBC" | "AESXCBC96" | "XCBC" => Some(AUTH_AES_XCBC_96),
        "NONE" | "NULL" => Some(AUTH_NONE),
        _ => None,
    }
}

/// Carrier-bundle PRF name -> PRF transform id.
///
/// `"SHA2-256"` / `"SHA256"` / `"HMAC-SHA2-256"` / `"PRF_HMAC_SHA2_256"` -> `PRF_HMAC_SHA2_256`;
/// 384/512 likewise; `"SHA1"` -> `PRF_HMAC_SHA1`; `"MD5"` -> `PRF_HMAC_MD5`.
pub fn prf_by_name(name: &str) -> Option<u16> {
    let core = hash_core(name, &[]);
    match core.as_str() {
        "SHA2256" => Some(PRF_HMAC_SHA2_256),
        "SHA2384" => Some(PRF_HMAC_SHA2_384),
        "SHA2512" => Some(PRF_HMAC_SHA2_512),
        "SHA1" | "SHA" => Some(PRF_HMAC_SHA1),
        "MD5" => Some(PRF_HMAC_MD5),
        "AES128XCBC" | "AESXCBC" | "XCBC" => Some(PRF_AES128_XCBC),
        _ => None,
    }
}

/// Human-readable `TYPE/NAME(id)` for a transform, for logs and errors.
pub fn transform_name(ttype: u8, id: u16) -> String {
    let (tname, name): (&str, Option<&str>) = match ttype {
        TT_ENCR => (
            "ENCR",
            match id {
                ENCR_DES => Some("DES"),
                ENCR_3DES => Some("3DES"),
                ENCR_NULL => Some("NULL"),
                ENCR_AES_CBC => Some("AES_CBC"),
                ENCR_AES_CTR => Some("AES_CTR"),
                ENCR_AES_GCM_8 => Some("AES_GCM_8"),
                ENCR_AES_GCM_12 => Some("AES_GCM_12"),
                ENCR_AES_GCM_16 => Some("AES_GCM_16"),
                ENCR_CHACHA20_POLY1305 => Some("CHACHA20_POLY1305"),
                _ => None,
            },
        ),
        TT_PRF => (
            "PRF",
            match id {
                PRF_HMAC_MD5 => Some("HMAC_MD5"),
                PRF_HMAC_SHA1 => Some("HMAC_SHA1"),
                PRF_AES128_XCBC => Some("AES128_XCBC"),
                PRF_HMAC_SHA2_256 => Some("HMAC_SHA2_256"),
                PRF_HMAC_SHA2_384 => Some("HMAC_SHA2_384"),
                PRF_HMAC_SHA2_512 => Some("HMAC_SHA2_512"),
                _ => None,
            },
        ),
        TT_INTEG => (
            "INTEG",
            match id {
                AUTH_NONE => Some("NONE"),
                AUTH_HMAC_MD5_96 => Some("HMAC_MD5_96"),
                AUTH_HMAC_SHA1_96 => Some("HMAC_SHA1_96"),
                AUTH_AES_XCBC_96 => Some("AES_XCBC_96"),
                AUTH_HMAC_SHA2_256_128 => Some("HMAC_SHA2_256_128"),
                AUTH_HMAC_SHA2_384_192 => Some("HMAC_SHA2_384_192"),
                AUTH_HMAC_SHA2_512_256 => Some("HMAC_SHA2_512_256"),
                _ => None,
            },
        ),
        TT_DH => (
            "DH",
            match id {
                DH_NONE => Some("NONE"),
                DH_MODP_768 => Some("MODP_768"),
                DH_MODP_1024 => Some("MODP_1024"),
                DH_MODP_1536 => Some("MODP_1536"),
                DH_MODP_2048 => Some("MODP_2048"),
                DH_MODP_3072 => Some("MODP_3072"),
                DH_MODP_4096 => Some("MODP_4096"),
                DH_ECP_256 => Some("ECP_256"),
                DH_ECP_384 => Some("ECP_384"),
                DH_CURVE25519 => Some("CURVE25519"),
                _ => None,
            },
        ),
        TT_ESN => (
            "ESN",
            match id {
                ESN_NO => Some("NO_ESN"),
                ESN_YES => Some("ESN"),
                _ => None,
            },
        ),
        _ => ("UNKNOWN_TYPE", None),
    };
    match name {
        Some(n) => format!("{tname}/{n}({id})"),
        None if ttype > TT_ESN || ttype == 0 => format!("{tname}{ttype}/UNKNOWN({id})"),
        None => format!("{tname}/UNKNOWN({id})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_lookup_by_id() {
        let c = cipher(ENCR_AES_CBC, Some(256)).expect("AES-256-CBC");
        assert_eq!(c.transform_id(), ENCR_AES_CBC);
        assert_eq!(c.key_len(), 32);
        assert_eq!(c.key_len_attr_bits(), Some(256));
        assert_eq!(cipher(ENCR_AES_CBC, Some(128)).unwrap().key_len(), 16);
        assert_eq!(cipher(ENCR_AES_CBC, Some(192)).unwrap().key_len(), 24);
        assert!(cipher(ENCR_AES_CBC, Some(64)).is_none());
        assert!(cipher(ENCR_AES_CBC, None).is_none());
        assert!(cipher(ENCR_3DES, None).is_none());
        assert!(cipher(ENCR_AES_GCM_16, Some(256)).is_none());
        assert!(cipher(0, None).is_none());
    }

    #[test]
    fn integrity_and_prf_lookup_by_id() {
        let i = integrity(AUTH_HMAC_SHA2_256_128).expect("SHA2-256-128");
        assert_eq!((i.transform_id(), i.key_len(), i.icv_len()), (AUTH_HMAC_SHA2_256_128, 32, 16));
        assert_eq!(integrity(AUTH_HMAC_SHA2_384_192).unwrap().icv_len(), 24);
        assert_eq!(integrity(AUTH_HMAC_SHA2_512_256).unwrap().icv_len(), 32);
        assert!(integrity(AUTH_HMAC_SHA1_96).is_none());
        assert!(integrity(AUTH_NONE).is_none());

        let p = prf(PRF_HMAC_SHA2_256).expect("PRF SHA2-256");
        assert_eq!((p.transform_id(), p.key_len(), p.output_len()), (PRF_HMAC_SHA2_256, 32, 32));
        assert_eq!(prf(PRF_HMAC_SHA2_384).unwrap().output_len(), 48);
        assert_eq!(prf(PRF_HMAC_SHA2_512).unwrap().output_len(), 64);
        assert!(prf(PRF_HMAC_SHA1).is_none());
        assert!(prf(PRF_AES128_XCBC).is_none());
    }

    #[test]
    fn dh_lookup_by_id() {
        let g = dh(DH_MODP_2048).expect("group 14");
        assert_eq!(g.group_id(), 14);
        assert_eq!(g.public_len(), 256);
        assert_eq!(dh(DH_MODP_1024).unwrap().public_len(), 128);
        assert_eq!(dh(DH_MODP_1536).unwrap().public_len(), 192);
        assert_eq!(dh(DH_MODP_3072).unwrap().public_len(), 384);
        assert_eq!(dh(DH_MODP_4096).unwrap().public_len(), 512);
        assert!(dh(DH_NONE).is_none());
        assert!(dh(DH_ECP_256).is_none());
        assert!(dh(DH_CURVE25519).is_none());
    }

    #[test]
    fn cipher_names() {
        for n in [
            "AES-256", "aes-256", "AES256", "aes256", "AES_256", "AES 256", "AES-CBC-256",
            "AES-256-CBC", "aes-cbc-256", "ENCR_AES_CBC_256", "encr-aes-cbc-256", "AES-256-bit",
        ] {
            assert_eq!(cipher_by_name(n), Some((ENCR_AES_CBC, Some(256))), "{n}");
        }
        assert_eq!(cipher_by_name("AES-128"), Some((ENCR_AES_CBC, Some(128))));
        assert_eq!(cipher_by_name("AES-CBC-128"), Some((ENCR_AES_CBC, Some(128))));
        assert_eq!(cipher_by_name("AES-192"), Some((ENCR_AES_CBC, Some(192))));
        for n in ["3DES", "3des", "3DES-CBC", "Triple-DES", "DES-EDE3", "ENCR_3DES"] {
            assert_eq!(cipher_by_name(n), Some((ENCR_3DES, None)), "{n}");
        }
        assert_eq!(cipher_by_name("DES"), Some((ENCR_DES, None)));
        assert_eq!(cipher_by_name("NULL"), Some((ENCR_NULL, None)));
        for n in ["", "AES", "AES-512", "AES-GCM-256", "AES-CTR-128", "CHACHA20", "RC4", "256"] {
            assert_eq!(cipher_by_name(n), None, "{n}");
        }
        // Name -> id -> implementation chain for the negotiated suite.
        let (id, bits) = cipher_by_name("AES-256").unwrap();
        assert!(cipher(id, bits).is_some());
        let (id, bits) = cipher_by_name("3DES").unwrap();
        assert!(cipher(id, bits).is_none(), "3DES resolves by name but is not implemented");
    }

    #[test]
    fn integrity_names() {
        for n in [
            "SHA2-256", "sha2-256", "SHA256", "sha256", "SHA-256", "HMAC-SHA2-256", "HMAC_SHA256",
            "HMAC-SHA2-256-128", "AUTH_HMAC_SHA2_256_128", "auth-hmac-sha2-256-128",
            "SHA2_256", "SHA2 256", "INTEG_HMAC_SHA2_256_128",
        ] {
            assert_eq!(integrity_by_name(n), Some(AUTH_HMAC_SHA2_256_128), "{n}");
        }
        for n in ["SHA2-384", "SHA384", "HMAC-SHA2-384-192", "AUTH_HMAC_SHA2_384_192"] {
            assert_eq!(integrity_by_name(n), Some(AUTH_HMAC_SHA2_384_192), "{n}");
        }
        for n in ["SHA2-512", "SHA512", "HMAC-SHA2-512-256", "AUTH_HMAC_SHA2_512_256"] {
            assert_eq!(integrity_by_name(n), Some(AUTH_HMAC_SHA2_512_256), "{n}");
        }
        for n in ["SHA1", "sha1", "SHA-1", "HMAC-SHA1", "HMAC-SHA1-96", "AUTH_HMAC_SHA1_96"] {
            assert_eq!(integrity_by_name(n), Some(AUTH_HMAC_SHA1_96), "{n}");
        }
        assert_eq!(integrity_by_name("MD5"), Some(AUTH_HMAC_MD5_96));
        assert_eq!(integrity_by_name("HMAC-MD5-96"), Some(AUTH_HMAC_MD5_96));
        assert_eq!(integrity_by_name("AES-XCBC-96"), Some(AUTH_AES_XCBC_96));
        assert_eq!(integrity_by_name("NONE"), Some(AUTH_NONE));
        for n in ["", "SHA2", "SHA2-224", "SHA3-256", "SHA2-256-96", "AES-256"] {
            assert_eq!(integrity_by_name(n), None, "{n}");
        }
        // SHA1 resolves by name but is not implemented at lookup time.
        assert!(integrity(integrity_by_name("SHA1").unwrap()).is_none());
        assert!(integrity(integrity_by_name("SHA2-256").unwrap()).is_some());
    }

    #[test]
    fn prf_names() {
        for n in [
            "SHA2-256", "sha2-256", "SHA256", "SHA-256", "HMAC-SHA2-256", "PRF_HMAC_SHA2_256",
            "prf-hmac-sha256", "PRF-SHA2-256",
        ] {
            assert_eq!(prf_by_name(n), Some(PRF_HMAC_SHA2_256), "{n}");
        }
        assert_eq!(prf_by_name("SHA2-384"), Some(PRF_HMAC_SHA2_384));
        assert_eq!(prf_by_name("PRF_HMAC_SHA2_512"), Some(PRF_HMAC_SHA2_512));
        assert_eq!(prf_by_name("SHA1"), Some(PRF_HMAC_SHA1));
        assert_eq!(prf_by_name("HMAC-SHA1"), Some(PRF_HMAC_SHA1));
        assert_eq!(prf_by_name("MD5"), Some(PRF_HMAC_MD5));
        assert_eq!(prf_by_name("AES128-XCBC"), Some(PRF_AES128_XCBC));
        for n in ["", "SHA2", "SHA2-256-128", "SHA3-256", "AES-256"] {
            assert_eq!(prf_by_name(n), None, "{n}");
        }
        assert!(prf(prf_by_name("SHA2-256").unwrap()).is_some());
        assert!(prf(prf_by_name("SHA1").unwrap()).is_none());
    }

    #[test]
    fn transform_names_for_logs() {
        assert_eq!(transform_name(TT_ENCR, ENCR_AES_CBC), "ENCR/AES_CBC(12)");
        assert_eq!(transform_name(TT_PRF, PRF_HMAC_SHA2_256), "PRF/HMAC_SHA2_256(5)");
        assert_eq!(transform_name(TT_INTEG, AUTH_HMAC_SHA2_256_128), "INTEG/HMAC_SHA2_256_128(12)");
        assert_eq!(transform_name(TT_DH, DH_MODP_2048), "DH/MODP_2048(14)");
        assert_eq!(transform_name(TT_ESN, ESN_NO), "ESN/NO_ESN(0)");
        assert_eq!(transform_name(TT_ESN, ESN_YES), "ESN/ESN(1)");
        assert_eq!(transform_name(TT_ENCR, 999), "ENCR/UNKNOWN(999)");
        assert_eq!(transform_name(TT_DH, 21), "DH/UNKNOWN(21)");
        assert_eq!(transform_name(9, 1), "UNKNOWN_TYPE9/UNKNOWN(1)");
        assert_eq!(transform_name(0, 0), "UNKNOWN_TYPE0/UNKNOWN(0)");
    }

    #[test]
    fn negotiated_suite_assembles() {
        // The exact T-Mobile profile: AES-256 / SHA2-256 / SHA2-256 / group 14.
        let (cid, bits) = cipher_by_name("AES-256").unwrap();
        let suite = crate::crypto::Suite {
            cipher: cipher(cid, bits).unwrap(),
            integrity: integrity(integrity_by_name("SHA2-256").unwrap()).unwrap(),
            prf: prf(prf_by_name("SHA2-256").unwrap()).unwrap(),
            dh: dh(14),
        };
        assert_eq!(suite.cipher.key_len(), 32);
        assert_eq!(suite.integrity.key_len(), 32);
        assert_eq!(suite.prf.key_len(), 32);
        let total = suite.prf.key_len()
            + 2 * suite.integrity.key_len()
            + 2 * suite.cipher.key_len()
            + 2 * suite.prf.key_len();
        assert_eq!(total, 224);
        assert_eq!(suite.dh.as_ref().unwrap().public_len(), 256);
    }
}
