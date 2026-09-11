//! HMAC-SHA2 integrity (`AUTH_HMAC_SHA2_256_128` / `_384_192` / `_512_256`, RFC 4868)
//! and PRF (`PRF_HMAC_SHA2_256` / `_384` / `_512`) transforms.
//!
//! Integrity keys are the full hash length (32/48/64); only the OUTPUT is
//! truncated to half the hash length (16/24/32). ICV verification is
//! constant-time via `subtle`. The PRFs are plain HMAC with untruncated output;
//! `prf+` comes from the default method on [`Prf`].

use crate::crypto::{Integrity, Prf};
use crate::ike::constants::{
    AUTH_HMAC_SHA2_256_128, AUTH_HMAC_SHA2_384_192, AUTH_HMAC_SHA2_512_256, PRF_HMAC_SHA2_256,
    PRF_HMAC_SHA2_384, PRF_HMAC_SHA2_512,
};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

macro_rules! hmac_full {
    ($digest:ty, $key:expr, $data:expr) => {{
        // HMAC accepts any key length (RFC 2104): longer keys are hashed, shorter
        // ones zero-padded — `new_from_slice` therefore cannot fail for HMAC.
        let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice($key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update($data);
        mac.finalize().into_bytes().to_vec()
    }};
}

macro_rules! define_integ {
    ($name:ident, $digest:ty, $id:expr, $key_len:expr, $icv_len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl Integrity for $name {
            fn transform_id(&self) -> u16 {
                $id
            }

            fn key_len(&self) -> usize {
                $key_len
            }

            fn icv_len(&self) -> usize {
                $icv_len
            }

            fn compute(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                let mut mac = hmac_full!($digest, key, data);
                mac.truncate($icv_len);
                mac
            }

            fn verify(&self, key: &[u8], data: &[u8], icv: &[u8]) -> bool {
                let expected = self.compute(key, data);
                if icv.len() != expected.len() {
                    return false;
                }
                expected.ct_eq(icv).into()
            }
        }
    };
}

macro_rules! define_prf {
    ($name:ident, $digest:ty, $id:expr, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl Prf for $name {
            fn transform_id(&self) -> u16 {
                $id
            }

            fn key_len(&self) -> usize {
                $len
            }

            fn output_len(&self) -> usize {
                $len
            }

            fn prf(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                hmac_full!($digest, key, data)
            }
        }
    };
}

define_integ!(
    HmacSha256Integ,
    Sha256,
    AUTH_HMAC_SHA2_256_128,
    32,
    16,
    "`AUTH_HMAC_SHA2_256_128`: HMAC-SHA-256 with a 32-byte key, output truncated to 16 bytes."
);
define_integ!(
    HmacSha384Integ,
    Sha384,
    AUTH_HMAC_SHA2_384_192,
    48,
    24,
    "`AUTH_HMAC_SHA2_384_192`: HMAC-SHA-384 with a 48-byte key, output truncated to 24 bytes."
);
define_integ!(
    HmacSha512Integ,
    Sha512,
    AUTH_HMAC_SHA2_512_256,
    64,
    32,
    "`AUTH_HMAC_SHA2_512_256`: HMAC-SHA-512 with a 64-byte key, output truncated to 32 bytes."
);

define_prf!(
    HmacSha256Prf,
    Sha256,
    PRF_HMAC_SHA2_256,
    32,
    "`PRF_HMAC_SHA2_256`: HMAC-SHA-256, 32-byte preferred key, 32-byte output."
);
define_prf!(
    HmacSha384Prf,
    Sha384,
    PRF_HMAC_SHA2_384,
    48,
    "`PRF_HMAC_SHA2_384`: HMAC-SHA-384, 48-byte preferred key, 48-byte output."
);
define_prf!(
    HmacSha512Prf,
    Sha512,
    PRF_HMAC_SHA2_512,
    64,
    "`PRF_HMAC_SHA2_512`: HMAC-SHA-512, 64-byte preferred key, 64-byte output."
);

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2.
    const KEY: &[u8] = b"Jefe";
    const DATA: &[u8] = b"what do ya want for nothing?";
    const SHA256_MAC: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const SHA384_MAC: &str = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
    const SHA512_MAC: &str = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";

    #[test]
    fn hmac_sha256_prf_kat_rfc4231_tc2() {
        let p = HmacSha256Prf;
        assert_eq!(hex::encode(p.prf(KEY, DATA)), SHA256_MAC);
        assert_eq!(p.transform_id(), PRF_HMAC_SHA2_256);
        assert_eq!(p.key_len(), 32);
        assert_eq!(p.output_len(), 32);
    }

    #[test]
    fn hmac_sha384_512_prf_kat_rfc4231_tc2() {
        assert_eq!(hex::encode(HmacSha384Prf.prf(KEY, DATA)), SHA384_MAC);
        assert_eq!(hex::encode(HmacSha512Prf.prf(KEY, DATA)), SHA512_MAC);
        assert_eq!(HmacSha384Prf.transform_id(), PRF_HMAC_SHA2_384);
        assert_eq!(HmacSha512Prf.transform_id(), PRF_HMAC_SHA2_512);
        assert_eq!(HmacSha384Prf.output_len(), 48);
        assert_eq!(HmacSha512Prf.output_len(), 64);
    }

    #[test]
    fn hmac_sha256_prf_kat_rfc4231_tc1() {
        // key = 20 x 0x0b, data = "Hi There".
        let key = [0x0bu8; 20];
        let out = HmacSha256Prf.prf(&key, b"Hi There");
        assert_eq!(
            hex::encode(out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn integ_truncation_and_verify() {
        let i = HmacSha256Integ;
        assert_eq!(i.transform_id(), AUTH_HMAC_SHA2_256_128);
        assert_eq!(i.key_len(), 32);
        assert_eq!(i.icv_len(), 16);
        let icv = i.compute(KEY, DATA);
        assert_eq!(icv.len(), 16);
        assert_eq!(hex::encode(&icv), &SHA256_MAC[..32]);
        assert!(i.verify(KEY, DATA, &icv));

        // Tampered ICV, wrong length, wrong key, wrong data.
        let mut bad = icv.clone();
        bad[15] ^= 1;
        assert!(!i.verify(KEY, DATA, &bad));
        assert!(!i.verify(KEY, DATA, &icv[..15]));
        let full = hex::decode(SHA256_MAC).unwrap();
        assert!(!i.verify(KEY, DATA, &full), "untruncated MAC must not verify");
        assert!(!i.verify(b"Jeff", DATA, &icv));
        assert!(!i.verify(KEY, b"what do ya want for nothing!", &icv));
        assert!(!i.verify(KEY, DATA, &[]));
    }

    #[test]
    fn integ_384_512_metadata_and_truncation() {
        let i384 = HmacSha384Integ;
        assert_eq!(i384.transform_id(), AUTH_HMAC_SHA2_384_192);
        assert_eq!((i384.key_len(), i384.icv_len()), (48, 24));
        let icv = i384.compute(KEY, DATA);
        assert_eq!(hex::encode(&icv), &SHA384_MAC[..48]);
        assert!(i384.verify(KEY, DATA, &icv));

        let i512 = HmacSha512Integ;
        assert_eq!(i512.transform_id(), AUTH_HMAC_SHA2_512_256);
        assert_eq!((i512.key_len(), i512.icv_len()), (64, 32));
        let icv = i512.compute(KEY, DATA);
        assert_eq!(hex::encode(&icv), &SHA512_MAC[..64]);
        assert!(i512.verify(KEY, DATA, &icv));
    }

    #[test]
    fn prf_plus_matches_hand_expansion() {
        // T1 = prf(K, S | 0x01); T2 = prf(K, T1 | S | 0x02); output = (T1 | T2)[..40].
        // Constants computed independently with Python's hmac module.
        let p = HmacSha256Prf;
        let t1_expected = "86a83299a0c0da43781616672c35abfe1b7fc6bb39ee07989fde386bd120b9d0";
        let t2_expected = "e033caafabcd10f22f194b4f7c8b6a0c60d10bdd34648387a35f2331ea3e0ade";

        let mut in1 = DATA.to_vec();
        in1.push(0x01);
        let t1 = p.prf(KEY, &in1);
        assert_eq!(hex::encode(&t1), t1_expected);
        let mut in2 = t1.clone();
        in2.extend_from_slice(DATA);
        in2.push(0x02);
        let t2 = p.prf(KEY, &in2);
        assert_eq!(hex::encode(&t2), t2_expected);

        let out = p.prf_plus(KEY, DATA, 40);
        assert_eq!(out.len(), 40);
        assert_eq!(&out[..32], &t1[..]);
        assert_eq!(&out[32..], &t2[..8]);
        assert_eq!(
            hex::encode(&out),
            format!("{t1_expected}{}", &t2_expected[..16])
        );

        // Exactly one block, and a whole-block boundary, and zero.
        assert_eq!(p.prf_plus(KEY, DATA, 32), t1);
        let two = p.prf_plus(KEY, DATA, 64);
        assert_eq!(&two[32..], &t2[..]);
        assert!(p.prf_plus(KEY, DATA, 0).is_empty());
    }

    #[test]
    fn prf_plus_ike_keymat_sizes() {
        // 7 x 32 = 224 bytes for the IKE SA; 4 x 32 = 128 for a child SA.
        let p = HmacSha256Prf;
        let seed = crate::crypto::random_bytes(80);
        let k = crate::crypto::random_bytes(32);
        let ike = p.prf_plus(&k, &seed, 224);
        assert_eq!(ike.len(), 224);
        let child = p.prf_plus(&k, &seed, 128);
        assert_eq!(child.len(), 128);
        // prf+ is a prefix-consistent stream.
        assert_eq!(&ike[..128], &child[..]);
    }

    #[test]
    fn any_key_length_accepted() {
        // 0-byte, 31-byte, 33-byte and 200-byte keys all work (HMAC semantics).
        for n in [0usize, 31, 33, 200] {
            let k = vec![0x5au8; n];
            assert_eq!(HmacSha256Prf.prf(&k, b"x").len(), 32);
            assert_eq!(HmacSha256Integ.compute(&k, b"x").len(), 16);
        }
    }
}
