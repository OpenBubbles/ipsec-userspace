//! IKE SA and Child SA key derivation (RFC 7296 §2.13, §2.14, §2.17, §2.18).
//!
//! Mirrors the AOSP `SaRecord` / `IkeMacPrf` behaviour byte for byte (see
//! `docs/AOSP_FACTS.md`, area "key derivation"):
//!
//! ```text
//! SKEYSEED        = prf(Ni | Nr, g^ir)                       // key = full-length nonces, data = g^ir
//! KEYMAT(IKE)     = prf+(SKEYSEED, Ni | Nr | SPIi(8 BE) | SPIr(8 BE))
//!                 = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
//! SKEYSEED(rekey) = prf(SK_d_old, g^ir | Ni | Nr)            // DH secret FIRST on rekey
//! KEYMAT(child)   = prf+(SK_d, [g^ir |] Ni | Nr)
//!                 = encr_i2r | integ_i2r | encr_r2i | integ_r2i
//! ```
//!
//! Nonces are used at their received length (no truncation — that only applies to
//! AES-XCBC/CMAC PRFs, which this crate does not implement). `g^ir` must be the
//! fixed-width, left-zero-padded value produced by [`crate::crypto::DhKeyPair`].

use crate::crypto::{Cipher, Integrity, Prf, Suite};
use std::fmt;

/// The seven IKE SA keys of RFC 7296 §2.14, in derivation order.
///
/// We are always the initiator, so messages we send use `sk_ei` / `sk_ai` and
/// messages from the gateway are verified/decrypted with `sk_er` / `sk_ar`.
/// All fields are zeroized on drop; `Debug` prints lengths only.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct IkeKeys {
    pub sk_d: Vec<u8>,
    pub sk_ai: Vec<u8>,
    pub sk_ar: Vec<u8>,
    pub sk_ei: Vec<u8>,
    pub sk_er: Vec<u8>,
    pub sk_pi: Vec<u8>,
    pub sk_pr: Vec<u8>,
}

impl fmt::Debug for IkeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IkeKeys")
            .field("sk_d", &format_args!("[{} bytes]", self.sk_d.len()))
            .field("sk_ai", &format_args!("[{} bytes]", self.sk_ai.len()))
            .field("sk_ar", &format_args!("[{} bytes]", self.sk_ar.len()))
            .field("sk_ei", &format_args!("[{} bytes]", self.sk_ei.len()))
            .field("sk_er", &format_args!("[{} bytes]", self.sk_er.len()))
            .field("sk_pi", &format_args!("[{} bytes]", self.sk_pi.len()))
            .field("sk_pr", &format_args!("[{} bytes]", self.sk_pr.len()))
            .finish()
    }
}

impl IkeKeys {
    /// Total KEYMAT length for `suite` (224 for the AES-256 / HMAC-SHA2-256 / PRF-SHA2-256 suite).
    pub fn keymat_len(suite: &Suite) -> usize {
        3 * suite.prf.key_len() + 2 * suite.integrity.key_len() + 2 * suite.cipher.key_len()
    }
}

/// The four Child SA (ESP) keys of RFC 7296 §2.17, in derivation order.
///
/// Initiator = us: outbound ESP uses (`encr_i2r`, `integ_i2r`) with the responder's
/// SPI; inbound uses (`encr_r2i`, `integ_r2i`) with our SPI.
/// All fields are zeroized on drop; `Debug` prints lengths only.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct ChildKeys {
    pub encr_i2r: Vec<u8>,
    pub integ_i2r: Vec<u8>,
    pub encr_r2i: Vec<u8>,
    pub integ_r2i: Vec<u8>,
}

impl fmt::Debug for ChildKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildKeys")
            .field("encr_i2r", &format_args!("[{} bytes]", self.encr_i2r.len()))
            .field("integ_i2r", &format_args!("[{} bytes]", self.integ_i2r.len()))
            .field("encr_r2i", &format_args!("[{} bytes]", self.encr_r2i.len()))
            .field("integ_r2i", &format_args!("[{} bytes]", self.integ_r2i.len()))
            .finish()
    }
}

impl ChildKeys {
    /// Total KEYMAT length (128 for AES-256 + HMAC-SHA2-256-128).
    pub fn keymat_len(cipher: &dyn Cipher, integrity: &dyn Integrity) -> usize {
        2 * cipher.key_len() + 2 * integrity.key_len()
    }
}

/// `SKEYSEED = prf(Ni | Nr, g^ir)` (RFC 7296 §2.14). Exposed for tests / diagnostics.
pub fn skeyseed(prf: &dyn Prf, nonce_i: &[u8], nonce_r: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(nonce_i.len() + nonce_r.len());
    key.extend_from_slice(nonce_i);
    key.extend_from_slice(nonce_r);
    let out = prf.prf(&key, shared_secret);
    zeroize::Zeroize::zeroize(&mut key);
    out
}

/// Rekey `SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)` (RFC 7296 §2.18). DH secret first.
pub fn skeyseed_rekey(prf: &dyn Prf, sk_d_old: &[u8], shared_secret_new: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(shared_secret_new.len() + nonce_i.len() + nonce_r.len());
    data.extend_from_slice(shared_secret_new);
    data.extend_from_slice(nonce_i);
    data.extend_from_slice(nonce_r);
    let out = prf.prf(sk_d_old, &data);
    zeroize::Zeroize::zeroize(&mut data);
    out
}

/// prf+ seed for the IKE SA: `Ni | Nr | SPIi(8 BE) | SPIr(8 BE)`.
fn ike_prf_plus_seed(nonce_i: &[u8], nonce_r: &[u8], spi_i: u64, spi_r: u64) -> Vec<u8> {
    let mut seed = Vec::with_capacity(nonce_i.len() + nonce_r.len() + 16);
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);
    seed.extend_from_slice(&spi_i.to_be_bytes());
    seed.extend_from_slice(&spi_r.to_be_bytes());
    seed
}

/// Slice KEYMAT into the seven IKE keys (order: d, ai, ar, ei, er, pi, pr).
fn split_ike_keymat(suite: &Suite, skeyseed: &[u8], seed: &[u8]) -> IkeKeys {
    let prf_len = suite.prf.key_len();
    let integ_len = suite.integrity.key_len();
    let encr_len = suite.cipher.key_len();
    let total = IkeKeys::keymat_len(suite);
    let mut keymat = suite.prf.prf_plus(skeyseed, seed, total);
    let mut cursor = KeymatCursor::new(&keymat);
    let keys = IkeKeys {
        sk_d: cursor.take(prf_len),
        sk_ai: cursor.take(integ_len),
        sk_ar: cursor.take(integ_len),
        sk_ei: cursor.take(encr_len),
        sk_er: cursor.take(encr_len),
        sk_pi: cursor.take(prf_len),
        sk_pr: cursor.take(prf_len),
    };
    debug_assert!(cursor.remaining() == 0, "IKE KEYMAT not fully consumed");
    zeroize::Zeroize::zeroize(&mut keymat);
    log::debug!(
        "derived IKE SA keys: SK_d={} SK_a*={} SK_e*={} SK_p*={} (KEYMAT {} bytes)",
        prf_len,
        integ_len,
        encr_len,
        prf_len,
        total
    );
    keys
}

/// Derive the initial IKE SA keys (RFC 7296 §2.14).
///
/// `nonce_i` / `nonce_r` are the nonce payload DATA (no generic header), at their
/// received length; `shared_secret` is the fixed-width `g^ir`; SPIs are the values
/// from the IKE_SA_INIT response header (SPIr is the responder's real SPI, not 0).
pub fn derive_ike_keys(suite: &Suite, nonce_i: &[u8], nonce_r: &[u8], shared_secret: &[u8], spi_i: u64, spi_r: u64) -> IkeKeys {
    let mut skeyseed = skeyseed(suite.prf.as_ref(), nonce_i, nonce_r, shared_secret);
    let seed = ike_prf_plus_seed(nonce_i, nonce_r, spi_i, spi_r);
    let keys = split_ike_keymat(suite, &skeyseed, &seed);
    zeroize::Zeroize::zeroize(&mut skeyseed);
    keys
}

/// IKE SA rekey (RFC 7296 §2.18): `SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)`, then
/// prf+ over `Ni | Nr | SPIi | SPIr` of the NEW SA, sliced exactly like [`derive_ike_keys`].
/// `nonce_i` / `nonce_r` are the CREATE_CHILD_SA exchange's nonces.
pub fn derive_ike_keys_rekey(
    suite: &Suite,
    sk_d_old: &[u8],
    shared_secret_new: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    spi_i: u64,
    spi_r: u64,
) -> IkeKeys {
    let mut skeyseed = skeyseed_rekey(suite.prf.as_ref(), sk_d_old, shared_secret_new, nonce_i, nonce_r);
    let seed = ike_prf_plus_seed(nonce_i, nonce_r, spi_i, spi_r);
    let keys = split_ike_keymat(suite, &skeyseed, &seed);
    zeroize::Zeroize::zeroize(&mut skeyseed);
    keys
}

/// Derive Child SA keys (RFC 7296 §2.17): `KEYMAT = prf+(SK_d, [g^ir |] Ni | Nr)`,
/// sliced as `encr_i2r | integ_i2r | encr_r2i | integ_r2i`.
///
/// For the child created in IKE_AUTH, `nonce_i`/`nonce_r` are the IKE_SA_INIT nonces
/// and `pfs_secret` is `None`. For a CREATE_CHILD_SA rekey they are that exchange's
/// nonces, with `pfs_secret = Some(g^ir)` only if a KE payload was exchanged.
pub fn derive_child_keys(
    cipher: &dyn Cipher,
    integrity: &dyn Integrity,
    prf: &dyn Prf,
    sk_d: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    pfs_secret: Option<&[u8]>,
) -> ChildKeys {
    let pfs = pfs_secret.unwrap_or(&[]);
    let mut seed = Vec::with_capacity(pfs.len() + nonce_i.len() + nonce_r.len());
    seed.extend_from_slice(pfs);
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);

    let encr_len = cipher.key_len();
    let integ_len = integrity.key_len();
    let total = ChildKeys::keymat_len(cipher, integrity);
    let mut keymat = prf.prf_plus(sk_d, &seed, total);
    let mut cursor = KeymatCursor::new(&keymat);
    let keys = ChildKeys {
        encr_i2r: cursor.take(encr_len),
        integ_i2r: cursor.take(integ_len),
        encr_r2i: cursor.take(encr_len),
        integ_r2i: cursor.take(integ_len),
    };
    debug_assert!(cursor.remaining() == 0, "child KEYMAT not fully consumed");
    zeroize::Zeroize::zeroize(&mut keymat);
    zeroize::Zeroize::zeroize(&mut seed);
    log::debug!(
        "derived child SA keys: encr={} integ={} pfs={} (KEYMAT {} bytes)",
        encr_len,
        integ_len,
        pfs_secret.is_some(),
        total
    );
    keys
}

/// Sequential slicer over a KEYMAT buffer. `prf_plus` always returns exactly the
/// requested length, so `take` cannot run past the end; it is still bounds-safe.
struct KeymatCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> KeymatCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        KeymatCursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let end = self.pos.saturating_add(n).min(self.buf.len());
        let out = self.buf.get(self.pos..end).unwrap_or(&[]).to_vec();
        self.pos = end;
        out
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hmac_sha2::{HmacSha256Integ, HmacSha256Prf};
    use crate::ike::constants::ENCR_AES_CBC;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::sync::Arc;

    /// Test-only cipher with the AES-256 key geometry, so these tests do not depend
    /// on the real AES implementation.
    struct FakeCipher256;
    impl Cipher for FakeCipher256 {
        fn transform_id(&self) -> u16 {
            ENCR_AES_CBC
        }
        fn key_len(&self) -> usize {
            32
        }
        fn block_len(&self) -> usize {
            16
        }
        fn iv_len(&self) -> usize {
            16
        }
        fn key_len_attr_bits(&self) -> Option<u16> {
            Some(256)
        }
        fn encrypt(&self, _key: &[u8], _iv: &[u8], _data: &mut [u8]) -> crate::Result<()> {
            Ok(())
        }
        fn decrypt(&self, _key: &[u8], _iv: &[u8], _data: &mut [u8]) -> crate::Result<()> {
            Ok(())
        }
    }

    fn suite() -> Suite {
        Suite {
            cipher: Arc::new(FakeCipher256),
            integrity: Arc::new(HmacSha256Integ),
            prf: Arc::new(HmacSha256Prf),
            dh: None,
        }
    }

    fn hmac256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }

    fn ni() -> Vec<u8> {
        (0u8..32).collect()
    }
    fn nr() -> Vec<u8> {
        (32u8..64).collect()
    }
    fn gir() -> Vec<u8> {
        vec![0xab; 256]
    }
    const SPI_I: u64 = 0x1122334455667788;
    const SPI_R: u64 = 0x99aabbccddeeff00;

    #[test]
    fn ike_key_lengths_total_224() {
        let s = suite();
        assert_eq!(IkeKeys::keymat_len(&s), 224);
        let k = derive_ike_keys(&s, &ni(), &nr(), &gir(), SPI_I, SPI_R);
        for v in [&k.sk_d, &k.sk_ai, &k.sk_ar, &k.sk_ei, &k.sk_er, &k.sk_pi, &k.sk_pr] {
            assert_eq!(v.len(), 32);
        }
        let all: Vec<&Vec<u8>> = vec![&k.sk_d, &k.sk_ai, &k.sk_ar, &k.sk_ei, &k.sk_er, &k.sk_pi, &k.sk_pr];
        // all seven keys are distinct
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "keys {i} and {j} identical");
            }
        }
    }

    #[test]
    fn child_key_lengths_total_128() {
        assert_eq!(ChildKeys::keymat_len(&FakeCipher256, &HmacSha256Integ), 128);
        let sk_d = vec![7u8; 32];
        let k = derive_child_keys(&FakeCipher256, &HmacSha256Integ, &HmacSha256Prf, &sk_d, &ni(), &nr(), None);
        assert_eq!(k.encr_i2r.len(), 32);
        assert_eq!(k.integ_i2r.len(), 32);
        assert_eq!(k.encr_r2i.len(), 32);
        assert_eq!(k.integ_r2i.len(), 32);
        assert_ne!(k.encr_i2r, k.encr_r2i);
        assert_ne!(k.integ_i2r, k.integ_r2i);
    }

    #[test]
    fn determinism_and_sensitivity() {
        let s = suite();
        let a = derive_ike_keys(&s, &ni(), &nr(), &gir(), SPI_I, SPI_R);
        let b = derive_ike_keys(&s, &ni(), &nr(), &gir(), SPI_I, SPI_R);
        assert_eq!(a.sk_d, b.sk_d);
        assert_eq!(a.sk_pr, b.sk_pr);
        // Changing SPIr changes prf+ output (but not SKEYSEED).
        let c = derive_ike_keys(&s, &ni(), &nr(), &gir(), SPI_I, SPI_R ^ 1);
        assert_ne!(a.sk_d, c.sk_d);
        // Swapping nonces changes SKEYSEED.
        let d = derive_ike_keys(&s, &nr(), &ni(), &gir(), SPI_I, SPI_R);
        assert_ne!(a.sk_d, d.sk_d);
        // Changing g^ir changes everything.
        let mut g2 = gir();
        g2[0] ^= 1;
        let e = derive_ike_keys(&s, &ni(), &nr(), &g2, SPI_I, SPI_R);
        assert_ne!(a.sk_d, e.sk_d);
    }

    #[test]
    fn skeyseed_matches_hmac_directly_and_python_kat() {
        let mut key = ni();
        key.extend_from_slice(&nr());
        let expected = hmac256(&key, &gir());
        let got = skeyseed(&HmacSha256Prf, &ni(), &nr(), &gir());
        assert_eq!(got, expected);
        // Independently computed with Python hmac/hashlib.
        assert_eq!(hex::encode(&got), "a62db80848de39e0f960cb8a27f2a3ad53260c10d04ca298350341ffb40ae93c");
    }

    #[test]
    fn prf_plus_chunk_boundaries_and_slicing() {
        let s = suite();
        let mut key = ni();
        key.extend_from_slice(&nr());
        let skeyseed = hmac256(&key, &gir());
        let mut seed = ni();
        seed.extend_from_slice(&nr());
        seed.extend_from_slice(&SPI_I.to_be_bytes());
        seed.extend_from_slice(&SPI_R.to_be_bytes());
        assert_eq!(seed.len(), 80);

        // T1 = prf(K, S|01), T2 = prf(K, T1|S|02), ... T7
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        let mut prev: Vec<u8> = Vec::new();
        for i in 1u8..=7 {
            let mut input = prev.clone();
            input.extend_from_slice(&seed);
            input.push(i);
            prev = hmac256(&skeyseed, &input);
            blocks.push(prev.clone());
        }
        assert_eq!(hex::encode(&blocks[0]), "bf5b47e849eed3628437a785bfa80d40e415fcaf9df6759191857b4c28a698dd");
        assert_eq!(hex::encode(&blocks[1]), "46264733792066d14e7bbe3cc4981cde65884ca6d0874bd64ee80c2a469040fa");

        let k = derive_ike_keys(&s, &ni(), &nr(), &gir(), SPI_I, SPI_R);
        assert_eq!(k.sk_d, blocks[0]);
        assert_eq!(k.sk_ai, blocks[1]);
        assert_eq!(k.sk_ar, blocks[2]);
        assert_eq!(k.sk_ei, blocks[3]);
        assert_eq!(k.sk_er, blocks[4]);
        assert_eq!(k.sk_pi, blocks[5]);
        assert_eq!(k.sk_pr, blocks[6]);

        // prf+ truncation at a non-block boundary: first 50 bytes == T1 | T2[..18]
        let out = HmacSha256Prf.prf_plus(&skeyseed, &seed, 50);
        assert_eq!(out.len(), 50);
        assert_eq!(&out[..32], &blocks[0][..]);
        assert_eq!(&out[32..], &blocks[1][..18]);
    }

    #[test]
    fn child_keys_without_pfs_seed_is_ni_nr() {
        let sk_d = vec![0x5a; 32];
        let mut seed = ni();
        seed.extend_from_slice(&nr());
        let keymat = HmacSha256Prf.prf_plus(&sk_d, &seed, 128);
        let k = derive_child_keys(&FakeCipher256, &HmacSha256Integ, &HmacSha256Prf, &sk_d, &ni(), &nr(), None);
        assert_eq!(k.encr_i2r, &keymat[0..32]);
        assert_eq!(k.integ_i2r, &keymat[32..64]);
        assert_eq!(k.encr_r2i, &keymat[64..96]);
        assert_eq!(k.integ_r2i, &keymat[96..128]);
        // T1 directly: prf(SK_d, Ni|Nr|01)
        let mut t1_in = seed.clone();
        t1_in.push(1);
        assert_eq!(k.encr_i2r, hmac256(&sk_d, &t1_in));
    }

    #[test]
    fn child_keys_with_pfs_seed_is_gir_ni_nr() {
        let sk_d = vec![0x5a; 32];
        let g = vec![0x11; 256];
        let mut seed = g.clone();
        seed.extend_from_slice(&ni());
        seed.extend_from_slice(&nr());
        let keymat = HmacSha256Prf.prf_plus(&sk_d, &seed, 128);
        let k = derive_child_keys(&FakeCipher256, &HmacSha256Integ, &HmacSha256Prf, &sk_d, &ni(), &nr(), Some(&g));
        assert_eq!(k.encr_i2r, &keymat[0..32]);
        assert_eq!(k.integ_r2i, &keymat[96..128]);
        let no_pfs = derive_child_keys(&FakeCipher256, &HmacSha256Integ, &HmacSha256Prf, &sk_d, &ni(), &nr(), None);
        assert_ne!(k.encr_i2r, no_pfs.encr_i2r);
    }

    #[test]
    fn rekey_skeyseed_is_prf_skd_gir_ni_nr() {
        let s = suite();
        let sk_d_old = vec![0x33; 32];
        let g = vec![0x44; 256];
        let mut data = g.clone();
        data.extend_from_slice(&ni());
        data.extend_from_slice(&nr());
        let expected_seed = hmac256(&sk_d_old, &data);
        assert_eq!(skeyseed_rekey(&HmacSha256Prf, &sk_d_old, &g, &ni(), &nr()), expected_seed);

        let mut seed = ni();
        seed.extend_from_slice(&nr());
        seed.extend_from_slice(&SPI_I.to_be_bytes());
        seed.extend_from_slice(&SPI_R.to_be_bytes());
        let keymat = HmacSha256Prf.prf_plus(&expected_seed, &seed, 224);
        let k = derive_ike_keys_rekey(&s, &sk_d_old, &g, &ni(), &nr(), SPI_I, SPI_R);
        assert_eq!(k.sk_d, &keymat[0..32]);
        assert_eq!(k.sk_pr, &keymat[192..224]);
        // Differs from the initial derivation with the same inputs.
        let initial = derive_ike_keys(&s, &ni(), &nr(), &g, SPI_I, SPI_R);
        assert_ne!(k.sk_d, initial.sk_d);
    }

    #[test]
    fn variable_length_nonces_are_used_untruncated() {
        let s = suite();
        let short_nr: Vec<u8> = (0u8..16).collect();
        let long_nr: Vec<u8> = (0u8..=255).collect(); // 256 bytes
        let a = derive_ike_keys(&s, &ni(), &short_nr, &gir(), SPI_I, SPI_R);
        let b = derive_ike_keys(&s, &ni(), &long_nr, &gir(), SPI_I, SPI_R);
        assert_ne!(a.sk_d, b.sk_d);
        // Cross-check with the long nonce: SKEYSEED key = Ni | Nr(256)
        let mut key = ni();
        key.extend_from_slice(&long_nr);
        let ss = hmac256(&key, &gir());
        let mut seed = ni();
        seed.extend_from_slice(&long_nr);
        seed.extend_from_slice(&SPI_I.to_be_bytes());
        seed.extend_from_slice(&SPI_R.to_be_bytes());
        let mut t1 = seed.clone();
        t1.push(1);
        assert_eq!(b.sk_d, hmac256(&ss, &t1));
    }

    #[test]
    fn debug_does_not_leak_key_bytes() {
        let s = suite();
        let k = derive_ike_keys(&s, &ni(), &nr(), &gir(), SPI_I, SPI_R);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("[32 bytes]"));
        assert!(!dbg.contains(&hex::encode(&k.sk_d)));
        let c = derive_child_keys(&FakeCipher256, &HmacSha256Integ, &HmacSha256Prf, &k.sk_d, &ni(), &nr(), None);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("encr_i2r: [32 bytes]"));
    }

    #[test]
    fn keymat_cursor_is_bounds_safe() {
        let buf = [1u8, 2, 3];
        let mut c = KeymatCursor::new(&buf);
        assert_eq!(c.take(2), vec![1, 2]);
        assert_eq!(c.take(5), vec![3]);
        assert_eq!(c.take(1), Vec::<u8>::new());
        assert_eq!(c.remaining(), 0);
    }
}
