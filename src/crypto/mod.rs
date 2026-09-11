//! Cryptographic primitives behind trait objects, selected by IKEv2 transform id.
//!
//! The protocol code never names an algorithm: it asks the [`registry`] for a
//! `dyn Cipher` / `dyn Integrity` / `dyn Prf` / `dyn DhGroup` by transform id (or
//! by the carrier-bundle name, e.g. `"AES-256"`, `"SHA2-256"`, DH group `14`).
//! Adding an algorithm = implement the trait + register it; no protocol changes.
//!
//! Implemented today (exactly what the T-Mobile ePDG profile negotiates):
//! - `ENCR_AES_CBC` 256-bit  ([`aes_cbc`])
//! - `AUTH_HMAC_SHA2_256_128` ([`hmac_sha2`])
//! - `PRF_HMAC_SHA2_256`      ([`hmac_sha2`])
//! - DH group 14, 2048-bit MODP ([`dh_modp`]; groups 2/5/15/16 primes included)

pub mod aes_cbc;
pub mod dh_modp;
pub mod hmac_sha2;
pub mod registry;

use crate::Result;
use std::sync::Arc;

/// A block/stream cipher for IKE SK payloads and ESP (RFC 7296 §3.14, RFC 4303).
/// Implementations are stateless; keys are passed per call.
pub trait Cipher: Send + Sync {
    /// IKEv2 ENCR transform id (e.g. 12 = ENCR_AES_CBC).
    fn transform_id(&self) -> u16;
    /// Key length in bytes (e.g. 32 for AES-256).
    fn key_len(&self) -> usize;
    /// Cipher block size in bytes (plaintext must be padded to a multiple of this). 1 for stream ciphers.
    fn block_len(&self) -> usize;
    /// IV length in bytes carried on the wire before the ciphertext.
    fn iv_len(&self) -> usize;
    /// Key-length attribute to advertise in the SA proposal, in BITS, if this cipher
    /// takes one (AES does: 256). `None` for fixed-key ciphers (3DES).
    fn key_len_attr_bits(&self) -> Option<u16>;
    /// Encrypt in place. `data.len()` must be a multiple of `block_len()`.
    fn encrypt(&self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()>;
    /// Decrypt in place. `data.len()` must be a multiple of `block_len()`.
    fn decrypt(&self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()>;
}

/// An integrity (MAC) algorithm with truncated output (RFC 7296 §3.3.2 INTEG).
pub trait Integrity: Send + Sync {
    /// IKEv2 INTEG transform id (e.g. 12 = AUTH_HMAC_SHA2_256_128).
    fn transform_id(&self) -> u16;
    /// MAC key length in bytes (32 for HMAC-SHA2-256-128 — full hash length, NOT the truncated 16).
    fn key_len(&self) -> usize;
    /// Truncated output (ICV) length in bytes (16 for HMAC-SHA2-256-128).
    fn icv_len(&self) -> usize;
    /// Compute the truncated MAC.
    fn compute(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
    /// Constant-time verification of a truncated MAC.
    fn verify(&self, key: &[u8], data: &[u8], icv: &[u8]) -> bool;
}

/// A pseudo-random function (RFC 7296 §2.13). `prf_plus` is the prf+ expansion of §2.13.
pub trait Prf: Send + Sync {
    /// IKEv2 PRF transform id (e.g. 5 = PRF_HMAC_SHA2_256).
    fn transform_id(&self) -> u16;
    /// Preferred/fixed key length in bytes used when deriving SK_d/SK_pi/SK_pr (32 for HMAC-SHA2-256).
    fn key_len(&self) -> usize;
    /// Output length in bytes (32 for HMAC-SHA2-256).
    fn output_len(&self) -> usize;
    /// prf(key, data). HMAC-based PRFs accept any key length.
    fn prf(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
    /// prf+ (K, S) = T1 | T2 | T3 ... truncated to `out_len`, where
    /// T1 = prf(K, S | 0x01), T2 = prf(K, T1 | S | 0x02), ... (RFC 7296 §2.13).
    fn prf_plus(&self, key: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len + self.output_len());
        let mut prev: Vec<u8> = Vec::new();
        let mut i: u8 = 1;
        while out.len() < out_len {
            let mut input = Vec::with_capacity(prev.len() + seed.len() + 1);
            input.extend_from_slice(&prev);
            input.extend_from_slice(seed);
            input.push(i);
            prev = self.prf(key, &input);
            out.extend_from_slice(&prev);
            i = i.checked_add(1).expect("prf+ counter overflow (>255 blocks)");
        }
        out.truncate(out_len);
        out
    }
}

/// A Diffie-Hellman group (RFC 7296 §3.3.2 D-H). `generate` makes a fresh ephemeral key pair.
pub trait DhGroup: Send + Sync {
    /// IKEv2 D-H group id (e.g. 14).
    fn group_id(&self) -> u16;
    /// Length in bytes of the public value / shared secret on the wire (256 for group 14).
    fn public_len(&self) -> usize;
    fn generate(&self) -> Result<Box<dyn DhKeyPair>>;
}

/// An ephemeral DH key pair.
pub trait DhKeyPair: Send {
    /// Public value, fixed length `public_len()`, big-endian, left zero-padded.
    fn public_value(&self) -> Vec<u8>;
    /// Shared secret g^ir, fixed length `public_len()`, big-endian, left zero-padded (RFC 7296 §2.14).
    fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>>;
}

/// The concrete algorithm set negotiated for an SA.
#[derive(Clone)]
pub struct Suite {
    pub cipher: Arc<dyn Cipher>,
    pub integrity: Arc<dyn Integrity>,
    pub prf: Arc<dyn Prf>,
    pub dh: Option<Arc<dyn DhGroup>>,
}

/// Cryptographically secure random bytes (nonces, SPIs, IVs, DH exponents).
pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}
