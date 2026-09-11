//! IKE_AUTH signed octets and the AUTH payload computation (RFC 7296 §2.15, §2.16;
//! RFC 5998 EAP-only).
//!
//! ```text
//! InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI,  MACedIDForI = prf(SK_pi, RestOfInitIDPayload)
//! ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR,  MACedIDForR = prf(SK_pr, RestOfRespIDPayload)
//! RestOfXIDPayload      = IDType(1) | Reserved(3) | IDData      (ID payload minus its 4-byte generic header)
//! AUTH (method 2)       = prf( prf(Shared Secret, "Key Pad for IKEv2"), SignedOctets )
//! ```
//!
//! With EAP-only authentication the "Shared Secret" is the full 64-byte EAP MSK
//! (never truncated — HMAC hashes over-long keys internally, exactly like the JCE
//! `HmacSHA256` the AOSP client uses). `RealMessage1` is the IKE_SA_INIT request
//! exactly as finally sent (after any COOKIE retry), `RealMessage2` the response
//! exactly as received (non-ESP marker already stripped); both include the 28-byte
//! IKE header. Nonces are the nonce payload DATA only.
//!
//! # Extension seam
//!
//! [`AuthMethod`] is the only thing `session.rs` sees. To add another method:
//! - **PSK** (`AUTH_SHARED_KEY_MIC`): reuse [`SharedKeyAuth`] with `key = psk`; the
//!   formula is identical (RFC 7296 §2.15).
//! - **RSA / ECDSA signatures** (`AUTH_RSA_DIGITAL_SIGNATURE` = 1,
//!   `AUTH_DIGITAL_SIGNATURE` = 14, RFC 7427): implement `AuthMethod` with
//!   `compute` = sign(`signed_octets`) (for method 14, prefix the DER AlgorithmIdentifier
//!   blob per RFC 7427 §3) and `verify` = verify against the peer's CERT payload.
//!   The signed octets are built with the same [`initiator_signed_octets`] /
//!   [`responder_signed_octets`] helpers.

use crate::crypto::Prf;
use crate::ike::constants::{AUTH_SHARED_KEY_MIC, KEY_PAD_FOR_IKEV2};
use crate::ike::payload::IdPayload;
use crate::{Error, Result};
use subtle::ConstantTimeEq;

/// An IKEv2 authentication method (RFC 7296 §3.8). Implementations produce and
/// verify the AUTH payload data over the signed octets of §2.15.
pub trait AuthMethod: Send + Sync {
    /// Auth Method field value of the AUTH payload (e.g. 2 = Shared Key MIC).
    fn method_id(&self) -> u8;
    /// Compute the AUTH payload data for `signed_octets`.
    fn compute(&self, prf: &dyn Prf, signed_octets: &[u8]) -> Result<Vec<u8>>;
    /// Verify the peer's AUTH payload data over `signed_octets`.
    /// Returns [`Error::AuthFailed`] on mismatch.
    fn verify(&self, prf: &dyn Prf, signed_octets: &[u8], auth_data: &[u8]) -> Result<()>;
}

/// `AUTH_SHARED_KEY_MIC` (method 2): `prf(prf(key, "Key Pad for IKEv2"), SignedOctets)`.
///
/// For EAP-only authentication `key` is the 64-byte EAP MSK (RFC 7296 §2.16); for
/// classic PSK authentication it is the pre-shared key. The key is used as the HMAC
/// key at its full length. Zeroized on drop.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct SharedKeyAuth {
    pub key: Vec<u8>,
}

impl std::fmt::Debug for SharedKeyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedKeyAuth {{ key: [{} bytes] }}", self.key.len())
    }
}

impl SharedKeyAuth {
    pub fn new(key: Vec<u8>) -> Self {
        SharedKeyAuth { key }
    }

    /// `prf(key, "Key Pad for IKEv2")` — the inner (signing) key.
    fn signing_key(&self, prf: &dyn Prf) -> Vec<u8> {
        prf.prf(&self.key, KEY_PAD_FOR_IKEV2)
    }
}

impl AuthMethod for SharedKeyAuth {
    fn method_id(&self) -> u8 {
        AUTH_SHARED_KEY_MIC
    }

    fn compute(&self, prf: &dyn Prf, signed_octets: &[u8]) -> Result<Vec<u8>> {
        if self.key.is_empty() {
            return Err(Error::AuthFailed("shared key (MSK) is empty".into()));
        }
        let mut signing_key = self.signing_key(prf);
        let mac = prf.prf(&signing_key, signed_octets);
        zeroize::Zeroize::zeroize(&mut signing_key);
        log::debug!("AUTH(method {}) computed over {} signed octets: {} bytes", AUTH_SHARED_KEY_MIC, signed_octets.len(), mac.len());
        Ok(mac)
    }

    fn verify(&self, prf: &dyn Prf, signed_octets: &[u8], auth_data: &[u8]) -> Result<()> {
        let expected = self.compute(prf, signed_octets)?;
        if expected.len() != auth_data.len() {
            log::debug!("AUTH length mismatch: got {} expected {}", auth_data.len(), expected.len());
            return Err(Error::AuthFailed(format!(
                "AUTH data length {} != expected {}",
                auth_data.len(),
                expected.len()
            )));
        }
        if bool::from(expected.ct_eq(auth_data)) {
            Ok(())
        } else {
            log::debug!("AUTH mismatch: got {} bytes, expected {} bytes (values not logged)", auth_data.len(), expected.len());
            Err(Error::AuthFailed("responder AUTH (shared key MIC) does not verify".into()))
        }
    }
}

/// `RestOfIDPayload` = `IDType(1) | Reserved(3, zero) | IDData` — the ID payload body
/// without its generic header. This is the exact input of `MACedIDForX`.
pub fn id_payload_body(id: &IdPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + id.data.len());
    out.push(id.id_type);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&id.data);
    out
}

/// `RealMessageX | NonceData | prf(sk_p, id_body)`.
fn signed_octets(prf: &dyn Prf, sk_p: &[u8], real_message: &[u8], nonce: &[u8], id_body: &[u8]) -> Vec<u8> {
    let maced_id = prf.prf(sk_p, id_body);
    let mut out = Vec::with_capacity(real_message.len() + nonce.len() + maced_id.len());
    out.extend_from_slice(real_message);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&maced_id);
    out
}

/// `InitiatorSignedOctets = RealMessage1 | NonceRData | prf(SK_pi, IDi body)`.
///
/// `real_message1` = the IKE_SA_INIT request bytes as finally sent (header included;
/// the cookie-bearing retry if one happened), `nonce_r` = responder nonce DATA,
/// `id_i_body` = [`id_payload_body`] of the IDi we sent in the first IKE_AUTH.
pub fn initiator_signed_octets(prf: &dyn Prf, sk_pi: &[u8], real_message1: &[u8], nonce_r: &[u8], id_i_body: &[u8]) -> Vec<u8> {
    let out = signed_octets(prf, sk_pi, real_message1, nonce_r, id_i_body);
    log::debug!(
        "InitiatorSignedOctets: msg1={} nonce_r={} maced_id={} total={}",
        real_message1.len(),
        nonce_r.len(),
        prf.output_len(),
        out.len()
    );
    out
}

/// `ResponderSignedOctets = RealMessage2 | NonceIData | prf(SK_pr, IDr body)`.
///
/// `real_message2` = the raw IKE_SA_INIT response bytes as received (header included,
/// non-ESP marker stripped), `nonce_i` = our nonce DATA, `id_r_body` =
/// [`id_payload_body`] of the IDr received in the FIRST IKE_AUTH response.
pub fn responder_signed_octets(prf: &dyn Prf, sk_pr: &[u8], real_message2: &[u8], nonce_i: &[u8], id_r_body: &[u8]) -> Vec<u8> {
    let out = signed_octets(prf, sk_pr, real_message2, nonce_i, id_r_body);
    log::debug!(
        "ResponderSignedOctets: msg2={} nonce_i={} maced_id={} total={}",
        real_message2.len(),
        nonce_i.len(),
        prf.output_len(),
        out.len()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hmac_sha2::HmacSha256Prf;
    use crate::ike::constants::{ID_FQDN, ID_RFC822_ADDR};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn hmac256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }

    #[test]
    fn id_body_layout() {
        let id = IdPayload { id_type: ID_RFC822_ADDR, data: b"user@example.com".to_vec() };
        let body = id_payload_body(&id);
        assert_eq!(&body[..4], &[3, 0, 0, 0]);
        assert_eq!(&body[4..], b"user@example.com");
        assert_eq!(body.len(), 4 + 16);

        let fqdn = IdPayload { id_type: ID_FQDN, data: b"ims.tmus".to_vec() };
        assert_eq!(id_payload_body(&fqdn), b"\x02\x00\x00\x00ims.tmus".to_vec());

        let empty = IdPayload { id_type: ID_FQDN, data: vec![] };
        assert_eq!(id_payload_body(&empty), vec![2, 0, 0, 0]);
    }

    #[test]
    fn initiator_signed_octets_exact_concatenation() {
        let sk_pi = [0x11u8; 32];
        let msg1 = b"MSG1";
        let nonce_r = b"NONCER";
        let id_body = b"\x03\x00\x00\x00id";
        let out = initiator_signed_octets(&HmacSha256Prf, &sk_pi, msg1, nonce_r, id_body);
        let maced = hmac256(&sk_pi, id_body);
        let mut expected = Vec::new();
        expected.extend_from_slice(msg1);
        expected.extend_from_slice(nonce_r);
        expected.extend_from_slice(&maced);
        assert_eq!(out, expected);
        assert_eq!(out.len(), 4 + 6 + 32);
        assert_eq!(&out[..4], b"MSG1");
        assert_eq!(&out[4..10], b"NONCER");
    }

    #[test]
    fn responder_signed_octets_exact_concatenation() {
        let sk_pr = [0x22u8; 32];
        let msg2 = b"MSG2!!";
        let nonce_i = b"NI";
        let id_body = b"\x02\x00\x00\x00ims.tmus";
        let out = responder_signed_octets(&HmacSha256Prf, &sk_pr, msg2, nonce_i, id_body);
        let maced = hmac256(&sk_pr, id_body);
        assert_eq!(&out[..6], b"MSG2!!");
        assert_eq!(&out[6..8], b"NI");
        assert_eq!(&out[8..], &maced[..]);
        assert_eq!(out.len(), 6 + 2 + 32);
        // Different SK_p => different MACedID, same prefix.
        let other = responder_signed_octets(&HmacSha256Prf, &[0x23u8; 32], msg2, nonce_i, id_body);
        assert_eq!(&other[..8], &out[..8]);
        assert_ne!(&other[8..], &out[8..]);
    }

    #[test]
    fn shared_key_auth_kat_full_msk() {
        // MSK = 0x00..0x3f (64 bytes), signed octets = "signed-octets-test";
        // expected computed independently with Python hmac/hashlib.
        let msk: Vec<u8> = (0u8..64).collect();
        let auth = SharedKeyAuth::new(msk.clone());
        assert_eq!(auth.method_id(), AUTH_SHARED_KEY_MIC);
        let so = b"signed-octets-test";
        let mac = auth.compute(&HmacSha256Prf, so).unwrap();
        assert_eq!(hex::encode(&mac), "d26aa44af069293d0c7429caf8bb62a58d9a52e075af8ec2bf524c2421b523ea");
        // Cross-check against hmac directly with the FULL 64-byte key.
        let inner = hmac256(&msk, b"Key Pad for IKEv2");
        assert_eq!(mac, hmac256(&inner, so));
        // Truncating the MSK to 32 bytes must NOT give the same answer.
        let truncated = SharedKeyAuth::new(msk[..32].to_vec()).compute(&HmacSha256Prf, so).unwrap();
        assert_ne!(truncated, mac);
    }

    #[test]
    fn key_pad_is_17_bytes_no_nul() {
        assert_eq!(KEY_PAD_FOR_IKEV2.len(), 17);
        // AOSP IKE_KEY_PAD_STRING_ASCII_HEX_BYTES: 4b 65 79 20 50 61 64 20 66 6f 72 20 49 4b 45 76 32
        assert_eq!(hex::encode(KEY_PAD_FOR_IKEV2), "4b65792050616420666f7220494b457632");
        assert!(!KEY_PAD_FOR_IKEV2.contains(&0));
    }

    #[test]
    fn compute_verify_round_trip_and_mismatch() {
        let auth = SharedKeyAuth::new(vec![0xaa; 64]);
        let so = b"some signed octets";
        let mac = auth.compute(&HmacSha256Prf, so).unwrap();
        assert_eq!(mac.len(), 32);
        auth.verify(&HmacSha256Prf, so, &mac).unwrap();

        // Flipped bit -> AuthFailed
        let mut bad = mac.clone();
        bad[5] ^= 0x80;
        assert!(matches!(auth.verify(&HmacSha256Prf, so, &bad), Err(Error::AuthFailed(_))));
        // Wrong length -> AuthFailed
        assert!(matches!(auth.verify(&HmacSha256Prf, so, &mac[..16]), Err(Error::AuthFailed(_))));
        assert!(matches!(auth.verify(&HmacSha256Prf, so, &[]), Err(Error::AuthFailed(_))));
        // Different signed octets -> AuthFailed
        assert!(matches!(auth.verify(&HmacSha256Prf, b"other octets", &mac), Err(Error::AuthFailed(_))));
        // Different key -> AuthFailed
        let other = SharedKeyAuth::new(vec![0xab; 64]);
        assert!(matches!(other.verify(&HmacSha256Prf, so, &mac), Err(Error::AuthFailed(_))));
    }

    #[test]
    fn empty_key_is_rejected() {
        let auth = SharedKeyAuth::new(vec![]);
        assert!(matches!(auth.compute(&HmacSha256Prf, b"x"), Err(Error::AuthFailed(_))));
    }

    #[test]
    fn end_to_end_initiator_and_responder_auth() {
        // Simulate both sides sharing the MSK and SK_pi/SK_pr.
        let msk: Vec<u8> = (100u8..164).collect();
        let sk_pi = [1u8; 32];
        let sk_pr = [2u8; 32];
        let msg1 = vec![0x10; 456];
        let msg2 = vec![0x20; 400];
        let ni = vec![3u8; 32];
        let nr = vec![4u8; 32];
        let idi = id_payload_body(&IdPayload { id_type: ID_RFC822_ADDR, data: b"x@y".to_vec() });
        let idr = id_payload_body(&IdPayload { id_type: ID_FQDN, data: b"ims.tmus".to_vec() });

        let auth = SharedKeyAuth::new(msk);
        let iso = initiator_signed_octets(&HmacSha256Prf, &sk_pi, &msg1, &nr, &idi);
        let rso = responder_signed_octets(&HmacSha256Prf, &sk_pr, &msg2, &ni, &idr);
        let auth_i = auth.compute(&HmacSha256Prf, &iso).unwrap();
        let auth_r = auth.compute(&HmacSha256Prf, &rso).unwrap();
        assert_ne!(auth_i, auth_r);
        auth.verify(&HmacSha256Prf, &iso, &auth_i).unwrap();
        auth.verify(&HmacSha256Prf, &rso, &auth_r).unwrap();
        // Using the wrong side's octets fails.
        assert!(auth.verify(&HmacSha256Prf, &rso, &auth_i).is_err());
    }

    #[test]
    fn debug_redacts_key() {
        let auth = SharedKeyAuth::new(vec![0x42; 64]);
        let s = format!("{auth:?}");
        assert!(s.contains("64 bytes"));
        assert!(!s.contains("42, 42"));
    }

    #[test]
    fn works_through_trait_object() {
        let m: Box<dyn AuthMethod> = Box::new(SharedKeyAuth::new(vec![9; 64]));
        let mac = m.compute(&HmacSha256Prf, b"abc").unwrap();
        m.verify(&HmacSha256Prf, b"abc", &mac).unwrap();
        assert_eq!(m.method_id(), 2);
    }
}
