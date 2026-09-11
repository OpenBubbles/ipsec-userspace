//! IKEv2 message = fixed header + payload chain (RFC 7296 §3), plain or wrapped in
//! one Encrypted (SK, type 46) payload (§3.14).
//!
//! SK layout on the wire (AOSP-exact, see `docs/AOSP_FACTS.md` "SK payload"):
//!
//! ```text
//! IKE header(28, next=46)
//! SK generic header(4): next = type of FIRST inner payload (0 if none) | 0 | length
//! [SKF only: Fragment Number(2) | Total Fragments(2)]
//! IV(iv_len, random)
//! E( inner payload chain | pad(0..block-1, zeros) | padlen(1) )
//! ICV(icv_len) = integrity(SK_a, bytes[0 .. len - icv_len])
//! ```
//!
//! The IKE header's Length includes the ICV; the SK payload MUST be the only
//! top-level payload (its length must equal `len - 28`), otherwise the datagram
//! is rejected as INVALID_SYNTAX just like AOSP does.

use crate::crypto::{Suite, random_bytes};
use crate::ike::constants::*;
use crate::ike::header::IkeHeader;
use crate::ike::payload::*;
use crate::{Error, Result};

/// Fragment Number(2) | Total Fragments(2) (RFC 7383 §2.5).
pub(crate) const SKF_HEADER_LEN: usize = 4;
/// Notify types below this value are errors (§3.10.1).
const NOTIFY_ERROR_MAX: u16 = 16384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IkeMessage {
    pub header: IkeHeader,
    pub payloads: Vec<Payload>,
}

impl IkeMessage {
    /// Build a message. `header.next_payload` and `header.length` are placeholders
    /// (0) until one of the `encode_*` methods fills them in on the wire copy.
    pub fn new(
        spi_i: u64,
        spi_r: u64,
        exchange_type: u8,
        flags: u8,
        message_id: u32,
        payloads: Vec<Payload>,
    ) -> Self {
        IkeMessage {
            header: IkeHeader {
                spi_i,
                spi_r,
                next_payload: PT_NONE,
                version: IKE_VERSION,
                exchange_type,
                flags,
                message_id,
                length: 0,
            },
            payloads,
        }
    }

    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    /// Unencrypted (IKE_SA_INIT). Fills header.next_payload and header.length.
    pub fn encode_plain(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let first = encode_payloads(&self.payloads, &mut body)?;
        let total = IkeHeader::LEN + body.len();
        let mut header = self.header;
        header.next_payload = first;
        header.length = u32::try_from(total)
            .map_err(|_| Error::Encode(format!("IKE message of {} bytes exceeds u32", total)))?;
        let mut out = Vec::with_capacity(total);
        header.encode(&mut out);
        out.extend_from_slice(&body);
        log::debug!(
            "encode_plain: exch={} msgid={} len={} first={}",
            header.exchange_type,
            header.message_id,
            total,
            Payload::type_name(first)
        );
        Ok(out)
    }

    /// Encode the inner payload chain once; returns (first inner type, chain bytes).
    fn inner_chain(&self) -> Result<(u8, Vec<u8>)> {
        let mut chain = Vec::new();
        let first = encode_payloads(&self.payloads, &mut chain)?;
        Ok((first, chain))
    }

    /// All payloads inside one SK payload (§3.14).
    pub fn encode_encrypted(&self, suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<Vec<u8>> {
        let (first, chain) = self.inner_chain()?;
        let mut header = self.header;
        header.next_payload = PT_SK;
        let out = seal(&header, first, None, &chain, suite, sk_e, sk_a)?;
        log::debug!(
            "encode_encrypted: exch={} msgid={} inner={}B total={}B first={}",
            header.exchange_type,
            header.message_id,
            chain.len(),
            out.len(),
            Payload::type_name(first)
        );
        Ok(out)
    }

    /// Like [`encode_encrypted`](Self::encode_encrypted) but if the unfragmented
    /// datagram would exceed `frag_threshold` bytes, emit RFC 7383 SKF fragments
    /// instead (see [`crate::ike::fragment`]). Always returns >= 1 datagram.
    pub fn encode_encrypted_fragmented(
        &self,
        suite: &Suite,
        sk_e: &[u8],
        sk_a: &[u8],
        frag_threshold: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let (first, chain) = self.inner_chain()?;
        let unfragmented = encrypted_message_len(suite, SKF_NONE, chain.len());
        if unfragmented <= frag_threshold {
            let mut header = self.header;
            header.next_payload = PT_SK;
            let out = seal(&header, first, None, &chain, suite, sk_e, sk_a)?;
            return Ok(vec![out]);
        }
        log::debug!(
            "encode_encrypted_fragmented: msgid={} unfragmented {}B > threshold {}B, fragmenting",
            self.header.message_id,
            unfragmented,
            frag_threshold
        );
        crate::ike::fragment::fragment(&self.header, first, &chain, suite, sk_e, sk_a, frag_threshold)
    }

    // -----------------------------------------------------------------------
    // Decoding
    // -----------------------------------------------------------------------

    /// Plain decode; `Error::Decode` if header.length != buf.len().
    pub fn decode_plain(buf: &[u8]) -> Result<IkeMessage> {
        let header = IkeHeader::decode(buf)?;
        check_total_length(&header, buf)?;
        let body = buf.get(IkeHeader::LEN..).unwrap_or(&[]);
        let payloads = decode_payloads(header.next_payload, body)?;
        log::debug!(
            "decode_plain: exch={} msgid={} len={} payloads={}",
            header.exchange_type,
            header.message_id,
            buf.len(),
            payloads.len()
        );
        Ok(IkeMessage { header, payloads })
    }

    /// Decode with SK: verify ICV (constant-time; `Error::Integrity` on mismatch),
    /// decrypt, strip pad, decode inner chain. The SK payload must be the only
    /// top-level payload. Buffer must be a whole message (not an SKF fragment —
    /// use [`crate::ike::fragment::Reassembler`] for those).
    pub fn decode_encrypted(buf: &[u8], suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<IkeMessage> {
        let opened = open(buf, PT_SK, suite, sk_e, sk_a)?;
        let payloads = decode_payloads(opened.first_inner, &opened.plaintext)?;
        let mut header = opened.header;
        header.next_payload = opened.first_inner;
        log::debug!(
            "decode_encrypted: exch={} msgid={} len={} inner={}B payloads={}",
            header.exchange_type,
            header.message_id,
            buf.len(),
            opened.plaintext.len(),
            payloads.len()
        );
        Ok(IkeMessage { header, payloads })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn sa(&self) -> Option<&SaPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Sa(sa) => Some(sa),
            _ => None,
        })
    }

    pub fn ke(&self) -> Option<&KePayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Ke(ke) => Some(ke),
            _ => None,
        })
    }

    pub fn nonce(&self) -> Option<&[u8]> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Nonce(n) => Some(n.as_slice()),
            _ => None,
        })
    }

    pub fn notifies(&self) -> impl Iterator<Item = &NotifyPayload> {
        self.payloads.iter().filter_map(|p| match p {
            Payload::Notify(n) => Some(n),
            _ => None,
        })
    }

    pub fn notify(&self, t: u16) -> Option<&NotifyPayload> {
        self.notifies().find(|n| n.notify_type == t)
    }

    pub fn id_i(&self) -> Option<&IdPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::IdI(id) => Some(id),
            _ => None,
        })
    }

    pub fn id_r(&self) -> Option<&IdPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::IdR(id) => Some(id),
            _ => None,
        })
    }

    pub fn auth(&self) -> Option<&AuthPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Auth(a) => Some(a),
            _ => None,
        })
    }

    pub fn cp(&self) -> Option<&ConfigPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Cp(c) => Some(c),
            _ => None,
        })
    }

    pub fn ts_i(&self) -> Option<&TsPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::TsI(t) => Some(t),
            _ => None,
        })
    }

    pub fn ts_r(&self) -> Option<&TsPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::TsR(t) => Some(t),
            _ => None,
        })
    }

    pub fn eap(&self) -> Option<&[u8]> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Eap(e) => Some(e.as_slice()),
            _ => None,
        })
    }

    pub fn deletes(&self) -> impl Iterator<Item = &DeletePayload> {
        self.payloads.iter().filter_map(|p| match p {
            Payload::Delete(d) => Some(d),
            _ => None,
        })
    }

    /// First error notify (type < 16384), as `Error::PeerNotify`.
    pub fn error_notify(&self, exchange: &'static str) -> Option<Error> {
        self.notifies()
            .find(|n| n.notify_type < NOTIFY_ERROR_MAX)
            .map(|n| Error::PeerNotify {
                notify_type: n.notify_type,
                name: notify_name(n.notify_type),
                exchange,
                data: n.data.clone(),
            })
    }
}

// ---------------------------------------------------------------------------
// Shared SK / SKF sealing and opening (used by fragment.rs too)
// ---------------------------------------------------------------------------

/// Marker for "plain SK, no SKF header" in [`encrypted_message_len`].
pub(crate) const SKF_NONE: usize = 0;

/// Ciphertext length for `plaintext_len` bytes of inner data: pad so that
/// `(inner + pad + 1) % block == 0`.
pub(crate) fn padded_len(plaintext_len: usize, block_len: usize) -> usize {
    let block = block_len.max(1);
    (plaintext_len + 1).div_ceil(block) * block
}

/// Total IKE message length (header + SK/SKF payload incl. ICV) for a given inner
/// plaintext length. `skf_header_len` is `SKF_HEADER_LEN` for a fragment, `SKF_NONE` for SK.
pub(crate) fn encrypted_message_len(suite: &Suite, skf_header_len: usize, plaintext_len: usize) -> usize {
    IkeHeader::LEN
        + GENERIC_PAYLOAD_HEADER_LEN
        + skf_header_len
        + suite.cipher.iv_len()
        + padded_len(plaintext_len, suite.cipher.block_len())
        + suite.integrity.icv_len()
}

fn check_keys(suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<()> {
    if sk_e.len() != suite.cipher.key_len() {
        return Err(Error::Crypto(format!(
            "SK_e is {} bytes, cipher needs {}",
            sk_e.len(),
            suite.cipher.key_len()
        )));
    }
    if sk_a.len() != suite.integrity.key_len() {
        return Err(Error::Crypto(format!(
            "SK_a is {} bytes, integrity needs {}",
            sk_a.len(),
            suite.integrity.key_len()
        )));
    }
    Ok(())
}

/// Build one complete encrypted IKE datagram.
///
/// `header.next_payload` must already be `PT_SK` (or `PT_SKF` when `skf` is
/// `Some((fragnum, total))`); `header.length` is computed here. `first_inner` goes
/// into the SK/SKF generic header's Next Payload field. `plaintext` is the (chunk of
/// the) encoded inner payload chain.
pub(crate) fn seal(
    header: &IkeHeader,
    first_inner: u8,
    skf: Option<(u16, u16)>,
    plaintext: &[u8],
    suite: &Suite,
    sk_e: &[u8],
    sk_a: &[u8],
) -> Result<Vec<u8>> {
    check_keys(suite, sk_e, sk_a)?;
    let cipher = &*suite.cipher;
    let integ = &*suite.integrity;
    let block = cipher.block_len().max(1);
    let iv_len = cipher.iv_len();
    let icv_len = integ.icv_len();
    let skf_len = if skf.is_some() { SKF_HEADER_LEN } else { SKF_NONE };

    // Pad so (plaintext + pad + 1) % block == 0; pad bytes zero, then the pad-length byte.
    let ct_len = padded_len(plaintext.len(), block);
    let pad_len = ct_len - plaintext.len() - 1;
    if pad_len >= 256 {
        return Err(Error::Encode(format!("pad length {} does not fit one byte", pad_len)));
    }
    let mut data = Vec::with_capacity(ct_len);
    data.extend_from_slice(plaintext);
    data.resize(ct_len - 1, 0);
    data.push(pad_len as u8);

    let iv = random_bytes(iv_len);
    cipher.encrypt(sk_e, &iv, &mut data)?;

    let sk_payload_len = GENERIC_PAYLOAD_HEADER_LEN + skf_len + iv_len + ct_len + icv_len;
    if sk_payload_len > u16::MAX as usize {
        return Err(Error::Encode(format!(
            "SK payload of {} bytes exceeds the 16-bit payload length",
            sk_payload_len
        )));
    }
    let total = IkeHeader::LEN + sk_payload_len;
    let mut hdr = *header;
    hdr.length = u32::try_from(total)
        .map_err(|_| Error::Encode(format!("IKE message of {} bytes exceeds u32", total)))?;

    let mut out = Vec::with_capacity(total);
    hdr.encode(&mut out);
    out.push(first_inner);
    out.push(0); // C=0, reserved
    out.extend_from_slice(&(sk_payload_len as u16).to_be_bytes());
    if let Some((num, tot)) = skf {
        out.extend_from_slice(&num.to_be_bytes());
        out.extend_from_slice(&tot.to_be_bytes());
    }
    out.extend_from_slice(&iv);
    out.extend_from_slice(&data);
    let icv = integ.compute(sk_a, &out);
    if icv.len() != icv_len {
        return Err(Error::Crypto(format!(
            "integrity produced {} bytes, expected icv_len {}",
            icv.len(),
            icv_len
        )));
    }
    out.extend_from_slice(&icv);
    debug_assert_eq!(out.len(), total);
    log::debug!("seal: msgid={} skf={:?} out={}", hdr.message_id, skf, hex::encode(&out));
    Ok(out)
}

/// Result of verifying + decrypting one SK or SKF datagram.
pub(crate) struct Opened {
    /// The datagram's IKE header (next_payload still PT_SK / PT_SKF).
    pub header: IkeHeader,
    /// Next Payload from the SK/SKF generic header (type of the first inner payload).
    pub first_inner: u8,
    /// `(fragment number, total fragments)` when the datagram was an SKF.
    pub skf: Option<(u16, u16)>,
    /// Inner plaintext with padding stripped.
    pub plaintext: Vec<u8>,
}

/// Verify the ICV over `buf[..len-icv]`, decrypt, strip padding. `expect` is `PT_SK`
/// or `PT_SKF` and must equal the header's Next Payload. The SK/SKF payload must be
/// the only top-level payload (its length must be exactly `buf.len() - 28`).
pub(crate) fn open(buf: &[u8], expect: u8, suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<Opened> {
    check_keys(suite, sk_e, sk_a)?;
    let header = IkeHeader::decode(buf)?;
    check_total_length(&header, buf)?;
    if header.next_payload != expect {
        return Err(Error::Decode(format!(
            "expected {} ({}) as the first payload, got {} ({})",
            expect,
            Payload::type_name(expect),
            header.next_payload,
            Payload::type_name(header.next_payload)
        )));
    }
    let skf_len = if expect == PT_SKF { SKF_HEADER_LEN } else { SKF_NONE };
    let cipher = &*suite.cipher;
    let integ = &*suite.integrity;
    let block = cipher.block_len().max(1);
    let iv_len = cipher.iv_len();
    let icv_len = integ.icv_len();

    let body = slice(buf, IkeHeader::LEN, buf.len(), "SK body")?;
    let generic = slice(body, 0, GENERIC_PAYLOAD_HEADER_LEN, "SK generic header")?;
    let first_inner = generic[0];
    // generic[1]: critical bit ignored (AOSP), reserved bits ignored.
    let sk_payload_len = u16::from_be_bytes([generic[2], generic[3]]) as usize;
    if sk_payload_len != body.len() {
        return Err(Error::Decode(format!(
            "{} payload length {} != message body {} (SK must be the only top-level payload)",
            Payload::type_name(expect),
            sk_payload_len,
            body.len()
        )));
    }
    let min_len = GENERIC_PAYLOAD_HEADER_LEN + skf_len + iv_len + block + icv_len;
    if body.len() < min_len {
        return Err(Error::Decode(format!(
            "{} payload of {} bytes shorter than minimum {}",
            Payload::type_name(expect),
            body.len(),
            min_len
        )));
    }
    let skf = if expect == PT_SKF {
        let h = slice(body, GENERIC_PAYLOAD_HEADER_LEN, GENERIC_PAYLOAD_HEADER_LEN + SKF_HEADER_LEN, "SKF header")?;
        Some((u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[2], h[3]])))
    } else {
        None
    };

    // ICV first, constant-time, before touching the ciphertext.
    let auth_end = buf.len() - icv_len;
    let (authed, icv) = buf.split_at(auth_end);
    if !integ.verify(sk_a, authed, icv) {
        log::debug!("open: ICV mismatch on msgid={} len={}", header.message_id, buf.len());
        return Err(Error::Integrity("IKE SK payload ICV mismatch"));
    }

    let iv_start = IkeHeader::LEN + GENERIC_PAYLOAD_HEADER_LEN + skf_len;
    let iv = slice(buf, iv_start, iv_start + iv_len, "SK IV")?;
    let ct = slice(buf, iv_start + iv_len, auth_end, "SK ciphertext")?;
    if ct.is_empty() || ct.len() % block != 0 {
        return Err(Error::Decode(format!(
            "SK ciphertext length {} is not a positive multiple of the block size {}",
            ct.len(),
            block
        )));
    }
    let mut plaintext = ct.to_vec();
    cipher.decrypt(sk_e, iv, &mut plaintext)?;
    let pad_len = *plaintext.last().ok_or_else(|| Error::Decode("SK plaintext empty".into()))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(Error::Decode(format!(
            "SK pad length {} exceeds decrypted length {}",
            pad_len,
            plaintext.len()
        )));
    }
    plaintext.truncate(plaintext.len() - pad_len - 1);
    log::trace!(
        "open: msgid={} skf={:?} first={} plaintext={}",
        header.message_id,
        skf,
        Payload::type_name(first_inner),
        hex::encode(&plaintext)
    );
    Ok(Opened { header, first_inner, skf, plaintext })
}

/// `Error::Decode` unless `header.length == buf.len()`.
pub(crate) fn check_total_length(header: &IkeHeader, buf: &[u8]) -> Result<()> {
    if header.length as usize != buf.len() {
        return Err(Error::Decode(format!(
            "IKE header length {} != datagram length {}",
            header.length,
            buf.len()
        )));
    }
    Ok(())
}

fn slice<'a>(buf: &'a [u8], start: usize, end: usize, what: &str) -> Result<&'a [u8]> {
    if start > end || end > buf.len() {
        return Err(Error::Decode(format!(
            "{}: need bytes {}..{} of a {}-byte buffer",
            what,
            start,
            end,
            buf.len()
        )));
    }
    Ok(&buf[start..end])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use crate::crypto::{Suite, registry};
    use crate::ike::constants::*;

    /// AES-256-CBC + HMAC-SHA2-256-128 + PRF-HMAC-SHA2-256, no DH.
    pub fn suite() -> Suite {
        Suite {
            cipher: registry::cipher(ENCR_AES_CBC, Some(256)).expect("AES-256-CBC in registry"),
            integrity: registry::integrity(AUTH_HMAC_SHA2_256_128).expect("HMAC-SHA2-256-128 in registry"),
            prf: registry::prf(PRF_HMAC_SHA2_256).expect("PRF-HMAC-SHA2-256 in registry"),
            dh: None,
        }
    }

    pub fn sk_e() -> Vec<u8> {
        (0u8..32).collect()
    }

    pub fn sk_a() -> Vec<u8> {
        (100u8..132).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn sample_payloads() -> Vec<Payload> {
        vec![
            Payload::Sa(SaPayload {
                proposals: vec![Proposal {
                    number: 1,
                    protocol_id: PROTO_IKE,
                    spi: vec![],
                    transforms: vec![
                        Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                        Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                        Transform::new(TT_DH, DH_MODP_2048),
                        Transform::new(TT_PRF, PRF_HMAC_SHA2_256),
                    ],
                }],
            }),
            Payload::Ke(KePayload { group: DH_MODP_2048, public: vec![0x42; 256] }),
            Payload::Nonce(vec![7u8; 32]),
            Payload::Notify(NotifyPayload::status(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![])),
            Payload::Notify(NotifyPayload::status(
                N_SIGNATURE_HASH_ALGORITHMS,
                vec![0, 1, 0, 2, 0, 3, 0, 4],
            )),
        ]
    }

    fn msg(exchange: u8, payloads: Vec<Payload>) -> IkeMessage {
        IkeMessage::new(0x0102030405060708, 0x1112131415161718, exchange, FLAG_INITIATOR, 1, payloads)
    }

    #[test]
    fn plain_round_trip() {
        let m = IkeMessage::new(0x0102030405060708, 0, EXCH_IKE_SA_INIT, FLAG_INITIATOR, 0, sample_payloads());
        let raw = m.encode_plain().unwrap();
        assert_eq!(raw[16], PT_SA);
        assert_eq!(raw[17], IKE_VERSION);
        assert_eq!(raw[18], EXCH_IKE_SA_INIT);
        assert_eq!(raw[19], FLAG_INITIATOR);
        assert_eq!(u32::from_be_bytes([raw[24], raw[25], raw[26], raw[27]]) as usize, raw.len());
        // SA 48 + KE 264 + Ni 36 + N 8 + N 16 = 372 + 28
        assert_eq!(raw.len(), 28 + 48 + 264 + 36 + 8 + 16);

        let d = IkeMessage::decode_plain(&raw).unwrap();
        assert_eq!(d.payloads, m.payloads);
        assert_eq!(d.header.spi_i, m.header.spi_i);
        assert_eq!(d.header.next_payload, PT_SA);
        assert_eq!(d.header.length as usize, raw.len());
        assert!(d.sa().is_some());
        assert_eq!(d.ke().unwrap().group, DH_MODP_2048);
        assert_eq!(d.nonce().unwrap(), &[7u8; 32]);
        assert!(d.notify(N_IKEV2_FRAGMENTATION_SUPPORTED).is_some());
        assert_eq!(d.notifies().count(), 2);
        assert!(d.error_notify("IKE_SA_INIT").is_none());
    }

    #[test]
    fn plain_empty_message() {
        let m = IkeMessage::new(1, 2, EXCH_INFORMATIONAL, FLAG_INITIATOR | FLAG_RESPONSE, 5, vec![]);
        let raw = m.encode_plain().unwrap();
        assert_eq!(raw.len(), 28);
        assert_eq!(raw[16], PT_NONE);
        let d = IkeMessage::decode_plain(&raw).unwrap();
        assert!(d.payloads.is_empty());
        assert!(d.header.is_response());
    }

    #[test]
    fn plain_length_mismatch_is_decode_error() {
        let m = IkeMessage::new(1, 0, EXCH_IKE_SA_INIT, FLAG_INITIATOR, 0, sample_payloads());
        let mut raw = m.encode_plain().unwrap();
        raw.push(0);
        assert!(matches!(IkeMessage::decode_plain(&raw), Err(Error::Decode(_))));
        raw.truncate(raw.len() - 2);
        assert!(matches!(IkeMessage::decode_plain(&raw), Err(Error::Decode(_))));
        assert!(matches!(IkeMessage::decode_plain(&raw[..10]), Err(Error::Decode(_))));
    }

    #[test]
    fn error_notify_reported() {
        let m = msg(
            EXCH_IKE_SA_INIT,
            vec![
                Payload::Notify(NotifyPayload::status(N_NAT_DETECTION_SOURCE_IP, vec![0; 20])),
                Payload::Notify(NotifyPayload::status(N_NO_PROPOSAL_CHOSEN, vec![])),
            ],
        );
        match m.error_notify("IKE_SA_INIT") {
            Some(Error::PeerNotify { notify_type, name, exchange, data }) => {
                assert_eq!(notify_type, N_NO_PROPOSAL_CHOSEN);
                assert_eq!(name, "NO_PROPOSAL_CHOSEN");
                assert_eq!(exchange, "IKE_SA_INIT");
                assert!(data.is_empty());
            }
            other => panic!("expected PeerNotify, got {:?}", other),
        }
    }

    #[test]
    fn encrypted_round_trip() {
        let suite = suite();
        let payloads = vec![
            Payload::IdI(IdPayload { id_type: ID_RFC822_ADDR, data: b"user@example.com".to_vec() }),
            Payload::IdR(IdPayload { id_type: ID_FQDN, data: b"ims.tmus".to_vec() }),
            Payload::Notify(NotifyPayload::status(N_EAP_ONLY_AUTHENTICATION, vec![])),
            Payload::TsI(TsPayload::any_v4_v6()),
            Payload::TsR(TsPayload::any_v4_v6()),
            Payload::Cp(ConfigPayload::request(&[1, 8, 3, 10, 2, 20, 21, 7])),
        ];
        let m = msg(EXCH_IKE_AUTH, payloads.clone());
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();

        // Header
        assert_eq!(raw[16], PT_SK);
        assert_eq!(raw[18], EXCH_IKE_AUTH);
        assert_eq!(u32::from_be_bytes([raw[24], raw[25], raw[26], raw[27]]) as usize, raw.len());
        // SK generic header: next = first inner (IDi), C=0, length = rest
        assert_eq!(raw[28], PT_IDI);
        assert_eq!(raw[29], 0);
        assert_eq!(u16::from_be_bytes([raw[30], raw[31]]) as usize, raw.len() - 28);
        // Length arithmetic: 4 + 16 IV + ct + 16 ICV, ct multiple of 16
        let ct_len = raw.len() - 28 - 4 - 16 - 16;
        assert_eq!(ct_len % 16, 0);
        let mut chain = Vec::new();
        encode_payloads(&payloads, &mut chain).unwrap();
        assert_eq!(ct_len, padded_len(chain.len(), 16));

        let d = IkeMessage::decode_encrypted(&raw, &suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(d.payloads, payloads);
        assert_eq!(d.header.next_payload, PT_IDI);
        assert_eq!(d.header.message_id, 1);
        assert_eq!(d.header.spi_r, 0x1112131415161718);
        assert_eq!(d.id_r().unwrap().data, b"ims.tmus");
        assert!(d.ts_i().is_some() && d.ts_r().is_some() && d.cp().is_some());
        assert!(d.auth().is_none() && d.eap().is_none());
    }

    #[test]
    fn encrypted_iv_is_fresh_per_message() {
        let suite = suite();
        let m = msg(EXCH_INFORMATIONAL, vec![Payload::Vendor(vec![1, 2, 3])]);
        let a = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        let b = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(a.len(), b.len());
        assert_ne!(a[32..48], b[32..48], "IV must be random per message");
    }

    #[test]
    fn icv_tamper_is_integrity_error() {
        let suite = suite();
        let m = msg(EXCH_IKE_AUTH, vec![Payload::Eap(vec![2, 1, 0, 5, 1])]);
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        // Flip a bit in the ICV
        let mut t = raw.clone();
        let last = t.len() - 1;
        t[last] ^= 0x01;
        assert!(matches!(IkeMessage::decode_encrypted(&t, &suite, &sk_e(), &sk_a()), Err(Error::Integrity(_))));
        // Flip a bit in the ciphertext
        let mut t = raw.clone();
        t[50] ^= 0x80;
        assert!(matches!(IkeMessage::decode_encrypted(&t, &suite, &sk_e(), &sk_a()), Err(Error::Integrity(_))));
        // Flip a bit in the IKE header (authenticated too)
        let mut t = raw.clone();
        t[20] ^= 0x01;
        assert!(matches!(IkeMessage::decode_encrypted(&t, &suite, &sk_e(), &sk_a()), Err(Error::Integrity(_))));
        // Flip the SK next-payload byte
        let mut t = raw.clone();
        t[28] ^= 0x01;
        assert!(matches!(IkeMessage::decode_encrypted(&t, &suite, &sk_e(), &sk_a()), Err(Error::Integrity(_))));
    }

    #[test]
    fn wrong_keys_are_integrity_error() {
        let suite = suite();
        let m = msg(EXCH_IKE_AUTH, vec![Payload::Eap(vec![2, 1, 0, 5, 1])]);
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        let bad_a: Vec<u8> = sk_a().iter().map(|b| b ^ 0xff).collect();
        assert!(matches!(IkeMessage::decode_encrypted(&raw, &suite, &sk_e(), &bad_a), Err(Error::Integrity(_))));
        // Wrong SK_e alone: ICV still verifies, decryption yields garbage -> a Decode
        // error is likely but not guaranteed (a random pad byte may be valid). Must not panic.
        let bad_e: Vec<u8> = sk_e().iter().map(|b| b ^ 0xff).collect();
        let _ = IkeMessage::decode_encrypted(&raw, &suite, &bad_e, &sk_a());
        // Wrong key LENGTH is a crypto error, never a panic.
        assert!(matches!(IkeMessage::decode_encrypted(&raw, &suite, &sk_e()[..16], &sk_a()), Err(Error::Crypto(_))));
        assert!(matches!(m.encode_encrypted(&suite, &sk_e(), &sk_a()[..8]), Err(Error::Crypto(_))));
    }

    #[test]
    fn padding_edge_cases() {
        let suite = suite();
        // Inner chain lengths 0, 15, 16, 17 (Vendor payload = 4 + body).
        for (inner_len, payloads) in [
            (0usize, vec![]),
            (15, vec![Payload::Vendor(vec![0xAA; 11])]),
            (16, vec![Payload::Vendor(vec![0xAA; 12])]),
            (17, vec![Payload::Vendor(vec![0xAA; 13])]),
        ] {
            let m = msg(EXCH_INFORMATIONAL, payloads.clone());
            let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
            let expected_ct = padded_len(inner_len, 16);
            assert_eq!(expected_ct, ((inner_len + 1) + 15) / 16 * 16);
            assert_eq!(raw.len(), 28 + 4 + 16 + expected_ct + 16, "inner_len {}", inner_len);
            let d = IkeMessage::decode_encrypted(&raw, &suite, &sk_e(), &sk_a()).unwrap();
            assert_eq!(d.payloads, payloads);
        }
        assert_eq!(padded_len(0, 16), 16);
        assert_eq!(padded_len(15, 16), 16);
        assert_eq!(padded_len(16, 16), 32);
        assert_eq!(padded_len(17, 16), 32);
        assert_eq!(padded_len(292, 16), 304);
    }

    #[test]
    fn dpd_empty_informational() {
        let suite = suite();
        let m = IkeMessage::new(1, 2, EXCH_INFORMATIONAL, FLAG_INITIATOR, 7, vec![]);
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(raw[16], PT_SK);
        assert_eq!(raw[28], PT_NONE, "SK next-payload must be 0 for an empty body");
        assert_eq!(raw.len(), 28 + 4 + 16 + 16 + 16);
        let d = IkeMessage::decode_encrypted(&raw, &suite, &sk_e(), &sk_a()).unwrap();
        assert!(d.payloads.is_empty());
        assert_eq!(d.header.next_payload, PT_NONE);
        assert_eq!(d.header.exchange_type, EXCH_INFORMATIONAL);
        assert_eq!(d.header.message_id, 7);
    }

    #[test]
    fn aosp_kat_lengths() {
        // §14.1: 292-byte inner -> 304 ct -> SK 340 -> message 368; 40-byte AUTH -> 112.
        let suite = suite();
        let m = msg(EXCH_IKE_AUTH, vec![Payload::Vendor(vec![0; 288])]);
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(raw.len(), 368);
        assert_eq!(u16::from_be_bytes([raw[30], raw[31]]), 340);
        let m = msg(EXCH_IKE_AUTH, vec![Payload::Auth(AuthPayload { method: AUTH_SHARED_KEY_MIC, data: vec![0; 32] })]);
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(raw.len(), 112);
        assert_eq!(raw[28], PT_AUTH);
        assert_eq!(u16::from_be_bytes([raw[30], raw[31]]), 84);
    }

    #[test]
    fn decode_encrypted_rejects_malformed() {
        let suite = suite();
        let m = msg(EXCH_IKE_AUTH, vec![Payload::Eap(vec![2, 1, 0, 5, 1])]);
        let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();

        // Not an SK message
        let plain = msg(EXCH_IKE_SA_INIT, vec![Payload::Nonce(vec![1; 32])]).encode_plain().unwrap();
        assert!(matches!(IkeMessage::decode_encrypted(&plain, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));

        // Truncated datagram (header length no longer matches)
        assert!(matches!(IkeMessage::decode_encrypted(&raw[..raw.len() - 1], &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
        assert!(matches!(IkeMessage::decode_encrypted(&raw[..20], &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));

        // SK not the only top-level payload: extra payload appended, header length fixed up,
        // SK length unchanged -> length mismatch -> Decode (checked before the ICV).
        let mut t = raw.clone();
        t.extend_from_slice(&[0, 0, 0, 4]);
        let len = t.len() as u32;
        t[24..28].copy_from_slice(&len.to_be_bytes());
        assert!(matches!(IkeMessage::decode_encrypted(&t, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));

        // SK payload too short to hold IV + one block + ICV
        let mut t = raw[..28 + 4 + 16 + 16].to_vec();
        let short_len = t.len();
        t[24..28].copy_from_slice(&(short_len as u32).to_be_bytes());
        t[30..32].copy_from_slice(&((short_len - 28) as u16).to_be_bytes());
        assert!(matches!(IkeMessage::decode_encrypted(&t, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
    }

    #[test]
    fn decode_encrypted_bad_pad_length() {
        // Craft a datagram whose plaintext's last byte claims more padding than exists.
        let suite = suite();
        let header = IkeHeader {
            spi_i: 1,
            spi_r: 2,
            next_payload: PT_SK,
            version: IKE_VERSION,
            exchange_type: EXCH_INFORMATIONAL,
            flags: FLAG_RESPONSE,
            message_id: 3,
            length: 0,
        };
        let mut data = vec![0u8; 16];
        data[15] = 200; // pad length 200 > 15 available
        let iv = vec![9u8; 16];
        suite.cipher.encrypt(&sk_e(), &iv, &mut data).unwrap();
        let mut out = Vec::new();
        let mut h = header;
        h.length = (28 + 4 + 16 + 16 + 16) as u32;
        h.encode(&mut out);
        out.extend_from_slice(&[PT_NONE, 0, 0, 52]);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&data);
        let icv = suite.integrity.compute(&sk_a(), &out);
        out.extend_from_slice(&icv);
        assert!(matches!(IkeMessage::decode_encrypted(&out, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
    }

    #[test]
    fn fragmented_below_threshold_is_single_sk() {
        let suite = suite();
        let m = msg(EXCH_IKE_AUTH, vec![Payload::Vendor(vec![0; 288])]);
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 1280).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].len(), 368);
        assert_eq!(frags[0][16], PT_SK);
        // Exactly at the threshold is NOT fragmented (AOSP: msgLen > fragSize).
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 368).unwrap();
        assert_eq!(frags.len(), 1);
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 367).unwrap();
        assert!(frags.len() >= 2);
        for f in &frags {
            assert_eq!(f[16], PT_SKF);
            assert!(f.len() <= 367);
        }
    }

    #[test]
    fn encrypted_message_len_matches_seal() {
        let suite = suite();
        for n in [0usize, 1, 15, 16, 17, 100, 292, 1195, 1196, 1197] {
            let m = if n < 4 && n > 0 {
                continue;
            } else if n == 0 {
                msg(EXCH_INFORMATIONAL, vec![])
            } else {
                msg(EXCH_INFORMATIONAL, vec![Payload::Vendor(vec![1; n - 4])])
            };
            let raw = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
            assert_eq!(raw.len(), encrypted_message_len(&suite, SKF_NONE, n), "n={}", n);
        }
    }
}
