//! IKEv2 message fragmentation (RFC 7383), mirroring AOSP byte-for-byte.
//!
//! An Encrypted Fragment payload (SKF, type 53) replaces the SK payload; each
//! fragment is a complete IKE message with its own header (same SPIs / exchange /
//! flags / message id, `next_payload = PT_SKF`), individually encrypted and MACed:
//!
//! ```text
//! IKE header(28, next=53) | SKF generic header(4) | Fragment Number(2) | Total Fragments(2)
//! | IV | E(chunk | pad | padlen) | ICV
//! ```
//!
//! The 4-byte fragnum/total header sits between the generic header and the IV and
//! is inside the authenticated region. Fragment 1's generic header carries the type
//! of the first inner payload; fragments 2..n carry 0. Fragment numbers are 1-based.
//!
//! Outbound: fragmentation applies when the whole encrypted message would exceed
//! the threshold (AOSP `DEFAULT_FRAGMENT_SIZE` = 1280 bytes): the encoded inner
//! payload chain is split byte-wise into chunks of
//! `threshold - 28 - 4 - 4 - iv_len - icv_len - block_len` (= 1196 for AES-CBC +
//! HMAC-SHA2-256-128), so every fragment datagram is <= the threshold.
//!
//! Inbound: [`Reassembler`] verifies + decrypts each fragment on arrival, keeps
//! the plaintext chunks per message id (and direction), and once all are present
//! concatenates them and parses the result as one payload chain.

use crate::crypto::Suite;
use crate::ike::constants::*;
use crate::ike::header::IkeHeader;
use crate::ike::message::{IkeMessage, SKF_HEADER_LEN, check_total_length, open, seal};
use crate::ike::payload::{Payload, decode_payloads};
use crate::{Error, Result};
use std::collections::HashMap;

/// True if the datagram's IKE header names an SKF payload first (i.e. it is one
/// fragment of a larger message). False for anything unparsable.
pub fn is_fragment(raw: &[u8]) -> bool {
    match IkeHeader::decode(raw) {
        Ok(h) => h.next_payload == PT_SKF,
        Err(_) => false,
    }
}

/// `(message_id, fragment_number, total_fragments)` of an SKF datagram, read
/// from the unencrypted headers (no integrity check — for routing only).
pub fn fragment_info(raw: &[u8]) -> Result<(u32, u16, u16)> {
    let h = IkeHeader::decode(raw)?;
    if h.next_payload != PT_SKF {
        return Err(Error::Decode(format!(
            "not an SKF fragment: first payload is {} ({})",
            h.next_payload,
            Payload::type_name(h.next_payload)
        )));
    }
    let off = IkeHeader::LEN + GENERIC_PAYLOAD_HEADER_LEN;
    let skf = raw.get(off..off + SKF_HEADER_LEN).ok_or_else(|| {
        Error::Decode(format!("SKF fragment of {} bytes has no fragment header", raw.len()))
    })?;
    let num = u16::from_be_bytes([skf[0], skf[1]]);
    let total = u16::from_be_bytes([skf[2], skf[3]]);
    Ok((h.message_id, num, total))
}

/// Plaintext bytes that fit in one fragment datagram of at most `threshold` bytes
/// (AOSP: `fragSize - 28 - 4 - 4 - ivLen - checksumLen - blockSize`, reserving a
/// full block for padding). `Error::Encode` if the threshold is too small.
pub(crate) fn plaintext_per_fragment(suite: &Suite, threshold: usize) -> Result<usize> {
    let overhead = IkeHeader::LEN
        + GENERIC_PAYLOAD_HEADER_LEN
        + SKF_HEADER_LEN
        + suite.cipher.iv_len()
        + suite.integrity.icv_len()
        + suite.cipher.block_len().max(1);
    match threshold.checked_sub(overhead) {
        Some(n) if n > 0 => Ok(n),
        _ => Err(Error::Encode(format!(
            "fragment threshold {} too small (need > {} bytes of overhead)",
            threshold, overhead
        ))),
    }
}

/// Split the encoded inner payload chain `chain` into SKF fragment datagrams.
/// `header` is the message's header (next_payload is overwritten with `PT_SKF`);
/// `first_inner` is the type of the first inner payload (goes into fragment 1's
/// SKF generic header, 0 in the rest).
pub(crate) fn fragment(
    header: &IkeHeader,
    first_inner: u8,
    chain: &[u8],
    suite: &Suite,
    sk_e: &[u8],
    sk_a: &[u8],
    threshold: usize,
) -> Result<Vec<Vec<u8>>> {
    let per = plaintext_per_fragment(suite, threshold)?;
    let total = chain.len().div_ceil(per).max(1);
    let total_u16 = u16::try_from(total).map_err(|_| {
        Error::Encode(format!("{} fragments needed, exceeds the 16-bit Total Fragments field", total))
    })?;
    let mut hdr = *header;
    hdr.next_payload = PT_SKF;
    let mut out = Vec::with_capacity(total);
    let mut chunks: Vec<&[u8]> = chain.chunks(per).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let num = (i + 1) as u16;
        let next = if num == 1 { first_inner } else { PT_NONE };
        let datagram = seal(&hdr, next, Some((num, total_u16)), chunk, suite, sk_e, sk_a)?;
        debug_assert!(datagram.len() <= threshold);
        out.push(datagram);
    }
    log::debug!(
        "fragment: msgid={} chain={}B -> {} fragments of <= {}B plaintext (threshold {})",
        header.message_id,
        chain.len(),
        total,
        per,
        threshold
    );
    Ok(out)
}

/// One in-progress reassembly.
#[derive(Debug)]
struct Pending {
    total: u16,
    /// Header of fragment 1 (the message's canonical header), once seen.
    first_header: Option<IkeHeader>,
    /// Next Payload from fragment 1's SKF generic header.
    first_inner: Option<u8>,
    /// Plaintext chunks indexed by `fragment_number - 1`.
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
}

/// Reassembles SKF fragments, keyed by message id and direction (request vs
/// response, so a peer request and our own response with the same id never mix).
#[derive(Debug, Default)]
pub struct Reassembler {
    pending: HashMap<(u32, bool), Pending>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify + decrypt this fragment (per-fragment ICV) and stash its plaintext.
    /// Returns `Some(message)` once every fragment is present: the reassembled
    /// message carries fragment 1's header (`next_payload` = the inner first type)
    /// and the concatenated inner chain decoded. Duplicates are ignored; a fragment
    /// whose Total Fragments differs from the stored set is `Error::Decode`.
    pub fn push(&mut self, raw: &[u8], suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<Option<IkeMessage>> {
        let opened = open(raw, PT_SKF, suite, sk_e, sk_a)?;
        let (num, total) = opened
            .skf
            .ok_or_else(|| Error::Decode("SKF datagram opened without a fragment header".into()))?;
        if num < 1 || total < 1 || num > total {
            return Err(Error::Decode(format!(
                "invalid SKF fragment numbering {}/{}",
                num, total
            )));
        }
        let header = opened.header;
        let key = (header.message_id, header.is_response());
        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            total,
            first_header: None,
            first_inner: None,
            chunks: vec![None; total as usize],
            received: 0,
        });
        if entry.total != total {
            let stored = entry.total;
            self.pending.remove(&key);
            return Err(Error::Decode(format!(
                "SKF total fragments changed from {} to {} for message id {}",
                stored, total, header.message_id
            )));
        }
        let slot = (num - 1) as usize;
        let Some(slot_ref) = entry.chunks.get_mut(slot) else {
            return Err(Error::Decode(format!("SKF fragment {}/{} out of range", num, total)));
        };
        if slot_ref.is_some() {
            log::debug!(
                "reassembler: duplicate fragment {}/{} for msgid {}, ignored",
                num,
                total,
                header.message_id
            );
            return Ok(None);
        }
        *slot_ref = Some(opened.plaintext);
        entry.received += 1;
        if num == 1 {
            entry.first_header = Some(header);
            entry.first_inner = Some(opened.first_inner);
        }
        log::debug!(
            "reassembler: msgid={} fragment {}/{} stored ({} of {})",
            header.message_id,
            num,
            total,
            entry.received,
            total
        );
        if entry.received < total as usize {
            return Ok(None);
        }

        // Complete: concatenate in fragment order and decode as one chain.
        let Some(done) = self.pending.remove(&key) else {
            return Err(Error::Decode("reassembler lost its pending state".into()));
        };
        let mut chain = Vec::new();
        for (i, c) in done.chunks.into_iter().enumerate() {
            match c {
                Some(bytes) => chain.extend_from_slice(&bytes),
                None => {
                    return Err(Error::Decode(format!(
                        "SKF reassembly for msgid {} missing fragment {}",
                        header.message_id,
                        i + 1
                    )));
                }
            }
        }
        let first_inner = done.first_inner.unwrap_or(PT_NONE);
        let mut hdr = done.first_header.unwrap_or(header);
        hdr.next_payload = first_inner;
        hdr.length = u32::try_from(IkeHeader::LEN + chain.len())
            .map_err(|_| Error::Decode("reassembled message exceeds u32 length".into()))?;
        let payloads = decode_payloads(first_inner, &chain)?;
        log::debug!(
            "reassembler: msgid={} complete, {} fragments -> {}B inner, {} payloads",
            hdr.message_id,
            total,
            chain.len(),
            payloads.len()
        );
        Ok(Some(IkeMessage { header: hdr, payloads }))
    }

    /// Drop any partial state for `message_id` (both directions).
    pub fn clear(&mut self, message_id: u32) {
        self.pending.remove(&(message_id, false));
        self.pending.remove(&(message_id, true));
    }

    /// Number of message ids currently being reassembled.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Convenience: decode a set of datagrams that together form one message —
/// a single SK datagram, or all SKF fragments of one message id.
pub fn decode_datagrams(datagrams: &[Vec<u8>], suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<IkeMessage> {
    let mut r = Reassembler::new();
    for d in datagrams {
        if is_fragment(d) {
            if let Some(m) = r.push(d, suite, sk_e, sk_a)? {
                return Ok(m);
            }
        } else {
            let h = IkeHeader::decode(d)?;
            check_total_length(&h, d)?;
            return IkeMessage::decode_encrypted(d, suite, sk_e, sk_a);
        }
    }
    Err(Error::Decode(format!(
        "incomplete fragment set: {} datagrams did not complete a message",
        datagrams.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ike::message::test_support::*;
    use crate::ike::payload::*;

    fn big_message() -> (IkeMessage, Vec<u8>) {
        // Two Vendor payloads with 1496-byte bodies -> chain of exactly 3000 bytes.
        let body_a: Vec<u8> = (0..1496u32).map(|i| (i % 251) as u8).collect();
        let body_b: Vec<u8> = (0..1496u32).map(|i| (i * 7 % 253) as u8).collect();
        let payloads = vec![Payload::Vendor(body_a), Payload::Vendor(body_b)];
        let mut chain = Vec::new();
        encode_payloads(&payloads, &mut chain).unwrap();
        assert_eq!(chain.len(), 3000);
        let m = IkeMessage::new(0xAAAA, 0xBBBB, EXCH_IKE_AUTH, FLAG_INITIATOR, 2, payloads);
        (m, chain)
    }

    #[test]
    fn per_fragment_plaintext_is_1196_for_glue_suite() {
        assert_eq!(plaintext_per_fragment(&suite(), 1280).unwrap(), 1196);
        assert!(matches!(plaintext_per_fragment(&suite(), 84), Err(Error::Encode(_))));
        assert!(matches!(plaintext_per_fragment(&suite(), 10), Err(Error::Encode(_))));
        assert_eq!(plaintext_per_fragment(&suite(), 85).unwrap(), 1);
    }

    #[test]
    fn three_thousand_bytes_fragment_into_three() {
        let suite = suite();
        let (m, chain) = big_message();
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 1280).unwrap();
        assert_eq!(frags.len(), 3000_usize.div_ceil(1196));
        assert_eq!(frags.len(), 3);
        for (i, f) in frags.iter().enumerate() {
            assert!(f.len() <= 1280, "fragment {} is {} bytes", i + 1, f.len());
            assert!(is_fragment(f));
            assert_eq!(f[16], PT_SKF);
            assert_eq!(f[18], EXCH_IKE_AUTH);
            assert_eq!(f[19], FLAG_INITIATOR);
            assert_eq!(u32::from_be_bytes([f[24], f[25], f[26], f[27]]) as usize, f.len());
            // SKF generic header
            let expected_next = if i == 0 { PT_VENDOR } else { PT_NONE };
            assert_eq!(f[28], expected_next, "fragment {} next payload", i + 1);
            assert_eq!(f[29], 0);
            assert_eq!(u16::from_be_bytes([f[30], f[31]]) as usize, f.len() - 28);
            // fragnum / total
            let (msgid, num, total) = fragment_info(f).unwrap();
            assert_eq!(msgid, 2);
            assert_eq!(num, (i + 1) as u16);
            assert_eq!(total, 3);
            assert_eq!(&f[32..36], &[0, num as u8, 0, 3]);
        }
        // Fragments 1 and 2 carry 1196 bytes each: ct = padded(1196) = 1200 -> 28+4+4+16+1200+16 = 1268
        assert_eq!(frags[0].len(), 1268);
        assert_eq!(frags[1].len(), 1268);
        // Fragment 3 carries 3000 - 2392 = 608 -> ct 624 -> 692
        assert_eq!(frags[2].len(), 28 + 4 + 4 + 16 + (608usize + 1).div_ceil(16) * 16 + 16);

        // Each fragment individually opens to the right chunk of the chain.
        for (i, f) in frags.iter().enumerate() {
            let o = open(f, PT_SKF, &suite, &sk_e(), &sk_a()).unwrap();
            let start = i * 1196;
            let end = (start + 1196).min(chain.len());
            assert_eq!(o.plaintext, &chain[start..end]);
        }
    }

    #[test]
    fn reassemble_shuffled_with_duplicate() {
        let suite = suite();
        let (m, _) = big_message();
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 1280).unwrap();
        let mut r = Reassembler::new();
        assert!(r.push(&frags[2], &suite, &sk_e(), &sk_a()).unwrap().is_none());
        assert!(r.push(&frags[0], &suite, &sk_e(), &sk_a()).unwrap().is_none());
        // duplicate of fragment 3 is ignored
        assert!(r.push(&frags[2], &suite, &sk_e(), &sk_a()).unwrap().is_none());
        assert_eq!(r.pending_count(), 1);
        let done = r.push(&frags[1], &suite, &sk_e(), &sk_a()).unwrap().expect("complete");
        assert_eq!(done.payloads, m.payloads);
        assert_eq!(done.header.spi_i, 0xAAAA);
        assert_eq!(done.header.spi_r, 0xBBBB);
        assert_eq!(done.header.message_id, 2);
        assert_eq!(done.header.exchange_type, EXCH_IKE_AUTH);
        assert_eq!(done.header.next_payload, PT_VENDOR);
        assert_eq!(done.header.length as usize, 28 + 3000);
        assert_eq!(r.pending_count(), 0);

        // Also via the convenience helper, in reverse order.
        let rev: Vec<Vec<u8>> = frags.iter().rev().cloned().collect();
        let d = decode_datagrams(&rev, &suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(d.payloads, m.payloads);
        let single = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        let d = decode_datagrams(&[single], &suite, &sk_e(), &sk_a()).unwrap();
        assert_eq!(d.payloads, m.payloads);
        assert!(matches!(
            decode_datagrams(&frags[..2], &suite, &sk_e(), &sk_a()),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn reassembler_rejects_bad_fragments() {
        let suite = suite();
        let (m, _) = big_message();
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 1280).unwrap();
        let mut r = Reassembler::new();

        // Tampered ICV on a fragment -> Integrity, state untouched.
        let mut t = frags[0].clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(matches!(r.push(&t, &suite, &sk_e(), &sk_a()), Err(Error::Integrity(_))));
        assert_eq!(r.pending_count(), 0);

        // Wrong SK_a -> Integrity.
        let bad_a: Vec<u8> = sk_a().iter().map(|b| b ^ 0x55).collect();
        assert!(matches!(r.push(&frags[0], &suite, &sk_e(), &bad_a), Err(Error::Integrity(_))));

        // A plain SK datagram is not a fragment.
        let single = m.encode_encrypted(&suite, &sk_e(), &sk_a()).unwrap();
        assert!(!is_fragment(&single));
        assert!(matches!(fragment_info(&single), Err(Error::Decode(_))));
        assert!(matches!(r.push(&single, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));

        // Mismatched total: forge a fragment claiming total=4 (re-sealed so the ICV is valid).
        assert!(r.push(&frags[0], &suite, &sk_e(), &sk_a()).unwrap().is_none());
        let mut hdr = m.header;
        hdr.next_payload = PT_SKF;
        let forged = seal(&hdr, PT_NONE, Some((2, 4)), b"xyz", &suite, &sk_e(), &sk_a()).unwrap();
        assert!(matches!(r.push(&forged, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
        assert_eq!(r.pending_count(), 0, "mismatch discards the pending set");

        // Invalid numbering: 0/3 and 4/3.
        let zero = seal(&hdr, PT_NONE, Some((0, 3)), b"xyz", &suite, &sk_e(), &sk_a()).unwrap();
        assert!(matches!(r.push(&zero, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
        let over = seal(&hdr, PT_NONE, Some((4, 3)), b"xyz", &suite, &sk_e(), &sk_a()).unwrap();
        assert!(matches!(r.push(&over, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
        let notot = seal(&hdr, PT_NONE, Some((1, 0)), b"xyz", &suite, &sk_e(), &sk_a()).unwrap();
        assert!(matches!(r.push(&notot, &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));

        // Truncated / garbage input never panics.
        assert!(!is_fragment(&[]));
        assert!(!is_fragment(&frags[0][..10]));
        assert!(matches!(fragment_info(&frags[0][..30]), Err(Error::Decode(_))));
        assert!(matches!(r.push(&frags[0][..40], &suite, &sk_e(), &sk_a()), Err(Error::Decode(_))));
    }

    #[test]
    fn clear_and_direction_separation() {
        let suite = suite();
        let (m, _) = big_message();
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 1280).unwrap();
        let mut resp = m.clone();
        resp.header.flags = FLAG_RESPONSE;
        let rfrags = resp.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 1280).unwrap();

        let mut r = Reassembler::new();
        assert!(r.push(&frags[0], &suite, &sk_e(), &sk_a()).unwrap().is_none());
        assert!(r.push(&rfrags[0], &suite, &sk_e(), &sk_a()).unwrap().is_none());
        assert_eq!(r.pending_count(), 2, "request and response with the same msgid are separate");
        r.clear(2);
        assert_eq!(r.pending_count(), 0);

        // After clear, a full set completes normally.
        for f in &rfrags[..2] {
            assert!(r.push(f, &suite, &sk_e(), &sk_a()).unwrap().is_none());
        }
        let done = r.push(&rfrags[2], &suite, &sk_e(), &sk_a()).unwrap().unwrap();
        assert!(done.header.is_response());
        assert_eq!(done.payloads, m.payloads);
    }

    #[test]
    fn single_fragment_set_and_empty_first_fragment_type() {
        // A tiny threshold forces fragmentation even of a small message; a message
        // that fragments into exactly one SKF must still round-trip.
        let suite = suite();
        let m = IkeMessage::new(1, 2, EXCH_INFORMATIONAL, FLAG_INITIATOR, 9, vec![Payload::Vendor(vec![5; 20])]);
        // Unfragmented would be 28+4+16+32+16 = 96 bytes; threshold 90 -> 6 plaintext bytes per fragment.
        let frags = m.encode_encrypted_fragmented(&suite, &sk_e(), &sk_a(), 90).unwrap();
        assert_eq!(frags.len(), 24usize.div_ceil(6));
        let mut r = Reassembler::new();
        let mut result = None;
        for f in &frags {
            assert!(f.len() <= 90);
            if let Some(d) = r.push(f, &suite, &sk_e(), &sk_a()).unwrap() {
                result = Some(d);
            }
        }
        assert_eq!(result.unwrap().payloads, m.payloads);

        // Direct fragment() of a chain that fits in one chunk -> exactly one SKF, 1/1.
        let mut chain = Vec::new();
        let first = encode_payloads(&m.payloads, &mut chain).unwrap();
        let one = fragment(&m.header, first, &chain, &suite, &sk_e(), &sk_a(), 1280).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(fragment_info(&one[0]).unwrap(), (9, 1, 1));
        let d = Reassembler::new().push(&one[0], &suite, &sk_e(), &sk_a()).unwrap().unwrap();
        assert_eq!(d.payloads, m.payloads);
    }
}
