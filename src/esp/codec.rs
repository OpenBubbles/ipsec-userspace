//! ESP tunnel-mode packet codec (RFC 4303) for UDP-encapsulated ESP (RFC 3948).
//!
//! Datagram layout (no non-ESP marker — a datagram on port 4500 whose first four
//! bytes are not zero IS an ESP packet, RFC 3948 §2.1):
//!
//! ```text
//! SPI(4) | Seq(4) | IV(iv_len) | E( payload | pad | PadLen(1) | NextHeader(1) ) | ICV(icv_len)
//! ```
//!
//! * `payload` is the complete inner IPv4/IPv6 packet (tunnel mode).
//! * `pad` is `1,2,3,…` (RFC 4303 §2.4 default padding) so that
//!   `(payload + pad + 2) % block_len == 0` and the total is 4-byte aligned.
//! * `NextHeader` is 4 (IPv4) or 41 (IPv6), taken from the inner version nibble.
//! * `ICV = integrity(auth_key, SPI..ciphertext)`; verified in constant time
//!   BEFORE decryption and BEFORE the anti-replay window is updated (§3.4.3/§3.4.4).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::{debug, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{Cipher, Integrity, random_bytes};
use crate::esp::replay::ReplayWindow;
use crate::ike::constants::{NATT_KEEPALIVE, NEXT_HEADER_IPV4, NEXT_HEADER_IPV6, NON_ESP_MARKER};
use crate::{Error, Result};

/// Length of `SPI(4) | Seq(4)`.
const ESP_HDR_LEN: usize = 8;

/// One direction of a Child SA: SPI, algorithms and keys.
///
/// Keys are wiped on drop. `enc_key.len()` must equal `cipher.key_len()` and
/// `auth_key.len()` must equal `integrity.key_len()`; this is checked on every
/// encapsulate/decapsulate and surfaces as `Error::Crypto`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EspSa {
    pub spi: u32,
    #[zeroize(skip)]
    pub cipher: Arc<dyn Cipher>,
    #[zeroize(skip)]
    pub integrity: Arc<dyn Integrity>,
    pub enc_key: Vec<u8>,
    pub auth_key: Vec<u8>,
}

impl std::fmt::Debug for EspSa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EspSa")
            .field("spi", &format_args!("{:#010x}", self.spi))
            .field("cipher", &self.cipher.transform_id())
            .field("integrity", &self.integrity.transform_id())
            .field("enc_key_len", &self.enc_key.len())
            .field("auth_key_len", &self.auth_key.len())
            .finish()
    }
}

impl EspSa {
    /// Check key lengths against the algorithms.
    fn validate(&self) -> Result<()> {
        if self.enc_key.len() != self.cipher.key_len() {
            return Err(Error::Crypto(format!(
                "ESP SPI {:#010x}: encryption key is {} bytes, cipher wants {}",
                self.spi,
                self.enc_key.len(),
                self.cipher.key_len()
            )));
        }
        if self.auth_key.len() != self.integrity.key_len() {
            return Err(Error::Crypto(format!(
                "ESP SPI {:#010x}: integrity key is {} bytes, algorithm wants {}",
                self.spi,
                self.auth_key.len(),
                self.integrity.key_len()
            )));
        }
        Ok(())
    }
}

/// Outbound (encrypt) half of a Child SA. Thread-safe: the sequence counter is atomic.
pub struct EspOutbound {
    sa: EspSa,
    /// Next sequence number to send. Starts at 1 (RFC 4303 §2.2).
    next_seq: AtomicU32,
}

impl EspOutbound {
    pub fn new(sa: EspSa) -> Self {
        EspOutbound { sa, next_seq: AtomicU32::new(1) }
    }

    /// Outbound SPI (the peer's inbound SPI).
    pub fn spi(&self) -> u32 {
        self.sa.spi
    }

    /// Sequence number of the most recently sent packet (0 before the first).
    pub fn seq(&self) -> u32 {
        self.next_seq.load(Ordering::SeqCst).wrapping_sub(1)
    }

    /// Reserve the next sequence number. `Error::Protocol` once the counter
    /// reaches 2^32-1: the SA must be rekeyed (RFC 4303 §2.2.1 without ESN).
    fn take_seq(&self) -> Result<u32> {
        self.next_seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| if s == u32::MAX { None } else { Some(s + 1) })
            .map_err(|_| Error::Protocol(format!("ESP SPI {:#010x}: sequence number exhausted, rekey required", self.sa.spi)))
    }

    /// Build a complete ESP-in-UDP datagram for `inner_ip_packet`
    /// (`SPI | Seq | IV | ciphertext | ICV`, no non-ESP marker).
    pub fn encapsulate(&self, inner_ip_packet: &[u8]) -> Result<Vec<u8>> {
        self.sa.validate()?;
        let next_header = next_header_of(inner_ip_packet)?;
        let cipher = &self.sa.cipher;
        let integ = &self.sa.integrity;
        let block_len = cipher.block_len().max(1);
        let iv_len = cipher.iv_len();
        let icv_len = integ.icv_len();

        // Pad so that payload | pad | PadLen | NextHeader is a multiple of the
        // block size AND 4-byte aligned (RFC 4303 §2.4).
        let align = block_len.max(4);
        let pad_len = (align - (inner_ip_packet.len() + 2) % align) % align;
        if pad_len > 255 {
            return Err(Error::Encode(format!("ESP pad length {} exceeds 255", pad_len)));
        }
        let plain_len = inner_ip_packet.len() + pad_len + 2;

        let seq = self.take_seq()?;

        let mut out = Vec::with_capacity(ESP_HDR_LEN + iv_len + plain_len + icv_len);
        out.extend_from_slice(&self.sa.spi.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        let iv = random_bytes(iv_len);
        out.extend_from_slice(&iv);
        let ct_start = out.len();
        out.extend_from_slice(inner_ip_packet);
        out.extend((1..=pad_len).map(|i| i as u8));
        out.push(pad_len as u8);
        out.push(next_header);
        debug_assert_eq!((out.len() - ct_start) % block_len, 0);

        cipher.encrypt(&self.sa.enc_key, &iv, &mut out[ct_start..])?;
        let icv = integ.compute(&self.sa.auth_key, &out);
        if icv.len() != icv_len {
            return Err(Error::Crypto(format!("integrity produced {} bytes, expected {}", icv.len(), icv_len)));
        }
        out.extend_from_slice(&icv);

        debug!(
            "ESP tx spi={:#010x} seq={} inner={}B nh={} pad={} datagram={}B",
            self.sa.spi,
            seq,
            inner_ip_packet.len(),
            next_header,
            pad_len,
            out.len()
        );
        Ok(out)
    }
}

/// Inbound (decrypt) half of a Child SA with its anti-replay window.
pub struct EspInbound {
    sa: EspSa,
    replay: ReplayWindow,
}

impl EspInbound {
    /// `replay_window` is rounded up to at least 32 (RFC 4303 §3.4.3).
    pub fn new(sa: EspSa, replay_window: u32) -> Self {
        EspInbound { sa, replay: ReplayWindow::new(replay_window) }
    }

    /// Inbound SPI (the SPI we allocated).
    pub fn spi(&self) -> u32 {
        self.sa.spi
    }

    /// The anti-replay window (for stats / diagnostics).
    pub fn replay_window(&self) -> &ReplayWindow {
        &self.replay
    }

    /// Verify and decrypt one ESP datagram (without non-ESP marker), returning
    /// the inner IP packet.
    ///
    /// Order of checks: length → SPI match (`Error::Protocol`) → ICV, constant
    /// time (`Error::Integrity`) → anti-replay (`Error::Protocol`) → decrypt →
    /// padding / NextHeader sanity (`Error::Decode`).
    pub fn decapsulate(&mut self, esp: &[u8]) -> Result<Vec<u8>> {
        self.sa.validate()?;
        let cipher = &self.sa.cipher;
        let integ = &self.sa.integrity;
        let block_len = cipher.block_len().max(1);
        let iv_len = cipher.iv_len();
        let icv_len = integ.icv_len();

        // Minimum: header + IV + at least one block (PadLen + NextHeader) + ICV.
        let min_len = ESP_HDR_LEN + iv_len + block_len + icv_len;
        if esp.len() < min_len {
            return Err(Error::Decode(format!("ESP datagram too short: {} bytes, need at least {}", esp.len(), min_len)));
        }
        let spi = u32::from_be_bytes([esp[0], esp[1], esp[2], esp[3]]);
        let seq = u32::from_be_bytes([esp[4], esp[5], esp[6], esp[7]]);
        if spi != self.sa.spi {
            return Err(Error::Protocol(format!("ESP SPI mismatch: got {:#010x}, expected {:#010x}", spi, self.sa.spi)));
        }

        // ICV over SPI..ciphertext, verified BEFORE anything else touches the payload.
        let (authed, icv) = esp.split_at(esp.len() - icv_len);
        if !integ.verify(&self.sa.auth_key, authed, icv) {
            debug!("ESP rx spi={:#010x} seq={} ICV mismatch ({} bytes)", spi, seq, esp.len());
            return Err(Error::Integrity("ESP ICV mismatch"));
        }

        // Anti-replay after authentication (RFC 4303 §3.4.3).
        if !self.replay.check_and_update(seq) {
            return Err(Error::Protocol(format!(
                "ESP replay: seq {} rejected on SPI {:#010x} (window right edge {})",
                seq,
                spi,
                self.replay.last_seq()
            )));
        }

        let iv = &authed[ESP_HDR_LEN..ESP_HDR_LEN + iv_len];
        let ct = &authed[ESP_HDR_LEN + iv_len..];
        if ct.is_empty() || ct.len() % block_len != 0 {
            return Err(Error::Decode(format!("ESP ciphertext length {} is not a multiple of {}", ct.len(), block_len)));
        }
        let mut plain = ct.to_vec();
        cipher.decrypt(&self.sa.enc_key, iv, &mut plain)?;

        // Trailer: ... | PadLen | NextHeader
        let next_header = plain[plain.len() - 1];
        let pad_len = usize::from(plain[plain.len() - 2]);
        let payload_len = plain
            .len()
            .checked_sub(2 + pad_len)
            .ok_or_else(|| Error::Decode(format!("ESP pad length {} exceeds plaintext {}", pad_len, plain.len() - 2)))?;
        if next_header != NEXT_HEADER_IPV4 && next_header != NEXT_HEADER_IPV6 {
            return Err(Error::Decode(format!("ESP next header {} is not IPv4 (4) or IPv6 (41)", next_header)));
        }
        // RFC 4303 §2.4: the receiver MAY inspect the default padding; we only warn.
        let pad_ok = plain[payload_len..payload_len + pad_len].iter().enumerate().all(|(i, &b)| b == (i + 1) as u8);
        if !pad_ok {
            warn!("ESP rx spi={:#010x} seq={}: non-standard padding bytes", spi, seq);
        }
        if let Some(&first) = plain.first() {
            let want = if next_header == NEXT_HEADER_IPV4 { 4 } else { 6 };
            if payload_len > 0 && first >> 4 != want {
                warn!(
                    "ESP rx spi={:#010x} seq={}: next header {} but inner version nibble {}",
                    spi,
                    seq,
                    next_header,
                    first >> 4
                );
            }
        }
        plain.truncate(payload_len);
        debug!(
            "ESP rx spi={:#010x} seq={} datagram={}B inner={}B nh={} pad={}",
            spi,
            seq,
            esp.len(),
            payload_len,
            next_header,
            pad_len
        );
        Ok(plain)
    }
}

/// Derive the ESP NextHeader value from the inner packet's IP version nibble.
fn next_header_of(inner: &[u8]) -> Result<u8> {
    match inner.first().map(|b| b >> 4) {
        Some(4) => Ok(NEXT_HEADER_IPV4),
        Some(6) => Ok(NEXT_HEADER_IPV6),
        Some(v) => Err(Error::Encode(format!("inner packet has IP version {}, expected 4 or 6", v))),
        None => Err(Error::Encode("inner packet is empty".into())),
    }
}

/// What a datagram received on the UDP/4500 socket is (RFC 3948 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramKind {
    /// Starts with the 4-byte zero non-ESP marker: an IKE message follows.
    IkeMarker,
    /// Exactly one `0xFF` byte: NAT-keepalive.
    Keepalive,
    /// Anything else: an ESP packet (SPI first).
    Esp,
}

/// Classify a datagram received on the NAT-T socket.
pub fn classify(datagram: &[u8]) -> DatagramKind {
    if datagram.len() >= NON_ESP_MARKER.len() && datagram[..NON_ESP_MARKER.len()] == NON_ESP_MARKER {
        DatagramKind::IkeMarker
    } else if datagram == NATT_KEEPALIVE {
        DatagramKind::Keepalive
    } else {
        DatagramKind::Esp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::registry;
    use crate::ike::constants::{AUTH_HMAC_SHA2_256_128, ENCR_AES_CBC};

    fn sa(spi: u32) -> EspSa {
        let cipher = registry::cipher(ENCR_AES_CBC, Some(256)).expect("AES-CBC-256 in registry");
        let integrity = registry::integrity(AUTH_HMAC_SHA2_256_128).expect("HMAC-SHA2-256-128 in registry");
        EspSa {
            spi,
            enc_key: (0..cipher.key_len()).map(|i| i as u8).collect(),
            auth_key: (0..integrity.key_len()).map(|i| 0xa0 ^ i as u8).collect(),
            cipher,
            integrity,
        }
    }

    fn pair(spi: u32) -> (EspOutbound, EspInbound) {
        (EspOutbound::new(sa(spi)), EspInbound::new(sa(spi), 12))
    }

    /// Minimal "inner packet": version nibble byte followed by `n` filler bytes.
    fn inner(version: u8, n: usize) -> Vec<u8> {
        let mut v = vec![version << 4 | 0x5];
        v.extend((0..n).map(|i| (i * 7 + 3) as u8));
        v
    }

    #[test]
    fn roundtrip_v4_v6_all_lengths() {
        for version in [4u8, 6u8] {
            let (tx, mut rx) = pair(0x1234_5678);
            for n in 0..48 {
                let pkt = inner(version, n);
                let esp = tx.encapsulate(&pkt).unwrap();
                let got = rx.decapsulate(&esp).unwrap();
                assert_eq!(got, pkt, "version {} filler {}", version, n);
            }
            assert_eq!(tx.seq(), 48);
            assert_eq!(rx.replay_window().last_seq(), 48);
        }
    }

    #[test]
    fn wire_layout() {
        let (tx, _) = pair(0xdead_beef);
        let pkt = inner(4, 19); // 20 bytes -> 20 + pad + 2 = 32 -> pad 10
        let esp = tx.encapsulate(&pkt).unwrap();
        assert_eq!(&esp[0..4], &0xdead_beefu32.to_be_bytes());
        assert_eq!(&esp[4..8], &1u32.to_be_bytes());
        let iv_len = 16;
        let icv_len = 16;
        let ct_len = esp.len() - 8 - iv_len - icv_len;
        assert_eq!(ct_len % 16, 0);
        assert_eq!(ct_len, 32);
        assert_eq!(esp.len(), 8 + 16 + 32 + 16);

        // Decrypt by hand to check the trailer: pad 1..=10 | 10 | 4.
        let s = sa(0xdead_beef);
        let mut plain = esp[24..24 + ct_len].to_vec();
        s.cipher.decrypt(&s.enc_key, &esp[8..24], &mut plain).unwrap();
        assert_eq!(&plain[..20], &pkt[..]);
        assert_eq!(&plain[20..30], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(plain[30], 10);
        assert_eq!(plain[31], NEXT_HEADER_IPV4);

        // ICV is HMAC over everything before it.
        let icv = s.integrity.compute(&s.auth_key, &esp[..esp.len() - icv_len]);
        assert_eq!(&esp[esp.len() - icv_len..], &icv[..]);

        // Second packet: seq 2; IPv6 next header.
        let esp2 = tx.encapsulate(&inner(6, 0)).unwrap();
        assert_eq!(&esp2[4..8], &2u32.to_be_bytes());
        let mut plain2 = esp2[24..esp2.len() - icv_len].to_vec();
        assert_eq!(plain2.len(), 16); // 1 + 13 pad + 2
        s.cipher.decrypt(&s.enc_key, &esp2[8..24], &mut plain2).unwrap();
        assert_eq!(plain2[14], 13);
        assert_eq!(plain2[15], NEXT_HEADER_IPV6);
        assert_eq!(&plain2[1..14], &(1u8..=13).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn pad_alignment_exact_block() {
        // payload 14 + 2 = 16 -> no pad
        let (tx, _) = pair(1);
        let esp = tx.encapsulate(&inner(4, 13)).unwrap();
        assert_eq!(esp.len(), 8 + 16 + 16 + 16);
        let s = sa(1);
        let mut plain = esp[24..40].to_vec();
        s.cipher.decrypt(&s.enc_key, &esp[8..24], &mut plain).unwrap();
        assert_eq!(plain[14], 0);
    }

    #[test]
    fn iv_differs_per_packet() {
        let (tx, _) = pair(1);
        let a = tx.encapsulate(&inner(4, 3)).unwrap();
        let b = tx.encapsulate(&inner(4, 3)).unwrap();
        assert_ne!(&a[8..24], &b[8..24]);
        assert_ne!(&a[24..40], &b[24..40]);
    }

    #[test]
    fn icv_tamper_is_integrity_error() {
        let (tx, mut rx) = pair(7);
        let mut esp = tx.encapsulate(&inner(4, 10)).unwrap();
        let last = esp.len() - 1;
        esp[last] ^= 0x01;
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Integrity(_))));
        // ciphertext tamper also fails the ICV
        let mut esp = tx.encapsulate(&inner(4, 10)).unwrap();
        esp[30] ^= 0x80;
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Integrity(_))));
        // seq tamper too
        let mut esp = tx.encapsulate(&inner(4, 10)).unwrap();
        esp[7] ^= 0x80;
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Integrity(_))));
        // failed packets must not have touched the replay window
        assert_eq!(rx.replay_window().last_seq(), 0);
        // an untampered packet still works
        let esp = tx.encapsulate(&inner(4, 10)).unwrap();
        assert!(rx.decapsulate(&esp).is_ok());
    }

    #[test]
    fn wrong_spi_rejected() {
        let tx = EspOutbound::new(sa(0x1111));
        let mut rx = EspInbound::new(sa(0x2222), 32);
        let esp = tx.encapsulate(&inner(4, 4)).unwrap();
        match rx.decapsulate(&esp) {
            Err(Error::Protocol(m)) => assert!(m.contains("SPI"), "{}", m),
            other => panic!("expected SPI error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn wrong_key_is_integrity_error() {
        let tx = EspOutbound::new(sa(5));
        let mut bad = sa(5);
        bad.auth_key[0] ^= 1;
        let mut rx = EspInbound::new(bad, 32);
        let esp = tx.encapsulate(&inner(4, 4)).unwrap();
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Integrity(_))));
    }

    #[test]
    fn bad_key_length_is_crypto_error() {
        let mut s = sa(5);
        s.enc_key.truncate(16);
        let tx = EspOutbound::new(s.clone());
        assert!(matches!(tx.encapsulate(&inner(4, 4)), Err(Error::Crypto(_))));
        let mut rx = EspInbound::new(s, 32);
        assert!(matches!(rx.decapsulate(&[0u8; 64]), Err(Error::Crypto(_))));
        let mut s = sa(5);
        s.auth_key.push(0);
        assert!(matches!(EspOutbound::new(s).encapsulate(&inner(4, 4)), Err(Error::Crypto(_))));
    }

    #[test]
    fn replay_semantics_through_decapsulate() {
        let (tx, mut rx) = pair(9);
        // Pre-build 100 packets with seq 1..=100.
        let pkts: Vec<Vec<u8>> = (0..100).map(|_| tx.encapsulate(&inner(6, 5)).unwrap()).collect();
        let p = |n: usize| &pkts[n - 1];
        assert!(rx.decapsulate(p(1)).is_ok());
        assert!(rx.decapsulate(p(3)).is_ok());
        assert!(rx.decapsulate(p(2)).is_ok());
        assert!(matches!(rx.decapsulate(p(2)), Err(Error::Protocol(_))));
        assert!(rx.decapsulate(p(100)).is_ok());
        assert!(matches!(rx.decapsulate(p(60)), Err(Error::Protocol(_))));
        assert!(rx.decapsulate(p(90)).is_ok());
        assert!(matches!(rx.decapsulate(p(90)), Err(Error::Protocol(_))));
    }

    #[test]
    fn seq_zero_rejected() {
        // Forge a valid packet with seq 0 using the SA keys directly.
        let s = sa(3);
        let mut esp = Vec::new();
        esp.extend_from_slice(&3u32.to_be_bytes());
        esp.extend_from_slice(&0u32.to_be_bytes());
        let iv = [0x11u8; 16];
        esp.extend_from_slice(&iv);
        let mut plain = inner(4, 13);
        plain.push(0);
        plain.push(NEXT_HEADER_IPV4);
        s.cipher.encrypt(&s.enc_key, &iv, &mut plain).unwrap();
        esp.extend_from_slice(&plain);
        let icv = s.integrity.compute(&s.auth_key, &esp);
        esp.extend_from_slice(&icv);
        let mut rx = EspInbound::new(s, 32);
        match rx.decapsulate(&esp) {
            Err(Error::Protocol(m)) => assert!(m.contains("replay"), "{}", m),
            other => panic!("expected replay rejection, got {:?}", other.map(|_| ())),
        }
    }

    /// Build an authenticated packet with an arbitrary plaintext trailer.
    fn forge(s: &EspSa, seq: u32, plain: &[u8]) -> Vec<u8> {
        let mut esp = Vec::new();
        esp.extend_from_slice(&s.spi.to_be_bytes());
        esp.extend_from_slice(&seq.to_be_bytes());
        let iv = [0x22u8; 16];
        esp.extend_from_slice(&iv);
        let mut ct = plain.to_vec();
        if !ct.is_empty() {
            s.cipher.encrypt(&s.enc_key, &iv, &mut ct).unwrap();
        }
        esp.extend_from_slice(&ct);
        let icv = s.integrity.compute(&s.auth_key, &esp);
        esp.extend_from_slice(&icv);
        esp
    }

    #[test]
    fn bad_next_header_is_decode_error() {
        let s = sa(4);
        let mut plain = inner(4, 13);
        plain.push(0);
        plain.push(17);
        let esp = forge(&s, 1, &plain);
        let mut rx = EspInbound::new(s, 32);
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Decode(_))));
    }

    #[test]
    fn oversize_pad_len_is_decode_error() {
        let s = sa(4);
        let mut plain = vec![0x45u8; 14];
        plain.push(200); // pad length > plaintext
        plain.push(NEXT_HEADER_IPV4);
        let esp = forge(&s, 1, &plain);
        let mut rx = EspInbound::new(s, 32);
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Decode(_))));
    }

    #[test]
    fn short_datagrams_are_decode_errors() {
        let s = sa(4);
        let mut rx = EspInbound::new(s.clone(), 32);
        assert!(matches!(rx.decapsulate(&[]), Err(Error::Decode(_))));
        assert!(matches!(rx.decapsulate(&[0u8; 8]), Err(Error::Decode(_))));
        assert!(matches!(rx.decapsulate(&[0u8; 55]), Err(Error::Decode(_))));
        // Authenticated but empty ciphertext (8 + 16 + 0 + 16 = 40 bytes) is too short.
        let esp = forge(&s, 1, &[]);
        assert_eq!(esp.len(), 40);
        assert!(matches!(rx.decapsulate(&esp), Err(Error::Decode(_))));
    }

    #[test]
    fn encapsulate_rejects_bad_inner() {
        let (tx, _) = pair(1);
        assert!(matches!(tx.encapsulate(&[]), Err(Error::Encode(_))));
        assert!(matches!(tx.encapsulate(&[0x50, 0, 0]), Err(Error::Encode(_))));
        assert!(matches!(tx.encapsulate(&[0x00]), Err(Error::Encode(_))));
        // failed encapsulations do not consume a sequence number
        assert_eq!(tx.seq(), 0);
        let esp = tx.encapsulate(&inner(4, 0)).unwrap();
        assert_eq!(&esp[4..8], &1u32.to_be_bytes());
    }

    #[test]
    fn seq_exhaustion_is_protocol_error() {
        let tx = EspOutbound::new(sa(1));
        tx.next_seq.store(u32::MAX - 1, Ordering::SeqCst);
        let esp = tx.encapsulate(&inner(4, 0)).unwrap();
        assert_eq!(&esp[4..8], &(u32::MAX - 1).to_be_bytes());
        assert_eq!(tx.seq(), u32::MAX - 1);
        assert!(matches!(tx.encapsulate(&inner(4, 0)), Err(Error::Protocol(_))));
        assert!(matches!(tx.encapsulate(&inner(4, 0)), Err(Error::Protocol(_))));
    }

    #[test]
    fn accessors() {
        let (tx, rx) = pair(0xabcd);
        assert_eq!(tx.spi(), 0xabcd);
        assert_eq!(rx.spi(), 0xabcd);
        assert_eq!(tx.seq(), 0);
        assert_eq!(rx.replay_window().size(), 32);
        assert_eq!(EspInbound::new(sa(1), 128).replay_window().size(), 128);
        let dbg = format!("{:?}", sa(0xabcd));
        assert!(dbg.contains("0x0000abcd"));
        assert!(!dbg.contains("enc_key:"));
    }

    #[test]
    fn classify_cases() {
        assert_eq!(classify(&[0, 0, 0, 0]), DatagramKind::IkeMarker);
        assert_eq!(classify(&[0, 0, 0, 0, 1, 2, 3]), DatagramKind::IkeMarker);
        assert_eq!(classify(&[0xff]), DatagramKind::Keepalive);
        assert_eq!(classify(&[0xff, 0xff]), DatagramKind::Esp);
        assert_eq!(classify(&[]), DatagramKind::Esp);
        assert_eq!(classify(&[0, 0, 0]), DatagramKind::Esp);
        assert_eq!(classify(&[0, 0, 0, 1]), DatagramKind::Esp);
        assert_eq!(classify(&[0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1]), DatagramKind::Esp);
        let (tx, _) = pair(0x0000_0001);
        assert_eq!(classify(&tx.encapsulate(&inner(4, 0)).unwrap()), DatagramKind::Esp);
    }
}
