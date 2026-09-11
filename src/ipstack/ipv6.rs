//! IPv6 + UDP build/parse (RFC 8200, RFC 768) and the Fragment-header reassembler
//! (RFC 8200 §4.5).
//!
//! Build: hop limit 64, next header 17, traffic class / flow label 0, MANDATORY UDP
//! checksum over the v6 pseudo-header (a computed 0 is transmitted as 0xffff).
//! Parse: walks Hop-by-Hop (0), Routing (43) and Destination Options (60) extension
//! headers; UDP is decoded, Fragment (44) is `Error::Unsupported` unless routed through
//! [`Ipv6FragmentReassembler`]; anything else is reported as `ParsedIp::Other`.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::time::{Duration, Instant};

use log::debug;

use crate::{Error, Result};

pub use super::udp::{ParsedIp, UdpDatagram};
use super::udp::{Checksum, IPPROTO_FRAGMENT, IPPROTO_UDP, split_udp, udp_segment};

/// Fixed IPv6 header length.
pub const IPV6_HEADER_LEN: usize = 40;
/// Length of the Fragment extension header.
pub const FRAGMENT_HEADER_LEN: usize = 8;
const HOP_LIMIT: u8 = 64;
const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_DEST_OPTS: u8 = 60;
/// Partially reassembled datagrams older than this are discarded.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Build an IPv6 packet carrying one UDP datagram.
pub fn build_udp(src: SocketAddrV6, dst: SocketAddrV6, payload: &[u8]) -> Result<Vec<u8>> {
    let mut udp = udp_segment(src.port(), dst.port(), payload)?;
    let csum = udp_checksum(src.ip(), dst.ip(), &udp);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    let mut pkt = Vec::with_capacity(IPV6_HEADER_LEN + udp.len());
    pkt.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, TC 0, flow label 0
    pkt.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pkt.push(IPPROTO_UDP);
    pkt.push(HOP_LIMIT);
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    pkt.extend_from_slice(&udp);
    Ok(pkt)
}

/// UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1) + the UDP segment, with the
/// RFC 768/8200 rule that a computed 0 is sent as 0xffff. `seg` must have a zero
/// checksum field.
pub fn udp_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, seg: &[u8]) -> u16 {
    match udp_checksum_raw(src, dst, seg) {
        0 => 0xffff,
        c => c,
    }
}

/// Same as [`udp_checksum`] without the 0 -> 0xffff substitution (verification value:
/// 0 for a valid segment).
fn udp_checksum_raw(src: &Ipv6Addr, dst: &Ipv6Addr, seg: &[u8]) -> u16 {
    let mut c = Checksum::new();
    c.add(&src.octets());
    c.add(&dst.octets());
    c.add_u32(seg.len() as u32);
    c.add_u16(0);
    c.add_u16(u16::from(IPPROTO_UDP));
    c.add(seg);
    c.finish()
}

/// Location of the upper-layer header after walking the extension chain.
struct Chain {
    /// Next-header value of the first non-extension header.
    next: u8,
    /// Offset of that header's data in the packet.
    offset: usize,
    /// Offset of the byte holding `next` (in the IPv6 header or the last ext header).
    next_field_offset: usize,
}

struct Fixed {
    payload_len: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
}

fn fixed_header(pkt: &[u8]) -> Result<Fixed> {
    if pkt.len() < IPV6_HEADER_LEN {
        return Err(Error::decode(format!("ipv6: packet too short ({} bytes)", pkt.len())));
    }
    let version = pkt[0] >> 4;
    if version != 6 {
        return Err(Error::decode(format!("ipv6: version nibble {version}")));
    }
    let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if IPV6_HEADER_LEN + payload_len > pkt.len() {
        return Err(Error::decode(format!(
            "ipv6: payload length {payload_len} exceeds available {} bytes",
            pkt.len() - IPV6_HEADER_LEN
        )));
    }
    let mut s = [0u8; 16];
    s.copy_from_slice(&pkt[8..24]);
    let mut d = [0u8; 16];
    d.copy_from_slice(&pkt[24..40]);
    Ok(Fixed { payload_len, src: Ipv6Addr::from(s), dst: Ipv6Addr::from(d) })
}

/// Walk Hop-by-Hop / Routing / Destination Options headers. Stops at the first header
/// that is not one of those (including Fragment).
fn walk_chain(pkt: &[u8], end: usize) -> Result<Chain> {
    let mut next = pkt[6];
    let mut next_field_offset = 6usize;
    let mut offset = IPV6_HEADER_LEN;
    loop {
        match next {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTS => {
                if offset + 2 > end {
                    return Err(Error::decode(format!(
                        "ipv6: extension header {next} truncated at offset {offset}"
                    )));
                }
                let len = (usize::from(pkt[offset + 1]) + 1) * 8;
                if offset + len > end {
                    return Err(Error::decode(format!(
                        "ipv6: extension header {next} length {len} exceeds packet"
                    )));
                }
                next_field_offset = offset;
                next = pkt[offset];
                offset += len;
            }
            _ => return Ok(Chain { next, offset, next_field_offset }),
        }
    }
}

/// True if the packet's header chain reaches a Fragment header.
pub fn is_fragment(pkt: &[u8]) -> Result<bool> {
    let f = fixed_header(pkt)?;
    let chain = walk_chain(pkt, IPV6_HEADER_LEN + f.payload_len)?;
    Ok(chain.next == IPPROTO_FRAGMENT)
}

/// Parse an IPv6 packet. Fragments are `Error::Unsupported` here.
pub fn parse(pkt: &[u8]) -> Result<ParsedIp> {
    let f = fixed_header(pkt)?;
    let end = IPV6_HEADER_LEN + f.payload_len;
    let chain = walk_chain(pkt, end)?;
    match chain.next {
        IPPROTO_UDP => {
            let seg = &pkt[chain.offset..end];
            let (hdr, payload) = split_udp(seg)?;
            if hdr.checksum == 0 {
                return Err(Error::decode("ipv6: udp checksum is zero (mandatory)"));
            }
            let seg = &seg[..usize::from(hdr.length)];
            if udp_checksum_raw(&f.src, &f.dst, seg) != 0 {
                return Err(Error::decode("ipv6: udp checksum mismatch"));
            }
            Ok(ParsedIp::Udp(UdpDatagram {
                src: SocketAddrV6::new(f.src, hdr.src_port, 0, 0).into(),
                dst: SocketAddrV6::new(f.dst, hdr.dst_port, 0, 0).into(),
                payload: payload.to_vec(),
            }))
        }
        IPPROTO_FRAGMENT => Err(Error::Unsupported(
            "ipv6: fragment without reassembler (use parse_ipv6_or_fragment)".into(),
        )),
        protocol => Ok(ParsedIp::Other {
            version: 6,
            protocol,
            src: IpAddr::V6(f.src),
            dst: IpAddr::V6(f.dst),
        }),
    }
}

// ---------------------------------------------------------------------------
// Fragment reassembly (RFC 8200 §4.5)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Partial {
    created: Instant,
    /// Unfragmentable part (IPv6 header + ext headers before the Fragment header),
    /// with the last next-header field already rewritten. Taken from the offset-0 fragment.
    unfragmentable: Option<Vec<u8>>,
    /// Fragment offset (bytes) -> fragment data.
    chunks: BTreeMap<usize, Vec<u8>>,
    /// Total fragmentable length, known once the M=0 fragment arrived.
    total_len: Option<usize>,
}

impl Partial {
    fn new(now: Instant) -> Self {
        Self { created: now, unfragmentable: None, chunks: BTreeMap::new(), total_len: None }
    }

    fn is_complete(&self) -> bool {
        let (Some(total), Some(_)) = (self.total_len, &self.unfragmentable) else {
            return false;
        };
        let mut expect = 0usize;
        for (&off, data) in &self.chunks {
            if off != expect {
                return false;
            }
            expect += data.len();
        }
        expect == total
    }
}

/// Reassembles fragmented IPv6 datagrams, keyed by (src, dst, identification).
#[derive(Debug, Default)]
pub struct Ipv6FragmentReassembler {
    partials: HashMap<(Ipv6Addr, Ipv6Addr, u32), Partial>,
}

impl Ipv6FragmentReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of datagrams currently being reassembled.
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    /// Feed one fragment. Returns the reassembled, unfragmented packet once complete.
    pub fn push(&mut self, pkt: &[u8]) -> Result<Option<Vec<u8>>> {
        self.push_at(pkt, Instant::now())
    }

    /// [`push`](Self::push) with an explicit clock (for tests of the eviction policy).
    pub fn push_at(&mut self, pkt: &[u8], now: Instant) -> Result<Option<Vec<u8>>> {
        self.evict(now);

        let f = fixed_header(pkt)?;
        let end = IPV6_HEADER_LEN + f.payload_len;
        let chain = walk_chain(pkt, end)?;
        if chain.next != IPPROTO_FRAGMENT {
            return Err(Error::decode("ipv6: not a fragment"));
        }
        let fh = chain.offset;
        if fh + FRAGMENT_HEADER_LEN > end {
            return Err(Error::decode("ipv6: fragment header truncated"));
        }
        let inner_next = pkt[fh];
        let off_flags = u16::from_be_bytes([pkt[fh + 2], pkt[fh + 3]]);
        let frag_offset = usize::from(off_flags >> 3) * 8;
        let more = off_flags & 1 != 0;
        let id = u32::from_be_bytes([pkt[fh + 4], pkt[fh + 5], pkt[fh + 6], pkt[fh + 7]]);
        let data = &pkt[fh + FRAGMENT_HEADER_LEN..end];

        if more && !data.len().is_multiple_of(8) {
            return Err(Error::decode(format!(
                "ipv6: non-final fragment length {} not a multiple of 8",
                data.len()
            )));
        }
        if frag_offset + data.len() > u16::MAX as usize {
            return Err(Error::decode("ipv6: reassembled datagram would exceed 65535 bytes"));
        }
        debug!(
            "ipv6 fragment id={id:#x} offset={frag_offset} len={} more={more} from {}",
            data.len(),
            f.src
        );

        let key = (f.src, f.dst, id);
        let p = self.partials.entry(key).or_insert_with(|| Partial::new(now));

        // Overlap / duplicate detection: RFC 8200 §4.5 says overlapping fragments must
        // cause the whole datagram to be discarded.
        let overlaps = p.chunks.iter().any(|(&o, d)| {
            let (a0, a1) = (o, o + d.len());
            let (b0, b1) = (frag_offset, frag_offset + data.len());
            a0 < b1 && b0 < a1
        });
        if overlaps {
            self.partials.remove(&key);
            return Err(Error::decode(format!("ipv6: overlapping fragment for id {id:#x}")));
        }

        if frag_offset == 0 {
            let mut unf = pkt[..fh].to_vec();
            unf[chain.next_field_offset] = inner_next;
            p.unfragmentable = Some(unf);
        }
        if !more {
            let total = frag_offset + data.len();
            if let Some(prev) = p.total_len
                && prev != total
            {
                self.partials.remove(&key);
                return Err(Error::decode("ipv6: conflicting final fragments"));
            }
            p.total_len = Some(total);
        }
        if let Some(total) = p.total_len
            && frag_offset + data.len() > total
        {
            self.partials.remove(&key);
            return Err(Error::decode("ipv6: fragment extends past final fragment"));
        }
        if !data.is_empty() {
            p.chunks.insert(frag_offset, data.to_vec());
        }

        if !p.is_complete() {
            return Ok(None);
        }
        let Some(p) = self.partials.remove(&key) else {
            return Ok(None);
        };
        let Some(mut out) = p.unfragmentable else {
            return Ok(None);
        };
        let total = p.total_len.unwrap_or(0);
        let payload_len = out.len() - IPV6_HEADER_LEN + total;
        if payload_len > u16::MAX as usize {
            return Err(Error::decode("ipv6: reassembled payload too large"));
        }
        out[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        for data in p.chunks.values() {
            out.extend_from_slice(data);
        }
        debug!("ipv6 reassembled id={id:#x} total {} bytes", out.len());
        Ok(Some(out))
    }

    /// Drop partial datagrams older than [`REASSEMBLY_TIMEOUT`].
    pub fn evict(&mut self, now: Instant) {
        self.partials.retain(|_, p| now.duration_since(p.created) < REASSEMBLY_TIMEOUT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipstack::udp::{build_udp_packet, parse_ip_packet, parse_ipv6_or_fragment};

    fn s(a: &str) -> SocketAddrV6 {
        a.parse().unwrap()
    }

    #[test]
    fn round_trip_via_dispatch() {
        let src = s("[2001:db8::1]:40000");
        let dst = s("[2001:db8::53]:53");
        let payload: Vec<u8> = (0..77u8).collect();
        let pkt = build_udp_packet(src.into(), dst.into(), &payload).unwrap();
        assert_eq!(pkt.len(), 40 + 8 + payload.len());
        assert_eq!(pkt[6], 17);
        assert_eq!(pkt[7], 64);
        assert_ne!(&pkt[46..48], &[0, 0]);
        match parse_ip_packet(&pkt).unwrap() {
            ParsedIp::Udp(d) => {
                assert_eq!(d.src, src.into());
                assert_eq!(d.dst, dst.into());
                assert_eq!(d.payload, payload);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Hand-built packet with the checksum computed independently from a word list.
    #[test]
    fn matches_hand_built_packet() {
        let src = s("[fd00::1]:4660"); // 0x1234
        let dst = s("[fd00::2]:53");
        let pkt = build_udp(src, dst, b"hi").unwrap();

        // pseudo-header words: src, dst, len(32) = 10, zeros(24)|nh = 0x0011
        let mut words: Vec<u16> = Vec::new();
        for a in [src.ip(), dst.ip()] {
            words.extend_from_slice(&a.segments());
        }
        words.extend_from_slice(&[0x0000, 0x000a, 0x0000, 0x0011]);
        // UDP: 1234 0035 000a 0000 6869
        words.extend_from_slice(&[0x1234, 0x0035, 0x000a, 0x0000, 0x6869]);
        let mut sum: u32 = words.iter().map(|&w| u32::from(w)).sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);

        let mut expected = vec![0x60, 0, 0, 0, 0x00, 0x0a, 17, 64];
        expected.extend_from_slice(&src.ip().octets());
        expected.extend_from_slice(&dst.ip().octets());
        expected.extend_from_slice(&[0x12, 0x34, 0x00, 0x35, 0x00, 0x0a]);
        expected.extend_from_slice(&csum.to_be_bytes());
        expected.extend_from_slice(b"hi");
        assert_eq!(pkt, expected);
    }

    #[test]
    fn zero_checksum_becomes_ffff() {
        // Construct a segment whose raw checksum is 0: fold everything into a payload
        // word that cancels the rest of the sum.
        let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let mut seg = udp_segment(1, 2, &[0, 0]).unwrap();
        let raw = udp_checksum_raw(&src, &dst, &seg); // = !fold(sum(rest))
        // Put raw in the payload word: fold(rest) + !fold(rest) = 0xffff -> checksum 0.
        seg[8..10].copy_from_slice(&raw.to_be_bytes());
        assert_eq!(udp_checksum_raw(&src, &dst, &seg), 0);
        assert_eq!(udp_checksum(&src, &dst, &seg), 0xffff);

        // A packet carrying 0xffff must verify.
        let s6 = SocketAddrV6::new(src, 1, 0, 0);
        let d6 = SocketAddrV6::new(dst, 2, 0, 0);
        let pkt = build_udp(s6, d6, &seg[8..10]).unwrap();
        assert_eq!(&pkt[46..48], &[0xff, 0xff]);
        assert!(matches!(parse(&pkt), Ok(ParsedIp::Udp(_))));
    }

    #[test]
    fn zero_checksum_and_corruption_rejected() {
        let pkt = build_udp(s("[::1]:1"), s("[::2]:2"), b"abc").unwrap();
        let mut zero = pkt.clone();
        zero[46] = 0;
        zero[47] = 0;
        assert!(matches!(parse(&zero), Err(Error::Decode(_))));
        let mut bad = pkt.clone();
        bad[48] ^= 1;
        assert!(matches!(parse(&bad), Err(Error::Decode(_))));
        assert!(matches!(parse(&pkt[..39]), Err(Error::Decode(_))));
        assert!(matches!(parse(&pkt[..pkt.len() - 1]), Err(Error::Decode(_))));
    }

    #[test]
    fn other_protocol_and_ext_headers() {
        // IPv6 + Destination Options (8 bytes, PadN) + ICMPv6 (58) body.
        let mut pkt = vec![0x60, 0, 0, 0, 0, 16, EXT_DEST_OPTS, 64];
        pkt.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        pkt.extend_from_slice(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets());
        pkt.extend_from_slice(&[58, 0, 1, 4, 0, 0, 0, 0]);
        pkt.extend_from_slice(&[128, 0, 0, 0, 0, 0, 0, 0]);
        match parse(&pkt).unwrap() {
            ParsedIp::Other { version, protocol, src, .. } => {
                assert_eq!((version, protocol), (6, 58));
                assert_eq!(src, IpAddr::V6(Ipv6Addr::LOCALHOST));
            }
            other => panic!("unexpected {other:?}"),
        }
        // Truncated ext header (Hdr Ext Len 5 -> 48 bytes, more than the packet holds).
        pkt[41] = 5;
        assert!(matches!(parse(&pkt), Err(Error::Decode(_))));
    }

    /// Split a built UDP/IPv6 packet into fragments of `chunk` bytes each.
    fn fragment(pkt: &[u8], id: u32, chunk: usize) -> Vec<Vec<u8>> {
        assert_eq!(chunk % 8, 0);
        let payload = &pkt[IPV6_HEADER_LEN..];
        let mut out = Vec::new();
        let mut off = 0;
        while off < payload.len() {
            let end = (off + chunk).min(payload.len());
            let more = end < payload.len();
            let mut f = pkt[..IPV6_HEADER_LEN].to_vec();
            f[6] = IPPROTO_FRAGMENT;
            let plen = FRAGMENT_HEADER_LEN + (end - off);
            f[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
            f.push(pkt[6]);
            f.push(0);
            let of = ((off / 8) as u16) << 3 | u16::from(more);
            f.extend_from_slice(&of.to_be_bytes());
            f.extend_from_slice(&id.to_be_bytes());
            f.extend_from_slice(&payload[off..end]);
            out.push(f);
            off = end;
        }
        out
    }

    #[test]
    fn reassembles_three_fragments_out_of_order() {
        let src = s("[2001:db8::a]:1111");
        let dst = s("[2001:db8::b]:2222");
        let payload: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        let full = build_udp(src, dst, &payload).unwrap();
        let frags = fragment(&full, 0xdeadbeef, 80);
        assert_eq!(frags.len(), 3);
        for f in &frags {
            assert!(is_fragment(f).unwrap());
            assert!(matches!(parse(f), Err(Error::Unsupported(_))));
        }

        let mut r = Ipv6FragmentReassembler::new();
        assert!(parse_ipv6_or_fragment(&frags[2], &mut r).unwrap().is_none());
        assert!(parse_ipv6_or_fragment(&frags[0], &mut r).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        let got = parse_ipv6_or_fragment(&frags[1], &mut r).unwrap().unwrap();
        assert_eq!(r.pending(), 0);
        match got {
            ParsedIp::Udp(d) => {
                assert_eq!(d.src, src.into());
                assert_eq!(d.dst, dst.into());
                assert_eq!(d.payload, payload);
            }
            other => panic!("unexpected {other:?}"),
        }

        // Raw reassembly output equals the original packet byte-for-byte.
        let mut r2 = Ipv6FragmentReassembler::new();
        assert!(r2.push(&frags[1]).unwrap().is_none());
        assert!(r2.push(&frags[2]).unwrap().is_none());
        assert_eq!(r2.push(&frags[0]).unwrap().unwrap(), full);
    }

    #[test]
    fn unfragmented_passes_through_dispatcher() {
        let full = build_udp(s("[::1]:1"), s("[::2]:2"), b"plain").unwrap();
        let mut r = Ipv6FragmentReassembler::new();
        assert!(matches!(parse_ipv6_or_fragment(&full, &mut r).unwrap(), Some(ParsedIp::Udp(_))));
        let v4 = build_udp_packet("1.1.1.1:1".parse().unwrap(), "2.2.2.2:2".parse().unwrap(), b"v4").unwrap();
        assert!(matches!(parse_ipv6_or_fragment(&v4, &mut r).unwrap(), Some(ParsedIp::Udp(_))));
    }

    #[test]
    fn interleaved_datagrams_and_eviction() {
        let a = build_udp(s("[::1]:1"), s("[::2]:2"), &[1u8; 100]).unwrap();
        let b = build_udp(s("[::1]:1"), s("[::2]:2"), &[2u8; 100]).unwrap();
        let fa = fragment(&a, 1, 64);
        let fb = fragment(&b, 2, 64);
        let mut r = Ipv6FragmentReassembler::new();
        let t0 = Instant::now();
        assert!(r.push_at(&fa[0], t0).unwrap().is_none());
        assert!(r.push_at(&fb[0], t0).unwrap().is_none());
        assert_eq!(r.pending(), 2);
        assert_eq!(r.push_at(&fb[1], t0 + Duration::from_secs(1)).unwrap().unwrap(), b);
        // `a` expires after 30 s; its last fragment then starts a new partial.
        assert!(r.push_at(&fa[1], t0 + Duration::from_secs(31)).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        assert!(r.push_at(&fa[0], t0 + Duration::from_secs(32)).unwrap().is_some());
    }

    #[test]
    fn overlap_and_bad_fragments_rejected() {
        let a = build_udp(s("[::1]:1"), s("[::2]:2"), &[1u8; 100]).unwrap();
        let fa = fragment(&a, 9, 64);
        let mut r = Ipv6FragmentReassembler::new();
        assert!(r.push(&fa[0]).unwrap().is_none());
        // Duplicate offset-0 fragment overlaps -> discarded.
        assert!(matches!(r.push(&fa[0]), Err(Error::Decode(_))));
        assert_eq!(r.pending(), 0);

        // Non-final fragment with length not a multiple of 8.
        let mut bad = fa[0].clone();
        bad.pop();
        let plen = (bad.len() - 40) as u16;
        bad[4..6].copy_from_slice(&plen.to_be_bytes());
        assert!(matches!(r.push(&bad), Err(Error::Decode(_))));

        // Not a fragment at all.
        assert!(matches!(r.push(&a), Err(Error::Decode(_))));

        // Truncated fragment header.
        let mut t = fa[0][..44].to_vec();
        t[4..6].copy_from_slice(&4u16.to_be_bytes());
        assert!(matches!(r.push(&t), Err(Error::Decode(_))));
    }
}
