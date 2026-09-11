//! IPv4 + UDP build/parse (RFC 791, RFC 768).
//!
//! Build: IHL 5, DSCP/ECN 0, random identification, DF=0/MF=0, TTL 64, protocol 17,
//! header checksum, UDP checksum over the IPv4 pseudo-header.
//! Parse: honours IHL (options skipped), verifies the header checksum, rejects
//! fragments with `Error::Unsupported`, verifies a non-zero UDP checksum.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use rand::RngCore;

use crate::{Error, Result};

pub use super::udp::{ParsedIp, UdpDatagram};
use super::udp::{Checksum, IPPROTO_UDP, internet_checksum, split_udp, udp_segment};

/// Minimum IPv4 header length (IHL = 5).
pub const IPV4_HEADER_LEN: usize = 20;
const TTL: u8 = 64;
const MF_FLAG: u16 = 0x2000;
const FRAG_OFFSET_MASK: u16 = 0x1fff;

/// Build an IPv4 packet carrying one UDP datagram.
pub fn build_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Result<Vec<u8>> {
    let id = (rand::thread_rng().next_u32() & 0xffff) as u16;
    build_udp_with_id(src, dst, payload, id)
}

/// Deterministic variant of [`build_udp`] (identification supplied by the caller).
pub fn build_udp_with_id(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
    id: u16,
) -> Result<Vec<u8>> {
    let mut udp = udp_segment(src.port(), dst.port(), payload)?;
    let total = IPV4_HEADER_LEN + udp.len();
    if total > u16::MAX as usize {
        return Err(Error::encode(format!("ipv4: packet too large ({total} bytes)")));
    }
    // RFC 768: a computed checksum of zero is transmitted as all ones (0 = "no checksum").
    let csum = match udp_checksum(src.ip(), dst.ip(), &udp) {
        0 => 0xffff,
        c => c,
    };
    udp[6..8].copy_from_slice(&csum.to_be_bytes());

    let mut pkt = Vec::with_capacity(total);
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0); // DSCP / ECN
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0, 0]); // flags (DF=0, MF=0) + fragment offset 0
    pkt.push(TTL);
    pkt.push(IPPROTO_UDP);
    pkt.extend_from_slice(&[0, 0]); // header checksum placeholder
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    let hc = header_checksum(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&hc.to_be_bytes());
    pkt.extend_from_slice(&udp);
    Ok(pkt)
}

/// IPv4 header checksum over `header` (the checksum field itself must be zero, or the
/// result is the verification value which is 0 for a valid header).
pub fn header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// UDP checksum over the IPv4 pseudo-header + the UDP segment (`seg` must have its
/// checksum field zeroed to compute; with the field present the result is 0 when valid).
pub fn udp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, seg: &[u8]) -> u16 {
    let mut c = Checksum::new();
    c.add(&src.octets());
    c.add(&dst.octets());
    c.add_u16(u16::from(IPPROTO_UDP));
    c.add_u16(seg.len() as u16);
    c.add(seg);
    c.finish()
}

/// Parse an IPv4 packet. Options are skipped; fragments are `Error::Unsupported`.
pub fn parse(pkt: &[u8]) -> Result<ParsedIp> {
    if pkt.len() < IPV4_HEADER_LEN {
        return Err(Error::decode(format!("ipv4: packet too short ({} bytes)", pkt.len())));
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return Err(Error::decode(format!("ipv4: version nibble {version}")));
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN {
        return Err(Error::decode(format!("ipv4: IHL {ihl} < 20")));
    }
    if pkt.len() < ihl {
        return Err(Error::decode(format!("ipv4: IHL {ihl} exceeds packet ({})", pkt.len())));
    }
    let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total_len < ihl {
        return Err(Error::decode(format!("ipv4: total length {total_len} < IHL {ihl}")));
    }
    if total_len > pkt.len() {
        return Err(Error::decode(format!(
            "ipv4: total length {total_len} exceeds available {} bytes",
            pkt.len()
        )));
    }
    if header_checksum(&pkt[..ihl]) != 0 {
        return Err(Error::decode("ipv4: header checksum mismatch"));
    }
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_frag & MF_FLAG != 0 || flags_frag & FRAG_OFFSET_MASK != 0 {
        return Err(Error::Unsupported("ipv4: fragmented packet".into()));
    }
    let protocol = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    if protocol != IPPROTO_UDP {
        return Ok(ParsedIp::Other {
            version: 4,
            protocol,
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
        });
    }

    let seg = &pkt[ihl..total_len];
    let (hdr, payload) = split_udp(seg)?;
    if hdr.checksum != 0 {
        let seg = &seg[..usize::from(hdr.length)];
        if udp_checksum(&src, &dst, seg) != 0 {
            return Err(Error::decode("ipv4: udp checksum mismatch"));
        }
    }
    Ok(ParsedIp::Udp(UdpDatagram {
        src: SocketAddrV4::new(src, hdr.src_port).into(),
        dst: SocketAddrV4::new(dst, hdr.dst_port).into(),
        payload: payload.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipstack::udp::{build_udp_packet, parse_ip_packet};

    fn s(a: &str) -> SocketAddrV4 {
        a.parse().unwrap()
    }

    /// Wikipedia "IPv4 header checksum" example: checksum 0xb861.
    #[test]
    fn header_checksum_kat() {
        let hdr = hex::decode("450000730000400040110000c0a80001c0a800c7").unwrap();
        assert_eq!(header_checksum(&hdr), 0xb861);
        let mut with = hdr.clone();
        with[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
        assert_eq!(header_checksum(&with), 0);
    }

    /// Independently hand-built packet: 10.0.0.1:1234 -> 10.0.0.2:53, payload "hi".
    #[test]
    fn matches_hand_built_packet() {
        let pkt = build_udp_with_id(s("10.0.0.1:1234"), s("10.0.0.2:53"), b"hi", 0x1234).unwrap();

        // Pseudo-header: 0a000001 0a000002 0011 000a ; UDP: 04d2 0035 000a 0000 6869
        let words: [u16; 9] = [
            0x0a00, 0x0001, 0x0a00, 0x0002, 0x0011, 0x000a, 0x04d2, 0x0035, 0x000a,
        ];
        let mut sum: u32 = words.iter().map(|&w| u32::from(w)).sum::<u32>() + 0x6869;
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let udp_csum = !(sum as u16);

        // Header: 45 00 001e 1234 0000 40 11 [csum] 0a000001 0a000002
        let hwords: [u16; 9] = [
            0x4500, 0x001e, 0x1234, 0x0000, 0x4011, 0x0a00, 0x0001, 0x0a00, 0x0002,
        ];
        let mut hs: u32 = hwords.iter().map(|&w| u32::from(w)).sum();
        while hs >> 16 != 0 {
            hs = (hs & 0xffff) + (hs >> 16);
        }
        let hdr_csum = !(hs as u16);

        let mut expected = vec![0x45, 0x00, 0x00, 0x1e, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11];
        expected.extend_from_slice(&hdr_csum.to_be_bytes());
        expected.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        expected.extend_from_slice(&[0x04, 0xd2, 0x00, 0x35, 0x00, 0x0a]);
        expected.extend_from_slice(&udp_csum.to_be_bytes());
        expected.extend_from_slice(b"hi");
        assert_eq!(pkt, expected);
    }

    #[test]
    fn round_trip_via_dispatch() {
        let src = s("192.168.1.10:40000");
        let dst = s("8.8.8.8:53");
        let payload: Vec<u8> = (0..101u8).collect(); // odd length exercises padding
        let pkt = build_udp_packet(src.into(), dst.into(), &payload).unwrap();
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[8], 64);
        assert_eq!(pkt[9], 17);
        assert_eq!(&pkt[6..8], &[0, 0]);
        match parse_ip_packet(&pkt).unwrap() {
            ParsedIp::Udp(d) => {
                assert_eq!(d.src, src.into());
                assert_eq!(d.dst, dst.into());
                assert_eq!(d.payload, payload);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn corrupted_udp_checksum_rejected_zero_checksum_accepted() {
        let pkt = build_udp_with_id(s("1.1.1.1:1"), s("2.2.2.2:2"), b"abc", 7).unwrap();
        let mut bad = pkt.clone();
        bad[28] ^= 0xff; // payload byte
        assert!(matches!(parse(&bad), Err(Error::Decode(_))));
        let mut zero = pkt.clone();
        zero[26] = 0;
        zero[27] = 0;
        assert!(matches!(parse(&zero), Ok(ParsedIp::Udp(_))));
    }

    #[test]
    fn computed_zero_udp_checksum_is_sent_as_ffff() {
        // RFC 768: a computed checksum of 0 is transmitted as all ones (0 means "none").
        let (src, dst) = (s("10.0.0.1:1"), s("10.0.0.2:2"));
        let payload = (0..=u16::MAX)
            .map(|v| v.to_be_bytes())
            .find(|p| udp_checksum(src.ip(), dst.ip(), &udp_segment(1, 2, p).unwrap()) == 0)
            .expect("some 2-byte payload sums to zero");
        let pkt = build_udp_with_id(src, dst, &payload, 0).unwrap();
        assert_eq!(&pkt[26..28], &[0xff, 0xff], "checksum field must not be 0");
        match parse(&pkt).unwrap() {
            ParsedIp::Udp(d) => assert_eq!(d.payload, payload),
            other => panic!("unexpected {other:?}"),
        }
        // A payload with a non-zero checksum is untouched.
        let pkt = build_udp_with_id(src, dst, b"abc", 0).unwrap();
        assert_ne!(&pkt[26..28], &[0xff, 0xff]);
        assert_ne!(&pkt[26..28], &[0, 0]);
    }

    #[test]
    fn corrupted_header_checksum_rejected() {
        let mut pkt = build_udp_with_id(s("1.1.1.1:1"), s("2.2.2.2:2"), b"abc", 7).unwrap();
        pkt[8] = 63; // TTL changed, checksum stale
        assert!(matches!(parse(&pkt), Err(Error::Decode(_))));
    }

    #[test]
    fn options_are_skipped() {
        // IHL 6 with a 4-byte NOP option block.
        let src = Ipv4Addr::new(10, 1, 1, 1);
        let dst = Ipv4Addr::new(10, 1, 1, 2);
        let mut udp = udp_segment(5000, 6000, b"opt").unwrap();
        let c = udp_checksum(&src, &dst, &udp);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        let total = 24 + udp.len();
        let mut pkt = vec![0x46, 0, (total >> 8) as u8, total as u8, 0, 1, 0, 0, 64, 17, 0, 0];
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&[1, 1, 1, 0]); // NOP NOP NOP EOL
        let hc = header_checksum(&pkt);
        pkt[10..12].copy_from_slice(&hc.to_be_bytes());
        pkt.extend_from_slice(&udp);
        match parse(&pkt).unwrap() {
            ParsedIp::Udp(d) => {
                assert_eq!(d.src.port(), 5000);
                assert_eq!(d.payload, b"opt");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn fragments_unsupported_and_other_protocols() {
        let mut pkt = build_udp_with_id(s("1.1.1.1:1"), s("2.2.2.2:2"), b"abc", 7).unwrap();
        pkt[6] = 0x20; // MF
        pkt[10] = 0;
        pkt[11] = 0;
        let hc = header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&hc.to_be_bytes());
        assert!(matches!(parse(&pkt), Err(Error::Unsupported(_))));

        let mut icmp = build_udp_with_id(s("1.1.1.1:1"), s("2.2.2.2:2"), b"abc", 7).unwrap();
        icmp[9] = 1;
        icmp[10] = 0;
        icmp[11] = 0;
        let hc = header_checksum(&icmp[..20]);
        icmp[10..12].copy_from_slice(&hc.to_be_bytes());
        match parse(&icmp).unwrap() {
            ParsedIp::Other { version, protocol, src, dst } => {
                assert_eq!((version, protocol), (4, 1));
                assert_eq!(src, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
                assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn truncated_and_bad_lengths() {
        let pkt = build_udp_with_id(s("1.1.1.1:1"), s("2.2.2.2:2"), b"abcdef", 7).unwrap();
        assert!(matches!(parse(&pkt[..19]), Err(Error::Decode(_))));
        assert!(matches!(parse(&pkt[..pkt.len() - 1]), Err(Error::Decode(_))));
        let mut bad_ihl = pkt.clone();
        bad_ihl[0] = 0x44;
        assert!(matches!(parse(&bad_ihl), Err(Error::Decode(_))));
        // Trailing padding beyond total length is tolerated.
        let mut padded = pkt.clone();
        padded.extend_from_slice(&[0; 4]);
        assert!(matches!(parse(&padded), Ok(ParsedIp::Udp(_))));
    }
}
