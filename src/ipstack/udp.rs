//! Shared inner-IP types, the family dispatchers and the Internet checksum.
//!
//! `build_udp_packet` / `parse_ip_packet` are the entry points the tunnel uses; the
//! per-family codecs live in [`super::ipv4`] and [`super::ipv6`].

use std::net::{IpAddr, SocketAddr};

use crate::{Error, Result};

use super::ipv4;
use super::ipv6::{self, Ipv6FragmentReassembler};

/// UDP protocol number (IPv4 protocol / IPv6 next header).
pub const IPPROTO_UDP: u8 = 17;
/// IPv6 Fragment extension header (RFC 8200 §4.5).
pub const IPPROTO_FRAGMENT: u8 = 44;
/// Length of a UDP header.
pub const UDP_HEADER_LEN: usize = 8;

/// One UDP datagram carried inside the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Result of parsing an inner IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedIp {
    Udp(UdpDatagram),
    /// Well-formed IP packet carrying a transport we do not decode.
    Other { version: u8, protocol: u8, src: IpAddr, dst: IpAddr },
}

/// Build a complete IPv4 or IPv6 packet carrying one UDP datagram. Both addresses
/// must belong to the same family.
pub fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => ipv4::build_udp(s, d, payload),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => ipv6::build_udp(s, d, payload),
        _ => Err(Error::encode(format!(
            "build_udp_packet: address family mismatch (src {src}, dst {dst})"
        ))),
    }
}

/// Parse an inner IP packet (v4 or v6, decided by the version nibble). IPv6 fragments
/// are rejected with `Error::Unsupported` here; use [`parse_ipv6_or_fragment`] when a
/// reassembler is available.
pub fn parse_ip_packet(pkt: &[u8]) -> Result<ParsedIp> {
    match version_of(pkt)? {
        4 => ipv4::parse(pkt),
        6 => ipv6::parse(pkt),
        v => Err(Error::decode(format!("ip: unsupported version {v}"))),
    }
}

/// Like [`parse_ip_packet`], but IPv6 packets whose header chain contains a Fragment
/// header are fed to `reassembler`. Returns `Ok(None)` while a datagram is still
/// incomplete; `Ok(Some(_))` once it is (or immediately for unfragmented packets).
pub fn parse_ipv6_or_fragment(
    pkt: &[u8],
    reassembler: &mut Ipv6FragmentReassembler,
) -> Result<Option<ParsedIp>> {
    match version_of(pkt)? {
        4 => ipv4::parse(pkt).map(Some),
        6 => {
            if ipv6::is_fragment(pkt)? {
                match reassembler.push(pkt)? {
                    Some(full) => ipv6::parse(&full).map(Some),
                    None => Ok(None),
                }
            } else {
                ipv6::parse(pkt).map(Some)
            }
        }
        v => Err(Error::decode(format!("ip: unsupported version {v}"))),
    }
}

fn version_of(pkt: &[u8]) -> Result<u8> {
    match pkt.first() {
        Some(b) => Ok(b >> 4),
        None => Err(Error::decode("ip: empty packet")),
    }
}

// ---------------------------------------------------------------------------
// Internet checksum (RFC 1071) helpers, shared by both families.
// ---------------------------------------------------------------------------

/// Incrementally accumulates the one's-complement sum of 16-bit big-endian words.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Checksum {
    sum: u32,
}

impl Checksum {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add bytes; an odd trailing byte is padded with a zero on the right.
    pub(crate) fn add(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(2);
        for w in &mut chunks {
            self.sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        if let [last] = chunks.remainder() {
            self.sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }

    pub(crate) fn add_u16(&mut self, v: u16) {
        self.sum += u32::from(v);
    }

    pub(crate) fn add_u32(&mut self, v: u32) {
        self.add_u16((v >> 16) as u16);
        self.add_u16(v as u16);
    }

    /// Fold and complement.
    pub(crate) fn finish(self) -> u16 {
        let mut s = self.sum;
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }
}

/// Plain Internet checksum over a byte slice.
pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    let mut c = Checksum::new();
    c.add(data);
    c.finish()
}

/// Encode a UDP header + payload (checksum field left zero; caller fills it in).
pub(crate) fn udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let len = UDP_HEADER_LEN + payload.len();
    if len > u16::MAX as usize {
        return Err(Error::encode(format!("udp: payload too large ({} bytes)", payload.len())));
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decoded UDP header fields.
pub(crate) struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// Split a UDP segment into its header and payload, validating the length field
/// against the available bytes (trailing bytes beyond `length` are ignored).
pub(crate) fn split_udp(seg: &[u8]) -> Result<(UdpHeader, &[u8])> {
    if seg.len() < UDP_HEADER_LEN {
        return Err(Error::decode(format!("udp: segment too short ({} bytes)", seg.len())));
    }
    let hdr = UdpHeader {
        src_port: u16::from_be_bytes([seg[0], seg[1]]),
        dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        length: u16::from_be_bytes([seg[4], seg[5]]),
        checksum: u16::from_be_bytes([seg[6], seg[7]]),
    };
    let len = hdr.length as usize;
    if len < UDP_HEADER_LEN {
        return Err(Error::decode(format!("udp: length field {len} < 8")));
    }
    if len > seg.len() {
        return Err(Error::decode(format!(
            "udp: length field {len} exceeds available {} bytes",
            seg.len()
        )));
    }
    Ok((hdr, &seg[UDP_HEADER_LEN..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // RFC 1071 §3 worked example: 00 01 f2 03 f4 f5 f6 f7 -> sum 0xddf2, checksum 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_odd_length_pads_zero() {
        let mut a = Checksum::new();
        a.add(&[0x12, 0x34, 0x56]);
        let mut b = Checksum::new();
        b.add(&[0x12, 0x34, 0x56, 0x00]);
        assert_eq!(a.finish(), b.finish());
    }

    #[test]
    fn checksum_of_packet_with_checksum_is_zero() {
        let mut data = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x00, 0x00];
        let c = internet_checksum(&data);
        data[6..8].copy_from_slice(&c.to_be_bytes());
        assert_eq!(internet_checksum(&data), 0);
    }

    #[test]
    fn family_mismatch_is_encode_error() {
        let s: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let d: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        assert!(matches!(build_udp_packet(s, d, b"x"), Err(Error::Encode(_))));
    }

    #[test]
    fn empty_and_bad_version() {
        assert!(matches!(parse_ip_packet(&[]), Err(Error::Decode(_))));
        assert!(matches!(parse_ip_packet(&[0x50; 40]), Err(Error::Decode(_))));
    }

    #[test]
    fn split_udp_length_checks() {
        assert!(split_udp(&[0; 7]).is_err());
        // length field 4 < 8
        assert!(split_udp(&[0, 0, 0, 0, 0, 4, 0, 0]).is_err());
        // length field 20 > 8 available
        assert!(split_udp(&[0, 0, 0, 0, 0, 20, 0, 0]).is_err());
        // trailing bytes ignored
        let (h, p) = split_udp(&[0, 1, 0, 2, 0, 9, 0, 0, 0xaa, 0xbb]).unwrap();
        assert_eq!((h.src_port, h.dst_port), (1, 2));
        assert_eq!(p, &[0xaa]);
    }
}
