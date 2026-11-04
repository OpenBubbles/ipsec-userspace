//! IP fragmentation shim around the smoltcp device (DESIGN.md §11.1).
//!
//! smoltcp 0.14 has no IPv6 fragmentation or reassembly on `Medium::Ip`, so the device
//! shows smoltcp a large MTU (`child.inner_mtu_stack`) and this module makes the wire
//! MTU (`child.inner_mtu`, 1280) hold:
//!
//! - **TX** [`fragment_for_wire`]: an IP packet longer than the wire MTU is split —
//!   IPv6 per RFC 8200 §4.5 (a Fragment extension header right after the base header;
//!   packets that already carry an extension header are refused), IPv4 per RFC 791
//!   (MF/offset, header checksum and Total Length recomputed). Packets that fit pass
//!   through untouched. **DF is not honoured**: smoltcp sets DF on every IPv4 packet it
//!   emits and offers no way to clear it, so honouring it would drop every IPv4 datagram
//!   above 1252 bytes; the shim clears DF and assigns a fresh Identification instead
//!   (§15 deviation).
//! - **RX** [`Ipv6Reassembler`]: IPv6 fragment sets are reassembled before the packet
//!   reaches smoltcp (keyed by source, destination and Identification; bounded; timed
//!   out). IPv4 fragments pass straight through — smoltcp reassembles those itself.
//! - **TCP** [`clamp_tcp_mss`] (DESIGN.md §11.2): smoltcp derives the MSS it announces —
//!   and the largest segment it sends — from the *stack* MTU, so left alone every full
//!   TCP segment would leave as a set of IP fragments (and an IPv4 one larger than
//!   smoltcp's 8 KiB reassembly buffer could never be put back together). The device
//!   clamps the MSS option of every SYN, in both directions, to what fits the *wire* MTU,
//!   so TCP never relies on fragmentation (RFC 8900). [`tcp_connection_request`] tells
//!   the stack which inbound packets are connection requests.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::ops::Range;
use std::time::{Duration, Instant};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TCP_HEADER_LEN, TcpPacket};

/// Bytes of the IPv6 base header.
pub const IPV6_HEADER_LEN: usize = 40;
/// Bytes of the IPv6 Fragment extension header.
pub const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
/// Largest reassembled IPv6 payload (Payload Length is 16 bits).
pub const MAX_IPV6_PAYLOAD: usize = 65_535;
/// Default number of fragment sets held at once (drop-oldest beyond it).
pub const DEFAULT_MAX_PENDING_SETS: usize = 32;
/// Default lifetime of an incomplete fragment set.
pub const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

const IPPROTO_FRAGMENT: u8 = 44;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_FLAG_DF: u16 = 0x4000;
const IPV4_FLAG_MF: u16 = 0x2000;
const IPV4_OFFSET_MASK: u16 = 0x1fff;
const IPV6_FRAG_MF: u16 = 0x0001;

/// Why a packet could not be fragmented for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentError {
    /// Not a well-formed IPv4/IPv6 packet.
    NotIp,
    /// IPv6 with an extension header (only base-header-only packets are fragmented).
    ExtensionHeader(u8),
    /// The wire MTU leaves no room for an 8-byte fragment payload.
    MtuTooSmall,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FragmentError::NotIp => write!(f, "not an IP packet"),
            FragmentError::ExtensionHeader(nh) => write!(f, "IPv6 packet with extension header {nh} cannot be fragmented"),
            FragmentError::MtuTooSmall => write!(f, "wire MTU too small for a fragment"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Split `pkt` into wire-sized fragments when it is longer than `wire_mtu`.
///
/// `Ok(None)`: the packet fits (or is empty) and must be sent as is. `Ok(Some(frags))`:
/// send every fragment, in order, as its own packet. `ident` is the Identification of
/// the new fragment set (IPv6 uses all 32 bits, IPv4 the low 16; an IPv4 packet that is
/// already a fragment keeps its own).
pub fn fragment_for_wire(pkt: &[u8], wire_mtu: usize, ident: u32) -> Result<Option<Vec<Vec<u8>>>, FragmentError> {
    if pkt.len() <= wire_mtu {
        return Ok(None);
    }
    match pkt.first().map(|b| b >> 4) {
        Some(6) => fragment_ipv6(pkt, wire_mtu, ident).map(Some),
        Some(4) => fragment_ipv4(pkt, wire_mtu, ident as u16).map(Some),
        _ => Err(FragmentError::NotIp),
    }
}

fn is_ipv6_extension_header(nh: u8) -> bool {
    // Hop-by-Hop, Routing, Fragment, ESP, AH, No Next Header, Destination Options,
    // Mobility, HIP, Shim6.
    matches!(nh, 0 | 43 | 44 | 50 | 51 | 59 | 60 | 135 | 139 | 140)
}

fn fragment_ipv6(pkt: &[u8], wire_mtu: usize, ident: u32) -> Result<Vec<Vec<u8>>, FragmentError> {
    if pkt.len() < IPV6_HEADER_LEN {
        return Err(FragmentError::NotIp);
    }
    let next_header = pkt[6];
    if is_ipv6_extension_header(next_header) {
        return Err(FragmentError::ExtensionHeader(next_header));
    }
    let chunk = (wire_mtu.saturating_sub(IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN) / 8) * 8;
    if chunk == 0 {
        return Err(FragmentError::MtuTooSmall);
    }
    let payload = &pkt[IPV6_HEADER_LEN..];
    let mut out = Vec::with_capacity(payload.len().div_ceil(chunk));
    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + chunk).min(payload.len());
        let data = &payload[offset..end];
        let more = end < payload.len();
        let mut frag = Vec::with_capacity(IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN + data.len());
        frag.extend_from_slice(&pkt[..IPV6_HEADER_LEN]);
        frag[4..6].copy_from_slice(&((IPV6_FRAGMENT_HEADER_LEN + data.len()) as u16).to_be_bytes());
        frag[6] = IPPROTO_FRAGMENT;
        let offset_field = ((offset / 8) as u16) << 3 | if more { IPV6_FRAG_MF } else { 0 };
        frag.push(next_header);
        frag.push(0);
        frag.extend_from_slice(&offset_field.to_be_bytes());
        frag.extend_from_slice(&ident.to_be_bytes());
        frag.extend_from_slice(data);
        out.push(frag);
        offset = end;
    }
    Ok(out)
}

/// RFC 1071 header checksum of an IPv4 header whose checksum field is zeroed.
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in header.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn fragment_ipv4(pkt: &[u8], wire_mtu: usize, ident: u16) -> Result<Vec<Vec<u8>>, FragmentError> {
    if pkt.len() < IPV4_MIN_HEADER_LEN {
        return Err(FragmentError::NotIp);
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || ihl > pkt.len() {
        return Err(FragmentError::NotIp);
    }
    let chunk = (wire_mtu.saturating_sub(ihl) / 8) * 8;
    if chunk == 0 {
        return Err(FragmentError::MtuTooSmall);
    }
    let flags_offset = u16::from_be_bytes([pkt[6], pkt[7]]);
    let orig_mf = flags_offset & IPV4_FLAG_MF != 0;
    let orig_offset = flags_offset & IPV4_OFFSET_MASK;
    let already_fragment = orig_mf || orig_offset != 0;
    let payload = &pkt[ihl..];
    // The IPv4 options (if any) are copied into every fragment; smoltcp emits none.
    let mut out = Vec::with_capacity(payload.len().div_ceil(chunk));
    let mut offset = 0usize;
    while offset < payload.len() {
        let end = (offset + chunk).min(payload.len());
        let data = &payload[offset..end];
        let more = end < payload.len() || orig_mf;
        let mut frag = Vec::with_capacity(ihl + data.len());
        frag.extend_from_slice(&pkt[..ihl]);
        frag[2..4].copy_from_slice(&((ihl + data.len()) as u16).to_be_bytes());
        if !already_fragment {
            frag[4..6].copy_from_slice(&ident.to_be_bytes());
        }
        let field = (orig_offset + (offset / 8) as u16) & IPV4_OFFSET_MASK | if more { IPV4_FLAG_MF } else { 0 };
        // DF cleared: see the module docs.
        debug_assert_eq!(field & IPV4_FLAG_DF, 0);
        frag[6..8].copy_from_slice(&field.to_be_bytes());
        frag[10..12].copy_from_slice(&[0, 0]);
        let csum = ipv4_header_checksum(&frag[..ihl]);
        frag[10..12].copy_from_slice(&csum.to_be_bytes());
        frag.extend_from_slice(data);
        out.push(frag);
        offset = end;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// TCP: MSS clamping and connection requests (DESIGN.md §11.2)
// ---------------------------------------------------------------------------

/// TCP option kind of the Maximum Segment Size option (RFC 9293 §3.2), and its length.
const TCP_OPTION_MSS: u8 = 2;
const TCP_OPTION_MSS_LEN: usize = 4;

/// The largest MSS that keeps a full TCP segment within `wire_mtu` without IP
/// fragmentation: the MTU minus the *fixed* IP and TCP headers (RFC 6691 §2 — options are
/// accounted for by the sender), i.e. 1220 (IPv6) / 1240 (IPv4) at the default 1280.
pub fn tcp_mss_for_wire(wire_mtu: usize, ipv6: bool) -> u16 {
    let ip = if ipv6 { IPV6_HEADER_LEN } else { IPV4_MIN_HEADER_LEN };
    u16::try_from(wire_mtu.saturating_sub(ip + TCP_HEADER_LEN)).unwrap_or(u16::MAX)
}

/// Locate the TCP segment of `pkt`: `(source, destination, byte range, IPv6?)`. Only an
/// IPv4 packet that is not a fragment and an IPv6 packet whose Next Header is TCP (no
/// extension headers: smoltcp emits none, and a SYN that carries them is left alone).
fn tcp_segment(pkt: &[u8]) -> Option<(IpAddress, IpAddress, Range<usize>, bool)> {
    match pkt.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp || ip.more_frags() || ip.frag_offset() != 0 {
                return None;
            }
            let range = usize::from(ip.header_len())..usize::from(ip.total_len());
            Some((IpAddress::Ipv4(ip.src_addr()), IpAddress::Ipv4(ip.dst_addr()), range, false))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let range = IPV6_HEADER_LEN..IPV6_HEADER_LEN + usize::from(ip.payload_len());
            Some((IpAddress::Ipv6(ip.src_addr()), IpAddress::Ipv6(ip.dst_addr()), range, true))
        }
        _ => None,
    }
}

/// Offset of the 2-byte value of the MSS option in a TCP options block; `None` when the
/// option is absent or the block is malformed (left for smoltcp to judge).
fn mss_option_value_at(opts: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => return None, // End of Option List
            1 => i += 1,      // No-Operation
            kind => {
                let len = usize::from(*opts.get(i + 1)?);
                if len < 2 || i + len > opts.len() {
                    return None;
                }
                if kind == TCP_OPTION_MSS {
                    return (len == TCP_OPTION_MSS_LEN).then_some(i + 2);
                }
                i += len;
            }
        }
    }
    None
}

/// Lower the MSS option of a TCP SYN (or SYN-ACK) in `pkt` to [`tcp_mss_for_wire`] and
/// fix the TCP checksum; returns the MSS it replaced, `None` when nothing changed (not
/// TCP, not a SYN, no MSS option, already small enough, or a segment whose checksum does
/// not verify — rewriting that would launder a corrupt packet past smoltcp's own check).
///
/// Applied to every packet the device transmits AND receives (§11.2): ours, so the peer
/// never sends a segment that needs fragmenting on the way in; the peer's, so smoltcp —
/// whose sending MSS is `min(stack MTU - 40/20 - 20, peer's MSS)` — never builds one on
/// the way out. This is the MSS clamping every tunnel endpoint does (RFC 4459 §3.2).
pub fn clamp_tcp_mss(pkt: &mut [u8], wire_mtu: usize) -> Option<u16> {
    let (src, dst, range, ipv6) = tcp_segment(pkt)?;
    let limit = tcp_mss_for_wire(wire_mtu, ipv6);
    let mut tcp = TcpPacket::new_checked(pkt.get_mut(range)?).ok()?;
    if !tcp.syn() || !tcp.verify_checksum(&src, &dst) {
        return None;
    }
    let opts = tcp.options_mut();
    let at = mss_option_value_at(opts)?;
    let mss = u16::from_be_bytes([opts[at], opts[at + 1]]);
    if mss <= limit {
        return None;
    }
    opts[at..at + 2].copy_from_slice(&limit.to_be_bytes());
    tcp.fill_checksum(&src, &dst);
    Some(mss)
}

/// `(source, destination)` of a TCP connection request in `pkt` — SYN set, ACK clear
/// (RFC 9293 §3.5) — or `None` for anything else.
pub fn tcp_connection_request(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let (src, dst, range, _) = tcp_segment(pkt)?;
    let tcp = TcpPacket::new_checked(pkt.get(range)?).ok()?;
    (tcp.syn() && !tcp.ack()).then(|| (SocketAddr::new(src.into(), tcp.src_port()), SocketAddr::new(dst.into(), tcp.dst_port())))
}

// ---------------------------------------------------------------------------
// IPv6 reassembly
// ---------------------------------------------------------------------------

/// Counters of an [`Ipv6Reassembler`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    /// IPv6 fragments received.
    pub fragments: u64,
    /// Complete packets rebuilt from fragments.
    pub reassembled: u64,
    /// Fragment sets discarded (malformed, overlapping, oversize, timed out, evicted).
    pub drops: u64,
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct SetKey {
    src: [u8; 16],
    dst: [u8; 16],
    ident: u32,
}

struct PendingSet {
    first_seen: Instant,
    /// Base header of the offset-0 fragment (Next Header / Payload Length rewritten on completion).
    header: Option<[u8; IPV6_HEADER_LEN]>,
    next_header: u8,
    /// Fragment data by byte offset.
    chunks: BTreeMap<u16, Vec<u8>>,
    /// Total fragmentable length once the M=0 fragment was seen.
    total: Option<usize>,
    bytes: usize,
}

impl PendingSet {
    fn complete(&self) -> bool {
        let Some(total) = self.total else { return false };
        self.header.is_some() && self.bytes == total && self.contiguous(total)
    }

    fn contiguous(&self, total: usize) -> bool {
        let mut expect = 0usize;
        for (off, data) in &self.chunks {
            if usize::from(*off) != expect {
                return false;
            }
            expect += data.len();
        }
        expect == total
    }

    fn rebuild(self) -> Vec<u8> {
        let total = self.total.unwrap_or(0);
        let mut header = self.header.unwrap_or([0; IPV6_HEADER_LEN]);
        header[4..6].copy_from_slice(&(total as u16).to_be_bytes());
        header[6] = self.next_header;
        let mut out = Vec::with_capacity(IPV6_HEADER_LEN + total);
        out.extend_from_slice(&header);
        for (_, data) in self.chunks {
            out.extend_from_slice(&data);
        }
        out
    }
}

/// Bounded IPv6 fragment reassembler applied to inbound packets before smoltcp.
pub struct Ipv6Reassembler {
    sets: HashMap<SetKey, PendingSet>,
    max_sets: usize,
    timeout: Duration,
    stats: ReassemblyStats,
}

impl Default for Ipv6Reassembler {
    fn default() -> Self {
        Ipv6Reassembler::new(DEFAULT_MAX_PENDING_SETS, DEFAULT_REASSEMBLY_TIMEOUT)
    }
}

impl Ipv6Reassembler {
    /// Hold at most `max_sets` incomplete sets (the oldest is evicted beyond that), each
    /// for at most `timeout`.
    pub fn new(max_sets: usize, timeout: Duration) -> Self {
        Ipv6Reassembler { sets: HashMap::new(), max_sets: max_sets.max(1), timeout, stats: ReassemblyStats::default() }
    }

    pub fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    /// Incomplete sets currently held.
    pub fn pending(&self) -> usize {
        self.sets.len()
    }

    /// Is `pkt` an IPv6 packet whose first extension header is a Fragment header?
    pub fn is_fragment(pkt: &[u8]) -> bool {
        pkt.len() >= IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN && pkt[0] >> 4 == 6 && pkt[6] == IPPROTO_FRAGMENT
    }

    /// Feed one inbound IP packet. Returns the packet to hand to smoltcp: `pkt` itself
    /// when it is not an IPv6 fragment, the rebuilt packet when it completes a set, and
    /// `None` while a set is still incomplete or when the fragment was dropped.
    pub fn push(&mut self, pkt: Vec<u8>, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        if !Self::is_fragment(&pkt) {
            return Some(pkt);
        }
        self.stats.fragments += 1;
        let h = &pkt[IPV6_HEADER_LEN..IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN];
        let next_header = h[0];
        let offset_field = u16::from_be_bytes([h[2], h[3]]);
        let offset = usize::from(offset_field >> 3) * 8;
        let more = offset_field & IPV6_FRAG_MF != 0;
        let ident = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let data = &pkt[IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN..];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&pkt[8..24]);
        dst.copy_from_slice(&pkt[24..40]);
        let key = SetKey { src, dst, ident };

        // RFC 8200 §4.5: every non-final fragment carries a multiple of 8 bytes; the
        // reassembled payload must fit the Payload Length field.
        if (more && !data.len().is_multiple_of(8)) || offset + data.len() > MAX_IPV6_PAYLOAD || (!more && data.is_empty()) {
            self.drop_set(&key);
            return None;
        }

        if !self.sets.contains_key(&key) {
            if self.sets.len() >= self.max_sets {
                let oldest = self.sets.iter().min_by_key(|(_, s)| s.first_seen).map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.drop_set(&k);
                }
            }
            self.sets.insert(
                key,
                PendingSet { first_seen: now, header: None, next_header, chunks: BTreeMap::new(), total: None, bytes: 0 },
            );
        }
        let set = self.sets.get_mut(&key).expect("just inserted");

        if !more {
            let total = offset + data.len();
            match set.total {
                Some(t) if t != total => {
                    self.drop_set(&key);
                    return None;
                }
                _ => set.total = Some(total),
            }
        }
        if let Some(total) = set.total
            && offset + data.len() > total
        {
            self.drop_set(&key);
            return None;
        }
        if offset == 0 && set.header.is_none() {
            let mut header = [0u8; IPV6_HEADER_LEN];
            header.copy_from_slice(&pkt[..IPV6_HEADER_LEN]);
            set.header = Some(header);
            set.next_header = next_header;
        }
        match set.chunks.get(&(offset as u16)) {
            Some(existing) if existing.len() == data.len() => {
                // Exact duplicate: ignore.
            }
            Some(_) => {
                self.drop_set(&key);
                return None;
            }
            None => {
                set.bytes += data.len();
                set.chunks.insert(offset as u16, data.to_vec());
            }
        }

        let set = self.sets.get(&key).expect("present");
        if set.total.is_some_and(|t| set.bytes >= t) {
            if set.complete() {
                let set = self.sets.remove(&key).expect("present");
                self.stats.reassembled += 1;
                return Some(set.rebuild());
            }
            // All bytes seen but not contiguous: overlapping fragments.
            self.drop_set(&key);
        }
        None
    }

    /// Discard sets older than the timeout.
    pub fn expire(&mut self, now: Instant) {
        let timeout = self.timeout;
        let before = self.sets.len();
        self.sets.retain(|_, s| now.saturating_duration_since(s.first_seen) < timeout);
        self.stats.drops += (before - self.sets.len()) as u64;
    }

    fn drop_set(&mut self, key: &SetKey) {
        self.sets.remove(key);
        self.stats.drops += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    const SRC6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 1);
    const DST6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xb, 0, 0, 0, 0, 1);
    const MTU: usize = 1280;
    const T0: Duration = Duration::from_secs(0);

    fn now_plus(d: Duration) -> Instant {
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *BASE.get_or_init(Instant::now) + d
    }

    /// IPv6 + UDP(-ish) packet with `payload_len` bytes of pattern payload.
    fn ipv6_packet(payload_len: usize) -> Vec<u8> {
        let mut p = vec![0u8; IPV6_HEADER_LEN];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        p[6] = 17;
        p[7] = 64;
        p[8..24].copy_from_slice(&SRC6.octets());
        p[24..40].copy_from_slice(&DST6.octets());
        p.extend((0..payload_len).map(|i| (i % 251) as u8));
        p
    }

    fn ipv4_packet(payload_len: usize, flags: u16) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6..8].copy_from_slice(&flags.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let csum = ipv4_header_checksum(&p);
        p[10..12].copy_from_slice(&csum.to_be_bytes());
        p.extend((0..payload_len).map(|i| (i % 253) as u8));
        p
    }

    fn frag6(pkt: &[u8], ident: u32) -> Vec<Vec<u8>> {
        fragment_for_wire(pkt, MTU, ident).unwrap().expect("needs fragmentation")
    }

    const SRC4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
    const DST4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 2);

    /// An IPv6 or IPv4 TCP segment `src:40000 -> dst:5060` built by smoltcp (valid
    /// checksums) with the given control, ACK, MSS option and payload.
    fn tcp_packet(v6: bool, control: smoltcp::wire::TcpControl, ack: bool, mss: Option<u16>, payload: &[u8]) -> Vec<u8> {
        use smoltcp::wire::{Ipv4Repr, Ipv6Repr, TcpRepr, TcpSeqNumber};
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let tcp = TcpRepr {
            src_port: 40000,
            dst_port: 5060,
            control,
            seq_number: TcpSeqNumber(1000),
            ack_number: ack.then_some(TcpSeqNumber(77)),
            window_len: 8192,
            window_scale: Some(0),
            max_seg_size: mss,
            sack_permitted: true,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let (src, dst) = if v6 { (IpAddress::Ipv6(SRC6), IpAddress::Ipv6(DST6)) } else { (IpAddress::Ipv4(SRC4), IpAddress::Ipv4(DST4)) };
        let ip_len = if v6 { IPV6_HEADER_LEN } else { 20 };
        let mut buf = vec![0u8; ip_len + tcp.buffer_len()];
        if v6 {
            let ip = Ipv6Repr { src_addr: SRC6, dst_addr: DST6, next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64 };
            ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf));
        } else {
            let ip = Ipv4Repr { src_addr: SRC4, dst_addr: DST4, next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64 };
            ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf), &caps);
        }
        tcp.emit(&mut TcpPacket::new_unchecked(&mut buf[ip_len..]), &src, &dst, &caps);
        buf
    }

    /// The MSS option of the TCP segment in `pkt`, parsed back by smoltcp (which also
    /// verifies the checksum).
    fn parsed_mss(pkt: &[u8]) -> Option<u16> {
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let (src, dst, range, _) = tcp_segment(pkt).expect("a TCP segment");
        let tcp = TcpPacket::new_checked(&pkt[range]).unwrap();
        smoltcp::wire::TcpRepr::parse(&tcp, &src, &dst, &caps).expect("valid TCP segment (checksum included)").max_seg_size
    }

    #[test]
    fn mss_for_the_wire_is_the_mtu_minus_the_fixed_headers() {
        assert_eq!(tcp_mss_for_wire(1280, true), 1220);
        assert_eq!(tcp_mss_for_wire(1280, false), 1240);
        assert_eq!(tcp_mss_for_wire(1500, true), 1440);
        assert_eq!(tcp_mss_for_wire(10, false), 0);
        assert_eq!(tcp_mss_for_wire(1 << 20, true), u16::MAX);
    }

    #[test]
    fn syn_mss_above_the_wire_limit_is_clamped_with_a_valid_checksum() {
        use smoltcp::wire::TcpControl;
        // smoltcp's own SYN at the 16384-byte stack MTU, both families, SYN and SYN-ACK.
        for (v6, ack) in [(true, false), (true, true), (false, false), (false, true)] {
            let mut pkt = tcp_packet(v6, TcpControl::Syn, ack, Some(16324), &[]);
            assert_eq!(clamp_tcp_mss(&mut pkt, MTU), Some(16324), "v6={v6} ack={ack}");
            assert_eq!(parsed_mss(&pkt), Some(if v6 { 1220 } else { 1240 }), "v6={v6} ack={ack}");
            // Idempotent: a clamped SYN is left alone.
            let before = pkt.clone();
            assert_eq!(clamp_tcp_mss(&mut pkt, MTU), None);
            assert_eq!(pkt, before);
        }
        // A peer's 1460 (IPv4 over Ethernet) is lowered too; an MSS that fits is kept.
        let mut pkt = tcp_packet(false, TcpControl::Syn, true, Some(1460), &[]);
        assert_eq!(clamp_tcp_mss(&mut pkt, MTU), Some(1460));
        assert_eq!(parsed_mss(&pkt), Some(1240));
        let mut small = tcp_packet(true, TcpControl::Syn, false, Some(536), &[]);
        let before = small.clone();
        assert_eq!(clamp_tcp_mss(&mut small, MTU), None);
        assert_eq!(small, before);
        // A larger wire MTU leaves more room.
        let mut pkt = tcp_packet(true, TcpControl::Syn, false, Some(16324), &[]);
        assert_eq!(clamp_tcp_mss(&mut pkt, 1400), Some(16324));
        assert_eq!(parsed_mss(&pkt), Some(1340));
    }

    #[test]
    fn mss_clamping_leaves_everything_else_untouched() {
        use smoltcp::wire::TcpControl;
        let check = |mut pkt: Vec<u8>, what: &str| {
            let before = pkt.clone();
            assert_eq!(clamp_tcp_mss(&mut pkt, MTU), None, "{what}");
            assert_eq!(pkt, before, "{what}");
        };
        check(tcp_packet(true, TcpControl::None, true, None, b"data"), "a data segment");
        check(tcp_packet(true, TcpControl::Syn, false, None, &[]), "a SYN without the MSS option");
        check(ipv6_packet(100), "UDP");
        check(ipv4_packet(100, 0), "UDP over IPv4");
        check(vec![], "nothing");
        check(vec![0x60; 10], "a runt");
        // A corrupt SYN keeps its bad checksum (smoltcp drops it), it is not "repaired".
        let mut corrupt = tcp_packet(true, TcpControl::Syn, false, Some(16324), &[]);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        check(corrupt, "a SYN with a bad checksum");
        // IPv4 fragments are not TCP headers.
        let mut frag = tcp_packet(false, TcpControl::Syn, false, Some(16324), &[]);
        frag[6] = 0x20; // MF
        check(frag, "an IPv4 fragment");
        // Malformed options (an MSS option claiming length 0, checksum recomputed so
        // only the options are wrong) are left for smoltcp to judge.
        let mut bad = tcp_packet(true, TcpControl::Syn, false, Some(16324), &[]);
        bad[IPV6_HEADER_LEN + 21] = 0;
        TcpPacket::new_unchecked(&mut bad[IPV6_HEADER_LEN..]).fill_checksum(&IpAddress::Ipv6(SRC6), &IpAddress::Ipv6(DST6));
        check(bad, "malformed options");
    }

    #[test]
    fn mss_option_scan_skips_padding_and_other_options() {
        assert_eq!(mss_option_value_at(&[2, 4, 0x05, 0xb4]), Some(2));
        assert_eq!(mss_option_value_at(&[1, 1, 3, 3, 7, 2, 4, 0x05, 0xb4, 0]), Some(7), "NOPs and window scale first");
        assert_eq!(mss_option_value_at(&[0, 2, 4, 0x05, 0xb4]), None, "after End of Option List");
        assert_eq!(mss_option_value_at(&[2, 3, 0x05]), None, "wrong length");
        assert_eq!(mss_option_value_at(&[8, 10, 0, 0]), None, "option runs past the block");
        assert_eq!(mss_option_value_at(&[4]), None, "truncated");
        assert_eq!(mss_option_value_at(&[]), None);
    }

    #[test]
    fn connection_requests_are_syns_without_ack() {
        use smoltcp::wire::TcpControl;
        let syn6 = tcp_packet(true, TcpControl::Syn, false, Some(1220), &[]);
        assert_eq!(
            tcp_connection_request(&syn6),
            Some((SocketAddr::new(SRC6.into(), 40000), SocketAddr::new(DST6.into(), 5060)))
        );
        let syn4 = tcp_packet(false, TcpControl::Syn, false, None, &[]);
        assert_eq!(tcp_connection_request(&syn4), Some((SocketAddr::new(SRC4.into(), 40000), SocketAddr::new(DST4.into(), 5060))));
        assert_eq!(tcp_connection_request(&tcp_packet(true, TcpControl::Syn, true, None, &[])), None, "SYN-ACK");
        assert_eq!(tcp_connection_request(&tcp_packet(true, TcpControl::None, true, None, b"x")), None, "data");
        assert_eq!(tcp_connection_request(&tcp_packet(false, TcpControl::Rst, false, None, &[])), None, "RST");
        assert_eq!(tcp_connection_request(&ipv6_packet(40)), None, "UDP");
    }

    #[test]
    fn packets_that_fit_pass_through_untouched() {
        assert_eq!(fragment_for_wire(&ipv6_packet(1240), MTU, 1), Ok(None), "exactly the MTU");
        assert_eq!(fragment_for_wire(&ipv4_packet(1260, IPV4_FLAG_DF), MTU, 1), Ok(None));
        assert_eq!(fragment_for_wire(&[], MTU, 1), Ok(None));
        assert_eq!(fragment_for_wire(&[0x60; 1281], 1280, 1).unwrap().unwrap().len(), 2);
        assert_eq!(fragment_for_wire(&[0xff; 1281], 1280, 1), Err(FragmentError::NotIp));
        assert_eq!(fragment_for_wire(&[0x60; 39], 10, 1), Err(FragmentError::NotIp));
    }

    #[test]
    fn ipv6_fragments_are_wire_sized_and_round_trip_at_every_size() {
        for size in [1241usize, 1281, 1500, 3000, 8000, 16384 - 40, 65535] {
            let pkt = ipv6_packet(size);
            let frags = frag6(&pkt, 0xdead_beef);
            assert!(frags.len() >= 2, "{size}");
            let expected = (size).div_ceil(1232);
            assert_eq!(frags.len(), expected, "size {size}: {} fragments", frags.len());
            for (i, f) in frags.iter().enumerate() {
                assert!(f.len() <= MTU, "fragment {i} of {size}: {} bytes", f.len());
                assert_eq!(f[6], IPPROTO_FRAGMENT);
                assert_eq!(u16::from_be_bytes([f[4], f[5]]) as usize, f.len() - IPV6_HEADER_LEN);
                assert_eq!(f[40], 17, "original next header carried in the fragment header");
                let off = u16::from_be_bytes([f[42], f[43]]);
                let last = i + 1 == frags.len();
                assert_eq!(off & IPV6_FRAG_MF != 0, !last, "M flag");
                assert_eq!(usize::from(off >> 3) * 8, i * 1232, "offset");
                assert_eq!(&f[44..48], &0xdead_beefu32.to_be_bytes());
                if !last {
                    assert_eq!((f.len() - 48) % 8, 0, "non-final fragments carry multiples of 8");
                }
            }
            // Reassemble in order.
            let mut r = Ipv6Reassembler::default();
            let mut out = None;
            for f in frags {
                out = r.push(f, now_plus(T0));
            }
            assert_eq!(out.as_deref(), Some(pkt.as_slice()), "size {size} round trip");
            assert_eq!(r.pending(), 0);
            assert_eq!(r.stats().reassembled, 1);
            assert_eq!(r.stats().drops, 0);
        }
    }

    #[test]
    fn ipv6_extension_headers_are_refused() {
        let mut pkt = ipv6_packet(2000);
        pkt[6] = 0; // Hop-by-Hop
        assert_eq!(fragment_for_wire(&pkt, MTU, 1), Err(FragmentError::ExtensionHeader(0)));
        pkt[6] = 44;
        assert_eq!(fragment_for_wire(&pkt, MTU, 1), Err(FragmentError::ExtensionHeader(44)));
        assert_eq!(fragment_for_wire(&ipv6_packet(100), 50, 1), Err(FragmentError::MtuTooSmall));
    }

    #[test]
    fn ipv4_3000_bytes_is_split_with_valid_headers_and_df_cleared() {
        let pkt = ipv4_packet(3000, IPV4_FLAG_DF);
        let frags = fragment_for_wire(&pkt, MTU, 0xabcd).unwrap().unwrap();
        assert_eq!(frags.len(), 3, "1256 + 1256 + 488 (multiples of 8)");
        let mut payload = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            assert!(f.len() <= MTU);
            assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, f.len());
            assert_eq!(&f[4..6], &0xabcdu16.to_be_bytes(), "fresh identification");
            let fo = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(fo & IPV4_FLAG_DF, 0, "DF cleared");
            assert_eq!(fo & IPV4_FLAG_MF != 0, i + 1 < frags.len());
            assert_eq!(usize::from(fo & IPV4_OFFSET_MASK) * 8, i * 1256);
            let mut h = f[..20].to_vec();
            h[10] = 0;
            h[11] = 0;
            assert_eq!(ipv4_header_checksum(&h).to_be_bytes(), &f[10..12], "header checksum");
            payload.extend_from_slice(&f[20..]);
        }
        assert_eq!(payload, pkt[20..].to_vec());
        // smoltcp accepts the fragments (header checksum verified) and reassembles them.
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        for f in &frags {
            let p = smoltcp::wire::Ipv4Packet::new_checked(f.as_slice()).unwrap();
            smoltcp::wire::Ipv4Repr::parse(&p, &caps).expect("fragment header parses with a valid checksum");
        }
    }

    #[test]
    fn ipv4_that_is_already_a_fragment_keeps_ident_and_extends_offsets() {
        // A middle fragment (MF set, offset 100 units) of some larger datagram.
        let pkt = ipv4_packet(2000, IPV4_FLAG_MF | 100);
        let frags = fragment_for_wire(&pkt, MTU, 0xffff).unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        for f in &frags {
            assert_eq!(&f[4..6], &0x1234u16.to_be_bytes(), "identification preserved");
            assert_ne!(u16::from_be_bytes([f[6], f[7]]) & IPV4_FLAG_MF, 0, "MF stays set on every piece");
        }
        assert_eq!(u16::from_be_bytes([frags[0][6], frags[0][7]]) & IPV4_OFFSET_MASK, 100);
        assert_eq!(u16::from_be_bytes([frags[1][6], frags[1][7]]) & IPV4_OFFSET_MASK, 100 + 1256 / 8);
    }

    #[test]
    fn reassembly_handles_out_of_order_and_duplicate_fragments() {
        let pkt = ipv6_packet(3000);
        let frags = frag6(&pkt, 7);
        let mut r = Ipv6Reassembler::default();
        assert!(r.push(frags[2].clone(), now_plus(T0)).is_none());
        assert!(r.push(frags[0].clone(), now_plus(T0)).is_none());
        assert!(r.push(frags[0].clone(), now_plus(T0)).is_none(), "duplicate is ignored");
        assert_eq!(r.pending(), 1);
        assert_eq!(r.push(frags[1].clone(), now_plus(T0)).as_deref(), Some(pkt.as_slice()));
        assert_eq!(r.stats(), ReassemblyStats { fragments: 4, reassembled: 1, drops: 0 });
        // Non-fragments pass straight through.
        let plain = ipv6_packet(100);
        assert_eq!(r.push(plain.clone(), now_plus(T0)).as_deref(), Some(plain.as_slice()));
        let mut v4 = ipv4_packet(100, IPV4_FLAG_MF);
        v4[6] = 0x20;
        assert_eq!(r.push(v4.clone(), now_plus(T0)).as_deref(), Some(v4.as_slice()), "IPv4 fragments go to smoltcp");
    }

    #[test]
    fn missing_fragment_times_out_and_is_counted() {
        let frags = frag6(&ipv6_packet(3000), 9);
        let mut r = Ipv6Reassembler::new(32, Duration::from_secs(30));
        r.push(frags[0].clone(), now_plus(T0));
        r.push(frags[2].clone(), now_plus(T0));
        assert_eq!(r.pending(), 1);
        r.expire(now_plus(Duration::from_secs(29)));
        assert_eq!(r.pending(), 1);
        // The next packet at 30 s evicts it.
        let plain = ipv6_packet(10);
        assert!(r.push(plain, now_plus(Duration::from_secs(30))).is_some());
        assert_eq!(r.pending(), 0);
        assert_eq!(r.stats().drops, 1);
        // A late fragment of the evicted set just opens a new (incomplete) set.
        assert!(r.push(frags[1].clone(), now_plus(Duration::from_secs(31))).is_none());
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn set_limit_evicts_the_oldest_set() {
        let mut r = Ipv6Reassembler::new(2, Duration::from_secs(30));
        for ident in 0..3u32 {
            let frags = frag6(&ipv6_packet(3000), ident);
            r.push(frags[0].clone(), now_plus(Duration::from_millis(ident as u64)));
        }
        assert_eq!(r.pending(), 2);
        assert_eq!(r.stats().drops, 1, "set 0 evicted");
        // Set 0 cannot complete any more; sets 1 and 2 can.
        let f0 = frag6(&ipv6_packet(3000), 0);
        r.push(f0[1].clone(), now_plus(T0));
        assert!(r.push(f0[2].clone(), now_plus(T0)).is_none());
        let f2 = frag6(&ipv6_packet(3000), 2);
        r.push(f2[1].clone(), now_plus(T0));
        assert!(r.push(f2[2].clone(), now_plus(T0)).is_some());
    }

    #[test]
    fn malformed_and_overlapping_fragments_drop_the_set() {
        let pkt = ipv6_packet(3000);
        let frags = frag6(&pkt, 5);
        // Non-final fragment whose length is not a multiple of 8.
        let mut r = Ipv6Reassembler::default();
        let mut bad = frags[0].clone();
        bad.truncate(bad.len() - 3);
        let bad_len = (bad.len() - 40) as u16;
        bad[4..6].copy_from_slice(&bad_len.to_be_bytes());
        assert!(r.push(bad, now_plus(T0)).is_none());
        assert_eq!(r.stats().drops, 1);
        assert_eq!(r.pending(), 0);
        // Overlap: a fragment claiming offset 0 with a different length than the real one.
        let mut r = Ipv6Reassembler::default();
        r.push(frags[0].clone(), now_plus(T0));
        let mut overlap = frags[0].clone();
        overlap.truncate(48 + 800);
        overlap[4..6].copy_from_slice(&(808u16).to_be_bytes());
        assert!(r.push(overlap, now_plus(T0)).is_none());
        assert_eq!(r.pending(), 0, "overlapping set discarded");
        assert_eq!(r.stats().drops, 1);
        // A fragment beyond the announced total.
        let mut r = Ipv6Reassembler::default();
        r.push(frags[2].clone(), now_plus(T0)); // final: total known
        let mut beyond = frags[1].clone();
        let off = ((3000 / 8) as u16) << 3 | IPV6_FRAG_MF;
        beyond[42..44].copy_from_slice(&off.to_be_bytes());
        assert!(r.push(beyond, now_plus(T0)).is_none());
        assert_eq!(r.pending(), 0);
    }
}
