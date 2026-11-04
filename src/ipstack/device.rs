//! [`EspDevice`]: the smoltcp [`Device`] backed by the ESP data plane (DESIGN.md §11).
//!
//! The tunnel-mode ESP payload is a raw IP packet, so the inner network is a
//! `Medium::Ip` link with no framing at all:
//!
//! - **TX**: smoltcp asks for a [`TxToken`], writes one IP packet into the device's
//!   scratch buffer and the token hands it to the injected *sink* — in the tunnel a
//!   closure doing `EspOutbound::encapsulate` + `IkeTransport::send_esp`; in tests a
//!   channel or the other stack's [`EspDevice::push_rx`]. The MTU smoltcp sees is the
//!   *stack* MTU (`child.inner_mtu_stack`, large); a packet longer than the *wire* MTU
//!   (`child.inner_mtu`) is split by [`fragment_for_wire`] (DESIGN.md §11.1) and every
//!   fragment is handed to the sink as its own packet.
//! - **RX**: the ESP receive thread pushes decapsulated inner IP packets with
//!   [`EspDevice::push_rx`] into a bounded queue (drop-oldest, drops counted);
//!   `receive()` pops one packet per call. (IPv6 reassembly happens before the device,
//!   in `InnerStack::push_rx`.)
//! - **TCP MSS** (DESIGN.md §11.2): the MSS option of every TCP SYN crossing the device —
//!   either way — is clamped to what fits the wire MTU ([`clamp_tcp_mss`]), so neither
//!   side ever builds a TCP segment that has to be fragmented.
//!
//! No allocation happens per packet beyond the `Vec` the caller already hands in:
//! received packets are moved through the queue and the TX scratch buffer is reused
//! (fragments are the exception: one `Vec` each).

use std::collections::VecDeque;
use std::sync::Arc;

use log::{debug, trace};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use super::frag::{clamp_tcp_mss, fragment_for_wire};
use crate::Result;

/// Where transmitted inner IP packets go: `Fn(ip_packet) -> Result<()>`. Every packet
/// handed to it fits the wire MTU.
pub type TxSink = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// Default depth of the receive queue (packets), see [`EspDevice::new`].
pub const DEFAULT_RX_QUEUE_DEPTH: usize = 256;

/// Packet / drop counters of one [`EspDevice`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceStats {
    /// Inner IP packets queued by `push_rx` (whether or not they were later consumed).
    pub rx_packets: u64,
    /// Bytes of inner IP packets queued by `push_rx`.
    pub rx_bytes: u64,
    /// Packets evicted from the receive queue because it was full (oldest first).
    pub rx_queue_drops: u64,
    /// Inner IP packets handed to the sink successfully.
    pub tx_packets: u64,
    /// Bytes of inner IP packets handed to the sink successfully.
    pub tx_bytes: u64,
    /// Sink failures (the packet was dropped).
    pub tx_errors: u64,
    /// IP packets from smoltcp that were split into wire-sized fragments.
    pub tx_fragmented: u64,
    /// IP packets longer than the wire MTU that could not be fragmented (dropped).
    pub tx_frag_drops: u64,
    /// TCP SYNs (ours or the peer's) whose MSS option was lowered to fit the wire MTU.
    pub tcp_mss_clamped: u64,
}

/// smoltcp `Medium::Ip` device over ESP. Not `Sync`: it lives inside the stack's mutex.
pub struct EspDevice {
    sink: TxSink,
    rx: VecDeque<Vec<u8>>,
    rx_capacity: usize,
    wire_mtu: usize,
    mtu: usize,
    scratch: Vec<u8>,
    /// Identification of the next fragment set.
    next_ident: u32,
    stats: DeviceStats,
}

impl EspDevice {
    /// A device whose transmitted packets go to `sink`, with wire MTU `wire_mtu` (the
    /// largest packet the sink is handed), link MTU `mtu` as seen by smoltcp (raised to
    /// at least `wire_mtu`; bytes of IP packet) and a receive queue of `rx_capacity`
    /// packets (min 1).
    pub fn new(sink: TxSink, wire_mtu: usize, mtu: usize, rx_capacity: usize) -> Self {
        let rx_capacity = rx_capacity.max(1);
        let mtu = mtu.max(wire_mtu);
        EspDevice {
            sink,
            rx: VecDeque::with_capacity(rx_capacity),
            rx_capacity,
            wire_mtu,
            mtu,
            scratch: Vec::with_capacity(wire_mtu),
            next_ident: rand::random(),
            stats: DeviceStats::default(),
        }
    }

    /// Queue one decapsulated inner IP packet for the stack. When the queue is full
    /// the oldest packet is dropped (and counted) so a stalled stack sheds load
    /// instead of blocking the ESP receive thread. A TCP SYN's MSS option is clamped to
    /// the wire MTU on the way in (§11.2).
    pub fn push_rx(&mut self, mut packet: Vec<u8>) {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += packet.len() as u64;
        if let Some(mss) = clamp_tcp_mss(&mut packet, self.wire_mtu) {
            self.stats.tcp_mss_clamped += 1;
            trace!("inner rx TCP SYN: MSS {mss} clamped for the wire MTU {}", self.wire_mtu);
        }
        if self.rx.len() >= self.rx_capacity {
            self.rx.pop_front();
            self.stats.rx_queue_drops += 1;
            debug!("inner rx queue full ({}); dropped the oldest packet", self.rx_capacity);
        }
        self.rx.push_back(packet);
    }

    /// Packets waiting in the receive queue.
    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }

    /// Receive queue depth.
    pub fn rx_capacity(&self) -> usize {
        self.rx_capacity
    }

    /// Link MTU as seen by smoltcp, in bytes of IP packet (`child.inner_mtu_stack`).
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Largest packet handed to the sink (`child.inner_mtu`).
    pub fn wire_mtu(&self) -> usize {
        self.wire_mtu
    }

    pub fn stats(&self) -> DeviceStats {
        self.stats
    }

    /// Hand exactly `len` bytes (filled in by `f`) to the sink, split into wire-sized
    /// fragments first when they exceed the wire MTU. A TCP SYN's MSS option is clamped
    /// to the wire MTU first (§11.2).
    fn transmit_with<R, F: FnOnce(&mut [u8]) -> R>(&mut self, len: usize, f: F) -> R {
        if self.scratch.len() < len {
            self.scratch.resize(len, 0);
        }
        let buf = &mut self.scratch[..len];
        let r = f(buf);
        if let Some(mss) = clamp_tcp_mss(buf, self.wire_mtu) {
            self.stats.tcp_mss_clamped += 1;
            trace!("inner tx TCP SYN: MSS {mss} clamped for the wire MTU {}", self.wire_mtu);
        }
        match fragment_for_wire(buf, self.wire_mtu, self.next_ident) {
            Ok(None) => emit(&self.sink, &mut self.stats, buf),
            Ok(Some(frags)) => {
                self.next_ident = self.next_ident.wrapping_add(1);
                self.stats.tx_fragmented += 1;
                trace!("inner tx {len} bytes split into {} fragments (wire MTU {})", frags.len(), self.wire_mtu);
                for frag in &frags {
                    emit(&self.sink, &mut self.stats, frag);
                }
            }
            Err(e) => {
                self.stats.tx_frag_drops += 1;
                debug!("inner tx {len} bytes exceeds the wire MTU {} and was dropped: {e}", self.wire_mtu);
            }
        }
        r
    }
}

/// Hand one wire-sized packet to the sink and count the outcome.
fn emit(sink: &TxSink, stats: &mut DeviceStats, packet: &[u8]) {
    match sink(packet) {
        Ok(()) => {
            stats.tx_packets += 1;
            stats.tx_bytes += packet.len() as u64;
            trace!("inner tx {} bytes", packet.len());
        }
        Err(e) => {
            stats.tx_errors += 1;
            debug!("inner tx {} bytes failed: {e}", packet.len());
        }
    }
}

impl std::fmt::Debug for EspDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EspDevice")
            .field("mtu", &self.mtu)
            .field("wire_mtu", &self.wire_mtu)
            .field("rx_len", &self.rx.len())
            .field("rx_capacity", &self.rx_capacity)
            .field("stats", &self.stats)
            .finish()
    }
}

/// One received inner IP packet, consumed by smoltcp.
pub struct EspRxToken(Vec<u8>);

impl RxToken for EspRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

/// Permission to transmit one inner IP packet through the device's sink.
pub struct EspTxToken<'a> {
    device: &'a mut EspDevice,
}

impl TxToken for EspTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        self.device.transmit_with(len, f)
    }
}

impl Device for EspDevice {
    type RxToken<'a>
        = EspRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = EspTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((EspRxToken(packet), EspTxToken { device: self }))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(EspTxToken { device: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = None;
        // smoltcp computes and verifies every checksum; ESP integrity is separate.
        let mut checksum = ChecksumCapabilities::default();
        checksum.ipv4 = Checksum::Both;
        checksum.udp = Checksum::Both;
        checksum.tcp = Checksum::Both;
        checksum.icmpv4 = Checksum::Both;
        checksum.icmpv6 = Checksum::Both;
        caps.checksum = checksum;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn capture() -> (TxSink, Arc<Mutex<Vec<Vec<u8>>>>) {
        let store = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&store);
        let sink: TxSink = Arc::new(move |pkt: &[u8]| {
            s.lock().unwrap().push(pkt.to_vec());
            Ok(())
        });
        (sink, store)
    }

    #[test]
    fn capabilities_are_ip_medium_with_configured_mtu() {
        let (sink, _) = capture();
        let dev = EspDevice::new(sink.clone(), 1400, 16384, 8);
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 16384, "smoltcp sees the stack MTU");
        assert_eq!(caps.ip_mtu(), 16384);
        assert!(caps.max_burst_size.is_none());
        assert!(caps.checksum.udp.tx() && caps.checksum.udp.rx());
        assert_eq!(dev.mtu(), 16384);
        assert_eq!(dev.wire_mtu(), 1400);
        // The stack MTU is never below the wire MTU.
        assert_eq!(EspDevice::new(sink, 1400, 100, 8).mtu(), 1400);
    }

    #[test]
    fn rx_queue_drops_oldest_and_counts() {
        let (sink, _) = capture();
        let mut dev = EspDevice::new(sink, 1280, 1280, 4);
        for i in 0..6u8 {
            dev.push_rx(vec![i; 10]);
        }
        assert_eq!(dev.rx_len(), 4);
        let s = dev.stats();
        assert_eq!(s.rx_packets, 6);
        assert_eq!(s.rx_bytes, 60);
        assert_eq!(s.rx_queue_drops, 2, "packets 0 and 1 were evicted");
        // Oldest survivor is packet 2.
        let (rx, _tx) = dev.receive(Instant::from_millis(0)).expect("queued packet");
        assert_eq!(rx.consume(|p| p[0]), 2);
        assert_eq!(dev.rx_len(), 3);
        // Draining returns packets 3, 4, 5 then None.
        let mut seen = Vec::new();
        while let Some((rx, _)) = dev.receive(Instant::from_millis(0)) {
            seen.push(rx.consume(|p| p[0]));
        }
        assert_eq!(seen, vec![3, 4, 5]);
        assert!(dev.receive(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn rx_capacity_is_at_least_one() {
        let (sink, _) = capture();
        let mut dev = EspDevice::new(sink, 1280, 1280, 0);
        assert_eq!(dev.rx_capacity(), 1);
        dev.push_rx(vec![1]);
        dev.push_rx(vec![2]);
        assert_eq!(dev.rx_len(), 1);
        assert_eq!(dev.stats().rx_queue_drops, 1);
    }

    #[test]
    fn tx_token_hands_the_packet_to_the_sink_and_counts() {
        let (sink, store) = capture();
        let mut dev = EspDevice::new(sink, 1280, 1280, 4);
        let tx = dev.transmit(Instant::from_millis(0)).expect("always transmittable");
        let r = tx.consume(5, |buf| {
            buf.copy_from_slice(b"hello");
            42
        });
        assert_eq!(r, 42);
        assert_eq!(store.lock().unwrap().as_slice(), &[b"hello".to_vec()]);
        let s = dev.stats();
        assert_eq!((s.tx_packets, s.tx_bytes, s.tx_errors), (1, 5, 0));
        // The scratch buffer is reused: a second, longer packet still arrives intact.
        dev.transmit(Instant::from_millis(0)).unwrap().consume(8, |buf| buf.copy_from_slice(b"ABCDEFGH"));
        assert_eq!(store.lock().unwrap()[1], b"ABCDEFGH".to_vec());
        assert_eq!(dev.stats().tx_bytes, 13);
    }

    #[test]
    fn tx_token_hands_exactly_len_bytes_however_large() {
        // No clamping: the sink sees exactly what smoltcp wrote, up to the maximum IP packet.
        let (sink, store) = capture();
        let mut dev = EspDevice::new(sink, 65_535, 65_535, 4);
        dev.transmit(Instant::from_millis(0)).unwrap().consume(65_535, |buf| {
            assert_eq!(buf.len(), 65_535);
            buf.fill(0x60);
        });
        assert_eq!(store.lock().unwrap()[0].len(), 65_535);
        let s = dev.stats();
        assert_eq!((s.tx_packets, s.tx_bytes, s.tx_fragmented, s.tx_frag_drops), (1, 65_535, 0, 0));
    }

    #[test]
    fn packets_longer_than_the_wire_mtu_are_fragmented_for_the_sink() {
        let (sink, store) = capture();
        let mut dev = EspDevice::new(sink, 1280, 16384, 4);
        // IPv6 + 3000 bytes of payload, written by "smoltcp" in one go.
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&3000u16.to_be_bytes());
        pkt[6] = 17;
        pkt[8..24].copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        pkt.extend((0..3000u32).map(|i| i as u8));
        dev.transmit(Instant::from_millis(0)).unwrap().consume(pkt.len(), |buf| buf.copy_from_slice(&pkt));
        let wire = store.lock().unwrap().clone();
        assert_eq!(wire.len(), 3, "3000 bytes at 1232 per fragment");
        assert!(wire.iter().all(|p| p.len() <= 1280), "{:?}", wire.iter().map(Vec::len).collect::<Vec<_>>());
        let ident = &wire[0][44..48];
        assert!(wire.iter().all(|p| &p[44..48] == ident), "one identification per set");
        let s = dev.stats();
        assert_eq!((s.tx_packets, s.tx_fragmented, s.tx_frag_drops, s.tx_errors), (3, 1, 0, 0));
        assert_eq!(s.tx_bytes as usize, wire.iter().map(Vec::len).sum::<usize>());
        // The next set gets a different identification.
        dev.transmit(Instant::from_millis(0)).unwrap().consume(pkt.len(), |buf| buf.copy_from_slice(&pkt));
        assert_ne!(&store.lock().unwrap()[3][44..48], ident);
        // Something unfragmentable (junk) above the wire MTU is dropped and counted.
        dev.transmit(Instant::from_millis(0)).unwrap().consume(2000, |buf| buf.fill(0xff));
        let s = dev.stats();
        assert_eq!((s.tx_packets, s.tx_fragmented, s.tx_frag_drops), (6, 2, 1));
        assert_eq!(store.lock().unwrap().len(), 6);
    }

    /// IPv6 TCP SYN `2001:db8::1:40000 -> 2001:db8::2:5060` announcing `mss`.
    fn tcp_syn(mss: u16) -> Vec<u8> {
        use smoltcp::wire::{IpAddress, IpProtocol, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};
        let (src, dst) = (std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let tcp = TcpRepr {
            src_port: 40000,
            dst_port: 5060,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1),
            ack_number: None,
            window_len: 1000,
            window_scale: None,
            max_seg_size: Some(mss),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv6Repr { src_addr: src, dst_addr: dst, next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64 };
        let mut buf = vec![0u8; 40 + tcp.buffer_len()];
        ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf));
        tcp.emit(&mut TcpPacket::new_unchecked(&mut buf[40..]), &IpAddress::Ipv6(src), &IpAddress::Ipv6(dst), &ChecksumCapabilities::default());
        buf
    }

    #[test]
    fn tcp_syn_mss_is_clamped_to_the_wire_mtu_both_ways() {
        let (sink, store) = capture();
        let mut dev = EspDevice::new(sink, 1280, 16384, 4);
        // TX: smoltcp announces 16384 - 60; the sink sees 1280 - 60.
        let syn = tcp_syn(16324);
        dev.transmit(Instant::from_millis(0)).unwrap().consume(syn.len(), |buf| buf.copy_from_slice(&syn));
        let sent = store.lock().unwrap()[0].clone();
        assert_eq!(u16::from_be_bytes([sent[62], sent[63]]), 1220, "MSS value right after kind/len at TCP offset 20");
        // RX: the peer's 1440 is lowered before smoltcp sees it.
        dev.push_rx(tcp_syn(1440));
        let (rx, _) = dev.receive(Instant::from_millis(0)).unwrap();
        assert_eq!(rx.consume(|p| u16::from_be_bytes([p[62], p[63]])), 1220);
        // A SYN that already fits passes untouched.
        dev.push_rx(tcp_syn(1000));
        let (rx, _) = dev.receive(Instant::from_millis(0)).unwrap();
        assert_eq!(rx.consume(|p| u16::from_be_bytes([p[62], p[63]])), 1000);
        assert_eq!(dev.stats().tcp_mss_clamped, 2);
    }

    #[test]
    fn tx_sink_failures_are_counted_not_propagated() {
        let sink: TxSink = Arc::new(|_: &[u8]| Err(crate::Error::Protocol("link down".into())));
        let mut dev = EspDevice::new(sink, 1280, 1280, 4);
        let r = dev.transmit(Instant::from_millis(0)).unwrap().consume(3, |buf| {
            buf.fill(7);
            "done"
        });
        assert_eq!(r, "done");
        let s = dev.stats();
        assert_eq!((s.tx_packets, s.tx_errors), (0, 1));
    }

    #[test]
    fn receive_pairs_the_packet_with_a_tx_token() {
        let (sink, store) = capture();
        let mut dev = EspDevice::new(sink, 1280, 1280, 4);
        dev.push_rx(vec![0x60, 0, 0, 0]);
        let (rx, tx) = dev.receive(Instant::from_millis(0)).unwrap();
        // A response can be emitted while the received packet is being consumed.
        rx.consume(|p| {
            assert_eq!(p[0] >> 4, 6);
            tx.consume(p.len(), |out| out.copy_from_slice(p));
        });
        assert_eq!(store.lock().unwrap().len(), 1);
    }
}
