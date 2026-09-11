//! [`EspDevice`]: the smoltcp [`Device`] backed by the ESP data plane (DESIGN.md §11).
//!
//! The tunnel-mode ESP payload is a raw IP packet, so the inner network is a
//! `Medium::Ip` link with no framing at all:
//!
//! - **TX**: smoltcp asks for a [`TxToken`], writes one IP packet into the device's
//!   scratch buffer and the token hands it to the injected *sink* — in the tunnel a
//!   closure doing `EspOutbound::encapsulate` + `IkeTransport::send_esp`; in tests a
//!   channel or the other stack's [`EspDevice::push_rx`].
//! - **RX**: the ESP receive thread pushes decapsulated inner IP packets with
//!   [`EspDevice::push_rx`] into a bounded queue (drop-oldest, drops counted);
//!   `receive()` pops one packet per call.
//!
//! No allocation happens per packet beyond the `Vec` the caller already hands in:
//! received packets are moved through the queue and the TX scratch buffer is reused.

use std::collections::VecDeque;
use std::sync::Arc;

use log::{debug, trace};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::Result;

/// Where transmitted inner IP packets go: `Fn(ip_packet) -> Result<()>`.
pub type TxSink = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// Default depth of the receive queue (packets), see [`EspDevice::new`].
pub const DEFAULT_RX_QUEUE_DEPTH: usize = 256;
/// Largest IP packet the TX scratch buffer will ever be grown to (IPv4/IPv6 maximum).
const MAX_IP_PACKET: usize = 65_535;

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
}

/// smoltcp `Medium::Ip` device over ESP. Not `Sync`: it lives inside the stack's mutex.
pub struct EspDevice {
    sink: TxSink,
    rx: VecDeque<Vec<u8>>,
    rx_capacity: usize,
    mtu: usize,
    scratch: Vec<u8>,
    stats: DeviceStats,
}

impl EspDevice {
    /// A device whose transmitted packets go to `sink`, with link MTU `mtu` (bytes of
    /// IP packet) and a receive queue of `rx_capacity` packets (min 1).
    pub fn new(sink: TxSink, mtu: usize, rx_capacity: usize) -> Self {
        let rx_capacity = rx_capacity.max(1);
        EspDevice {
            sink,
            rx: VecDeque::with_capacity(rx_capacity),
            rx_capacity,
            mtu,
            scratch: Vec::with_capacity(mtu),
            stats: DeviceStats::default(),
        }
    }

    /// Queue one decapsulated inner IP packet for the stack. When the queue is full
    /// the oldest packet is dropped (and counted) so a stalled stack sheds load
    /// instead of blocking the ESP receive thread.
    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += packet.len() as u64;
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

    /// Link MTU in bytes of IP packet.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn stats(&self) -> DeviceStats {
        self.stats
    }

    /// Hand `len` bytes (filled in by `f`) to the sink.
    fn transmit_with<R, F: FnOnce(&mut [u8]) -> R>(&mut self, len: usize, f: F) -> R {
        let len = len.min(MAX_IP_PACKET);
        if self.scratch.len() < len {
            self.scratch.resize(len, 0);
        }
        let buf = &mut self.scratch[..len];
        let r = f(buf);
        match (self.sink)(buf) {
            Ok(()) => {
                self.stats.tx_packets += 1;
                self.stats.tx_bytes += len as u64;
                trace!("inner tx {len} bytes");
            }
            Err(e) => {
                self.stats.tx_errors += 1;
                debug!("inner tx {len} bytes failed: {e}");
            }
        }
        r
    }
}

impl std::fmt::Debug for EspDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EspDevice")
            .field("mtu", &self.mtu)
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
        let dev = EspDevice::new(sink, 1400, 8);
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1400);
        assert_eq!(caps.ip_mtu(), 1400);
        assert!(caps.max_burst_size.is_none());
        assert!(caps.checksum.udp.tx() && caps.checksum.udp.rx());
        assert_eq!(dev.mtu(), 1400);
    }

    #[test]
    fn rx_queue_drops_oldest_and_counts() {
        let (sink, _) = capture();
        let mut dev = EspDevice::new(sink, 1280, 4);
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
        let mut dev = EspDevice::new(sink, 1280, 0);
        assert_eq!(dev.rx_capacity(), 1);
        dev.push_rx(vec![1]);
        dev.push_rx(vec![2]);
        assert_eq!(dev.rx_len(), 1);
        assert_eq!(dev.stats().rx_queue_drops, 1);
    }

    #[test]
    fn tx_token_hands_the_packet_to_the_sink_and_counts() {
        let (sink, store) = capture();
        let mut dev = EspDevice::new(sink, 1280, 4);
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
    fn tx_sink_failures_are_counted_not_propagated() {
        let sink: TxSink = Arc::new(|_: &[u8]| Err(crate::Error::Protocol("link down".into())));
        let mut dev = EspDevice::new(sink, 1280, 4);
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
        let mut dev = EspDevice::new(sink, 1280, 4);
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
