//! Inner IP stack = smoltcp over the ESP data plane (DESIGN.md §11).
//!
//! - [`device`]: [`EspDevice`], a `Medium::Ip` [`smoltcp::phy::Device`] whose TX goes
//!   to an injected sink (ESP encapsulation in the tunnel) and whose RX queue is fed
//!   by the ESP receive thread.
//! - [`frag`]: the IP fragmentation shim of §11.1 — smoltcp 0.14 cannot fragment or
//!   reassemble IPv6 on `Medium::Ip`, so the device splits outbound packets to the
//!   wire MTU and [`InnerStack::push_rx`] reassembles inbound IPv6 fragment sets.
//! - [`stack`]: [`InnerStack`], the `Interface` + `SocketSet` + device behind one
//!   mutex, driven by the single stack thread; [`InnerUdpSocket`] and
//!   [`InnerStack::resolve`] are the caller-facing surface.

pub mod device;
pub mod frag;
pub mod stack;

pub use device::{DEFAULT_RX_QUEUE_DEPTH, DeviceStats, EspDevice, TxSink};
pub use frag::{FragmentError, Ipv6Reassembler, ReassemblyStats, fragment_for_wire};
pub use stack::{
    EPHEMERAL_PORT_HI, EPHEMERAL_PORT_LO, InnerStack, InnerUdpSocket, MAX_INNER_MTU, MIN_INNER_MTU,
    SMOLTCP_DNS_RETRANSMIT_TIMEOUT, StackStats, UDP_QUEUE_DEPTH, UdpDatagram, max_udp_payload,
};
