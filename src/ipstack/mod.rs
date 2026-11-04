//! Inner IP stack = smoltcp over the ESP data plane (DESIGN.md §11).
//!
//! - [`device`]: [`EspDevice`], a `Medium::Ip` [`smoltcp::phy::Device`] whose TX goes
//!   to an injected sink (ESP encapsulation in the tunnel) and whose RX queue is fed
//!   by the ESP receive thread.
//! - [`frag`]: the IP fragmentation shim of §11.1 — smoltcp 0.14 cannot fragment or
//!   reassemble IPv6 on `Medium::Ip`, so the device splits outbound packets to the
//!   wire MTU and [`InnerStack::push_rx`] reassembles inbound IPv6 fragment sets.
//!   It also clamps the MSS of TCP SYNs to the wire MTU (§11.2), so TCP never needs it.
//! - [`stack`]: [`InnerStack`], the `Interface` + `SocketSet` + device behind one
//!   mutex, driven by the single stack thread; [`InnerUdpSocket`],
//!   [`InnerStack::resolve`], [`InnerTcpStream`] and [`InnerTcpListener`] are the
//!   caller-facing surface.

pub mod device;
pub mod frag;
pub mod stack;

pub use device::{DEFAULT_RX_QUEUE_DEPTH, DeviceStats, EspDevice, TxSink};
pub use frag::{
    FragmentError, Ipv6Reassembler, ReassemblyStats, clamp_tcp_mss, fragment_for_wire, tcp_connection_request, tcp_mss_for_wire,
};
pub use stack::{
    EPHEMERAL_PORT_HI, EPHEMERAL_PORT_LO, InnerStack, InnerTcpListener, InnerTcpStream, InnerUdpSocket, MAX_INNER_MTU,
    MIN_INNER_MTU, SMOLTCP_DNS_RETRANSMIT_TIMEOUT, StackStats, TCP_BUFFER_BYTES, TCP_LISTEN_BACKLOG, TCP_ORPHAN_LINGER,
    UDP_QUEUE_DEPTH, UdpDatagram, max_udp_payload,
};
