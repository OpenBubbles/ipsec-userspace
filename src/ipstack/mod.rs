//! Inner IP stack = smoltcp over the ESP data plane (DESIGN.md §11).
//!
//! - [`device`]: [`EspDevice`], a `Medium::Ip` [`smoltcp::phy::Device`] whose TX goes
//!   to an injected sink (ESP encapsulation in the tunnel) and whose RX queue is fed
//!   by the ESP receive thread.
//! - [`stack`]: [`InnerStack`], the `Interface` + `SocketSet` + device behind one
//!   mutex, driven by the single stack thread; [`InnerUdpSocket`] and
//!   [`InnerStack::resolve`] are the caller-facing surface.

pub mod device;
pub mod stack;

pub use device::{DEFAULT_RX_QUEUE_DEPTH, DeviceStats, EspDevice, TxSink};
pub use stack::{
    EPHEMERAL_PORT_HI, EPHEMERAL_PORT_LO, InnerStack, InnerUdpSocket, MAX_INNER_MTU, MIN_INNER_MTU, StackStats,
    UDP_QUEUE_DEPTH, UdpDatagram, max_udp_payload,
};
