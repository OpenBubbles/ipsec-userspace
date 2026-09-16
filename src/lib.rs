//! `epdg` — a userspace IKEv2 + EAP-TLS + ESP-in-UDP client for 3GPP ePDG (VoWiFi) gateways.
//!
//! Everything runs over plain UDP sockets: IKEv2 (RFC 7296) with EAP-only
//! authentication (RFC 5998) carrying EAP-TLS (RFC 5216 / RFC 9190), tunnel-mode
//! ESP (RFC 4303) encapsulated in UDP (RFC 3948), and an inner IPv4/IPv6 stack
//! (smoltcp over the ESP data plane) so callers can talk to hosts inside the tunnel
//! (UDP sockets, DNS). No raw sockets, no kernel IPsec, no privileges.
//!
//! Driven entirely by a carrier-bundle style [`Config`] (see `docs/DESIGN.md`); the
//! algorithm set is a registry (`crypto::registry`) so new transforms can be added
//! without touching the protocol code.
//!
//! Layout:
//! - [`config`]  — configuration model + plist bundle parsing
//! - [`crypto`]  — cipher / integrity / PRF / DH traits, implementations, registry
//! - [`ike`]     — IKEv2 wire codec, key derivation, initiator state machine, transport
//! - [`eap`]     — EAP framing and the EAP-TLS method (OpenSSL-backed)
//! - [`esp`]     — ESP codec, anti-replay, UDP encapsulation
//! - [`ipstack`] — inner IP stack: smoltcp `Medium::Ip` device over ESP + stack thread (UDP, DNS)
//! - [`tunnel`]  — the public facade: `EpdgTunnel::connect(&Config)`, MOBIKE / RFC 7296 §2.23
//!   address updates, path monitoring and liveness (DESIGN §17)
//! - [`netstack`] — `NetStack`: one UDP/TCP/DNS abstraction over the OS stack (`StdNetStack`) and the tunnel
//! - [`pem`]     — PEM → DER at the boundary (test fixtures, provisioning responses); the config itself is DER-only

pub mod config;
pub mod crypto;
pub mod eap;
pub mod error;
pub mod esp;
pub mod ike;
pub mod ipstack;
pub mod netstack;
pub mod pem;
pub mod tunnel;

pub use config::Config;
pub use error::{Error, Result};
pub use netstack::{NetStack, StdNetStack, StreamIo, TcpListenerLike, TcpStreamLike, UdpSocketLike};
pub use tunnel::{EpdgTunnel, InnerUdpSocket, TunnelInfo};
