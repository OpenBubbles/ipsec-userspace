//! Crate-wide error type.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// All failures surfaced by the crate. Protocol-level failures carry enough
/// context (exchange, payload, notify type) to diagnose against a packet capture.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Malformed or unexpected bytes on the wire.
    #[error("decode error: {0}")]
    Decode(String),

    /// Encoding a message failed (e.g. oversize payload).
    #[error("encode error: {0}")]
    Encode(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    /// Unsupported algorithm / transform id / group.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The peer sent an error Notify (type < 16384). `data` is the raw notify data.
    #[error("peer notify error {notify_type} ({name}) in {exchange}")]
    PeerNotify { notify_type: u16, name: &'static str, exchange: &'static str, data: Vec<u8> },

    /// Integrity check (ICV) failed on an IKE SK payload or ESP packet.
    #[error("integrity check failed: {0}")]
    Integrity(&'static str),

    /// The peer's AUTH payload did not verify.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// EAP method failure (EAP-Failure received, or TLS handshake error).
    #[error("eap error: {0}")]
    Eap(String),

    /// TLS engine (OpenSSL) failure: handshake, certificate verification, exporter.
    #[error("tls error: {0}")]
    Tls(String),

    /// No response after all retransmissions.
    #[error("timeout waiting for {0}")]
    Timeout(&'static str),

    /// State-machine misuse or unexpected message for the current state.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// The tunnel was closed (locally or by a peer DELETE).
    #[error("tunnel closed: {0}")]
    Closed(String),
}

impl Error {
    pub fn decode(msg: impl fmt::Display) -> Self { Error::Decode(msg.to_string()) }
    pub fn encode(msg: impl fmt::Display) -> Self { Error::Encode(msg.to_string()) }
    pub fn protocol(msg: impl fmt::Display) -> Self { Error::Protocol(msg.to_string()) }
    pub fn config(msg: impl fmt::Display) -> Self { Error::Config(msg.to_string()) }
    pub fn crypto(msg: impl fmt::Display) -> Self { Error::Crypto(msg.to_string()) }
}
