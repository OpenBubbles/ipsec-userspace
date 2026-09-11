//! EAP-TLS method (RFC 5216; TLS 1.3 keying per RFC 9190), backed by OpenSSL.
//!
//! Type 13. Type-Data = `Flags(1) | [TLS Message Length(4) if L] | TLS data`.
//! Flags: L = 0x80 (length included), M = 0x40 (more fragments), S = 0x20 (start),
//! low 3 bits = version (always 0 on send, ignored on receive).
//!
//! The state machine mirrors the proven AOSP client (`docs/AOSP_FACTS.md`, EAP area):
//! - outbound TLS flights are cut into `max_fragment_len` (1024) byte fragments; the FIRST
//!   fragment (and every unfragmented non-empty message) carries L + the 4-byte total
//!   length, continuation fragments carry no L; M is set on every chunk but the last;
//!   continuation fragments go out only when the server sends an ACK (flags 0, no data);
//! - inbound fragments are reassembled into a buffer sized by the L length on the server's
//!   first fragment; each fragment with M set is answered with the ACK `02 <id> 00 06 0d 00`;
//!   the last fragment is detected solely by M = 0;
//! - once the handshake completes with nothing left to write, the MSK/EMSK are exported
//!   immediately and the empty ACK is sent; the following EAP-Success yields
//!   [`EapAction::Success`]; an EAP-Success before completion is a fatal [`EapAction::Failure`];
//! - responses always echo the request identifier.
//!
//! TLS engine (`docs/DESIGN.md` §9.3): OpenSSL, because the T-Mobile ePDG negotiates only
//! `TLS_RSA_WITH_AES_128_CBC_SHA` (0x002F, TLS 1.2) — RSA key exchange + CBC, which rustls does
//! not implement. The cipher list is [`CIPHER_LIST`] so that suite is offered next to modern
//! ones. The connection is driven sans-I/O through an in-memory duplex: the server's TLS bytes
//! are queued into the duplex inbox, `SslStream::connect()` is stepped (`WANT_READ` = wait for
//! the next server flight, `Ok` = handshake complete), and the outbox is drained into the
//! EAP-TLS fragment queue after every step.
//!
//! Key material: 128 exporter bytes; MSK = `[..64]`, EMSK = `[64..]`.
//! TLS 1.2: label `"client EAP encryption"`, no context (RFC 5216 §2.3).
//! TLS 1.3: label `"EXPORTER_EAP_TLS_Key_Material"`, context `[0x0D]` (RFC 9190 §2.1).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::IpAddr;

use log::{debug, info, warn};
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::ssl::{ErrorCode, Ssl, SslContext, SslMethod, SslOptions, SslRef, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::verify::X509CheckFlags;
use openssl::x509::{X509, X509VerifyResult};
use zeroize::Zeroizing;

use super::packet::EapPacket;
use crate::ike::constants::*;
use crate::{Error, Result};

/// Default outbound fragment size in TLS-data bytes (AOSP `DEFAULT_FRAGMENTATION_SIZE`).
pub const DEFAULT_MAX_FRAGMENT_LEN: usize = 1024;
/// Exporter output length: MSK (64) | EMSK (64).
const KEY_MATERIAL_LEN: usize = 128;
const MSK_LEN: usize = 64;
/// Upper bound on a declared inbound EAP-TLS flight (a TLS 1.2 handshake flight is far
/// below this; RFC 5216 §2.1.5 fragments one TLS flight per EAP-TLS message). Bounds the
/// buffer the peer's 32-bit L field can make us allocate.
pub const MAX_INBOUND_TLS_FLIGHT: usize = 256 * 1024;
/// Largest outbound fragment that still fits an EAP packet (RFC 3748 Length is u16).
pub const MAX_OUTBOUND_FRAGMENT_LEN: usize = u16::MAX as usize - 10;
/// OpenSSL cipher list for the TLS <= 1.2 ClientHello: `DEFAULT` at security level 1, so
/// `AES128-SHA` (`TLS_RSA_WITH_AES_128_CBC_SHA`, 0x002F — the only suite the T-Mobile ePDG
/// accepts) is offered alongside the ECDHE/AEAD suites.
pub const CIPHER_LIST: &str = "DEFAULT:@SECLEVEL=1";

/// Configuration for one EAP-TLS session.
pub struct EapTlsConfig {
    /// EAP-Response/Identity body (raw bytes, no NUL, no realm added).
    pub identity: Vec<u8>,
    /// Client certificate PEM; may contain a chain (leaf first). Only the leaf is sent (AOSP).
    pub client_cert_pem: String,
    /// Client private key PEM (PKCS#8, PKCS#1 or SEC1).
    pub client_key_pem: String,
    /// Validate the server certificate against `server_ca_pem`. `false` = trust-all (AOSP default).
    pub validate_server: bool,
    /// Trust anchors (PEM bundle) used when `validate_server` is set.
    pub server_ca_pem: Option<String>,
    /// TLS server name: sent as SNI (unless it is an IP literal, which RFC 6066 §3 forbids)
    /// and, when `validate_server` is set, checked against the server certificate.
    /// `None` = no SNI and no hostname check (the default; AOSP sends none).
    pub server_name: Option<String>,
    /// Outbound fragment size in TLS-data bytes; 0 = [`DEFAULT_MAX_FRAGMENT_LEN`].
    pub max_fragment_len: usize,
    /// Also offer TLS 1.3 (AOSP is TLS 1.2 only).
    pub allow_tls13: bool,
}

/// What the caller must do after feeding a peer EAP packet to [`EapTlsClient::handle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EapAction {
    /// Send this EAP packet to the peer (in an IKE_AUTH request carrying only `EAP`).
    Send(EapPacket),
    /// EAP-Success received after a completed handshake: keying material is ready.
    Success { msk: Zeroizing<Vec<u8>>, emsk: Zeroizing<Vec<u8>> },
    /// Fatal EAP-level failure (EAP-Failure received, or EAP-Success before completion).
    Failure(String),
}

/// Decoded EAP-TLS Type-Data (RFC 5216 §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EapTlsData {
    /// Flag byte as received/sent. On encode, L is set iff `length.is_some()`.
    pub flags: u8,
    /// TLS Message Length field, present iff L.
    pub length: Option<u32>,
    /// TLS record bytes.
    pub data: Vec<u8>,
}

impl EapTlsData {
    /// The ACK / empty response: single flags byte `0x00`.
    pub fn ack() -> EapTlsData {
        EapTlsData { flags: 0, length: None, data: Vec::new() }
    }

    pub fn has_l(&self) -> bool { self.flags & EAP_TLS_FLAG_L != 0 }
    pub fn has_m(&self) -> bool { self.flags & EAP_TLS_FLAG_M != 0 }
    pub fn has_s(&self) -> bool { self.flags & EAP_TLS_FLAG_S != 0 }

    /// An ACK is: no data, and none of L/M/S (version bits ignored).
    pub fn is_ack(&self) -> bool {
        self.data.is_empty() && self.flags & (EAP_TLS_FLAG_L | EAP_TLS_FLAG_M | EAP_TLS_FLAG_S) == 0
    }

    /// Decode Type-Data. Rejects a missing flags byte, L with fewer than 4 length bytes,
    /// and (M clear, L set) data longer than the declared length. Shorter is accepted.
    pub fn decode(type_data: &[u8]) -> Result<EapTlsData> {
        let flags = *type_data
            .first()
            .ok_or_else(|| Error::decode("EAP-TLS type-data missing flags byte"))?;
        let (length, data) = if flags & EAP_TLS_FLAG_L != 0 {
            if type_data.len() < 5 {
                return Err(Error::decode(format!(
                    "EAP-TLS L flag set but only {} bytes after flags",
                    type_data.len() - 1
                )));
            }
            let l = u32::from_be_bytes([type_data[1], type_data[2], type_data[3], type_data[4]]);
            (Some(l), &type_data[5..])
        } else {
            (None, &type_data[1..])
        };
        if flags & EAP_TLS_FLAG_M == 0 {
            if let Some(l) = length {
                if data.len() > l as usize {
                    return Err(Error::decode(format!(
                        "EAP-TLS payload ({} bytes) larger than declared length {l}",
                        data.len()
                    )));
                }
            }
        }
        Ok(EapTlsData { flags, length, data: data.to_vec() })
    }

    /// Encode Type-Data. L is emitted iff `length` is present; version bits are cleared.
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = self.flags & (EAP_TLS_FLAG_M | EAP_TLS_FLAG_S);
        let mut out = Vec::with_capacity(5 + self.data.len());
        if let Some(l) = self.length {
            flags |= EAP_TLS_FLAG_L;
            out.push(flags);
            out.extend_from_slice(&l.to_be_bytes());
        } else {
            out.push(flags);
        }
        out.extend_from_slice(&self.data);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Before the first EAP-TLS request: Identity / Nak phase.
    Created,
    /// TLS handshake in progress.
    Handshake,
    /// Handshake complete, MSK derived, final ACK sent; waiting for EAP-Success.
    AwaitingSuccess,
    /// EAP-Success delivered.
    Done,
    /// Fatal failure reported.
    Failed,
}

/// In-progress inbound reassembly.
struct RxBuffer {
    buf: Vec<u8>,
    capacity: usize,
}

/// In-memory transport under the [`SslStream`]: OpenSSL reads the peer's TLS bytes from
/// `inbox` (an empty inbox reads as `WouldBlock`, which `connect()` reports as
/// `ErrorCode::WANT_READ`) and writes its own records into `outbox`.
#[derive(Default)]
struct Duplex {
    inbox: VecDeque<u8>,
    outbox: Vec<u8>,
}

impl Read for Duplex {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inbox.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inbox.read(buf)
    }
}

impl Write for Duplex {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbox.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Protocol version and cipher suite as reported by OpenSSL once the ServerHello is in.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Negotiated {
    version: String,
    cipher: String,
}

fn negotiated(ssl: &SslRef) -> Option<Negotiated> {
    let cipher = ssl.current_cipher()?;
    Some(Negotiated { version: ssl.version_str().to_string(), cipher: cipher.name().to_string() })
}

/// The EAP-TLS client state machine (sans-I/O, synchronous).
pub struct EapTlsClient {
    identity: Vec<u8>,
    tls_ctx: SslContext,
    server_name: Option<String>,
    validate_server: bool,
    max_fragment_len: usize,
    conn: Option<SslStream<Duplex>>,
    /// `connect()` returned `Ok`: from here on inbound records are post-handshake data
    /// (TLS 1.3 NewSessionTicket, the RFC 9190 commitment byte) consumed via `ssl_read`.
    handshake_done: bool,
    negotiated: Option<Negotiated>,
    rx: Option<RxBuffer>,
    /// Outbound TLS bytes awaiting transmission; `tx_offset` = bytes already sent.
    tx: Vec<u8>,
    tx_offset: usize,
    state: State,
    msk: Option<Zeroizing<Vec<u8>>>,
    emsk: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for EapTlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EapTlsClient")
            .field("state", &self.state)
            .field("handshake_done", &self.handshake_done)
            .field("negotiated", &self.negotiated)
            .field("tx_pending", &(self.tx.len() - self.tx_offset))
            .field("rx_pending", &self.rx.as_ref().map(|r| (r.buf.len(), r.capacity)))
            .field("msk", &self.msk.as_ref().map(|_| "<derived>"))
            .finish()
    }
}

impl EapTlsClient {
    /// Build the OpenSSL context up front so PEM / trust-store errors surface early.
    pub fn new(cfg: EapTlsConfig) -> Result<Self> {
        let tls_ctx = build_context(&cfg)?;
        // Clamp so EAP hdr(4) + type(1) + flags(1) + L(4) + data always fits the 16-bit Length.
        let max_fragment_len = if cfg.max_fragment_len == 0 { DEFAULT_MAX_FRAGMENT_LEN } else { cfg.max_fragment_len }
            .min(MAX_OUTBOUND_FRAGMENT_LEN);
        Ok(EapTlsClient {
            identity: cfg.identity,
            tls_ctx,
            server_name: cfg.server_name.filter(|n| !n.is_empty()),
            validate_server: cfg.validate_server,
            max_fragment_len,
            conn: None,
            handshake_done: false,
            negotiated: None,
            rx: None,
            tx: Vec::new(),
            tx_offset: 0,
            state: State::Created,
            msk: None,
            emsk: None,
        })
    }

    /// Feed ANY EAP packet from the peer (Request/Identity, Request/TLS, Success, Failure)
    /// and get the action to take.
    pub fn handle(&mut self, packet: &EapPacket) -> Result<EapAction> {
        match packet.code {
            EAP_CODE_SUCCESS => match self.state {
                State::AwaitingSuccess => {
                    let (Some(msk), Some(emsk)) = (self.msk.as_ref(), self.emsk.as_ref()) else {
                        self.state = State::Failed;
                        return Ok(EapAction::Failure("EAP-Success received but no MSK was derived".into()));
                    };
                    info!("EAP-Success received; EAP-TLS complete (MSK ready)");
                    self.state = State::Done;
                    Ok(EapAction::Success { msk: Zeroizing::new(msk.to_vec()), emsk: Zeroizing::new(emsk.to_vec()) })
                }
                State::Done => Err(Error::protocol("EAP-Success received after the EAP session finished")),
                State::Failed => Err(Error::protocol("EAP-Success received after the EAP session failed")),
                State::Created | State::Handshake => {
                    warn!("EAP-Success received before the TLS handshake completed (state {:?})", self.state);
                    self.state = State::Failed;
                    Ok(EapAction::Failure("EAP-Success received before the TLS handshake completed".into()))
                }
            },
            EAP_CODE_FAILURE => {
                warn!("EAP-Failure received (state {:?})", self.state);
                self.state = State::Failed;
                Ok(EapAction::Failure("EAP-Failure received".into()))
            }
            EAP_CODE_RESPONSE => Err(Error::Eap("received an EAP Response; only Requests are expected".into())),
            EAP_CODE_REQUEST => {
                let eap_type = packet
                    .eap_type
                    .ok_or_else(|| Error::decode("EAP Request without a Type"))?;
                match eap_type {
                    EAP_TYPE_NOTIFICATION => {
                        info!("EAP-Request/Notification: {}", String::from_utf8_lossy(&packet.type_data));
                        Ok(EapAction::Send(EapPacket::notification_response(packet.identifier)))
                    }
                    EAP_TYPE_IDENTITY => match self.state {
                        State::Created => {
                            debug!("EAP-Request/Identity -> Response/Identity ({} bytes)", self.identity.len());
                            Ok(EapAction::Send(EapPacket::identity_response(packet.identifier, &self.identity)))
                        }
                        _ => Err(Error::Eap(format!(
                            "EAP-Request/Identity received in state {:?}; expected EAP Type 13",
                            self.state
                        ))),
                    },
                    EAP_TYPE_TLS => self.handle_tls(packet.identifier, &packet.type_data),
                    EAP_TYPE_NAK => Err(Error::Eap("received an EAP-Request of Type 3 (Nak)".into())),
                    other => match self.state {
                        State::Created => {
                            info!("EAP-Request of unsupported Type {other}; sending Nak for EAP-TLS");
                            Ok(EapAction::Send(EapPacket::nak(packet.identifier, &[EAP_TYPE_TLS])))
                        }
                        _ => Err(Error::Eap(format!("expected EAP Type 13, received {other}"))),
                    },
                }
            }
            other => Err(Error::decode(format!("unknown EAP code {other}"))),
        }
    }

    /// Negotiated TLS protocol version (OpenSSL's name, e.g. `"TLSv1.2"`), once the
    /// ServerHello has been processed.
    pub fn protocol_version(&self) -> Option<&str> {
        self.negotiated.as_ref().map(|n| n.version.as_str())
    }

    /// Negotiated cipher suite (OpenSSL's name, e.g. `"AES128-SHA"`), once the ServerHello
    /// has been processed.
    pub fn cipher_name(&self) -> Option<&str> {
        self.negotiated.as_ref().map(|n| n.cipher.as_str())
    }

    /// The 64-byte MSK, available as soon as the handshake completed.
    pub fn msk(&self) -> Option<&[u8]> {
        self.msk.as_deref().map(|v| v.as_slice())
    }

    // ---- EAP-TLS request handling -------------------------------------------------------

    fn handle_tls(&mut self, id: u8, type_data: &[u8]) -> Result<EapAction> {
        let td = EapTlsData::decode(type_data)?;
        debug!(
            "EAP-TLS in: id={id} len={} flags=0x{:02x} lenField={} data={}",
            type_data.len(),
            td.flags,
            td.length.map(|l| l.to_string()).unwrap_or_else(|| "-".into()),
            hex::encode(&td.data)
        );
        match self.state {
            State::Created => {
                if !td.has_s() {
                    return Err(Error::Eap("first EAP-TLS request received without the Start bit set".into()));
                }
                if !td.data.is_empty() {
                    warn!("EAP-TLS Start carried {} bytes of TLS data; ignored", td.data.len());
                }
                self.start_handshake()?;
                self.state = State::Handshake;
                self.send_next_fragment(id)
            }
            State::Handshake => {
                if td.has_s() {
                    return Err(Error::Eap("EAP-TLS Start received while a TLS session already exists".into()));
                }
                let pending = self.tx.len() - self.tx_offset;
                if td.is_ack() {
                    if pending > 0 {
                        return self.send_next_fragment(id);
                    }
                    return Err(Error::Eap("EAP-TLS ACK from server but no outbound fragments are pending".into()));
                }
                if pending > 0 {
                    return Err(Error::Eap(format!(
                        "EAP-TLS data received while {pending} outbound bytes are still pending an ACK"
                    )));
                }
                match self.reassemble(td)? {
                    None => {
                        debug!("EAP-TLS fragment buffered; sending ACK");
                        Ok(EapAction::Send(EapPacket::response(id, EAP_TYPE_TLS, EapTlsData::ack().encode())))
                    }
                    Some(msg) => self.process_inbound(id, &msg),
                }
            }
            State::AwaitingSuccess | State::Done => Err(Error::Eap(format!(
                "unexpected EAP-TLS request after handshake completion (state {:?})",
                self.state
            ))),
            State::Failed => Err(Error::Eap("EAP-TLS request after the EAP session failed".into())),
        }
    }

    fn start_handshake(&mut self) -> Result<()> {
        info!(
            "EAP-TLS Start: opening TLS client session (SNI: {})",
            self.server_name.as_deref().unwrap_or("none")
        );
        let mut ssl = Ssl::new(&self.tls_ctx).map_err(tls_err)?;
        if let Some(name) = &self.server_name {
            let ip = name.parse::<IpAddr>().ok();
            match ip {
                Some(_) => debug!("EAP-TLS: server_name {name:?} is an IP literal; no SNI is sent (RFC 6066 §3)"),
                None => ssl.set_hostname(name).map_err(tls_err)?,
            }
            if self.validate_server {
                let param = ssl.param_mut();
                param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
                match ip {
                    Some(ip) => param.set_ip(ip),
                    None => param.set_host(name),
                }
                .map_err(tls_err)?;
            }
        }
        self.conn = Some(SslStream::new(ssl, Duplex::default()).map_err(tls_err)?);
        self.handshake_done = false;
        self.negotiated = None;
        self.step_tls()?;
        let tx = self.take_outbox();
        if tx.is_empty() {
            return Err(Error::Eap("TLS client produced no ClientHello".into()));
        }
        debug!("EAP-TLS ClientHello: {} bytes", tx.len());
        self.tx = tx;
        self.tx_offset = 0;
        Ok(())
    }

    /// Emit the next outbound fragment: L (+ total length) on the first, M while more remain.
    fn send_next_fragment(&mut self, id: u8) -> Result<EapAction> {
        let remaining = self.tx.len() - self.tx_offset;
        if remaining == 0 {
            return Err(Error::Eap("no outbound EAP-TLS data to send".into()));
        }
        let chunk_len = remaining.min(self.max_fragment_len);
        let first = self.tx_offset == 0;
        let more = chunk_len < remaining;
        let total = self.tx.len();
        let chunk = self.tx[self.tx_offset..self.tx_offset + chunk_len].to_vec();
        self.tx_offset += chunk_len;
        if self.tx_offset == self.tx.len() {
            self.tx.clear();
            self.tx_offset = 0;
        }
        let td = EapTlsData {
            flags: if more { EAP_TLS_FLAG_M } else { 0 },
            length: if first { Some(u32::try_from(total).map_err(|_| Error::encode("TLS message too long"))?) } else { None },
            data: chunk,
        };
        debug!(
            "EAP-TLS out: id={id} chunk={chunk_len} total={total} first={first} more={more} remaining={}",
            remaining - chunk_len
        );
        Ok(EapAction::Send(EapPacket::response(id, EAP_TYPE_TLS, td.encode())))
    }

    /// Inbound reassembly (AOSP `EapTtlsInboundFragmentationHelper` semantics).
    /// Returns `Some(message)` when the last fragment (M = 0) has arrived.
    fn reassemble(&mut self, td: EapTlsData) -> Result<Option<Vec<u8>>> {
        match self.rx.take() {
            None => {
                if td.has_m() {
                    let capacity = td.length.ok_or_else(|| {
                        Error::Eap("EAP-TLS first fragment has M set but no L/length (more data than declared)".into())
                    })? as usize;
                    // The declared length is peer-controlled (and pre-authentication): bound it
                    // before it sizes a buffer, or a hostile L of 0xFFFFFFFF forces a 4 GiB
                    // zero-fill at the M=0 fragment.
                    if capacity > MAX_INBOUND_TLS_FLIGHT {
                        return Err(Error::Eap(format!(
                            "EAP-TLS declared length {capacity} exceeds the {MAX_INBOUND_TLS_FLIGHT} byte inbound flight limit"
                        )));
                    }
                    if td.data.len() > capacity {
                        return Err(Error::Eap(format!(
                            "EAP-TLS fragment carries {} bytes but declared total is {capacity}",
                            td.data.len()
                        )));
                    }
                    debug!("EAP-TLS reassembly started: {}/{capacity} bytes", td.data.len());
                    self.rx = Some(RxBuffer { buf: td.data, capacity });
                    Ok(None)
                } else {
                    // Unfragmented message; a shorter-than-declared payload is accepted as-is.
                    Ok(Some(td.data))
                }
            }
            Some(mut rx) => {
                if let Some(l) = td.length {
                    if l as usize != rx.capacity {
                        return Err(Error::Eap(format!(
                            "EAP-TLS fragment declares total length {l} but reassembly expects {}",
                            rx.capacity
                        )));
                    }
                }
                let remaining = rx.capacity - rx.buf.len();
                if td.data.len() > remaining {
                    return Err(Error::Eap(format!(
                        "EAP-TLS fragment carries {} bytes but only {remaining} remain of the declared {}",
                        td.data.len(),
                        rx.capacity
                    )));
                }
                rx.buf.extend_from_slice(&td.data);
                debug!("EAP-TLS reassembly: {}/{} bytes", rx.buf.len(), rx.capacity);
                if td.has_m() {
                    self.rx = Some(rx);
                    Ok(None)
                } else {
                    if rx.buf.len() < rx.capacity {
                        warn!(
                            "EAP-TLS server delivered {} of {} declared bytes; zero-padding (AOSP behaviour)",
                            rx.buf.len(),
                            rx.capacity
                        );
                        rx.buf.resize(rx.capacity, 0);
                    }
                    Ok(Some(rx.buf))
                }
            }
        }
    }

    /// Feed a complete inbound TLS flight and decide the reply.
    fn process_inbound(&mut self, id: u8, msg: &[u8]) -> Result<EapAction> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| Error::protocol("EAP-TLS data before the TLS session was started"))?;
        debug!("EAP-TLS feeding {} bytes to TLS", msg.len());
        conn.get_mut().inbox.extend(msg);
        self.step_tls()?;
        let tx = self.take_outbox();
        debug!(
            "EAP-TLS after TLS processing: {} bytes to send, handshake_done={}",
            tx.len(),
            self.handshake_done
        );

        if !tx.is_empty() {
            self.tx = tx;
            self.tx_offset = 0;
            return self.send_next_fragment(id);
        }
        if self.msk.is_some() {
            self.state = State::AwaitingSuccess;
            debug!("EAP-TLS sending final empty response; awaiting EAP-Success");
            return Ok(EapAction::Send(EapPacket::response(id, EAP_TYPE_TLS, EapTlsData::ack().encode())));
        }
        Err(Error::Eap(
            "TLS handshake stalled: the server flight produced no reply but the handshake is not complete \
             (record split across EAP messages, or a message that needs no answer)"
                .into(),
        ))
    }

    // ---- OpenSSL plumbing ---------------------------------------------------------------

    /// Advance the TLS engine over whatever is in the duplex inbox.
    ///
    /// Before completion this is one `connect()` step: `Ok` = handshake complete (the
    /// MSK/EMSK are exported right away), `WANT_READ` = the next server flight is needed,
    /// anything else = [`Error::Tls`]. After completion it lets OpenSSL consume
    /// post-handshake records (TLS 1.3 NewSessionTicket, the RFC 9190 commitment byte).
    fn step_tls(&mut self) -> Result<()> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| Error::protocol("EAP-TLS data before the TLS session was started"))?;
        if !self.handshake_done {
            match conn.connect() {
                Ok(()) => {
                    self.handshake_done = true;
                    let ssl = conn.ssl();
                    let neg = negotiated(ssl)
                        .ok_or_else(|| Error::Tls("handshake complete but OpenSSL reports no cipher suite".into()))?;
                    let tls13 = ssl.version2() == Some(SslVersion::TLS1_3);
                    let (msk, emsk) = derive_key_material(ssl, tls13)?;
                    info!("EAP-TLS handshake complete: {} {}; MSK/EMSK derived", neg.version, neg.cipher);
                    self.negotiated = Some(neg);
                    self.msk = Some(msk);
                    self.emsk = Some(emsk);
                }
                Err(e) if e.code() == ErrorCode::WANT_READ => {
                    if let Some(neg) = negotiated(conn.ssl())
                        && self.negotiated.as_ref() != Some(&neg)
                    {
                        info!("EAP-TLS ServerHello: {} {}", neg.version, neg.cipher);
                        self.negotiated = Some(neg);
                    }
                    let leftover = conn.get_ref().inbox.len();
                    debug!("EAP-TLS handshake in progress; waiting for the next server flight ({leftover} bytes buffered)");
                }
                Err(e) => return Err(handshake_error(conn.ssl(), e)),
            }
        } else {
            let mut sink = [0u8; 256];
            loop {
                match conn.ssl_read(&mut sink) {
                    Ok(0) => break,
                    Ok(n) => debug!(
                        "EAP-TLS: {n} bytes of TLS application data after the handshake ignored \
                         (EAP-TLS carries none; RFC 9190 commitment message)"
                    ),
                    Err(e) if e.code() == ErrorCode::WANT_READ => break,
                    Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                        debug!("EAP-TLS: server sent close_notify after the handshake");
                        break;
                    }
                    Err(e) => return Err(handshake_error(conn.ssl(), e)),
                }
            }
        }
        Ok(())
    }

    /// Collect every record OpenSSL wrote since the last call.
    fn take_outbox(&mut self) -> Vec<u8> {
        self.conn.as_mut().map(|c| std::mem::take(&mut c.get_mut().outbox)).unwrap_or_default()
    }
}

fn tls_err(e: ErrorStack) -> Error {
    Error::Tls(e.to_string())
}

/// Map a failed `connect()`/`ssl_read()` to [`Error::Tls`], adding the X.509 verification
/// result when the server certificate was the problem.
fn handshake_error(ssl: &SslRef, e: openssl::ssl::Error) -> Error {
    let mut msg = format!("handshake failed: {e}");
    let vr = ssl.verify_result();
    if vr != X509VerifyResult::OK {
        msg.push_str(&format!(" (server certificate verification: {})", vr.error_string()));
    }
    if msg.contains("handshake failure") {
        msg.push_str(" (the server rejected every offered cipher suite / protocol version)");
    }
    Error::Tls(msg)
}

/// `(MSK, EMSK)`, 64 bytes each.
type KeyMaterial = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn derive_key_material(ssl: &SslRef, tls13: bool) -> Result<KeyMaterial> {
    let (label, context): (&str, Option<&[u8]>) = if tls13 {
        ("EXPORTER_EAP_TLS_Key_Material", Some(&[0x0D]))
    } else {
        ("client EAP encryption", None)
    };
    let mut km = Zeroizing::new([0u8; KEY_MATERIAL_LEN]);
    ssl.export_keying_material(&mut km[..], label, context)
        .map_err(|e| Error::Tls(format!("TLS exporter failed: {e}")))?;
    let msk = Zeroizing::new(km[..MSK_LEN].to_vec());
    let emsk = Zeroizing::new(km[MSK_LEN..].to_vec());
    Ok((msk, emsk))
}

fn parse_certs(pem: &str, what: &str) -> Result<Vec<X509>> {
    let certs = X509::stack_from_pem(pem.as_bytes())
        .map_err(|e| Error::config(format!("{what}: invalid certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(Error::config(format!("{what}: no certificate found in PEM")));
    }
    Ok(certs)
}

/// The per-session OpenSSL context (`docs/DESIGN.md` §9.3): TLS 1.2 only unless
/// `allow_tls13`, trust-all or the PEM CA bundle, client leaf + key, [`CIPHER_LIST`].
fn build_context(cfg: &EapTlsConfig) -> Result<SslContext> {
    let mut b = SslContext::builder(SslMethod::tls_client()).map_err(tls_err)?;
    b.set_options(SslOptions::NO_COMPRESSION);
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).map_err(tls_err)?;
    let max = if cfg.allow_tls13 { SslVersion::TLS1_3 } else { SslVersion::TLS1_2 };
    b.set_max_proto_version(Some(max)).map_err(tls_err)?;
    b.set_cipher_list(CIPHER_LIST).map_err(tls_err)?;

    if cfg.validate_server {
        let ca_pem = cfg.server_ca_pem.as_deref().ok_or_else(|| {
            Error::config("validate_server_cert is set but no server CA PEM was provided (no system trust store)")
        })?;
        let anchors = parse_certs(ca_pem, "server CA")?;
        let count = anchors.len();
        for cert in anchors {
            b.cert_store_mut()
                .add_cert(cert)
                .map_err(|e| Error::config(format!("server CA: cannot add trust anchor: {e}")))?;
        }
        b.set_verify(SslVerifyMode::PEER);
        info!(
            "EAP-TLS: validating server certificate against {count} trust anchor(s); hostname check {}",
            match cfg.server_name.as_deref() {
                Some(n) if !n.is_empty() => format!("against {n:?}"),
                _ => "off (no server_name configured)".into(),
            }
        );
    } else {
        warn!("EAP-TLS: server certificate validation DISABLED (trust-all, as configured)");
        b.set_verify(SslVerifyMode::NONE);
    }

    let mut certs = parse_certs(&cfg.client_cert_pem, "client certificate")?;
    if certs.len() > 1 {
        debug!("EAP-TLS: client PEM has {} certificates; sending the leaf only", certs.len());
        certs.truncate(1);
    }
    let key = PKey::private_key_from_pem(cfg.client_key_pem.as_bytes())
        .map_err(|e| Error::config(format!("client key: invalid PEM: {e}")))?;
    b.set_certificate(&certs[0])
        .map_err(|e| Error::config(format!("client certificate: {e}")))?;
    b.set_private_key(&key)
        .map_err(|e| Error::config(format!("client key: {e}")))?;
    b.check_private_key()
        .map_err(|e| Error::config(format!("client certificate and key do not match: {e}")))?;
    Ok(b.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ssl::SslContextBuilder;

    const CLIENT_CERT_PEM: &str = include_str!("../../tests/fixtures/client.crt");
    const CLIENT_KEY_PEM: &str = include_str!("../../tests/fixtures/client.key");

    // Static RSA-2048 test PKI (valid until 2126), generated once with the openssl CLI. RSA
    // (not EC) so the server can do RSA key exchange, i.e. TLS_RSA_WITH_AES_128_CBC_SHA:
    //   openssl req -x509 -newkey rsa:2048 -nodes -days 36500 -subj "/CN=epdg-test-rsa-ca" \
    //     -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    //     -keyout ca.key -out ca.crt
    //   openssl req -new -newkey rsa:2048 -nodes -subj "/CN=epdg-test-rsa-server" -keyout server.key -out server.csr
    //   openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 36500 \
    //     -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n\
    //                        keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n") -out server.crt
    //   openssl req -new -newkey rsa:2048 -nodes -subj "/CN=epdg-test-rsa-client" -keyout client.key -out client.csr
    //   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 36500 \
    //     -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n") -out client.crt
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIUZSVBwyJCcwRWPIEljjP8QcRIJSMwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZXBkZy10ZXN0LXJzYS1jYTAgFw0yNjA5MTEwODAzNDRa
GA8yMTI2MDgxODA4MDM0NFowGzEZMBcGA1UEAwwQZXBkZy10ZXN0LXJzYS1jYTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMxP/R4vWKCWSF/3CMkJBv8N
uEWRuIpdVxxNI8r0VzcVOP+SUpZYimWM0lxVX+tV1/V0CQe+ORwQHs4KUA3IQtAF
LZ9O9pFz+7mHEbMUkFtyIAemNJdZdGzeuuUR/vBYtEzlVS4JZnLFD5SkUYt9H0ML
68bdMuaCEFr31OZriNQoDhJ2zmajAvgVqQyIQymIkSYGlRkQVgYDYTZUNptly261
pLCoTLUTW+5+fGTS7L+94wgXLUQkXr1KM4qyIHLFJtsTY6EJYQVMrKwao+ELteW2
knxK+djzkToYPnI128ROvTrQ6cSbwx4aWzUaBl+SSMWqliGhy9cx51UXlA7xE0kC
AwEAAaNjMGEwHQYDVR0OBBYEFHBLs5dKZbngI8VmdYvicY/Q8dLEMB8GA1UdIwQY
MBaAFHBLs5dKZbngI8VmdYvicY/Q8dLEMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBGuHtflINDcjjsKIAoblmX380I
EaWQWfvkMvOiiOqmzB/niTq0EYeD6hmqeNmae8PTQ/mh4oHtHBQyTIiZWTDw3ALK
p80uZzBg1o6at564f7FfxW/NMOLLQZI8yT0Mqx0Jd994YHIY9bQVigBvVQBIABno
hLYHBFACa/0STr2AWMOS22A7Hc8YN00riDSuHnX5lQdzrjfAayt8FjvnfPGGRNmr
M6OYy3eX22l2eTjmp4z6Fye7JP7Geo1NNjm4EnrQEHKhmp9q9XiudT0+bhdJXB6D
fOW14rrIi7moFkbmTTjH2kEnTGqk7BmO3D8xfNyANzPAq4ZBSIO+TvnQcOl1
-----END CERTIFICATE-----
";
    const SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDVzCCAj+gAwIBAgIUT3aewf+r0D//Nkhlh32glXDVbAYwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZXBkZy10ZXN0LXJzYS1jYTAgFw0yNjA5MTEwODAzNDRa
GA8yMTI2MDgxODA4MDM0NFowHzEdMBsGA1UEAwwUZXBkZy10ZXN0LXJzYS1zZXJ2
ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQdTtkh4i2oLT/WBoS
ZIfQs9/7T1p2q0gxFY3XWyIEF2OI3DUbv4JTC30YIhnnO7kXgct4ccTnzKpl4CF1
uwICyFBoOlDWHp3Q576muW6/DKwrrGu7qJye8N/4r9/PVVTMoonGDNBPpMhEyU/A
X9CV7GzhW//PLrOeMiy1WuxzMbd+20j3+cpHmZVP5+An5Dg+k7ogi8GfX2zV12oT
0eK2brmN01xG7Cm9tUKBulC5PTp+uxe2wPuQE8DE0xb2XTZUIwXcEUBDQIsZ3Mff
5JMPYUHfMXzDIDAEEueW7B0QwcV4lBsA/FZi3L4uPXMMGG0Rn7ANslwCwWwSZNOD
AOQzAgMBAAGjgYwwgYkwGgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0MAkGA1Ud
EwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQW
BBQG11OPtJQWpULP6B5fb02fZJ7JoTAfBgNVHSMEGDAWgBRwS7OXSmW54CPFZnWL
4nGP0PHSxDANBgkqhkiG9w0BAQsFAAOCAQEALNXAIckdvU9Ck8owUTQRcBx9iMOF
HEWtRd2SPTjWM/xpmXojHmENyFLZfXOFxEvkvNT8TCNXVDU+qo0Xf4joUMyAlcMY
gBJucTMtVxHe6HVHwUcsJNr1+8LKGr40yMs+JQpFoyTXz+WF1IHqxKfk6P2Sq+fv
vXgeJSFRWJsiGIIV6H4J7yOeN1At5AElHsToFFd+zs4G1g/ZDyr2mKI03kmprWOp
9tBRWf5D0VpkR1KNRXyPl2nYq17ULqvsEC1JMW8LG/lkp2E5YLx6A8qL8BcMRQ/A
rexvNdpEeE6VFvwWo6HTTYcCUZMOGTqgj0scfLoOkWYcxNBIbHmRmTl47w==
-----END CERTIFICATE-----
";
    const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDQdTtkh4i2oLT/
WBoSZIfQs9/7T1p2q0gxFY3XWyIEF2OI3DUbv4JTC30YIhnnO7kXgct4ccTnzKpl
4CF1uwICyFBoOlDWHp3Q576muW6/DKwrrGu7qJye8N/4r9/PVVTMoonGDNBPpMhE
yU/AX9CV7GzhW//PLrOeMiy1WuxzMbd+20j3+cpHmZVP5+An5Dg+k7ogi8GfX2zV
12oT0eK2brmN01xG7Cm9tUKBulC5PTp+uxe2wPuQE8DE0xb2XTZUIwXcEUBDQIsZ
3Mff5JMPYUHfMXzDIDAEEueW7B0QwcV4lBsA/FZi3L4uPXMMGG0Rn7ANslwCwWwS
ZNODAOQzAgMBAAECggEABEafiQTOKW/Jqt0tlgtdYYDH4sVhh3iDKfh6cw8fn4Zw
qTPuSw20gblqNZpiutijUdslG7MtS7hwnFePuqrHTyzu9o7ggflWAfSjmQxd/5If
UQVIMxHg4qnW4uU9EHa/wNU7hLVjruaJQuPx6C65DwjyOnuVidXnUmYmLgqqirNE
r9byy4wWf6/OyY883AtK/I9EijV5F7jqQYxlq/UEcW9NpIPcLULCRXHp4Lp5B6XD
ywE9XQNdxcVdYrJjitiAz4/RPVwRSynhF2pd1guQqAJPQWIxeDGNlMi16H1HnrR4
7fDEmYT7jbfUkYUadhRLxuIX428pTV2oxPA+BdEosQKBgQD24cPlZ7N1TiUNdxsL
a7NRL0rfS5CKWsoJ1h5EaTW9R/SoOkt9JMxDGY0asPsjI4KfDuuQzsczFX3206Wm
L2BcIMtRtmt/5xmLDvIwhQ618JrKKyyGLqZFdT6AppX/OCVNdgk670IHQrZNdIYI
+QQvk0bVK9yq2VLmfcKZ1rNaMQKBgQDYKCxpTrooalmVgNgoQecRah0kGUzLhkrP
drYF7n6An8CrV76vd2bWQpQpN3W7LPLRIhtcPZkF0WRzjEehQ3an7F7+OkvYyrjg
A3E4mFWwBKCCt3eO2C05Se6Lmse5tdBsBisS3ufvOSoURxOse0iG6tMblv0/XJNv
e0YG5+EnowKBgHr6v2CZJbX7dU2d1ST9Q1ffnQZaV+fzjc0UkgM1/YUKQP9D+rKe
D/ok0jtHifJZEAo3nnSF7Iiv3g2EJHICC5gY5e8QVcBi2ECC83Xj8g4DirfGhelZ
d44F91qSoQl/aGWLtNFcuaFwQ+uVbecuVD12ucQak1Ov6jHS14tWfgUhAoGAIjZx
mRVp5521ojErhWuw7BO0mxMaEZim3KF4fAXcpfUjJLuVpeYrM7yEAOYTT1X09N8G
H5psTvxufs90QvUPodKK0ohdmumzS1mgIQoTffGtiiMJ3GUg+1FVXWlZNW6ul3p+
dNUtNrMAkwcQ+RrmRtyCH3rNiKrZdyq20b7/5ysCgYBnaQSiv75b0rrVtfy7Ujeb
0gBSPBO+Xk/6SXgaFsyl1pyjvc8v05DEz5MvJTf2IsIik2TlPsv54WQ1thkL2dDy
aQu35Pa8sADwOPzP+Fwr+S75P5RllsiU6+bykOYj4JCrM8gZwEVBTJj+qoKnQ42+
dKsS9b3yOHiDI15KZMkicQ==
-----END PRIVATE KEY-----
";
    const TEST_CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIUT3aewf+r0D//Nkhlh32glXDVbAcwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZXBkZy10ZXN0LXJzYS1jYTAgFw0yNjA5MTEwODAzNDRa
GA8yMTI2MDgxODA4MDM0NFowHzEdMBsGA1UEAwwUZXBkZy10ZXN0LXJzYS1jbGll
bnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9z7+IfdLvv96zy/6B
LglhIyDxXU/OoDy3YI2bwoyYoa7S+d6sLJktqusiXh2UjHKE+OFK6HOmZ6b44H+J
Z1R7gQpUVFdTIepsiAxfiim+tFVR90Z+ol5rznCVECFEObpjQsaM6HbBDgHfocNy
6Lx643hnLuX9dmYiZo3/jB8ilpcv6daRdjyznODdhNJgU76jhLIEJcy1jAluPC5R
/IhCE5HgQOwuIDNzlfMY91OB1cHZHG91HbMDDRZCOnVTYWmNLIHjyVLPyLOUXgP8
e7puc9pOxUwa+CBFuQamj8t3pYqzEou3c/bhOvzzVFsxE420slAGUvc+vBRbqbWE
jcovAgMBAAGjbzBtMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoG
CCsGAQUFBwMCMB0GA1UdDgQWBBTtUEkGk9UcPJo9690KaGkbuDoYszAfBgNVHSME
GDAWgBRwS7OXSmW54CPFZnWL4nGP0PHSxDANBgkqhkiG9w0BAQsFAAOCAQEAbSRR
Dy0IwwAx9ttP/uTH0KqP89crXOWHJFzK1QpqlstLkTDekeHiHPZhTrtHpMHCkT3h
/fIKG8UFR1Jb7jY0cEaOlAyp513l/Wpl9Qd4DD+/LlBqF+KSnAP2DFhqcj970/du
RYQW0khntmoCtEnlarfGUaXBAJrxOOMpFzEKfZvKKVfY/Avplymr0Ebm8mHZoaoX
dKzQDwMJFXPnTM/TxntZ9ujdWZQOEWJJSUqkFItpLUIxTVV68TuETOACGFXHhmci
AOANxn8iqw7rRXj6IGGjJzGkqUZdxOyMUQgbHKpMheu63im6n+rXTQXDBUp8nA5m
dhZ2H73yh2pGbiVGCw==
-----END CERTIFICATE-----
";
    const TEST_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9z7+IfdLvv96z
y/6BLglhIyDxXU/OoDy3YI2bwoyYoa7S+d6sLJktqusiXh2UjHKE+OFK6HOmZ6b4
4H+JZ1R7gQpUVFdTIepsiAxfiim+tFVR90Z+ol5rznCVECFEObpjQsaM6HbBDgHf
ocNy6Lx643hnLuX9dmYiZo3/jB8ilpcv6daRdjyznODdhNJgU76jhLIEJcy1jAlu
PC5R/IhCE5HgQOwuIDNzlfMY91OB1cHZHG91HbMDDRZCOnVTYWmNLIHjyVLPyLOU
XgP8e7puc9pOxUwa+CBFuQamj8t3pYqzEou3c/bhOvzzVFsxE420slAGUvc+vBRb
qbWEjcovAgMBAAECggEAJIF6wGkWsyavUdw3kCfHBQgpE1LTgRV/Z/NpeN4ThV1/
TrNg+LNBKK/ZNkxsmv/iHKHzTqFjcMs5qV8gGFCnxnMchfiMrP/2YrZNzug3PCbZ
zABnbf6Tc1+KdpjaFRGXP/T9U+d3w4yKnrSxbv3FFkt+gjXaZQOrBA2+XLpZ2KBS
G1DR8Th7C0W8qSj7NMtdJ/FAtQvxDhKskT0WxoiS03jI3v1B3ZdsybRK4k3mws3C
TK8WcP5iS+67W/5KSe1QpZv7xxibDPGJQAc5UR2l2v9gNNFggBrZk/a0JoLN/bd/
+UA+R49mFy3gP+IiLGjfglLoSARTUoA0GHrxOmPDcQKBgQDdytiA1clb8tH4V8iV
UwUHr7h1EyszqsNRN83ON6mm2duUZ6fVvTpSv8a1965CZEyo9wt8UOz5T8Q21nQC
arpvpRKdmNYd3MU6uTGC7HdpbUhHi76CfI8816e3sBboJVHaI6H8b/lr7R5txeap
UHTh5XXHqMGSCr9nLTiUMe/9PwKBgQDbFi8yIOSNkUgFQNcXXvaW9SFGGvUCrNrX
9ZE80k6MEAzDVnQ1D8yS3GM/ZIQ9Q/4U9uBVsesjAJhKNR4NHBDAEJELPGkIlKPz
ArVL6fyZYIWdTIPHwCh9vZOLms2SQ1vE778MQH0Ef5ezlqCpgjzB3MZgO+wDOFKd
/uzoD77HEQKBgFSFa9JVJmIq/Adm9KKrO5x9Q48iGfGbnslBueVfYwCZv0sj4Vrb
vPEx8jkARWE5tdkiJDdg453y3vSC7zzIjXnkb16tktNYgbTqREr/cFY19jiFsbkq
XK+0A09GBMS9DB9UOvPnfCa7+z+cDlXxukkn16WZ0wKjo+Ne4VPgX/OjAoGBAJD9
gYZ/VkKKX0t6ud5xrmgBGmA2/uciVkKN9ex2kh0HkirEUGu9ZPnceKI/d3TERqbB
K34LHT4w6phRxu2OIVe6nwL8m9Zd6JKuvCTdWZp30nVjaeMMPL/acob1kA64HUec
EqedFh+gAVmM2g7UbjkuTurpPSx0XdjKGScLJIrBAoGARg8tFUY8hoz3CO2z4sIm
QxF+eM0Uh3ayaWES3piBELHxK4RhcsbrNrHQg5l43MazhuH+hKsrYa7zb5mhx2uP
faUa5/97UXdp+Q369a+DnlvFGBpNFdwq3aKUEjdMUF5JFQw+Z1EPC6+6yA9q0V2l
7NO/0MPv/XB0H9mUDhmZwpQ=
-----END PRIVATE KEY-----
";

    const IDENTITY: &[u8] = b"900999990302421609@prodepdg.t-mobile.com";

    /// The only suite the T-Mobile ePDG negotiates: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F).
    const TMOBILE_SUITE: &str = "AES128-SHA";
    const TMOBILE_SUITE_ID: u16 = 0x002F;
    const MODERN_SUITE: &str = "ECDHE-RSA-AES128-GCM-SHA256";

    fn client_cfg(validate: bool, tls13: bool) -> EapTlsConfig {
        EapTlsConfig {
            identity: IDENTITY.to_vec(),
            client_cert_pem: TEST_CLIENT_CERT_PEM.to_string(),
            client_key_pem: TEST_CLIENT_KEY_PEM.to_string(),
            validate_server: validate,
            server_ca_pem: if validate { Some(TEST_CA_PEM.to_string()) } else { None },
            server_name: None,
            max_fragment_len: 1024,
            allow_tls13: tls13,
        }
    }

    /// The real credential fixtures (issuer CA unknown to us).
    fn fixture_client_cfg() -> EapTlsConfig {
        EapTlsConfig { client_cert_pem: CLIENT_CERT_PEM.to_string(), client_key_pem: CLIENT_KEY_PEM.to_string(), ..client_cfg(false, false) }
    }

    fn request(id: u8, eap_type: u8, type_data: Vec<u8>) -> EapPacket {
        EapPacket { code: EAP_CODE_REQUEST, identifier: id, eap_type: Some(eap_type), type_data }
    }

    fn tls_request(id: u8, td: &EapTlsData) -> EapPacket {
        request(id, EAP_TYPE_TLS, td.encode())
    }

    fn start_request(id: u8) -> EapPacket {
        request(id, EAP_TYPE_TLS, vec![EAP_TLS_FLAG_S])
    }

    fn expect_send(action: EapAction) -> EapPacket {
        match action {
            EapAction::Send(p) => p,
            other => panic!("expected Send, got {other:?}"),
        }
    }

    /// Cipher suite ids offered by a ClientHello record (`16 03 01 len | 01 len3 | version(2)
    /// random(32) session_id<1..> cipher_suites<2..> ...`).
    fn client_hello_suites(record: &[u8]) -> Vec<u16> {
        assert_eq!(record[0], 0x16, "handshake record");
        assert_eq!(record[5], 0x01, "ClientHello");
        let body = &record[9..];
        let mut p = 2 + 32;
        p += 1 + body[p] as usize;
        let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        body[p..p + n].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
    }

    // ---- type-data codec ---------------------------------------------------------------

    #[test]
    fn type_data_encode_decode_flags_and_length() {
        let start = EapTlsData::decode(&[0x20]).unwrap();
        assert!(start.has_s() && !start.has_l() && !start.has_m() && !start.is_ack());
        assert_eq!(start.encode(), [0x20]);

        let ack = EapTlsData::decode(&[0x00]).unwrap();
        assert!(ack.is_ack());
        assert_eq!(EapTlsData::ack().encode(), [0x00]);
        // version bits are ignored for ack detection
        assert!(EapTlsData::decode(&[0x03]).unwrap().is_ack());

        let with_len = EapTlsData::decode(&[0xC0, 0x00, 0x00, 0x10, 0x00, 1, 2, 3]).unwrap();
        assert!(with_len.has_l() && with_len.has_m());
        assert_eq!(with_len.length, Some(0x1000));
        assert_eq!(with_len.data, [1, 2, 3]);
        assert_eq!(with_len.encode(), [0xC0, 0x00, 0x00, 0x10, 0x00, 1, 2, 3]);

        // encode sets L iff length is present, regardless of the flags byte
        let e = EapTlsData { flags: 0, length: Some(5), data: vec![9; 5] };
        assert_eq!(e.encode(), [0x80, 0, 0, 0, 5, 9, 9, 9, 9, 9]);
        let e = EapTlsData { flags: EAP_TLS_FLAG_L | EAP_TLS_FLAG_M, length: None, data: vec![7] };
        assert_eq!(e.encode(), [0x40, 7]);

        let no_len = EapTlsData::decode(&[0x40, 0xAA, 0xBB]).unwrap();
        assert_eq!(no_len.length, None);
        assert_eq!(no_len.data, [0xAA, 0xBB]);
    }

    #[test]
    fn type_data_decode_errors_and_tolerances() {
        assert!(matches!(EapTlsData::decode(&[]), Err(Error::Decode(_))));
        assert!(matches!(EapTlsData::decode(&[0x80, 0, 0]), Err(Error::Decode(_))));
        // M clear, L set, data longer than declared -> error
        assert!(matches!(EapTlsData::decode(&[0x80, 0, 0, 0, 2, 1, 2, 3]), Err(Error::Decode(_))));
        // shorter than declared is accepted
        let short = EapTlsData::decode(&[0x80, 0, 0, 0, 9, 1, 2]).unwrap();
        assert_eq!(short.length, Some(9));
        assert_eq!(short.data, [1, 2]);
        // with M set the check does not apply
        let m = EapTlsData::decode(&[0xC0, 0, 0, 0, 2, 1, 2, 3]).unwrap();
        assert_eq!(m.data.len(), 3);
    }

    // ---- outbound fragmentation ------------------------------------------------------

    fn client_with_tx(tx: Vec<u8>) -> EapTlsClient {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        c.state = State::Handshake;
        c.tx = tx;
        c.tx_offset = 0;
        c
    }

    #[test]
    fn outbound_fragmentation_2500_bytes() {
        let msg: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
        let mut c = client_with_tx(msg.clone());

        let f1 = expect_send(c.send_next_fragment(10).unwrap());
        assert_eq!((f1.code, f1.identifier, f1.eap_type), (2, 10, Some(13)));
        let td1 = EapTlsData::decode(&f1.type_data).unwrap();
        assert!(td1.has_l() && td1.has_m() && !td1.has_s());
        assert_eq!(td1.length, Some(2500));
        assert_eq!(td1.data, &msg[..1024]);
        assert_eq!(&f1.type_data[..5], &[0xC0, 0x00, 0x00, 0x09, 0xC4]);

        // continuation only on server ACK
        let f2 = expect_send(c.handle(&tls_request(11, &EapTlsData::ack())).unwrap());
        assert_eq!(f2.identifier, 11);
        let td2 = EapTlsData::decode(&f2.type_data).unwrap();
        assert!(!td2.has_l() && td2.has_m());
        assert_eq!(td2.length, None);
        assert_eq!(td2.data, &msg[1024..2048]);
        assert_eq!(f2.type_data[0], 0x40);

        let f3 = expect_send(c.handle(&tls_request(12, &EapTlsData::ack())).unwrap());
        let td3 = EapTlsData::decode(&f3.type_data).unwrap();
        assert!(!td3.has_l() && !td3.has_m());
        assert_eq!(td3.data.len(), 452);
        assert_eq!(td3.data, &msg[2048..]);
        assert_eq!(f3.type_data[0], 0x00);

        // nothing left: a further ACK is an error
        assert!(matches!(c.handle(&tls_request(13, &EapTlsData::ack())), Err(Error::Eap(_))));
    }

    #[test]
    fn unfragmented_message_carries_l() {
        let msg = vec![0x16u8; 300];
        let mut c = client_with_tx(msg.clone());
        let f = expect_send(c.send_next_fragment(1).unwrap());
        let td = EapTlsData::decode(&f.type_data).unwrap();
        assert!(td.has_l() && !td.has_m());
        assert_eq!(td.length, Some(300));
        assert_eq!(td.data, msg);
        assert_eq!(f.encode().len(), 4 + 1 + 5 + 300);
    }

    #[test]
    fn exact_multiple_fragmentation() {
        let msg = vec![1u8; 2048];
        let mut c = client_with_tx(msg);
        let f1 = expect_send(c.send_next_fragment(1).unwrap());
        assert!(EapTlsData::decode(&f1.type_data).unwrap().has_m());
        let f2 = expect_send(c.handle(&tls_request(2, &EapTlsData::ack())).unwrap());
        let td2 = EapTlsData::decode(&f2.type_data).unwrap();
        assert!(!td2.has_m() && !td2.has_l());
        assert_eq!(td2.data.len(), 1024);
    }

    #[test]
    fn data_while_fragments_pending_is_error() {
        let mut c = client_with_tx(vec![0u8; 3000]);
        let _ = expect_send(c.send_next_fragment(1).unwrap());
        let data = EapTlsData { flags: 0, length: Some(3), data: vec![1, 2, 3] };
        assert!(matches!(c.handle(&tls_request(2, &data)), Err(Error::Eap(_))));
    }

    // ---- inbound reassembly ----------------------------------------------------------

    #[test]
    fn inbound_reassembly_with_l_on_first_fragment() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let total: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();

        let f1 = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(1500), data: total[..700].to_vec() };
        assert_eq!(c.reassemble(f1).unwrap(), None);
        // repeated L with the same total is tolerated (T-Mobile does this)
        let f2 = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(1500), data: total[700..1400].to_vec() };
        assert_eq!(c.reassemble(f2).unwrap(), None);
        let f3 = EapTlsData { flags: 0, length: None, data: total[1400..].to_vec() };
        assert_eq!(c.reassemble(f3).unwrap(), Some(total.clone()));
        assert!(c.rx.is_none());

        // unfragmented with L
        let u = EapTlsData { flags: 0, length: Some(3), data: vec![1, 2, 3] };
        assert_eq!(c.reassemble(u).unwrap(), Some(vec![1, 2, 3]));
        // unfragmented without L
        let u = EapTlsData { flags: 0, length: None, data: vec![4, 5] };
        assert_eq!(c.reassemble(u).unwrap(), Some(vec![4, 5]));
    }

    #[test]
    fn inbound_reassembly_errors() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        // first fragment with M but no L
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: None, data: vec![1, 2] };
        assert!(matches!(c.reassemble(f), Err(Error::Eap(_))));
        assert!(c.rx.is_none());

        // more data than declared on the first fragment
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(1), data: vec![1, 2] };
        assert!(matches!(c.reassemble(f), Err(Error::Eap(_))));

        // total length changes mid-stream
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(10), data: vec![1, 2] };
        assert_eq!(c.reassemble(f).unwrap(), None);
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(11), data: vec![3] };
        assert!(matches!(c.reassemble(f), Err(Error::Eap(_))));

        // overflow of the declared capacity
        c.rx = None;
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(4), data: vec![1, 2] };
        assert_eq!(c.reassemble(f).unwrap(), None);
        let f = EapTlsData { flags: 0, length: None, data: vec![3, 4, 5] };
        assert!(matches!(c.reassemble(f), Err(Error::Eap(_))));
    }

    #[test]
    fn inbound_declared_length_above_cap_is_rejected_without_allocating() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        // A hostile first fragment declaring a 4 GiB flight must be rejected up front
        // (the M=0 fragment would otherwise zero-fill the whole declared size).
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(u32::MAX), data: vec![0x16; 5] };
        assert!(matches!(c.reassemble(f), Err(Error::Eap(_))));
        assert!(c.rx.is_none(), "no reassembly buffer is kept for a rejected length");
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some((MAX_INBOUND_TLS_FLIGHT + 1) as u32), data: vec![1] };
        assert!(matches!(c.reassemble(f), Err(Error::Eap(_))));
        // Exactly the cap is still accepted (and under-delivery zero-pads to it).
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(MAX_INBOUND_TLS_FLIGHT as u32), data: vec![1] };
        assert_eq!(c.reassemble(f).unwrap(), None);
        let f = EapTlsData { flags: 0, length: None, data: vec![2] };
        let out = c.reassemble(f).unwrap().unwrap();
        assert_eq!(out.len(), MAX_INBOUND_TLS_FLIGHT);
        assert_eq!(&out[..2], &[1, 2]);
    }

    #[test]
    fn inbound_under_delivery_is_zero_padded() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let f = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(4), data: vec![1, 2] };
        assert_eq!(c.reassemble(f).unwrap(), None);
        let f = EapTlsData { flags: 0, length: None, data: vec![3] };
        assert_eq!(c.reassemble(f).unwrap(), Some(vec![1, 2, 3, 0]));
    }

    #[test]
    fn ack_bytes_for_server_fragment() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        // Start the handshake so we are in Handshake state with nothing pending.
        let hello = expect_send(c.handle(&start_request(1)).unwrap());
        assert_eq!(hello.identifier, 1);
        // The ClientHello is a single fragment (well under 1024 bytes).
        assert!(!EapTlsData::decode(&hello.type_data).unwrap().has_m());

        let frag = EapTlsData { flags: EAP_TLS_FLAG_M, length: Some(4000), data: vec![0x16; 1000] };
        let ack = expect_send(c.handle(&tls_request(0x2B, &frag)).unwrap());
        assert_eq!(ack.encode(), [0x02, 0x2B, 0x00, 0x06, 0x0d, 0x00]);
    }

    // ---- top-level EAP behaviour -----------------------------------------------------

    #[test]
    fn identity_nak_notification_and_failure_handling() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let r = expect_send(c.handle(&request(5, EAP_TYPE_IDENTITY, b"prompt".to_vec())).unwrap());
        assert_eq!(r, EapPacket::identity_response(5, IDENTITY));
        // repeated identity request is fine before the method starts
        let r = expect_send(c.handle(&request(6, EAP_TYPE_IDENTITY, vec![])).unwrap());
        assert_eq!(r.identifier, 6);
        // unknown method -> Nak listing only EAP-TLS
        let r = expect_send(c.handle(&request(7, EAP_TYPE_AKA, vec![1, 2])).unwrap());
        assert_eq!(r.encode(), [0x02, 0x07, 0x00, 0x06, 0x03, 0x0d]);
        // notification
        let r = expect_send(c.handle(&request(8, EAP_TYPE_NOTIFICATION, b"hi".to_vec())).unwrap());
        assert_eq!(r.encode(), [0x02, 0x08, 0x00, 0x05, 0x02]);
        // a Response from the peer is an error
        assert!(matches!(c.handle(&EapPacket::response(9, 1, vec![])), Err(Error::Eap(_))));
        // Nak request is an error
        assert!(matches!(c.handle(&request(9, EAP_TYPE_NAK, vec![])), Err(Error::Eap(_))));
        // Success before the method even started -> fatal Failure
        let s = EapPacket { code: EAP_CODE_SUCCESS, identifier: 9, eap_type: None, type_data: vec![] };
        assert!(matches!(c.handle(&s).unwrap(), EapAction::Failure(_)));
        assert!(c.msk().is_none());
    }

    #[test]
    fn eap_failure_is_failure() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let f = EapPacket { code: EAP_CODE_FAILURE, identifier: 1, eap_type: None, type_data: vec![] };
        assert!(matches!(c.handle(&f).unwrap(), EapAction::Failure(_)));
    }

    #[test]
    fn first_tls_request_must_have_start_bit() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        assert!(matches!(c.handle(&tls_request(1, &EapTlsData::ack())), Err(Error::Eap(_))));
    }

    #[test]
    fn start_produces_client_hello_and_success_before_completion_is_fatal() {
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let hello = expect_send(c.handle(&start_request(0x42)).unwrap());
        assert_eq!((hello.code, hello.identifier, hello.eap_type), (2, 0x42, Some(13)));
        let td = EapTlsData::decode(&hello.type_data).unwrap();
        assert!(td.has_l() && !td.has_m() && !td.has_s());
        assert_eq!(td.length, Some(td.data.len() as u32));
        // TLS record header: handshake(0x16), version 3.1 (ClientHello legacy record version)
        assert_eq!(td.data[0], 0x16);
        assert_eq!(td.data[1], 0x03);
        // ...ClientHello handshake type
        assert_eq!(td.data[5], 0x01);
        assert!(c.protocol_version().is_none(), "nothing negotiated yet");

        // second Start is an error
        assert!(matches!(c.handle(&start_request(0x43)), Err(Error::Eap(_))));
        // Identity request after method start is an error
        assert!(matches!(c.handle(&request(0x43, EAP_TYPE_IDENTITY, vec![])), Err(Error::Eap(_))));
        // foreign type after method start is an error (no Nak)
        assert!(matches!(c.handle(&request(0x43, EAP_TYPE_AKA, vec![])), Err(Error::Eap(_))));
        // EAP-Success during the handshake is fatal
        let s = EapPacket { code: EAP_CODE_SUCCESS, identifier: 0x44, eap_type: None, type_data: vec![] };
        assert!(matches!(c.handle(&s).unwrap(), EapAction::Failure(_)));
    }

    #[test]
    fn client_hello_offers_tls_rsa_with_aes_128_cbc_sha() {
        // The live finding behind the OpenSSL switch: the T-Mobile ePDG only accepts 0x002F.
        let mut c = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let hello = expect_send(c.handle(&start_request(1)).unwrap());
        let suites = client_hello_suites(&EapTlsData::decode(&hello.type_data).unwrap().data);
        assert!(suites.contains(&TMOBILE_SUITE_ID), "ClientHello must offer 0x002F; offered {suites:04x?}");
        // ...and still leads with a modern ECDHE/AEAD suite.
        assert!(suites.iter().any(|s| matches!(s, 0xC02B | 0xC02C | 0xC02F | 0xC030)), "no ECDHE/GCM suite in {suites:04x?}");
    }

    #[test]
    fn config_errors_surface_at_new() {
        let mut cfg = client_cfg(false, false);
        cfg.client_key_pem = "garbage".into();
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let mut cfg = client_cfg(false, false);
        cfg.client_cert_pem = "".into();
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        // key that does not belong to the certificate
        let mut cfg = client_cfg(false, false);
        cfg.client_key_pem = SERVER_KEY_PEM.into();
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let mut cfg = client_cfg(true, false);
        cfg.server_ca_pem = None;
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let mut cfg = client_cfg(true, false);
        cfg.server_ca_pem = Some("not a pem".into());
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let cfg = client_cfg(true, false);
        assert!(EapTlsClient::new(cfg).is_ok());
    }

    #[test]
    fn fixture_client_credentials_load() {
        // The real tests/fixtures credentials (RSA-2048, PKCS#8 key) must build a client.
        let c = EapTlsClient::new(fixture_client_cfg()).unwrap();
        assert!(c.msk().is_none());
        // A chain PEM (leaf first) is accepted; only the leaf is used.
        let mut cfg = fixture_client_cfg();
        cfg.client_cert_pem = format!("{CLIENT_CERT_PEM}{TEST_CA_PEM}");
        assert!(EapTlsClient::new(cfg).is_ok());
    }

    #[test]
    fn pkcs1_client_key_is_accepted() {
        // Same key re-encoded as PKCS#1 ("BEGIN RSA PRIVATE KEY").
        let rsa = PKey::private_key_from_pem(TEST_CLIENT_KEY_PEM.as_bytes()).unwrap().rsa().unwrap();
        let pkcs1 = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
        assert!(pkcs1.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        let mut cfg = client_cfg(false, false);
        cfg.client_key_pem = pkcs1;
        assert!(EapTlsClient::new(cfg).is_ok());
    }

    // ---- in-process end-to-end against an OpenSSL server -----------------------------

    /// The test peer: an OpenSSL server over the same in-memory duplex, driven with
    /// `accept()` until it returns `Ok` and `ssl_read()` afterwards.
    struct TestServer {
        stream: SslStream<Duplex>,
        done: bool,
    }

    /// Server context: RSA-2048 leaf + issuer (so the Certificate flight is > 1024 bytes on the
    /// wire), client certificate required and verified against the test CA.
    fn server_builder(min: SslVersion, max: SslVersion) -> SslContextBuilder {
        let mut b = SslContext::builder(SslMethod::tls_server()).unwrap();
        b.set_min_proto_version(Some(min)).unwrap();
        b.set_max_proto_version(Some(max)).unwrap();
        b.set_certificate(&X509::from_pem(SERVER_CERT_PEM.as_bytes()).unwrap()).unwrap();
        b.set_private_key(&PKey::private_key_from_pem(SERVER_KEY_PEM.as_bytes()).unwrap()).unwrap();
        b.add_extra_chain_cert(X509::from_pem(TEST_CA_PEM.as_bytes()).unwrap()).unwrap();
        b.cert_store_mut().add_cert(X509::from_pem(TEST_CA_PEM.as_bytes()).unwrap()).unwrap();
        b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        b
    }

    /// The T-Mobile ePDG: TLS 1.2, TLS_RSA_WITH_AES_128_CBC_SHA only.
    fn tmobile_server() -> SslContext {
        let mut b = server_builder(SslVersion::TLS1_2, SslVersion::TLS1_2);
        b.set_cipher_list(&format!("{TMOBILE_SUITE}:@SECLEVEL=1")).unwrap();
        b.build()
    }

    /// A modern TLS 1.2 server: ECDHE-RSA-AES128-GCM-SHA256 only.
    fn modern_server() -> SslContext {
        let mut b = server_builder(SslVersion::TLS1_2, SslVersion::TLS1_2);
        b.set_cipher_list(MODERN_SUITE).unwrap();
        b.build()
    }

    fn tls13_server() -> SslContext {
        server_builder(SslVersion::TLS1_3, SslVersion::TLS1_3).build()
    }

    /// T-Mobile suite, but accepts any client certificate (we do not have the issuer CA of the
    /// real fixture credentials); a certificate is still required and OpenSSL still checks
    /// the CertificateVerify signature against it.
    fn accept_any_client_server() -> SslContext {
        let mut b = server_builder(SslVersion::TLS1_2, SslVersion::TLS1_2);
        b.set_cipher_list(&format!("{TMOBILE_SUITE}:@SECLEVEL=1")).unwrap();
        b.set_verify_callback(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT, |_preverified, _ctx| true);
        b.build()
    }

    impl TestServer {
        fn new(ctx: &SslContext) -> TestServer {
            let ssl = Ssl::new(ctx).unwrap();
            TestServer { stream: SslStream::new(ssl, Duplex::default()).unwrap(), done: false }
        }

        /// Feed one complete client flight and step the server. Returns the server's verdict
        /// and whatever it wants to send (the reply flight, or an alert on error).
        fn step(&mut self, data: &[u8]) -> (std::result::Result<(), String>, Vec<u8>) {
            self.stream.get_mut().inbox.extend(data);
            let verdict = if !self.done {
                match self.stream.accept() {
                    Ok(()) => {
                        self.done = true;
                        Ok(())
                    }
                    Err(e) if e.code() == ErrorCode::WANT_READ => Ok(()),
                    Err(e) => Err(format!("server TLS error: {e} (verify: {})", self.stream.ssl().verify_result().error_string())),
                }
            } else {
                let mut sink = [0u8; 64];
                loop {
                    match self.stream.ssl_read(&mut sink) {
                        Ok(0) => break Ok(()),
                        Ok(_) => {}
                        Err(e) if e.code() == ErrorCode::WANT_READ => break Ok(()),
                        Err(e) => break Err(format!("server post-handshake TLS error: {e}")),
                    }
                }
            };
            (verdict, std::mem::take(&mut self.stream.get_mut().outbox))
        }

        /// [`Self::step`] for the happy path: panics on a server error, returns the reply flight.
        fn feed(&mut self, data: &[u8]) -> Vec<u8> {
            let (verdict, out) = self.step(data);
            verdict.unwrap_or_else(|e| panic!("{e}"));
            out
        }

        fn cipher(&self) -> String {
            self.stream.ssl().current_cipher().unwrap().name().to_string()
        }

        fn saw_client_cert(&self) -> bool {
            self.stream.ssl().peer_certificate().is_some()
        }

        /// RFC 5216 / RFC 9190 MSK from the server's exporter.
        fn export_msk(&self) -> Vec<u8> {
            let ssl = self.stream.ssl();
            let (label, ctx): (&str, Option<&[u8]>) = if ssl.version2() == Some(SslVersion::TLS1_3) {
                ("EXPORTER_EAP_TLS_Key_Material", Some(&[0x0D]))
            } else {
                ("client EAP encryption", None)
            };
            let mut km = [0u8; 128];
            ssl.export_keying_material(&mut km, label, ctx).unwrap();
            km[..64].to_vec()
        }
    }

    #[derive(Debug)]
    struct Stats {
        client_fragments: usize,
        client_acks: usize,
        server_fragments: usize,
        server_acks: usize,
        /// Largest server flight on the wire (before the fake EAP server fragments it).
        max_server_flight: usize,
    }

    fn next_server_fragment(
        s_tx: &[u8],
        s_off: &mut usize,
        frag: usize,
        repeat_l: bool,
        stats: &mut Stats,
    ) -> EapTlsData {
        let remaining = s_tx.len() - *s_off;
        let n = remaining.min(frag);
        let first = *s_off == 0;
        let more = n < remaining;
        let chunk = s_tx[*s_off..*s_off + n].to_vec();
        *s_off += n;
        stats.server_fragments += 1;
        EapTlsData {
            flags: if more { EAP_TLS_FLAG_M } else { 0 },
            length: if first || repeat_l { Some(s_tx.len() as u32) } else { None },
            data: chunk,
        }
    }

    /// Runs the E2E flow and asserts the client MSK equals the server's exporter output and
    /// that the expected version / suite was negotiated.
    fn e2e_check(cfg: EapTlsConfig, server: SslContext, version: &str, suite: &str, server_frag: usize, repeat_l: bool) -> Stats {
        let (msk, stats, client, server) = run_e2e(cfg, server, server_frag, repeat_l);
        assert_eq!(msk.len(), 64);
        assert_eq!(msk, server.export_msk(), "client MSK must equal the server's exporter output");
        assert!(server.saw_client_cert(), "server must have seen the client cert");
        assert_eq!(client.protocol_version(), Some(version));
        assert_eq!(client.cipher_name(), Some(suite));
        assert_eq!(server.cipher(), suite);
        stats
    }

    /// Fake EAP server: Identity -> Start -> data with fragmentation/ACKs both ways -> Success.
    /// `server_frag` is the server's outbound fragment size; `repeat_l` sets L on every
    /// server fragment (T-Mobile behaviour) instead of only the first. Returns the client
    /// MSK, conversation statistics and both endpoints (for exporter comparison).
    fn run_e2e(
        cfg: EapTlsConfig,
        server_ctx: SslContext,
        server_frag: usize,
        repeat_l: bool,
    ) -> (Vec<u8>, Stats, EapTlsClient, TestServer) {
        let mut server = TestServer::new(&server_ctx);
        let mut client = EapTlsClient::new(cfg).unwrap();
        let mut stats =
            Stats { client_fragments: 0, client_acks: 0, server_fragments: 0, server_acks: 0, max_server_flight: 0 };
        let mut id: u8 = 0xF0; // wraps around 0xFF -> 0x00 during the run

        let r = expect_send(client.handle(&request(id, EAP_TYPE_IDENTITY, vec![])).unwrap());
        assert_eq!(r, EapPacket::identity_response(id, IDENTITY));
        id = id.wrapping_add(1);

        let mut s_tx: Vec<u8> = Vec::new();
        let mut s_off = 0usize;
        let mut s_rx: Option<(Vec<u8>, usize)> = None;
        let mut req = start_request(id);
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 64, "EAP conversation did not converge");
            let action = client.handle(&req).unwrap_or_else(|e| panic!("client error in round {rounds}: {e}"));
            let resp = match action {
                EapAction::Send(p) => p,
                EapAction::Success { msk, emsk } => {
                    assert_eq!(emsk.len(), 64);
                    assert_ne!(msk, emsk);
                    assert_eq!(client.msk(), Some(&msk[..]));
                    return (msk.to_vec(), stats, client, server);
                }
                EapAction::Failure(s) => panic!("client failure: {s}"),
            };
            assert_eq!(resp.code, EAP_CODE_RESPONSE);
            assert_eq!(resp.identifier, req.identifier, "identifier must be echoed");
            assert_eq!(resp.eap_type, Some(EAP_TYPE_TLS));
            let td = EapTlsData::decode(&resp.type_data).unwrap();
            id = id.wrapping_add(1);

            if td.is_ack() {
                assert_eq!(resp.encode(), [0x02, req.identifier, 0x00, 0x06, 0x0d, 0x00]);
                stats.client_acks += 1;
                if s_off < s_tx.len() {
                    req = tls_request(id, &next_server_fragment(&s_tx, &mut s_off, server_frag, repeat_l, &mut stats));
                    continue;
                }
                assert!(server.done, "client finished but server still handshaking");
                assert!(client.msk().is_some(), "client must have derived the MSK before the final ACK");
                req = EapPacket { code: EAP_CODE_SUCCESS, identifier: id, eap_type: None, type_data: vec![] };
                continue;
            }

            stats.client_fragments += 1;
            let (buf, cap) = match s_rx.take() {
                None => {
                    assert!(td.has_l(), "first/unfragmented client message must carry L");
                    (td.data.clone(), td.length.unwrap() as usize)
                }
                Some((mut buf, cap)) => {
                    assert!(!td.has_l(), "continuation fragments must not carry L");
                    buf.extend_from_slice(&td.data);
                    (buf, cap)
                }
            };
            assert!(buf.len() <= cap);
            if td.has_m() {
                assert_eq!(td.data.len(), 1024, "non-final client fragment must be exactly 1024 bytes");
                s_rx = Some((buf, cap));
                stats.server_acks += 1;
                req = tls_request(id, &EapTlsData::ack());
                continue;
            }
            assert_eq!(buf.len(), cap, "client message shorter than declared");
            s_tx = server.feed(&buf);
            s_off = 0;
            stats.max_server_flight = stats.max_server_flight.max(s_tx.len());
            if s_tx.is_empty() {
                assert!(server.done);
                req = EapPacket { code: EAP_CODE_SUCCESS, identifier: id, eap_type: None, type_data: vec![] };
                continue;
            }
            req = tls_request(id, &next_server_fragment(&s_tx, &mut s_off, server_frag, repeat_l, &mut stats));
        }
    }

    #[test]
    fn e2e_tmobile_tls_rsa_aes128_cbc_sha_fragmented_both_ways() {
        let stats = e2e_check(client_cfg(false, false), tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 700, false);
        // Client flight (RSA-2048 cert + CKE + CV + CCS + Finished) exceeds 1024 -> >= 2 fragments,
        // each non-final one acked by the server.
        assert!(stats.client_fragments >= 3, "expected ClientHello + >=2 flight fragments, got {stats:?}");
        assert!(stats.server_acks >= 1, "{stats:?}");
        // Server flight (leaf + issuer cert) exceeds 1024 on the wire; split at 700 -> at least
        // 2 server fragments and >= 1 client ACK, plus the final post-handshake ACK.
        assert!(stats.max_server_flight > 1024, "{stats:?}");
        assert!(stats.server_fragments >= 3, "{stats:?}");
        assert!(stats.client_acks >= 2, "{stats:?}");
    }

    #[test]
    fn e2e_tmobile_repeated_l_on_every_server_fragment() {
        let stats = e2e_check(client_cfg(false, false), tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 500, true);
        assert!(stats.server_fragments >= 3, "{stats:?}");
    }

    #[test]
    fn e2e_tmobile_unfragmented_server_flight() {
        // Large server fragment size -> every server message is a single unfragmented EAP-TLS request.
        let stats = e2e_check(client_cfg(false, false), tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 65536, false);
        assert_eq!(stats.client_acks, 1, "only the final post-handshake ACK: {stats:?}");
        assert!(stats.client_fragments >= 3, "{stats:?}");
    }

    #[test]
    fn e2e_tmobile_with_server_validation() {
        // Chain validation only (no server_name -> no SNI, no hostname check).
        e2e_check(client_cfg(true, false), tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 900, false);
        // DNS name: SNI is sent and checked against the SAN.
        let mut cfg = client_cfg(true, false);
        cfg.server_name = Some("localhost".into());
        e2e_check(cfg, tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 900, false);
        // IP literal: no SNI, checked against the IP SAN.
        let mut cfg = client_cfg(true, false);
        cfg.server_name = Some("127.0.0.1".into());
        e2e_check(cfg, tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 900, false);
    }

    /// Drives Start + the server's first flight and returns the client's verdict on it.
    fn first_server_flight_result(cfg: EapTlsConfig, server_ctx: SslContext) -> Result<EapAction> {
        let mut server = TestServer::new(&server_ctx);
        let mut client = EapTlsClient::new(cfg).unwrap();
        let hello = expect_send(client.handle(&start_request(1)).unwrap());
        let flight = server.feed(&EapTlsData::decode(&hello.type_data).unwrap().data);
        assert!(!flight.is_empty(), "server produced no reply to the ClientHello");
        client.handle(&tls_request(2, &EapTlsData { flags: 0, length: Some(flight.len() as u32), data: flight }))
    }

    #[test]
    fn e2e_validation_fails_against_untrusted_server() {
        let mut cfg = client_cfg(true, false);
        // Trust the client cert instead of the CA -> chain validation must fail.
        cfg.server_ca_pem = Some(TEST_CLIENT_CERT_PEM.to_string());
        match first_server_flight_result(cfg, tmobile_server()) {
            Err(Error::Tls(e)) => assert!(e.contains("certificate verify failed"), "{e}"),
            other => panic!("expected a TLS certificate error, got {other:?}"),
        }
    }

    #[test]
    fn e2e_validation_fails_on_hostname_mismatch() {
        let mut cfg = client_cfg(true, false);
        cfg.server_name = Some("epdg.example.invalid".into());
        match first_server_flight_result(cfg, tmobile_server()) {
            Err(Error::Tls(e)) => assert!(e.contains("hostname mismatch"), "{e}"),
            other => panic!("expected a hostname mismatch error, got {other:?}"),
        }
        // Trust-all ignores the name entirely.
        let mut cfg = client_cfg(false, false);
        cfg.server_name = Some("epdg.example.invalid".into());
        e2e_check(cfg, tmobile_server(), "TLSv1.2", TMOBILE_SUITE, 900, false);
    }

    #[test]
    fn e2e_modern_ecdhe_rsa_aes128_gcm_sha256() {
        let stats = e2e_check(client_cfg(false, false), modern_server(), "TLSv1.2", MODERN_SUITE, 700, false);
        assert!(stats.client_fragments >= 3, "{stats:?}");
    }

    #[test]
    fn e2e_fixture_credentials_against_tmobile_suite() {
        // The real client certificate/key fixtures complete the T-Mobile handshake.
        let stats = e2e_check(fixture_client_cfg(), accept_any_client_server(), "TLSv1.2", TMOBILE_SUITE, 700, false);
        assert!(stats.client_fragments >= 3, "{stats:?}");
    }

    #[test]
    fn e2e_tls13_when_allowed() {
        let stats = e2e_check(client_cfg(false, true), tls13_server(), "TLSv1.3", "TLS_AES_256_GCM_SHA384", 800, false);
        assert!(stats.client_fragments >= 2, "{stats:?}");
    }

    #[test]
    fn tls13_only_server_is_rejected_by_default() {
        // allow_tls13 = false caps the ClientHello at TLS 1.2: a 1.3-only server refuses it
        // ("unsupported protocol") and its protocol_version alert fails the client handshake.
        let mut server = TestServer::new(&tls13_server());
        let mut client = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let hello = expect_send(client.handle(&start_request(1)).unwrap());
        let (verdict, alert) = server.step(&EapTlsData::decode(&hello.type_data).unwrap().data);
        assert!(matches!(&verdict, Err(e) if e.contains("unsupported protocol")), "{verdict:?}");
        assert_eq!(alert.first(), Some(&0x15), "server must answer with an alert record");
        let req = tls_request(2, &EapTlsData { flags: 0, length: Some(alert.len() as u32), data: alert });
        match client.handle(&req) {
            Err(Error::Tls(e)) => assert!(e.contains("protocol version"), "{e}"),
            other => panic!("expected a TLS protocol version error, got {other:?}"),
        }
    }

    #[test]
    fn e2e_success_arriving_early_is_fatal() {
        // Drive up to the client's flight, then inject EAP-Success before the server Finished.
        let mut server = TestServer::new(&tmobile_server());
        let mut client = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let hello = expect_send(client.handle(&start_request(1)).unwrap());
        let flight = server.feed(&EapTlsData::decode(&hello.type_data).unwrap().data);
        let req = tls_request(2, &EapTlsData { flags: 0, length: Some(flight.len() as u32), data: flight });
        let f1 = expect_send(client.handle(&req).unwrap());
        assert!(EapTlsData::decode(&f1.type_data).unwrap().has_m());
        assert_eq!(client.cipher_name(), Some(TMOBILE_SUITE), "suite is known once the ServerHello is in");
        let s = EapPacket { code: EAP_CODE_SUCCESS, identifier: 3, eap_type: None, type_data: vec![] };
        assert!(matches!(client.handle(&s).unwrap(), EapAction::Failure(_)));
        assert!(client.msk().is_none());
    }
}
