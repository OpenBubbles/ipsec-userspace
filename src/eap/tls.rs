//! EAP-TLS method (RFC 5216; TLS 1.3 keying per RFC 9190), backed by rustls.
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
//! Key material: 128 exporter bytes; MSK = `[..64]`, EMSK = `[64..]`.
//! TLS 1.2: label `"client EAP encryption"`, no context (RFC 5216 §2.3).
//! TLS 1.3: label `"EXPORTER_EAP_TLS_Key_Material"`, context `[0x0D]` (RFC 9190 §2.1).

use std::io;
use std::sync::Arc;

use log::{debug, info, warn};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    AlertDescription, ClientConfig, ClientConnection, DigitallySignedStruct, ProtocolVersion, RootCertStore,
    SignatureScheme,
};
use zeroize::Zeroizing;

use super::packet::EapPacket;
use crate::ike::constants::*;
use crate::{Error, Result};

/// Default outbound fragment size in TLS-data bytes (AOSP `DEFAULT_FRAGMENTATION_SIZE`).
pub const DEFAULT_MAX_FRAGMENT_LEN: usize = 1024;
/// Exporter output length: MSK (64) | EMSK (64).
const KEY_MATERIAL_LEN: usize = 128;
const MSK_LEN: usize = 64;

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
    /// TLS server name. `ServerName::IpAddress` sends no SNI (AOSP sends none).
    pub server_name: ServerName<'static>,
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
    Success { msk: Vec<u8>, emsk: Vec<u8> },
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

/// The EAP-TLS client state machine (sans-I/O, synchronous).
pub struct EapTlsClient {
    identity: Vec<u8>,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    max_fragment_len: usize,
    conn: Option<ClientConnection>,
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
            .field("tx_pending", &(self.tx.len() - self.tx_offset))
            .field("rx_pending", &self.rx.as_ref().map(|r| (r.buf.len(), r.capacity)))
            .field("msk", &self.msk.as_ref().map(|_| "<derived>"))
            .finish()
    }
}

impl EapTlsClient {
    /// Build the rustls configuration up front so PEM / trust-store errors surface early.
    pub fn new(cfg: EapTlsConfig) -> Result<Self> {
        let tls_config = build_client_config(&cfg)?;
        let max_fragment_len = if cfg.max_fragment_len == 0 { DEFAULT_MAX_FRAGMENT_LEN } else { cfg.max_fragment_len };
        Ok(EapTlsClient {
            identity: cfg.identity,
            tls_config,
            server_name: cfg.server_name,
            max_fragment_len,
            conn: None,
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
                    Ok(EapAction::Success { msk: msk.to_vec(), emsk: emsk.to_vec() })
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

    /// Negotiated TLS protocol version, once known.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.conn.as_ref().and_then(|c| c.protocol_version())
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
        info!("EAP-TLS Start: opening TLS client session");
        let mut conn = ClientConnection::new(self.tls_config.clone(), self.server_name.clone())?;
        let mut tx = Vec::new();
        drain_writes(&mut conn, &mut tx)?;
        if tx.is_empty() {
            return Err(Error::Eap("TLS client produced no ClientHello".into()));
        }
        debug!("EAP-TLS ClientHello: {} bytes", tx.len());
        self.conn = Some(conn);
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
        feed_reads(conn, msg)?;
        let mut tx = Vec::new();
        drain_writes(conn, &mut tx)?;
        let handshaking = conn.is_handshaking();
        debug!("EAP-TLS after TLS processing: {} bytes to send, handshaking={handshaking}", tx.len());

        if !handshaking && self.msk.is_none() {
            let version = conn
                .protocol_version()
                .ok_or_else(|| Error::Eap("TLS handshake complete but no protocol version".into()))?;
            let (msk, emsk) = derive_key_material(conn, version)?;
            info!("EAP-TLS handshake complete ({version:?}); MSK/EMSK derived");
            self.msk = Some(msk);
            self.emsk = Some(emsk);
        }

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
}

// ---- rustls plumbing ------------------------------------------------------------------

/// Push TLS bytes into the connection and process them, looping until all are consumed.
fn feed_reads(conn: &mut ClientConnection, msg: &[u8]) -> Result<()> {
    let mut consumed = 0;
    while consumed < msg.len() {
        let mut rd = &msg[consumed..];
        let n = conn
            .read_tls(&mut rd)
            .map_err(|e| Error::Eap(format!("TLS read_tls failed: {e}")))?;
        if n == 0 {
            return Err(Error::Eap("TLS engine refused input (connection closed?)".into()));
        }
        consumed += n;
        conn.process_new_packets().map_err(map_tls_error)?;
    }
    Ok(())
}

/// Collect every pending outbound TLS record.
fn drain_writes(conn: &mut ClientConnection, out: &mut Vec<u8>) -> Result<()> {
    while conn.wants_write() {
        let n = conn.write_tls(out).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
    }
    Ok(())
}

fn map_tls_error(e: rustls::Error) -> Error {
    match e {
        rustls::Error::AlertReceived(AlertDescription::HandshakeFailure) => Error::Eap(
            "TLS handshake_failure alert from server: no common cipher suite (rustls offers only ECDHE + AEAD \
             suites for TLS 1.2; a server insisting on RSA key exchange or CBC suites cannot be served)"
                .into(),
        ),
        other => Error::Tls(other),
    }
}

fn derive_key_material(
    conn: &ClientConnection,
    version: ProtocolVersion,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
    let (label, context): (&[u8], Option<&[u8]>) = match version {
        ProtocolVersion::TLSv1_3 => (b"EXPORTER_EAP_TLS_Key_Material", Some(&[0x0D])),
        _ => (b"client EAP encryption", None),
    };
    let km = Zeroizing::new(
        conn.export_keying_material(vec![0u8; KEY_MATERIAL_LEN], label, context)
            .map_err(|e| Error::Eap(format!("TLS exporter failed: {e}")))?,
    );
    let msk = Zeroizing::new(km[..MSK_LEN].to_vec());
    let emsk = Zeroizing::new(km[MSK_LEN..].to_vec());
    Ok((msk, emsk))
}

/// Trust-all server certificate verifier (AOSP `validateServerCert=false`).
#[derive(Debug)]
struct NoVerify {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

fn parse_certs(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = io::Cursor::new(pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::config(format!("{what}: invalid certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(Error::config(format!("{what}: no certificate found in PEM")));
    }
    Ok(certs)
}

fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut rd = io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| Error::config(format!("client key: invalid PEM: {e}")))?
        .ok_or_else(|| Error::config("client key: no private key found in PEM"))
}

fn build_client_config(cfg: &EapTlsConfig) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if cfg.allow_tls13 {
        &[&rustls::version::TLS12, &rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS12]
    };
    let builder = ClientConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions)?;

    let builder = if cfg.validate_server {
        let ca_pem = cfg.server_ca_pem.as_deref().ok_or_else(|| {
            Error::config("validate_server_cert is set but no server CA PEM was provided (no system trust store)")
        })?;
        let mut roots = RootCertStore::empty();
        for cert in parse_certs(ca_pem, "server CA")? {
            roots.add(cert)?;
        }
        info!("EAP-TLS: validating server certificate against {} trust anchor(s)", roots.len());
        builder.with_root_certificates(roots)
    } else {
        warn!("EAP-TLS: server certificate validation DISABLED (trust-all, as configured)");
        let schemes = provider.signature_verification_algorithms.supported_schemes();
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify { schemes }))
    };

    let mut certs = parse_certs(&cfg.client_cert_pem, "client certificate")?;
    if certs.len() > 1 {
        debug!("EAP-TLS: client PEM has {} certificates; sending the leaf only", certs.len());
        certs.truncate(1);
    }
    let key = parse_private_key(&cfg.client_key_pem)?;
    let config = builder.with_client_auth_cert(certs, key)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::{DistinguishedName, ServerConfig, ServerConnection};
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT_CERT_PEM: &str = include_str!("../../tests/fixtures/client.crt");
    const CLIENT_KEY_PEM: &str = include_str!("../../tests/fixtures/client.key");

    // Static EC P-256 test PKI (valid until 2126), generated once with the openssl CLI:
    //   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
    //     -subj "/CN=epdg-test-ca" -addext "basicConstraints=critical,CA:TRUE" \
    //     -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.crt
    //   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    //     -subj "/CN=epdg-test-server" -keyout server.key -out server.csr
    //   openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 36500 \
    //     -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n\
    //                        keyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n") -out server.crt
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBljCCATugAwIBAgIUSVmbkn1ma9DZM1EstSjBVzx0vPswCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMZXBkZy10ZXN0LWNhMCAXDTI2MDkxMTA2NTgxOFoYDzIxMjYw
ODE4MDY1ODE4WjAXMRUwEwYDVQQDDAxlcGRnLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARXVPwk2yGKTy0dObsooI/pCFtq2A7wIwoyrj8bEw0DA9CR
6SdDenXTiVbVhVEa72qWvZtINhHAQxsqw2rsHJLCo2MwYTAdBgNVHQ4EFgQUrD07
ivBZrHFEmKx3S2lzQ+FAAvMwHwYDVR0jBBgwFoAUrD07ivBZrHFEmKx3S2lzQ+FA
AvMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SQAwRgIhAPykK9NL9hoK5Ahs6fiu/TAU72rPUO12nf3oACZXB2mDAiEArUbK78pQ
ZXvJixAi4hPuxxbH1U6BhWObym2/HOiLUAc=
-----END CERTIFICATE-----
";
    const SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBwzCCAWmgAwIBAgIUZh/yEw+WFVkQkqoNttOQkRcDWiUwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMZXBkZy10ZXN0LWNhMCAXDTI2MDkxMTA2NTgxOFoYDzIxMjYw
ODE4MDY1ODE4WjAbMRkwFwYDVQQDDBBlcGRnLXRlc3Qtc2VydmVyMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEsy5tLB4tIvteNdpzZ3Ai7IWg54BtZSk7qFGWc+f2
noaz1moOG1eQceI5TdtLXINKakY+7v5RK+9zBiq/LVO2mKOBjDCBiTAaBgNVHREE
EzARhwR/AAABgglsb2NhbGhvc3QwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFJT07xOQaa5qAhtuDA0TW3FcqlyY
MB8GA1UdIwQYMBaAFKw9O4rwWaxxRJisd0tpc0PhQALzMAoGCCqGSM49BAMCA0gA
MEUCIH+XOABG6LVGV8SCN11nPrjRjhblFcBvvumhPJxzd7MxAiEA3RnpDfCN3QBW
UbUVMJCch6so8IVIwkHjxJZQOdEIdGE=
-----END CERTIFICATE-----
";
    const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy/+mW9SHraGtpU6f
VZALz/3/qX+RTbYyOm9TV/KHBamhRANCAASzLm0sHi0i+1412nNncCLshaDngG1l
KTuoUZZz5/aehrPWag4bV5Bx4jlN20tcg0pqRj7u/lEr73MGKr8tU7aY
-----END PRIVATE KEY-----
";

    const IDENTITY: &[u8] = b"900999990302421609@prodepdg.t-mobile.com";

    fn client_cfg(validate: bool, tls13: bool) -> EapTlsConfig {
        EapTlsConfig {
            identity: IDENTITY.to_vec(),
            client_cert_pem: CLIENT_CERT_PEM.to_string(),
            client_key_pem: CLIENT_KEY_PEM.to_string(),
            validate_server: validate,
            server_ca_pem: if validate { Some(TEST_CA_PEM.to_string()) } else { None },
            server_name: ServerName::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            max_fragment_len: 1024,
            allow_tls13: tls13,
        }
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
    fn config_errors_surface_at_new() {
        let mut cfg = client_cfg(false, false);
        cfg.client_key_pem = "garbage".into();
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let mut cfg = client_cfg(false, false);
        cfg.client_cert_pem = "".into();
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let mut cfg = client_cfg(true, false);
        cfg.server_ca_pem = None;
        assert!(matches!(EapTlsClient::new(cfg), Err(Error::Config(_))));

        let cfg = client_cfg(true, false);
        assert!(EapTlsClient::new(cfg).is_ok());
    }

    // ---- in-process end-to-end against a rustls server -------------------------------

    /// Accepts any client certificate (we do not have the T-Mobile issuer CA) but still
    /// verifies the CertificateVerify signature against the presented certificate.
    #[derive(Debug)]
    struct AcceptAnyClientCert(Arc<rustls::crypto::CryptoProvider>);

    impl ClientCertVerifier for AcceptAnyClientCert {
        fn root_hint_subjects(&self) -> &[DistinguishedName] { &[] }

        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> std::result::Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn server_config(tls13: bool) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] =
            if tls13 { &[&rustls::version::TLS13] } else { &[&rustls::version::TLS12] };
        let certs = parse_certs(SERVER_CERT_PEM, "server").unwrap();
        let key = parse_private_key(SERVER_KEY_PEM).unwrap();
        let cfg = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(Arc::new(AcceptAnyClientCert(provider)))
            .with_single_cert(certs, key)
            .unwrap();
        Arc::new(cfg)
    }

    fn server_feed(server: &mut ServerConnection, data: &[u8]) {
        let mut consumed = 0;
        while consumed < data.len() {
            let mut rd = &data[consumed..];
            let n = server.read_tls(&mut rd).unwrap();
            assert!(n > 0, "server refused input");
            consumed += n;
            server.process_new_packets().unwrap_or_else(|e| panic!("server TLS error: {e}"));
        }
    }

    fn server_drain(server: &mut ServerConnection) -> Vec<u8> {
        let mut out = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut out).unwrap();
        }
        out
    }

    struct Stats {
        client_fragments: usize,
        client_acks: usize,
        server_fragments: usize,
        server_acks: usize,
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

    fn server_msk(tls13: bool) -> impl Fn(&ServerConnection) -> Vec<u8> {
        move |s: &ServerConnection| {
            let (label, ctx): (&[u8], Option<&[u8]>) = if tls13 {
                (b"EXPORTER_EAP_TLS_Key_Material", Some(&[0x0D]))
            } else {
                (b"client EAP encryption", None)
            };
            s.export_keying_material(vec![0u8; 128], label, ctx).unwrap()[..64].to_vec()
        }
    }

    /// Runs the E2E flow and asserts the client MSK equals the server's exporter output.
    fn e2e_check(cfg: EapTlsConfig, tls13: bool, server_frag: usize, repeat_l: bool) -> Stats {
        let export = server_msk(tls13);
        let (msk, stats, server) = run_e2e(cfg, tls13, server_frag, repeat_l);
        assert_eq!(msk.len(), 64);
        assert_eq!(msk, export(&server), "client MSK must equal the server's exporter output");
        assert!(server.peer_certificates().is_some_and(|c| !c.is_empty()), "server must have seen the client cert");
        stats
    }

    /// Fake EAP server: Identity -> Start -> data with fragmentation/ACKs both ways -> Success.
    /// `server_frag` is the server's outbound fragment size; `repeat_l` sets L on every
    /// server fragment (T-Mobile behaviour) instead of only the first. Returns the client
    /// MSK, conversation statistics and the server connection (for exporter comparison).
    fn run_e2e(
        cfg: EapTlsConfig,
        tls13: bool,
        server_frag: usize,
        repeat_l: bool,
    ) -> (Vec<u8>, Stats, ServerConnection) {
        let mut server = ServerConnection::new(server_config(tls13)).unwrap();
        let mut client = EapTlsClient::new(cfg).unwrap();
        let mut stats = Stats { client_fragments: 0, client_acks: 0, server_fragments: 0, server_acks: 0 };
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
                    let expected = if tls13 { ProtocolVersion::TLSv1_3 } else { ProtocolVersion::TLSv1_2 };
                    assert_eq!(client.protocol_version(), Some(expected));
                    return (msk, stats, server);
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
                assert!(!server.is_handshaking(), "client finished but server still handshaking");
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
            server_feed(&mut server, &buf);
            s_tx = server_drain(&mut server);
            s_off = 0;
            if s_tx.is_empty() {
                assert!(!server.is_handshaking());
                req = EapPacket { code: EAP_CODE_SUCCESS, identifier: id, eap_type: None, type_data: vec![] };
                continue;
            }
            req = tls_request(id, &next_server_fragment(&s_tx, &mut s_off, server_frag, repeat_l, &mut stats));
        }
    }

    #[test]
    fn e2e_tls12_trust_all_fragmented_both_ways() {
        let stats = e2e_check(client_cfg(false, false), false, 700, false);
        // Client flight (RSA-2048 cert + CKE + CV + CCS + Finished) exceeds 1024 -> >= 2 fragments,
        // each non-final one acked by the server.
        assert!(stats.client_fragments >= 3, "expected ClientHello + >=2 flight fragments, got {}", stats.client_fragments);
        assert!(stats.server_acks >= 1);
        // Server flight (~1 KB+) split at 700 -> at least 2 server fragments and >= 1 client ACK,
        // plus the final post-handshake ACK.
        assert!(stats.server_fragments >= 3);
        assert!(stats.client_acks >= 2);
    }

    #[test]
    fn e2e_tls12_repeated_l_on_every_server_fragment() {
        let stats = e2e_check(client_cfg(false, false), false, 500, true);
        assert!(stats.server_fragments >= 3);
    }

    #[test]
    fn e2e_tls12_unfragmented_server_flight() {
        // Large server fragment size -> every server message is a single unfragmented EAP-TLS request.
        let stats = e2e_check(client_cfg(false, false), false, 65536, false);
        assert_eq!(stats.client_acks, 1, "only the final post-handshake ACK");
        assert!(stats.client_fragments >= 3);
    }

    #[test]
    fn e2e_tls12_with_server_validation() {
        let mut cfg = client_cfg(true, false);
        cfg.server_name = ServerName::try_from("localhost").unwrap();
        e2e_check(cfg, false, 900, false);
        // IP SAN works too.
        e2e_check(client_cfg(true, false), false, 900, false);
    }

    #[test]
    fn e2e_tls12_validation_fails_against_untrusted_server() {
        let mut cfg = client_cfg(true, false);
        // Trust the client cert instead of the server cert -> chain validation must fail.
        cfg.server_ca_pem = Some(CLIENT_CERT_PEM.to_string());
        let mut server = ServerConnection::new(server_config(false)).unwrap();
        let mut client = EapTlsClient::new(cfg).unwrap();
        let hello = expect_send(client.handle(&start_request(1)).unwrap());
        let td = EapTlsData::decode(&hello.type_data).unwrap();
        server_feed(&mut server, &td.data);
        let flight = server_drain(&mut server);
        let req = tls_request(2, &EapTlsData { flags: 0, length: Some(flight.len() as u32), data: flight });
        match client.handle(&req) {
            Err(Error::Tls(e)) => assert!(matches!(e, rustls::Error::InvalidCertificate(_)), "{e}"),
            other => panic!("expected a TLS certificate error, got {other:?}"),
        }
    }

    #[test]
    fn e2e_tls13_when_allowed() {
        let stats = e2e_check(client_cfg(false, true), true, 800, false);
        assert!(stats.client_fragments >= 2);
    }

    #[test]
    fn e2e_success_arriving_early_is_fatal() {
        // Drive up to the client's flight, then inject EAP-Success before the server Finished.
        let mut server = ServerConnection::new(server_config(false)).unwrap();
        let mut client = EapTlsClient::new(client_cfg(false, false)).unwrap();
        let hello = expect_send(client.handle(&start_request(1)).unwrap());
        server_feed(&mut server, &EapTlsData::decode(&hello.type_data).unwrap().data);
        let flight = server_drain(&mut server);
        let req = tls_request(2, &EapTlsData { flags: 0, length: Some(flight.len() as u32), data: flight });
        let f1 = expect_send(client.handle(&req).unwrap());
        assert!(EapTlsData::decode(&f1.type_data).unwrap().has_m());
        let s = EapPacket { code: EAP_CODE_SUCCESS, identifier: 3, eap_type: None, type_data: vec![] };
        assert!(matches!(client.handle(&s).unwrap(), EapAction::Failure(_)));
        assert!(client.msk().is_none());
    }
}
