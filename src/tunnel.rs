//! The public facade (DESIGN.md §12): [`EpdgTunnel::connect`] runs the whole
//! IKE_SA_INIT → IKE_AUTH/EAP-TLS → child-SA sequence, then keeps the tunnel alive
//! with a receive thread (ESP demux + peer IKE requests), a NAT-T keepalive thread
//! and a maintenance thread (DPD, child/IKE rekey at the soft lifetime).
//!
//! Threads after establishment:
//! - **rx**: `IkeTransport::recv` loop. ESP → `EspInbound::decapsulate` → the inner IP
//!   packet is pushed into the smoltcp stack (`InnerStack::push_rx`, no parsing here).
//!   IKE responses → the pending-request slot (matched by `(SPIi, message id)`);
//!   IKE requests → `IkeInitiator::handle_peer_request` → response sent; a peer
//!   `DELETE(IKE)` marks the tunnel dead.
//! - **stack** (`epdg-stack`): the smoltcp poll loop of [`InnerStack`] (DESIGN §11).
//!   Its TX sink is `EspOutbound::encapsulate` + `IkeTransport::send_esp`; it delivers
//!   inner UDP to [`InnerUdpSocket`] channels and completes [`EpdgTunnel::resolve`].
//! - **keepalive**: one `0xFF` byte to `gateway:4500` every `keepalive_interval_secs`
//!   on the same socket as IKE, regardless of traffic (AOSP behaviour, RFC 3948 §4).
//! - **timer** (1 s tick): DPD after `dpd.interval_secs` without any rx, with
//!   `max_retries` × `retry_interval_secs`; child rekey then IKE rekey at the soft
//!   lifetime `lifetime × (1 − rekey_margin_fraction)` (no jitter, like AOSP).
//!
//! All post-establishment IKE requests go through one [`ike_request`] helper that
//! serialises on a mutex (one outstanding request), retransmits per the configured
//! policy and gets its response from the rx thread's pending slot. Nothing here
//! logs key material.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use log::{debug, error, info, trace, warn};

use crate::config::{Config, RetransmitConfig};
use crate::crypto::registry;
use crate::eap::packet::EapPacket;
use crate::eap::tls::{EapAction, EapTlsClient, EapTlsConfig};
use crate::esp::codec::{EspInbound, EspOutbound, EspSa};
use crate::ike::constants::*;
use crate::ike::fragment::{fragment_info, is_fragment};
use crate::ike::header::IkeHeader;
use crate::ike::message::IkeMessage;
use crate::ike::nat::NatStatus;
use crate::ike::session::{AssignedConfig, AuthResponse, ChildSaInfo, IkeInitiator, PeerEvent, SaInitOutcome};
use crate::ike::transport::{IkeTransport, Incoming};
use crate::ipstack::{InnerStack, StackStats, TxSink};
use crate::{Error, Result};

pub use crate::ipstack::{InnerUdpSocket, UdpDatagram};

/// Rx thread socket wait per iteration (also bounds thread-stop latency).
const RX_POLL: Duration = Duration::from_millis(500);
/// Sleep slice for the keepalive / timer threads.
const TICK_SLICE: Duration = Duration::from_millis(200);
/// Timer thread evaluation period (DESIGN §12: 1 s tick).
const TIMER_TICK: Duration = Duration::from_secs(1);
/// Upper bound on IKE_SA_INIT retries (COOKIE / INVALID_KE_PAYLOAD) per candidate.
const MAX_SA_INIT_RETRIES: usize = 4;
/// Upper bound on EAP rounds inside IKE_AUTH.
const MAX_EAP_ROUNDS: usize = 64;
/// Incomplete SKF fragment sets in the rx thread older than this are dropped.
const FRAGMENT_SET_TTL: Duration = Duration::from_secs(30);
/// Retransmit attempts for the DELETE(IKE) sent by `close()`.
const CLOSE_ATTEMPTS: u32 = 2;
/// Delay before a failed (non-timeout) rekey is attempted again.
const REKEY_RETRY_DELAY: Duration = Duration::from_secs(60);
/// Upper bound on any config-derived interval (`Instant + Duration` must never overflow).
const MAX_INTERVAL: Duration = Duration::from_secs(365 * 86400);
/// Poll slice of the handshake-time keepalive ticker.
const HANDSHAKE_KEEPALIVE_SLICE: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Everything worth knowing about an established tunnel.
#[derive(Clone, Debug)]
pub struct TunnelInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub nat: NatStatus,
    pub assigned: AssignedConfig,
    pub ike_spi_i: u64,
    pub ike_spi_r: u64,
    pub child_spi_in: u32,
    pub child_spi_out: u32,
    pub ike_suite: String,
    pub child_suite: String,
    pub tls_version: String,
    pub handshake_duration: Duration,
}

/// Counters maintained by the tunnel threads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TunnelStats {
    pub esp_tx_packets: u64,
    pub esp_tx_bytes: u64,
    pub esp_rx_packets: u64,
    pub esp_rx_bytes: u64,
    pub replay_drops: u64,
    pub icv_failures: u64,
    pub keepalives_sent: u64,
    pub child_rekeys: u64,
    pub ike_rekeys: u64,
    pub peer_dpd_answered: u64,
    /// Inbound inner UDP datagrams dropped because the port's receive queue was full
    /// (same as `stack.udp_queue_drops`).
    pub rx_queue_drops: u64,
    /// Instant of the last IKE / ESP / keepalive datagram received from the gateway.
    pub last_rx: Option<Instant>,
    /// Counters of the smoltcp inner stack (device queue, UDP delivery, DNS).
    pub stack: StackStats,
}

/// An established ePDG tunnel. Dropping it closes the tunnel (best effort).
pub struct EpdgTunnel {
    shared: Arc<Shared>,
    info: TunnelInfo,
    stack_thread: Option<JoinHandle<()>>,
    rx_thread: Option<JoinHandle<()>>,
    keepalive_thread: Option<JoinHandle<()>>,
    timer_thread: Option<JoinHandle<()>>,
    closed: bool,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// The response slot of the single outstanding IKE request.
struct PendingSlot {
    spi_i: u64,
    message_id: u32,
    response: Option<IkeMessage>,
}

#[derive(Default)]
struct Counters {
    esp_tx_packets: AtomicU64,
    esp_tx_bytes: AtomicU64,
    esp_rx_packets: AtomicU64,
    esp_rx_bytes: AtomicU64,
    replay_drops: AtomicU64,
    icv_failures: AtomicU64,
    keepalives_sent: AtomicU64,
    child_rekeys: AtomicU64,
    ike_rekeys: AtomicU64,
    peer_dpd_answered: AtomicU64,
}

struct Shared {
    cfg: Config,
    /// Shared with the inner stack's TX sink (`send_esp`).
    transport: Arc<IkeTransport>,
    ike: Mutex<IkeInitiator>,
    /// Held for the whole duration of one post-establishment request.
    request_lock: Mutex<()>,
    pending: Mutex<Option<PendingSlot>>,
    pending_cv: Condvar,
    /// Current outbound SA; shared with the inner stack's TX sink (`encapsulate`).
    outbound: Arc<RwLock<Arc<EspOutbound>>>,
    /// Current inbound SA(s); the old one stays until its DELETE completes.
    inbound: Mutex<Vec<EspInbound>>,
    /// The smoltcp inner IP stack (DESIGN §11): inner UDP sockets and DNS.
    stack: InnerStack,
    alive: AtomicBool,
    stop: AtomicBool,
    dead_reason: Mutex<Option<String>>,
    /// Shared with the inner stack's TX sink (ESP tx counters).
    counters: Arc<Counters>,
    last_rx: Mutex<Option<Instant>>,
    /// Creation instants of the current child SA / IKE SA (rekey scheduling).
    child_created: Mutex<Instant>,
    ike_created: Mutex<Instant>,
    /// When the transport switched to 4500: the NAT-T keepalive cadence is anchored here.
    natt_since: Instant,
}

/// Lock a mutex, recovering from poisoning (a panicked thread must not take the
/// whole tunnel down with it).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst)
    }

    fn mark_dead(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if self.alive.swap(false, Ordering::SeqCst) {
            error!("tunnel dead: {reason}");
            // Inner sockets / resolvers see Error::Closed with the same reason.
            self.stack.close(reason.clone());
            *lock(&self.dead_reason) = Some(reason);
        }
        // Wake anyone waiting for a response so it returns Error::Closed.
        self.pending_cv.notify_all();
    }

    fn closed_error(&self) -> Error {
        let reason = lock(&self.dead_reason).clone().unwrap_or_else(|| "tunnel is closed".into());
        Error::Closed(reason)
    }

    fn touch_rx(&self) {
        *lock(&self.last_rx) = Some(Instant::now());
    }

    fn idle_for(&self) -> Duration {
        lock(&self.last_rx).map(|t| t.elapsed()).unwrap_or_default()
    }

    fn stats(&self) -> TunnelStats {
        let c = &self.counters;
        let stack = self.stack.stats();
        TunnelStats {
            esp_tx_packets: c.esp_tx_packets.load(Ordering::Relaxed),
            esp_tx_bytes: c.esp_tx_bytes.load(Ordering::Relaxed),
            esp_rx_packets: c.esp_rx_packets.load(Ordering::Relaxed),
            esp_rx_bytes: c.esp_rx_bytes.load(Ordering::Relaxed),
            replay_drops: c.replay_drops.load(Ordering::Relaxed),
            icv_failures: c.icv_failures.load(Ordering::Relaxed),
            keepalives_sent: c.keepalives_sent.load(Ordering::Relaxed),
            child_rekeys: c.child_rekeys.load(Ordering::Relaxed),
            ike_rekeys: c.ike_rekeys.load(Ordering::Relaxed),
            peer_dpd_answered: c.peer_dpd_answered.load(Ordering::Relaxed),
            rx_queue_drops: stack.udp_queue_drops,
            last_rx: *lock(&self.last_rx),
            stack,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------

/// A config interval in seconds as a `Duration`, clamped to `[1 s, MAX_INTERVAL]` so that
/// `Instant + Duration` can never overflow on a hostile plist value.
fn interval_secs(secs: u64) -> Duration {
    Duration::from_secs(secs.max(1)).min(MAX_INTERVAL)
}

/// The first keepalive instant strictly after `now` on the cadence
/// `anchor + k * interval` (k >= 1). The cadence is anchored at the switch to 4500 so the
/// schedule does not restart when the keepalive thread is (re)started.
fn next_keepalive(anchor: Instant, interval: Duration, now: Instant) -> Instant {
    let mut next = anchor + interval;
    while next <= now {
        next += interval;
    }
    next
}

/// Run `body`, turning a panic into a call to `on_panic` with the panic message.
/// Returns `true` when the body completed normally.
fn run_guarded(body: impl FnOnce(), on_panic: impl FnOnce(String)) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(()) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".into());
            on_panic(msg);
            false
        }
    }
}

/// Retransmit timeout after the `attempt`-th (0-based) send: `initial * backoff^attempt`.
fn retransmit_timeout(policy: &RetransmitConfig, attempt: u32) -> Duration {
    let mult = if policy.backoff_multiplier.is_finite() && policy.backoff_multiplier > 0.0 {
        policy.backoff_multiplier
    } else {
        1.0
    };
    let ms = policy.initial_timeout_ms as f64 * mult.powi(attempt as i32);
    let ms = if ms.is_finite() { ms.clamp(1.0, u32::MAX as f64) } else { u32::MAX as f64 };
    Duration::from_millis(ms as u64)
}

/// Soft lifetime = `lifetime × (1 − margin)`, margin clamped to `[0, 0.9]`.
fn soft_lifetime(lifetime_secs: u64, margin: f64) -> Duration {
    let margin = if margin.is_finite() { margin.clamp(0.0, 0.9) } else { 0.1 };
    Duration::from_secs_f64(lifetime_secs as f64 * (1.0 - margin))
}

/// Human-readable IKE suite, e.g. `ENCR_AES_CBC-256/AUTH_HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/DH14`.
fn ike_suite_name(ike: &IkeInitiator) -> String {
    let s = ike.suite();
    let bits = s.cipher.key_len_attr_bits().map(|b| format!("-{b}")).unwrap_or_default();
    format!(
        "{}{}/{}/{}/DH{}",
        registry::transform_name(TT_ENCR, s.cipher.transform_id()),
        bits,
        registry::transform_name(TT_INTEG, s.integrity.transform_id()),
        registry::transform_name(TT_PRF, s.prf.transform_id()),
        s.dh.as_ref().map(|d| d.group_id()).unwrap_or(0)
    )
}

fn child_suite_name(child: &ChildSaInfo) -> String {
    let bits = child.cipher.key_len_attr_bits().map(|b| format!("-{b}")).unwrap_or_default();
    format!(
        "{}{}/{}",
        registry::transform_name(TT_ENCR, child.cipher.transform_id()),
        bits,
        registry::transform_name(TT_INTEG, child.integrity.transform_id())
    )
}

/// Errors during the handshake that are specific to one gateway address (worth
/// trying the next candidate) rather than to our credentials / configuration.
fn is_candidate_specific(e: &Error) -> bool {
    matches!(e, Error::Timeout(_) | Error::Io(_) | Error::Decode(_) | Error::Protocol(_) | Error::Integrity(_))
}

/// Build the ESP SA pair from an established child (§5.2: outbound = spi_out +
/// i2r keys, inbound = spi_in + r2i keys).
fn esp_pair(child: &ChildSaInfo) -> (EspOutbound, EspInbound) {
    let outbound = EspOutbound::new(EspSa {
        spi: child.spi_out,
        cipher: child.cipher.clone(),
        integrity: child.integrity.clone(),
        enc_key: child.keys.encr_i2r.clone(),
        auth_key: child.keys.integ_i2r.clone(),
    });
    let inbound = EspInbound::new(
        EspSa {
            spi: child.spi_in,
            cipher: child.cipher.clone(),
            integrity: child.integrity.clone(),
            enc_key: child.keys.encr_r2i.clone(),
            auth_key: child.keys.integ_r2i.clone(),
        },
        child.replay_window,
    );
    (outbound, inbound)
}

/// Collects SKF fragments of inbound messages in the rx thread until a set is complete.
struct FragmentCollector {
    sets: HashMap<(u64, u32, bool), FragmentSet>,
}

struct FragmentSet {
    total: u16,
    chunks: BTreeMap<u16, Vec<u8>>,
    started: Instant,
}

impl FragmentCollector {
    fn new() -> Self {
        FragmentCollector { sets: HashMap::new() }
    }

    /// Feed one SKF datagram; returns the ordered complete set once all fragments are in.
    fn push(&mut self, raw: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
        let h = IkeHeader::decode(raw)?;
        let (msgid, num, total) = fragment_info(raw)?;
        if num == 0 || total == 0 || num > total {
            return Err(Error::Decode(format!("invalid SKF fragment numbers {num}/{total}")));
        }
        let key = (h.spi_i, msgid, h.is_response());
        let set = self
            .sets
            .entry(key)
            .or_insert_with(|| FragmentSet { total, chunks: BTreeMap::new(), started: Instant::now() });
        if set.total != total {
            let mismatch = set.total;
            self.sets.remove(&key);
            return Err(Error::Decode(format!("SKF total fragments changed {mismatch} -> {total}")));
        }
        set.chunks.entry(num).or_insert_with(|| raw.to_vec());
        if set.chunks.len() == usize::from(total) {
            let set = self.sets.remove(&key).ok_or_else(|| Error::Protocol("fragment set vanished".into()))?;
            return Ok(Some(set.chunks.into_values().collect()));
        }
        Ok(None)
    }

    fn evict_stale(&mut self) {
        self.sets.retain(|_, s| s.started.elapsed() < FRAGMENT_SET_TTL);
    }
}

// ---------------------------------------------------------------------------
// Handshake helpers (no rx thread yet: the transport's own request() is used)
// ---------------------------------------------------------------------------

/// Encode → `transport.request` → decode, for one handshake exchange.
fn handshake_exchange(transport: &IkeTransport, ike: &mut IkeInitiator, msg: &IkeMessage, policy: &RetransmitConfig) -> Result<IkeMessage> {
    let datagrams = ike.encode(msg)?;
    for (i, d) in datagrams.iter().enumerate() {
        debug!(
            "tx exch {} msgid {} datagram {}/{} ({} bytes): {}",
            msg.header.exchange_type,
            msg.header.message_id,
            i + 1,
            datagrams.len(),
            d.len(),
            hex::encode(d)
        );
    }
    let mut on_other = |d: Vec<u8>| {
        warn!("ignoring unexpected IKE datagram during the handshake ({} bytes): {}", d.len(), hex::encode(&d));
    };
    let mut on_esp = |d: Vec<u8>| debug!("ignoring {} byte ESP datagram during the handshake", d.len());
    let response = transport.request(&datagrams, msg.header.message_id, policy, &mut on_other, &mut on_esp)?;
    for (i, d) in response.iter().enumerate() {
        debug!("rx msgid {} datagram {}/{} ({} bytes): {}", msg.header.message_id, i + 1, response.len(), d.len(), hex::encode(d));
    }
    ike.decode(&response)
}

/// IKE_SA_INIT with the COOKIE / INVALID_KE_PAYLOAD retry loop. Returns the initiator
/// (possibly rebuilt for another DH group) and the NAT status.
fn sa_init(cfg: &Config, transport: &IkeTransport, mut ike: IkeInitiator) -> Result<(IkeInitiator, NatStatus)> {
    let policy = &cfg.ike.retransmit;
    let mut cookie: Option<Vec<u8>> = None;
    for round in 0..=MAX_SA_INIT_RETRIES {
        let raw = ike.build_sa_init(cookie.as_deref())?;
        info!(
            "IKE_SA_INIT -> {} (SPIi {:#018x}, {} bytes{})",
            transport.remote_addr(),
            ike.spi_i(),
            raw.len(),
            if cookie.is_some() { ", with COOKIE" } else { "" }
        );
        debug!("tx IKE_SA_INIT request: {}", hex::encode(&raw));
        let mut on_other = |d: Vec<u8>| warn!("ignoring unexpected IKE datagram during IKE_SA_INIT ({} bytes)", d.len());
        let mut on_esp = |_: Vec<u8>| {};
        let response = transport.request(std::slice::from_ref(&raw), 0, policy, &mut on_other, &mut on_esp)?;
        let first = response.first().ok_or_else(|| Error::Protocol("empty IKE_SA_INIT response set".into()))?;
        if response.len() > 1 {
            warn!("IKE_SA_INIT response arrived as {} datagrams; using the first", response.len());
        }
        debug!("rx IKE_SA_INIT response ({} bytes): {}", first.len(), hex::encode(first));
        match ike.handle_sa_init_response(first)? {
            SaInitOutcome::Established { nat } => {
                info!(
                    "IKE_SA_INIT established: SPIr {:#018x}, suite {}, nat local={} remote={} detected={}",
                    ike.spi_r(),
                    ike_suite_name(&ike),
                    nat.local_behind_nat,
                    nat.remote_behind_nat,
                    nat.detected
                );
                return Ok((ike, nat));
            }
            SaInitOutcome::RetryWithCookie(c) => {
                if cookie.is_some() {
                    return Err(Error::Protocol("responder demanded a COOKIE twice".into()));
                }
                info!("IKE_SA_INIT: retrying with COOKIE ({} bytes)", c.len());
                cookie = Some(c);
            }
            SaInitOutcome::RetryWithGroup(group) => {
                info!("IKE_SA_INIT: restarting with DH group {group} (fresh SPIi, nonce, KE)");
                ike = IkeInitiator::new_with_dh_group(cfg, transport.local_addr(), transport.remote_addr(), group)?;
                cookie = None;
            }
        }
        if round == MAX_SA_INIT_RETRIES {
            break;
        }
    }
    Err(Error::Protocol(format!("IKE_SA_INIT did not complete after {MAX_SA_INIT_RETRIES} retries")))
}

fn eap_tls_config(cfg: &Config) -> EapTlsConfig {
    // SNI (and, when validating, the hostname check) only when a name is configured; the
    // ePDG is addressed by IP and AOSP sends no SNI.
    let server_name = cfg.eap_tls.tls_server_name.clone().filter(|n| !n.is_empty());
    EapTlsConfig {
        identity: cfg.identity.eap_identity.clone(),
        client_cert_pem: cfg.eap_tls.client_cert_pem.clone(),
        client_key_pem: cfg.eap_tls.client_key_pem.clone(),
        validate_server: cfg.eap_tls.validate_server_cert,
        server_ca_pem: cfg.eap_tls.server_ca_pem.clone(),
        server_name,
        max_fragment_len: cfg.eap_tls.max_fragment_len,
        allow_tls13: cfg.eap_tls.allow_tls13,
    }
}

/// IKE_AUTH: initial request, EAP-TLS rounds, MSK, final AUTH. Returns the
/// establishment result and the negotiated TLS version.
fn ike_auth(cfg: &Config, transport: &IkeTransport, ike: &mut IkeInitiator) -> Result<(crate::ike::session::Established, String)> {
    let policy = &cfg.ike.retransmit;
    let mut eap = EapTlsClient::new(eap_tls_config(cfg))?;

    let msg = ike.build_auth_initial()?;
    info!("IKE_AUTH #1 (msgid {}): IDi/IDr/EAP_ONLY/SA/TSi/TSr/CP", msg.header.message_id);
    let mut response = handshake_exchange(transport, ike, &msg, policy)?;
    let mut rounds = 0usize;
    loop {
        match ike.handle_auth_response(&response)? {
            AuthResponse::Established(est) => {
                let tls_version = eap.protocol_version().unwrap_or("unknown").to_string();
                info!(
                    "IKE_AUTH complete: child SPI_in {:#010x} SPI_out {:#010x} ({}), TLS {}",
                    est.child.spi_in,
                    est.child.spi_out,
                    child_suite_name(&est.child),
                    tls_version
                );
                return Ok((*est, tls_version));
            }
            AuthResponse::EapRequest(bytes) => {
                rounds += 1;
                if rounds > MAX_EAP_ROUNDS {
                    return Err(Error::Eap(format!("EAP did not finish within {MAX_EAP_ROUNDS} rounds")));
                }
                let packet = EapPacket::decode(&bytes)?;
                debug!(
                    "EAP in: code {} id {} type {:?} ({} bytes)",
                    packet.code,
                    packet.identifier,
                    packet.eap_type,
                    bytes.len()
                );
                match eap.handle(&packet)? {
                    EapAction::Send(reply) => {
                        let encoded = reply.encode();
                        let msg = ike.build_auth_eap(&encoded)?;
                        info!(
                            "IKE_AUTH EAP round {} (msgid {}): EAP response code {} id {} type {:?} {} bytes",
                            rounds,
                            msg.header.message_id,
                            reply.code,
                            reply.identifier,
                            reply.eap_type,
                            encoded.len()
                        );
                        response = handshake_exchange(transport, ike, &msg, policy)?;
                    }
                    EapAction::Success { msk, .. } => {
                        info!(
                            "EAP-Success: MSK derived ({} bytes), TLS {} {}",
                            msk.len(),
                            eap.protocol_version().unwrap_or("unknown"),
                            eap.cipher_name().unwrap_or("unknown")
                        );
                        // The Vec moves into SharedKeyAuth (ZeroizeOnDrop); `msk`/`emsk` zeroize on drop.
                        ike.set_msk(msk.to_vec());
                        let msg = ike.build_auth_final()?;
                        info!("IKE_AUTH final (msgid {}): AUTH(method 2)", msg.header.message_id);
                        response = handshake_exchange(transport, ike, &msg, policy)?;
                    }
                    EapAction::Failure(reason) => return Err(Error::Eap(reason)),
                }
            }
        }
    }
}

/// One full connection attempt against one gateway address.
fn connect_candidate(cfg: &Config, gateway: IpAddr) -> Result<EpdgTunnel> {
    let started = Instant::now();
    let mut transport = IkeTransport::bind(cfg.gateway.local_addr, gateway, cfg.gateway.ike_port)?;
    info!("connecting to ePDG {} from {}", transport.remote_addr(), transport.local_addr());
    let ike = IkeInitiator::new(cfg, transport.local_addr(), transport.remote_addr())?;
    let (mut ike, nat) = sa_init(cfg, &transport, ike)?;

    let keepalive_interval = interval_secs(cfg.ike.natt.keepalive_interval_secs);
    let handshake_keepalives = AtomicU64::new(0);
    let natt_since = Instant::now();
    if nat.detected || !cfg.ike.natt.disable_switch_to_natt_port {
        transport.switch_to_natt(cfg.gateway.natt_port);
        info!("switched to NAT-T: {} (non-ESP marker on)", transport.remote_addr());
        if !nat.detected {
            warn!("responder detected no NAT; it may reject UDP-encapsulated ESP on port {}", cfg.gateway.natt_port);
        }
        // AOSP sends the first 0xFF immediately on the switch, then every interval
        // regardless of traffic (DESIGN §12) — including during IKE_AUTH.
        match transport.send_keepalive() {
            Ok(()) => {
                handshake_keepalives.fetch_add(1, Ordering::Relaxed);
                debug!("NAT-T keepalive #1 sent (right after the switch to 4500)");
            }
            Err(e) => warn!("initial NAT-T keepalive failed: {e}"),
        }
    } else {
        error!("staying on port {}: raw ESP cannot be carried by a userspace client, the tunnel will not pass traffic", cfg.gateway.ike_port);
    }

    // IKE_AUTH (EAP-TLS rounds, possibly many seconds) with the keepalive cadence running
    // on the same socket; the ticker stops as soon as IKE_AUTH returns.
    let ticker_stop = AtomicBool::new(false);
    let auth_result = thread::scope(|scope| {
        if transport.using_natt() {
            let transport = &transport;
            let stop = &ticker_stop;
            let sent = &handshake_keepalives;
            scope.spawn(move || handshake_keepalive_ticker(transport, stop, sent, natt_since, keepalive_interval));
        }
        let r = ike_auth(cfg, &transport, &mut ike);
        ticker_stop.store(true, Ordering::SeqCst);
        r
    });
    let (est, tls_version) = auth_result?;
    let handshake_duration = started.elapsed();
    let child = est.child;
    let assigned = est.assigned;
    info!(
        "tunnel established in {:?}: inner v4 {:?} v6 {:?} dns v4 {:?} v6 {:?} pcscf v4 {:?} v6 {:?}",
        handshake_duration,
        assigned.internal_ipv4,
        assigned.internal_ipv6,
        assigned.dns_ipv4,
        assigned.dns_ipv6,
        assigned.pcscf_ipv4,
        assigned.pcscf_ipv6
    );
    if assigned.internal_ipv4.is_empty() && assigned.internal_ipv6.is_empty() {
        warn!("gateway assigned no inner address; InnerUdpSocket::send_to will fail");
    }

    let info = TunnelInfo {
        local_addr: transport.local_addr(),
        remote_addr: transport.remote_addr(),
        nat,
        assigned: assigned.clone(),
        ike_spi_i: ike.spi_i(),
        ike_spi_r: ike.spi_r(),
        child_spi_in: child.spi_in,
        child_spi_out: child.spi_out,
        ike_suite: ike_suite_name(&ike),
        child_suite: child_suite_name(&child),
        tls_version,
        handshake_duration,
    };

    let (outbound, inbound) = esp_pair(&child);
    let now = Instant::now();
    let transport = Arc::new(transport);
    let outbound = Arc::new(RwLock::new(Arc::new(outbound)));
    let counters = Arc::new(Counters::default());
    counters.keepalives_sent.store(handshake_keepalives.load(Ordering::Relaxed), Ordering::Relaxed);
    let stack = InnerStack::new(&assigned, esp_sink(&transport, &outbound, &counters), cfg.child.inner_mtu)?;
    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        transport,
        ike: Mutex::new(ike),
        request_lock: Mutex::new(()),
        pending: Mutex::new(None),
        pending_cv: Condvar::new(),
        outbound,
        inbound: Mutex::new(vec![inbound]),
        stack,
        alive: AtomicBool::new(true),
        stop: AtomicBool::new(false),
        dead_reason: Mutex::new(None),
        counters,
        last_rx: Mutex::new(Some(now)),
        child_created: Mutex::new(child.created),
        ike_created: Mutex::new(now),
        natt_since,
    });

    let stack_thread = spawn_named("epdg-stack", Arc::clone(&shared), stack_loop)?;
    let rx_thread = spawn_named("epdg-rx", Arc::clone(&shared), rx_loop)?;
    let keepalive_thread = spawn_named("epdg-keepalive", Arc::clone(&shared), keepalive_loop)?;
    let timer_thread = spawn_named("epdg-timer", Arc::clone(&shared), timer_loop)?;

    Ok(EpdgTunnel {
        shared,
        info,
        stack_thread: Some(stack_thread),
        rx_thread: Some(rx_thread),
        keepalive_thread: Some(keepalive_thread),
        timer_thread: Some(timer_thread),
        closed: false,
    })
}

/// The inner stack's TX sink: `EspOutbound::encapsulate` (current outbound SA, so a
/// child rekey is picked up transparently) + `IkeTransport::send_esp`, counting ESP tx.
/// Runs on the stack thread inside `Interface::poll`.
fn esp_sink(transport: &Arc<IkeTransport>, outbound: &Arc<RwLock<Arc<EspOutbound>>>, counters: &Arc<Counters>) -> TxSink {
    let transport = Arc::clone(transport);
    let outbound = Arc::clone(outbound);
    let counters = Arc::clone(counters);
    Arc::new(move |inner: &[u8]| {
        let sa = outbound.read().unwrap_or_else(|e| e.into_inner()).clone();
        let esp = sa.encapsulate(inner)?;
        transport.send_esp(&esp)?;
        counters.esp_tx_packets.fetch_add(1, Ordering::Relaxed);
        counters.esp_tx_bytes.fetch_add(esp.len() as u64, Ordering::Relaxed);
        trace!("tx inner IP packet {} bytes -> ESP {} bytes (SPI {:#010x} seq {})", inner.len(), esp.len(), sa.spi(), sa.seq());
        Ok(())
    })
}

/// Body of the `epdg-stack` thread: the smoltcp poll loop (DESIGN §11).
fn stack_loop(shared: Arc<Shared>) {
    shared.stack.run();
}

/// Spawn a tunnel thread under a panic guard: a panicking thread marks the tunnel dead
/// (waiters wake with `Error::Closed`) and stops the others instead of leaving a
/// half-open tunnel that still reports `is_alive()`.
fn spawn_named(name: &str, shared: Arc<Shared>, body: fn(Arc<Shared>)) -> Result<JoinHandle<()>> {
    let guard = Arc::clone(&shared);
    let thread_name = name.to_string();
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            run_guarded(
                || body(shared),
                |msg| {
                    guard.mark_dead(format!("{thread_name} thread panicked: {msg}"));
                    guard.stop.store(true, Ordering::SeqCst);
                },
            );
        })
        .map_err(Error::Io)
}

/// Keepalive cadence during IKE_AUTH (before `Shared` exists): `anchor + k * interval`.
fn handshake_keepalive_ticker(
    transport: &IkeTransport,
    stop: &AtomicBool,
    sent: &AtomicU64,
    anchor: Instant,
    interval: Duration,
) {
    let mut next = next_keepalive(anchor, interval, Instant::now());
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now < next {
            thread::sleep((next - now).min(HANDSHAKE_KEEPALIVE_SLICE));
            continue;
        }
        next = next_keepalive(anchor, interval, now);
        match transport.send_keepalive() {
            Ok(()) => {
                let n = sent.fetch_add(1, Ordering::Relaxed) + 1;
                debug!("NAT-T keepalive #{n} sent (during IKE_AUTH)");
            }
            Err(e) => warn!("NAT-T keepalive failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Post-establishment request helper
// ---------------------------------------------------------------------------

/// Run one IKE request after establishment: build under the IKE lock, send, wait for
/// the rx thread to deliver the response into the pending slot, retransmitting per
/// `policy`. One request at a time (serialised on `request_lock`).
fn ike_request(
    shared: &Shared,
    what: &'static str,
    policy: &RetransmitConfig,
    build: impl FnOnce(&mut IkeInitiator) -> Result<IkeMessage>,
) -> Result<IkeMessage> {
    let _serial = lock(&shared.request_lock);
    if !shared.is_alive() {
        return Err(shared.closed_error());
    }
    let (datagrams, spi_i, message_id) = {
        let mut ike = lock(&shared.ike);
        let msg = build(&mut ike)?;
        let datagrams = ike.encode(&msg)?;
        (datagrams, msg.header.spi_i, msg.header.message_id)
    };
    for (i, d) in datagrams.iter().enumerate() {
        debug!("tx {what} msgid {message_id} datagram {}/{} ({} bytes): {}", i + 1, datagrams.len(), d.len(), hex::encode(d));
    }
    *lock(&shared.pending) = Some(PendingSlot { spi_i, message_id, response: None });

    let attempts = policy.max_attempts.max(1);
    let mut outcome = Err(Error::Timeout(what));
    'attempts: for attempt in 0..attempts {
        if let Err(e) = datagrams.iter().try_for_each(|d| shared.transport.send_ike(d)) {
            outcome = Err(e);
            break;
        }
        let timeout = retransmit_timeout(policy, attempt);
        debug!("{what} msgid {message_id}: sent attempt {}/{attempts}, waiting {:?}", attempt + 1, timeout);
        let deadline = Instant::now() + timeout;
        let mut slot = lock(&shared.pending);
        loop {
            if let Some(resp) = slot.as_mut().and_then(|s| s.response.take()) {
                outcome = Ok(resp);
                break 'attempts;
            }
            if !shared.is_alive() {
                outcome = Err(shared.closed_error());
                break 'attempts;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            slot = shared.pending_cv.wait_timeout(slot, remaining).unwrap_or_else(|e| e.into_inner()).0;
        }
        drop(slot);
        if attempt + 1 < attempts {
            debug!("{what} msgid {message_id}: no response after {:?}; retransmitting", timeout);
        }
    }
    if outcome.is_err() {
        // Free the session's single request slot (RFC 7296 §2.1: the unanswered message
        // id is reused by the next request); otherwise every later DPD / rekey / DELETE
        // would fail with "another request is outstanding".
        lock(&shared.ike).abort_request();
    }
    *lock(&shared.pending) = None;
    match &outcome {
        Ok(_) => debug!("{what} msgid {message_id}: response received"),
        Err(Error::Timeout(_)) => warn!("{what} msgid {message_id}: no response after {attempts} attempt(s)"),
        Err(e) => warn!("{what} msgid {message_id}: {e}"),
    }
    outcome
}

/// Run a response handler under the IKE lock; a rejected response abandons the
/// session's request slot (idempotent), so a later request can be built.
fn settle<T>(shared: &Shared, handle: impl FnOnce(&mut IkeInitiator) -> Result<T>) -> Result<T> {
    let mut ike = lock(&shared.ike);
    let r = handle(&mut ike);
    if r.is_err() {
        ike.abort_request();
    }
    r
}

/// Empty INFORMATIONAL (liveness check); returns the round-trip time.
fn do_dpd(shared: &Shared, policy: &RetransmitConfig) -> Result<Duration> {
    let started = Instant::now();
    let response = ike_request(shared, "DPD", policy, |ike| ike.build_dpd())?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    let rtt = started.elapsed();
    info!("DPD ok, rtt {:?}", rtt);
    Ok(rtt)
}

/// CREATE_CHILD_SA child rekey, install the new ESP SAs, then DELETE the old child.
fn rekey_child(shared: &Shared) -> Result<()> {
    let policy = &shared.cfg.ike.retransmit;
    let old_spi_in = lock(&shared.ike).child().map(|c| c.spi_in).ok_or_else(|| Error::Protocol("no child SA to rekey".into()))?;
    let response = ike_request(shared, "CREATE_CHILD_SA (rekey child)", policy, |ike| ike.build_rekey_child())?;
    let new = settle(shared, |ike| ike.handle_rekey_child_response(&response))?;
    let (outbound, inbound) = esp_pair(&new);
    lock(&shared.inbound).push(inbound);
    *shared.outbound.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(outbound);
    *lock(&shared.child_created) = new.created;
    shared.counters.child_rekeys.fetch_add(1, Ordering::Relaxed);
    info!("child SA rekeyed: SPI_in {:#010x} SPI_out {:#010x}; deleting old {:#010x}", new.spi_in, new.spi_out, old_spi_in);

    let response = ike_request(shared, "DELETE(ESP)", policy, |ike| ike.build_delete_child(old_spi_in))?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    lock(&shared.inbound).retain(|sa| sa.spi() != old_spi_in);
    Ok(())
}

/// CREATE_CHILD_SA IKE rekey, then DELETE the old IKE SA (on the old SA).
fn rekey_ike(shared: &Shared) -> Result<()> {
    let policy = &shared.cfg.ike.retransmit;
    let response = ike_request(shared, "CREATE_CHILD_SA (rekey IKE)", policy, |ike| ike.build_rekey_ike())?;
    settle(shared, |ike| ike.handle_rekey_ike_response(&response))?;
    *lock(&shared.ike_created) = Instant::now();
    shared.counters.ike_rekeys.fetch_add(1, Ordering::Relaxed);
    {
        let ike = lock(&shared.ike);
        info!("IKE SA rekeyed: SPIs {:#018x}/{:#018x}; deleting the old IKE SA", ike.spi_i(), ike.spi_r());
    }
    let response = ike_request(shared, "DELETE(IKE) old SA", policy, |ike| ike.build_delete_ike())?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

fn rx_loop(shared: Arc<Shared>) {
    let mut fragments = FragmentCollector::new();
    let mut last_evict = Instant::now();
    let mut consecutive_errors: u32 = 0;
    while !shared.stop.load(Ordering::SeqCst) {
        match shared.transport.recv(RX_POLL) {
            Ok(None) => consecutive_errors = 0,
            Ok(Some(Incoming::Keepalive)) => {
                consecutive_errors = 0;
                shared.touch_rx();
                debug!("NAT-T keepalive received");
            }
            Ok(Some(Incoming::Esp(packet))) => {
                consecutive_errors = 0;
                shared.touch_rx();
                handle_esp(&shared, &packet);
            }
            Ok(Some(Incoming::Ike(datagram))) => {
                consecutive_errors = 0;
                shared.touch_rx();
                handle_ike_datagram(&shared, datagram, &mut fragments);
            }
            Err(e) => {
                if shared.stop.load(Ordering::SeqCst) {
                    break;
                }
                consecutive_errors = consecutive_errors.saturating_add(1);
                // Exponential backoff 100 ms -> 5 s keeps a persistent socket error from
                // becoming a 10 Hz warning loop.
                let backoff = rx_error_backoff(consecutive_errors);
                if consecutive_errors <= 3 || consecutive_errors.is_power_of_two() {
                    warn!("rx: socket error ({consecutive_errors} in a row, next poll in {backoff:?}): {e}");
                }
                if !sleep_unless_stopped(&shared, backoff) {
                    break;
                }
            }
        }
        if last_evict.elapsed() >= Duration::from_secs(5) {
            fragments.evict_stale();
            last_evict = Instant::now();
        }
    }
    if !shared.stop.load(Ordering::SeqCst) {
        shared.mark_dead("rx thread exited");
    }
    debug!("rx thread stopped");
}

/// Backoff after the `n`-th consecutive receive error: `100 ms * 2^(n-1)`, capped at 5 s.
fn rx_error_backoff(n: u32) -> Duration {
    Duration::from_millis(100u64.saturating_mul(1u64 << n.saturating_sub(1).min(6))).min(Duration::from_secs(5))
}

/// Decapsulate one ESP datagram and hand the inner IP packet to the smoltcp stack.
fn handle_esp(shared: &Shared, packet: &[u8]) {
    let spi = match packet.get(0..4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => {
            debug!("rx: runt ESP datagram ({} bytes)", packet.len());
            return;
        }
    };
    let inner = {
        let mut sas = lock(&shared.inbound);
        let Some(sa) = sas.iter_mut().find(|sa| sa.spi() == spi) else {
            debug!("rx: ESP for unknown SPI {spi:#010x} ({} bytes)", packet.len());
            return;
        };
        match sa.decapsulate(packet) {
            Ok(inner) => inner,
            Err(Error::Integrity(_)) => {
                shared.counters.icv_failures.fetch_add(1, Ordering::Relaxed);
                warn!("rx: ESP ICV failure on SPI {spi:#010x}");
                return;
            }
            Err(Error::Protocol(msg)) if msg.contains("replay") => {
                shared.counters.replay_drops.fetch_add(1, Ordering::Relaxed);
                debug!("rx: {msg}");
                return;
            }
            Err(e) => {
                debug!("rx: ESP decapsulation failed on SPI {spi:#010x}: {e}");
                return;
            }
        }
    };
    shared.counters.esp_rx_packets.fetch_add(1, Ordering::Relaxed);
    shared.counters.esp_rx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
    trace!("rx: inner IP packet {} bytes -> stack", inner.len());
    // No parsing here: smoltcp classifies, reassembles (IPv4) and delivers.
    shared.stack.push_rx(inner);
}

fn handle_ike_datagram(shared: &Shared, datagram: Vec<u8>, fragments: &mut FragmentCollector) {
    debug!("rx IKE datagram ({} bytes): {}", datagram.len(), hex::encode(&datagram));
    let header = match IkeHeader::decode(&datagram) {
        Ok(h) => h,
        Err(e) => {
            warn!("rx: undecodable IKE header: {e}");
            return;
        }
    };
    let set: Vec<Vec<u8>> = if is_fragment(&datagram) {
        match fragments.push(&datagram) {
            Ok(Some(set)) => set,
            Ok(None) => return,
            Err(e) => {
                warn!("rx: bad SKF fragment: {e}");
                return;
            }
        }
    } else {
        vec![datagram]
    };

    let mut ike = lock(&shared.ike);
    let msg = match ike.decode(&set) {
        Ok(m) => m,
        Err(e) => {
            warn!("rx: IKE message (exch {} msgid {}) rejected: {e}", header.exchange_type, header.message_id);
            return;
        }
    };

    if header.is_response() {
        drop(ike);
        let mut slot = lock(&shared.pending);
        match slot.as_mut() {
            Some(s) if s.spi_i == header.spi_i && s.message_id == header.message_id => {
                if s.response.is_some() {
                    debug!("rx: duplicate response msgid {}; dropped", header.message_id);
                } else {
                    s.response = Some(msg);
                    shared.pending_cv.notify_all();
                }
            }
            _ => warn!("rx: unsolicited IKE response (exch {} msgid {}) dropped", header.exchange_type, header.message_id),
        }
        return;
    }

    // Peer-initiated request.
    let (reply, event) = match ike.handle_peer_request(&msg) {
        Ok(v) => v,
        Err(e) => {
            warn!("rx: peer request (exch {} msgid {}) not handled: {e}", header.exchange_type, header.message_id);
            return;
        }
    };
    let datagrams = match ike.encode(&reply) {
        Ok(d) => d,
        Err(e) => {
            warn!("rx: cannot encode response to peer request: {e}");
            return;
        }
    };
    drop(ike);
    for d in &datagrams {
        if let Err(e) = shared.transport.send_ike(d) {
            warn!("rx: sending response to peer request failed: {e}");
        }
    }
    match event {
        PeerEvent::Dpd => {
            shared.counters.peer_dpd_answered.fetch_add(1, Ordering::Relaxed);
            info!("peer DPD answered (msgid {})", header.message_id);
        }
        PeerEvent::DeleteIke => {
            info!("peer deleted the IKE SA");
            shared.mark_dead("IKE SA deleted by the gateway");
        }
        PeerEvent::DeleteChild(spis) => {
            info!("peer deleted child SA(s) {:?}", spis.iter().map(|s| format!("{s:#010x}")).collect::<Vec<_>>());
            let mut sas = lock(&shared.inbound);
            sas.retain(|sa| !spis.contains(&sa.spi()));
            if sas.is_empty() {
                drop(sas);
                shared.mark_dead("child SA deleted by the gateway");
            }
        }
        PeerEvent::Notify(notifies) => {
            for n in &notifies {
                info!("peer notify {} ({} bytes)", n.notify_type, n.data.len());
            }
        }
        PeerEvent::Other => debug!("peer request exch {} msgid {} answered", header.exchange_type, header.message_id),
    }
}

/// Sleep `d` in slices, returning early (false) when the tunnel is stopping.
fn sleep_unless_stopped(shared: &Shared, d: Duration) -> bool {
    let deadline = Instant::now() + d;
    while !shared.stop.load(Ordering::SeqCst) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(TICK_SLICE));
    }
    false
}

fn keepalive_loop(shared: Arc<Shared>) {
    if !shared.transport.using_natt() {
        warn!("not on the NAT-T port; NAT-T keepalives disabled");
        return;
    }
    let interval = interval_secs(shared.cfg.ike.natt.keepalive_interval_secs);
    // Continue the cadence started at the switch to 4500 (the handshake ticker's slots).
    let mut next = next_keepalive(shared.natt_since, interval, Instant::now());
    while !shared.stop.load(Ordering::SeqCst) {
        let wait = next.saturating_duration_since(Instant::now());
        if !sleep_unless_stopped(&shared, wait) {
            break;
        }
        next = next_keepalive(shared.natt_since, interval, Instant::now());
        if !shared.alive.load(Ordering::SeqCst) {
            continue;
        }
        match shared.transport.send_keepalive() {
            Ok(()) => {
                let n = shared.counters.keepalives_sent.fetch_add(1, Ordering::Relaxed) + 1;
                debug!("NAT-T keepalive #{n} sent");
            }
            Err(e) => warn!("NAT-T keepalive failed: {e}"),
        }
    }
    debug!("keepalive thread stopped");
}

fn timer_loop(shared: Arc<Shared>) {
    let cfg = &shared.cfg;
    let child_soft = soft_lifetime(cfg.child.lifetime_secs, cfg.ike.rekey_margin_fraction);
    let ike_soft = soft_lifetime(cfg.ike.lifetime_secs, cfg.ike.rekey_margin_fraction);
    let dpd_interval = interval_secs(cfg.ike.dpd.interval_secs);
    let dpd_retry = Duration::from_secs(cfg.ike.dpd.retry_interval_secs).min(MAX_INTERVAL);
    info!(
        "timer: child rekey in {:?}, IKE rekey in {:?}, DPD {}",
        child_soft,
        ike_soft,
        if cfg.ike.dpd.enabled { format!("after {:?} idle", dpd_interval) } else { "disabled".into() }
    );
    let mut child_retry_after: Option<Instant> = None;
    let mut ike_retry_after: Option<Instant> = None;

    while sleep_unless_stopped(&shared, TIMER_TICK) {
        if !shared.alive.load(Ordering::SeqCst) {
            continue;
        }

        // Dead peer detection.
        if cfg.ike.dpd.enabled && shared.idle_for() >= dpd_interval {
            let mut ok = false;
            for attempt in 0..=cfg.ike.dpd.max_retries {
                match do_dpd(&shared, &cfg.ike.retransmit) {
                    Ok(_) => {
                        ok = true;
                        break;
                    }
                    Err(Error::Timeout(_)) if attempt < cfg.ike.dpd.max_retries => {
                        warn!("DPD attempt {}/{} timed out; retrying in {:?}", attempt + 1, cfg.ike.dpd.max_retries + 1, dpd_retry);
                        if !sleep_unless_stopped(&shared, dpd_retry) {
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("DPD failed: {e}");
                        break;
                    }
                }
            }
            if !ok {
                // AOSP: torn down WITHOUT sending DELETE.
                shared.mark_dead("dead peer detection failed");
                continue;
            }
        }

        // Child SA rekey at the soft lifetime.
        let child_due = lock(&shared.child_created).elapsed() >= child_soft
            && child_retry_after.is_none_or(|t| Instant::now() >= t);
        if child_due {
            match rekey_child(&shared) {
                Ok(()) => child_retry_after = None,
                Err(Error::Timeout(what)) => {
                    shared.mark_dead(format!("child rekey: no response to {what}"));
                    continue;
                }
                Err(e) => {
                    warn!("child rekey failed: {e}; retrying in {:?}", REKEY_RETRY_DELAY);
                    child_retry_after = Some(Instant::now() + REKEY_RETRY_DELAY);
                }
            }
        }

        // IKE SA rekey at the soft lifetime.
        let ike_due = lock(&shared.ike_created).elapsed() >= ike_soft
            && ike_retry_after.is_none_or(|t| Instant::now() >= t);
        if ike_due {
            match rekey_ike(&shared) {
                Ok(()) => ike_retry_after = None,
                Err(Error::Timeout(what)) => {
                    shared.mark_dead(format!("IKE rekey: no response to {what}"));
                }
                Err(e) => {
                    warn!("IKE rekey failed: {e}; retrying in {:?}", REKEY_RETRY_DELAY);
                    ike_retry_after = Some(Instant::now() + REKEY_RETRY_DELAY);
                }
            }
        }
    }
    debug!("timer thread stopped");
}

// ---------------------------------------------------------------------------
// EpdgTunnel
// ---------------------------------------------------------------------------

impl EpdgTunnel {
    /// Resolve the gateway and bring the tunnel up against the first address that works.
    pub fn connect(cfg: &Config) -> Result<EpdgTunnel> {
        let candidates = cfg.gateway_candidates()?;
        info!("gateway {} candidates: {:?}", cfg.gateway.hostname, candidates);
        let mut last_err: Option<Error> = None;
        for (i, gateway) in candidates.iter().enumerate() {
            info!("candidate {}/{}: {}", i + 1, candidates.len(), gateway);
            match connect_candidate(cfg, *gateway) {
                Ok(t) => return Ok(t),
                Err(e) if is_candidate_specific(&e) && i + 1 < candidates.len() => {
                    warn!("candidate {gateway} failed: {e}; trying the next one");
                    last_err = Some(e);
                }
                Err(e) => {
                    error!("connection to {gateway} failed: {e}");
                    return Err(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Config("no gateway candidates".into())))
    }

    pub fn info(&self) -> &TunnelInfo {
        &self.info
    }

    /// Create an inner UDP socket. `local_port == 0` picks a free port in
    /// `49152..=65535`. smoltcp picks the source address by destination family.
    pub fn bind_udp(&self, local_port: u16) -> Result<InnerUdpSocket> {
        if !self.shared.is_alive() {
            return Err(self.shared.closed_error());
        }
        self.shared.stack.bind_udp(local_port)
    }

    /// Resolve `name` over the tunnel with the gateway-assigned DNS servers (smoltcp
    /// DNS socket): AAAA then A, skipping a family we have no inner address for.
    /// `Error::Timeout` when nothing answered within `timeout`.
    pub fn resolve(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>> {
        if !self.shared.is_alive() {
            return Err(self.shared.closed_error());
        }
        self.shared.stack.resolve(name, timeout)
    }

    /// True while the IKE SA is up (no peer DELETE, no DPD failure, not closed).
    pub fn is_alive(&self) -> bool {
        self.shared.is_alive()
    }

    /// On-demand liveness check (empty INFORMATIONAL); returns the round-trip time.
    pub fn dpd(&self) -> Result<Duration> {
        let r = do_dpd(&self.shared, &self.shared.cfg.ike.retransmit);
        if let Err(Error::Timeout(_)) = &r {
            // AOSP: retransmission exhaustion tears the session down WITHOUT a DELETE.
            self.shared.mark_dead("dead peer detection failed");
        }
        r
    }

    pub fn stats(&self) -> TunnelStats {
        self.shared.stats()
    }

    /// Send `DELETE(IKE)` (best effort, short timeout) and stop the threads.
    pub fn close(mut self) -> Result<()> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let shared = &self.shared;
        let result = if shared.is_alive() {
            let policy = RetransmitConfig {
                initial_timeout_ms: shared.cfg.ike.retransmit.initial_timeout_ms,
                backoff_multiplier: shared.cfg.ike.retransmit.backoff_multiplier,
                max_attempts: CLOSE_ATTEMPTS,
            };
            info!("closing tunnel: DELETE(IKE)");
            let r = ike_request(shared, "DELETE(IKE)", &policy, |ike| ike.build_delete_ike())
                .and_then(|resp| settle(shared, |ike| ike.handle_informational_response(&resp)));
            match r {
                Ok(()) => {
                    info!("IKE SA deleted");
                    Ok(())
                }
                // The gateway's own DELETE(IKE) crossed ours: the rx thread answered it and
                // marked the tunnel dead — a clean teardown by both sides.
                Err(Error::Closed(reason)) if reason.contains("deleted by the gateway") => {
                    info!("IKE SA deleted by the gateway while our DELETE was outstanding");
                    Ok(())
                }
                Err(e) => {
                    warn!("DELETE(IKE) not acknowledged: {e}");
                    Err(e)
                }
            }
        } else {
            debug!("close: tunnel already dead ({:?})", lock(&shared.dead_reason));
            Ok(())
        };
        shared.alive.store(false, Ordering::SeqCst);
        shared.stop.store(true, Ordering::SeqCst);
        shared.pending_cv.notify_all();
        shared.stack.close("tunnel closed");
        for h in [self.rx_thread.take(), self.keepalive_thread.take(), self.timer_thread.take(), self.stack_thread.take()]
            .into_iter()
            .flatten()
        {
            if h.join().is_err() {
                warn!("a tunnel thread panicked");
            }
        }
        info!("tunnel closed; stats: {:?}", shared.stats());
        result
    }
}

impl Drop for EpdgTunnel {
    fn drop(&mut self) {
        if !self.closed {
            if let Err(e) = self.shutdown() {
                debug!("drop: close failed: {e}");
            }
        }
    }
}

impl std::fmt::Debug for EpdgTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpdgTunnel").field("info", &self.info).field("alive", &self.is_alive()).finish()
    }
}

// ---------------------------------------------------------------------------
// Tests (offline)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn retransmit_schedule_matches_aosp() {
        let p = RetransmitConfig { initial_timeout_ms: 500, backoff_multiplier: 2.0, max_attempts: 5 };
        let waits: Vec<u64> = (0..5).map(|a| retransmit_timeout(&p, a).as_millis() as u64).collect();
        assert_eq!(waits, vec![500, 1000, 2000, 4000, 8000]);
        let bad = RetransmitConfig { initial_timeout_ms: 300, backoff_multiplier: f64::NAN, max_attempts: 2 };
        assert_eq!(retransmit_timeout(&bad, 3), Duration::from_millis(300));
    }

    #[test]
    fn soft_lifetime_has_no_jitter_and_clamps_margin() {
        assert_eq!(soft_lifetime(80000, 0.1), Duration::from_secs(72000));
        assert_eq!(soft_lifetime(3600, 0.0), Duration::from_secs(3600));
        assert_eq!(soft_lifetime(1000, 5.0), Duration::from_secs(100)); // margin clamped to 0.9
        assert_eq!(soft_lifetime(1000, -1.0), Duration::from_secs(1000)); // clamped to 0
        assert_eq!(soft_lifetime(1000, f64::NAN), Duration::from_secs(900)); // default 0.1
    }

    #[test]
    fn candidate_specific_errors() {
        assert!(is_candidate_specific(&Error::Timeout("x")));
        assert!(is_candidate_specific(&Error::Io(std::io::Error::other("x"))));
        assert!(!is_candidate_specific(&Error::AuthFailed("x".into())));
        assert!(!is_candidate_specific(&Error::Eap("x".into())));
        assert!(!is_candidate_specific(&Error::Config("x".into())));
        assert!(!is_candidate_specific(&Error::PeerNotify { notify_type: 24, name: "AUTHENTICATION_FAILED", exchange: "IKE_AUTH", data: vec![] }));
    }

    /// A minimal SKF datagram: IKE header (next payload SKF) + generic payload header +
    /// fragment number / total. Enough for `fragment_info` and the collector.
    fn skf_datagram(spi_i: u64, msgid: u32, response: bool, num: u16, total: u16) -> Vec<u8> {
        let flags = FLAG_INITIATOR | if response { FLAG_RESPONSE } else { 0 };
        let body_len = 4 + 4 + 16; // generic hdr + frag nums + fake IV/data
        let hdr = IkeHeader {
            spi_i,
            spi_r: 0x1122334455667788,
            next_payload: PT_SKF,
            version: 0x20,
            exchange_type: EXCH_INFORMATIONAL,
            flags,
            message_id: msgid,
            length: (IKE_HEADER_LEN + body_len) as u32,
        };
        let mut out = Vec::new();
        hdr.encode(&mut out);
        out.push(PT_NONE);
        out.push(0);
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        out.extend_from_slice(&num.to_be_bytes());
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&[num as u8; 16]);
        out
    }

    #[test]
    fn fragment_collector_completes_in_order_and_ignores_duplicates() {
        let mut c = FragmentCollector::new();
        let f1 = skf_datagram(7, 3, true, 1, 3);
        let f2 = skf_datagram(7, 3, true, 2, 3);
        let f3 = skf_datagram(7, 3, true, 3, 3);
        assert!(c.push(&f3).unwrap().is_none());
        assert!(c.push(&f1).unwrap().is_none());
        assert!(c.push(&f1).unwrap().is_none()); // duplicate
        let set = c.push(&f2).unwrap().expect("complete");
        assert_eq!(set, vec![f1.clone(), f2.clone(), f3.clone()]);
        assert!(c.sets.is_empty());
    }

    #[test]
    fn fragment_collector_keys_by_spi_msgid_and_direction() {
        let mut c = FragmentCollector::new();
        assert!(c.push(&skf_datagram(7, 3, true, 1, 2)).unwrap().is_none());
        assert!(c.push(&skf_datagram(7, 3, false, 2, 2)).unwrap().is_none()); // a request, not the response
        assert!(c.push(&skf_datagram(8, 3, true, 2, 2)).unwrap().is_none()); // other SA
        assert!(c.push(&skf_datagram(7, 4, true, 2, 2)).unwrap().is_none()); // other msgid
        assert_eq!(c.sets.len(), 4);
        assert!(c.push(&skf_datagram(7, 3, true, 2, 2)).unwrap().is_some());
        assert_eq!(c.sets.len(), 3);
    }

    #[test]
    fn fragment_collector_rejects_bad_numbers_and_total_changes() {
        let mut c = FragmentCollector::new();
        assert!(c.push(&skf_datagram(1, 1, true, 0, 2)).is_err());
        assert!(c.push(&skf_datagram(1, 1, true, 3, 2)).is_err());
        assert!(c.push(&skf_datagram(1, 1, true, 1, 2)).unwrap().is_none());
        assert!(c.push(&skf_datagram(1, 1, true, 2, 3)).is_err());
        assert!(c.sets.is_empty(), "set dropped after a total mismatch");
        assert!(c.push(&[0u8; 10]).is_err(), "runt datagram");
    }

    #[test]
    fn fragment_collector_evicts_stale_sets() {
        let mut c = FragmentCollector::new();
        assert!(c.push(&skf_datagram(1, 1, true, 1, 2)).unwrap().is_none());
        c.evict_stale();
        assert_eq!(c.sets.len(), 1, "fresh sets are kept");
        for s in c.sets.values_mut() {
            s.started = Instant::now() - FRAGMENT_SET_TTL - Duration::from_secs(1);
        }
        c.evict_stale();
        assert!(c.sets.is_empty());
    }

    #[test]
    fn stats_default_is_zero() {
        let s = TunnelStats::default();
        assert_eq!(s.keepalives_sent, 0);
        assert_eq!(s.esp_rx_packets, 0);
        assert_eq!(s.rx_queue_drops, 0);
        assert_eq!(s.stack, StackStats::default());
        assert!(s.last_rx.is_none());
    }

    #[test]
    fn keepalive_cadence_is_anchored_at_the_natt_switch() {
        let anchor = Instant::now();
        let iv = Duration::from_secs(10);
        // Started right at the switch: the next slot is anchor + 10 s, not now + 10 s.
        assert_eq!(next_keepalive(anchor, iv, anchor), anchor + iv);
        assert_eq!(next_keepalive(anchor, iv, anchor + Duration::from_secs(3)), anchor + iv);
        // Started 25 s after the switch (long IKE_AUTH): continue on the 30 s slot.
        assert_eq!(next_keepalive(anchor, iv, anchor + Duration::from_secs(25)), anchor + Duration::from_secs(30));
        // Exactly on a slot: strictly after `now`.
        assert_eq!(next_keepalive(anchor, iv, anchor + iv), anchor + Duration::from_secs(20));
    }

    #[test]
    fn config_intervals_are_clamped() {
        assert_eq!(interval_secs(0), Duration::from_secs(1));
        assert_eq!(interval_secs(10), Duration::from_secs(10));
        assert_eq!(interval_secs(u64::MAX), MAX_INTERVAL);
        // Must not overflow `Instant + Duration`.
        let _ = Instant::now() + interval_secs(u64::MAX);
        let _ = next_keepalive(Instant::now(), interval_secs(u64::MAX), Instant::now());
    }

    #[test]
    fn rx_error_backoff_grows_and_caps() {
        assert_eq!(rx_error_backoff(1), Duration::from_millis(100));
        assert_eq!(rx_error_backoff(2), Duration::from_millis(200));
        assert_eq!(rx_error_backoff(4), Duration::from_millis(800));
        assert_eq!(rx_error_backoff(7), Duration::from_secs(5));
        assert_eq!(rx_error_backoff(u32::MAX), Duration::from_secs(5));
    }

    #[test]
    fn run_guarded_reports_panics() {
        let mut seen = None;
        assert!(run_guarded(|| {}, |m| seen = Some(m)));
        assert!(seen.is_none());
        assert!(!run_guarded(|| panic!("boom {}", 42), |m| seen = Some(m)));
        assert_eq!(seen.as_deref(), Some("boom 42"));
        assert!(!run_guarded(|| std::panic::panic_any(7u8), |m| seen = Some(m)));
        assert_eq!(seen.as_deref(), Some("non-string panic payload"));
    }

    /// A `Shared` over a loopback socket that never sends anything: enough to exercise
    /// the thread plumbing without a gateway.
    fn test_shared() -> Arc<Shared> {
        let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
        let cfg = Config::from_plist_files(
            std::path::Path::new(&format!("{fx}tmobile_prod_bundle.plist")),
            std::path::Path::new(&format!("{fx}tmobile_creds.plist")),
            std::path::Path::new(&format!("{fx}client.crt")),
            std::path::Path::new(&format!("{fx}client.key")),
        )
        .unwrap();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let transport = IkeTransport::bind(Some(lo), lo, 500).unwrap();
        let ike = IkeInitiator::new(&cfg, transport.local_addr(), transport.remote_addr()).unwrap();
        let sa = || EspSa {
            spi: 0x1234_5678,
            cipher: registry::cipher(ENCR_AES_CBC, Some(256)).unwrap(),
            integrity: registry::integrity(AUTH_HMAC_SHA2_256_128).unwrap(),
            enc_key: vec![1; 32],
            auth_key: vec![2; 32],
        };
        let now = Instant::now();
        let transport = Arc::new(transport);
        let outbound = Arc::new(RwLock::new(Arc::new(EspOutbound::new(sa()))));
        let counters = Arc::new(Counters::default());
        let stack = InnerStack::new(&AssignedConfig::default(), esp_sink(&transport, &outbound, &counters), 1280).unwrap();
        Arc::new(Shared {
            cfg,
            transport,
            ike: Mutex::new(ike),
            request_lock: Mutex::new(()),
            pending: Mutex::new(None),
            pending_cv: Condvar::new(),
            outbound,
            inbound: Mutex::new(vec![EspInbound::new(sa(), 64)]),
            stack,
            alive: AtomicBool::new(true),
            stop: AtomicBool::new(false),
            dead_reason: Mutex::new(None),
            counters,
            last_rx: Mutex::new(Some(now)),
            child_created: Mutex::new(now),
            ike_created: Mutex::new(now),
            natt_since: now,
        })
    }

    #[test]
    fn a_panicking_tunnel_thread_marks_the_tunnel_dead() {
        let shared = test_shared();
        assert!(shared.is_alive());
        // A waiter on the pending slot must be woken with Error::Closed, not hang.
        let waiter = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut slot = lock(&shared.pending);
                let deadline = Instant::now() + Duration::from_secs(10);
                while shared.is_alive() && Instant::now() < deadline {
                    slot = shared.pending_cv.wait_timeout(slot, Duration::from_millis(100)).unwrap().0;
                }
                shared.is_alive()
            })
        };
        let h = spawn_named("epdg-test", Arc::clone(&shared), |_| panic!("hostile datagram")).unwrap();
        assert!(h.join().is_ok(), "the guard swallows the panic");
        assert!(!shared.is_alive());
        assert!(shared.stop.load(Ordering::SeqCst), "the other threads are told to stop");
        let reason = lock(&shared.dead_reason).clone().unwrap();
        assert!(reason.contains("epdg-test thread panicked") && reason.contains("hostile datagram"), "{reason}");
        assert!(!waiter.join().unwrap(), "waiter observed the dead tunnel");
        assert!(matches!(shared.closed_error(), Error::Closed(_)));
    }

    #[test]
    fn rx_thread_exit_marks_the_tunnel_dead_unless_stopping() {
        let shared = test_shared();
        // A normal stop: not dead by the rx thread's exit.
        shared.stop.store(true, Ordering::SeqCst);
        rx_loop(Arc::clone(&shared));
        assert!(lock(&shared.dead_reason).is_none());
    }
}
