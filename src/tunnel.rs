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
//!   `max_retries` × `retry_interval_secs`; the one-way-traffic probe once
//!   [`ONE_WAY_PROBE_SILENCE`] has passed since the FIRST transmission that followed the
//!   last inbound IKE/ESP datagram, and the [`IDLE_PROBE_SILENCE`] probe for a tunnel that
//!   never transmits at all (both independent of the bundle's DPD flag, which operators
//!   often clear); the child rekey the path monitor asks for after a move it could not
//!   verify; child rekey then IKE rekey at the soft lifetime
//!   `lifetime × (1 − rekey_margin_fraction)` (no jitter, like AOSP). A rekey that fails
//!   while the path monitor is repairing the path is retried, never read as a dead peer.
//!   This is the thread that is allowed to block for a retransmit schedule.
//! - **path** (`epdg-path`): mobility (DESIGN §17). Every [`PATH_PROBE_INTERVAL`] — and
//!   immediately on [`EpdgTunnel::network_changed`] or a failed outer send — it re-runs
//!   the egress route probe. A changed address rebinds the outer socket (same SAs, same
//!   keys, new 5-tuple) and announces it with MOBIKE `UPDATE_SA_ADDRESSES` (RFC 4555
//!   §3.5), or with an empty INFORMATIONAL when the peer has no MOBIKE (the RFC 7296
//!   §2.23 dynamic address update). A path it cannot repair within [`NO_ROUTE_GRACE`]
//!   marks the tunnel dead, which fails every inner socket with `Error::Closed` so the
//!   SIP transport above tears its connection down. It never runs a blocking exchange
//!   itself beyond the announce (which is abandoned at the grace deadline): it is the only
//!   thread that enforces the grace, so the child rekeys a non-MOBIKE move can call for
//!   are handed to the timer thread, which reports each outcome back.
//!
//! All post-establishment IKE requests go through one `ike_request` helper that
//! serialises on a mutex (one outstanding request), retransmits per the configured
//! policy and gets its response from the rx thread's pending slot. It also takes an
//! optional abort predicate, so a request abandons within one tick when the path moved
//! under it (its source address no longer exists, and its silence says nothing about the
//! gateway) or when `close()` has started. Nothing here logs key material.
//!
//! **Death propagation** (DESIGN §17.6). When the tunnel becomes unrecoverable —
//! a peer `DELETE(IKE)`, a DPD or one-way probe that went unanswered, a rekey that timed
//! out, a path that could not be repaired within [`NO_ROUTE_GRACE`], a thread panic —
//! `mark_dead(reason)` publishes the reason and closes the inner stack. That drops every
//! inner UDP binding's sender, so a blocked `InnerUdpSocket::recv_timeout` returns
//! `Error::Closed(reason)` **immediately** rather than at its own timeout, pending
//! resolvers are completed with the same error, and every later `send_to` / `bind_udp` /
//! `resolve` fails the same way. Through `netstack::to_io` that is
//! `io::ErrorKind::NotConnected` with the reason still in the error's `Display`, which is
//! what a SIP transport above turns into a close event and a fresh connection. It is
//! idempotent and the first reason wins, so a deliberate `close()` (reason
//! `"tunnel closed by request"`) never relabels a tunnel that died of a real failure.
//!
//! Tunables live here as documented `pub const`s rather than as config fields, because
//! the config structs are built with exhaustive struct literals by embedders:
//! [`PATH_PROBE_INTERVAL`], [`PATH_PROBE_MIN_SPACING`], [`NO_ROUTE_GRACE`],
//! [`ONE_WAY_PROBE_SILENCE`], [`IDLE_PROBE_SILENCE`], [`MIN_ADDRESS_UPDATE_INTERVAL`],
//! [`ESP_SEND_ERROR_LOG_INTERVAL`], [`PROBE_ERROR_LOG_INTERVAL`], [`SPEND_MSGID_ATTEMPTS`],
//! [`ESP_MIGRATION_REKEY_ATTEMPTS`] (and [`crate::ike::transport::OUTER_SEND_TIMEOUT`]).

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
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

// --- Mobility and liveness tunables (DESIGN §17) ---------------------------------
//
// Every value below is the AOSP-compatible default we ship; change the const and
// rebuild. Why consts and not config fields: see the module docs.

/// How often the path monitor re-runs the route probe toward the gateway
/// ([`IkeTransport::probe_egress`]: one bind + connect on a throwaway socket, no
/// packets). 2 s — fast enough that a Wi-Fi/LTE handover is announced long before the
/// SIP registration expires, cheap enough to run for the life of the tunnel.
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Floor between probes when one is requested out of band (an outer send that failed
/// with a path error). 250 ms — a downed interface can fail thousands of ESP sends per
/// second and each one records a path error; without this floor the monitor would spin
/// on `bind`. [`EpdgTunnel::network_changed`] bypasses it, being caller-driven and rare.
pub const PATH_PROBE_MIN_SPACING: Duration = Duration::from_millis(250);

/// How long the tunnel tolerates an impaired path — no route at all, a rebind that keeps
/// failing, an address the gateway will not acknowledge, or an outer socket whose sends
/// all fail — before it is declared unrecoverable. 30 s: survives a screen-off Wi-Fi blip
/// or a re-association without tearing down the SIP registration, and comfortably
/// contains the 15.5 s default retransmit schedule.
pub const NO_ROUTE_GRACE: Duration = Duration::from_secs(30);

/// One-way-traffic threshold: once this long has passed since the FIRST IKE/ESP
/// transmission that followed the last inbound IKE/ESP datagram (NAT-T keepalives count
/// on neither side), one DPD probe runs regardless of `cfg.ike.dpd.enabled`. 20 s.
/// Operator bundles routinely disable DPD (the T-Mobile one does), so in practice this is
/// the only automatic liveness check — including for a child SA that was one-way from the
/// start, where nothing has ever been received.
pub const ONE_WAY_PROBE_SILENCE: Duration = Duration::from_secs(20);

/// How long an otherwise silent tunnel may go without hearing anything from the gateway
/// before one DPD probe runs, independent of `cfg.ike.dpd.enabled`. 120 s.
///
/// [`ONE_WAY_PROBE_SILENCE`] needs evidence that we transmitted, which a registered but
/// idle IMS tunnel never produces (NAT-T keepalives deliberately do not count, and the
/// SIP layer may be quiet for minutes between registration refreshes). Without this an
/// operator bundle that disables DPD — the T-Mobile one does — would leave such a tunnel
/// with no liveness check at all: the gateway could drop the SA and nothing would notice
/// until the next outgoing request. 120 s is long enough to be free on a tunnel that
/// already sends a keepalive every 10 s, short enough that an incoming call is not lost
/// for minutes.
pub const IDLE_PROBE_SILENCE: Duration = Duration::from_secs(120);

/// Minimum spacing between address updates. 5 s: a flapping default route on a
/// dual-homed host would otherwise issue one `UPDATE_SA_ADDRESSES` — invalidating the
/// gateway's NAT binding each time — every probe interval, which ePDGs rate-limit.
///
/// The first move after a quiet period — a Wi-Fi/LTE handover, the case this feature
/// exists for — passes immediately; only a second move inside the window waits.
///
/// It damps the rebind that RECOVERS from an impairment on the address we are already
/// bound to as well, not just a move to a different address: a link that flaps between
/// "no route" and the same address alternates those two branches, and an out-of-band
/// probe request (every failing send asks for one) makes the cycle as short as
/// [`PATH_PROBE_MIN_SPACING`].
pub const MIN_ADDRESS_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

/// Minimum spacing between "ESP send failed" warnings. 5 s — that path runs per
/// datagram; the other error sites (keepalive, IKE request) are rare enough to log
/// unconditionally.
pub const ESP_SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// Minimum spacing between "cannot probe the egress route" warnings. 60 s: the causes
/// (EMFILE under fd pressure, a sandbox or MDM denying the throwaway probe socket) are
/// usually PERMANENT, and such a probe deliberately never impairs the tunnel — so the
/// loop keeps running, and logging it once per [`PATH_PROBE_INTERVAL`] for the life of a
/// registration would be pure spam.
pub const PROBE_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Transmissions the DPD that spends an abandoned message id gets before `announce`
/// gives up on it and sends the address update on that id anyway (DESIGN §17.2).
///
/// 2 (≈1.5 s with the default schedule) rather than the full 5 (≈15.5 s): the spend is a
/// courtesy, not the point of the exchange. A silent gateway — the dominant announce
/// failure — cannot answer it, and a spend that owned the whole schedule would spend
/// [`NO_ROUTE_GRACE`] transmitting empty INFORMATIONALs instead of the
/// `UPDATE_SA_ADDRESSES` the move actually needs.
pub const SPEND_MSGID_ATTEMPTS: u32 = 2;

/// Child-SA rekeys the non-MOBIKE ESP-migration escalation attempts per move before the
/// tunnel is declared dead (DESIGN §17.3).
///
/// 2: the gateway's normal answer while it is rekeying on its own is
/// `N(TEMPORARY_FAILURE)` (RFC 7296 §2.25), which is worth one retry — but a child SA
/// that stays black-holed after the move is invisible to every liveness check (the IKE
/// SA answers, so the probes are satisfied), so the escalation must end in death rather
/// than be silently forgotten.
///
/// Only a rekey that REACHED the gateway spends an attempt — a completed one included,
/// since a gateway that answers the CREATE_CHILD_SA on the (moved) IKE SA may still
/// leave ESP black-holed. One the path monitor abandoned before it was sent spends
/// nothing (DESIGN §17.3/§17.4).
pub const ESP_MIGRATION_REKEY_ATTEMPTS: u32 = 2;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Everything worth knowing about an established tunnel.
#[derive(Clone, Debug)]
pub struct TunnelInfo {
    /// The outer socket's local address **at establishment**. It moves when the path
    /// monitor rebinds; use [`EpdgTunnel::local_addr`] for the current one.
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// True when the responder announced `MOBIKE_SUPPORTED` (RFC 4555 §3.1). That is all
    /// it says: whether an address change actually goes out as `UPDATE_SA_ADDRESSES`
    /// rather than as the RFC 7296 §2.23 fallback is `peer_mobike && ike.mobike`, so a
    /// caller that turned `ike.mobike` off still sees this flag set on a MOBIKE gateway.
    pub peer_mobike: bool,
    /// The gateway's NAT verdict **at establishment** (`IKE_SA_INIT`). A MOBIKE address
    /// update re-runs NAT detection and can replace it — notably with "no NAT detected",
    /// which predicts UDP-encapsulated ESP breaking; use [`EpdgTunnel::nat`] for the
    /// current one.
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
    /// Successful address updates (MOBIKE `UPDATE_SA_ADDRESSES` or the RFC 7296 §2.23
    /// fallback) since establishment — i.e. how often the tunnel moved (DESIGN §17).
    pub address_updates: u64,
    /// Datagrams dropped because they did not come from the gateway's address.
    pub stray_sources: u64,
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
    path_thread: Option<JoinHandle<()>>,
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
    address_updates: AtomicU64,
}

/// Mobility state shared by the path thread, the rx/keepalive/timer threads and the ESP
/// TX sink (DESIGN §17). One mutex holds every clock the decision core reads, so a tick
/// sees a consistent picture; the flags the abort closures poll are atomics, because
/// those run while the `pending` mutex is held.
#[derive(Default)]
struct PathState {
    inner: Mutex<PathInner>,
    cv: Condvar,
    /// True from the moment the monitor decides to move (or repair) the path until the
    /// gateway has acknowledged the new address. A request outstanding across that was
    /// sent from an address that no longer exists, so its silence says nothing about the
    /// peer, and liveness checks must stay out of the way.
    suspended: AtomicBool,
    /// The handshake for the post-move child rekey (DESIGN §17.3): the path thread
    /// decides, the timer thread executes — it is allowed to block for a retransmit
    /// schedule, the path thread is not, being the only one that enforces
    /// [`NO_ROUTE_GRACE`]. [`ESP_REKEY_IDLE`] → [`ESP_REKEY_REQUESTED`] → either
    /// [`ESP_REKEY_DONE`] or [`ESP_REKEY_FAILED`], both of which the path thread takes to
    /// re-arm the escalation instead of leaving a black-holed child SA behind. A rekey
    /// the timer thread abandoned before it reached the gateway reports NOTHING and
    /// simply re-requests itself.
    esp_rekey: AtomicU8,
}

/// Nothing outstanding.
const ESP_REKEY_IDLE: u8 = 0;
/// The path thread asked for a child rekey; the timer thread has not taken it yet.
const ESP_REKEY_REQUESTED: u8 = 1;
/// The timer thread ran the rekey and it did not complete (non-fatally).
const ESP_REKEY_FAILED: u8 = 2;
/// The timer thread ran the rekey and the gateway completed it. NOT proof that ESP was
/// restored — only that the exchange happened — so the path thread re-arms the stall
/// check against a fresh window rather than treating the move as repaired (DESIGN §17.3).
const ESP_REKEY_DONE: u8 = 3;

#[derive(Default)]
struct PathInner {
    /// An out-of-band probe was asked for (send error, or `network_changed()`).
    requested: bool,
    /// A `network_changed()` request, which bypasses `PATH_PROBE_MIN_SPACING`.
    forced: bool,
    last_probe: Option<Instant>,
    /// The FIRST IKE/ESP transmission since the last thing we received (cleared by
    /// `note_rx_data`; NAT-T keepalives are excluded on both sides, being sent
    /// unconditionally). Anchoring the one-way silence window at that FIRST transmission
    /// rather than at the latest one is what makes the probe reachable: a client that
    /// keeps retransmitting into a black hole moves the latest one forward every few
    /// hundred milliseconds, so the window would stay at zero and the probe would never
    /// become due — the very case R2 exists for.
    first_tx_since_rx: Option<Instant>,
    /// Since when outer sends have been failing with a path error (`None` while they
    /// succeed, and never started by an unrelated failure such as ENOBUFS).
    sends_failing_since: Option<Instant>,
    /// Last IKE or ESP datagram received. Unlike `Shared::last_rx` this excludes inbound
    /// keepalives, which a gateway echoes even when the SAs are gone.
    last_rx_data: Option<Instant>,
    /// Last ESP datagram sent / received. The IKE-inclusive clocks above cannot answer
    /// "is the CHILD SA carrying traffic": after a non-MOBIKE move the IKE SA is by
    /// assumption working, so its own DPD response would disarm the very check that
    /// exists for a child SA left behind (DESIGN §17.3).
    last_esp_tx: Option<Instant>,
    last_esp_rx: Option<Instant>,
    /// Rate limiter for the ESP sink's send-error warning (the one high-rate site).
    last_esp_error_log: Option<Instant>,
    /// Rate limiter for the path thread's "cannot probe the egress route" warning. That
    /// failure is usually permanent and deliberately never impairs the tunnel, so the
    /// loop — and the warning — would otherwise run for the life of the registration.
    last_probe_error_log: Option<Instant>,
}

/// The clocks one `PathMonitor::tick` needs, read under a single lock.
#[derive(Clone, Copy, Debug)]
struct PathTimes {
    first_tx_since_rx: Option<Instant>,
    last_rx_data: Option<Instant>,
    last_esp_tx: Option<Instant>,
    last_esp_rx: Option<Instant>,
    sends_failing_since: Option<Instant>,
}

/// Does this error mean the local path (address or route) is broken, as opposed to an
/// unrelated failure? A thin adapter from [`Error`] to the policy in
/// [`crate::ike::transport::is_path_error`] (which io kinds and errnos count), used
/// wherever a path failure has to be told apart from an unrelated one.
fn is_path_failure(e: &Error) -> bool {
    matches!(e, Error::Io(io) if crate::ike::transport::is_path_error(io))
}

impl PathState {
    /// Ask for an out-of-band probe. `force` (only [`EpdgTunnel::network_changed`])
    /// bypasses the minimum spacing.
    fn request_probe(&self, force: bool) {
        {
            let mut p = lock(&self.inner);
            p.requested = true;
            p.forced |= force;
        }
        self.cv.notify_all();
    }

    /// Record an operation that failed on the outer socket (a receive, a route probe, a
    /// rebind). A path-kind error asks for a probe; anything else is ignored, so an
    /// unrelated failure can never start a rebind storm.
    fn note_path_error(&self, e: &Error) {
        if is_path_failure(e) {
            self.request_probe(false);
        }
    }

    /// An outer send the OS accepted that carried no traffic of ours — a NAT-T keepalive.
    /// Clears the "sends are failing" clock without touching the transmission clocks, so
    /// the socket can report that it still works without pretending the tunnel carried
    /// traffic.
    fn note_send_ok(&self) {
        lock(&self.inner).sends_failing_since = None;
    }

    /// An outer send that failed. Only a path-kind error starts the "sends are failing"
    /// clock the wedge rule reads: an isolated ENOBUFS or short write says nothing about
    /// the socket's usability, and starting the clock for it would have an idle tunnel
    /// rebind (and re-announce) 30 s later for no reason.
    fn note_send_error(&self, e: &Error) {
        if is_path_failure(e) {
            lock(&self.inner).sends_failing_since.get_or_insert(Instant::now());
            self.request_probe(false);
        }
    }

    /// A successful outer transmission of real traffic — an IKE request or an ESP packet,
    /// never a keepalive. This is the evidence the one-way probe needs, and (like every
    /// accepted send) it clears the "sends are failing" clock. One lock: this runs per
    /// ESP datagram.
    fn note_data_tx(&self) {
        self.note_tx(false);
    }

    /// As [`PathState::note_data_tx`], for an ESP packet: it additionally stamps the
    /// ESP-only clock the migration check reads.
    fn note_esp_tx(&self) {
        self.note_tx(true);
    }

    fn note_tx(&self, esp: bool) {
        let now = Instant::now();
        let mut p = lock(&self.inner);
        p.first_tx_since_rx.get_or_insert(now);
        p.sends_failing_since = None;
        if esp {
            p.last_esp_tx = Some(now);
        }
    }

    /// Record an IKE/ESP datagram received from the gateway. The silence window starts
    /// again at the next transmission, not here.
    fn note_rx_data(&self) {
        self.note_rx(false);
    }

    /// As [`PathState::note_rx_data`], for an ESP packet.
    fn note_rx_esp(&self) {
        self.note_rx(true);
    }

    fn note_rx(&self, esp: bool) {
        let now = Instant::now();
        let mut p = lock(&self.inner);
        p.last_rx_data = Some(now);
        p.first_tx_since_rx = None;
        if esp {
            p.last_esp_rx = Some(now);
        }
    }

    /// Rate limiter for the route probe's failure warning ([`PROBE_ERROR_LOG_INTERVAL`]).
    fn should_log_probe_error(&self, now: Instant) -> bool {
        let mut p = lock(&self.inner);
        if p.last_probe_error_log.is_none_or(|t| now.saturating_duration_since(t) >= PROBE_ERROR_LOG_INTERVAL) {
            p.last_probe_error_log = Some(now);
            return true;
        }
        false
    }

    fn should_log_esp_error(&self, now: Instant) -> bool {
        let mut p = lock(&self.inner);
        if p.last_esp_error_log.is_none_or(|t| now.saturating_duration_since(t) >= ESP_SEND_ERROR_LOG_INTERVAL) {
            p.last_esp_error_log = Some(now);
            return true;
        }
        false
    }

    fn snapshot(&self) -> PathTimes {
        let p = lock(&self.inner);
        PathTimes {
            first_tx_since_rx: p.first_tx_since_rx,
            last_rx_data: p.last_rx_data,
            last_esp_tx: p.last_esp_tx,
            last_esp_rx: p.last_esp_rx,
            sends_failing_since: p.sends_failing_since,
        }
    }

    /// Ask the timer thread for one child rekey after a move (DESIGN §17.3).
    fn request_esp_rekey(&self) {
        self.esp_rekey.store(ESP_REKEY_REQUESTED, Ordering::SeqCst);
    }

    /// Take the request, if any (the timer thread's side of `request_esp_rekey`).
    fn take_esp_rekey_request(&self) -> bool {
        self.esp_rekey.compare_exchange(ESP_REKEY_REQUESTED, ESP_REKEY_IDLE, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    /// The rekey the timer thread ran did not complete (non-fatally): report it back so
    /// the path thread re-arms the escalation.
    fn note_esp_rekey_failed(&self) {
        self.esp_rekey.store(ESP_REKEY_FAILED, Ordering::SeqCst);
    }

    /// Take the failure report, if any (the path thread's side of
    /// `note_esp_rekey_failed`).
    fn take_esp_rekey_failure(&self) -> bool {
        self.esp_rekey.compare_exchange(ESP_REKEY_FAILED, ESP_REKEY_IDLE, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    /// The rekey the timer thread ran COMPLETED: report it back so the path thread
    /// re-checks the ESP clocks against a fresh window. A gateway that moved the IKE SA
    /// but derives the new child SA's encapsulation from the same stale state answers
    /// the CREATE_CHILD_SA perfectly and still black-holes ESP, so "the exchange
    /// completed" must not be read as "the move is repaired" (DESIGN §17.3).
    fn note_esp_rekey_done(&self) {
        self.esp_rekey.store(ESP_REKEY_DONE, Ordering::SeqCst);
    }

    /// Take the completion report, if any (the path thread's side of
    /// `note_esp_rekey_done`).
    fn take_esp_rekey_done(&self) -> bool {
        self.esp_rekey.compare_exchange(ESP_REKEY_DONE, ESP_REKEY_IDLE, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    fn suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    fn set_suspended(&self, v: bool) {
        self.suspended.store(v, Ordering::SeqCst);
    }

    /// Wake the path thread (shutdown, or a tunnel that just died).
    fn wake(&self) {
        self.cv.notify_all();
    }
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
    /// Set at the very top of `shutdown()`, before the DELETE(IKE): the path thread and
    /// any address update abandon at once, so closing never waits out a retransmit
    /// schedule. `stop` cannot be used for this — the rx thread must stay alive to
    /// deliver the DELETE(IKE) response.
    closing: AtomicBool,
    /// Mobility state and the outer-traffic clocks (DESIGN §17); shared with the ESP sink.
    path: Arc<PathState>,
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

    /// Publish `reason`, then tear the inner stack down. The reason is stored *first*:
    /// a thread woken by the stack close immediately asks `closed_error()` for it, and
    /// must not get the generic fallback. It is what every inner socket returns
    /// (`Error::Closed`) and what the SIP transport logs on its way out (DESIGN §17).
    /// The first reason wins: a tunnel that already died of a failure keeps that reason
    /// when it is subsequently closed.
    fn close_stack(&self, reason: String) {
        let reason = {
            let mut slot = lock(&self.dead_reason);
            slot.get_or_insert(reason).clone()
        };
        self.stack.close(reason);
    }

    fn mark_dead(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if self.alive.swap(false, Ordering::SeqCst) {
            error!("tunnel dead: {reason}");
            // Inner sockets / resolvers see Error::Closed with the same reason.
            self.close_stack(reason);
        }
        // Wake anyone waiting for a response so it returns Error::Closed.
        self.pending_cv.notify_all();
        self.path.wake();
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
            address_updates: c.address_updates.load(Ordering::Relaxed),
            stray_sources: self.transport.stray_sources(),
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

// --- Path monitor decision core (pure; clock and probe injected) ------------------

/// What the route probe said about the path to the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeOutcome {
    /// The OS says this is the source address it would use for the gateway.
    Egress(IpAddr),
    /// A path-kind error: there is genuinely no route right now.
    NoRoute,
    /// The probe itself could not run (EMFILE, a sandbox denying the socket, …). It
    /// never starts or advances a failure clock: a denied probe socket must not tear
    /// down a working registration.
    Unknown,
}

/// Everything one tick of [`PathMonitor::tick`] looks at.
#[derive(Clone, Copy, Debug)]
struct PathInput {
    probe: ProbeOutcome,
    /// The address the outer socket is bound to.
    bound: IpAddr,
    sends_failing_since: Option<Instant>,
    last_rx_data: Option<Instant>,
    now: Instant,
}

/// What the tunnel should do about the path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathAction {
    /// Nothing to do.
    Idle,
    /// Bind a fresh socket on this address, then announce it.
    Rebind(IpAddr),
    /// The socket is already where it should be; (re)tell the gateway.
    Announce,
    /// Unrecoverable: `mark_dead` with this reason.
    Dead(String),
}

/// The mobility state machine (DESIGN §17). Free of I/O and of `Instant::now()` so every
/// branch is a pure unit test.
#[derive(Debug, Default)]
struct PathMonitor {
    /// One clock for every kind of impairment; `impaired_reason` names which.
    impaired_since: Option<Instant>,
    impaired_reason: &'static str,
    /// The socket was rebound but the gateway has not acknowledged the new address yet:
    /// retry the announce, never another rebind.
    needs_announce: bool,
    last_move: Option<Instant>,
    /// We already rebound once to break a wedged socket; a second wedge is fatal.
    wedge_rebound: bool,
}

impl PathMonitor {
    /// Start (or keep) the impairment clock under `reason`. A new reason replaces the
    /// label but keeps the original instant: the grace covers the whole outage, not each
    /// of its phases in turn.
    fn impair(&mut self, now: Instant, reason: &'static str) {
        self.impaired_since.get_or_insert(now);
        self.impaired_reason = reason;
    }

    fn healthy(&mut self) {
        self.impaired_since = None;
        self.impaired_reason = "";
    }

    fn tick(&mut self, i: PathInput) -> PathAction {
        // An already-running grace clock is evaluated FIRST, whatever the probe said.
        // A probe that cannot run (EMFILE, a sandbox EPERM on the throwaway socket) is
        // usually persistent, and returning early here used to freeze the clock forever:
        // the tunnel stayed `suspended`, which disables DPD, both liveness probes and
        // every rekey, so nothing could ever declare it dead (DESIGN §17.1/§17.4).
        if let Some(since) = self.impaired_since
            && i.now.saturating_duration_since(since) >= NO_ROUTE_GRACE
        {
            return PathAction::Dead(format!("{} for {:?}", self.impaired_reason, NO_ROUTE_GRACE));
        }
        // A probe that could not run tells us nothing: never START or advance a clock
        // for it.
        if i.probe == ProbeOutcome::Unknown {
            return PathAction::Idle;
        }
        let ProbeOutcome::Egress(ip) = i.probe else {
            self.impair(i.now, "no route to the gateway");
            return PathAction::Idle;
        };

        // A rebound socket the gateway has not acknowledged: finish that first. If the
        // route moved again in the meantime, rebind to where it points now.
        if self.needs_announce {
            return if ip == i.bound { PathAction::Announce } else { PathAction::Rebind(ip) };
        }

        // Flap damping: one move per MIN_ADDRESS_UPDATE_INTERVAL. A flapping default
        // route would otherwise burn one UPDATE_SA_ADDRESSES — and the gateway's NAT
        // binding — every probe interval. The first move after a quiet period (the
        // Wi-Fi/LTE handover this whole feature exists for) passes immediately.
        let recent = self.last_move.is_some_and(|t| i.now.saturating_duration_since(t) < MIN_ADDRESS_UPDATE_INTERVAL);

        if ip != i.bound {
            if recent {
                return PathAction::Idle;
            }
            return PathAction::Rebind(ip);
        }

        // The route is back on the address we are bound to, but we were impaired: the
        // old binding may be stale, and the fresh ephemeral port is itself the change
        // the gateway must learn.
        //
        // Damped exactly like a move to a different address, and for the same reason: a
        // link that flaps between "no route" and the same address (an AP whose
        // `discover_egress` momentarily fails) alternates these two branches, and an
        // undamped recovery would announce a new ephemeral port on every blip — as often
        // as an out-of-band probe request allows, which is `PATH_PROBE_MIN_SPACING`, not
        // the probe interval. Waiting costs nothing: the impairment clock keeps running,
        // so `NO_ROUTE_GRACE` still bounds the outage.
        if self.impaired_since.is_some() {
            return if recent { PathAction::Idle } else { PathAction::Rebind(ip) };
        }

        // Nothing moved, yet every send fails and nothing comes back: the socket is
        // wedged. Try one fresh binding, then give up.
        let wedged = i.sends_failing_since.is_some_and(|t| i.now.saturating_duration_since(t) >= NO_ROUTE_GRACE)
            && i.last_rx_data.is_none_or(|t| i.now.saturating_duration_since(t) >= NO_ROUTE_GRACE);
        if wedged {
            if self.wedge_rebound {
                return PathAction::Dead(format!("the outer socket has been unusable for {NO_ROUTE_GRACE:?}"));
            }
            self.wedge_rebound = true;
            return PathAction::Rebind(ip);
        }
        // The path looks healthy again: a future wedge gets its own retry.
        self.wedge_rebound = false;
        PathAction::Idle
    }

    /// The socket was rebound; the gateway has not been told yet.
    fn rebound(&mut self, now: Instant) {
        self.needs_announce = true;
        self.impair(now, "the gateway has not acknowledged our new address");
    }

    /// The gateway accepted the new address.
    fn announced(&mut self, now: Instant) {
        self.needs_announce = false;
        self.last_move = Some(now);
        self.healthy();
    }

    /// The announce failed transiently: keep `needs_announce` so the next tick retries
    /// it from the socket we already rebound instead of binding yet another one.
    fn announce_failed(&mut self, now: Instant) {
        self.impair(now, "the gateway has not acknowledged our new address");
    }

    fn rebind_failed(&mut self, now: Instant) {
        self.impair(now, "cannot bind a socket on the new egress address");
    }
}

/// Should a one-way-traffic liveness probe run (R2)? We transmitted after the last thing
/// we received, nothing has come back for `silence`, and the previous probe is at least
/// `silence` old — a successful probe's response updates `last_rx_data`, so this
/// self-clears and does not re-fire without new one-way evidence. All comparisons
/// saturate, so an injected `now` before the stored instants cannot panic.
fn one_way_probe_due(
    first_tx_since_rx: Option<Instant>,
    last_probe: Option<Instant>,
    now: Instant,
    silence: Duration,
) -> bool {
    // Why the FIRST transmission and not the latest: see `PathInner::first_tx_since_rx`.
    let Some(since) = first_tx_since_rx else { return false };
    if now.saturating_duration_since(since) < silence {
        return false;
    }
    // A probe that is answered clears `first_tx_since_rx`, so this self-clears; the
    // spacing only bounds re-probing while the silence continues.
    last_probe.is_none_or(|p| now.saturating_duration_since(p) >= silence)
}

/// Should the idle-tunnel liveness probe run (DESIGN §17.5)? Nothing has been received
/// from the gateway for `silence` and the previous idle probe is at least `silence` old.
///
/// This is the companion of [`one_way_probe_due`] for the case that one cannot see: a
/// registered but silent tunnel never transmits (NAT-T keepalives deliberately do not
/// count), so there is no one-way evidence to trigger on, and with the bundle's DPD
/// disabled nothing else would ever check the gateway. `established` anchors a tunnel
/// that has not received anything at all yet.
fn idle_probe_due(
    last_rx_data: Option<Instant>,
    last_probe: Option<Instant>,
    established: Instant,
    now: Instant,
    silence: Duration,
) -> bool {
    let anchor = [last_rx_data, last_probe].into_iter().flatten().max().unwrap_or(established);
    now.saturating_duration_since(anchor) >= silence
}

/// Is an address-update failure fatal? `Some(reason)` → `mark_dead`; `None` → transient,
/// keep retrying inside the grace period.
///
/// The fatal cases are listed explicitly rather than left to a catch-all, because only
/// the gateway's own ANSWER proves that retrying is pointless: a rejection notify, or a
/// response we cannot decode or authenticate (a gateway that lost our SA, or something
/// on the path rewriting IKE). Everything else — a timeout, a local send failure of any
/// errno, a builder-side state race — is transient by construction and bounded by
/// `NO_ROUTE_GRACE`, which is the single authority for death (DESIGN §17.4).
///
/// A catch-all used to make every non-path `Error::Io` fatal, so one `ENOBUFS` (errno 55,
/// an `Uncategorized` kind) or one `EPERM` from a host firewall on the FIRST datagram out
/// of a brand-new interface killed the tunnel during exactly the handover this feature
/// exists to survive.
fn address_update_failure(e: &Error) -> Option<String> {
    match e {
        // A gateway that actively rejects the move will reject the retry too. This
        // covers RFC 4555 §12's UNACCEPTABLE_ADDRESSES / UNEXPECTED_NAT_DETECTION and
        // the status-range NO_NATS_ALLOWED alike.
        Error::PeerNotify { .. } => Some(format!("address update rejected: {e}")),
        // A response that does not decode or does not authenticate on an SA the gateway
        // is supposed to share with us: retrying cannot fix it.
        Error::Decode(_) | Error::Integrity(_) => Some(format!("address update rejected: {e}")),
        // Transient: a path that broke again, a silent gateway (the DOMINANT announce
        // failure — a new AP whose uplink is not usable yet), a local send error, a
        // builder-side state race, a crossing teardown. Killing the tunnel for any of
        // them would cap the handover tolerance at the 15.5 s retransmit schedule
        // instead of the advertised NO_ROUTE_GRACE.
        _ => None,
    }
}

/// Does a failed rekey prove the gateway is gone?
///
/// Only retransmissions running out on a path that is NOT being repaired does. While the
/// path monitor is moving the SA, a rekey request left an address the gateway has never
/// been told about, so its silence says nothing — and an aborted rekey (a path-kind `Io`
/// from the abort predicate, or `Closed` while shutting down) never reached the gateway
/// at all. Everything else is retried after `REKEY_RETRY_DELAY`.
fn rekey_failure_is_fatal(e: &Error, path_suspended: bool) -> bool {
    matches!(e, Error::Timeout(_)) && !path_suspended
}

/// What the post-move escalation (DESIGN §17.3) does with the outcome of the child rekey
/// it asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscalationOutcome {
    /// The gateway is gone: `mark_dead`.
    Fatal,
    /// The child SA was migrated. Reported back so the path thread watches the ESP clocks
    /// over a FRESH window — a completed exchange is not proof that ESP was restored.
    Done,
    /// The gateway refused it or could not complete it: one attempt for this move is
    /// spent and the escalation is re-armed.
    Failed,
    /// It never reached the gateway, so it is evidence of nothing: re-request it without
    /// spending an attempt (DESIGN §17.4).
    Abandoned,
}

/// Classify that outcome. `installed` is [`rekey_child`]'s flag: the CREATE_CHILD_SA half
/// committed the new SAs before the error, so only the DELETE of the old child failed and
/// the repair itself did happen.
fn escalation_outcome(e: Option<&Error>, installed: bool, path_suspended: bool) -> EscalationOutcome {
    match e {
        None => EscalationOutcome::Done,
        // Retransmissions exhausted on a path that is NOT being repaired: the same proof
        // of a dead gateway here as for a lifetime rekey.
        Some(e) if rekey_failure_is_fatal(e, path_suspended) => EscalationOutcome::Fatal,
        Some(_) if installed => EscalationOutcome::Done,
        // The abort predicate fired (the path monitor is moving the SA) or the tunnel is
        // being torn down — in both cases possibly before the first datagram was sent.
        // A `Timeout` can only reach this arm while the path is being repaired (the arm
        // above takes the settled case), and retransmissions that left an address the
        // gateway has never been told about are evidence of nothing either.
        Some(e) if is_path_failure(e) || matches!(e, Error::Closed(_) | Error::Timeout(_)) => {
            EscalationOutcome::Abandoned
        }
        // `N(TEMPORARY_FAILURE)` while the gateway rekeys on its own (RFC 7296 §2.25),
        // `NO_ADDITIONAL_SAS`, a protocol or builder-state error: the gateway was reached
        // (or the request is one we can never send), so it counts.
        Some(_) => EscalationOutcome::Failed,
    }
}

/// After a move on a peer that does **not** support MOBIKE, the gateway may have moved
/// the IKE SA (RFC 7296 §2.23) but not the child SA's UDP-encapsulation port — AOSP
/// rekeys the child SA instead of relying on that. Up to
/// [`ESP_MIGRATION_REKEY_ATTEMPTS`] rekeys per move (the path thread re-arms this by
/// clearing `rekeyed` on the OUTCOME of each one — a completed rekey is not proof that
/// ESP came back, so it re-arms too, against a window restarted at its completion
/// instant), and only on real
/// evidence of a stall: the move was acknowledged, we have sent ESP from the new address
/// since, and no ESP has come back. Without the outbound half, an idle registered tunnel
/// — which receives nothing by definition — would be rekeyed after every single move.
///
/// Both clocks are ESP-only ([`PathInner::last_esp_tx`] / [`PathInner::last_esp_rx`]), not
/// the IKE-inclusive ones. The hypothesis under test is "IKE moved, ESP did not", so
/// inbound IKE — a peer DPD, or the response to our own one-way probe, which is *due at
/// the same threshold* — is exactly what the failure case produces; counting it as
/// evidence of health would disarm this check precisely when it is needed. Symmetrically,
/// an IKE request of ours is not evidence that ESP was sent.
fn esp_migration_stalled(
    mobike: bool,
    rekeyed: bool,
    moved_at: Option<Instant>,
    last_esp_tx: Option<Instant>,
    last_esp_rx: Option<Instant>,
    now: Instant,
    silence: Duration,
) -> bool {
    if mobike || rekeyed {
        return false;
    }
    moved_at.is_some_and(|m| {
        // `silence` has to have passed since the TRANSMISSION, not merely since the move:
        // a tunnel that is idle for minutes after a move and then sends one packet would
        // otherwise be "stalled" within a probe interval, before the gateway could
        // possibly have answered. The floor since the move is kept as well.
        now.saturating_duration_since(m) >= silence
            && last_esp_tx.is_some_and(|tx| tx > m && now.saturating_duration_since(tx) >= silence)
            && last_esp_rx.is_none_or(|rx| rx <= m)
    })
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
        client_cert_der: cfg.eap_tls.client_cert_der.clone(),
        client_key_der: cfg.eap_tls.client_key_der.clone(),
        validate_server: cfg.eap_tls.validate_server_cert,
        server_ca_der: cfg.eap_tls.server_ca_der.clone(),
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
        peer_mobike: ike.peer_mobike(),
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
    let path = Arc::new(PathState::default());
    let stack = InnerStack::new(
        &assigned,
        esp_sink(&transport, &outbound, &counters, &path),
        cfg.child.inner_mtu,
        cfg.child.inner_mtu_stack,
    )?;
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
        closing: AtomicBool::new(false),
        path,
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
    let path_thread = spawn_named("epdg-path", Arc::clone(&shared), path_loop)?;

    Ok(EpdgTunnel {
        shared,
        info,
        stack_thread: Some(stack_thread),
        rx_thread: Some(rx_thread),
        keepalive_thread: Some(keepalive_thread),
        timer_thread: Some(timer_thread),
        path_thread: Some(path_thread),
        closed: false,
    })
}

/// The inner stack's TX sink: `EspOutbound::encapsulate` (current outbound SA, so a
/// child rekey is picked up transparently) + `IkeTransport::send_esp`, counting ESP tx.
/// Runs on the stack thread inside `Interface::poll` (and on a caller's thread when an
/// `InnerUdpSocket` is dropped with datagrams still queued). Every packet it is handed
/// already fits `child.inner_mtu` (the device fragments, §11.1).
fn esp_sink(
    transport: &Arc<IkeTransport>,
    outbound: &Arc<RwLock<Arc<EspOutbound>>>,
    counters: &Arc<Counters>,
    path: &Arc<PathState>,
) -> TxSink {
    let transport = Arc::clone(transport);
    let outbound = Arc::clone(outbound);
    let counters = Arc::clone(counters);
    let path = Arc::clone(path);
    Arc::new(move |inner: &[u8]| {
        let sa = outbound.read().unwrap_or_else(|e| e.into_inner()).clone();
        let esp = sa.encapsulate(inner)?;
        if let Err(e) = transport.send_esp(&esp) {
            // Per-datagram path: record the failure (and ask for a probe when it looks
            // like a broken route) but rate-limit the log. The device still counts it.
            path.note_send_error(&e);
            if path.should_log_esp_error(Instant::now()) {
                warn!("ESP send failed: {e}");
            }
            return Err(e);
        }
        path.note_esp_tx();
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

/// An extra early exit for a request's wait loop, re-checked before every send and on
/// every wake. `Some(err)` abandons the request with that error instead of waiting out
/// the whole retransmit schedule. It runs while the `pending` mutex is held, so it must
/// only read atomics.
type Abort<'a> = &'a dyn Fn() -> Option<Error>;

/// The path moved (or is being repaired) under an outstanding request: its silence says
/// nothing about the peer, so the caller must not read it as a dead gateway.
///
/// `suspended` is the single condition: the monitor raises it before every rebind and
/// clears it only once the gateway has acknowledged the new address, and every
/// post-establishment request holds `request_lock` for its whole life — so a request
/// cannot be outstanding across a completed move without having seen it set.
fn path_abort(shared: &Shared) -> Option<Error> {
    shared.path.suspended().then(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::NetworkDown,
            "the local path changed while the request was outstanding",
        ))
    })
}

/// `close()` is running: abandon so shutdown never waits out a retransmit schedule.
fn closing_abort(shared: &Shared) -> Option<Error> {
    shared.closing.load(Ordering::SeqCst).then(|| Error::Closed("tunnel closing".into()))
}

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
    ike_request_locked(shared, what, policy, None, build)
}

/// [`ike_request`] with an [`Abort`] predicate.
fn ike_request_abortable(
    shared: &Shared,
    what: &'static str,
    policy: &RetransmitConfig,
    abort: Abort<'_>,
    build: impl FnOnce(&mut IkeInitiator) -> Result<IkeMessage>,
) -> Result<IkeMessage> {
    let _serial = lock(&shared.request_lock);
    ike_request_locked(shared, what, policy, Some(abort), build)
}

/// The body of [`ike_request`] for a caller that already holds `request_lock` (a
/// multi-exchange operation such as a rekey holds it across both of its exchanges, so an
/// address update can never interleave between them).
fn ike_request_locked(
    shared: &Shared,
    what: &'static str,
    policy: &RetransmitConfig,
    abort: Option<Abort<'_>>,
    build: impl FnOnce(&mut IkeInitiator) -> Result<IkeMessage>,
) -> Result<IkeMessage> {
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
    // Did any datagram reach the socket? A request no datagram of which was ever handed
    // to the socket was never seen by the gateway, so its id cannot have a cached
    // response (DESIGN §17.2). Counted, not assumed: `send_raw` swallows
    // `WouldBlock`/`TimedOut` as `Ok`, so an `Err` out of `send_ike` proves that
    // datagram did NOT go out — the EHOSTUNREACH/EPERM of a handover's very first
    // datagram out of a brand-new interface. A send that fails AFTER an earlier
    // datagram of the same message went out (fragment 2 of N) still counts as sent.
    let mut sent = false;
    'attempts: for attempt in 0..attempts {
        if let Some(e) = abort.and_then(|a| a()) {
            outcome = Err(e);
            break;
        }
        let mut delivered = 0usize;
        let result = datagrams.iter().try_for_each(|d| {
            shared.transport.send_ike(d)?;
            delivered += 1;
            Ok(())
        });
        sent |= delivered > 0;
        match result {
            Ok(()) => shared.path.note_data_tx(),
            Err(e) => {
                // An outer send failure is also path evidence: record it (and, when it
                // looks like a broken route, ask the monitor to re-probe) before giving up.
                shared.path.note_send_error(&e);
                outcome = Err(e);
                break;
            }
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
            if let Some(e) = abort.and_then(|a| a()) {
                outcome = Err(e);
                break 'attempts;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Sliced so an `abort` (a path change, a close) is noticed within one tick
            // instead of at the end of this attempt's retransmit timeout.
            let slice = remaining.min(TICK_SLICE);
            slot = shared.pending_cv.wait_timeout(slot, slice).unwrap_or_else(|e| e.into_inner()).0;
        }
        drop(slot);
        if attempt + 1 < attempts {
            debug!("{what} msgid {message_id}: no response after {:?}; retransmitting", timeout);
        }
    }
    if outcome.is_err() {
        // Free the session's single request slot (RFC 7296 §2.1: the unanswered message
        // id is reused by the next request); otherwise every later DPD / rekey / DELETE
        // would fail with "another request is outstanding". Only a request that actually
        // reached the socket marks its id abandoned.
        let mut ike = lock(&shared.ike);
        if sent { ike.abort_request() } else { ike.abort_unsent_request() }
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
///
/// Abandoned (with a `NetworkDown` `Io` error, not a `Timeout`) when the path moves
/// while it is outstanding: a probe sent from an address that no longer exists must
/// never be read as a dead peer.
fn do_dpd(shared: &Shared, policy: &RetransmitConfig) -> Result<Duration> {
    let started = Instant::now();
    // `closing_abort` first: `close()` must never wait out a retransmit schedule behind
    // `request_lock`, which its DELETE(IKE) needs (DESIGN §17.6).
    let abort = || closing_abort(shared).or_else(|| path_abort(shared));
    let response = ike_request_abortable(shared, "DPD", policy, &abort, |ike| ike.build_dpd())?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    let rtt = started.elapsed();
    info!("DPD ok, rtt {:?}", rtt);
    Ok(rtt)
}

/// CREATE_CHILD_SA child rekey, install the new ESP SAs, then DELETE the old child.
///
/// `request_lock` is held across *both* exchanges so an address update cannot slip
/// between the rekey and the DELETE of the old child.
///
/// `installed` is set the moment the CREATE_CHILD_SA half has committed the new SAs. A
/// later error therefore means the OLD child could not be deleted, not that the rekey
/// failed — the post-move escalation (DESIGN §17.3) must not charge that as a failed
/// repair, because the repair did happen.
fn rekey_child(shared: &Shared, installed: &mut bool) -> Result<()> {
    let policy = &shared.cfg.ike.retransmit;
    let _serial = lock(&shared.request_lock);
    // Same abort protocol as `do_dpd`, for the same two reasons: a rekey whose request
    // left an address that no longer exists must not be read as a dead peer (its
    // retransmissions would otherwise run the full schedule and `timer_loop` would tear
    // the tunnel down in the middle of a handover), and `close()` must never wait out a
    // retransmit schedule behind `request_lock`.
    let abort = || closing_abort(shared).or_else(|| path_abort(shared));
    let old_spi_in = lock(&shared.ike).child().map(|c| c.spi_in).ok_or_else(|| Error::Protocol("no child SA to rekey".into()))?;
    let response =
        ike_request_locked(shared, "CREATE_CHILD_SA (rekey child)", policy, Some(&abort), |ike| ike.build_rekey_child())?;
    let new = settle(shared, |ike| ike.handle_rekey_child_response(&response))?;
    let (outbound, inbound) = esp_pair(&new);
    lock(&shared.inbound).push(inbound);
    *shared.outbound.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(outbound);
    *lock(&shared.child_created) = new.created;
    *installed = true;
    shared.counters.child_rekeys.fetch_add(1, Ordering::Relaxed);
    info!("child SA rekeyed: SPI_in {:#010x} SPI_out {:#010x}; deleting old {:#010x}", new.spi_in, new.spi_out, old_spi_in);

    let response = ike_request_locked(shared, "DELETE(ESP)", policy, Some(&abort), |ike| ike.build_delete_child(old_spi_in))?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    lock(&shared.inbound).retain(|sa| sa.spi() != old_spi_in);
    Ok(())
}

/// CREATE_CHILD_SA IKE rekey, then DELETE the old IKE SA (on the old SA). Both exchanges
/// run under one `request_lock`, as in [`rekey_child`].
fn rekey_ike(shared: &Shared) -> Result<()> {
    let policy = &shared.cfg.ike.retransmit;
    let _serial = lock(&shared.request_lock);
    let abort = || closing_abort(shared).or_else(|| path_abort(shared));
    let response =
        ike_request_locked(shared, "CREATE_CHILD_SA (rekey IKE)", policy, Some(&abort), |ike| ike.build_rekey_ike())?;
    settle(shared, |ike| ike.handle_rekey_ike_response(&response))?;
    *lock(&shared.ike_created) = Instant::now();
    shared.counters.ike_rekeys.fetch_add(1, Ordering::Relaxed);
    {
        let ike = lock(&shared.ike);
        info!("IKE SA rekeyed: SPIs {:#018x}/{:#018x}; deleting the old IKE SA", ike.spi_i(), ike.spi_r());
    }
    let response = ike_request_locked(shared, "DELETE(IKE) old SA", policy, Some(&abort), |ike| ike.build_delete_ike())?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    Ok(())
}

/// Announce the outer socket's current 5-tuple to the gateway (DESIGN §17).
///
/// With MOBIKE this is `INFORMATIONAL { N(UPDATE_SA_ADDRESSES), NAT-D }` (RFC 4555
/// §3.5); without it an empty INFORMATIONAL, which the gateway accepts as the RFC 7296
/// §2.23 dynamic address update because our deliberate fake `NAT_DETECTION_SOURCE_IP`
/// has it convinced we are behind a NAT. Either way the ESP SAs are untouched — same
/// SPIs, keys and replay state — only the 5-tuple moved.
///
/// Serialised against every other post-establishment request, so no DPD or rekey
/// retransmission can straddle the swap.
///
/// `deadline` is the instant the path monitor's grace period expires. The announce is
/// abandoned there instead of running its retransmit schedule to the end, so the path
/// thread is back in `tick` — the only place that can declare the tunnel dead — within
/// one probe interval of [`NO_ROUTE_GRACE`] rather than up to a whole schedule later.
///
/// Every call that reaches that deadline with time to spare transmits an address update:
/// the optional DPD that spends an abandoned message id is bounded by
/// [`SPEND_MSGID_ATTEMPTS`] (≈1.5 s of a 30 s grace) and never aborts the announce on its
/// own — only a teardown or the deadline itself does.
fn announce(shared: &Shared, deadline: Option<Instant>) -> Result<SocketAddr> {
    let _serial = lock(&shared.request_lock);
    if !shared.is_alive() {
        return Err(shared.closed_error());
    }
    if let Some(e) = closing_abort(shared) {
        return Err(e);
    }
    let new = shared.transport.local_addr();
    // The transport's live destination (gateway:4500 after the NAT-T switch), never
    // `IkeInitiator::remote`, which still says :500 until an address update commits.
    let remote = shared.transport.remote_addr();
    let mobike = lock(&shared.ike).mobike_enabled();
    let what = if mobike { "INFORMATIONAL (UPDATE_SA_ADDRESSES)" } else { "INFORMATIONAL (address update)" };
    let abort = || {
        closing_abort(shared).or_else(|| {
            deadline
                .is_some_and(|d| Instant::now() >= d)
                .then_some(Error::Timeout("address update (grace period expired)"))
        })
    };
    // Never announce on a message id that was abandoned earlier: RFC 7296 §2.1 lets the
    // gateway replay its CACHED response for such an id instead of processing the new
    // request, and that replay cannot be told from an acknowledgement — if the abandoned
    // request was itself an UPDATE_SA_ADDRESSES, its cached response carries the very
    // NAT-D pair a genuine one does, hashed over the address we were moving to LAST time.
    // Committing it would leave us believing we are at C while the gateway keeps the SA
    // at B, and RFC 4555 §3.8 forbids the responder to re-learn our address from ESP, so
    // the tunnel would be a black hole until the liveness probes killed it.
    //
    // So the abandoned id is SPENT on a plain DPD first. A replay there is harmless (an
    // empty INFORMATIONAL and an old address-update response are both "the peer answered"
    // to a DPD), and receiving anything for that id advances the window — the announce
    // then runs on a provably fresh id. Note this does not skip an id: the window stays
    // in step either way, so the gateway never sees a gap.
    //
    // The spend gets [`SPEND_MSGID_ATTEMPTS`], NOT the full retransmit schedule, and an
    // unanswered spend does NOT abort the announce. A silent gateway is the DOMINANT
    // announce failure (see `address_update_failure`), and it is exactly the case in
    // which the spend cannot be answered: letting it run the whole schedule and then
    // return would mean the only thing this tunnel ever transmits during an outage is
    // empty INFORMATIONALs — which RFC 4555 §3.8 does not let the responder move the
    // child SAs from — until `NO_ROUTE_GRACE` kills the tunnel. So we fall through and
    // send the real `UPDATE_SA_ADDRESSES` on the reused id: `handle_address_update_response`
    // refuses a reused-id response unconditionally, so a replay is rejected (transient,
    // nothing committed) and costs one exchange, while a gateway that never saw the
    // abandoned request gets a genuine address update on every retry inside the grace.
    if lock(&shared.ike).next_msgid_is_abandoned() {
        let spend_policy = RetransmitConfig { max_attempts: SPEND_MSGID_ATTEMPTS, ..shared.cfg.ike.retransmit.clone() };
        match ike_request_locked(shared, "DPD (spending an abandoned message id)", &spend_policy, Some(&abort), |ike| {
            ike.build_dpd()
        }) {
            Ok(spend) => {
                if let Err(e) = settle(shared, |ike| ike.handle_informational_response(&spend)) {
                    // The CONTENT is irrelevant — most likely the gateway's cached response
                    // for the request we gave up on. Receiving it is what mattered.
                    debug!("the response that spent the abandoned message id was not a clean DPD reply ({e}); continuing");
                }
            }
            Err(e) => {
                // Only a teardown or the grace deadline ends the announce here; silence
                // does not.
                if let Some(fatal) = abort() {
                    return Err(fatal);
                }
                if !shared.is_alive() {
                    return Err(shared.closed_error());
                }
                debug!("the abandoned message id could not be spent ({e}); announcing on it anyway");
            }
        }
    }
    let response =
        ike_request_locked(shared, what, &shared.cfg.ike.retransmit, Some(&abort), |ike| ike.build_address_update(new, remote))?;
    settle(shared, |ike| ike.handle_informational_response(&response))?;
    shared.counters.address_updates.fetch_add(1, Ordering::Relaxed);
    if shared.transport.using_natt() {
        // Re-open the gateway's NAT binding for the new port straight away instead of
        // waiting for the next cadence slot.
        match shared.transport.send_keepalive() {
            Ok(()) => {
                shared.counters.keepalives_sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => warn!("keepalive after the move failed: {e}"),
        }
    }
    info!("address update done: {new} -> {remote} (mobike={mobike}); ESP SAs unchanged");
    Ok(new)
}

/// Wait for the next probe slot or an out-of-band request; `false` when the tunnel is
/// stopping or closing. An out-of-band request is honoured only once
/// [`PATH_PROBE_MIN_SPACING`] has passed since the last probe, unless it was forced by
/// [`EpdgTunnel::network_changed`].
fn path_wait(shared: &Shared, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut p = lock(&shared.path.inner);
    loop {
        if shared.stop.load(Ordering::SeqCst) || shared.closing.load(Ordering::SeqCst) {
            return false;
        }
        let now = Instant::now();
        if p.requested {
            let spaced = p.last_probe.is_none_or(|t| now.saturating_duration_since(t) >= PATH_PROBE_MIN_SPACING);
            if p.forced || spaced {
                p.requested = false;
                p.forced = false;
                p.last_probe = Some(now);
                return true;
            }
        }
        if now >= deadline {
            p.requested = false;
            p.forced = false;
            p.last_probe = Some(now);
            return true;
        }
        let slice = deadline.saturating_duration_since(now).min(TICK_SLICE);
        p = shared.path.cv.wait_timeout(p, slice).unwrap_or_else(|e| e.into_inner()).0;
    }
}

/// Body of the `epdg-path` thread: watch the egress route, move the outer socket when it
/// changes and tell the gateway, declare the tunnel dead when the path cannot be
/// repaired within [`NO_ROUTE_GRACE`] (DESIGN §17).
fn path_loop(shared: Arc<Shared>) {
    let mut m = PathMonitor::default();
    // For the non-MOBIKE ESP escalation.
    let mut moved_at: Option<Instant> = None;
    let mut rekeyed_after_move = false;
    let mut esp_rekey_attempts: u32 = 0;
    // An explicitly configured source address is a promise to the caller: the monitor
    // may rebind on it (a fresh port after an outage) but must never move off it. The
    // route probe is still run, because it is what reports "no route at all".
    let pinned = shared.cfg.gateway.local_addr.filter(|ip| !ip.is_unspecified());

    while path_wait(&shared, PATH_PROBE_INTERVAL) {
        if !shared.alive.load(Ordering::SeqCst) {
            continue;
        }
        let bound = shared.transport.local_addr();
        let probe = match shared.transport.probe_egress() {
            Ok(ip) => ProbeOutcome::Egress(pinned.unwrap_or(ip)),
            Err(ref e) if is_path_failure(e) => ProbeOutcome::NoRoute,
            Err(e) => {
                // Rate-limited: this failure is usually permanent (EMFILE, a sandbox or
                // MDM denying the throwaway socket) and an `Unknown` probe deliberately
                // never impairs the tunnel, so the loop keeps running for its whole life.
                if shared.path.should_log_probe_error(Instant::now()) {
                    warn!("path: cannot probe the egress route ({e}); leaving the tunnel alone");
                } else {
                    debug!("path: cannot probe the egress route ({e}); leaving the tunnel alone");
                }
                ProbeOutcome::Unknown
            }
        };
        let times = shared.path.snapshot();
        let now = Instant::now();
        let action = m.tick(PathInput {
            probe,
            bound: bound.ip(),
            sends_failing_since: times.sends_failing_since,
            last_rx_data: times.last_rx_data,
            now,
        });

        let mut announce_now = false;
        // The socket a rebind replaced. Held only until the announce that follows it has
        // finished, so the kernel cannot hand its ephemeral port to another socket in
        // this process while the gateway's NAT binding may still point at it. It is never
        // read from: late inbound ESP in that window is lost (DESIGN §17.8).
        let mut replaced: Option<Arc<std::net::UdpSocket>> = None;
        match action {
            PathAction::Idle => {}
            PathAction::Dead(reason) => {
                if shared.is_alive() {
                    shared.mark_dead(reason);
                }
                continue;
            }
            PathAction::Rebind(ip) => {
                shared.path.set_suspended(true);
                match shared.transport.rebind(ip) {
                    Ok((new, old)) => {
                        replaced = Some(old);
                        debug!("path: outer socket moved to {new}; announcing it");
                        // The session's own address is committed by the response
                        // handler, not here: `nat::evaluate` compares the gateway's
                        // NAT_DETECTION_DESTINATION_IP against the address we asked for.
                        m.rebound(now);
                        announce_now = true;
                    }
                    Err(e) => {
                        shared.path.note_path_error(&e);
                        m.rebind_failed(now);
                        warn!("path: cannot rebind the outer socket to {ip}: {e}");
                    }
                }
            }
            PathAction::Announce => {
                shared.path.set_suspended(true);
                announce_now = true;
            }
        }

        if announce_now {
            // Give the announce back to this loop at the grace deadline: `tick` is the
            // only place that declares the tunnel dead, and it cannot run while we are
            // inside a retransmit schedule.
            let deadline = m.impaired_since.map(|since| since + NO_ROUTE_GRACE);
            match announce(&shared, deadline) {
                Ok(new) => {
                    m.announced(Instant::now());
                    moved_at = Some(Instant::now());
                    rekeyed_after_move = false;
                    esp_rekey_attempts = 0;
                    shared.path.set_suspended(false);
                    info!("path: tunnel moved {bound} -> {new}");
                }
                // A crossing teardown won the race; its reason is the right one.
                Err(_) if !shared.is_alive() => {}
                Err(e) => match address_update_failure(&e) {
                    Some(reason) => shared.mark_dead(reason),
                    None => {
                        m.announce_failed(Instant::now());
                        warn!("path: address update did not complete ({e}); retrying");
                    }
                },
            }
        }
        drop(replaced);
        // Leave "suspended" set while the monitor still has work to do, so the liveness
        // checks stay out of the way.
        shared.path.set_suspended(m.needs_announce || m.impaired_since.is_some());

        // The timer thread reports the OUTCOME of the rekey it ran. `rekeyed_after_move`
        // is a flag for "the repair is in flight", so only an outcome may clear it;
        // leaving it set disarms `esp_migration_stalled` for the rest of the tunnel's
        // life and leaves a black hole nothing else can see (DESIGN §17.3). Both
        // outcomes spend one of this move's attempts, and both re-arm the check — the
        // decision to give up is taken where the stall is re-evaluated, below, so a
        // spent budget never kills a tunnel whose ESP has come back in the meantime.
        if shared.path.take_esp_rekey_failure() {
            esp_rekey_attempts += 1;
            warn!(
                "path: the child rekey after the move did not complete; re-arming \
                 (attempt {esp_rekey_attempts}/{ESP_MIGRATION_REKEY_ATTEMPTS})"
            );
            rekeyed_after_move = false;
        }
        // A rekey the gateway COMPLETED is not proof that ESP was restored: the peer this
        // escalation exists for answers on the IKE SA (which did move) and may still
        // derive the new child SA's encapsulation from the same stale state. So the
        // evidence window is restarted at the completion instant — a following ESP
        // transmission with no answer for ONE_WAY_PROBE_SILENCE re-arms the escalation,
        // and an unrepaired "success" reaches `mark_dead` exactly like a failure
        // (DESIGN §17.3).
        if shared.path.take_esp_rekey_done() {
            esp_rekey_attempts += 1;
            moved_at = Some(Instant::now());
            rekeyed_after_move = false;
            info!(
                "path: the child rekey after the move completed; watching for ESP again \
                 (attempt {esp_rekey_attempts}/{ESP_MIGRATION_REKEY_ATTEMPTS})"
            );
        }

        // Non-MOBIKE fallback safety net: the gateway moved the IKE SA but may not have
        // moved the child SA's encapsulation port. Up to ESP_MIGRATION_REKEY_ATTEMPTS
        // child rekeys per move — a failed one re-arms this check above — and only
        // when we sent ESP from the new address and no ESP came back — an idle tunnel is
        // silent because there is nothing to hear, not because ESP is broken. The DECISION
        // is made here; the rekey itself runs on the timer thread, which is allowed to
        // block for two retransmit schedules. This thread is not: it is the only one that
        // enforces NO_ROUTE_GRACE, and a blocking rekey would stop it probing the route,
        // following a second address change and declaring the tunnel dead on time
        // (DESIGN §17.1). Skipped once `close()` has started.
        let mobike = lock(&shared.ike).mobike_enabled();
        let times = shared.path.snapshot();
        if !shared.closing.load(Ordering::SeqCst)
            && esp_migration_stalled(
                mobike,
                rekeyed_after_move,
                moved_at,
                times.last_esp_tx,
                times.last_esp_rx,
                Instant::now(),
                ONE_WAY_PROBE_SILENCE,
            )
        {
            // Out of attempts for this move: the child SA is black-holed, every rekey we
            // were allowed to run has been answered or refused, and no liveness check can
            // see it (the IKE SA did move, so it answers every probe). The caller has to
            // rebuild the tunnel.
            if esp_rekey_attempts >= ESP_MIGRATION_REKEY_ATTEMPTS {
                if shared.is_alive() {
                    shared.mark_dead(format!(
                        "the child SA did not survive the address update \
                         ({esp_rekey_attempts} rekeys did not restore ESP)"
                    ));
                }
                continue;
            }
            rekeyed_after_move = true;
            warn!("path: no ESP since the address update and the peer has no MOBIKE; asking for a child SA rekey");
            shared.path.request_esp_rekey();
        }
    }
    debug!("path thread stopped");
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
                // The path clocks are stamped inside `handle_esp`, and only for a packet
                // that DECRYPTED: see the note there.
                handle_esp(&shared, &packet);
            }
            Ok(Some(Incoming::Ike(datagram))) => {
                consecutive_errors = 0;
                shared.touch_rx();
                // Likewise stamped inside, once the message has been authenticated.
                handle_ike_datagram(&shared, datagram, &mut fragments);
            }
            Err(e) => {
                if shared.stop.load(Ordering::SeqCst) {
                    break;
                }
                // A removed address often surfaces on `recvfrom` first; the path monitor
                // decides what it means (this loop never marks the tunnel dead).
                shared.path.note_path_error(&e);
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
    // Only NOW, with the ICV verified and the replay window passed, is this evidence
    // that the gateway is still there: this is what the one-way probe and the wedge rule
    // count, and — on its ESP-only clock — what tells the migration check that the child
    // SA survived a move (DESIGN §17.3/§17.5). Datagrams that do not authenticate must
    // not refresh it: a gateway emitting ESP under an SPI we no longer hold would
    // otherwise suppress every liveness check forever while carrying nothing.
    shared.path.note_rx_esp();
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
    // Authenticated under our SK_a: only now is it proof that the gateway is answering
    // (DESIGN §17.5). An undecodable datagram must not clear `first_tx_since_rx`.
    shared.path.note_rx_data();

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

/// Sleep `d` in slices, returning early (false) when the tunnel is stopping OR
/// `close()` has started — used between DPD retries, which must not keep `close()`
/// waiting for a retry window it will never need.
fn sleep_unless_closing(shared: &Shared, d: Duration) -> bool {
    let deadline = Instant::now() + d;
    while !shared.stop.load(Ordering::SeqCst) && !shared.closing.load(Ordering::SeqCst) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(TICK_SLICE));
    }
    false
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
                // Evidence that the socket can still send — but deliberately NOT
                // `note_data_tx`: a keepalive is sent unconditionally and must never
                // count as one-way traffic.
                shared.path.note_send_ok();
                let n = shared.counters.keepalives_sent.fetch_add(1, Ordering::Relaxed) + 1;
                debug!("NAT-T keepalive #{n} sent");
            }
            Err(e) => {
                // On an idle registered tunnel this is the only outbound traffic there
                // is, so it is also the only thing that can start the "sends are failing"
                // clock the wedge rule reads.
                shared.path.note_send_error(&e);
                warn!("NAT-T keepalive failed: {e}");
            }
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
        "timer: child rekey in {:?}, IKE rekey in {:?}, DPD {}, one-way probe after {:?} of silence, idle probe after {:?}",
        child_soft,
        ike_soft,
        if cfg.ike.dpd.enabled { format!("after {:?} idle", dpd_interval) } else { "disabled".into() },
        ONE_WAY_PROBE_SILENCE,
        IDLE_PROBE_SILENCE
    );
    let mut child_retry_after: Option<Instant> = None;
    let mut ike_retry_after: Option<Instant> = None;
    let mut last_one_way: Option<Instant> = None;
    let mut last_idle_probe: Option<Instant> = None;
    let established = Instant::now();

    while sleep_unless_stopped(&shared, TIMER_TICK) {
        if !shared.alive.load(Ordering::SeqCst) {
            continue;
        }
        // `close()` is running: it needs `request_lock` for its DELETE(IKE), and nothing
        // here may take it — nor relabel a deliberate close as a gateway failure.
        if shared.closing.load(Ordering::SeqCst) {
            continue;
        }
        // While the path monitor is repairing the path, a silent gateway proves nothing.
        let suspended = shared.path.suspended();

        // Dead peer detection (only when the bundle enables it).
        if cfg.ike.dpd.enabled && !suspended && shared.idle_for() >= dpd_interval {
            let mut ok = false;
            for attempt in 0..=cfg.ike.dpd.max_retries {
                match do_dpd(&shared, &cfg.ike.retransmit) {
                    Ok(_) => {
                        ok = true;
                        break;
                    }
                    // The probe never left a working socket: that is a local path
                    // failure, not a dead peer. Leave it to the path monitor.
                    Err(ref e) if is_path_failure(e) => {
                        warn!("DPD could not be sent on a broken path ({e}); leaving it to the path monitor");
                        ok = true;
                        break;
                    }
                    Err(Error::Timeout(_)) if attempt < cfg.ike.dpd.max_retries => {
                        warn!("DPD attempt {}/{} timed out; retrying in {:?}", attempt + 1, cfg.ike.dpd.max_retries + 1, dpd_retry);
                        if !sleep_unless_closing(&shared, dpd_retry) {
                            return;
                        }
                    }
                    // `close()` abandoned the probe (or the tunnel is already dead): that
                    // is not a dead peer, and marking it one here would both lose the real
                    // reason and clear `alive` under the DELETE(IKE) still to be sent.
                    Err(Error::Closed(_)) => {
                        debug!("DPD abandoned: the tunnel is closing");
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        warn!("DPD failed: {e}");
                        break;
                    }
                }
            }
            if !ok {
                if shared.path.suspended() {
                    // The path moved while we were probing.
                    continue;
                }
                // AOSP: torn down WITHOUT sending DELETE.
                shared.mark_dead("dead peer detection failed");
                continue;
            }
        }

        // Liveness probes that do not depend on `dpd.enabled`, since operator bundles
        // routinely turn DPD off (DESIGN §17.5). Either we have been transmitting IKE/ESP
        // and nothing came back (ONE_WAY_PROBE_SILENCE), or the tunnel is fully idle and
        // the gateway has said nothing at all for IDLE_PROBE_SILENCE.
        let times = shared.path.snapshot();
        let now = Instant::now();
        let probe = if suspended {
            None
        } else if one_way_probe_due(times.first_tx_since_rx, last_one_way, now, ONE_WAY_PROBE_SILENCE) {
            last_one_way = Some(now);
            Some(format!("one-way traffic: nothing received for {ONE_WAY_PROBE_SILENCE:?} while sending"))
        } else if idle_probe_due(times.last_rx_data, last_idle_probe, established, now, IDLE_PROBE_SILENCE) {
            last_idle_probe = Some(now);
            Some(format!("idle tunnel: nothing received from the gateway for {IDLE_PROBE_SILENCE:?}"))
        } else {
            None
        };
        if let Some(why) = probe {
            warn!("{why}; probing the gateway");
            match do_dpd(&shared, &cfg.ike.retransmit) {
                Ok(rtt) => info!("liveness probe answered in {rtt:?}"),
                Err(Error::Timeout(_)) if !shared.path.suspended() && !shared.closing.load(Ordering::SeqCst) => {
                    shared.mark_dead("gateway stopped answering");
                    continue;
                }
                // The path moved (or the tunnel is going down) under the probe.
                Err(Error::Timeout(_)) | Err(Error::Closed(_)) => continue,
                Err(e) => {
                    shared.path.note_path_error(&e);
                    warn!("liveness probe failed: {e}");
                }
            }
        }

        // The path thread found the child SA stalled after a non-MOBIKE move and handed
        // the repair here (DESIGN §17.3): this thread may block for a retransmit
        // schedule, the path thread — the only one that enforces NO_ROUTE_GRACE — may not.
        // Not while the path monitor is repairing the path: `rekey_child`'s abort
        // predicate would fire before the first send, so the exchange would be charged as
        // a failed repair without a single datagram leaving the host (DESIGN §17.4). The
        // request simply stays pending until the path has settled.
        if !suspended && shared.path.take_esp_rekey_request() {
            warn!("rekeying the child SA after the address update (no ESP came back and the peer has no MOBIKE)");
            let mut installed = false;
            let error = rekey_child(&shared, &mut installed).err();
            match escalation_outcome(error.as_ref(), installed, shared.path.suspended()) {
                EscalationOutcome::Fatal => {
                    // Only ever returned for an error.
                    if let Some(e) = error {
                        shared.mark_dead(format!("child rekey after the address update: {e}"));
                    }
                    continue;
                }
                EscalationOutcome::Done => {
                    match &error {
                        None => info!("child SA rekeyed after the move"),
                        Some(e) => warn!(
                            "the old child SA could not be deleted after the move ({e}); the rekey itself completed"
                        ),
                    }
                    shared.path.note_esp_rekey_done();
                }
                EscalationOutcome::Abandoned => {
                    if let Some(e) = &error {
                        debug!(
                            "the child rekey after the move was abandoned before it reached the gateway ({e}); re-arming"
                        );
                    }
                    shared.path.request_esp_rekey();
                }
                EscalationOutcome::Failed => {
                    if let Some(e) = &error {
                        warn!("child rekey after the move failed: {e}");
                    }
                    shared.path.note_esp_rekey_failed();
                }
            }
        }

        // Child SA rekey at the soft lifetime.
        let child_due = lock(&shared.child_created).elapsed() >= child_soft
            && child_retry_after.is_none_or(|t| Instant::now() >= t);
        if child_due {
            // The lifetime rekey does not care WHERE it failed: a failed DELETE of the
            // old child SA is retried with the whole exchange after `REKEY_RETRY_DELAY`.
            let mut installed = false;
            match rekey_child(&shared, &mut installed) {
                Ok(()) => child_retry_after = None,
                Err(e) if rekey_failure_is_fatal(&e, shared.path.suspended()) => {
                    shared.mark_dead(format!("child rekey: {e}"));
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
                Err(e) if rekey_failure_is_fatal(&e, shared.path.suspended()) => {
                    shared.mark_dead(format!("IKE rekey: {e}"));
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

    /// The outer socket's local address right now. Unlike `info().local_addr` this
    /// follows the path monitor's rebinds (DESIGN §17).
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.transport.local_addr()
    }

    /// True when the responder announced `MOBIKE_SUPPORTED` (RFC 4555 §3.1).
    ///
    /// This reports only what the gateway announced. The form an address change takes is
    /// decided by `peer_mobike && cfg.ike.mobike`: with MOBIKE switched off in the config
    /// this stays true while every move uses the RFC 7296 §2.23 fallback.
    pub fn peer_mobike(&self) -> bool {
        self.info.peer_mobike
    }

    /// The gateway's CURRENT NAT verdict. Unlike `info().nat` this follows the NAT
    /// detection re-run by a MOBIKE address update (RFC 4555 §3.8), which is where a
    /// handover can turn `detected` off and with it break UDP-encapsulated ESP.
    /// `None` before `IKE_SA_INIT` has been answered.
    pub fn nat(&self) -> Option<NatStatus> {
        lock(&self.shared.ike).nat()
    }

    /// Tell the tunnel that the host's network may have changed — call this from an OS
    /// network-change callback (`NWPathMonitor`, `ConnectivityManager`, …).
    ///
    /// Returns immediately. The path thread re-probes within milliseconds and, if the
    /// egress address moved, rebinds the outer socket and announces the new address.
    /// The tunnel also detects changes on its own every [`PATH_PROBE_INTERVAL`]; this
    /// only makes the reaction prompt.
    pub fn network_changed(&self) {
        if self.shared.is_alive() {
            info!("network change reported by the caller");
            self.shared.path.request_probe(true);
        }
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
        if let Err(Error::Timeout(_)) = &r
            && !self.shared.path.suspended()
            && !self.shared.closing.load(Ordering::SeqCst)
        {
            // AOSP: retransmission exhaustion tears the session down WITHOUT a DELETE.
            // Unless the path monitor is mid-repair: then the silence is ours, not the
            // gateway's, and the grace period decides.
            self.shared.mark_dead("dead peer detection failed");
        }
        r
    }

    pub fn stats(&self) -> TunnelStats {
        self.shared.stats()
    }

    /// The inner smoltcp stack (for the `NetStack` implementation: inner addresses).
    pub(crate) fn stack(&self) -> &InnerStack {
        &self.shared.stack
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
        // Before the DELETE: the path thread and any address update abandon at once, so
        // close() cannot wait out a retransmit schedule behind `request_lock`. `stop` is
        // deliberately NOT set yet — the rx thread must stay alive to deliver the
        // DELETE(IKE) response below.
        shared.closing.store(true, Ordering::SeqCst);
        shared.path.wake();
        shared.pending_cv.notify_all();
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
        shared.path.wake();
        // A deliberate close and a failure both reach inner sockets as Error::Closed;
        // only the reason distinguishes them (DESIGN §17).
        shared.close_stack("tunnel closed by request".into());
        for h in [
            self.rx_thread.take(),
            self.keepalive_thread.take(),
            self.timer_thread.take(),
            self.path_thread.take(),
            self.stack_thread.take(),
        ]
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
        if !self.closed
            && let Err(e) = self.shutdown()
        {
            debug!("drop: close failed: {e}");
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
        assert_eq!(s.address_updates, 0);
        assert_eq!(s.stray_sources, 0);
        assert_eq!(s.stack, StackStats::default());
        assert!(s.last_rx.is_none());
    }

    // --- Path monitor (pure) ------------------------------------------------------

    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));
    const IP_C: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 20, 3, 4));

    /// A tick with no send failures and traffic flowing.
    fn input(probe: ProbeOutcome, bound: IpAddr, now: Instant) -> PathInput {
        PathInput { probe, bound, sends_failing_since: None, last_rx_data: Some(now), now }
    }

    #[test]
    fn path_monitor_moves_on_a_changed_egress() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_A, t0)), PathAction::Rebind(IP_B));
        // After the rebind the socket is on B but the gateway has not been told.
        m.rebound(t0);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, t0 + Duration::from_secs(2))), PathAction::Announce);
        m.announced(t0 + Duration::from_secs(2));
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, t0 + Duration::from_secs(4))), PathAction::Idle);
        assert!(m.impaired_since.is_none());
    }

    #[test]
    fn path_monitor_is_idle_when_unchanged() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        for k in 0..30 {
            let now = t0 + Duration::from_secs(k * 2);
            assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_A, now)), PathAction::Idle);
        }
    }

    #[test]
    fn path_monitor_ignores_an_unknown_probe() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        // A probe that could not run must not start the impairment clock ...
        for k in 0..20 {
            let now = t0 + Duration::from_secs(k);
            assert_eq!(m.tick(input(ProbeOutcome::Unknown, IP_A, now)), PathAction::Idle);
        }
        assert!(m.impaired_since.is_none());
        // ... so a real "no route" that follows still gets the full grace period.
        let t1 = t0 + Duration::from_secs(20);
        assert_eq!(m.tick(input(ProbeOutcome::NoRoute, IP_A, t1)), PathAction::Idle);
        assert_eq!(m.tick(input(ProbeOutcome::NoRoute, IP_A, t1 + NO_ROUTE_GRACE - Duration::from_secs(1))), PathAction::Idle);
        assert!(matches!(m.tick(input(ProbeOutcome::NoRoute, IP_A, t1 + NO_ROUTE_GRACE)), PathAction::Dead(_)));
    }

    /// Regression: a probe that cannot run (EMFILE under fd pressure, a sandbox/MDM EPERM
    /// on the throwaway route-probe socket, `discover_egress` finding no address) is
    /// usually PERSISTENT. Returning `Idle` before the grace check froze an
    /// already-running impairment clock forever, and `path_loop` re-latched `suspended`
    /// from the unchanged monitor state — which disables the bundle DPD, both liveness
    /// probes and every rekey. The tunnel then had no path to death at all: `is_alive()`
    /// stayed true while it carried nothing. The clock is evaluated first now.
    #[test]
    fn a_frozen_probe_still_lets_the_grace_expire() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        // A handover: rebound, announce failed transiently, clock running.
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_A, t0)), PathAction::Rebind(IP_B));
        m.rebound(t0);
        m.announce_failed(t0 + Duration::from_secs(16));
        // From here the route probe itself fails in a non-path way, every single tick.
        let mut t = t0 + Duration::from_secs(18);
        while t < t0 + NO_ROUTE_GRACE {
            assert_eq!(m.tick(input(ProbeOutcome::Unknown, IP_B, t)), PathAction::Idle);
            t += PATH_PROBE_INTERVAL;
        }
        match m.tick(input(ProbeOutcome::Unknown, IP_B, t0 + NO_ROUTE_GRACE)) {
            PathAction::Dead(reason) => assert!(reason.contains("acknowledged"), "{reason}"),
            other => panic!("the grace must expire even while the probe cannot run, got {other:?}"),
        }
    }

    #[test]
    fn path_monitor_dies_after_the_no_route_grace() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        assert_eq!(m.tick(input(ProbeOutcome::NoRoute, IP_A, t0)), PathAction::Idle);
        let action = m.tick(input(ProbeOutcome::NoRoute, IP_A, t0 + NO_ROUTE_GRACE));
        match action {
            PathAction::Dead(reason) => assert!(reason.contains("no route to the gateway"), "{reason}"),
            other => panic!("expected death, got {other:?}"),
        }
    }

    #[test]
    fn path_monitor_rebinds_when_the_route_returns_on_the_same_address() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        assert_eq!(m.tick(input(ProbeOutcome::NoRoute, IP_A, t0)), PathAction::Idle);
        // The interface came back on the same address: the old binding may be stale and
        // the fresh ephemeral port is itself what the gateway must learn.
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_A, t0 + Duration::from_secs(4))), PathAction::Rebind(IP_A));
    }

    #[test]
    fn path_monitor_retries_the_announce_without_rebinding() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_A, t0)), PathAction::Rebind(IP_B));
        m.rebound(t0);
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, t1)), PathAction::Announce);
        m.announce_failed(t1);
        // Still an announce, never another rebind (that was the unbounded-rebind bug).
        let t2 = t0 + Duration::from_secs(4);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, t2)), PathAction::Announce);
        // ... until the grace period runs out, with the announce reason.
        match m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, t0 + NO_ROUTE_GRACE)) {
            PathAction::Dead(reason) => assert!(reason.contains("acknowledged"), "{reason}"),
            other => panic!("expected death, got {other:?}"),
        }
    }

    /// Regression: a silent gateway after a handover (a new AP whose uplink is not usable
    /// for a few seconds) is the dominant announce failure. Classifying its retransmission
    /// exhaustion as fatal killed the tunnel at 15.5 s and made the whole retry-inside-the
    /// grace machinery unreachable; the grace must be the single authority.
    #[test]
    fn a_silent_gateway_after_a_move_is_retried_until_the_grace_expires() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_A, t0)), PathAction::Rebind(IP_B));
        m.rebound(t0);
        // Exactly what `announce()` returns when the schedule runs out; `path_loop` only
        // marks the tunnel dead when this classifies as fatal.
        let exhausted = Error::Timeout("INFORMATIONAL (UPDATE_SA_ADDRESSES)");
        assert!(address_update_failure(&exhausted).is_none(), "a silent gateway is transient");
        m.announce_failed(t0);
        // One full 15.5 s retransmit schedule later the tunnel is still up and the
        // announce is simply retried from the socket we already rebound.
        let after_one_schedule = t0 + Duration::from_millis(15_500);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, after_one_schedule)), PathAction::Announce);
        assert!(address_update_failure(&exhausted).is_none());
        m.announce_failed(after_one_schedule);
        // Death comes from the grace, not from the retransmit schedule.
        match m.tick(input(ProbeOutcome::Egress(IP_B), IP_B, t0 + NO_ROUTE_GRACE)) {
            PathAction::Dead(reason) => assert!(reason.contains("acknowledged"), "{reason}"),
            other => panic!("expected death at the grace, got {other:?}"),
        }
    }

    #[test]
    fn path_monitor_rebinds_to_the_same_address_when_sends_are_wedged_then_dies() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        let wedged = |now: Instant| PathInput {
            probe: ProbeOutcome::Egress(IP_A),
            bound: IP_A,
            sends_failing_since: Some(t0),
            last_rx_data: Some(t0),
            now,
        };
        assert_eq!(m.tick(wedged(t0 + Duration::from_secs(1))), PathAction::Idle);
        // Sends have been failing and nothing came back for the whole grace: one retry.
        assert_eq!(m.tick(wedged(t0 + NO_ROUTE_GRACE)), PathAction::Rebind(IP_A));
        m.rebound(t0 + NO_ROUTE_GRACE);
        m.announced(t0 + NO_ROUTE_GRACE);
        // Still wedged afterwards: fatal.
        match m.tick(wedged(t0 + NO_ROUTE_GRACE + Duration::from_secs(1))) {
            PathAction::Dead(reason) => assert!(reason.contains("unusable"), "{reason}"),
            other => panic!("expected death, got {other:?}"),
        }
    }

    #[test]
    fn path_monitor_damps_a_flapping_route() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        // The first move is immediate: a handover must not be delayed.
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_A, t0)), PathAction::Rebind(IP_B));
        m.rebound(t0);
        m.announced(t0);
        // A move right back has to wait MIN_ADDRESS_UPDATE_INTERVAL out; that interval
        // is the ONLY gate (there is no separate confirmation step).
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_B, t1)), PathAction::Idle);
        let t2 = t0 + Duration::from_secs(2);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_B, t2)), PathAction::Idle);
        let t3 = t0 + MIN_ADDRESS_UPDATE_INTERVAL;
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_B, t3)), PathAction::Rebind(IP_A));
    }

    /// Regression (round-5 finding): the recovery rebind is damped too.
    ///
    /// A link that flaps between "no route" and the SAME address alternates the
    /// impairment branch and the recovery branch, neither of which used to consult
    /// `last_move`: every blip bound a fresh ephemeral port and spent one
    /// UPDATE_SA_ADDRESSES — invalidating the gateway's NAT binding each time, which is
    /// precisely what `MIN_ADDRESS_UPDATE_INTERVAL` exists to prevent. Out-of-band probe
    /// requests (an ESP send error) make the cycle as short as `PATH_PROBE_MIN_SPACING`,
    /// so the rate was not bounded by the probe interval either.
    #[test]
    fn path_monitor_damps_a_route_that_flaps_back_to_the_same_address() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        m.announced(t0);
        // The route disappears and comes straight back on the address we are bound to.
        assert_eq!(m.tick(input(ProbeOutcome::NoRoute, IP_A, t0 + Duration::from_secs(2))), PathAction::Idle);
        assert_eq!(
            m.tick(input(ProbeOutcome::Egress(IP_A), IP_A, t0 + Duration::from_secs(4))),
            PathAction::Idle,
            "a recovery inside the minimum interval must not spend an address update"
        );
        // The impairment clock keeps running while we wait, so NO_ROUTE_GRACE still
        // bounds the outage — and once the interval has passed the rebind happens.
        assert_eq!(
            m.tick(input(ProbeOutcome::Egress(IP_A), IP_A, t0 + MIN_ADDRESS_UPDATE_INTERVAL)),
            PathAction::Rebind(IP_A)
        );
        // A first impairment with no move behind it is still acted on immediately.
        let mut fresh = PathMonitor::default();
        assert_eq!(fresh.tick(input(ProbeOutcome::NoRoute, IP_A, t0)), PathAction::Idle);
        assert_eq!(fresh.tick(input(ProbeOutcome::Egress(IP_A), IP_A, t0)), PathAction::Rebind(IP_A));
    }

    /// Regression (finding: two gates doing one job): a candidate that merely differs
    /// from the previous probe's used to be held back for one more probe interval, which
    /// delayed a genuine handover without lowering the update rate — and could stall a
    /// move indefinitely while a route alternated between two addresses that were both
    /// different from the bound one. Only the minimum interval gates a move now.
    #[test]
    fn path_monitor_moves_to_a_new_candidate_as_soon_as_the_interval_allows() {
        let t0 = Instant::now();
        let mut m = PathMonitor::default();
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_B), IP_A, t0)), PathAction::Rebind(IP_B));
        m.rebound(t0);
        m.announced(t0);
        // Inside the minimum interval nothing happens, whatever the route says.
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_B, t0 + Duration::from_secs(1))), PathAction::Idle);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_C), IP_B, t0 + Duration::from_secs(2))), PathAction::Idle);
        // Once it has elapsed the next probe is acted on, even though the previous one
        // named a different candidate.
        let after = t0 + MIN_ADDRESS_UPDATE_INTERVAL + Duration::from_secs(1);
        assert_eq!(m.tick(input(ProbeOutcome::Egress(IP_A), IP_B, after)), PathAction::Rebind(IP_A));
    }

    // --- Liveness / failure classification (pure) ----------------------------------

    #[test]
    fn one_way_probe_due_needs_new_evidence() {
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let late = t0 + Duration::from_secs(25);
        // Never transmitted since the last thing we heard: nothing to conclude.
        assert!(!one_way_probe_due(None, None, late, silence));
        // Transmitting, but the silence is still short.
        assert!(!one_way_probe_due(Some(t0 + Duration::from_secs(10)), None, t0 + Duration::from_secs(15), silence));
        // Transmitting into silence for long enough.
        assert!(one_way_probe_due(Some(t0 + Duration::from_secs(1)), None, late, silence));
        // A probe just ran: do not re-probe without new evidence.
        assert!(!one_way_probe_due(Some(t0 + Duration::from_secs(1)), Some(late), late, silence));
        assert!(one_way_probe_due(Some(t0 + Duration::from_secs(1)), Some(t0 + Duration::from_secs(2)), late, silence));
        // A `now` before the stored instants must not panic.
        assert!(!one_way_probe_due(Some(late), None, t0, silence));
    }

    /// Regression: a tunnel that has NEVER received anything while retransmitting into a
    /// black hole (a one-way child SA — the case R2 exists for) must become due. Anchoring
    /// the window at the LATEST transmission kept it at zero forever, so the probe never
    /// ran, the tunnel was never declared dead and the SIP transport was never told.
    #[test]
    fn one_way_probe_fires_while_a_client_keeps_retransmitting_into_silence() {
        let t0 = Instant::now();
        let silence = ONE_WAY_PROBE_SILENCE;
        let state = PathState::default();
        let mut due_at: Option<Duration> = None;
        for ms in (0..120_000u64).step_by(500) {
            let now = t0 + Duration::from_millis(ms);
            // Every tick sends again and nothing ever comes back.
            state.note_data_tx();
            let times = state.snapshot();
            assert!(times.last_rx_data.is_none());
            if due_at.is_none() && one_way_probe_due(times.first_tx_since_rx, None, now, silence) {
                due_at = Some(Duration::from_millis(ms));
            }
        }
        let due_at = due_at.expect("the probe must become due while transmitting into silence");
        assert!(due_at >= silence, "not before the silence threshold: {due_at:?}");
        assert!(due_at < silence + Duration::from_secs(1), "and right at it: {due_at:?}");

        // A datagram from the gateway restarts the window at the NEXT transmission.
        state.note_rx_data();
        assert!(state.snapshot().first_tx_since_rx.is_none());
        assert!(!one_way_probe_due(state.snapshot().first_tx_since_rx, None, t0 + Duration::from_secs(600), silence));
        state.note_data_tx();
        assert!(!one_way_probe_due(state.snapshot().first_tx_since_rx, None, Instant::now(), silence));
    }

    #[test]
    fn esp_migration_stalled_only_without_mobike() {
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let late = t0 + Duration::from_secs(25);
        let sent = Some(t0 + Duration::from_secs(1));
        // MOBIKE peers move the child SA themselves.
        assert!(!esp_migration_stalled(true, false, Some(t0), sent, Some(t0), late, silence));
        // A rekey is in flight or done for this move.
        assert!(!esp_migration_stalled(false, true, Some(t0), sent, Some(t0), late, silence));
        // No move yet.
        assert!(!esp_migration_stalled(false, false, None, sent, Some(t0), late, silence));
        // ESP came back after the move: nothing stalled.
        assert!(!esp_migration_stalled(false, false, Some(t0), sent, Some(t0 + Duration::from_secs(2)), late, silence));
        // Too early to tell.
        assert!(!esp_migration_stalled(false, false, Some(t0), sent, Some(t0), t0 + Duration::from_secs(5), silence));
        // Moved, transmitted since, and silent ever since.
        assert!(esp_migration_stalled(false, false, Some(t0), sent, Some(t0), late, silence));
        assert!(esp_migration_stalled(false, false, Some(t0), sent, None, late, silence));
    }

    /// Regression (finding: the escalation was gated on an IKE-inclusive clock): after a
    /// non-MOBIKE move the IKE SA is by assumption working, so a peer DPD — or the
    /// response to our own one-way probe, which becomes due at the SAME threshold — used
    /// to disarm the escalation permanently for that move, in exactly the state it exists
    /// for. The check now reads the ESP-only clocks, and IKE traffic does not touch them.
    #[test]
    fn esp_migration_ignores_ike_traffic_after_the_move() {
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let esp_sent = Some(t0 + Duration::from_secs(1));
        // Inbound IKE at t0+5 (a peer DPD, or our probe's own response) leaves
        // `last_esp_rx` where it was: the child SA is still black-holed.
        let no_esp_back = Some(t0 - Duration::from_millis(1));
        assert!(esp_migration_stalled(false, false, Some(t0), esp_sent, no_esp_back, t0 + Duration::from_secs(25), silence));
        // Symmetrically, an IKE request of ours is not evidence that ESP was sent: an
        // idle tunnel whose only transmission after the move was a DPD must not be
        // rekeyed.
        assert!(!esp_migration_stalled(false, false, Some(t0), no_esp_back, no_esp_back, t0 + Duration::from_secs(25), silence));
    }

    /// Regression: an IDLE registered tunnel receives nothing by definition (NAT-T
    /// keepalives are excluded and the gateway sends nothing unsolicited), so a move on a
    /// non-MOBIKE peer used to escalate to a full child rekey 20 s later every single
    /// time. Without outbound traffic since the move, nothing is owed and nothing stalls.
    #[test]
    fn esp_migration_is_not_stalled_on_an_idle_tunnel() {
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let late = t0 + Duration::from_secs(25);
        // `moved_at` is taken after the announce response, so any ESP from before the
        // move is older than it.
        let before_move = Some(t0 - Duration::from_millis(1));
        assert!(!esp_migration_stalled(false, false, Some(t0), before_move, before_move, late, silence));
        assert!(!esp_migration_stalled(false, false, Some(t0), None, None, late, silence));
        // One ESP packet after the move and no answer: now it is a stall.
        assert!(esp_migration_stalled(false, false, Some(t0), Some(t0 + Duration::from_secs(1)), before_move, late, silence));
    }

    /// Regression: the ESP-silence window is measured from the TRANSMISSION, not merely
    /// from the move. With only `now - moved_at >= silence` the escalation armed on the
    /// first ESP packet after a quiet move — an idle IMS registration that sends one
    /// REGISTER five minutes later was "stalled" within one probe interval, before the
    /// gateway could possibly have answered, costing a spurious CREATE_CHILD_SA +
    /// DELETE(ESP) on a healthy tunnel.
    #[test]
    fn esp_migration_waits_out_the_silence_after_the_transmission() {
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let before_move = Some(t0 - Duration::from_millis(1));
        // Idle across the move, then one ESP packet at m + 300 s.
        let tx = t0 + Duration::from_secs(300);
        assert!(!esp_migration_stalled(false, false, Some(t0), Some(tx), before_move, tx + Duration::from_millis(1), silence));
        assert!(!esp_migration_stalled(false, false, Some(t0), Some(tx), before_move, tx + Duration::from_millis(500), silence));
        assert!(!esp_migration_stalled(false, false, Some(t0), Some(tx), before_move, tx + silence - Duration::from_secs(1), silence));
        // Only once the silence has elapsed SINCE THAT PACKET is it evidence of a stall.
        assert!(esp_migration_stalled(false, false, Some(t0), Some(tx), before_move, tx + silence, silence));
        // An answer in the meantime disarms it for good (that move is proven healthy).
        assert!(!esp_migration_stalled(
            false,
            false,
            Some(t0),
            Some(tx),
            Some(tx + Duration::from_millis(30)),
            tx + silence,
            silence
        ));
    }

    /// Regression (finding: an idle tunnel had no liveness check at all): the one-way
    /// probe needs evidence that we transmitted, which a registered but silent tunnel
    /// never produces, and the bundle-driven DPD is disabled by the operator. The idle
    /// probe is anchored on what we last HEARD instead.
    #[test]
    fn idle_probe_fires_on_a_tunnel_that_never_transmits() {
        let t0 = Instant::now();
        let silence = Duration::from_secs(120);
        // Nothing has ever been received: the anchor is establishment.
        assert!(!idle_probe_due(None, None, t0, t0 + Duration::from_secs(119), silence));
        assert!(idle_probe_due(None, None, t0, t0 + silence, silence));
        // The one-way probe would never fire here (no transmission), which is the gap
        // this closes.
        assert!(!one_way_probe_due(None, None, t0 + Duration::from_secs(600), silence));
        // Anything received from the gateway restarts the window ...
        let rx = Some(t0 + Duration::from_secs(60));
        assert!(!idle_probe_due(rx, None, t0, t0 + Duration::from_secs(150), silence));
        assert!(idle_probe_due(rx, None, t0, t0 + Duration::from_secs(181), silence));
        // ... and so does a probe of our own, so an unanswered-but-not-fatal probe does
        // not re-fire every tick.
        let probed = Some(t0 + Duration::from_secs(180));
        assert!(!idle_probe_due(rx, probed, t0, t0 + Duration::from_secs(181), silence));
        assert!(idle_probe_due(rx, probed, t0, t0 + Duration::from_secs(300), silence));
    }

    #[test]
    fn address_update_failure_classifies_outcomes() {
        // A silent gateway is transient: the 30 s grace, not the 15.5 s retransmit
        // schedule, decides when a handover has failed for good.
        assert!(address_update_failure(&Error::Timeout("INFORMATIONAL (UPDATE_SA_ADDRESSES)")).is_none());
        assert!(
            address_update_failure(&Error::PeerNotify {
                notify_type: N_UNEXPECTED_NAT_DETECTION,
                name: notify_name(N_UNEXPECTED_NAT_DETECTION),
                exchange: "INFORMATIONAL (address update)",
                data: vec![],
            })
            .is_some()
        );
        assert!(address_update_failure(&Error::Decode("x".into())).is_some());
        assert!(address_update_failure(&Error::Integrity("SK")).is_some());
        // Transient: the monitor keeps working inside the grace period.
        assert!(
            address_update_failure(&Error::Io(std::io::Error::new(std::io::ErrorKind::NetworkUnreachable, "x"))).is_none()
        );
        assert!(address_update_failure(&Error::Closed("already dead".into())).is_none());
        assert!(address_update_failure(&Error::Protocol("another request is outstanding".into())).is_none());
    }

    /// Regression: a LOCAL send failure during the announce is not the gateway rejecting
    /// the move. The classifier used to have a catch-all that made every non-path
    /// `Error::Io` fatal, so one ENOBUFS (errno 55, an `Uncategorized` kind that
    /// `is_path_failure` does not know) or one EPERM from a host firewall on the first
    /// datagram out of a brand-new interface tore the tunnel — and the SIP registration —
    /// down during exactly the Wi-Fi/LTE handover this feature exists to survive.
    #[test]
    fn a_local_send_failure_during_an_announce_is_not_a_rejection() {
        let enobufs = Error::Io(std::io::Error::from_raw_os_error(55));
        assert!(!is_path_failure(&enobufs), "ENOBUFS is deliberately not a path failure");
        assert!(address_update_failure(&enobufs).is_none(), "ENOBUFS must not kill the tunnel");
        let eperm = Error::Io(std::io::Error::from_raw_os_error(1));
        assert!(!is_path_failure(&eperm));
        assert!(address_update_failure(&eperm).is_none(), "a firewall EPERM must not kill the tunnel");
        // A short write is synthesised as WriteZero by the transport; same reasoning.
        assert!(
            address_update_failure(&Error::Io(std::io::Error::new(std::io::ErrorKind::WriteZero, "short send"))).is_none()
        );
        // Encoding our own request cannot be the gateway's fault either.
        assert!(address_update_failure(&Error::Encode("x".into())).is_none());
    }

    /// Regression: a rekey running while the path monitor moves the SA used to time out
    /// (its request had left an address that no longer existed) and be read as a dead
    /// peer, tearing the tunnel down in the middle of the handover R1 exists to survive.
    #[test]
    fn rekey_failures_are_only_fatal_on_a_settled_path() {
        let timeout = Error::Timeout("CREATE_CHILD_SA (rekey child)");
        assert!(rekey_failure_is_fatal(&timeout, false), "a settled path: the gateway is gone");
        assert!(!rekey_failure_is_fatal(&timeout, true), "the monitor is repairing the path");
        // What the abort predicate returns when the path moved or close() started: the
        // request never reached the gateway.
        let aborted = Error::Io(std::io::Error::new(std::io::ErrorKind::NetworkDown, "the local path changed"));
        assert!(!rekey_failure_is_fatal(&aborted, false));
        assert!(!rekey_failure_is_fatal(&Error::Closed("tunnel closing".into()), false));
        assert!(!rekey_failure_is_fatal(&Error::Protocol("no child SA to rekey".into()), false));
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
        test_shared_to(500)
    }

    /// [`test_shared`] aimed at a caller-chosen loopback port, so a test can bind a plain
    /// `UdpSocket` there and inspect the datagrams the tunnel actually sends.
    fn test_shared_to(remote_port: u16) -> Arc<Shared> {
        test_shared_remote(Ipv4Addr::LOCALHOST, remote_port)
    }

    /// [`test_shared_to`] with the gateway address too, so a test can aim the outer
    /// socket somewhere `send_to` REFUSES (the v4 broadcast address on a socket without
    /// `SO_BROADCAST` fails with EACCES on macOS and Linux alike) and exercise the
    /// send-failure paths without any live traffic.
    fn test_shared_remote(remote_ip: Ipv4Addr, remote_port: u16) -> Arc<Shared> {
        let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
        let cfg = Config::from_plist_files(
            std::path::Path::new(&format!("{fx}tmobile_prod_bundle.plist")),
            std::path::Path::new(&format!("{fx}tmobile_creds.plist")),
            std::path::Path::new(&format!("{fx}client.crt")),
            std::path::Path::new(&format!("{fx}client.key")),
        )
        .unwrap();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let transport = IkeTransport::bind(Some(lo), IpAddr::V4(remote_ip), remote_port).unwrap();
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
        let path = Arc::new(PathState::default());
        let stack =
            InnerStack::new(&AssignedConfig::default(), esp_sink(&transport, &outbound, &counters, &path), 1280, 16384)
                .unwrap();
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
            closing: AtomicBool::new(false),
            path,
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

    #[test]
    fn mark_dead_publishes_the_reason_before_closing_the_stack() {
        let shared = test_shared();
        let sock = shared.stack.bind_udp(0).unwrap();
        // A receiver parked on an inner socket must wake with the tunnel's dead reason
        // at once — not at its own timeout — so the SIP transport can close promptly.
        let waiter = thread::spawn(move || {
            let started = Instant::now();
            let r = sock.recv_timeout(Duration::from_secs(10));
            (r, started.elapsed(), sock)
        });
        thread::sleep(Duration::from_millis(50));
        shared.mark_dead("boom");

        let (r, elapsed, sock) = waiter.join().unwrap();
        assert!(elapsed < Duration::from_secs(2), "woken in {elapsed:?}");
        match r {
            Err(Error::Closed(reason)) => assert!(reason.contains("boom"), "{reason}"),
            other => panic!("expected Closed, got {other:?}"),
        }
        // Everything else fails with the same reason afterwards.
        for e in [
            sock.send_to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060), b"x").unwrap_err(),
            shared.stack.bind_udp(0).unwrap_err(),
            shared.closed_error(),
        ] {
            match e {
                Error::Closed(reason) => assert!(reason.contains("boom"), "{reason}"),
                other => panic!("expected Closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn closing_a_dead_tunnel_keeps_the_first_reason() {
        let shared = test_shared();
        shared.mark_dead("gateway stopped answering");
        // Idempotent: a second death (and the close that follows it, e.g. from `Drop`)
        // must not relabel a tunnel that died of a real failure — the reason is what the
        // SIP transport logs and what a caller reads back (DESIGN §17.6).
        shared.mark_dead("no route to the gateway for 30s");
        shared.close_stack("tunnel closed by request".into());
        let reason = lock(&shared.dead_reason).clone().unwrap();
        assert_eq!(reason, "gateway stopped answering");
        match shared.stack.bind_udp(0).unwrap_err() {
            Error::Closed(r) => assert_eq!(r, "gateway stopped answering"),
            other => panic!("expected Closed, got {other:?}"),
        }
        // A tunnel that is closed without ever having died reports the deliberate close.
        let shared = test_shared();
        shared.close_stack("tunnel closed by request".into());
        assert_eq!(lock(&shared.dead_reason).clone().unwrap(), "tunnel closed by request");
    }

    #[test]
    fn path_thread_stops_on_closing_without_stop() {
        let shared = test_shared();
        let h = spawn_named("epdg-path", Arc::clone(&shared), path_loop).unwrap();
        // `close()` sets `closing` before the DELETE(IKE) and leaves `stop` clear so the
        // rx thread can still deliver its response; the path thread must go anyway.
        shared.closing.store(true, Ordering::SeqCst);
        shared.path.wake();
        let started = Instant::now();
        h.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1), "joined in {:?}", started.elapsed());
        assert!(!shared.stop.load(Ordering::SeqCst));
        assert!(shared.is_alive(), "the path thread's exit does not kill the tunnel");
    }

    #[test]
    fn network_changed_wakes_the_path_thread() {
        let shared = test_shared();
        let h = spawn_named("epdg-path", Arc::clone(&shared), path_loop).unwrap();
        // The route to 127.0.0.1 is 127.0.0.1, i.e. exactly what the transport is bound
        // to, so every tick is a no-op; only the probe clock moves.
        let before = lock(&shared.path.inner).last_probe;
        shared.path.request_probe(true);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut probed = false;
        while Instant::now() < deadline {
            if lock(&shared.path.inner).last_probe != before {
                probed = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        shared.closing.store(true, Ordering::SeqCst);
        shared.path.wake();
        h.join().unwrap();
        assert!(probed, "a forced probe request runs well before the {PATH_PROBE_INTERVAL:?} tick");
        assert!(shared.is_alive());
        assert!(!shared.path.suspended());
    }

    #[test]
    fn path_wait_spaces_unforced_probe_requests() {
        let shared = test_shared();
        // A just-completed probe, as after a tick.
        lock(&shared.path.inner).last_probe = Some(Instant::now());
        shared.path.request_probe(false);
        let started = Instant::now();
        assert!(path_wait(&shared, PATH_PROBE_MIN_SPACING * 2));
        assert!(
            started.elapsed() >= PATH_PROBE_MIN_SPACING,
            "an unforced request waits out the spacing floor ({:?})",
            started.elapsed()
        );
        // A forced request (network_changed) is served immediately.
        shared.path.request_probe(true);
        let started = Instant::now();
        assert!(path_wait(&shared, Duration::from_secs(30)));
        assert!(started.elapsed() < Duration::from_millis(100), "{:?}", started.elapsed());
    }

    #[test]
    fn path_abort_fires_while_the_path_is_suspended() {
        let shared = test_shared();
        assert!(path_abort(&shared).is_none());
        shared.path.set_suspended(true);
        match path_abort(&shared) {
            Some(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NetworkDown),
            other => panic!("expected NetworkDown, got {other:?}"),
        }
        shared.path.set_suspended(false);
        assert!(path_abort(&shared).is_none());
        // And `close()` aborts a request the same way.
        assert!(closing_abort(&shared).is_none());
        shared.closing.store(true, Ordering::SeqCst);
        assert!(matches!(closing_abort(&shared), Some(Error::Closed(_))));
    }

    /// Regression (finding: `close()` waited out the DPD schedule): `do_dpd` installs
    /// only the path abort, so a probe in flight kept `request_lock` — which `close()`
    /// needs for its DELETE(IKE) — for the whole 15.5 s schedule, and the timer then
    /// labelled a deliberate close "gateway stopped answering". The probe must abandon
    /// within a tick of `closing`, and must not mark the tunnel dead.
    #[test]
    fn closing_abandons_an_in_flight_dpd_instead_of_waiting_out_the_schedule() {
        let shared = test_shared();
        lock(&shared.ike).force_established_for_tests();
        let probing = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || do_dpd(&shared, &shared.cfg.ike.retransmit))
        };
        // Let the probe take `request_lock` and send its first datagram (nothing answers
        // on loopback:500, so it would otherwise run the full schedule).
        thread::sleep(Duration::from_millis(150));
        assert!(shared.request_lock.try_lock().is_err(), "the probe holds request_lock");
        let closed_at = Instant::now();
        shared.closing.store(true, Ordering::SeqCst);
        shared.pending_cv.notify_all();
        let r = probing.join().unwrap();
        let waited = closed_at.elapsed();
        assert!(matches!(r, Err(Error::Closed(_))), "{r:?}");
        assert!(waited < Duration::from_secs(2), "close waited {waited:?} for the probe");
        assert!(shared.request_lock.try_lock().is_ok(), "request_lock is free for the DELETE(IKE)");
        assert!(lock(&shared.dead_reason).is_none(), "a deliberate close is not a gateway failure");
        assert!(shared.alive.load(Ordering::SeqCst));
        shared.stack.stop();
    }

    /// Regression (finding: the grace could overshoot by a whole retransmit schedule):
    /// `announce` used to run its 15.5 s schedule to the end whatever the clock said, and
    /// `PathMonitor::tick` — the only place that declares the tunnel dead — cannot run
    /// while the path thread is inside it. An announce that straddles the deadline is now
    /// abandoned there, transiently, so the next tick declares death on time.
    #[test]
    fn an_announce_is_abandoned_at_the_grace_deadline() {
        let shared = test_shared();
        lock(&shared.ike).force_established_for_tests();
        let started = Instant::now();
        let r = announce(&shared, Some(started + Duration::from_millis(200)));
        let waited = started.elapsed();
        let e = r.expect_err("nothing answers on loopback:500");
        assert!(matches!(e, Error::Timeout(_)), "{e}");
        assert!(waited < Duration::from_secs(2), "the announce ran on for {waited:?}");
        assert!(address_update_failure(&e).is_none(), "abandoning is transient; the grace decides");
        assert!(lock(&shared.dead_reason).is_none());
        shared.stack.stop();
    }

    /// Regression (round-3 finding): the liveness clocks used to be stamped in `rx_loop`
    /// BEFORE the datagram was validated, so traffic that never authenticated counted as
    /// proof that the gateway was still there. A gateway emitting ESP under an SPI we no
    /// longer hold (a gateway-side restart on the same 5-tuple, a child rekey we did not
    /// apply) more often than once per `IDLE_PROBE_SILENCE` cleared `first_tx_since_rx`
    /// and refreshed `last_rx_data` / `last_esp_rx` forever: the one-way probe could not
    /// arm, the idle probe never fired, the bundle DPD is disabled, and the ESP-migration
    /// escalation stayed disarmed — a black hole that `is_alive()` reported as healthy.
    #[test]
    fn traffic_that_does_not_authenticate_is_not_proof_of_life() {
        let shared = test_shared();
        shared.path.note_data_tx();
        let before = shared.path.snapshot();
        assert!(before.first_tx_since_rx.is_some(), "one-way evidence is armed");

        // A runt, ESP under an SPI we do not hold, and ESP on a known SPI that fails ICV.
        handle_esp(&shared, &[0x12, 0x34]);
        handle_esp(&shared, &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1]);
        let mut forged = vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1];
        forged.extend_from_slice(&[0x5a; 64]);
        handle_esp(&shared, &forged);
        // An IKE datagram that does not decode under our SK_a.
        handle_ike_datagram(&shared, vec![0x77; 64], &mut FragmentCollector::new());

        let after = shared.path.snapshot();
        assert_eq!(after.last_esp_rx, None, "an unauthenticated packet is not inbound ESP");
        assert_eq!(after.last_rx_data, before.last_rx_data, "nor inbound data");
        assert_eq!(
            after.first_tx_since_rx, before.first_tx_since_rx,
            "and it must not disarm the one-way probe"
        );
        assert_eq!(shared.counters.esp_rx_packets.load(Ordering::Relaxed), 0);
        shared.stack.stop();
    }

    /// Regression (round-3 finding): a request abandoned BEFORE its first datagram left
    /// the socket must not mark its message id as abandoned. `do_dpd`'s abort predicate
    /// fires at the top of attempt 0, so a `dpd()` that loses the race with the path
    /// monitor never reaches the wire — yet it used to poison the next id, which the
    /// announce then had to spend an extra exchange on.
    #[test]
    fn an_unsent_request_does_not_poison_the_next_message_id() {
        let shared = test_shared();
        lock(&shared.ike).force_established_for_tests();
        // The path monitor is repairing the path: every request aborts at attempt 0.
        shared.path.set_suspended(true);
        let started = Instant::now();
        let e = do_dpd(&shared, &shared.cfg.ike.retransmit).unwrap_err();
        assert!(matches!(e, Error::Io(_)), "{e}");
        assert!(started.elapsed() < Duration::from_secs(1), "it must not run the schedule");
        assert!(shared.path.snapshot().first_tx_since_rx.is_none(), "nothing left the socket");
        assert!(!lock(&shared.ike).has_pending_request(), "the request slot is free again");
        assert!(!lock(&shared.ike).next_msgid_is_abandoned(), "an id the gateway never saw is not abandoned");
        shared.stack.stop();
    }

    /// Regression (round-4 finding): the other way a request can fail to reach the wire.
    /// `ike_request_locked` used to raise its "sent" flag BEFORE offering the datagram to
    /// the socket, so a single-datagram request whose only `send_ike` returned an error
    /// — the EHOSTUNREACH/EPERM of the first datagram out of a brand-new interface,
    /// which is exactly the handover this feature exists for — marked its id abandoned
    /// although nothing had left the host. `send_raw` swallows WouldBlock/TimedOut as
    /// `Ok`, so an `Err` there proves the datagram did not go out.
    ///
    /// The cost was the next announce paying a spend-DPD it did not need.
    #[test]
    fn a_request_whose_only_send_failed_does_not_poison_the_next_message_id() {
        // Aimed at the v4 broadcast address: `send_to` fails immediately with EACCES on a
        // socket that never asked for SO_BROADCAST. No datagram leaves the host.
        let shared = test_shared_remote(Ipv4Addr::BROADCAST, 500);
        lock(&shared.ike).force_established_for_tests();
        let started = Instant::now();
        let e = do_dpd(&shared, &shared.cfg.ike.retransmit).unwrap_err();
        assert!(matches!(e, Error::Io(_)), "{e}");
        assert!(started.elapsed() < Duration::from_secs(1), "a refused send must not run the schedule");
        assert!(shared.path.snapshot().first_tx_since_rx.is_none(), "the path monitor agrees nothing went out");
        assert!(!lock(&shared.ike).has_pending_request(), "the request slot is free again");
        assert!(
            !lock(&shared.ike).next_msgid_is_abandoned(),
            "a datagram the socket refused cannot have been cached by the gateway"
        );
        // So the next announce goes straight to the address update, with no spend-DPD.
        assert!(lock(&shared.ike).build_address_update(shared.transport.local_addr(), shared.transport.remote_addr()).is_ok());
        shared.stack.stop();
    }

    /// Regression (round-3 finding): an announce must never go out on a message id that
    /// was abandoned earlier. RFC 7296 §2.1 lets the gateway replay its CACHED response
    /// for such an id, and if the request cached under it was itself an
    /// UPDATE_SA_ADDRESSES that replay carries the very NAT-D pair a genuine answer does
    /// — so it cannot be told apart, and we would commit a move the gateway never made.
    /// The id is spent on a plain DPD first (a replay there is harmless), and only then
    /// is the SA moved.
    ///
    /// The discriminator is the datagram itself: an empty INFORMATIONAL is materially
    /// shorter than `N(UPDATE_SA_ADDRESSES) + NAT_DETECTION_SOURCE_IP + _DESTINATION_IP`.
    #[test]
    fn an_announce_spends_an_abandoned_message_id_on_a_dpd_first() {
        let update = announce_datagrams(false, Duration::from_millis(400));
        let spend = announce_datagrams(true, Duration::from_millis(400));
        assert!(
            spend[0].len() < update[0].len(),
            "on an abandoned id the first datagram must be the empty DPD ({} bytes), not the \
             address update ({} bytes)",
            spend[0].len(),
            update[0].len()
        );
    }

    /// Every datagram an `announce` against a silent loopback peer puts on the wire,
    /// with the message id optionally poisoned first.
    fn announce_datagrams(abandon: bool, grace: Duration) -> Vec<Vec<u8>> {
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let shared = test_shared_to(peer.local_addr().unwrap().port());
        {
            let mut ike = lock(&shared.ike);
            ike.force_established_for_tests();
            ike.force_mobike_peer_for_tests();
            if abandon {
                let _ = ike.build_dpd().unwrap();
                ike.abort_request();
                assert!(ike.next_msgid_is_abandoned());
            }
        }
        let announcing = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                // Nothing ever answers, so the announce gives up at the grace deadline.
                let _ = announce(&shared, Some(Instant::now() + grace));
            })
        };
        // Let the announce run to its deadline, then drain: a handful of small datagrams
        // sits in the kernel receive buffer, and reading them afterwards keeps the
        // helper free of timing assumptions about when each one goes out.
        announcing.join().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok(n) = peer.recv(&mut buf) {
            seen.push(buf[..n].to_vec());
        }
        shared.stack.stop();
        assert!(!seen.is_empty(), "the tunnel sent something");
        seen
    }

    /// Regression (round-4 finding): the spend-DPD must not be able to own the whole
    /// grace period.
    ///
    /// A silent gateway is the DOMINANT announce failure (a new AP whose uplink is not
    /// usable yet), and it is precisely the case in which the spend cannot be answered.
    /// Driving it with the full retransmit schedule and propagating its failure meant
    /// the only thing the tunnel transmitted during an outage was empty INFORMATIONALs
    /// — which RFC 4555 §3.8 does not let the responder move the child SAs from — until
    /// `NO_ROUTE_GRACE` killed the tunnel: the `UPDATE_SA_ADDRESSES` was never sent, not
    /// once, no matter how many times the path monitor retried inside the grace.
    ///
    /// The spend is bounded by `SPEND_MSGID_ATTEMPTS` now and never aborts the announce.
    #[test]
    fn a_silent_gateway_still_sees_the_address_update_after_an_unspendable_message_id() {
        // The length of a real address update, from an announce on a clean id.
        let update_len = announce_datagrams(false, Duration::from_millis(400))[0].len();
        // Long enough for the bounded spend (2 attempts ≈ 1.5 s) plus the first update.
        let seen = announce_datagrams(true, Duration::from_millis(2_000));
        assert!(seen[0].len() < update_len, "the spend-DPD still goes first");
        let updates = seen.iter().filter(|d| d.len() == update_len).count();
        assert!(
            updates >= 1,
            "an unanswered spend must not swallow the address update; datagram sizes: {:?} \
             (an update is {update_len} bytes)",
            seen.iter().map(|d| d.len()).collect::<Vec<_>>()
        );
    }

    /// Regression (round-5 findings 3/4): an escalation rekey the path monitor aborted
    /// never reached the gateway, so it must not spend one of this move's attempts.
    ///
    /// `rekey_child`'s abort predicate fires at the top of attempt 0 while the path is
    /// suspended, so the request returns in microseconds with a path-kind `Io` and
    /// nothing on the wire. Charging that used to cost an attempt per path tick, so two
    /// ticks (~4 s) tore the tunnel down inside a `NO_ROUTE_GRACE` window that had 25 s
    /// left — blaming the child SA for a CREATE_CHILD_SA that was never sent.
    #[test]
    fn an_escalation_rekey_that_never_reached_the_gateway_does_not_spend_an_attempt() {
        let shared = test_shared();
        lock(&shared.ike).force_established_for_tests();
        // The path monitor is repairing the path, so `rekey_child`'s abort predicate —
        // the same one `do_dpd` uses — fires at the top of attempt 0.
        shared.path.set_suspended(true);
        let started = Instant::now();
        let e = ike_request_locked(&shared, "CREATE_CHILD_SA (rekey child)", &shared.cfg.ike.retransmit, Some(&|| {
            closing_abort(&shared).or_else(|| path_abort(&shared))
        }), |ike| ike.build_dpd())
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1), "the abort fires before the first send");
        assert!(shared.path.snapshot().first_tx_since_rx.is_none(), "nothing left the socket");
        assert!(is_path_failure(&e), "{e}");
        assert!(!rekey_failure_is_fatal(&e, true), "an aborted rekey is never fatal");
        assert_eq!(escalation_outcome(Some(&e), false, true), EscalationOutcome::Abandoned);
        shared.stack.stop();

        // The path-kind `Io` the abort predicate itself produces classifies the same way,
        // as does a crossing teardown.
        let io = Error::Io(std::io::Error::new(std::io::ErrorKind::NetworkDown, "x"));
        assert!(is_path_failure(&io));
        assert_eq!(escalation_outcome(Some(&io), false, true), EscalationOutcome::Abandoned);
        assert_eq!(escalation_outcome(Some(&Error::Closed("closing".into())), false, false), EscalationOutcome::Abandoned);
    }

    /// The rest of the escalation's outcome table (DESIGN §17.3/§17.4).
    #[test]
    fn the_escalation_classifies_every_rekey_outcome() {
        // A completed exchange is reported back, not treated as a repair.
        assert_eq!(escalation_outcome(None, true, false), EscalationOutcome::Done);
        // The gateway was reached and refused: one attempt is spent.
        let notify = Error::Protocol("N(TEMPORARY_FAILURE)".into());
        assert_eq!(escalation_outcome(Some(&notify), false, false), EscalationOutcome::Failed);
        // Retransmissions exhausted on a settled path: the gateway is gone.
        let timeout = Error::Timeout("CREATE_CHILD_SA (rekey child)");
        assert_eq!(escalation_outcome(Some(&timeout), false, false), EscalationOutcome::Fatal);
        // ... but not while the path is being repaired: those retransmissions left an
        // address the gateway has never been told about, so their silence says nothing.
        assert_eq!(escalation_outcome(Some(&timeout), false, true), EscalationOutcome::Abandoned);
        // The migration happened and only the DELETE of the old child SA failed: the
        // gateway completed the repair, so it must not be reported as a failure.
        assert_eq!(escalation_outcome(Some(&notify), true, false), EscalationOutcome::Done);
        assert_eq!(escalation_outcome(Some(&timeout), true, true), EscalationOutcome::Done);
    }

    /// Regression (round-5 finding 2): a rekey the gateway COMPLETED is not proof that
    /// ESP came back — the peer this escalation exists for answers on the IKE SA, which
    /// did move. Reporting completion re-arms the stall check against a fresh window
    /// instead of disarming it for the rest of the move.
    #[test]
    fn a_completed_esp_rekey_is_reported_back_and_re_arms_the_escalation() {
        let shared = test_shared();
        shared.path.request_esp_rekey();
        assert!(shared.path.take_esp_rekey_request());
        assert!(!shared.path.take_esp_rekey_done(), "nothing to report yet");
        shared.path.note_esp_rekey_done();
        assert!(!shared.path.take_esp_rekey_request(), "a completion report is not a new request");
        assert!(!shared.path.take_esp_rekey_failure(), "and it is not a failure report");
        assert!(shared.path.take_esp_rekey_done(), "the path thread picks it up");
        assert!(!shared.path.take_esp_rekey_done(), "and only once");
        shared.stack.stop();

        // The path thread's side: clearing `rekeyed` re-arms the check, and restarting
        // `moved_at` at the completion instant gives the repair a full silence window
        // before it is judged — evidence from BEFORE the rekey no longer counts.
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let repaired_at = t0 + Duration::from_secs(25);
        let esp_tx = Some(t0 + Duration::from_secs(1));
        let now = repaired_at + Duration::from_secs(1);
        assert!(
            !esp_migration_stalled(false, false, Some(repaired_at), esp_tx, None, now, silence),
            "the pre-rekey transmission is not evidence against the repair"
        );
        // ... and if ESP is still one-way a silence window later, the escalation fires
        // again, which is what eventually reaches mark_dead.
        let tx_after = Some(repaired_at + Duration::from_secs(1));
        let later = repaired_at + Duration::from_secs(1) + silence;
        assert!(esp_migration_stalled(false, false, Some(repaired_at), tx_after, None, later, silence));
    }

    /// The non-MOBIKE escalation is decided by the path thread but executed by the timer
    /// thread: the path thread is the only one that enforces `NO_ROUTE_GRACE`, and
    /// `rekey_child` blocks for up to two retransmit schedules. The request is a
    /// one-shot flag.
    #[test]
    fn the_esp_rekey_request_is_handed_to_the_timer_thread_once() {
        let shared = test_shared();
        assert!(!shared.path.take_esp_rekey_request());
        shared.path.request_esp_rekey();
        shared.path.request_esp_rekey();
        assert!(shared.path.take_esp_rekey_request(), "the timer thread picks it up");
        assert!(!shared.path.take_esp_rekey_request(), "and only once");
        shared.stack.stop();
    }

    /// Regression (round-4 finding): the escalation must be driven by the OUTCOME of the
    /// rekey, not by the fact that one was requested.
    ///
    /// `rekey_failure_is_fatal` is only "a timeout on a path that is not being repaired",
    /// so the gateway's normal `N(TEMPORARY_FAILURE)` while it rekeys on its own (RFC 7296
    /// §2.25) lands in the non-fatal arm. That used to be a bare `warn!`, and because the
    /// path thread had already set `rekeyed_after_move` when it made the REQUEST,
    /// `esp_migration_stalled` stayed disarmed for the rest of the tunnel's life — leaving
    /// a child SA pinned to the pre-move encapsulation port that no liveness check can
    /// see (the IKE SA did move, so it answers every probe).
    #[test]
    fn a_failed_esp_rekey_is_reported_back_and_re_arms_the_escalation() {
        let shared = test_shared();
        // The timer thread's side: a non-fatal failure is reported, not swallowed.
        shared.path.request_esp_rekey();
        assert!(shared.path.take_esp_rekey_request());
        assert!(!shared.path.take_esp_rekey_failure(), "nothing to report yet");
        shared.path.note_esp_rekey_failed();
        assert!(!shared.path.take_esp_rekey_request(), "a failure report is not a new request");
        assert!(shared.path.take_esp_rekey_failure(), "the path thread picks it up");
        assert!(!shared.path.take_esp_rekey_failure(), "and only once");
        shared.stack.stop();

        // The path thread's side: clearing `rekeyed` re-arms the check for the SAME move,
        // and it is still armed — the evidence of the stall has not gone anywhere.
        let t0 = Instant::now();
        let silence = Duration::from_secs(20);
        let now = t0 + Duration::from_secs(25);
        let esp_tx = Some(t0 + Duration::from_secs(1));
        let stalled = |rekeyed| esp_migration_stalled(false, rekeyed, Some(t0), esp_tx, Some(t0), now, silence);
        assert!(stalled(false), "armed while no rekey is in flight");
        assert!(!stalled(true), "disarmed while one is");
        assert!(stalled(false), "and re-armed once the failure comes back");
    }

    /// A persistent probe failure (EMFILE, a sandbox denying the throwaway socket) never
    /// impairs the tunnel by design, so the path loop keeps running — and its warning
    /// must be rate-limited like the ESP sink's, not logged once per probe interval for
    /// the life of the registration.
    #[test]
    fn the_route_probe_failure_warning_is_rate_limited() {
        let shared = test_shared();
        let now = Instant::now();
        assert!(shared.path.should_log_probe_error(now));
        assert!(!shared.path.should_log_probe_error(now + PROBE_ERROR_LOG_INTERVAL / 2));
        assert!(!shared.path.should_log_probe_error(now + PROBE_ERROR_LOG_INTERVAL - Duration::from_millis(1)));
        assert!(shared.path.should_log_probe_error(now + PROBE_ERROR_LOG_INTERVAL));
        // Far longer than the ESP sink's spacing: a probe runs every PATH_PROBE_INTERVAL
        // for the whole life of the tunnel, an ESP send only while there is traffic.
        assert!(PROBE_ERROR_LOG_INTERVAL > ESP_SEND_ERROR_LOG_INTERVAL);
        shared.stack.stop();
    }

    #[test]
    fn path_state_tracks_traffic_and_send_failures() {
        let shared = test_shared();
        let path_error = || Error::Io(std::io::Error::new(std::io::ErrorKind::NetworkDown, "x"));
        assert!(shared.path.snapshot().first_tx_since_rx.is_none());
        shared.path.note_data_tx();
        let s = shared.path.snapshot();
        assert!(s.first_tx_since_rx.is_some() && s.sends_failing_since.is_none());
        assert!(s.last_esp_tx.is_none(), "an IKE request is not ESP traffic");
        shared.path.note_send_error(&path_error());
        let first_failure = shared.path.snapshot().sends_failing_since.expect("failure clock started");
        shared.path.note_send_error(&path_error());
        assert_eq!(shared.path.snapshot().sends_failing_since, Some(first_failure), "the clock is not restarted");
        shared.path.note_send_ok();
        assert!(shared.path.snapshot().sends_failing_since.is_none(), "a successful send clears it");

        // An unrelated send failure (ENOBUFS, a short write) must NOT start the clock:
        // the wedge rule would otherwise rebind and re-announce an idle, healthy tunnel
        // 30 s later.
        shared.path.note_send_error(&Error::Io(std::io::Error::other("ENOBUFS")));
        shared.path.note_send_error(&Error::Timeout("x"));
        assert!(shared.path.snapshot().sends_failing_since.is_none(), "only a path error wedges the socket");

        // A keepalive reports on the socket without claiming the tunnel carried traffic.
        let before = shared.path.snapshot();
        shared.path.note_send_error(&path_error());
        assert!(shared.path.snapshot().sends_failing_since.is_some(), "a failed keepalive starts the clock");
        // ... and the next keepalive the OS accepts clears it again, on its own.
        shared.path.note_send_ok();
        let after = shared.path.snapshot();
        assert_eq!(after.first_tx_since_rx, before.first_tx_since_rx, "a keepalive is not traffic");
        assert!(after.sends_failing_since.is_none());

        // An inbound datagram restarts the one-way window at the next transmission.
        shared.path.note_rx_data();
        assert!(shared.path.snapshot().first_tx_since_rx.is_none());
        shared.path.note_data_tx();
        assert!(shared.path.snapshot().first_tx_since_rx.is_some());

        // The ESP-only clocks (DESIGN §17.3) move for ESP and for nothing else.
        let before = shared.path.snapshot();
        shared.path.note_rx_data();
        assert_eq!(shared.path.snapshot().last_esp_rx, before.last_esp_rx, "inbound IKE is not ESP");
        assert!(shared.path.snapshot().last_rx_data > before.last_rx_data);
        shared.path.note_esp_tx();
        shared.path.note_rx_esp();
        let s = shared.path.snapshot();
        assert!(s.last_esp_tx.is_some() && s.last_esp_rx.is_some());

        // Only a path-kind error asks for a probe.
        lock(&shared.path.inner).requested = false;
        shared.path.note_path_error(&Error::Timeout("x"));
        assert!(!lock(&shared.path.inner).requested);
        shared.path.note_path_error(&Error::Io(std::io::Error::new(std::io::ErrorKind::NetworkDown, "x")));
        assert!(lock(&shared.path.inner).requested);

        // The ESP error log is rate limited.
        let now = Instant::now();
        assert!(shared.path.should_log_esp_error(now));
        assert!(!shared.path.should_log_esp_error(now + ESP_SEND_ERROR_LOG_INTERVAL / 2));
        assert!(shared.path.should_log_esp_error(now + ESP_SEND_ERROR_LOG_INTERVAL));
    }

}
