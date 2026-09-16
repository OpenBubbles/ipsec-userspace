//! UDP transport for IKEv2 + UDP-encapsulated ESP (RFC 3948), DESIGN.md §7.
//!
//! One `UdpSocket` lives for the whole tunnel: IKE and ESP are multiplexed on it.
//! The destination port starts at 500 (no marker); [`IkeTransport::switch_to_natt`]
//! moves it to 4500 and turns on the 4-byte zero non-ESP marker for IKE datagrams.
//!
//! Inbound classification while on 4500 (RFC 3948 §2.2 / §4, AOSP
//! `IkeUdpEncapPortPacketHandler`):
//! - first four bytes zero → IKE (marker stripped)
//! - length 1 and byte `0xFF` → NAT-T keepalive
//! - anything else → ESP (first four bytes are the SPI, never zero)
//!
//! While still on port 500 every datagram is IKE and there is no marker in either direction.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use log::{debug, info, trace, warn};

use crate::config::RetransmitConfig;
use crate::ike::constants::*;
use crate::ike::header::IkeHeader;
use crate::{Error, Result};

/// Largest datagram we are prepared to receive (IKE messages are far smaller,
/// ESP packets are bounded by the path MTU).
const RECV_BUF_LEN: usize = 65_536;

/// Byte offset of the SKF Fragment Number field inside a datagram whose only
/// top-level payload is SKF: 28 (IKE header) + 4 (generic payload header).
const SKF_FRAG_NUM_OFFSET: usize = IKE_HEADER_LEN + 4;
/// Byte offset of the SKF Total Fragments field.
const SKF_FRAG_TOTAL_OFFSET: usize = SKF_FRAG_NUM_OFFSET + 2;
/// Minimum datagram length that can carry the SKF fragment header.
const SKF_MIN_LEN: usize = SKF_FRAG_TOTAL_OFFSET + 2;

/// Longest a single `recv_from` may block before [`IkeTransport::recv`] re-reads the
/// current socket. A [`IkeTransport::rebind`] swaps the socket under a blocked receive;
/// slicing the wait bounds how long the rx thread keeps listening on the old one.
const RECV_SLICE: Duration = Duration::from_millis(200);

/// Longest a single outer send may block before it is abandoned and the datagram counted
/// as lost.
///
/// 250 ms, well inside the 500 ms first retransmit interval. A UDP `send_to` only blocks
/// when the socket buffer is full or, in this crate's usual environment, when a host
/// firewall holds the flow pending a verdict — and the ESP TX sink runs that send
/// SYNCHRONOUSLY under the inner stack's `state` mutex, which everything else on the
/// stack (including the thread that delivers IKE responses) needs, so the timeout is the
/// ceiling on how long one held datagram can stall the tunnel (DESIGN §17.6).
pub const OUTER_SEND_TIMEOUT: Duration = Duration::from_millis(250);

/// Minimum spacing between "datagram from an unexpected peer" warnings. A gateway that
/// moves (or any host that can guess our ephemeral port) must not be able to turn the
/// receive loop into a log flood; the datagrams are counted either way.
const STRAY_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// A datagram received from the gateway, classified per RFC 3948.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// An IKE message (non-ESP marker already stripped when on 4500).
    Ike(Vec<u8>),
    /// A UDP-encapsulated ESP packet (raw, starting at the SPI).
    Esp(Vec<u8>),
    /// A one-byte `0xFF` NAT-T keepalive.
    Keepalive,
}

/// The socket and the address it is bound to, swapped as a unit by
/// [`IkeTransport::rebind`] so no operation can ever see one without the other.
struct Bound {
    socket: Arc<UdpSocket>,
    /// Real egress address (never 0.0.0.0 / ::) and the bound ephemeral port.
    local: SocketAddr,
}

/// The UDP socket shared by IKE and ESP for the life of the tunnel.
///
/// The socket is behind an `RwLock` because the path monitor (DESIGN §17) replaces it
/// when the host's egress address changes, while the rx thread, the keepalive thread,
/// the ESP TX sink and any outstanding IKE request keep using "the current socket".
/// Every operation clones the `Arc` out of the lock and releases the guard before the
/// syscall, so a lock is never held across a blocking send or receive.
pub struct IkeTransport {
    bound: RwLock<Bound>,
    remote_ip: IpAddr,
    remote_port: u16,
    /// `true` after `switch_to_natt`: prepend/strip the non-ESP marker, allow ESP.
    use_marker: bool,
    /// Datagrams dropped because they came from something other than the gateway.
    stray_sources: AtomicU64,
    last_stray_log: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for IkeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IkeTransport")
            .field("local", &self.local_addr())
            .field("remote", &self.remote_addr())
            .field("use_marker", &self.use_marker)
            .finish()
    }
}

impl IkeTransport {
    /// Bind an ephemeral UDP port on `local` (or on the discovered egress address for
    /// `remote` when `local` is `None`/unspecified) and aim at `remote:ike_port`.
    pub fn bind(local: Option<IpAddr>, remote: IpAddr, ike_port: u16) -> Result<Self> {
        let local_ip = match local {
            Some(ip) if !ip.is_unspecified() => ip,
            _ => discover_egress(remote, ike_port)?,
        };
        if local_ip.is_ipv4() != remote.is_ipv4() {
            return Err(Error::Config(format!(
                "local address {} and gateway {} are of different IP families",
                local_ip, remote
            )));
        }
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
        // Bound every send: a paused/held flow must surface as an error, not block forever.
        socket.set_write_timeout(Some(OUTER_SEND_TIMEOUT))?;
        let bound = socket.local_addr()?;
        // If the kernel still reports an unspecified address (shouldn't happen once we
        // bound to a concrete IP) substitute the discovered egress so callers never see 0.0.0.0.
        let local = if bound.ip().is_unspecified() {
            SocketAddr::new(local_ip, bound.port())
        } else {
            bound
        };
        debug!("ike transport bound {} -> {}:{}", local, remote, ike_port);
        Ok(IkeTransport {
            bound: RwLock::new(Bound { socket: Arc::new(socket), local }),
            remote_ip: remote,
            remote_port: ike_port,
            use_marker: false,
            stray_sources: AtomicU64::new(0),
            last_stray_log: Mutex::new(None),
        })
    }

    /// The socket to use right now and the address it is bound to. The guard is dropped
    /// before returning: callers hold only an `Arc`, so a concurrent `rebind` can swap
    /// the socket while an in-flight syscall keeps the old one alive.
    fn current(&self) -> (Arc<UdpSocket>, SocketAddr) {
        let b = self.bound.read().unwrap_or_else(|e| e.into_inner());
        (Arc::clone(&b.socket), b.local)
    }

    /// Real egress `addr:port` of the socket (never an unspecified address). This moves
    /// when the path monitor rebinds; [`crate::EpdgTunnel::local_addr`] exposes it.
    pub fn local_addr(&self) -> SocketAddr {
        self.current().1
    }

    /// The address the OS would use to reach the gateway right now: a bind + connect
    /// route probe on a throwaway socket, no packets sent. The path monitor's authority
    /// for "did our egress address change / is there a route at all" (DESIGN §17); a
    /// failure whose [`is_path_error`] holds means "no route", anything else means the
    /// probe itself could not run and says nothing about the path.
    pub fn probe_egress(&self) -> Result<IpAddr> {
        discover_egress(self.remote_ip, self.remote_port)
    }

    /// Bind a fresh ephemeral port on `local_ip` and make it the transport's socket.
    ///
    /// The destination, the non-ESP marker and every SA (IKE and ESP SPIs, keys, replay
    /// state) are untouched: only our side of the 5-tuple moves, which is exactly what
    /// MOBIKE `UPDATE_SA_ADDRESSES` (RFC 4555 §3.5) / the RFC 7296 §2.23 dynamic address
    /// update announce afterwards. On any error nothing is swapped and the old socket
    /// stays in use.
    ///
    /// Returns the new local address and the replaced socket; the caller keeps that `Arc`
    /// alive across the announce that follows, so the kernel cannot hand the old ephemeral
    /// port to another socket in this process while the gateway's NAT binding may still
    /// point at it. (The old socket is not read from; see DESIGN §17.8.)
    pub fn rebind(&self, local_ip: IpAddr) -> Result<(SocketAddr, Arc<UdpSocket>)> {
        // Defensive: an explicit `gateway.local_addr` of the wrong family would otherwise
        // produce a socket that can never reach the gateway. Losing the last route of the
        // gateway's family is reported as "no route" instead and ends in the grace period.
        if local_ip.is_ipv4() != self.remote_ip.is_ipv4() {
            return Err(Error::Config(format!(
                "cannot rebind to {} for gateway {}: different IP families",
                local_ip, self.remote_ip
            )));
        }
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
        socket.set_write_timeout(Some(OUTER_SEND_TIMEOUT))?;
        let bound = socket.local_addr()?;
        let local = if bound.ip().is_unspecified() { SocketAddr::new(local_ip, bound.port()) } else { bound };
        let (old_socket, old_local) = {
            let mut b = self.bound.write().unwrap_or_else(|e| e.into_inner());
            let old = std::mem::replace(&mut *b, Bound { socket: Arc::new(socket), local });
            (old.socket, old.local)
        };
        info!("ike transport rebound {} -> {} (dst {})", old_local, local, self.remote_addr());
        Ok((local, old_socket))
    }

    /// Datagrams dropped because their source was not the gateway (counted, not fatal:
    /// anything that can reach our port could otherwise tear the tunnel down).
    pub fn stray_sources(&self) -> u64 {
        self.stray_sources.load(Ordering::Relaxed)
    }

    /// Current destination: `gateway:500` before NAT-T, `gateway:4500` after.
    pub fn remote_addr(&self) -> SocketAddr {
        SocketAddr::new(self.remote_ip, self.remote_port)
    }

    /// Move the destination to the NAT-T port and enable the non-ESP marker on IKE.
    pub fn switch_to_natt(&mut self, natt_port: u16) {
        debug!("ike transport: switching to NAT-T port {} (non-ESP marker on)", natt_port);
        self.remote_port = natt_port;
        self.use_marker = true;
    }

    pub fn using_natt(&self) -> bool {
        self.use_marker
    }

    /// Send one IKE datagram, prepending the 4-byte non-ESP marker when on NAT-T.
    pub fn send_ike(&self, datagram: &[u8]) -> Result<()> {
        let dst = self.remote_addr();
        trace!("ike tx {} bytes -> {}: {}", datagram.len(), dst, hex::encode(datagram));
        if self.use_marker {
            let mut out = Vec::with_capacity(NON_ESP_MARKER.len() + datagram.len());
            out.extend_from_slice(&NON_ESP_MARKER);
            out.extend_from_slice(datagram);
            self.send_raw(&out, dst)
        } else {
            self.send_raw(datagram, dst)
        }
    }

    /// Send a raw UDP-encapsulated ESP packet (starts at the SPI). Requires NAT-T.
    pub fn send_esp(&self, esp: &[u8]) -> Result<()> {
        if !self.use_marker {
            return Err(Error::Protocol("send_esp before NAT-T port switch".into()));
        }
        if esp.len() >= NON_ESP_MARKER.len() && esp[..NON_ESP_MARKER.len()] == NON_ESP_MARKER {
            return Err(Error::Protocol("ESP packet with SPI 0 would be read as an IKE marker".into()));
        }
        let dst = self.remote_addr();
        trace!("esp tx {} bytes -> {}", esp.len(), dst);
        self.send_raw(esp, dst)
    }

    /// Send the one-byte `0xFF` NAT-T keepalive. Requires NAT-T.
    pub fn send_keepalive(&self) -> Result<()> {
        if !self.use_marker {
            return Err(Error::Protocol("send_keepalive before NAT-T port switch".into()));
        }
        let dst = self.remote_addr();
        trace!("natt keepalive -> {}", dst);
        self.send_raw(&NATT_KEEPALIVE, dst)
    }

    fn send_raw(&self, bytes: &[u8], dst: SocketAddr) -> Result<()> {
        let (socket, _) = self.current();
        let n = match socket.send_to(bytes, dst) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                // A send that is held/blocked (e.g. a host firewall pausing the flow pending a
                // verdict) must never stall the state machine: count the datagram as lost and let
                // the retransmission schedule cover it.
                warn!("UDP send to {} did not complete ({}); treating datagram as lost", dst, e);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        if n != bytes.len() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short UDP send: {} of {} bytes", n, bytes.len()),
            )));
        }
        Ok(())
    }

    /// Wait up to `timeout` for a datagram from the gateway and classify it.
    /// `Ok(None)` on timeout. Datagrams from any other source address are counted
    /// and dropped without consuming the whole timeout.
    ///
    /// The wait is sliced (`RECV_SLICE`) and the socket is re-read on every slice, so a
    /// [`IkeTransport::rebind`] performed while this call is blocked starts delivering
    /// from the new socket within one slice instead of at the caller's own deadline.
    pub fn recv(&self, timeout: Duration) -> Result<Option<Incoming>> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; RECV_BUF_LEN];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let (socket, _) = self.current();
            // set_read_timeout(Some(0)) would mean "block forever"; clamp to >= 1 ms.
            let slice = remaining.min(RECV_SLICE).max(Duration::from_millis(1));
            socket.set_read_timeout(Some(slice))?;
            let (n, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                // Slice expired: re-check the deadline and pick up a swapped socket.
                Err(e) if is_timeout(&e) => continue,
                Err(e) if is_transient(&e) => {
                    // ICMP-derived errors on an unconnected UDP socket (Windows, Linux with
                    // IP_RECVERR): the datagram is lost; the retransmit schedule covers it.
                    warn!("UDP receive error treated as a lost datagram: {e}");
                    continue;
                }
                Err(e) => return Err(Error::Io(e)),
            };
            let expected = self.remote_addr();
            if src != expected {
                let total = self.stray_sources.fetch_add(1, Ordering::Relaxed) + 1;
                let mut last = self.last_stray_log.lock().unwrap_or_else(|e| e.into_inner());
                if last.is_none_or(|t| t.elapsed() >= STRAY_LOG_INTERVAL) {
                    warn!(
                        "dropping {} byte datagram from unexpected peer {} (expected {}; {} so far)",
                        n, src, expected, total
                    );
                    *last = Some(Instant::now());
                }
                continue;
            }
            let data = &buf[..n];
            return Ok(Some(self.classify(data)));
        }
    }

    fn classify(&self, data: &[u8]) -> Incoming {
        if !self.use_marker {
            trace!("ike rx {} bytes (port {}): {}", data.len(), self.remote_port, hex::encode(data));
            return Incoming::Ike(data.to_vec());
        }
        if data.len() == NATT_KEEPALIVE.len() && data[0] == NATT_KEEPALIVE[0] {
            trace!("natt keepalive rx");
            return Incoming::Keepalive;
        }
        if data.len() >= NON_ESP_MARKER.len() && data[..NON_ESP_MARKER.len()] == NON_ESP_MARKER {
            let ike = &data[NON_ESP_MARKER.len()..];
            trace!("ike rx {} bytes (natt): {}", ike.len(), hex::encode(ike));
            return Incoming::Ike(ike.to_vec());
        }
        trace!("esp rx {} bytes", data.len());
        Incoming::Esp(data.to_vec())
    }

    /// Send a request (one datagram, or its SKF fragments) and collect the response
    /// datagrams for `message_id`.
    ///
    /// All datagrams are (re)sent together on every attempt, identical bytes each time,
    /// following `policy` (`initial_timeout_ms * backoff^n` after the n-th send,
    /// `max_attempts` sends total, then [`Error::Timeout`]).
    ///
    /// The response is recognised by `is_response && message_id == ours && spi_i == ours`
    /// (our SPI is taken from the first request datagram). An unfragmented response is
    /// returned as a single datagram; an SKF-fragmented one is collected until all
    /// `total` distinct fragment numbers arrived (returned in fragment order), each
    /// fragment being allowed the current retransmit timeout. Other IKE datagrams go to
    /// `on_other`, ESP packets to `on_esp`, keepalives are ignored.
    pub fn request(
        &self,
        datagrams: &[Vec<u8>],
        message_id: u32,
        policy: &RetransmitConfig,
        on_other: &mut dyn FnMut(Vec<u8>),
        on_esp: &mut dyn FnMut(Vec<u8>),
    ) -> Result<Vec<Vec<u8>>> {
        let first = datagrams
            .first()
            .ok_or_else(|| Error::Protocol("request() called with no datagrams".into()))?;
        let our_spi = IkeHeader::decode(first)
            .map_err(|e| Error::Protocol(format!("request datagram has no valid IKE header: {}", e)))?
            .spi_i;

        let attempts = policy.max_attempts.max(1);
        let mut frags = FragmentSet::default();

        for attempt in 0..attempts {
            for d in datagrams {
                self.send_ike(d)?;
            }
            let timeout = retransmit_timeout(policy, attempt);
            debug!(
                "ike request msgid={} sent ({} datagram(s), attempt {}/{}), waiting {:?}",
                message_id,
                datagrams.len(),
                attempt + 1,
                attempts,
                timeout
            );

            // Each received fragment re-arms the wait with the current timeout.
            let mut deadline = Instant::now() + timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let Some(incoming) = self.recv(remaining)? else { break };
                let data = match incoming {
                    Incoming::Keepalive => continue,
                    Incoming::Esp(p) => {
                        on_esp(p);
                        continue;
                    }
                    Incoming::Ike(d) => d,
                };
                let hdr = match IkeHeader::decode(&data) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("dropping undecodable IKE datagram ({} bytes): {}", data.len(), e);
                        continue;
                    }
                };
                if !(hdr.is_response() && hdr.message_id == message_id && hdr.spi_i == our_spi) {
                    debug!(
                        "ike rx not our response (resp={} msgid={} spi_i={:016x}); handing to on_other",
                        hdr.is_response(),
                        hdr.message_id,
                        hdr.spi_i
                    );
                    on_other(data);
                    continue;
                }

                if hdr.next_payload != PT_SKF {
                    if frags.total.is_some() {
                        // AOSP: a complete message received while reassembling is discarded.
                        warn!("dropping unfragmented response msgid={} while collecting SKF fragments", message_id);
                        continue;
                    }
                    debug!("ike response msgid={} received ({} bytes)", message_id, data.len());
                    return Ok(vec![data]);
                }

                match skf_numbers(&data) {
                    Ok((num, total)) => {
                        if frags.insert(num, total, data) {
                            deadline = Instant::now() + timeout;
                        }
                        if frags.is_complete() {
                            debug!("ike response msgid={} reassembled from {} fragments", message_id, frags.total.unwrap_or(0));
                            return Ok(frags.into_datagrams());
                        }
                    }
                    Err(e) => warn!("dropping malformed SKF fragment: {}", e),
                }
            }
            if attempt + 1 < attempts {
                debug!("ike request msgid={} timed out after {:?}; retransmitting", message_id, timeout);
            }
        }
        warn!("ike request msgid={} gave up after {} attempt(s)", message_id, attempts);
        Err(Error::Timeout("IKE response"))
    }
}

/// Timeout to wait after the `attempt`-th (0-based) send.
fn retransmit_timeout(policy: &RetransmitConfig, attempt: u32) -> Duration {
    let mult = if policy.backoff_multiplier.is_finite() && policy.backoff_multiplier > 0.0 {
        policy.backoff_multiplier
    } else {
        1.0
    };
    let ms = policy.initial_timeout_ms as f64 * mult.powi(attempt as i32);
    // Guard against absurd/overflowing values; never wait less than 1 ms.
    let ms = if ms.is_finite() { ms.clamp(1.0, u32::MAX as f64) } else { u32::MAX as f64 };
    Duration::from_millis(ms as u64)
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionAborted
    )
}

/// Does this error mean "the address or the route this socket depends on is gone"?
///
/// Used by the path monitor (DESIGN §17) to tell a broken local path (re-probe the
/// egress, rebind, announce) from an unrelated failure (leave the tunnel alone). The
/// `ErrorKind` variants are the portable answer; the errno fallback covers platforms
/// and libc paths where std still reports `Uncategorized`.
pub fn is_path_error(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(e.kind(), AddrNotAvailable | NetworkUnreachable | HostUnreachable | NetworkDown)
        || e.raw_os_error().is_some_and(path_errno)
}

/// EADDRNOTAVAIL(49) ENETDOWN(50) ENETUNREACH(51) EHOSTUNREACH(65)
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn path_errno(n: i32) -> bool {
    matches!(n, 49 | 50 | 51 | 65)
}

/// EADDRNOTAVAIL(99) ENETDOWN(100) ENETUNREACH(101) EHOSTUNREACH(113)
#[cfg(target_os = "linux")]
fn path_errno(n: i32) -> bool {
    matches!(n, 99 | 100 | 101 | 113)
}

/// Elsewhere the `ErrorKind` check above is the only classification.
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn path_errno(_n: i32) -> bool {
    false
}

/// Read (Fragment Number, Total Fragments) from an SKF datagram (RFC 7383 §2.5).
fn skf_numbers(data: &[u8]) -> Result<(u16, u16)> {
    if data.len() < SKF_MIN_LEN {
        return Err(Error::Decode(format!(
            "SKF datagram too short for fragment header: {} < {}",
            data.len(),
            SKF_MIN_LEN
        )));
    }
    let num = u16::from_be_bytes([data[SKF_FRAG_NUM_OFFSET], data[SKF_FRAG_NUM_OFFSET + 1]]);
    let total = u16::from_be_bytes([data[SKF_FRAG_TOTAL_OFFSET], data[SKF_FRAG_TOTAL_OFFSET + 1]]);
    if num == 0 || total == 0 || num > total {
        return Err(Error::Decode(format!("invalid SKF fragment numbers {}/{}", num, total)));
    }
    Ok((num, total))
}

/// Fragments collected for one response, keyed by fragment number.
#[derive(Default)]
struct FragmentSet {
    total: Option<u16>,
    frags: BTreeMap<u16, Vec<u8>>,
}

impl FragmentSet {
    /// Store a fragment following the AOSP rules: a larger `total` restarts collection,
    /// a smaller one is dropped, duplicates are ignored. Returns `true` if stored.
    fn insert(&mut self, num: u16, total: u16, data: Vec<u8>) -> bool {
        match self.total {
            Some(t) if total > t => {
                warn!("SKF total grew {} -> {}; restarting fragment collection", t, total);
                self.frags.clear();
                self.total = Some(total);
            }
            Some(t) if total < t => {
                warn!("SKF fragment {}/{} has smaller total than {}; dropped", num, total, t);
                return false;
            }
            Some(_) => {}
            None => self.total = Some(total),
        }
        if self.frags.contains_key(&num) {
            debug!("duplicate SKF fragment {}/{} ignored", num, total);
            return false;
        }
        debug!("SKF fragment {}/{} received ({} bytes)", num, total, data.len());
        self.frags.insert(num, data);
        true
    }

    fn is_complete(&self) -> bool {
        matches!(self.total, Some(t) if self.frags.len() == t as usize)
    }

    fn into_datagrams(self) -> Vec<Vec<u8>> {
        self.frags.into_values().collect()
    }
}

/// Find the address the OS would use to reach `remote:port` by connecting a
/// throwaway UDP socket (no packets are sent).
fn discover_egress(remote: IpAddr, port: u16) -> Result<IpAddr> {
    let any: IpAddr = if remote.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    let probe = UdpSocket::bind(SocketAddr::new(any, 0))?;
    // Re-wrapped so the message names the gateway (this is what a caller sees when
    // `EpdgTunnel::connect` runs with the interface down). `io::Error::new` keeps
    // `kind()`, which is what `is_path_error` looks at first, so the classification the
    // path monitor depends on is unaffected; only `raw_os_error()` is dropped, and that
    // is a fallback for platforms where std leaves the kind `Uncategorized`.
    probe
        .connect(SocketAddr::new(remote, port))
        .map_err(|e| Error::Io(io::Error::new(e.kind(), format!("no route to gateway {}:{}: {}", remote, port, e))))?;
    let ip = probe.local_addr()?.ip();
    if ip.is_unspecified() {
        return Err(Error::Config(format!("could not determine egress address for {}", remote)));
    }
    debug!("egress address for {} is {}", remote, ip);
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;

    const LOOP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const OUR_SPI: u64 = 0x1122334455667788;

    fn peer() -> UdpSocket {
        let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s
    }

    fn transport(peer: &UdpSocket) -> IkeTransport {
        IkeTransport::bind(Some(LOOP), LOOP, peer.local_addr().unwrap().port()).unwrap()
    }

    fn header(flags: u8, msg_id: u32, next: u8, spi_i: u64, len: usize) -> IkeHeader {
        IkeHeader {
            spi_i,
            spi_r: 0xaaaa,
            next_payload: next,
            version: IKE_VERSION,
            exchange_type: EXCH_IKE_AUTH,
            flags,
            message_id: msg_id,
            length: len as u32,
        }
    }

    fn request_dgram(msg_id: u32) -> Vec<u8> {
        let body = [0x41u8; 12];
        let mut v = Vec::new();
        header(FLAG_INITIATOR, msg_id, PT_SK, OUR_SPI, 28 + body.len()).encode(&mut v);
        v.extend_from_slice(&body);
        v
    }

    fn response_dgram(msg_id: u32, spi_i: u64, tag: u8) -> Vec<u8> {
        let body = [tag; 20];
        let mut v = Vec::new();
        header(FLAG_RESPONSE, msg_id, PT_SK, spi_i, 28 + body.len()).encode(&mut v);
        v.extend_from_slice(&body);
        v
    }

    fn skf_dgram(msg_id: u32, num: u16, total: u16, payload: &[u8]) -> Vec<u8> {
        let generic_len = 4 + 4 + payload.len();
        let mut v = Vec::new();
        header(FLAG_RESPONSE, msg_id, PT_SKF, OUR_SPI, 28 + generic_len).encode(&mut v);
        v.push(if num == 1 { PT_EAP } else { PT_NONE });
        v.push(0);
        v.extend_from_slice(&(generic_len as u16).to_be_bytes());
        v.extend_from_slice(&num.to_be_bytes());
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn peer_recv(peer: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0u8; 4096];
        let (n, src) = peer.recv_from(&mut buf).unwrap();
        buf.truncate(n);
        (buf, src)
    }

    fn fast_policy(attempts: u32) -> RetransmitConfig {
        RetransmitConfig { initial_timeout_ms: 60, backoff_multiplier: 2.0, max_attempts: attempts }
    }

    #[test]
    fn bind_reports_concrete_local_addr() {
        let p = peer();
        let t = transport(&p);
        assert_eq!(t.local_addr().ip(), LOOP);
        assert_ne!(t.local_addr().port(), 0);
        assert_eq!(t.remote_addr(), p.local_addr().unwrap());
        assert!(!t.using_natt());

        // egress discovery for loopback yields loopback
        let t2 = IkeTransport::bind(None, LOOP, p.local_addr().unwrap().port()).unwrap();
        assert_eq!(t2.local_addr().ip(), LOOP);
        let t3 = IkeTransport::bind(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), LOOP, 500).unwrap();
        assert_eq!(t3.local_addr().ip(), LOOP);
    }

    #[test]
    fn bind_rejects_mixed_families() {
        let r = IkeTransport::bind(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), LOOP, 500);
        assert!(matches!(r, Err(Error::Config(_))));
    }

    #[test]
    fn send_ike_marker_only_after_switch_to_natt() {
        let p = peer();
        let mut t = transport(&p);
        let msg = request_dgram(3);

        t.send_ike(&msg).unwrap();
        let (got, src) = peer_recv(&p);
        assert_eq!(got, msg);
        assert_eq!(src, t.local_addr());

        assert!(matches!(t.send_esp(&[1, 2, 3, 4, 5]), Err(Error::Protocol(_))));
        assert!(matches!(t.send_keepalive(), Err(Error::Protocol(_))));

        // rebind the peer as the "4500" endpoint
        let natt_peer = peer();
        t.switch_to_natt(natt_peer.local_addr().unwrap().port());
        assert!(t.using_natt());
        assert_eq!(t.remote_addr(), natt_peer.local_addr().unwrap());

        t.send_ike(&msg).unwrap();
        let (got, _) = peer_recv(&natt_peer);
        assert_eq!(&got[..4], &NON_ESP_MARKER);
        assert_eq!(&got[4..], &msg[..]);

        t.send_keepalive().unwrap();
        let (got, _) = peer_recv(&natt_peer);
        assert_eq!(got, NATT_KEEPALIVE.to_vec());

        let esp = [0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad];
        t.send_esp(&esp).unwrap();
        let (got, _) = peer_recv(&natt_peer);
        assert_eq!(got, esp.to_vec());

        // SPI 0 would be mistaken for the marker
        assert!(matches!(t.send_esp(&[0, 0, 0, 0, 1]), Err(Error::Protocol(_))));
    }

    #[test]
    fn recv_classifies_marker_keepalive_esp() {
        let p = peer();
        let mut t = transport(&p);
        let local = t.local_addr();
        let msg = request_dgram(1);

        // port 500: everything is IKE, no marker
        p.send_to(&msg, local).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Ike(msg.clone())));

        t.switch_to_natt(p.local_addr().unwrap().port());

        let mut marked = NON_ESP_MARKER.to_vec();
        marked.extend_from_slice(&msg);
        p.send_to(&marked, local).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Ike(msg.clone())));

        p.send_to(&NATT_KEEPALIVE, local).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Keepalive));

        let esp = vec![0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x07, 0xff];
        p.send_to(&esp, local).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Esp(esp)));

        // a lone non-0xFF byte is not a keepalive; with a non-zero prefix it's ESP-ish
        p.send_to(&[0x01], local).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Esp(vec![0x01])));

        // timeout -> None
        let start = Instant::now();
        assert_eq!(t.recv(Duration::from_millis(50)).unwrap(), None);
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn recv_drops_datagrams_from_other_peers() {
        let p = peer();
        let stranger = peer();
        let t = transport(&p);
        stranger.send_to(&request_dgram(9), t.local_addr()).unwrap();
        let start = Instant::now();
        assert_eq!(t.recv(Duration::from_millis(100)).unwrap(), None);
        assert!(start.elapsed() >= Duration::from_millis(80));

        // and the real peer still gets through afterwards
        stranger.send_to(&request_dgram(9), t.local_addr()).unwrap();
        p.send_to(&request_dgram(2), t.local_addr()).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Ike(request_dgram(2))));
    }

    #[test]
    fn request_returns_matching_response_and_ignores_unrelated() {
        let p = peer();
        let t = transport(&p);
        let req = request_dgram(4);

        let expected_req = req.clone();
        let peer_thread = thread::spawn(move || {
            let (got, src) = peer_recv(&p);
            assert_eq!(got, expected_req);
            // unrelated message id (response), a peer-initiated request, wrong SPI, then the real one
            p.send_to(&response_dgram(7, OUR_SPI, 0x77), src).unwrap();
            let mut peer_req = Vec::new();
            header(0, 0, PT_SK, OUR_SPI, 28).encode(&mut peer_req);
            p.send_to(&peer_req, src).unwrap();
            p.send_to(&response_dgram(4, 0x9999, 0x99), src).unwrap();
            p.send_to(&response_dgram(4, OUR_SPI, 0x44), src).unwrap();
            p
        });

        let mut others = Vec::new();
        let mut esps = Vec::new();
        let resp = t
            .request(&[req], 4, &fast_policy(3), &mut |d| others.push(d), &mut |e| esps.push(e))
            .unwrap();
        assert_eq!(resp, vec![response_dgram(4, OUR_SPI, 0x44)]);
        assert_eq!(others.len(), 3);
        assert_eq!(others[0], response_dgram(7, OUR_SPI, 0x77));
        assert_eq!(others[2], response_dgram(4, 0x9999, 0x99));
        assert!(esps.is_empty());
        peer_thread.join().unwrap();
    }

    #[test]
    fn request_passes_esp_and_ignores_keepalive_on_natt() {
        let p = peer();
        let mut t = transport(&p);
        t.switch_to_natt(p.local_addr().unwrap().port());
        let req = request_dgram(5);

        let peer_thread = thread::spawn(move || {
            let (got, src) = peer_recv(&p);
            assert_eq!(&got[..4], &NON_ESP_MARKER);
            p.send_to(&NATT_KEEPALIVE, src).unwrap();
            p.send_to(&[0, 0, 0, 5, 0, 0, 0, 1, 0xab], src).unwrap();
            let mut marked = NON_ESP_MARKER.to_vec();
            marked.extend_from_slice(&response_dgram(5, OUR_SPI, 0x55));
            p.send_to(&marked, src).unwrap();
        });

        let mut others = Vec::new();
        let mut esps = Vec::new();
        let resp = t
            .request(&[req], 5, &fast_policy(3), &mut |d| others.push(d), &mut |e| esps.push(e))
            .unwrap();
        assert_eq!(resp, vec![response_dgram(5, OUR_SPI, 0x55)]);
        assert!(others.is_empty());
        assert_eq!(esps, vec![vec![0, 0, 0, 5, 0, 0, 0, 1, 0xab]]);
        peer_thread.join().unwrap();
    }

    #[test]
    fn request_retransmits_then_times_out() {
        let p = peer();
        let t = transport(&p);
        let req = request_dgram(6);
        let policy = fast_policy(3); // 60 + 120 + 240 ms

        let expected = req.clone();
        let counter = thread::spawn(move || {
            p.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            let deadline = Instant::now() + Duration::from_millis(1200);
            let mut count = 0;
            let mut buf = [0u8; 2048];
            while Instant::now() < deadline {
                if let Ok((n, _)) = p.recv_from(&mut buf) {
                    assert_eq!(&buf[..n], &expected[..]);
                    count += 1;
                }
            }
            count
        });

        let start = Instant::now();
        let r = t.request(&[req], 6, &policy, &mut |_| panic!("no other"), &mut |_| panic!("no esp"));
        let elapsed = start.elapsed();
        assert!(matches!(r, Err(Error::Timeout(_))), "got {:?}", r);
        assert!(elapsed >= Duration::from_millis(400), "elapsed {:?}", elapsed);
        assert_eq!(counter.join().unwrap(), 3);
    }

    #[test]
    fn request_resends_all_fragments_of_a_fragmented_request() {
        let p = peer();
        let t = transport(&p);
        let d1 = request_dgram(8);
        let mut d2 = request_dgram(8);
        d2.push(0xee);
        let policy = RetransmitConfig { initial_timeout_ms: 40, backoff_multiplier: 1.0, max_attempts: 2 };

        let counter = thread::spawn(move || {
            p.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            let deadline = Instant::now() + Duration::from_millis(600);
            let mut seen = Vec::new();
            let mut buf = [0u8; 2048];
            while Instant::now() < deadline {
                if let Ok((n, _)) = p.recv_from(&mut buf) {
                    seen.push(buf[..n].to_vec());
                }
            }
            seen
        });

        let r = t.request(&[d1.clone(), d2.clone()], 8, &policy, &mut |_| {}, &mut |_| {});
        assert!(matches!(r, Err(Error::Timeout(_))));
        assert_eq!(counter.join().unwrap(), vec![d1.clone(), d2.clone(), d1, d2]);
    }

    #[test]
    fn fragmented_response_is_collected() {
        let p = peer();
        let t = transport(&p);
        let req = request_dgram(2);
        let f1 = skf_dgram(2, 1, 2, &[0x11; 40]);
        let f2 = skf_dgram(2, 2, 2, &[0x22; 30]);

        let (f1c, f2c) = (f1.clone(), f2.clone());
        let peer_thread = thread::spawn(move || {
            let (_, src) = peer_recv(&p);
            // out of order, with a duplicate, and an unfragmented straggler that must be dropped
            p.send_to(&f2c, src).unwrap();
            p.send_to(&f2c, src).unwrap();
            p.send_to(&response_dgram(2, OUR_SPI, 0x00), src).unwrap();
            p.send_to(&f1c, src).unwrap();
        });

        let mut others = Vec::new();
        let resp = t
            .request(&[req], 2, &fast_policy(3), &mut |d| others.push(d), &mut |_| panic!("no esp"))
            .unwrap();
        assert_eq!(resp, vec![f1, f2]);
        assert!(others.is_empty());
        peer_thread.join().unwrap();
    }

    #[test]
    fn fragmented_response_survives_retransmit_and_larger_total_restart() {
        let p = peer();
        let t = transport(&p);
        let req = request_dgram(3);
        let policy = RetransmitConfig { initial_timeout_ms: 80, backoff_multiplier: 1.0, max_attempts: 4 };
        let a1 = skf_dgram(3, 1, 3, &[0xa1; 10]);
        let a2 = skf_dgram(3, 2, 3, &[0xa2; 10]);
        let a3 = skf_dgram(3, 3, 3, &[0xa3; 10]);

        let (b1, b2, b3) = (a1.clone(), a2.clone(), a3.clone());
        let peer_thread = thread::spawn(move || {
            let (_, src) = peer_recv(&p);
            // a bogus 2-fragment set first, then only fragment 1 of the real set;
            // the rest only after the client retransmits
            p.send_to(&skf_dgram(3, 1, 2, &[0xbb; 5]), src).unwrap();
            p.send_to(&b1, src).unwrap();
            // a fragment with a smaller total than the current set is dropped
            p.send_to(&skf_dgram(3, 2, 2, &[0xcc; 5]), src).unwrap();
            let _ = peer_recv(&p); // retransmitted request
            p.send_to(&b2, src).unwrap();
            p.send_to(&b3, src).unwrap();
        });

        let resp = t.request(&[req], 3, &policy, &mut |_| panic!("no other"), &mut |_| {}).unwrap();
        assert_eq!(resp, vec![a1, a2, a3]);
        peer_thread.join().unwrap();
    }

    #[test]
    fn request_rejects_empty_or_headerless_input() {
        let p = peer();
        let t = transport(&p);
        let r = t.request(&[], 1, &fast_policy(1), &mut |_| {}, &mut |_| {});
        assert!(matches!(r, Err(Error::Protocol(_))));
        let r = t.request(&[vec![1, 2, 3]], 1, &fast_policy(1), &mut |_| {}, &mut |_| {});
        assert!(matches!(r, Err(Error::Protocol(_))));
    }

    #[test]
    fn skf_numbers_parsing() {
        assert_eq!(skf_numbers(&skf_dgram(1, 2, 5, &[])).unwrap(), (2, 5));
        assert!(matches!(skf_numbers(&skf_dgram(1, 2, 5, &[])[..35]), Err(Error::Decode(_))));
        assert!(matches!(skf_numbers(&skf_dgram(1, 0, 5, &[])), Err(Error::Decode(_))));
        assert!(matches!(skf_numbers(&skf_dgram(1, 6, 5, &[])), Err(Error::Decode(_))));
        assert!(matches!(skf_numbers(&skf_dgram(1, 1, 0, &[])), Err(Error::Decode(_))));
    }

    /// Every outer socket — the original binding and every rebind — bounds its sends by
    /// [`OUTER_SEND_TIMEOUT`]. The ESP TX sink runs `send_raw` synchronously under the
    /// inner stack's `state` mutex, so this timeout is the ceiling on how long one
    /// datagram held by a host firewall can stall everything else on the stack
    /// (DESIGN §17.6).
    #[test]
    fn every_outer_socket_bounds_its_sends() {
        let p = peer();
        let t = transport(&p);
        let (sock, _) = t.current();
        assert_eq!(sock.write_timeout().unwrap(), Some(OUTER_SEND_TIMEOUT));
        let (_, _old) = t.rebind(LOOP).unwrap();
        let (sock, _) = t.current();
        assert_eq!(sock.write_timeout().unwrap(), Some(OUTER_SEND_TIMEOUT), "a rebind keeps the bound");
        // Well inside the first retransmit interval, so a held datagram is retransmitted
        // rather than sat on.
        assert!(OUTER_SEND_TIMEOUT < Duration::from_millis(crate::config::RetransmitConfig::default().initial_timeout_ms));
    }

    #[test]
    fn rebind_moves_the_source_port_and_keeps_the_destination() {
        let p = peer();
        let t = transport(&p);
        let before = t.local_addr();
        t.send_ike(&request_dgram(1)).unwrap();
        let (_, src) = peer_recv(&p);
        assert_eq!(src, before);

        // The old socket is held for the whole test so the kernel cannot recycle its
        // port into the new binding and make the inequality below flaky.
        let (new, _old) = t.rebind(LOOP).unwrap();
        assert_ne!(new.port(), before.port());
        assert_eq!(new.ip(), LOOP);
        assert_eq!(t.local_addr(), new);
        assert_eq!(t.remote_addr(), p.local_addr().unwrap(), "destination unchanged");

        // Sends leave the new port ...
        t.send_ike(&request_dgram(2)).unwrap();
        let (got, src) = peer_recv(&p);
        assert_eq!(got, request_dgram(2));
        assert_eq!(src, new);
        // ... and receives arrive on it.
        p.send_to(&response_dgram(2, OUR_SPI, 0x22), new).unwrap();
        assert_eq!(t.recv(Duration::from_secs(2)).unwrap(), Some(Incoming::Ike(response_dgram(2, OUR_SPI, 0x22))));
    }

    #[test]
    fn rebind_while_a_receive_is_blocked_is_picked_up_quickly() {
        let p = peer();
        let t = Arc::new(transport(&p));
        let rx = {
            let t = Arc::clone(&t);
            thread::spawn(move || {
                let started = Instant::now();
                let got = t.recv(Duration::from_secs(5)).unwrap();
                (got, started.elapsed())
            })
        };
        // Give the receiver time to park on the old socket, then move underneath it.
        thread::sleep(Duration::from_millis(50));
        let (new, _old) = t.rebind(LOOP).unwrap();
        thread::sleep(Duration::from_millis(50));
        p.send_to(&response_dgram(3, OUR_SPI, 0x33), new).unwrap();

        let (got, elapsed) = rx.join().unwrap();
        assert_eq!(got, Some(Incoming::Ike(response_dgram(3, OUR_SPI, 0x33))));
        assert!(elapsed < Duration::from_secs(3), "picked up the new socket in {elapsed:?}");
    }

    #[test]
    fn probe_egress_reports_the_route_address() {
        let p = peer();
        let t = transport(&p);
        assert_eq!(t.probe_egress().unwrap(), LOOP);
    }

    #[test]
    fn path_errors_are_classified() {
        use io::ErrorKind::*;
        for kind in [AddrNotAvailable, NetworkUnreachable, HostUnreachable, NetworkDown] {
            assert!(is_path_error(&io::Error::new(kind, "x")), "{kind:?}");
        }
        for kind in [TimedOut, WouldBlock, PermissionDenied, ConnectionRefused] {
            assert!(!is_path_error(&io::Error::new(kind, "x")), "{kind:?}");
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        assert!(is_path_error(&io::Error::from_raw_os_error(50)), "ENETDOWN");
        #[cfg(target_os = "linux")]
        assert!(is_path_error(&io::Error::from_raw_os_error(100)), "ENETDOWN");
        assert!(!is_path_error(&io::Error::from_raw_os_error(2)), "ENOENT is not a path error");
    }

    /// `discover_egress` names the gateway in its error. Re-wrapping must not cost the
    /// path classification the monitor needs — `io::Error::new` keeps `kind()`, which
    /// `is_path_error` checks before the errno fallback.
    #[test]
    fn a_connect_error_keeps_its_gateway_context_and_its_classification() {
        for kind in [io::ErrorKind::NetworkUnreachable, io::ErrorKind::HostUnreachable] {
            let raw = io::Error::new(kind, "Network is unreachable");
            let wrapped = io::Error::new(raw.kind(), format!("no route to gateway 203.0.113.9:500: {raw}"));
            assert!(is_path_error(&wrapped), "{kind:?}");
            assert!(wrapped.to_string().contains("no route to gateway 203.0.113.9:500"), "{wrapped}");
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
        {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            let raw = io::Error::from_raw_os_error(51);
            #[cfg(target_os = "linux")]
            let raw = io::Error::from_raw_os_error(101);
            // The errno is dropped by the re-wrap; the kind std derived from it is not.
            let wrapped = io::Error::new(raw.kind(), format!("no route to gateway 203.0.113.9:500: {raw}"));
            assert!(is_path_error(&wrapped), "ENETUNREACH survives the re-wrap as a kind");
        }
    }

    #[test]
    fn stray_source_datagrams_are_counted_not_fatal() {
        let p = peer();
        let stranger = peer();
        let t = transport(&p);
        stranger.send_to(&request_dgram(9), t.local_addr()).unwrap();
        assert_eq!(t.recv(Duration::from_millis(150)).unwrap(), None);
        assert_eq!(t.stray_sources(), 1);
    }

    #[test]
    fn rebind_rejects_a_different_family() {
        let p = peer();
        let t = transport(&p);
        let r = t.rebind(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(matches!(r, Err(Error::Config(_))), "got {r:?}");
        assert_eq!(t.local_addr().ip(), LOOP, "nothing was swapped");
    }

    #[test]
    fn retransmit_schedule_matches_aosp_defaults() {
        let d = RetransmitConfig::default();
        let waits: Vec<u64> = (0..5).map(|n| retransmit_timeout(&d, n).as_millis() as u64).collect();
        assert_eq!(waits, vec![500, 1000, 2000, 4000, 8000]);
        let odd = RetransmitConfig { initial_timeout_ms: 0, backoff_multiplier: f64::NAN, max_attempts: 1 };
        assert_eq!(retransmit_timeout(&odd, 3), Duration::from_millis(1));
    }
}
