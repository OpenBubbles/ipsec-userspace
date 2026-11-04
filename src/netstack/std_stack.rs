//! [`StdNetStack`] — the [`NetStack`] backend over `std::net` and the libc resolver
//! (DESIGN.md §16). No dependencies beyond `std`.
//!
//! - UDP: `std::net::UdpSocket`. The default stack is a dual-stack `[::]` socket
//!   (IPv4 peers appear as `::ffff:a.b.c.d`), so IPv4 destinations are mapped on send
//!   and v4-mapped peers are normalised back to IPv4 on receive. The largest datagram
//!   `send_to` accepts is the OS's (macOS: `net.inet.udp.maxdgram`, 9216 bytes by
//!   default; larger payloads fail with `EMSGSIZE`), whereas the tunnel fragments up
//!   to ~64 KiB — keep SIP messages that must work on both under that limit.
//! - TCP: `TcpStream::connect_timeout` / `TcpListener`. std listeners have no accept
//!   timeout, so `accept_timeout` polls a non-blocking `accept` every
//!   [`ACCEPT_POLL_INTERVAL`] until the deadline and hands back a blocking stream.
//! - DNS: `std::net::ToSocketAddrs` (`getaddrinfo`) on a detached helper thread, so
//!   the caller's timeout is honoured even though `getaddrinfo` itself cannot be
//!   interrupted.
//! - `local_addrs`: the bind address when specific, else the egress address per
//!   family, discovered with a `connect`ed UDP socket that never sends anything
//!   (`connect` only performs the route lookup).

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, trace, warn};

use super::{NetStack, TcpListenerLike, TcpStreamLike, UdpSocketLike, normalise, parse_ip_literal, validate_hostname};

/// How often `accept_timeout` re-tries a non-blocking `accept` while waiting.
pub const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Receive buffer of `recv_timeout`: the largest UDP payload plus slack.
const UDP_RECV_BUFFER: usize = 64 * 1024;
/// `set_read_timeout(Some(0))` is an error in std; the shortest wait we ask for.
const MIN_TIMEOUT: Duration = Duration::from_millis(1);
/// Egress probes for `local_addrs`: TEST-NET-1 and the documentation prefix, never
/// transmitted (a UDP `connect` only selects the route and source address).
const V4_PROBE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
const V6_PROBE: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 9);

/// The host OS network stack as a [`NetStack`].
///
/// [`StdNetStack::new`] binds every socket to the dual-stack wildcard `[::]` (both
/// families through one socket; falls back to `0.0.0.0` when IPv6 is unavailable or
/// the OS makes `[::]` sockets IPv6-only). [`StdNetStack::with_bind_addr`] pins one
/// address, which also selects the family. Outgoing TCP connections are not bound to
/// a specific bind address (std has no bind-before-connect); the OS picks the source.
#[derive(Clone, Debug)]
pub struct StdNetStack {
    bind_addr: IpAddr,
    /// `bind_addr` is `[::]` and sockets bound to it accept IPv4 traffic as well.
    dual_stack: bool,
}

impl Default for StdNetStack {
    fn default() -> Self {
        Self::new()
    }
}

impl StdNetStack {
    /// Dual-stack `[::]` when the OS supports it, else `0.0.0.0`.
    pub fn new() -> StdNetStack {
        match Self::ipv6_wildcard_is_dual_stack() {
            Ok(()) => StdNetStack { bind_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), dual_stack: true },
            Err(e) => {
                warn!("std netstack: dual-stack [::] unavailable ({e}); using 0.0.0.0 (IPv4 only)");
                StdNetStack { bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), dual_stack: false }
            }
        }
    }

    /// Bind every socket to `addr` (a specific address pins the family; `::` means
    /// dual-stack as in [`StdNetStack::new`] — IPv6 only if the OS refuses IPv4 on
    /// `[::]` sockets — and `0.0.0.0` IPv4 only).
    pub fn with_bind_addr(addr: IpAddr) -> StdNetStack {
        let dual_stack = addr == IpAddr::V6(Ipv6Addr::UNSPECIFIED) && Self::ipv6_wildcard_is_dual_stack().is_ok();
        StdNetStack { bind_addr: addr, dual_stack }
    }

    /// The address sockets are bound to.
    pub fn bind_addr(&self) -> IpAddr {
        self.bind_addr
    }

    /// Whether sockets reach both families through one `[::]` socket.
    pub fn is_dual_stack(&self) -> bool {
        self.dual_stack
    }

    /// Can we bind `[::]` and does such a socket take IPv4 destinations (`IPV6_V6ONLY`
    /// off, the macOS/Linux default)? Nothing is transmitted.
    fn ipv6_wildcard_is_dual_stack() -> io::Result<()> {
        let probe = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))?;
        probe.connect(SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 9))
    }

    fn bind_socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.bind_addr, port)
    }
}

/// The moment `timeout` from now expires; `None` when it never does (`Duration::MAX`
/// and friends overflow `Instant`, which must mean "wait forever", not a panic).
fn deadline_after(timeout: Duration) -> Option<Instant> {
    Instant::now().checked_add(timeout)
}

/// `a.b.c.d` → `::ffff:a.b.c.d` (for sending from a dual-stack IPv6 socket).
fn map_to_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)),
        v6 => v6,
    }
}

// ---------------------------------------------------------------------------
// NetStack
// ---------------------------------------------------------------------------

impl NetStack for StdNetStack {
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>> {
        let sock = UdpSocket::bind(self.bind_socket_addr(local_port))?;
        let local = normalise(sock.local_addr()?);
        debug!("std UDP socket bound on {local}");
        Ok(Box::new(StdUdpSocket { sock, local, dual_stack: self.dual_stack, rx: Mutex::new(Vec::new()) }))
    }

    fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>> {
        let remote = normalise(remote);
        // std refuses a zero timeout with InvalidInput; a zero budget is a (very
        // short) timeout here, like everywhere else in this stack.
        let stream = TcpStream::connect_timeout(&remote, timeout.max(MIN_TIMEOUT))?;
        let stream = StdTcpStream::new(stream)?;
        debug!("std TCP connected {} -> {}", stream.local, stream.peer);
        Ok(Box::new(stream))
    }

    fn listen_tcp(&self, local_port: u16) -> io::Result<Box<dyn TcpListenerLike>> {
        let inner = TcpListener::bind(self.bind_socket_addr(local_port))?;
        inner.set_nonblocking(true)?;
        let local = normalise(inner.local_addr()?);
        debug!("std TCP listener on {local}");
        Ok(Box::new(StdTcpListener { inner, local }))
    }

    fn resolve(&self, host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![ip]);
        }
        validate_hostname(host)?;
        let (tx, rx) = mpsc::channel::<io::Result<Vec<IpAddr>>>();
        let name = host.to_string();
        thread::Builder::new().name("epdg-resolve".into()).spawn(move || {
            let r = (name.as_str(), 0u16).to_socket_addrs().map(|addrs| {
                let mut out: Vec<IpAddr> = Vec::new();
                for ip in addrs.map(|sa| normalise(sa).ip()) {
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
                out
            });
            // The caller may have given up already; nothing to do then.
            let _ = tx.send(r);
        })?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(addrs)) if addrs.is_empty() => Err(io::Error::new(ErrorKind::NotFound, format!("{host}: no addresses"))),
            Ok(Ok(addrs)) => {
                trace!("std resolved {host} -> {addrs:?}");
                Ok(addrs)
            }
            Ok(Err(e)) => Err(e),
            Err(RecvTimeoutError::Timeout) => {
                debug!("std resolver: {host} not answered within {timeout:?} (helper thread detached)");
                Err(io::Error::new(ErrorKind::TimedOut, format!("resolving {host} took longer than {timeout:?}")))
            }
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::other(format!("resolver thread for {host} ended without a result"))),
        }
    }

    fn local_addrs(&self) -> Vec<IpAddr> {
        if !self.bind_addr.is_unspecified() {
            return vec![self.bind_addr];
        }
        let mut out = Vec::new();
        if self.bind_addr.is_ipv6() {
            out.extend(egress_address(V6_PROBE));
        }
        out.extend(egress_address(V4_PROBE));
        out
    }

    fn name(&self) -> &'static str {
        "std"
    }
}

/// The source address the OS would use towards `probe`, without sending anything:
/// bind the family's wildcard, `connect` (route lookup only), read `local_addr`.
/// `None` when the family has no route, or when the selected source is link-local
/// (an `fe80::` / `169.254.` address without its zone is unusable as a SIP
/// Via/Contact; that happens when the only IPv6 default route came from a router
/// advertisement without a global prefix).
fn egress_address(probe: SocketAddr) -> Option<IpAddr> {
    let wildcard = if probe.is_ipv6() { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
    let sock = match UdpSocket::bind(SocketAddr::new(wildcard, 0)) {
        Ok(s) => s,
        Err(e) => {
            trace!("egress probe: cannot bind {wildcard}: {e}");
            return None;
        }
    };
    if let Err(e) = sock.connect(probe) {
        trace!("egress probe: no route towards {probe}: {e}");
        return None;
    }
    let ip = normalise(sock.local_addr().ok()?).ip();
    if is_link_local(ip) {
        trace!("egress probe: source towards {probe} is link-local ({ip}); not usable without its zone, omitted");
        return None;
    }
    (!ip.is_unspecified()).then_some(ip)
}

/// `fe80::/10` or `169.254.0.0/16`.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
        IpAddr::V4(v4) => v4.is_link_local(),
    }
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

struct StdUdpSocket {
    sock: UdpSocket,
    local: SocketAddr,
    dual_stack: bool,
    /// Receive buffer; also serialises receivers (one `set_read_timeout` + `recv_from`
    /// at a time, like the tunnel socket's receiver mutex).
    rx: Mutex<Vec<u8>>,
}

impl UdpSocketLike for StdUdpSocket {
    fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let dst = if self.dual_stack { map_to_v6(dst) } else { dst };
        let n = self.sock.send_to(payload, dst)?;
        if n != payload.len() {
            return Err(io::Error::new(ErrorKind::WriteZero, format!("short UDP send: {n} of {} bytes", payload.len())));
        }
        Ok(())
    }

    fn recv_timeout(&self, timeout: Duration) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        let mut buf = self.rx.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() < UDP_RECV_BUFFER {
            buf.resize(UDP_RECV_BUFFER, 0);
        }
        let deadline = deadline_after(timeout);
        loop {
            // No deadline (an unrepresentably long timeout): block without a timeout.
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()).max(MIN_TIMEOUT));
            self.sock.set_read_timeout(left)?;
            match self.sock.recv_from(&mut buf) {
                Ok((n, peer)) => return Ok(Some((normalise(peer), buf[..n].to_vec()))),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(None),
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Ok(None);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

struct StdTcpStream {
    inner: TcpStream,
    local: SocketAddr,
    peer: SocketAddr,
}

impl StdTcpStream {
    fn new(inner: TcpStream) -> io::Result<StdTcpStream> {
        let local = normalise(inner.local_addr()?);
        let peer = normalise(inner.peer_addr()?);
        Ok(StdTcpStream { inner, local, peer })
    }
}

impl TcpStreamLike for StdTcpStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // One `send`: on a write timeout the kernel returns what it accepted, or an
        // error having accepted nothing — never both, so TLS may retry the record.
        (&self.inner).write(buf)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn shutdown(&self) -> io::Result<()> {
        match self.inner.shutdown(Shutdown::Both) {
            // Already down (peer closed, or shut down before): ENOTCONN on the BSDs /
            // macOS. Both directions are what the caller wanted; nothing to report.
            Err(e) if e.kind() == ErrorKind::NotConnected => Ok(()),
            r => r,
        }
    }
}

struct StdTcpListener {
    /// Kept non-blocking; accepted streams are switched back to blocking.
    inner: TcpListener,
    local: SocketAddr,
}

impl TcpListenerLike for StdTcpListener {
    fn accept_timeout(&self, timeout: Duration) -> io::Result<Option<(Box<dyn TcpStreamLike>, SocketAddr)>> {
        let deadline = deadline_after(timeout);
        loop {
            match self.inner.accept() {
                Ok((stream, _)) => {
                    // BSDs hand out non-blocking accepted sockets; std's Read/Write
                    // contract here is blocking (with the optional timeouts).
                    stream.set_nonblocking(false)?;
                    let stream = StdTcpStream::new(stream)?;
                    let peer = stream.peer;
                    debug!("std TCP accepted {peer} on {}", self.local);
                    return Ok(Some((Box::new(stream), peer)));
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                    let now = Instant::now();
                    let nap = match deadline {
                        Some(d) if now >= d => return Ok(None),
                        Some(d) => (d - now).min(ACCEPT_POLL_INTERVAL),
                        None => ACCEPT_POLL_INTERVAL,
                    };
                    thread::sleep(nap);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

// ---------------------------------------------------------------------------
// Tests (loopback only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstack::tests::{SILENCE, WAIT, exercise_tcp, exercise_tcp_write_timeout, exercise_udp, exercise_udp_via, recv};
    use std::sync::Arc;

    const V4_LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const V6_LO: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    fn ipv6_loopback_available() -> bool {
        UdpSocket::bind(SocketAddr::new(V6_LO, 0)).is_ok()
    }

    // ---- helpers ------------------------------------------------------------

    #[test]
    fn address_mapping_helpers() {
        let v4 = SocketAddr::new(V4_LO, 5060);
        let mapped = map_to_v6(v4);
        assert_eq!(mapped.to_string(), "[::ffff:127.0.0.1]:5060");
        assert_eq!(normalise(mapped), v4);
        let v6 = SocketAddr::new(V6_LO, 1);
        assert_eq!(map_to_v6(v6), v6);
        assert_eq!(normalise(v6), v6);
        assert_eq!(normalise(v4), v4);
        assert!(is_link_local(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(is_link_local(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_link_local(V6_LO) && !is_link_local(V4_LO));
        assert!(!is_link_local(IpAddr::V6("2001:db8::1".parse().unwrap())));
        // Unrepresentable deadlines mean "never", not a panic.
        assert!(deadline_after(Duration::MAX).is_none());
        assert!(deadline_after(Duration::from_secs(u64::MAX / 2)).is_none());
        assert!(deadline_after(Duration::ZERO).is_some_and(|d| d <= Instant::now()));
        assert!(deadline_after(WAIT).is_some_and(|d| d > Instant::now()));
    }

    #[test]
    fn constructors_report_bind_address_and_name() {
        let s = StdNetStack::new();
        assert_eq!(s.name(), "std");
        assert!(s.bind_addr().is_unspecified());
        assert_eq!(s.is_dual_stack(), s.bind_addr().is_ipv6());
        assert_eq!(StdNetStack::default().bind_addr(), s.bind_addr());
        let pinned = StdNetStack::with_bind_addr(V4_LO);
        assert_eq!(pinned.bind_addr(), V4_LO);
        assert!(!pinned.is_dual_stack());
        assert_eq!(pinned.local_addrs(), vec![V4_LO]);
        assert!(!StdNetStack::with_bind_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).is_dual_stack());
        assert!(format!("{s:?}").contains("StdNetStack"));
    }

    #[test]
    fn local_addrs_of_the_wildcard_stack_are_real_egress_addresses() {
        let addrs = StdNetStack::new().local_addrs();
        // Empty is legal on a machine without any route (nothing to assert then).
        for a in &addrs {
            assert!(!a.is_unspecified(), "{a}");
            assert!(!matches!(a, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()), "{a} is v4-mapped");
            assert!(!is_link_local(*a), "{a} is link-local (unusable as a Via/Contact without its zone)");
        }
        let mut dedup = addrs.clone();
        dedup.dedup();
        assert_eq!(dedup, addrs);
        assert!(addrs.iter().filter(|a| a.is_ipv4()).count() <= 1);
        assert!(addrs.iter().filter(|a| a.is_ipv6()).count() <= 1);
    }

    // ---- UDP ----------------------------------------------------------------

    #[test]
    fn udp_exercise_on_ipv4_loopback() {
        let a = StdNetStack::with_bind_addr(V4_LO);
        let b = StdNetStack::with_bind_addr(V4_LO);
        exercise_udp(&a, &b);
    }

    #[test]
    fn udp_exercise_on_ipv6_loopback() {
        if !ipv6_loopback_available() {
            eprintln!("skipping: no IPv6 loopback");
            return;
        }
        let a = StdNetStack::with_bind_addr(V6_LO);
        let b = StdNetStack::with_bind_addr(V6_LO);
        exercise_udp(&a, &b);
    }

    #[test]
    fn udp_exercise_on_the_dual_stack_default_through_arc_dyn() {
        let a: Arc<dyn NetStack> = Arc::new(StdNetStack::new());
        let b: Arc<dyn NetStack> = Arc::new(StdNetStack::new());
        if a.local_addrs().is_empty() {
            eprintln!("skipping: this machine has no route (local_addrs is empty)");
            return;
        }
        // Loopback only: b is reached over IPv4 (the v4-mapped path of a dual-stack
        // socket), a over IPv6 when the host has an IPv6 loopback.
        let a_ip = if a.local_addrs().iter().any(IpAddr::is_ipv6) && ipv6_loopback_available() { V6_LO } else { V4_LO };
        exercise_udp_via(&*a, &*b, Some((a_ip, V4_LO)));
        exercise_udp_via(&a, &b, Some((a_ip, V4_LO)));
    }

    #[test]
    fn dual_stack_udp_socket_maps_ipv4_peers_both_ways() {
        let stack = StdNetStack::new();
        if !stack.is_dual_stack() {
            eprintln!("skipping: no dual-stack [::] socket on this host");
            return;
        }
        let v6 = stack.bind_udp(0).unwrap();
        assert!(v6.local_addr().ip().is_unspecified() && v6.local_addr().is_ipv6(), "{}", v6.local_addr());
        let v4 = StdNetStack::with_bind_addr(V4_LO).bind_udp(0).unwrap();
        // v4-only peer -> dual-stack socket: the peer is reported as plain IPv4.
        v4.send_to(SocketAddr::new(V4_LO, v6.local_addr().port()), b"from v4").unwrap();
        let (peer, payload) = recv(&*v6, "dual-stack socket receives from IPv4");
        assert_eq!(payload, b"from v4");
        assert_eq!(peer, v4.local_addr(), "v4-mapped peer normalised to IPv4");
        // ...and that address is directly usable for the reply (mapped on send).
        v6.send_to(peer, b"to v4").unwrap();
        let (peer, payload) = recv(&*v4, "IPv4 socket receives the reply");
        assert_eq!(payload, b"to v4");
        assert_eq!(peer, SocketAddr::new(V4_LO, v6.local_addr().port()));
        // IPv6 still works on the same socket.
        if ipv6_loopback_available() {
            v6.send_to(SocketAddr::new(V6_LO, v6.local_addr().port()), b"self v6").unwrap();
            let (peer, payload) = recv(&*v6, "dual-stack socket receives IPv6");
            assert_eq!(payload, b"self v6");
            assert_eq!(peer, SocketAddr::new(V6_LO, v6.local_addr().port()));
        }
    }

    #[test]
    fn udp_fixed_port_conflicts_and_wrong_family_are_errors() {
        let stack = StdNetStack::with_bind_addr(V4_LO);
        let first = stack.bind_udp(0).unwrap();
        let e = stack.bind_udp(first.local_addr().port()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AddrInUse, "{e}");
        // An IPv6 destination from an IPv4-only socket is refused by the OS.
        assert!(first.send_to(SocketAddr::new(V6_LO, 9), b"x").is_err());
        // A socket shared between a receiver thread and a sender (Send + Sync).
        let shared: Arc<dyn UdpSocketLike> = Arc::from(stack.bind_udp(0).unwrap());
        let receiver = {
            let s = Arc::clone(&shared);
            thread::spawn(move || s.recv_timeout(WAIT))
        };
        thread::sleep(Duration::from_millis(20));
        first.send_to(shared.local_addr(), b"wake").unwrap();
        let (peer, payload) = receiver.join().unwrap().unwrap().expect("datagram");
        assert_eq!(payload, b"wake");
        assert_eq!(peer, first.local_addr());
    }

    /// `Duration::MAX` (and any timeout that overflows `Instant`) means "wait until
    /// something happens" — the receiver / acceptor must wake up, not panic.
    #[test]
    fn wait_forever_timeouts_block_until_woken_instead_of_panicking() {
        let stack = StdNetStack::with_bind_addr(V4_LO);
        for timeout in [Duration::MAX, Duration::from_secs(u64::MAX / 2)] {
            // UDP: a receiver blocked "forever" is woken by a datagram.
            let shared: Arc<dyn UdpSocketLike> = Arc::from(stack.bind_udp(0).unwrap());
            let receiver = {
                let s = Arc::clone(&shared);
                thread::spawn(move || s.recv_timeout(timeout))
            };
            thread::sleep(Duration::from_millis(20));
            let sender = stack.bind_udp(0).unwrap();
            sender.send_to(shared.local_addr(), b"wake").unwrap();
            let (peer, payload) = receiver.join().expect("recv_timeout must not panic").unwrap().expect("datagram");
            assert_eq!(payload, b"wake");
            assert_eq!(peer, sender.local_addr());
            // A finite timeout still works on the same socket afterwards (the read
            // timeout is re-armed per call).
            let started = Instant::now();
            assert!(shared.recv_timeout(SILENCE).unwrap().is_none());
            assert!(started.elapsed() < WAIT);

            // TCP: an acceptor blocked "forever" is woken by a connection.
            let listener: Arc<dyn TcpListenerLike> = Arc::from(stack.listen_tcp(0).unwrap());
            let acceptor = {
                let l = Arc::clone(&listener);
                thread::spawn(move || l.accept_timeout(timeout))
            };
            thread::sleep(Duration::from_millis(20));
            let client = stack.connect_tcp(listener.local_addr(), WAIT).unwrap();
            let (server, peer) = acceptor.join().expect("accept_timeout must not panic").unwrap().expect("accepted");
            assert_eq!(peer, client.local_addr());
            assert_eq!(server.peer_addr(), client.local_addr());
            assert!(listener.accept_timeout(SILENCE).unwrap().is_none());
        }
    }

    // ---- TCP ----------------------------------------------------------------

    /// `StreamIo::write` (and `TcpStreamLike::write`) keep the `io::Write` contract
    /// under a write timeout: an `Err` never consumed bytes. TLS relies on that to
    /// retry a record; the old `write_all`-based adapter delivered a partial record
    /// and then reported failure.
    #[test]
    fn write_under_a_write_timeout_never_loses_bytes() {
        exercise_tcp_write_timeout(&StdNetStack::with_bind_addr(V4_LO), &StdNetStack::with_bind_addr(V4_LO));
    }

    #[test]
    fn tcp_exercise_on_ipv4_loopback() {
        exercise_tcp(&StdNetStack::with_bind_addr(V4_LO), &StdNetStack::with_bind_addr(V4_LO));
    }

    #[test]
    fn tcp_exercise_on_ipv6_loopback() {
        if !ipv6_loopback_available() {
            eprintln!("skipping: no IPv6 loopback");
            return;
        }
        exercise_tcp(&StdNetStack::with_bind_addr(V6_LO), &StdNetStack::with_bind_addr(V6_LO));
    }

    #[test]
    fn dual_stack_listener_reports_ipv4_peers_as_ipv4() {
        let stack = StdNetStack::new();
        if !stack.is_dual_stack() {
            eprintln!("skipping: no dual-stack [::] socket on this host");
            return;
        }
        let listener = stack.listen_tcp(0).unwrap();
        let remote = SocketAddr::new(V4_LO, listener.local_addr().port());
        let client = thread::spawn(move || StdNetStack::with_bind_addr(V4_LO).connect_tcp(remote, WAIT));
        let (server, peer) = listener.accept_timeout(WAIT).unwrap().expect("accepted");
        let client = client.join().unwrap().unwrap();
        assert!(peer.is_ipv4(), "{peer}");
        assert_eq!(peer, client.local_addr());
        assert_eq!(server.local_addr(), remote, "v4-mapped local address normalised");
        // The dual-stack side can also connect out to an IPv4 listener.
        let v4_listener = StdNetStack::with_bind_addr(V4_LO).listen_tcp(0).unwrap();
        let out = stack.connect_tcp(v4_listener.local_addr(), WAIT).unwrap();
        assert_eq!(out.peer_addr(), v4_listener.local_addr());
        assert!(v4_listener.accept_timeout(WAIT).unwrap().is_some());
    }

    #[test]
    fn accept_timeout_returns_a_blocking_stream() {
        let stack = StdNetStack::with_bind_addr(V4_LO);
        let listener = stack.listen_tcp(0).unwrap();
        let remote = listener.local_addr();
        let client = thread::spawn(move || StdNetStack::with_bind_addr(V4_LO).connect_tcp(remote, WAIT));
        let (server, _) = listener.accept_timeout(WAIT).unwrap().expect("accepted");
        let client = client.join().unwrap().unwrap();
        // A blocking read with a timeout waits (a non-blocking one would fail at once).
        let started = Instant::now();
        server.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        let e = server.read(&mut [0u8; 8]).unwrap_err();
        assert!(matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut), "{e}");
        assert!(started.elapsed() >= Duration::from_millis(100), "read blocked for the timeout: {:?}", started.elapsed());
        drop(client);
    }

    // ---- DNS ----------------------------------------------------------------

    #[test]
    fn resolve_localhost_contains_a_loopback() {
        let stack = StdNetStack::new();
        let addrs = stack.resolve("localhost", WAIT).unwrap();
        assert!(addrs.iter().any(|a| a.is_loopback()), "{addrs:?}");
        let mut dedup = addrs.clone();
        dedup.dedup();
        assert_eq!(dedup, addrs, "deduplicated");
    }

    #[test]
    fn resolve_ip_literals_without_the_resolver() {
        let stack = StdNetStack::new();
        // A zero timeout proves no resolver round trip happened.
        assert_eq!(stack.resolve("127.0.0.1", Duration::ZERO).unwrap(), vec![V4_LO]);
        assert_eq!(stack.resolve("::1", Duration::ZERO).unwrap(), vec![V6_LO]);
        assert_eq!(stack.resolve("[::1]", Duration::ZERO).unwrap(), vec![V6_LO]);
    }

    #[test]
    fn resolve_rejects_invalid_names_without_the_resolver() {
        let stack = StdNetStack::new();
        for bad in ["", "a..b", ".", "bad host", "a/b"] {
            let e = stack.resolve(bad, WAIT).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}: {e}");
        }
    }

    #[test]
    fn resolve_honours_a_too_short_timeout() {
        let stack = StdNetStack::new();
        let started = Instant::now();
        let r = stack.resolve("localhost", Duration::ZERO);
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(1), "returned promptly: {elapsed:?}");
        match r {
            Err(e) => assert!(matches!(e.kind(), ErrorKind::TimedOut) || elapsed < Duration::from_millis(500), "{e}"),
            Ok(addrs) => assert!(addrs.iter().any(|a| a.is_loopback()), "the helper was quicker than the deadline: {addrs:?}"),
        }
        // Short but not zero: the same contract.
        let r = stack.resolve("localhost", Duration::from_millis(1));
        assert!(r.is_ok() || r.as_ref().unwrap_err().kind() == ErrorKind::TimedOut, "{r:?}");
    }
}
