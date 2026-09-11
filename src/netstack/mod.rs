//! [`NetStack`] — one socket/DNS abstraction over the host OS stack and the ePDG
//! tunnel (DESIGN.md §16).
//!
//! Application code (a SIP client, say) is written once against `&dyn NetStack` /
//! `Arc<dyn NetStack>` and runs unchanged on either backend:
//!
//! - [`StdNetStack`] (`std_stack`): `std::net` sockets and the libc resolver
//!   (`getaddrinfo`). UDP, TCP (client + listener) and DNS.
//! - [`EpdgTunnel`]: inner UDP sockets and the smoltcp DNS socket over the
//!   gateway-assigned servers (the libc resolver cannot reach tunnel-internal DNS).
//!   TCP over the tunnel is **not implemented yet**: `connect_tcp` / `listen_tcp`
//!   return `Err(ErrorKind::Unsupported)`. [`InnerStack`] implements the trait the
//!   same way so the abstraction is testable offline over the two-stack loopback.
//!
//! Everything is synchronous and object-safe. Errors are `io::Error`; the crate's
//! [`Error`] is mapped by [`to_io`] (`Timeout` → `TimedOut`, `Closed` → `NotConnected`,
//! `Config`/`Unsupported` → `InvalidInput`, the rest → `Other`, source preserved).

use std::fmt;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::Error;
use crate::ipstack::{InnerStack, InnerUdpSocket};
use crate::tunnel::EpdgTunnel;

pub mod std_stack;

pub use std_stack::StdNetStack;

/// Message of the `Unsupported` error returned by the tunnel backend's TCP methods.
pub const TUNNEL_TCP_UNSUPPORTED: &str = "TCP over the ePDG tunnel is not implemented yet";

/// A network stack: UDP sockets, TCP connections/listeners and a resolver, all
/// sourced from the same place (the OS or the ePDG tunnel). Object-safe.
pub trait NetStack: Send + Sync {
    /// Bind a UDP socket on `local_port` (0 = ephemeral).
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>>;
    /// Open a TCP connection to `remote` within `timeout`. Tunnel backend:
    /// `Err(ErrorKind::Unsupported)` for now.
    fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>>;
    /// Listen for TCP connections on `local_port` (0 = ephemeral). Tunnel backend:
    /// `Err(ErrorKind::Unsupported)` for now.
    fn listen_tcp(&self, local_port: u16) -> io::Result<Box<dyn TcpListenerLike>>;
    /// Resolve `host` to A/AAAA addresses with THIS stack's resolver, within
    /// `timeout`. IP literals (also bracketed, `[::1]`) return immediately without
    /// touching the resolver. `Err(TimedOut)` when the resolver did not answer in time.
    fn resolve(&self, host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>>;
    /// Addresses this stack sources traffic from (SIP Via/Contact): the tunnel's inner
    /// addresses; for the OS stack the configured bind address, else the
    /// route-selected egress address per family (families without a route omitted).
    fn local_addrs(&self) -> Vec<IpAddr>;
    /// Backend name for logs: `"std"` / `"epdg-tunnel"`.
    fn name(&self) -> &'static str;
}

/// A bound UDP socket. `Send + Sync`: one thread may block in `recv_timeout` while
/// others `send_to`.
pub trait UdpSocketLike: Send + Sync {
    /// Send one datagram to `dst`.
    fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> io::Result<()>;
    /// Wait up to `timeout` for one datagram: `Ok(Some((peer, payload)))`, `Ok(None)`
    /// on timeout, `Err(NotConnected)` once the stack is closed.
    fn recv_timeout(&self, timeout: Duration) -> io::Result<Option<(SocketAddr, Vec<u8>)>>;
    /// The bound address (port always meaningful; the IP may be unspecified for a
    /// wildcard-bound OS socket).
    fn local_addr(&self) -> SocketAddr;
}

/// A connected TCP stream. Methods take `&self` (like `impl Read/Write for
/// &std::net::TcpStream`) so one connection can be shared by a reader thread and a
/// writer thread through `Arc<dyn TcpStreamLike>`; wrap it in [`StreamIo`] for
/// `io::Read + io::Write` consumers (TLS).
pub trait TcpStreamLike: Send + Sync {
    /// Read into `buf`; `Ok(0)` = EOF; honours the read timeout
    /// (`Err(WouldBlock | TimedOut)` on expiry).
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write all of `buf` (honours the write timeout).
    fn write_all(&self, buf: &[u8]) -> io::Result<()>;
    /// Read timeout for subsequent `read`s (`None` = block forever).
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Write timeout for subsequent `write_all`s (`None` = block forever).
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Toggle Nagle's algorithm.
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
    /// Our end of the connection.
    fn local_addr(&self) -> SocketAddr;
    /// The peer's end of the connection.
    fn peer_addr(&self) -> SocketAddr;
    /// Shut down both directions (the peer reads EOF).
    fn shutdown(&self) -> io::Result<()>;
}

/// A TCP listener.
pub trait TcpListenerLike: Send + Sync {
    /// Accept one connection, waiting at most `timeout`; `Ok(None)` on timeout.
    fn accept_timeout(&self, timeout: Duration) -> io::Result<Option<(Box<dyn TcpStreamLike>, SocketAddr)>>;
    /// The bound address (the port is what peers connect to).
    fn local_addr(&self) -> SocketAddr;
}

impl fmt::Debug for dyn UdpSocketLike {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSocketLike").field("local_addr", &self.local_addr()).finish()
    }
}

impl fmt::Debug for dyn TcpStreamLike {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStreamLike").field("local_addr", &self.local_addr()).field("peer_addr", &self.peer_addr()).finish()
    }
}

impl fmt::Debug for dyn TcpListenerLike {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListenerLike").field("local_addr", &self.local_addr()).finish()
    }
}

/// `std::io::Read + Write` adapter over any `&dyn TcpStreamLike` so TLS (e.g.
/// `openssl::ssl::SslStream`) or any other `Read`/`Write` consumer can wrap it.
/// `flush` is a no-op: `write` already writes everything (`write_all`).
pub struct StreamIo<'a>(pub &'a dyn TcpStreamLike);

impl io::Read for StreamIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Write for StreamIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Map the crate's [`Error`] to an `io::Error`, keeping the original as the source:
/// `Io(e)` → `e`; `Timeout` → `TimedOut`; `Closed` → `NotConnected`;
/// `Config` / `Unsupported` → `InvalidInput`; everything else → `Other`.
pub fn to_io(e: Error) -> io::Error {
    let e = match e {
        Error::Io(inner) => return inner,
        other => other,
    };
    let kind = match &e {
        Error::Timeout(_) => ErrorKind::TimedOut,
        Error::Closed(_) => ErrorKind::NotConnected,
        Error::Config(_) | Error::Unsupported(_) => ErrorKind::InvalidInput,
        _ => return io::Error::other(e),
    };
    io::Error::new(kind, e)
}

/// `Err(Unsupported)` for the tunnel backend's TCP methods.
fn tunnel_tcp_unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(ErrorKind::Unsupported, TUNNEL_TCP_UNSUPPORTED))
}

/// Parse an IP literal, accepting the bracketed IPv6 form (`[::1]`) and a zone-less
/// address; `None` for anything that needs a resolver.
pub(crate) fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let inner = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    inner.parse().ok()
}

/// Cheap syntactic hostname check performed before a resolver is involved, so that
/// obviously invalid names fail with `InvalidInput` instead of a (possibly slow)
/// lookup: non-empty, ≤ 253 characters, labels of 1..=63 characters made of ASCII
/// letters, digits, `-` and `_` (a single trailing dot is allowed).
pub(crate) fn validate_hostname(host: &str) -> io::Result<()> {
    let invalid = |why: &str| Err(io::Error::new(ErrorKind::InvalidInput, format!("invalid host name {host:?}: {why}")));
    if host.is_empty() {
        return invalid("empty");
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() {
        return invalid("no labels");
    }
    if name.len() > 253 {
        return invalid("longer than 253 characters");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return invalid("empty label");
        }
        if label.len() > 63 {
            return invalid("label longer than 63 characters");
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return invalid("label contains characters outside [A-Za-z0-9-_]");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tunnel backend
// ---------------------------------------------------------------------------

impl UdpSocketLike for InnerUdpSocket {
    fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        InnerUdpSocket::send_to(self, dst, payload).map_err(to_io)
    }

    fn recv_timeout(&self, timeout: Duration) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        InnerUdpSocket::recv_timeout(self, timeout).map(|d| d.map(|d| (d.src, d.payload))).map_err(to_io)
    }

    fn local_addr(&self) -> SocketAddr {
        InnerUdpSocket::local_addr(self)
    }
}

/// The inner stack on its own (no IKE/ESP): the same delegation as [`EpdgTunnel`],
/// so the trait can be exercised offline over the two-stack loopback harness.
impl NetStack for InnerStack {
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>> {
        Ok(Box::new(InnerStack::bind_udp(self, local_port).map_err(to_io)?))
    }

    fn connect_tcp(&self, _remote: SocketAddr, _timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>> {
        tunnel_tcp_unsupported()
    }

    fn listen_tcp(&self, _local_port: u16) -> io::Result<Box<dyn TcpListenerLike>> {
        tunnel_tcp_unsupported()
    }

    fn resolve(&self, host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![ip]);
        }
        InnerStack::resolve(self, host, timeout).map_err(to_io)
    }

    fn local_addrs(&self) -> Vec<IpAddr> {
        self.addresses().into_iter().map(|(a, _)| a).collect()
    }

    fn name(&self) -> &'static str {
        "epdg-tunnel"
    }
}

/// The ePDG tunnel as a network stack: inner UDP sockets and DNS over the assigned
/// servers; TCP is not implemented yet (`Err(Unsupported)`).
impl NetStack for EpdgTunnel {
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>> {
        Ok(Box::new(EpdgTunnel::bind_udp(self, local_port).map_err(to_io)?))
    }

    fn connect_tcp(&self, _remote: SocketAddr, _timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>> {
        tunnel_tcp_unsupported()
    }

    fn listen_tcp(&self, _local_port: u16) -> io::Result<Box<dyn TcpListenerLike>> {
        tunnel_tcp_unsupported()
    }

    fn resolve(&self, host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![ip]);
        }
        EpdgTunnel::resolve(self, host, timeout).map_err(to_io)
    }

    fn local_addrs(&self) -> Vec<IpAddr> {
        self.stack().local_addrs()
    }

    fn name(&self) -> &'static str {
        "epdg-tunnel"
    }
}

/// Blanket forwarding so an `Arc<dyn NetStack>` (or `Arc<StdNetStack>`) is itself a
/// `NetStack` and can be passed where `&S: NetStack` is expected.
impl<S: NetStack + ?Sized> NetStack for Arc<S> {
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>> {
        (**self).bind_udp(local_port)
    }

    fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>> {
        (**self).connect_tcp(remote, timeout)
    }

    fn listen_tcp(&self, local_port: u16) -> io::Result<Box<dyn TcpListenerLike>> {
        (**self).listen_tcp(local_port)
    }

    fn resolve(&self, host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
        (**self).resolve(host, timeout)
    }

    fn local_addrs(&self) -> Vec<IpAddr> {
        (**self).local_addrs()
    }

    fn name(&self) -> &'static str {
        (**self).name()
    }
}

// ---------------------------------------------------------------------------
// Tests: the generic exercise shared by both backends, plus the tunnel backend
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread;

    use crate::ipstack::stack::tests::{ANS_V4, ANS_V6, DnsServer, HOST, Pair};

    pub(crate) const WAIT: Duration = Duration::from_secs(5);
    pub(crate) const SILENCE: Duration = Duration::from_millis(60);

    /// Wait for a datagram, panicking with context if none arrives in time.
    pub(crate) fn recv(sock: &dyn UdpSocketLike, what: &str) -> (SocketAddr, Vec<u8>) {
        sock.recv_timeout(WAIT).unwrap_or_else(|e| panic!("{what}: {e}")).unwrap_or_else(|| panic!("{what}: nothing within {WAIT:?}"))
    }

    /// Bind a fixed (non-ephemeral) port: random candidates in 40000..50000 until one
    /// is free (other tests bind ports concurrently), and check it is reported back.
    fn bind_fixed<S: NetStack + ?Sized>(stack: &S) -> Box<dyn UdpSocketLike> {
        for _ in 0..50 {
            let port = 40000 + rand::random::<u16>() % 10000;
            match stack.bind_udp(port) {
                Ok(s) => {
                    assert_eq!(s.local_addr().port(), port, "local_addr reports the requested port");
                    return s;
                }
                Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
                Err(e) => panic!("bind_udp({port}): {e}"),
            }
        }
        panic!("no free port found in 40000..50000");
    }

    /// The generic UDP exercise of DESIGN.md §16, run over both backends: bind two
    /// sockets (one per stack), send both ways, echo, silence → `None`, `local_addr`
    /// port, `local_addrs` non-empty, distinct ephemeral ports. Datagrams are addressed
    /// to each stack's first `local_addrs()` entry.
    pub(crate) fn exercise_udp<S: NetStack + ?Sized>(a: &S, b: &S) {
        exercise_udp_via(a, b, None);
    }

    /// [`exercise_udp`] with the addresses peers reach `a` and `b` at overridden (an
    /// OS wildcard stack is exercised over loopback rather than its egress address).
    pub(crate) fn exercise_udp_via<S: NetStack + ?Sized>(a: &S, b: &S, via: Option<(IpAddr, IpAddr)>) {
        assert!(!a.name().is_empty());
        assert!(!a.local_addrs().is_empty(), "{}: local_addrs of a", a.name());
        assert!(!b.local_addrs().is_empty(), "{}: local_addrs of b", b.name());
        let (a_ip, b_ip) = via.unwrap_or_else(|| (a.local_addrs()[0], b.local_addrs()[0]));

        let sa = a.bind_udp(0).unwrap();
        let sb = b.bind_udp(0).unwrap();
        let sa2 = a.bind_udp(0).unwrap();
        assert_ne!(sa.local_addr().port(), 0, "ephemeral port allocated");
        assert_ne!(sa.local_addr().port(), sa2.local_addr().port(), "ephemeral ports are distinct");
        drop(sa2);
        drop(sa);
        let sa = bind_fixed(a);

        let to_b = SocketAddr::new(b_ip, sb.local_addr().port());
        let to_a = SocketAddr::new(a_ip, sa.local_addr().port());
        let not_mapped = |addr: SocketAddr| {
            assert!(!matches!(addr.ip(), IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()), "{addr} is a v4-mapped peer");
        };

        // a -> b, b echoes to the source it saw, a -> b again from the reply address.
        sa.send_to(to_b, b"ping").unwrap();
        let (from, payload) = recv(&*sb, "b receives a's ping");
        assert_eq!(payload, b"ping");
        assert_eq!(from.port(), sa.local_addr().port(), "source port of a's datagram");
        not_mapped(from);
        sb.send_to(from, b"pong").unwrap();
        let (from_b, payload) = recv(&*sa, "a receives b's echo");
        assert_eq!(payload, b"pong");
        assert_eq!(from_b.port(), sb.local_addr().port());
        assert_eq!(from_b.ip(), to_b.ip(), "echo comes from the address we sent to");

        // b -> a directly.
        sb.send_to(to_a, b"hello a").unwrap();
        let (from, payload) = recv(&*sa, "a receives b's direct datagram");
        assert_eq!(payload, b"hello a");
        assert_eq!(from.port(), sb.local_addr().port());
        not_mapped(from);
        assert!(b.local_addrs().contains(&from.ip()) || from.ip().is_loopback(), "{from} is not one of b's addresses");

        // Silence.
        assert!(sa.recv_timeout(SILENCE).unwrap().is_none(), "recv_timeout -> None on silence");
        assert!(sb.recv_timeout(Duration::ZERO).unwrap().is_none(), "zero timeout -> None");

        // Bigger payload survives too.
        let big = vec![0xabu8; 1200];
        sa.send_to(to_b, &big).unwrap();
        assert_eq!(recv(&*sb, "b receives 1200 bytes").1, big);
    }

    // ---- pure helpers -----------------------------------------------------

    #[test]
    fn to_io_maps_kinds_and_keeps_the_source() {
        let e = to_io(Error::Timeout("DNS response"));
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        let inner = e.get_ref().and_then(|s| s.downcast_ref::<Error>()).expect("the crate error is kept inside");
        assert!(matches!(inner, Error::Timeout("DNS response")));
        assert!(e.to_string().contains("DNS response"), "{e}");
        assert_eq!(to_io(Error::Closed("gone".into())).kind(), ErrorKind::NotConnected);
        assert_eq!(to_io(Error::Config("bad".into())).kind(), ErrorKind::InvalidInput);
        assert_eq!(to_io(Error::Unsupported("nope".into())).kind(), ErrorKind::InvalidInput);
        assert_eq!(to_io(Error::Protocol("x".into())).kind(), ErrorKind::Other);
        assert!(to_io(Error::Protocol("x".into())).get_ref().is_some_and(|s| s.is::<Error>()));
        let io = io::Error::new(ErrorKind::AddrInUse, "taken");
        let back = to_io(Error::Io(io));
        assert_eq!(back.kind(), ErrorKind::AddrInUse);
        assert_eq!(back.to_string(), "taken", "Io(e) is returned as-is");
    }

    #[test]
    fn ip_literals_are_parsed_including_brackets() {
        assert_eq!(parse_ip_literal("127.0.0.1"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(parse_ip_literal("::1"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(parse_ip_literal("[::1]"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(parse_ip_literal("[2001:db8::1]"), Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert_eq!(parse_ip_literal("localhost"), None);
        assert_eq!(parse_ip_literal("[localhost]"), None);
        assert_eq!(parse_ip_literal("[::1"), None);
        assert_eq!(parse_ip_literal(""), None);
    }

    #[test]
    fn hostname_validation() {
        for ok in ["localhost", "localhost.", "a.b", "pcscf.example.test", "x-y_z.example", "1.example", &"a".repeat(63)] {
            validate_hostname(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["", ".", "a..b", ".a", "a b", "a/b", "ünïcode.example", &format!("{}.example", "x".repeat(64)), &"a.".repeat(128)] {
            let e = validate_hostname(bad).expect_err(bad);
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad}");
        }
    }

    #[test]
    fn stream_io_write_reports_the_whole_buffer() {
        // A stub stream that records writes and serves a canned read.
        struct Stub(std::sync::Mutex<Vec<u8>>);
        impl TcpStreamLike for Stub {
            fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
                let n = buf.len().min(3);
                buf[..n].copy_from_slice(&b"abc"[..n]);
                Ok(n)
            }
            fn write_all(&self, buf: &[u8]) -> io::Result<()> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(())
            }
            fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
            fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
            fn set_nodelay(&self, _: bool) -> io::Result<()> {
                Ok(())
            }
            fn local_addr(&self) -> SocketAddr {
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1)
            }
            fn peer_addr(&self) -> SocketAddr {
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2)
            }
            fn shutdown(&self) -> io::Result<()> {
                Ok(())
            }
        }
        use io::{Read, Write};
        let stub = Stub(std::sync::Mutex::new(Vec::new()));
        let mut io = StreamIo(&stub);
        assert_eq!(io.write(b"hello").unwrap(), 5);
        io.write_all(b" world").unwrap();
        io.flush().unwrap();
        assert_eq!(stub.0.lock().unwrap().as_slice(), b"hello world");
        let mut buf = [0u8; 8];
        assert_eq!(io.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"abc");
    }

    // ---- tunnel backend (InnerStack over the two-stack loopback) -------------

    #[test]
    fn tunnel_udp_exercise_over_the_loopback_pair() {
        let p = Pair::dual();
        assert_eq!(p.a.name(), "epdg-tunnel");
        exercise_udp(&p.a, &p.b);
        // The inner socket's address is the first inner address (IPv6 first) + port.
        let s = NetStack::bind_udp(&p.a, 0).unwrap();
        assert_eq!(s.local_addr().ip(), *p.a.local_addrs().first().unwrap());
        assert!(s.local_addr().is_ipv6());
    }

    #[test]
    fn tunnel_udp_exercise_through_arc_dyn_netstack() {
        let p = Pair::dual();
        let a: Arc<dyn NetStack> = Arc::new(p.a.clone());
        let b: Arc<dyn NetStack> = Arc::new(p.b.clone());
        exercise_udp(&*a, &*b);
        exercise_udp(&a, &b); // Arc<dyn NetStack> is itself a NetStack
        let moved = Arc::clone(&a);
        let t = thread::spawn(move || moved.bind_udp(0).map(|s| s.local_addr().port()));
        assert_ne!(t.join().unwrap().unwrap(), 0);
    }

    #[test]
    fn tunnel_resolve_uses_the_tunnel_dns_and_ip_literals_skip_it() {
        let p = Pair::dual();
        let server = DnsServer::start(&p.b, vec![IpAddr::V6(ANS_V6), IpAddr::V4(ANS_V4)], 0);
        let stack: &dyn NetStack = &p.a;
        assert_eq!(stack.resolve(HOST, WAIT).unwrap(), vec![IpAddr::V6(ANS_V6), IpAddr::V4(ANS_V4)]);
        assert_eq!(stack.resolve("[2001:db8::7]", WAIT).unwrap(), vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))]);
        assert_eq!(stack.resolve("192.0.2.9", WAIT).unwrap(), vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))]);
        let seen = server.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "only the host name reached the DNS server: {seen:?}");
        assert_eq!(stack.resolve("a..b", WAIT).unwrap_err().kind(), ErrorKind::InvalidInput);
        // A silent server: our timeout, mapped to TimedOut.
        drop(server);
        let e = stack.resolve("other.example.test", Duration::from_millis(200)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut, "{e}");
    }

    #[test]
    fn tunnel_tcp_is_unsupported_for_now() {
        let p = Pair::dual();
        let stack: &dyn NetStack = &p.a;
        let remote = SocketAddr::new(p.b.local_addrs()[0], 5060);
        let e = stack.connect_tcp(remote, WAIT).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        assert_eq!(e.to_string(), TUNNEL_TCP_UNSUPPORTED);
        assert_eq!(stack.listen_tcp(0).unwrap_err().kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn tunnel_socket_reports_not_connected_after_close() {
        let p = Pair::dual();
        let stack: &dyn NetStack = &p.a;
        let s = stack.bind_udp(0).unwrap();
        p.a.close("tunnel torn down");
        let e = s.recv_timeout(Duration::from_millis(10)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotConnected, "{e}");
        assert!(e.to_string().contains("tunnel torn down"), "{e}");
        let e = s.send_to(SocketAddr::new(p.b.local_addrs()[0], 1), b"x").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotConnected, "{e}");
        assert_eq!(stack.bind_udp(0).unwrap_err().kind(), ErrorKind::NotConnected);
        assert_eq!(stack.resolve(HOST, WAIT).unwrap_err().kind(), ErrorKind::NotConnected);
    }
}
