//! [`InnerStack`] — the smoltcp inner IP stack over ESP and its single owner thread
//! (DESIGN.md §11).
//!
//! `Interface`, `SocketSet` and [`EspDevice`] are `!Sync`, so they live behind one
//! `Mutex` (+ `Condvar`) and are *driven* by exactly one thread, the stack thread
//! (`epdg-stack`, [`InnerStack::run`]):
//!
//! ```text
//! loop { lock; for each queued packet { iface.poll_ingress_single(); drain UDP sockets ->
//!        per-binding channels; complete DNS queries -> waiters }; iface.poll_egress();
//!        delay = iface.poll_delay(); condvar.wait_timeout(delay) }
//! ```
//!
//! Ingress is drained packet by packet: a smoltcp UDP socket holds only
//! `UDP_SOCKET_PACKETS` datagrams, far fewer than the device queue, so draining once per
//! poll would lose the rest of a burst inside smoltcp (uncounted).
//!
//! Everyone else holds the lock only to enqueue or dequeue, then notifies the condvar:
//! the ESP rx thread pushes decapsulated packets ([`InnerStack::push_rx`]),
//! [`InnerUdpSocket::send_to`] queues a datagram on its smoltcp socket,
//! [`InnerStack::bind_udp`] adds a socket, [`InnerStack::resolve`] starts DNS queries
//! and then waits on a per-query slot (its own mutex/condvar, not the stack lock).
//! Receives never touch the stack lock: each binding has a bounded `sync_channel`
//! filled by the stack thread. All queues are bounded and every drop is counted.
//!
//! TCP (DESIGN.md §11.2): [`InnerStack::connect_tcp`], [`InnerStack::listen_tcp`],
//! [`InnerTcpStream`] and [`InnerTcpListener`] are blocking adapters over smoltcp TCP
//! sockets in the same `SocketSet`. A call takes the stack lock only to move bytes in or
//! out of its socket's buffers (or to look at its state) and otherwise parks on the
//! stack's TCP event counter — its own mutex/condvar, bumped by the stack thread after
//! every poll that moved packets while TCP sockets exist, and by `close`. A listener is a
//! small backlog of listening sockets (smoltcp has no accept queue); the stack thread
//! frees the sockets of dropped streams once their close handshake is over.
//!
//! Lock rule for the TX sink: it runs on the stack thread *with the stack lock held*
//! (inside `Interface::poll`), so it must only do things that never wait on the ESP rx
//! thread — a UDP send is fine, taking another stack's lock is not (see the loopback
//! test harness, which forwards through a channel for exactly that reason).
//!
//! smoltcp 0.14 facts this module relies on (verified in the crate source):
//! - `Medium::Ip` needs no neighbour discovery, but a matching route is still
//!   REQUIRED: `has_neighbor` is true only when `route()` finds one, so without the
//!   default routes an off-prefix datagram would sit in its socket forever. Only the
//!   next-hop value is nominal (tested below).
//! - IPv4 packets larger than the MTU are fragmented (`proto-ipv4-fragmentation`) up to
//!   `FRAGMENTATION_BUFFER_SIZE`, and inbound IPv4 fragments are reassembled up to
//!   `REASSEMBLY_BUFFER_SIZE`. **IPv6 fragmentation is not implemented for `Medium::Ip`**
//!   (the `proto-ipv6-fragmentation` feature only covers 6LoWPAN): an oversize IPv6
//!   packet is dropped by smoltcp and an inbound IPv6 Fragment header is answered with
//!   an ICMPv6 Parameter Problem. Hence the shim of DESIGN.md §11.1: smoltcp sees the
//!   *stack* MTU (`child.inner_mtu_stack`, 16384 by default) so it never refuses a large
//!   datagram, the device splits what it emits to the *wire* MTU (`child.inner_mtu`,
//!   1280) and [`InnerStack::push_rx`] reassembles inbound IPv6 fragment sets
//!   ([`super::frag`]). `send_to` caps payloads at `inner_mtu_stack - 48/-28`.
//! - The DNS socket keeps at most `DNS_MAX_SERVER_COUNT` servers and returns at most
//!   `DNS_MAX_RESULT_COUNT` addresses per query (both raised via Cargo features), and
//!   gives up on a silent server after its private 10 s retransmit timeout (see
//!   [`SMOLTCP_DNS_RETRANSMIT_TIMEOUT`]).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use log::{debug, info, trace, warn};
use smoltcp::iface::{Config as IfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, State as TcpState};
use smoltcp::socket::{dns, udp};
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use super::device::{DEFAULT_RX_QUEUE_DEPTH, DeviceStats, EspDevice, TxSink};
use super::frag::{Ipv6Reassembler, ReassemblyStats, tcp_connection_request};
use crate::ike::session::AssignedConfig;
use crate::{Error, Result};

/// Lowest port handed out by `bind_udp(0)`, `listen_tcp(0)` and to outbound TCP
/// connections (IANA dynamic range; UDP and TCP ports are allocated independently).
pub const EPHEMERAL_PORT_LO: u16 = 49152;
/// Highest ephemeral port.
pub const EPHEMERAL_PORT_HI: u16 = 65535;
/// Smallest accepted inner MTU (the IPv6 minimum link MTU, RFC 8200 §5).
pub const MIN_INNER_MTU: usize = 1280;
/// Largest accepted inner MTU (maximum IP packet).
pub const MAX_INNER_MTU: usize = 65_535;
/// smoltcp 0.14's private `dns::RETRANSMIT_TIMEOUT`: after this long without an answer
/// it moves to the next server, and reports `Failed` once every server timed out — so a
/// `Failed` that arrives `servers x` this late means silence, not a negative answer.
pub const SMOLTCP_DNS_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-binding receive queue depth (datagrams); beyond it the newest datagram is dropped.
pub const UDP_QUEUE_DEPTH: usize = 256;
/// smoltcp-side packet slots per UDP socket direction (drained on every poll).
const UDP_SOCKET_PACKETS: usize = 32;
/// smoltcp-side payload ring per UDP socket direction (must hold the largest datagram).
const UDP_SOCKET_BYTES: usize = 64 * 1024;
/// IPv4 fragment reassembly timeout.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest the stack thread sleeps without an event (bounds stop latency).
const MAX_IDLE_WAIT: Duration = Duration::from_millis(500);
/// Consecutive zero-delay polls before the stack thread yields for a millisecond.
const MAX_IMMEDIATE_POLLS: u32 = 64;
const IPV4_UDP_OVERHEAD: usize = 20 + 8;
const IPV6_UDP_OVERHEAD: usize = 40 + 8;
/// smoltcp receive and transmit buffer of every inner TCP socket, per direction (§11.2).
/// It bounds the advertised window (below 64 KiB, so no window scaling is needed) and
/// what one `write` can queue: a larger message — a 64 KiB SIP NOTIFY, say — goes out in
/// pieces as the peer acknowledges.
pub const TCP_BUFFER_BYTES: usize = 32 * 1024;
/// Listening sockets per inner TCP listener (§11.2). smoltcp has no accept queue — a
/// socket in LISTEN takes exactly one connection — so a listener keeps this many, each
/// either listening or holding a connection `accept_timeout` has not handed out yet; a
/// SYN that arrives while all of them are taken is answered with RST.
pub const TCP_LISTEN_BACKLOG: usize = 2;
/// How long the socket of a dropped [`InnerTcpStream`] may take to finish its close
/// handshake — FIN-WAIT-2 on a peer that never sends its FIN, LAST-ACK on one that never
/// acknowledges ours, neither of which smoltcp times out — before it is reset and freed.
pub const TCP_ORPHAN_LINGER: Duration = Duration::from_secs(60);
/// smoltcp socket timeout of a listener's backlog slots (§11.2): a slot resets (RST) a
/// connection whose peer has been silent this long before `accept_timeout` took it — a
/// handshake whose final ACK never came, or a connection nobody accepts — and goes back
/// to LISTEN, so neither can occupy the backlog for good. Cleared on accept.
const TCP_BACKLOG_TIMEOUT: Duration = Duration::from_secs(30);

/// Lock a mutex, recovering from poisoning (a panicked thread must not take the
/// whole stack down with it).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One UDP datagram received inside the tunnel. `dst` is our inner address + port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Counters of the inner stack (device queue, UDP delivery, DNS, TCP).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackStats {
    /// Inner IP packets pushed into the device by the ESP rx thread.
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Packets evicted from the device receive queue (oldest first) because it was full.
    pub rx_queue_drops: u64,
    /// Inner IP packets handed to the TX sink (ESP) successfully.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// TX sink failures (packet dropped).
    pub tx_errors: u64,
    /// IP packets split into wire-sized fragments on the way out (§11.1).
    pub tx_fragmented: u64,
    /// IP packets above the wire MTU that could not be fragmented (dropped).
    pub tx_frag_drops: u64,
    /// Inbound IPv6 fragments seen by the reassembler.
    pub rx_fragments: u64,
    /// Inbound IPv6 packets rebuilt from fragments.
    pub rx_reassembled: u64,
    /// Inbound IPv6 fragment sets discarded (malformed, overlapping, timed out, evicted).
    pub rx_reassembly_drops: u64,
    /// UDP datagrams delivered to a binding's channel.
    pub udp_delivered: u64,
    /// UDP datagrams dropped because the binding's channel was full.
    pub udp_queue_drops: u64,
    /// `send_to` calls refused because the socket's send buffer was full.
    pub udp_send_full: u64,
    /// Datagrams accepted by `send_to` but discarded because the socket was closed
    /// before they could be transmitted (should stay 0: `Drop` flushes first).
    pub udp_tx_drops: u64,
    /// DNS queries started (`resolve` issues one per address family).
    pub dns_queries: u64,
    /// Currently bound inner UDP ports.
    pub udp_bindings: u64,
    /// Outbound TCP connections established by `connect_tcp`.
    pub tcp_connections_opened: u64,
    /// TCP connections handed out by `accept_timeout`.
    pub tcp_accepted: u64,
    /// Bytes TCP `write`s queued for transmission.
    pub tcp_tx_bytes: u64,
    /// Bytes TCP `read`s returned.
    pub tcp_rx_bytes: u64,
    /// smoltcp TCP sockets currently allocated: streams, listener backlog slots, and the
    /// sockets of dropped streams still finishing their close handshake.
    pub tcp_sockets: u64,
    /// Retransmitted SYNs for a connection the stack already holds, dropped before a
    /// listening socket could take them for a new one (§11.2).
    pub tcp_dup_syn_drops: u64,
    /// TCP SYNs (ours or the peer's) whose MSS option was lowered to fit the wire MTU
    /// (§11.2).
    pub tcp_mss_clamped: u64,
}

/// A UDP "socket" inside the tunnel, bound to one inner port on every inner address.
/// Sends go through the smoltcp stack (source address chosen by smoltcp), receives
/// come from the stack thread through a bounded channel. `Send + Sync`: one thread can
/// block in `recv_timeout` while others `send_to` on the same handle. Dropping it
/// flushes what `send_to` accepted, then unbinds the port.
pub struct InnerUdpSocket {
    port: u16,
    /// Locked only inside `recv_timeout` (the receiver itself is `!Sync`).
    rx: Mutex<Receiver<UdpDatagram>>,
    stack: InnerStack,
}

/// A TCP connection inside the tunnel (§11.2): opened by [`InnerStack::connect_tcp`] or
/// handed out by [`InnerTcpListener::accept_timeout`]. Its smoltcp socket lives in the
/// stack's `SocketSet` and is driven by the stack thread; the methods here only move bytes
/// in and out of the socket's buffers under the stack lock and park on the stack's TCP
/// event counter in between (never on the stack lock, so a close wakes them at once —
/// DESIGN §17.6). `Send + Sync` and `&self` throughout: one thread may block in `read`
/// while another writes. Dropping it closes the connection gracefully (FIN); the stack
/// thread frees the socket once the close handshake is over.
pub struct InnerTcpStream {
    stack: InnerStack,
    /// Key of the connection in `State::tcp`.
    id: u64,
    local: SocketAddr,
    peer: SocketAddr,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    /// `shutdown` was called: reads return EOF and writes fail with `BrokenPipe`, as
    /// after `shutdown(Both)` on an OS socket.
    shut: AtomicBool,
}

/// A TCP listener inside the tunnel on one inner port, every inner address (§11.2):
/// [`TCP_LISTEN_BACKLOG`] smoltcp listening sockets, refilled as connections are
/// accepted. Dropping it removes the listening sockets and resets the connections nobody
/// accepted.
pub struct InnerTcpListener {
    stack: InnerStack,
    port: u16,
    /// Tells this listener apart from a later one on the same port.
    id: u64,
    local: SocketAddr,
}

/// Handle to the inner stack; cheap to clone (`Arc`). See the module docs.
#[derive(Clone)]
pub struct InnerStack {
    shared: Arc<StackShared>,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct StackShared {
    state: Mutex<State>,
    cv: Condvar,
    stop: AtomicBool,
    /// `Some(reason)` once the stack has been closed.
    ///
    /// Deliberately NOT inside `State`: the stack thread holds that mutex across a whole
    /// `poll`, which drives the device's TX sink and therefore a BLOCKING outer ESP send
    /// (up to the socket's write timeout, per packet). A close that had to wait for it
    /// could not publish the death, let alone wake the parked receivers, for seconds —
    /// while `mark_dead` promises the opposite (DESIGN §17.6).
    closed: Mutex<Option<String>>,
    /// Everything a close must fail immediately, for the same reason: the senders whose
    /// drop wakes a blocked [`InnerUdpSocket::recv_timeout`], and the completion slots of
    /// in-flight DNS queries.
    wakers: Mutex<Wakers>,
    /// TCP wake-ups (§11.2): a generation counter, bumped by the stack thread after every
    /// poll that moved packets while TCP sockets exist, by `close` and by a stream's
    /// `shutdown`. A blocked TCP call parks on `tcp_cv` with THIS lock and never with
    /// `state`, for the reason `closed` lives outside `state`: a close must wake it while
    /// the stack thread sits in a slow outer send, and the woken call must be able to
    /// return without waiting for that poll to finish.
    tcp_events: Mutex<u64>,
    tcp_cv: Condvar,
    /// Monotonic origin of smoltcp's clock.
    epoch: Instant,
}

#[derive(Default)]
struct Wakers {
    udp: HashMap<u16, SyncSender<UdpDatagram>>,
    dns: Vec<Arc<DnsSlot>>,
}

impl StackShared {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.epoch.elapsed().as_micros().min(i64::MAX as u128) as i64)
    }

    fn notify(&self) {
        self.cv.notify_all();
    }

    fn closed_error(&self) -> Option<Error> {
        lock(&self.closed).as_ref().map(|r| Error::Closed(r.clone()))
    }

    /// The current TCP event generation. A TCP call reads it BEFORE it looks at its
    /// socket, so an event that lands in between moves it and the park returns at once.
    fn tcp_generation(&self) -> u64 {
        *lock(&self.tcp_events)
    }

    /// Wake every parked TCP call: something may have changed for its socket.
    fn tcp_wake(&self) {
        {
            let mut generation = lock(&self.tcp_events);
            *generation = generation.wrapping_add(1);
        }
        self.tcp_cv.notify_all();
    }

    /// Park until the TCP event generation moves past `seen`; `false` once `deadline`
    /// (`None` = never) passes first.
    fn tcp_park(&self, seen: u64, deadline: Option<Instant>) -> bool {
        let mut generation = lock(&self.tcp_events);
        while *generation == seen {
            generation = match deadline {
                None => self.tcp_cv.wait(generation).unwrap_or_else(|e| e.into_inner()),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    self.tcp_cv.wait_timeout(generation, left).unwrap_or_else(|e| e.into_inner()).0
                }
            };
        }
        true
    }
}

struct UdpBinding {
    handle: SocketHandle,
}

/// Completion slot of one DNS query, waited on by `resolve` (own lock, not the stack's).
#[derive(Default)]
struct DnsSlot {
    result: Mutex<Option<Result<Vec<IpAddr>>>>,
    cv: Condvar,
}

impl DnsSlot {
    fn complete(&self, r: Result<Vec<IpAddr>>) {
        *lock(&self.result) = Some(r);
        self.cv.notify_all();
    }

    /// Wait for the result until `deadline`; `None` on expiry.
    fn wait_until(&self, deadline: Instant) -> Option<Result<Vec<IpAddr>>> {
        let mut g = lock(&self.result);
        loop {
            if let Some(r) = g.take() {
                return Some(r);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            g = self.cv.wait_timeout(g, remaining).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    fn take(&self) -> Option<Result<Vec<IpAddr>>> {
        lock(&self.result).take()
    }
}

/// Removes this call's DNS slots from [`StackShared::wakers`] however `resolve` returns.
struct DnsRegistration<'a> {
    shared: &'a StackShared,
    slots: &'a [Arc<DnsSlot>],
}

impl Drop for DnsRegistration<'_> {
    fn drop(&mut self) {
        let mut w = lock(&self.shared.wakers);
        w.dns.retain(|s| !self.slots.iter().any(|mine| Arc::ptr_eq(mine, s)));
    }
}

struct DnsWaiter {
    handle: dns::QueryHandle,
    slot: Arc<DnsSlot>,
    /// smoltcp time at which the query was started.
    started: smoltcp::time::Instant,
}

/// The smoltcp socket behind one [`InnerTcpStream`] (§11.2).
struct TcpConn {
    handle: SocketHandle,
    /// Local port (an accepted connection shares its listener's).
    port: u16,
    /// Opened by `connect_tcp`: its ephemeral port is not available to `listen_tcp`.
    outbound: bool,
    /// When the stream was dropped. The stack thread frees the socket once its close
    /// handshake is over, and resets it after [`TCP_ORPHAN_LINGER`].
    orphaned: Option<Instant>,
}

/// The listening sockets of one [`InnerTcpListener`] (§11.2).
struct TcpListen {
    /// Tells the listener apart from a later one on the same port.
    id: u64,
    /// [`TCP_LISTEN_BACKLOG`] sockets, each in LISTEN or holding a connection that has
    /// not been accepted yet.
    slots: Vec<SocketHandle>,
}

struct State {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: EspDevice,
    /// IPv6 fragment reassembly in front of the device (§11.1).
    reassembler: Ipv6Reassembler,
    dns: SocketHandle,
    udp: HashMap<u16, UdpBinding>,
    dns_waiters: Vec<DnsWaiter>,
    has_v4: bool,
    has_v6: bool,
    dns_servers: usize,
    udp_delivered: u64,
    udp_queue_drops: u64,
    udp_send_full: u64,
    udp_tx_drops: u64,
    dns_queries: u64,
    /// Inner TCP connections by stream id (§11.2).
    tcp: HashMap<u64, TcpConn>,
    /// Inner TCP listeners by local port.
    listeners: HashMap<u16, TcpListen>,
    /// Allocated smoltcp TCP sockets per local port — connections, backlog slots and
    /// orphans alike: the ephemeral port picker's view of the TCP port space.
    tcp_ports: HashMap<u16, usize>,
    /// Last id handed to a TCP stream or listener.
    tcp_ids: u64,
    tcp_connections_opened: u64,
    tcp_accepted: u64,
    tcp_tx_bytes: u64,
    tcp_rx_bytes: u64,
    tcp_dup_syn_drops: u64,
}

impl State {
    /// One stack-thread iteration: ingest the queued packets one at a time, moving what
    /// each one produced out to the waiting callers before the next (a smoltcp UDP
    /// socket only buffers `UDP_SOCKET_PACKETS` datagrams), then transmit, then the TCP
    /// housekeeping. Returns whether any packet was processed or sent — i.e. whether a TCP
    /// socket's state or buffers may have changed (§11.2).
    fn poll(&mut self, now: smoltcp::time::Instant, wakers: &Mutex<Wakers>) -> bool {
        self.iface.poll_maintenance(now);
        let mut moved = false;
        loop {
            match self.iface.poll_ingress_single(now, &mut self.device, &mut self.sockets) {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => {
                    moved = true;
                    self.drain(now, wakers);
                }
            }
        }
        while self.iface.poll_egress(now, &mut self.device, &mut self.sockets) == PollResult::SocketStateChanged {
            moved = true;
        }
        self.drain(now, wakers);
        if self.has_tcp() {
            self.tcp_housekeeping();
        }
        moved
    }

    fn has_tcp(&self) -> bool {
        !self.tcp.is_empty() || !self.listeners.is_empty()
    }

    fn next_tcp_id(&mut self) -> u64 {
        self.tcp_ids += 1;
        self.tcp_ids
    }

    /// The socket of stream `id`; `Error::Closed` once it is gone (after a close).
    fn tcp_socket(&mut self, id: u64) -> Result<&mut tcp::Socket<'static>> {
        let handle = self.tcp.get(&id).map(|c| c.handle).ok_or_else(|| Error::Closed("inner TCP connection is gone".into()))?;
        Ok(self.sockets.get_mut::<tcp::Socket>(handle))
    }

    /// Add one listening backlog slot on `port`.
    fn add_listen_slot(&mut self, port: u16) -> Result<SocketHandle> {
        let mut sock = new_tcp_socket();
        sock.set_timeout(Some(TCP_BACKLOG_TIMEOUT.into()));
        sock.listen(port).map_err(|e| Error::Config(format!("inner TCP listen on port {port}: {e}")))?;
        *self.tcp_ports.entry(port).or_default() += 1;
        Ok(self.sockets.add(sock))
    }

    /// Remove a TCP socket from the set and release its port.
    fn free_tcp_socket(&mut self, handle: SocketHandle, port: u16) {
        self.sockets.remove(handle);
        if let Some(n) = self.tcp_ports.get_mut(&port) {
            *n -= 1;
            if *n == 0 {
                self.tcp_ports.remove(&port);
            }
        }
    }

    /// Forget stream `id` and free its socket at once, sending nothing (a connect that
    /// failed or timed out: like an OS socket, the abandoned SYN gets no RST).
    fn abandon_tcp(&mut self, id: u64) {
        if let Some(c) = self.tcp.remove(&id) {
            self.free_tcp_socket(c.handle, c.port);
        }
    }

    /// The TCP half of every poll (§11.2): free the sockets of dropped streams whose
    /// close handshake is over — a socket is done once it is CLOSED with no 4-tuple left
    /// (TIME-WAIT expired, LAST-ACK acknowledged, reset, or its abort RST sent) — and
    /// reset the ones still lingering after [`TCP_ORPHAN_LINGER`]; put a backlog slot
    /// that smoltcp closed (its handshake timed out, or the connection was reset before
    /// anyone accepted it) back into LISTEN.
    fn tcp_housekeeping(&mut self) {
        let mut done = Vec::new();
        for (id, c) in &self.tcp {
            let Some(since) = c.orphaned else { continue };
            let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
            if s.state() == TcpState::Closed && s.remote_endpoint().is_none() {
                done.push(*id);
            } else if s.state() != TcpState::Closed && since.elapsed() >= TCP_ORPHAN_LINGER {
                debug!(
                    "inner TCP {:?} -> {:?}: close handshake unfinished after {TCP_ORPHAN_LINGER:?} ({}); resetting",
                    s.local_endpoint(),
                    s.remote_endpoint(),
                    s.state()
                );
                s.abort();
            }
        }
        for id in done {
            self.abandon_tcp(id);
        }
        for (port, l) in &self.listeners {
            for h in &l.slots {
                let s = self.sockets.get_mut::<tcp::Socket>(*h);
                if s.state() == TcpState::Closed && s.remote_endpoint().is_none() {
                    // A reset forgets the listen endpoint: listen again.
                    let _ = s.listen(*port);
                }
            }
        }
    }

    /// Take the first connection of listener `(port, id)` that completed its handshake
    /// (ESTABLISHED, or CLOSE-WAIT when the peer already sent everything and its FIN) and
    /// refill its backlog slot with a fresh listening socket. `None` while there is none.
    fn accept_pending(&mut self, port: u16, id: u64) -> Option<Result<(u64, SocketAddr, SocketAddr)>> {
        let Some(l) = self.listeners.get(&port).filter(|l| l.id == id) else {
            return Some(Err(Error::Closed(format!("inner TCP listener on port {port} is gone"))));
        };
        let (slot, handle) = l
            .slots
            .iter()
            .copied()
            .enumerate()
            .find(|(_, h)| matches!(self.sockets.get::<tcp::Socket>(*h).state(), TcpState::Established | TcpState::CloseWait))?;
        let fresh = match self.add_listen_slot(port) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };
        if let Some(l) = self.listeners.get_mut(&port) {
            l.slots[slot] = fresh;
        }
        let s = self.sockets.get_mut::<tcp::Socket>(handle);
        // The backlog's bound is not the connection's.
        s.set_timeout(None);
        let Some((local, peer)) = s.local_endpoint().zip(s.remote_endpoint()) else {
            // Unreachable in these states; reset it and let the reaper have the socket.
            s.abort();
            let stream = self.next_tcp_id();
            self.tcp.insert(stream, TcpConn { handle, port, outbound: false, orphaned: Some(Instant::now()) });
            return Some(Err(Error::Protocol(format!("inner TCP port {port}: accepted socket has no endpoints"))));
        };
        let stream = self.next_tcp_id();
        self.tcp.insert(stream, TcpConn { handle, port, outbound: false, orphaned: None });
        self.tcp_accepted += 1;
        Some(Ok((stream, SocketAddr::from(local), SocketAddr::from(peer))))
    }

    /// Is `packet` a retransmitted SYN for a connection the stack already holds (§11.2)?
    /// smoltcp gives each segment to the FIRST socket that accepts it, and a socket in
    /// LISTEN accepts any SYN to its port. Were a listening backlog slot to come before
    /// the connection's own socket in the `SocketSet`, it would answer the duplicate with
    /// a second SYN-ACK (another ISN), and the peer's next ACK — matching both sockets'
    /// 4-tuple — could be answered with RST. The connection's socket ignores a SYN in a
    /// synchronized state (its SYN-ACK is retransmitted on its own timer), so dropping the
    /// duplicate here is what would happen in the right order anyway. Only consulted while
    /// a listener exists.
    fn is_duplicate_syn(&self, packet: &[u8]) -> bool {
        if self.listeners.is_empty() {
            return false;
        }
        let Some((src, dst)) = tcp_connection_request(packet) else {
            return false;
        };
        let (local, remote) = (IpEndpoint::from(dst), IpEndpoint::from(src));
        let mut handles = self.tcp.values().map(|c| c.handle).chain(self.listeners.values().flat_map(|l| l.slots.iter().copied()));
        handles.any(|h| {
            let s = self.sockets.get::<tcp::Socket>(h);
            // A SYN-SENT socket takes a SYN as a simultaneous open.
            !matches!(s.state(), TcpState::Listen | TcpState::Closed | TcpState::SynSent)
                && s.local_endpoint() == Some(local)
                && s.remote_endpoint() == Some(remote)
        })
    }

    /// Move everything smoltcp's sockets hold out to the callers. `wakers` holds the
    /// per-port senders (see [`StackShared::wakers`]).
    fn drain(&mut self, now: smoltcp::time::Instant, wakers: &Mutex<Wakers>) {
        let State { sockets, dns, udp, dns_waiters, dns_servers, udp_delivered, udp_queue_drops, .. } = self;

        // UDP: smoltcp socket rx buffers -> per-binding channels.
        let mut disconnected = Vec::new();
        let senders = lock(wakers);
        for (port, binding) in udp.iter() {
            let Some(tx) = senders.udp.get(port) else {
                disconnected.push(*port);
                continue;
            };
            let sock = sockets.get_mut::<udp::Socket>(binding.handle);
            while let Ok((payload, meta)) = sock.recv() {
                let src = SocketAddr::from(meta.endpoint);
                let dst_ip = meta.local_address.map(IpAddr::from).unwrap_or(match src.ip() {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                });
                let dg = UdpDatagram { src, dst: SocketAddr::new(dst_ip, *port), payload: payload.to_vec() };
                trace!("inner UDP rx {} -> {} ({} bytes)", dg.src, dg.dst, dg.payload.len());
                match tx.try_send(dg) {
                    Ok(()) => *udp_delivered += 1,
                    Err(TrySendError::Full(_)) => {
                        *udp_queue_drops += 1;
                        debug!("inner UDP port {port}: receive queue full; datagram dropped");
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        disconnected.push(*port);
                        break;
                    }
                }
            }
        }
        drop(senders);
        for port in disconnected {
            if let Some(b) = udp.remove(&port) {
                sockets.remove(b.handle);
                debug!("inner UDP port {port}: receiver gone; unbound");
            }
        }

        // DNS: finished queries -> their waiters.
        let dns_sock = sockets.get_mut::<dns::Socket>(*dns);
        dns_waiters.retain(|w| match dns_sock.get_query_result(w.handle) {
            Err(dns::GetQueryResultError::Pending) => true,
            Ok(addrs) => {
                w.slot.complete(Ok(addrs.iter().map(|a| IpAddr::from(*a)).collect()));
                false
            }
            Err(dns::GetQueryResultError::Failed) => {
                // smoltcp reports silence the same way as a negative answer, but only
                // after every server's retransmit timeout has elapsed.
                let give_up = smoltcp::time::Duration::from(SMOLTCP_DNS_RETRANSMIT_TIMEOUT) * (*dns_servers as u32).max(1);
                w.slot.complete(Err(if now - w.started >= give_up {
                    Error::Timeout("DNS response")
                } else {
                    Error::Protocol("DNS query failed (no answer of that type, NXDOMAIN or server failure)".into())
                }));
                false
            }
        });
    }

    /// Cancel every query and remove every smoltcp socket. The waiters and receivers have
    /// already been failed by [`InnerStack::close`], which does not need this mutex.
    /// Idempotent.
    fn shutdown(&mut self, reason: &str) {
        let State { sockets, dns, udp, dns_waiters, tcp: conns, listeners, tcp_ports, .. } = self;
        let dns_sock = sockets.get_mut::<dns::Socket>(*dns);
        for w in dns_waiters.drain(..) {
            dns_sock.cancel_query(w.handle);
            w.slot.complete(Err(Error::Closed(reason.to_string())));
        }
        for (_, b) in udp.drain() {
            sockets.remove(b.handle);
        }
        // Nothing can be sent any more: the TCP sockets just go. Their adapters fail with
        // `Error::Closed` from `StackShared::closed`, never touching a removed handle.
        for (_, c) in conns.drain() {
            sockets.remove(c.handle);
        }
        for (_, l) in listeners.drain() {
            for h in l.slots {
                sockets.remove(h);
            }
        }
        tcp_ports.clear();
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------

/// Pick a free inner port in `49152..=65535`, scanning upward from `start` and
/// wrapping around; `None` when every port is in use. (UDP bindings and TCP sockets
/// keep separate maps: the two port spaces are independent.)
fn pick_free_port<V>(used: &HashMap<u16, V>, start: u16) -> Option<u16> {
    let range = u32::from(EPHEMERAL_PORT_HI - EPHEMERAL_PORT_LO) + 1;
    let start = start.clamp(EPHEMERAL_PORT_LO, EPHEMERAL_PORT_HI);
    let offset = u32::from(start - EPHEMERAL_PORT_LO);
    (0..range)
        .map(|i| EPHEMERAL_PORT_LO + ((offset + i) % range) as u16)
        .find(|p| !used.contains_key(p))
}

/// Largest UDP payload the stack can carry to a destination of the given family, given
/// the MTU smoltcp sees (`child.inner_mtu_stack`): IPv4 is additionally fragmented by
/// smoltcp up to its fragmentation buffer, IPv6 must fit one stack-MTU packet (the
/// device then splits it to the wire MTU, §11.1).
pub fn max_udp_payload(mtu: usize, ipv4: bool) -> usize {
    if ipv4 {
        smoltcp::config::FRAGMENTATION_BUFFER_SIZE.max(mtu).saturating_sub(IPV4_UDP_OVERHEAD)
    } else {
        mtu.saturating_sub(IPV6_UDP_OVERHEAD)
    }
}

/// A random starting point for [`pick_free_port`] (RFC 6056: no predictable ports).
fn random_ephemeral_start() -> u16 {
    EPHEMERAL_PORT_LO + (rand::random::<u16>() % (EPHEMERAL_PORT_HI - EPHEMERAL_PORT_LO + 1))
}

/// Clamp a configured inner MTU into `[MIN_INNER_MTU, MAX_INNER_MTU]`.
fn effective_mtu(inner_mtu: usize) -> usize {
    inner_mtu.clamp(MIN_INNER_MTU, MAX_INNER_MTU)
}

fn udp_buffer() -> udp::PacketBuffer<'static> {
    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_PACKETS], vec![0u8; UDP_SOCKET_BYTES])
}

/// A fresh smoltcp TCP socket with [`TCP_BUFFER_BYTES`] each way. smoltcp's defaults
/// otherwise: Nagle on (like an OS socket; `set_nodelay` turns it off), 10 ms delayed
/// ACK, no keep-alive, no timeout.
fn new_tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]), tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]))
}

// ---------------------------------------------------------------------------
// InnerStack
// ---------------------------------------------------------------------------

impl InnerStack {
    /// Build the interface from the gateway-assigned configuration: every inner IPv6
    /// address with its prefix and every inner IPv4 address as /32, default routes
    /// (next hop = first DNS server of the family, else the inner address itself), DNS
    /// servers of the families we have an address for. `inner_mtu` is the wire MTU
    /// (clamped to `[1280, 65535]`), `inner_mtu_stack` the MTU smoltcp sees (raised to
    /// at least the wire MTU, §11.1). Nothing runs until [`InnerStack::run`] /
    /// [`InnerStack::spawn`].
    pub fn new(assigned: &AssignedConfig, sink: TxSink, inner_mtu: usize, inner_mtu_stack: usize) -> Result<InnerStack> {
        let mtu = effective_mtu(inner_mtu);
        if mtu != inner_mtu {
            warn!("inner MTU {inner_mtu} clamped to {mtu}");
        }
        let stack_mtu = inner_mtu_stack.clamp(mtu, MAX_INNER_MTU);
        if stack_mtu != inner_mtu_stack {
            warn!("inner stack MTU {inner_mtu_stack} clamped to {stack_mtu}");
        }
        let epoch = Instant::now();
        let mut device = EspDevice::new(sink, mtu, stack_mtu, DEFAULT_RX_QUEUE_DEPTH);
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::from_micros(0i64));
        iface.set_reassembly_timeout(REASSEMBLY_TIMEOUT.into());

        // Addresses (smoltcp panics on non-unicast addresses, so filter first).
        let mut v6: Vec<Ipv6Addr> = Vec::new();
        let mut v4: Vec<Ipv4Addr> = Vec::new();
        let mut cidrs: Vec<IpCidr> = Vec::new();
        for (addr, prefix) in &assigned.internal_ipv6 {
            let ip = IpAddress::Ipv6(*addr);
            if !ip.is_unicast() {
                warn!("ignoring non-unicast inner IPv6 address {addr}");
                continue;
            }
            cidrs.push(IpCidr::new(ip, (*prefix).min(128)));
            v6.push(*addr);
        }
        for addr in &assigned.internal_ipv4 {
            let ip = IpAddress::Ipv4(*addr);
            if !ip.is_unicast() {
                warn!("ignoring non-unicast inner IPv4 address {addr}");
                continue;
            }
            cidrs.push(IpCidr::new(ip, 32));
            v4.push(*addr);
        }
        let mut installed = 0usize;
        iface.update_ip_addrs(|addrs| {
            for cidr in cidrs {
                if addrs.push(cidr).is_err() {
                    warn!(
                        "inner interface holds at most {} addresses; {cidr} not installed",
                        smoltcp::config::IFACE_MAX_ADDR_COUNT
                    );
                    break;
                }
                installed += 1;
            }
        });
        let has_v6 = iface.ip_addrs().iter().any(|c| matches!(c, IpCidr::Ipv6(_)));
        let has_v4 = iface.ip_addrs().iter().any(|c| matches!(c, IpCidr::Ipv4(_)));

        // Default routes: required for off-prefix delivery (smoltcp's `has_neighbor`
        // needs a route); only the next hop is nominal (no ND/ARP on Medium::Ip).
        if has_v6 {
            let gw = assigned.dns_ipv6.first().copied().or(v6.first().copied()).unwrap_or(Ipv6Addr::UNSPECIFIED);
            iface.routes_mut().add_default_ipv6_route(gw).map_err(|e| Error::Config(format!("inner IPv6 route: {e:?}")))?;
        }
        if has_v4 {
            let gw = assigned.dns_ipv4.first().copied().or(v4.first().copied()).unwrap_or(Ipv4Addr::UNSPECIFIED);
            iface.routes_mut().add_default_ipv4_route(gw).map_err(|e| Error::Config(format!("inner IPv4 route: {e:?}")))?;
        }

        // DNS servers of the families we can reach (smoltcp fails every query sent to a
        // non-unicast server, so those are skipped); smoltcp keeps the first DNS_MAX_SERVER_COUNT.
        let mut servers: Vec<IpAddress> = Vec::new();
        if has_v6 {
            servers.extend(assigned.dns_ipv6.iter().map(|a| IpAddress::Ipv6(*a)));
        }
        if has_v4 {
            servers.extend(assigned.dns_ipv4.iter().map(|a| IpAddress::Ipv4(*a)));
        }
        servers.retain(|s| {
            if s.is_unicast() {
                true
            } else {
                warn!("ignoring non-unicast inner DNS server {s}");
                false
            }
        });
        if servers.len() > smoltcp::config::DNS_MAX_SERVER_COUNT {
            warn!(
                "{} inner DNS servers assigned; keeping the first {}",
                servers.len(),
                smoltcp::config::DNS_MAX_SERVER_COUNT
            );
            servers.truncate(smoltcp::config::DNS_MAX_SERVER_COUNT);
        }
        let mut sockets = SocketSet::new(vec![]);
        let dns = sockets.add(dns::Socket::new(&servers, vec![]));

        info!(
            "inner stack: wire mtu {mtu}, stack mtu {stack_mtu}, addresses {:?}, dns {:?}, smoltcp ipv4 fragmentation up to {} bytes",
            iface.ip_addrs(),
            servers,
            smoltcp::config::FRAGMENTATION_BUFFER_SIZE
        );
        if installed == 0 {
            warn!("inner stack has no address: sends will fail until one is assigned");
        }

        Ok(InnerStack {
            shared: Arc::new(StackShared {
                closed: Mutex::new(None),
                wakers: Mutex::new(Wakers::default()),
                state: Mutex::new(State {
                    iface,
                    sockets,
                    device,
                    reassembler: Ipv6Reassembler::default(),
                    dns,
                    udp: HashMap::new(),
                    dns_waiters: Vec::new(),
                    has_v4,
                    has_v6,
                    dns_servers: servers.len(),
                    udp_delivered: 0,
                    udp_queue_drops: 0,
                    udp_send_full: 0,
                    udp_tx_drops: 0,
                    dns_queries: 0,
                    tcp: HashMap::new(),
                    listeners: HashMap::new(),
                    tcp_ports: HashMap::new(),
                    tcp_ids: 0,
                    tcp_connections_opened: 0,
                    tcp_accepted: 0,
                    tcp_tx_bytes: 0,
                    tcp_rx_bytes: 0,
                    tcp_dup_syn_drops: 0,
                }),
                cv: Condvar::new(),
                tcp_events: Mutex::new(0),
                tcp_cv: Condvar::new(),
                stop: AtomicBool::new(false),
                epoch,
            }),
        })
    }

    /// Spawn the stack thread (`epdg-stack`) running [`InnerStack::run`]. Should the
    /// thread panic, the stack is closed (every pending and later operation fails with
    /// `Error::Closed`) instead of stranding its waiters.
    pub fn spawn(&self) -> Result<JoinHandle<()>> {
        let stack = self.clone();
        thread::Builder::new()
            .name("epdg-stack".into())
            .spawn(move || {
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stack.run())) {
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    warn!("stack thread panicked: {msg}");
                    stack.close(format!("stack thread panicked: {msg}"));
                }
            })
            .map_err(Error::Io)
    }

    /// The stack thread body: poll, hand results out, sleep until the next smoltcp
    /// deadline or an external event. Returns after [`InnerStack::stop`] / `close`.
    pub fn run(&self) {
        let sh = &*self.shared;
        let mut st = lock(&sh.state);
        let mut immediate = 0u32;
        while !sh.stop.load(Ordering::SeqCst) {
            let now = sh.now();
            if st.poll(now, &sh.wakers) && st.has_tcp() {
                // TCP calls park on their own event counter, not on this lock (§11.2):
                // tell them their socket may have changed.
                sh.tcp_wake();
            }
            let delay = {
                let s = &mut *st;
                s.iface.poll_delay(now, &s.sockets)
            };
            let wait = match delay {
                Some(d) if d.total_micros() == 0 => {
                    immediate += 1;
                    if immediate < MAX_IMMEDIATE_POLLS {
                        // Release `state` between re-polls. Every packet a poll emits
                        // runs the outer ESP send synchronously under this mutex, and a
                        // send that a host firewall holds pending a verdict blocks for
                        // [`crate::ike::transport::OUTER_SEND_TIMEOUT`]. Carrying the
                        // guard across up to MAX_IMMEDIATE_POLLS polls would stack those
                        // holds while `push_rx` (the thread that also delivers IKE
                        // responses), `bind_udp`, `send_to` and `close`'s smoltcp
                        // cleanup all wait on it (DESIGN §17.6).
                        drop(st);
                        std::thread::yield_now();
                        st = lock(&sh.state);
                        continue;
                    }
                    debug!("stack: {immediate} immediate re-polls in a row; yielding");
                    Duration::from_millis(1)
                }
                Some(d) => Duration::from(d).min(MAX_IDLE_WAIT),
                None => MAX_IDLE_WAIT,
            };
            immediate = 0;
            st = sh.cv.wait_timeout(st, wait).unwrap_or_else(|e| e.into_inner()).0;
        }
        drop(st);
        // Whatever ended the loop, everything that could be waiting must fail.
        self.close("inner stack stopped");
        debug!("stack thread stopped");
    }

    /// Stop the stack thread and fail every pending operation with `Error::Closed`.
    pub fn stop(&self) {
        self.close("inner stack stopped");
    }

    /// Like [`InnerStack::stop`] with a reason that later callers see in `Error::Closed`.
    ///
    /// Nothing here waits for the stack thread's `state` mutex first: that mutex is held
    /// across a whole poll, which can block in an outer ESP send for the socket's write
    /// timeout, and the promise `mark_dead` makes is that a blocked receiver fails
    /// IMMEDIATELY (DESIGN §17.6). So the reason is published, the UDP senders are dropped
    /// (which is what wakes a parked `recv_timeout`), the DNS waiters are completed and the
    /// TCP event counter is moved (which wakes a parked TCP read / write / accept /
    /// connect) — all under their own short-lived locks — and only then does the
    /// smoltcp-side cleanup take `state` and wait for the poll in progress.
    ///
    /// The reason is published BEFORE `stop`: setting `stop` first is a race in which the
    /// stack thread leaves its loop and closes with its own generic reason, losing the
    /// tunnel's dead reason that every inner socket and the SIP transport's exit log
    /// report. Idempotent, and the first reason wins.
    pub fn close(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let reason = {
            let mut slot = lock(&self.shared.closed);
            slot.get_or_insert(reason).clone()
        };
        {
            let mut w = lock(&self.shared.wakers);
            // Dropping the senders disconnects every receive channel: a thread parked in
            // `InnerUdpSocket::recv_timeout` returns at once with `Error::Closed`.
            w.udp.clear();
            for slot in w.dns.drain(..) {
                slot.complete(Err(Error::Closed(reason.clone())));
            }
        }
        // A blocked TCP call parks on the TCP event counter (§11.2): moving it makes the
        // call look at `closed` again, which it reads without `state` either.
        self.shared.tcp_wake();
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.notify();
        lock(&self.shared.state).shutdown(&reason);
    }

    pub fn is_closed(&self) -> bool {
        self.shared.stop.load(Ordering::SeqCst) || lock(&self.shared.closed).is_some()
    }

    /// Queue one decapsulated inner IP packet (from the ESP rx thread) and wake the
    /// stack thread. IPv6 fragments are held by the reassembler until their set is
    /// complete (§11.1); a retransmitted SYN for a TCP connection the stack already holds
    /// is dropped (§11.2). Never blocks for long: the device queue is bounded
    /// (drop-oldest).
    pub fn push_rx(&self, packet: Vec<u8>) {
        {
            if self.shared.closed_error().is_some() {
                return;
            }
            let mut st = lock(&self.shared.state);
            let Some(packet) = st.reassembler.push(packet, Instant::now()) else {
                return;
            };
            if st.is_duplicate_syn(&packet) {
                st.tcp_dup_syn_drops += 1;
                debug!("inner TCP: retransmitted SYN for an existing connection dropped");
                return;
            }
            st.device.push_rx(packet);
        }
        self.shared.notify();
    }

    /// Bind an inner UDP port on every inner address. `port == 0` picks a free port
    /// in `49152..=65535`.
    pub fn bind_udp(&self, port: u16) -> Result<InnerUdpSocket> {
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        let mut st = lock(&self.shared.state);
        // Re-check under the lock: a close may have landed while we waited for it.
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        let port = if port == 0 {
            pick_free_port(&st.udp, random_ephemeral_start()).ok_or_else(|| Error::Config("no free inner UDP port".into()))?
        } else {
            if st.udp.contains_key(&port) {
                // `Io(AddrInUse)`, so the NetStack mapping (§16) yields the same kind
                // as the OS backend and a caller can fall back to another port.
                return Err(Error::Io(io::Error::new(io::ErrorKind::AddrInUse, format!("inner UDP port {port} is already bound"))));
            }
            port
        };
        let mut sock = udp::Socket::new(udp_buffer(), udp_buffer());
        sock.bind(IpListenEndpoint { addr: None, port })
            .map_err(|e| Error::Config(format!("inner UDP bind to port {port}: {e}")))?;
        let (tx, rx) = mpsc::sync_channel(UDP_QUEUE_DEPTH);
        {
            // Publishing the sender and the last "is it closed?" check happen under the
            // SAME lock that `close` clears, so a close landing here either wakes this
            // receiver or is seen right now — never neither. Nothing has been mutated yet
            // on the error path.
            let mut w = lock(&self.shared.wakers);
            if let Some(e) = self.shared.closed_error() {
                return Err(e);
            }
            w.udp.insert(port, tx);
        }
        let handle = st.sockets.add(sock);
        st.udp.insert(port, UdpBinding { handle });
        drop(st);
        self.shared.notify();
        debug!("inner UDP port {port} bound");
        Ok(InnerUdpSocket { port, rx: Mutex::new(rx), stack: self.clone() })
    }

    /// Resolve `name` over the assigned DNS servers: AAAA and A queries (a family we
    /// have no inner address for is skipped), answers AAAA first. `Error::Timeout`
    /// when nothing answered before `timeout`, `Error::Protocol` when every query
    /// failed (NXDOMAIN / no records / server failure).
    pub fn resolve(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>> {
        // `Duration::MAX` overflows `Instant`; smoltcp's own retransmit give-up bounds
        // the wait anyway, so a far-future deadline is "until the resolver gives up".
        let deadline = Instant::now().checked_add(timeout).unwrap_or_else(|| Instant::now() + Duration::from_secs(1 << 30));
        let waiters = self.start_queries(name)?;
        // Registered outside `state` so a close can complete them at once; removed again
        // on every exit path below.
        lock(&self.shared.wakers).dns.extend(waiters.iter().cloned());
        self.shared.notify();

        let mut answers: Vec<IpAddr> = Vec::new();
        let mut failure: Option<Error> = None;
        let mut timed_out = false;
        let _unregister = DnsRegistration { shared: &self.shared, slots: &waiters };
        for slot in &waiters {
            let outcome = match slot.wait_until(deadline) {
                Some(r) => Some(r),
                None => self.cancel_or_take(slot),
            };
            match outcome {
                Some(Ok(addrs)) => answers.extend(addrs),
                Some(Err(e)) => failure = failure.or(Some(e)),
                None => timed_out = true,
            }
        }
        if !answers.is_empty() {
            debug!("resolved {name} -> {answers:?}");
            return Ok(answers);
        }
        if timed_out {
            return Err(Error::Timeout("DNS response"));
        }
        Err(failure.unwrap_or_else(|| Error::Protocol(format!("DNS lookup of {name} returned no addresses"))))
    }

    /// Start one query per usable family; returns the completion slots (AAAA first).
    fn start_queries(&self, name: &str) -> Result<Vec<Arc<DnsSlot>>> {
        let mut st = lock(&self.shared.state);
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        if st.dns_servers == 0 {
            return Err(Error::Config("no inner DNS server assigned".into()));
        }
        let types: Vec<DnsQueryType> = [(st.has_v6, DnsQueryType::Aaaa), (st.has_v4, DnsQueryType::A)]
            .into_iter()
            .filter_map(|(has, t)| has.then_some(t))
            .collect();
        if types.is_empty() {
            return Err(Error::Config("no inner address assigned; cannot resolve".into()));
        }
        let started = self.shared.now();
        let State { iface, sockets, dns, dns_waiters, dns_queries, .. } = &mut *st;
        let sock = sockets.get_mut::<dns::Socket>(*dns);
        let mut slots = Vec::with_capacity(types.len());
        for t in types {
            match sock.start_query(iface.context(), name, t) {
                Ok(handle) => {
                    let slot = Arc::new(DnsSlot::default());
                    dns_waiters.push(DnsWaiter { handle, slot: Arc::clone(&slot), started });
                    slots.push(slot);
                    *dns_queries += 1;
                    trace!("dns query {t:?} {name} started");
                }
                Err(e) => {
                    // Undo the queries already started for this call.
                    for slot in &slots {
                        if let Some(pos) = dns_waiters.iter().position(|w| Arc::ptr_eq(&w.slot, slot)) {
                            let w = dns_waiters.remove(pos);
                            sock.cancel_query(w.handle);
                        }
                    }
                    return Err(match e {
                        dns::StartQueryError::InvalidName | dns::StartQueryError::NameTooLong => {
                            Error::Config(format!("DNS name {name:?}: {e}"))
                        }
                        dns::StartQueryError::NoFreeSlot => Error::Protocol("no free inner DNS query slot".into()),
                    });
                }
            }
        }
        Ok(slots)
    }

    /// The deadline passed: cancel the query if it is still pending, otherwise take the
    /// result the stack thread stored in the meantime.
    fn cancel_or_take(&self, slot: &Arc<DnsSlot>) -> Option<Result<Vec<IpAddr>>> {
        let mut st = lock(&self.shared.state);
        let State { sockets, dns, dns_waiters, .. } = &mut *st;
        if let Some(pos) = dns_waiters.iter().position(|w| Arc::ptr_eq(&w.slot, slot)) {
            let w = dns_waiters.remove(pos);
            sockets.get_mut::<dns::Socket>(*dns).cancel_query(w.handle);
            return None;
        }
        drop(st);
        slot.take()
    }

    /// Open a TCP connection to `remote` from an ephemeral inner port (§11.2), waiting
    /// at most `timeout` for the handshake (`Duration::MAX`: until it completes or
    /// fails). smoltcp picks the source address among the inner addresses of `remote`'s
    /// family. `Error::Timeout` when nothing answered in time, `Io(ConnectionRefused)`
    /// when the peer answered with RST, `Config` when there is no inner address of that
    /// family (or `remote` is not a destination), `Error::Closed` once the stack is closed
    /// — at once, also for a call already waiting.
    pub fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> Result<InnerTcpStream> {
        let deadline = Instant::now().checked_add(timeout);
        let (id, local) = self.start_connect(remote)?;
        self.shared.notify();
        let established = self.tcp_wait_for(deadline, |st| {
            let state = match st.tcp_socket(id) {
                Ok(s) => s.state(),
                Err(e) => return Some(Err(e)),
            };
            match state {
                TcpState::SynSent | TcpState::SynReceived => None,
                // A RST (or anything else that closed it) before the handshake completed.
                TcpState::Closed | TcpState::TimeWait | TcpState::Listen => Some(Err(Error::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("inner TCP connection to {remote} refused"),
                )))),
                // ESTABLISHED — or already past it when the peer closed right away.
                _ => {
                    st.tcp_connections_opened += 1;
                    Some(Ok(()))
                }
            }
        });
        match established {
            Ok(Some(())) => {
                debug!("inner TCP connected {local} -> {remote}");
                Ok(InnerTcpStream::new(self.clone(), id, local, remote))
            }
            outcome => {
                let e = outcome.err().unwrap_or(Error::Timeout("inner TCP handshake"));
                // After a close the socket is gone already, and taking `state` here could
                // wait out the poll in progress — the wait a close must not impose (§17.6).
                if !matches!(e, Error::Closed(_)) {
                    lock(&self.shared.state).abandon_tcp(id);
                }
                Err(e)
            }
        }
    }

    /// Register a SYN-SENT socket for `remote`: `(stream id, local address)`.
    fn start_connect(&self, remote: SocketAddr) -> Result<(u64, SocketAddr)> {
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        let mut st = lock(&self.shared.state);
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        let (has_family, family) = match remote {
            SocketAddr::V4(_) => (st.has_v4, "IPv4"),
            SocketAddr::V6(_) => (st.has_v6, "IPv6"),
        };
        if !has_family {
            return Err(Error::Config(format!("no assigned inner {family} address to reach {remote}")));
        }
        let port = pick_free_port(&st.tcp_ports, random_ephemeral_start())
            .ok_or_else(|| Error::Io(io::Error::new(io::ErrorKind::AddrNotAvailable, "no free inner TCP port")))?;
        let mut sock = new_tcp_socket();
        sock.connect(st.iface.context(), IpEndpoint::from(remote), port).map_err(|e| match e {
            tcp::ConnectError::Unaddressable => Error::Config(format!("inner TCP: {remote} is not addressable")),
            tcp::ConnectError::InvalidState => Error::Protocol(format!("inner TCP connect to {remote}: fresh socket in an {e}")),
        })?;
        let local = sock
            .local_endpoint()
            .map(SocketAddr::from)
            .ok_or_else(|| Error::Protocol(format!("inner TCP connect to {remote}: no source address chosen")))?;
        let handle = st.sockets.add(sock);
        *st.tcp_ports.entry(port).or_default() += 1;
        let id = st.next_tcp_id();
        st.tcp.insert(id, TcpConn { handle, port, outbound: true, orphaned: None });
        trace!("inner TCP SYN {local} -> {remote}");
        Ok((id, local))
    }

    /// Listen for TCP connections on inner `port` on every inner address (§11.2); `port
    /// == 0` picks a free port in `49152..=65535`. A port that already has a listener, or
    /// is the local port of an outbound connection, is `Io(AddrInUse)` — the kind the OS
    /// backend reports (§16).
    pub fn listen_tcp(&self, port: u16) -> Result<InnerTcpListener> {
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        let mut st = lock(&self.shared.state);
        if let Some(e) = self.shared.closed_error() {
            return Err(e);
        }
        let port = if port == 0 {
            pick_free_port(&st.tcp_ports, random_ephemeral_start())
                .ok_or_else(|| Error::Io(io::Error::new(io::ErrorKind::AddrNotAvailable, "no free inner TCP port")))?
        } else {
            if st.listeners.contains_key(&port) || st.tcp.values().any(|c| c.outbound && c.port == port) {
                return Err(Error::Io(io::Error::new(io::ErrorKind::AddrInUse, format!("inner TCP port {port} is already in use"))));
            }
            port
        };
        let mut slots = Vec::with_capacity(TCP_LISTEN_BACKLOG);
        for _ in 0..TCP_LISTEN_BACKLOG {
            match st.add_listen_slot(port) {
                Ok(h) => slots.push(h),
                Err(e) => {
                    for h in slots {
                        st.free_tcp_socket(h, port);
                    }
                    return Err(e);
                }
            }
        }
        let id = st.next_tcp_id();
        st.listeners.insert(port, TcpListen { id, slots });
        let ip = st.iface.ip_addrs().first().map(|c| IpAddr::from(c.address())).unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        drop(st);
        debug!("inner TCP listener on port {port}");
        Ok(InnerTcpListener { stack: self.clone(), port, id, local: SocketAddr::new(ip, port) })
    }

    /// The blocking core of every TCP call (§11.2): run `attempt` under `state` until it
    /// returns `Some`, parking on the TCP event counter — never on `state` — in between.
    /// `Ok(None)` once `deadline` (`None` = never) passed first; `Error::Closed` as soon as
    /// the stack is closed, before and after every attempt. A finished attempt may have
    /// queued data or freed buffer space, so the stack thread is woken to act on it.
    fn tcp_wait_for<T>(&self, deadline: Option<Instant>, mut attempt: impl FnMut(&mut State) -> Option<Result<T>>) -> Result<Option<T>> {
        let sh = &*self.shared;
        loop {
            if let Some(e) = sh.closed_error() {
                return Err(e);
            }
            let seen = sh.tcp_generation();
            let outcome = {
                let mut st = lock(&sh.state);
                // Re-checked under the lock: a close's smoltcp cleanup (which needs this
                // lock) has not run yet if `closed` is still empty here.
                if let Some(e) = sh.closed_error() {
                    return Err(e);
                }
                attempt(&mut st)
            };
            if let Some(r) = outcome {
                sh.notify();
                return r.map(Some);
            }
            if !sh.tcp_park(seen, deadline) {
                return Ok(None);
            }
        }
    }

    pub fn stats(&self) -> StackStats {
        let st = lock(&self.shared.state);
        let d: DeviceStats = st.device.stats();
        let r: ReassemblyStats = st.reassembler.stats();
        StackStats {
            rx_packets: d.rx_packets,
            rx_bytes: d.rx_bytes,
            rx_queue_drops: d.rx_queue_drops,
            tx_packets: d.tx_packets,
            tx_bytes: d.tx_bytes,
            tx_errors: d.tx_errors,
            tx_fragmented: d.tx_fragmented,
            tx_frag_drops: d.tx_frag_drops,
            rx_fragments: r.fragments,
            rx_reassembled: r.reassembled,
            rx_reassembly_drops: r.drops,
            udp_delivered: st.udp_delivered,
            udp_queue_drops: st.udp_queue_drops,
            udp_send_full: st.udp_send_full,
            udp_tx_drops: st.udp_tx_drops,
            dns_queries: st.dns_queries,
            udp_bindings: st.udp.len() as u64,
            tcp_connections_opened: st.tcp_connections_opened,
            tcp_accepted: st.tcp_accepted,
            tcp_tx_bytes: st.tcp_tx_bytes,
            tcp_rx_bytes: st.tcp_rx_bytes,
            tcp_sockets: (st.tcp.len() + st.listeners.values().map(|l| l.slots.len()).sum::<usize>()) as u64,
            tcp_dup_syn_drops: st.tcp_dup_syn_drops,
            tcp_mss_clamped: d.tcp_mss_clamped,
        }
    }

    /// Inner addresses installed on the interface, with prefix lengths.
    pub fn addresses(&self) -> Vec<(IpAddr, u8)> {
        lock(&self.shared.state)
            .iface
            .ip_addrs()
            .iter()
            .map(|c| (IpAddr::from(c.address()), c.prefix_len()))
            .collect()
    }

    /// Wire MTU of the inner interface (`child.inner_mtu`): the largest packet handed
    /// to the TX sink.
    pub fn mtu(&self) -> usize {
        lock(&self.shared.state).device.wire_mtu()
    }

    /// MTU smoltcp sees (`child.inner_mtu_stack`, §11.1): bounds one UDP datagram.
    pub fn stack_mtu(&self) -> usize {
        lock(&self.shared.state).device.mtu()
    }

    #[cfg(test)]
    fn pending_dns_queries(&self) -> usize {
        lock(&self.shared.state).dns_waiters.len()
    }
}

impl std::fmt::Debug for InnerStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerStack").field("closed", &self.is_closed()).field("stats", &self.stats()).finish()
    }
}

// ---------------------------------------------------------------------------
// InnerUdpSocket
// ---------------------------------------------------------------------------

impl InnerUdpSocket {
    /// Queue `payload` for `dst` on this socket and wake the stack thread. The source
    /// address is chosen by smoltcp among the inner addresses of `dst`'s family.
    pub fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> Result<()> {
        if let Some(e) = self.stack.shared.closed_error() {
            return Err(e);
        }
        let mut st = lock(&self.stack.shared.state);
        if let Some(e) = self.stack.shared.closed_error() {
            return Err(e);
        }
        let (has_family, family) = match dst {
            SocketAddr::V4(_) => (st.has_v4, "IPv4"),
            SocketAddr::V6(_) => (st.has_v6, "IPv6"),
        };
        if !has_family {
            return Err(Error::Config(format!("no assigned inner {family} address to reach {dst}")));
        }
        let max = max_udp_payload(st.device.mtu(), dst.is_ipv4());
        if payload.len() > max {
            return Err(Error::Protocol(format!(
                "{} byte payload exceeds the {max} byte limit for inner {family} datagrams (inner_mtu_stack {})",
                payload.len(),
                st.device.mtu()
            )));
        }
        let handle = st
            .udp
            .get(&self.port)
            .map(|b| b.handle)
            .ok_or_else(|| Error::Closed(format!("inner UDP port {} is no longer bound", self.port)))?;
        if let Err(e) = st.sockets.get_mut::<udp::Socket>(handle).send_slice(payload, IpEndpoint::from(dst)) {
            return Err(match e {
                udp::SendError::BufferFull => {
                    st.udp_send_full += 1;
                    Error::Protocol(format!("inner UDP port {}: send buffer full", self.port))
                }
                udp::SendError::Unaddressable => Error::Config(format!("inner UDP: {dst} is not addressable")),
            });
        }
        drop(st);
        self.stack.shared.notify();
        trace!("inner UDP tx port {} -> {} ({} bytes)", self.port, dst, payload.len());
        Ok(())
    }

    /// Wait up to `timeout` for a datagram addressed to this port. `Ok(None)` on
    /// timeout, `Error::Closed` once the stack is stopped.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<UdpDatagram>> {
        let r = lock(&self.rx).recv_timeout(timeout);
        match r {
            Ok(dg) => Ok(Some(dg)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                // `StackShared::closed` deliberately, not `State`: the stack thread may be
                // holding `state` inside a blocking outer send, and this must not wait.
                Err(self.stack.shared.closed_error().unwrap_or_else(|| Error::Closed("inner stack stopped".into())))
            }
        }
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// The socket's address as seen by peers: the first inner address of the stack
    /// (IPv6 before IPv4, in the order they were assigned) with the bound port. The
    /// socket is bound on *every* inner address; this is the one to advertise (SIP
    /// Via/Contact) when a single address is needed. `[::]:port` if the stack has no
    /// address at all.
    pub fn local_addr(&self) -> SocketAddr {
        let ip = self.stack.addresses().first().map(|(a, _)| *a).unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        SocketAddr::new(ip, self.port)
    }
}

impl Drop for InnerUdpSocket {
    /// Unbind the port. Datagrams `send_to` accepted but the stack thread has not
    /// transmitted yet are flushed first (the sink is synchronous, so this thread can
    /// drive egress itself); whatever still cannot leave is counted in `udp_tx_drops`.
    fn drop(&mut self) {
        {
            let mut st = lock(&self.stack.shared.state);
            if let Some(b) = st.udp.remove(&self.port) {
                let queued = st.sockets.get::<udp::Socket>(b.handle).send_queue();
                if queued > 0 {
                    let now = self.stack.shared.now();
                    let State { iface, device, sockets, .. } = &mut *st;
                    while iface.poll_egress(now, device, sockets) == PollResult::SocketStateChanged {}
                    let left = st.sockets.get::<udp::Socket>(b.handle).send_queue();
                    if left > 0 {
                        st.udp_tx_drops += left as u64;
                        debug!("inner UDP port {}: {left} queued datagram(s) dropped on close", self.port);
                    }
                }
                st.sockets.remove(b.handle);
                debug!("inner UDP port {} unbound", self.port);
            }
            // After the binding, so a concurrent `drain` never sees a bound port whose
            // sender has already gone (it would unbind it before the queued egress above
            // could be flushed).
            lock(&self.stack.shared.wakers).udp.remove(&self.port);
        }
        self.stack.shared.notify();
    }
}

impl std::fmt::Debug for InnerUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerUdpSocket").field("port", &self.port).finish()
    }
}

// ---------------------------------------------------------------------------
// InnerTcpStream / InnerTcpListener
// ---------------------------------------------------------------------------

/// `Some(now + timeout)`; `None` (wait forever) without a timeout or when it overflows.
fn deadline_after(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|t| Instant::now().checked_add(t))
}

/// std's answer to a zero timeout (`set_read_timeout(Some(ZERO))` is an error there too).
fn zero_timeout_error() -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, "cannot set a 0 duration timeout"))
}

impl InnerTcpStream {
    fn new(stack: InnerStack, id: u64, local: SocketAddr, peer: SocketAddr) -> InnerTcpStream {
        InnerTcpStream {
            stack,
            id,
            local,
            peer,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            shut: AtomicBool::new(false),
        }
    }

    fn reset_error(&self) -> Error {
        Error::Io(io::Error::new(io::ErrorKind::ConnectionReset, format!("inner TCP connection to {} was reset", self.peer)))
    }

    fn broken_pipe(&self) -> Error {
        Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, format!("inner TCP connection to {} is shut down", self.peer)))
    }

    /// Read into `buf`: `Ok(n)` with what is buffered, waiting per the read timeout while
    /// nothing is; `Ok(0)` at EOF — the peer closed and everything it sent before its FIN
    /// has been read — or after [`shutdown`](Self::shutdown). `Error::Timeout` when the
    /// read timeout expired, `Io(ConnectionReset)` when the peer reset the connection,
    /// `Error::Closed` once the stack is closed.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = deadline_after(*lock(&self.read_timeout));
        let read = self.stack.tcp_wait_for(deadline, |st| {
            if self.shut.load(Ordering::SeqCst) {
                return Some(Ok(0));
            }
            let s = match st.tcp_socket(self.id) {
                Ok(s) => s,
                Err(e) => return Some(Err(e)),
            };
            match s.recv_slice(buf) {
                // ESTABLISHED (or FIN-WAIT) with nothing buffered: wait.
                Ok(0) => None,
                Ok(n) => {
                    st.tcp_rx_bytes += n as u64;
                    Some(Ok(n))
                }
                // The peer's FIN, everything before it consumed.
                Err(tcp::RecvError::Finished) => Some(Ok(0)),
                // Closed without a FIN: reset.
                Err(tcp::RecvError::InvalidState) => Some(Err(self.reset_error())),
            }
        })?;
        read.ok_or(Error::Timeout("inner TCP read"))
    }

    /// Queue some of `data` for transmission: `Ok(n)` with how much the send buffer took,
    /// waiting per the write timeout while it is full. On every error nothing was queued
    /// (the `io::Write` contract TLS relies on): `Error::Timeout` when the write timeout
    /// expired, `Io(BrokenPipe)` after [`shutdown`](Self::shutdown), `Io(ConnectionReset)`
    /// when the peer reset the connection, `Error::Closed` once the stack is closed.
    pub fn write(&self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let deadline = deadline_after(*lock(&self.write_timeout));
        let written = self.stack.tcp_wait_for(deadline, |st| {
            if self.shut.load(Ordering::SeqCst) {
                return Some(Err(self.broken_pipe()));
            }
            let s = match st.tcp_socket(self.id) {
                Ok(s) => s,
                Err(e) => return Some(Err(e)),
            };
            match s.send_slice(data) {
                // The send buffer is full: wait for the peer to acknowledge.
                Ok(0) => None,
                Ok(n) => {
                    st.tcp_tx_bytes += n as u64;
                    Some(Ok(n))
                }
                Err(tcp::SendError::InvalidState) => {
                    Some(Err(if s.state() == TcpState::Closed { self.reset_error() } else { self.broken_pipe() }))
                }
            }
        })?;
        written.ok_or(Error::Timeout("inner TCP write"))
    }

    /// Timeout of later `read`s (`None`: wait forever). `Some(ZERO)` is an error, as in std.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(zero_timeout_error());
        }
        *lock(&self.read_timeout) = timeout;
        Ok(())
    }

    /// Timeout of later `write`s (`None`: wait forever). `Some(ZERO)` is an error, as in std.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(zero_timeout_error());
        }
        *lock(&self.write_timeout) = timeout;
        Ok(())
    }

    /// `true` disables Nagle's algorithm (smoltcp's `set_nagle_enabled(false)`, the
    /// equivalent of `TCP_NODELAY`).
    pub fn set_nodelay(&self, nodelay: bool) -> Result<()> {
        if let Some(e) = self.stack.shared.closed_error() {
            return Err(e);
        }
        let mut st = lock(&self.stack.shared.state);
        if let Some(e) = self.stack.shared.closed_error() {
            return Err(e);
        }
        st.tcp_socket(self.id)?.set_nagle_enabled(!nodelay);
        Ok(())
    }

    /// Close both directions: a FIN to the peer (which reads EOF once it has read
    /// everything before it); from now on our reads return EOF and our writes fail with
    /// `BrokenPipe`. A call blocked in `read` / `write` on this stream returns. Idempotent,
    /// and `Ok(())` also when the connection or the whole stack is already down.
    pub fn shutdown(&self) -> Result<()> {
        if !self.shut.swap(true, Ordering::SeqCst) && self.stack.shared.closed_error().is_none() {
            if let Ok(s) = lock(&self.stack.shared.state).tcp_socket(self.id) {
                s.close();
            }
            self.stack.shared.notify();
        }
        self.stack.shared.tcp_wake();
        Ok(())
    }

    /// Our end: the inner address smoltcp chose (or the peer connected to) and the port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl Drop for InnerTcpStream {
    /// Close gracefully (FIN, or nothing when the connection is already down) and leave
    /// the socket to the stack thread, which frees it once the close handshake is over
    /// and resets it after [`TCP_ORPHAN_LINGER`] (§11.2).
    fn drop(&mut self) {
        {
            let mut st = lock(&self.stack.shared.state);
            let State { tcp: conns, sockets, .. } = &mut *st;
            if let Some(c) = conns.get_mut(&self.id) {
                c.orphaned = Some(Instant::now());
                sockets.get_mut::<tcp::Socket>(c.handle).close();
            }
        }
        self.stack.shared.notify();
    }
}

impl std::fmt::Debug for InnerTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerTcpStream").field("local", &self.local).field("peer", &self.peer).finish()
    }
}

impl InnerTcpListener {
    /// Wait at most `timeout` for a connection (`Duration::MAX`: until one arrives):
    /// `Ok(Some((stream, peer)))`, `Ok(None)` on timeout, `Error::Closed` once the stack is
    /// closed. The backlog slot the connection arrived on gets a fresh listening socket
    /// at once (§11.2).
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<(InnerTcpStream, SocketAddr)>> {
        let deadline = Instant::now().checked_add(timeout);
        let accepted = self.stack.tcp_wait_for(deadline, |st| st.accept_pending(self.port, self.id))?;
        Ok(accepted.map(|(id, local, peer)| {
            debug!("inner TCP accepted {peer} on {local}");
            (InnerTcpStream::new(self.stack.clone(), id, local, peer), peer)
        }))
    }

    /// The listening port with the stack's first inner address (IPv6 before IPv4, like
    /// [`InnerUdpSocket::local_addr`]); the listener takes connections to every inner
    /// address. `[::]:port` if the stack has no address at all.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }
}

impl Drop for InnerTcpListener {
    /// Remove the listening sockets; a connection nobody accepted is reset (as an OS
    /// listener does with its accept queue) and freed once the RST is out.
    fn drop(&mut self) {
        {
            let mut st = lock(&self.stack.shared.state);
            if st.listeners.get(&self.port).is_some_and(|l| l.id == self.id)
                && let Some(l) = st.listeners.remove(&self.port)
            {
                for h in l.slots {
                    let s = st.sockets.get_mut::<tcp::Socket>(h);
                    if s.state() == TcpState::Listen || (s.state() == TcpState::Closed && s.remote_endpoint().is_none()) {
                        st.free_tcp_socket(h, self.port);
                    } else {
                        s.abort();
                        let id = st.next_tcp_id();
                        st.tcp.insert(id, TcpConn { handle: h, port: self.port, outbound: false, orphaned: Some(Instant::now()) });
                    }
                }
            }
        }
        self.stack.shared.notify();
        debug!("inner TCP listener on port {} closed", self.port);
    }
}

impl std::fmt::Debug for InnerTcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerTcpListener").field("local", &self.local).finish()
    }
}

// ---------------------------------------------------------------------------
// Tests: an in-process two-stack loopback (no ESP needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicU64;

    const A_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 1);
    const B_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xb, 0, 0, 0, 0, 1);
    const A_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    /// Wire MTU: every packet a sink sees must fit it.
    const MTU: usize = 1280;
    /// MTU smoltcp sees (§11.1).
    const STACK_MTU: usize = 16384;
    const WAIT: Duration = Duration::from_secs(5);

    fn assigned(v6: Option<Ipv6Addr>, v4: Option<Ipv4Addr>, dns6: Option<Ipv6Addr>, dns4: Option<Ipv4Addr>) -> AssignedConfig {
        AssignedConfig {
            internal_ipv6: v6.map(|a| vec![(a, 64)]).unwrap_or_default(),
            internal_ipv4: v4.map(|a| vec![a]).unwrap_or_default(),
            dns_ipv6: dns6.map(|a| vec![a]).unwrap_or_default(),
            dns_ipv4: dns4.map(|a| vec![a]).unwrap_or_default(),
            ..Default::default()
        }
    }

    /// Test knobs of one direction of the loopback wire.
    #[derive(Default)]
    pub(crate) struct WireCtl {
        /// Record every packet but deliver none (a path that eats everything).
        blackhole: AtomicBool,
        /// Sleep this long inside the sink — on the sending stack's thread, with its lock
        /// held — standing in for a congested outer socket.
        stall_ms: AtomicU64,
        /// Set once the sink entered a stall.
        stalled: AtomicBool,
    }

    /// One direction of the loopback "wire": the sink (which runs on the sending
    /// stack's thread, with that stack's lock held) asserts the packet fits the wire
    /// MTU (§11.1), records it and queues it; a forwarder thread pushes it into the far
    /// stack. The sink must never lock the far stack itself: the two stack threads
    /// would deadlock (A holds A, pushes into B; B holds B, replies into A). The real
    /// tunnel has the same shape — the sink does a UDP send, the far side's rx thread
    /// does `push_rx`.
    fn wire(
        name: &str,
        target: Arc<OnceLock<InnerStack>>,
        tap: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        ctl: Arc<WireCtl>,
    ) -> (TxSink, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let sink: TxSink = Arc::new(move |pkt: &[u8]| {
            assert!(pkt.len() <= MTU, "sink handed a {} byte packet, wire MTU is {MTU}", pkt.len());
            tap.lock().unwrap().push(pkt.to_vec());
            let stall = ctl.stall_ms.load(Ordering::SeqCst);
            if stall > 0 {
                ctl.stalled.store(true, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(stall));
            }
            if ctl.blackhole.load(Ordering::SeqCst) {
                return Ok(());
            }
            tx.send(pkt.to_vec()).map_err(|_| Error::Protocol("wire down".into()))
        });
        let forwarder = thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                loop {
                    match rx.recv_timeout(Duration::from_millis(20)) {
                        Ok(pkt) => {
                            if let Some(t) = target.get() {
                                t.push_rx(pkt);
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .unwrap();
        (sink, forwarder)
    }

    /// Two stacks whose devices feed each other over asynchronous wires; `a_wire` /
    /// `b_wire` record every IP packet A / B transmitted. Stops and joins every thread
    /// on drop.
    pub(crate) struct Pair {
        pub(crate) a: InnerStack,
        pub(crate) b: InnerStack,
        a_wire: Arc<Mutex<Vec<Vec<u8>>>>,
        b_wire: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Knobs of the A -> B and B -> A directions.
        a_ctl: Arc<WireCtl>,
        b_ctl: Arc<WireCtl>,
        stop_wires: Arc<AtomicBool>,
        threads: Vec<JoinHandle<()>>,
    }

    impl Pair {
        fn new(a_cfg: AssignedConfig, b_cfg: AssignedConfig) -> Pair {
            let a_wire = Arc::new(Mutex::new(Vec::new()));
            let b_wire = Arc::new(Mutex::new(Vec::new()));
            let a_ctl = Arc::new(WireCtl::default());
            let b_ctl = Arc::new(WireCtl::default());
            let stop_wires = Arc::new(AtomicBool::new(false));
            let b_slot: Arc<OnceLock<InnerStack>> = Arc::new(OnceLock::new());
            let a_slot: Arc<OnceLock<InnerStack>> = Arc::new(OnceLock::new());
            let (sink_a, wire_ab) =
                wire("wire-a-to-b", Arc::clone(&b_slot), Arc::clone(&a_wire), Arc::clone(&stop_wires), Arc::clone(&a_ctl));
            let (sink_b, wire_ba) =
                wire("wire-b-to-a", Arc::clone(&a_slot), Arc::clone(&b_wire), Arc::clone(&stop_wires), Arc::clone(&b_ctl));
            let a = InnerStack::new(&a_cfg, sink_a, MTU, STACK_MTU).unwrap();
            let b = InnerStack::new(&b_cfg, sink_b, MTU, STACK_MTU).unwrap();
            let _ = b_slot.set(b.clone());
            let _ = a_slot.set(a.clone());
            let threads = vec![a.spawn().unwrap(), b.spawn().unwrap(), wire_ab, wire_ba];
            Pair { a, b, a_wire, b_wire, a_ctl, b_ctl, stop_wires, threads }
        }

        /// Sizes of the packets A transmitted so far.
        fn a_wire_lens(&self) -> Vec<usize> {
            self.a_wire.lock().unwrap().iter().map(Vec::len).collect()
        }

        /// Wait until B has transmitted at least `n` packets; returns them.
        fn b_wire_after(&self, n: usize) -> Vec<Vec<u8>> {
            let deadline = Instant::now() + WAIT;
            while self.b_wire.lock().unwrap().len() < n && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            self.b_wire.lock().unwrap().clone()
        }

        /// A(v6 + v4, DNS = B) <-> B(v6 on another /64 + v4, DNS = A).
        pub(crate) fn dual() -> Pair {
            Pair::new(
                assigned(Some(A_V6), Some(A_V4), Some(B_V6), Some(B_V4)),
                assigned(Some(B_V6), Some(B_V4), Some(A_V6), Some(A_V4)),
            )
        }
    }

    impl Drop for Pair {
        fn drop(&mut self) {
            self.a.stop();
            self.b.stop();
            self.stop_wires.store(true, Ordering::SeqCst);
            for t in self.threads.drain(..) {
                t.join().unwrap();
            }
        }
    }

    fn recv(sock: &InnerUdpSocket) -> UdpDatagram {
        sock.recv_timeout(WAIT).unwrap().expect("datagram within the wait")
    }

    // ---- pure helpers -------------------------------------------------------

    fn bindings(ports: &[u16]) -> HashMap<u16, UdpBinding> {
        ports.iter().map(|p| (*p, UdpBinding { handle: SocketHandle::default() })).collect()
    }

    #[test]
    fn free_port_starts_at_requested_and_skips_used() {
        let used = bindings(&[50000, 50001]);
        assert_eq!(pick_free_port(&used, 50000), Some(50002));
        assert_eq!(pick_free_port(&used, 49999), Some(49999));
        assert_eq!(pick_free_port(&bindings(&[]), 49152), Some(49152));
    }

    #[test]
    fn free_port_wraps_and_clamps() {
        let used = bindings(&[65535]);
        assert_eq!(pick_free_port(&used, 65535), Some(49152));
        assert_eq!(pick_free_port(&bindings(&[]), 80), Some(49152));
    }

    #[test]
    fn free_port_none_when_exhausted() {
        let all: Vec<u16> = (EPHEMERAL_PORT_LO..=EPHEMERAL_PORT_HI).collect();
        let used = bindings(&all);
        assert_eq!(pick_free_port(&used, 50000), None);
        let mut almost = used;
        almost.remove(&60000);
        assert_eq!(pick_free_port(&almost, 12), Some(60000));
    }

    #[test]
    fn mtu_is_clamped_and_payload_limits_follow_it() {
        assert_eq!(effective_mtu(100), MIN_INNER_MTU);
        assert_eq!(effective_mtu(1400), 1400);
        assert_eq!(effective_mtu(1 << 20), MAX_INNER_MTU);
        // The payload cap follows the stack MTU (§11.1): inner_mtu_stack - 48 / - 28.
        assert_eq!(max_udp_payload(1280, false), 1280 - 48);
        assert_eq!(max_udp_payload(STACK_MTU, false), STACK_MTU - 48);
        assert_eq!(max_udp_payload(1280, true), smoltcp::config::FRAGMENTATION_BUFFER_SIZE - 28);
        assert_eq!(max_udp_payload(STACK_MTU, true), STACK_MTU - 28);
        assert!(max_udp_payload(STACK_MTU, false) >= 3000, "the stack MTU must hold the test payload");
        assert_eq!(max_udp_payload(65535, true), 65535 - 28);
    }

    #[test]
    fn stack_installs_addresses_and_stats_start_at_zero() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        let s = InnerStack::new(&assigned(Some(A_V6), Some(A_V4), Some(B_V6), None), sink.clone(), 1400, 9000).unwrap();
        let mut addrs = s.addresses();
        addrs.sort();
        assert_eq!(addrs, vec![(IpAddr::V4(A_V4), 32), (IpAddr::V6(A_V6), 64)]);
        assert_eq!(s.mtu(), 1400);
        assert_eq!(s.stack_mtu(), 9000);
        assert_eq!(s.stats(), StackStats::default());
        assert!(!s.is_closed());
        // The stack MTU is clamped to [wire MTU, 65535].
        let s = InnerStack::new(&assigned(Some(A_V6), None, None, None), sink.clone(), 1400, 100).unwrap();
        assert_eq!((s.mtu(), s.stack_mtu()), (1400, 1400));
        let s = InnerStack::new(&assigned(Some(A_V6), None, None, None), sink, 1400, 1 << 20).unwrap();
        assert_eq!((s.mtu(), s.stack_mtu()), (1400, MAX_INNER_MTU));
    }

    #[test]
    fn non_unicast_dns_servers_are_skipped() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        let cfg = AssignedConfig {
            internal_ipv6: vec![(A_V6, 64)],
            internal_ipv4: vec![A_V4],
            dns_ipv6: vec![Ipv6Addr::UNSPECIFIED, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)],
            dns_ipv4: vec![Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST],
            ..Default::default()
        };
        let s = InnerStack::new(&cfg, sink.clone(), MTU, STACK_MTU).unwrap();
        let e = s.resolve(HOST, WAIT).unwrap_err();
        assert!(matches!(e, Error::Config(ref m) if m.contains("no inner DNS server")), "{e}");
        assert_eq!(s.stats().dns_queries, 0);
        // A usable server after a garbage one is kept and used.
        let p = Pair::new(
            AssignedConfig {
                internal_ipv6: vec![(A_V6, 64)],
                internal_ipv4: vec![A_V4],
                dns_ipv4: vec![Ipv4Addr::UNSPECIFIED, B_V4],
                ..Default::default()
            },
            assigned(Some(B_V6), Some(B_V4), None, None),
        );
        let _server = DnsServer::start(&p.b, vec![IpAddr::V4(ANS_V4)], 0);
        assert_eq!(p.a.resolve(HOST, WAIT).unwrap(), vec![IpAddr::V4(ANS_V4)]);
    }

    #[test]
    fn non_unicast_addresses_are_ignored_not_fatal() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        let cfg = AssignedConfig {
            internal_ipv6: vec![(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 64), (A_V6, 200)],
            internal_ipv4: vec![Ipv4Addr::BROADCAST, Ipv4Addr::UNSPECIFIED, A_V4],
            ..Default::default()
        };
        let s = InnerStack::new(&cfg, sink, 1280, STACK_MTU).unwrap();
        let mut addrs = s.addresses();
        addrs.sort();
        assert_eq!(addrs, vec![(IpAddr::V4(A_V4), 32), (IpAddr::V6(A_V6), 128)], "prefix clamped to 128");
    }

    // ---- UDP over the loopback ---------------------------------------------

    #[test]
    fn udp_both_directions_ipv6_and_ipv4_with_correct_endpoints() {
        let p = Pair::dual();
        let sa = p.a.bind_udp(40000).unwrap();
        let sb = p.b.bind_udp(40001).unwrap();

        // A -> B over IPv6 (B is on another /64: off-prefix, via the nominal default route).
        sa.send_to(SocketAddr::new(B_V6.into(), 40001), b"ping6").unwrap();
        let dg = recv(&sb);
        assert_eq!(dg.src, SocketAddr::new(A_V6.into(), 40000));
        assert_eq!(dg.dst, SocketAddr::new(B_V6.into(), 40001));
        assert_eq!(dg.payload, b"ping6");
        // B -> A over IPv6.
        sb.send_to(dg.src, b"pong6").unwrap();
        let dg = recv(&sa);
        assert_eq!(dg.src, SocketAddr::new(B_V6.into(), 40001));
        assert_eq!(dg.dst, SocketAddr::new(A_V6.into(), 40000));
        assert_eq!(dg.payload, b"pong6");

        // Same over IPv4 (/32 addresses: everything is off-prefix).
        sa.send_to(SocketAddr::new(B_V4.into(), 40001), b"ping4").unwrap();
        let dg = recv(&sb);
        assert_eq!(dg.src, SocketAddr::new(A_V4.into(), 40000));
        assert_eq!(dg.dst, SocketAddr::new(B_V4.into(), 40001));
        assert_eq!(dg.payload, b"ping4");
        sb.send_to(dg.src, b"pong4").unwrap();
        let dg = recv(&sa);
        assert_eq!(dg.src, SocketAddr::new(B_V4.into(), 40001));
        assert_eq!(dg.dst, SocketAddr::new(A_V4.into(), 40000));
        assert_eq!(dg.payload, b"pong4");

        let sa_stats = p.a.stats();
        assert_eq!(sa_stats.udp_delivered, 2);
        assert_eq!(sa_stats.tx_packets, 2);
        assert_eq!(sa_stats.rx_packets, 2);
        assert_eq!(sa_stats.udp_bindings, 1);
        assert_eq!(sa_stats.tx_errors, 0);
        assert!(sa.recv_timeout(Duration::from_millis(50)).unwrap().is_none(), "nothing else queued");
    }

    #[test]
    fn off_prefix_ipv6_destination_is_delivered_via_default_route() {
        // A: 2001:db8:a::/64, B: 2001:db8:b::/64 — B is not on A's prefix.
        let a_cidr = IpCidr::new(IpAddress::Ipv6(A_V6), 64);
        assert!(!a_cidr.contains_addr(&IpAddress::Ipv6(B_V6)), "test premise: B is off A's prefix");
        // Even with NO DNS server (so the nominal gateway is the inner address itself).
        let p = Pair::new(assigned(Some(A_V6), None, None, None), assigned(Some(B_V6), None, None, None));
        let sa = p.a.bind_udp(0).unwrap();
        let sb = p.b.bind_udp(5060).unwrap();
        sa.send_to(SocketAddr::new(B_V6.into(), 5060), b"INVITE").unwrap();
        let dg = recv(&sb);
        assert_eq!(dg.src, SocketAddr::new(A_V6.into(), sa.local_port()));
        assert_eq!(dg.payload, b"INVITE");
        // A has no IPv4 address: an IPv4 destination is refused up front.
        let e = sa.send_to(SocketAddr::new(B_V4.into(), 5060), b"x").unwrap_err();
        assert!(matches!(e, Error::Config(ref m) if m.contains("IPv4")), "{e}");
    }

    #[test]
    fn ipv4_3000_byte_payload_is_fragmented_at_the_mtu_and_reassembled() {
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        let sb = p.b.bind_udp(7000).unwrap();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        sa.send_to(SocketAddr::new(B_V4.into(), 7000), &payload).unwrap();
        let dg = recv(&sb);
        assert_eq!(dg.payload.len(), 3000);
        assert_eq!(dg.payload, payload, "reassembled payload intact");
        assert_eq!(dg.src, SocketAddr::new(A_V4.into(), sa.local_port()));
        let wire = p.a_wire_lens();
        assert!(wire.len() >= 3, "3028 bytes need >= 3 fragments at MTU 1280, saw {wire:?}");
        assert!(wire.iter().all(|&len| len <= MTU), "every fragment fits the MTU: {wire:?}");
        assert_eq!(wire.iter().sum::<usize>(), 3000 + 8 + 20 * wire.len(), "fragments carry the whole datagram once");
        let st = p.a.stats();
        assert_eq!(st.tx_packets as usize, wire.len());
        assert_eq!((st.tx_fragmented, st.tx_frag_drops), (1, 0), "split by the §11.1 shim, not smoltcp: {st:?}");
        // And back, so B's fragmenter is exercised too.
        sb.send_to(dg.src, &payload).unwrap();
        assert_eq!(recv(&sa).payload, payload);
    }

    #[test]
    fn ipv6_3000_byte_payload_is_fragmented_at_the_wire_mtu_and_reassembled() {
        // §11.1: the wire MTU is 1280 (every sink asserts it), smoltcp sees STACK_MTU.
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        let sb = p.b.bind_udp(5060).unwrap();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 249) as u8).collect();
        sa.send_to(SocketAddr::new(B_V6.into(), 5060), &payload).unwrap();
        let dg = recv(&sb);
        assert_eq!(dg.payload, payload, "reassembled payload intact");
        assert_eq!(dg.src, SocketAddr::new(A_V6.into(), sa.local_port()));
        assert_eq!(dg.dst, SocketAddr::new(B_V6.into(), 5060));
        let wire = p.a_wire.lock().unwrap().clone();
        assert_eq!(wire.len(), 3, "3008 bytes = 1232 + 1232 + 544 at MTU 1280");
        assert!(wire.iter().all(|pkt| pkt.len() <= MTU && pkt[6] == 44), "IPv6 fragments within the wire MTU");
        let a = p.a.stats();
        assert_eq!((a.tx_packets, a.tx_fragmented, a.tx_frag_drops, a.tx_errors), (3, 1, 0, 0), "{a:?}");
        let b = p.b.stats();
        assert_eq!((b.rx_packets, b.rx_fragments, b.rx_reassembled, b.rx_reassembly_drops), (1, 3, 1, 0), "{b:?}");
        // And back, so B's fragmenter and A's reassembler are exercised too.
        sb.send_to(dg.src, &payload).unwrap();
        assert_eq!(recv(&sa).payload, payload);
        assert_eq!(p.a.stats().rx_reassembled, 1);
        // Both families at once, larger still.
        let big: Vec<u8> = (0..8000u32).map(|i| (i % 7) as u8).collect();
        sa.send_to(SocketAddr::new(B_V6.into(), 5060), &big).unwrap();
        assert_eq!(recv(&sb).payload, big);
    }

    #[test]
    fn ipv6_payload_beyond_the_stack_mtu_is_refused_up_front() {
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        let sb = p.b.bind_udp(7000).unwrap();
        // Above the wire MTU but within the stack MTU: accepted and delivered (§11.1).
        sa.send_to(SocketAddr::new(B_V6.into(), 7000), &vec![7u8; MTU - 48 + 1]).unwrap();
        assert_eq!(recv(&sb).payload.len(), MTU - 48 + 1);
        let limit = STACK_MTU - 48;
        sa.send_to(SocketAddr::new(B_V6.into(), 7000), &vec![1u8; limit]).unwrap();
        assert_eq!(recv(&sb).payload.len(), limit);
        let e = sa.send_to(SocketAddr::new(B_V6.into(), 7000), &vec![0u8; limit + 1]).unwrap_err();
        assert!(matches!(e, Error::Protocol(ref m) if m.contains("inner_mtu_stack")), "{e}");
        let e = sa.send_to(SocketAddr::new(B_V4.into(), 7000), &vec![0u8; STACK_MTU - 28 + 1]).unwrap_err();
        assert!(matches!(e, Error::Protocol(_)), "{e}");
    }

    /// Hand-built IPv6/UDP datagram `src:sport -> dst:dport` with valid checksums.
    fn ipv6_udp_packet(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        use smoltcp::wire::{Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr};
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let udp = UdpRepr { src_port: sport, dst_port: dport };
        let ip = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: smoltcp::wire::IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + ip.payload_len];
        let mut ipp = Ipv6Packet::new_unchecked(&mut buf);
        ip.emit(&mut ipp);
        let mut udpp = UdpPacket::new_unchecked(ipp.payload_mut());
        udp.emit(&mut udpp, &IpAddress::Ipv6(src), &IpAddress::Ipv6(dst), payload.len(), |b| b.copy_from_slice(payload), &caps);
        buf
    }

    #[test]
    fn burst_larger_than_the_smoltcp_socket_buffer_is_delivered_in_full() {
        // Everything queued in the device before the stack thread runs (a whole device
        // queue, 256 packets, far more than the 32 slots of a smoltcp UDP socket) must
        // reach the binding's channel: ingress is drained packet by packet.
        let (sink, _tap) = {
            let tap = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let t = Arc::clone(&tap);
            let sink: TxSink = Arc::new(move |pkt: &[u8]| {
                t.lock().unwrap().push(pkt.to_vec());
                Ok(())
            });
            (sink, tap)
        };
        let b = InnerStack::new(&assigned(Some(B_V6), None, None, None), sink, MTU, STACK_MTU).unwrap();
        let sb = b.bind_udp(6000).unwrap();
        let n = DEFAULT_RX_QUEUE_DEPTH;
        assert!(n > UDP_SOCKET_PACKETS);
        for i in 0..n {
            b.push_rx(ipv6_udp_packet(A_V6, B_V6, 40000, 6000, &(i as u32).to_be_bytes()));
        }
        assert_eq!(b.stats().rx_packets as usize, n);
        assert_eq!(b.stats().rx_queue_drops, 0);
        let t = b.spawn().unwrap();
        for i in 0..n {
            let dg = sb.recv_timeout(WAIT).unwrap().unwrap_or_else(|| panic!("datagram {i} of {n} missing"));
            assert_eq!(dg.payload, (i as u32).to_be_bytes(), "in order");
            assert_eq!(dg.src, SocketAddr::new(A_V6.into(), 40000));
        }
        let st = b.stats();
        assert_eq!((st.udp_delivered as usize, st.udp_queue_drops), (n, 0), "{st:?}");
        b.stop();
        t.join().unwrap();
    }

    #[test]
    fn send_to_then_drop_still_transmits_the_datagram() {
        // Fire-and-forget (bind, send, drop): Drop flushes the socket before removing it.
        let p = Pair::dual();
        let sb = p.b.bind_udp(5062).unwrap();
        let n = 40u32;
        for i in 0..n {
            let s = p.a.bind_udp(0).unwrap();
            s.send_to(SocketAddr::new(B_V6.into(), 5062), &i.to_be_bytes()).unwrap();
            drop(s);
        }
        let mut got: Vec<u32> = (0..n).map(|_| u32::from_be_bytes(recv(&sb).payload.try_into().unwrap())).collect();
        got.sort_unstable();
        assert_eq!(got, (0..n).collect::<Vec<_>>());
        let st = p.a.stats();
        assert_eq!((st.tx_packets, st.udp_tx_drops, st.udp_bindings), (n as u64, 0, 0), "{st:?}");
    }

    #[test]
    fn send_buffer_full_is_an_error_and_counted() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        // No stack thread: nothing drains the smoltcp tx buffer.
        let s = InnerStack::new(&assigned(Some(A_V6), None, None, None), sink, MTU, STACK_MTU).unwrap();
        let sock = s.bind_udp(0).unwrap();
        for _ in 0..UDP_SOCKET_PACKETS {
            sock.send_to(SocketAddr::new(B_V6.into(), 9), b"x").unwrap();
        }
        let e = sock.send_to(SocketAddr::new(B_V6.into(), 9), b"x").unwrap_err();
        assert!(matches!(e, Error::Protocol(ref m) if m.contains("send buffer full")), "{e}");
        assert_eq!(s.stats().udp_send_full, 1);
        // Drop flushes the 32 queued datagrams through the sink on this thread.
        drop(sock);
        let st = s.stats();
        assert_eq!((st.tx_packets, st.udp_tx_drops), (UDP_SOCKET_PACKETS as u64, 0), "{st:?}");
    }

    #[test]
    fn inner_udp_socket_is_shared_between_a_receiver_and_senders() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InnerUdpSocket>();
        assert_send_sync::<InnerStack>();
        assert_send_sync::<UdpDatagram>();

        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        let sb = p.b.bind_udp(5060).unwrap();
        let n = 20u32;
        thread::scope(|sc| {
            // One thread blocks receiving on `sb` while two others send on the same handle.
            let echo = sc.spawn(|| {
                for _ in 0..n {
                    let dg = recv(&sb);
                    sb.send_to(dg.src, &dg.payload).unwrap();
                }
            });
            let senders: Vec<_> = (0..2)
                .map(|t| {
                    let sa = &sa;
                    sc.spawn(move || {
                        for i in 0..n / 2 {
                            sa.send_to(SocketAddr::new(B_V6.into(), 5060), &(t * 100 + i).to_be_bytes()).unwrap();
                            thread::sleep(Duration::from_millis(1));
                        }
                    })
                })
                .collect();
            for s in senders {
                s.join().unwrap();
            }
            echo.join().unwrap();
        });
        let mut got: Vec<u32> = (0..n).map(|_| u32::from_be_bytes(recv(&sa).payload.try_into().unwrap())).collect();
        got.sort_unstable();
        let mut want: Vec<u32> = (0..2).flat_map(|t| (0..n / 2).map(move |i| t * 100 + i)).collect();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn icmp_echo_requests_are_answered() {
        use smoltcp::wire::{
            Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
        };
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let p = Pair::dual();
        // ICMPv6 echo request A -> B (as a P-CSCF liveness ping would arrive).
        let data = b"ping-v6";
        let req = Icmpv6Repr::EchoRequest { ident: 0x1234, seq_no: 7, data };
        let ip = Ipv6Repr { src_addr: A_V6, dst_addr: B_V6, next_header: IpProtocol::Icmpv6, payload_len: req.buffer_len(), hop_limit: 64 };
        let mut buf = vec![0u8; ip.buffer_len() + ip.payload_len];
        let mut ipp = Ipv6Packet::new_unchecked(&mut buf);
        ip.emit(&mut ipp);
        req.emit(&A_V6, &B_V6, &mut Icmpv6Packet::new_unchecked(ipp.payload_mut()), &caps);
        p.b.push_rx(buf);
        let wire = p.b_wire_after(1);
        assert_eq!(wire.len(), 1, "B answered with exactly one packet");
        let ipp = Ipv6Packet::new_checked(wire[0].as_slice()).unwrap();
        let ipr = Ipv6Repr::parse(&ipp).unwrap();
        assert_eq!((ipr.src_addr, ipr.dst_addr, ipr.next_header), (B_V6, A_V6, IpProtocol::Icmpv6));
        let reply = Icmpv6Repr::parse(&B_V6, &A_V6, &Icmpv6Packet::new_checked(ipp.payload()).unwrap(), &caps).unwrap();
        assert_eq!(reply, Icmpv6Repr::EchoReply { ident: 0x1234, seq_no: 7, data });

        // ICMPv4 echo request A -> B.
        let data4 = b"ping-v4";
        let req4 = Icmpv4Repr::EchoRequest { ident: 0x4321, seq_no: 9, data: data4 };
        let ip4 = Ipv4Repr { src_addr: A_V4, dst_addr: B_V4, next_header: IpProtocol::Icmp, payload_len: req4.buffer_len(), hop_limit: 64 };
        let mut buf4 = vec![0u8; ip4.buffer_len() + ip4.payload_len];
        let mut ipp4 = Ipv4Packet::new_unchecked(&mut buf4);
        ip4.emit(&mut ipp4, &caps);
        req4.emit(&mut Icmpv4Packet::new_unchecked(ipp4.payload_mut()), &caps);
        p.b.push_rx(buf4);
        let wire = p.b_wire_after(2);
        assert_eq!(wire.len(), 2);
        let ipp4 = Ipv4Packet::new_checked(wire[1].as_slice()).unwrap();
        let ipr4 = Ipv4Repr::parse(&ipp4, &caps).unwrap();
        assert_eq!((ipr4.src_addr, ipr4.dst_addr, ipr4.next_header), (B_V4, A_V4, IpProtocol::Icmp));
        let reply4 = Icmpv4Repr::parse(&Icmpv4Packet::new_checked(ipp4.payload()).unwrap(), &caps).unwrap();
        assert_eq!(reply4, Icmpv4Repr::EchoReply { ident: 0x4321, seq_no: 9, data: data4 });
        assert_eq!(p.b.stats().rx_packets, 2);
    }

    #[test]
    fn bind_udp_zero_picks_distinct_free_ports_and_unbinds_on_drop() {
        let p = Pair::dual();
        let s1 = p.a.bind_udp(0).unwrap();
        let s2 = p.a.bind_udp(0).unwrap();
        assert_ne!(s1.local_port(), s2.local_port());
        for s in [&s1, &s2] {
            assert!((EPHEMERAL_PORT_LO..=EPHEMERAL_PORT_HI).contains(&s.local_port()));
        }
        assert_eq!(p.a.stats().udp_bindings, 2);
        let e = p.a.bind_udp(s1.local_port()).unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::AddrInUse), "{e}");
        assert!(e.to_string().contains("already bound"), "{e}");
        let port = s1.local_port();
        drop(s1);
        assert_eq!(p.a.stats().udp_bindings, 1);
        let again = p.a.bind_udp(port).expect("port free after drop");
        assert_eq!(again.local_port(), port);
        // Explicit low ports work and a duplicate is refused.
        let dns = p.a.bind_udp(53).unwrap();
        assert_eq!(dns.local_port(), 53);
        assert!(p.a.bind_udp(53).is_err());
        assert_eq!(p.a.stats().udp_bindings, 3);
    }

    #[test]
    fn datagram_to_an_unbound_port_is_dropped_and_binding_queue_bound_counts_drops() {
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        // Unbound port on B: smoltcp answers ICMP port unreachable; nothing breaks.
        sa.send_to(SocketAddr::new(B_V6.into(), 9), b"nobody home").unwrap();
        // Bound but never drained: the channel holds UDP_QUEUE_DEPTH, then drops (counted).
        let sb = p.b.bind_udp(6000).unwrap();
        let n = UDP_QUEUE_DEPTH + 20;
        for i in 0..n {
            sa.send_to(SocketAddr::new(B_V6.into(), 6000), &(i as u32).to_be_bytes()).unwrap();
            // Pace the sends so smoltcp's 32-packet socket buffer does not fill first.
            if i % 8 == 7 {
                thread::sleep(Duration::from_millis(2));
            }
        }
        let deadline = Instant::now() + WAIT;
        while p.b.stats().udp_delivered + p.b.stats().udp_queue_drops < n as u64 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let st = p.b.stats();
        assert_eq!(st.udp_delivered, UDP_QUEUE_DEPTH as u64, "{st:?}");
        assert_eq!(st.udp_queue_drops, 20, "{st:?}");
        assert_eq!(recv(&sb).payload, 0u32.to_be_bytes());
    }

    // ---- DNS ---------------------------------------------------------------

    /// Build a DNS response to `query` (hand-encoded wire format): echoes id + question,
    /// answers with every address matching the question type (A / AAAA).
    fn dns_reply(query: &[u8], rcode: u8, answers: &[IpAddr]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let mut p = 12;
        loop {
            let l = *query.get(p)? as usize;
            p += 1;
            if l == 0 {
                break;
            }
            p += l;
        }
        let qtype = u16::from_be_bytes([*query.get(p)?, *query.get(p + 1)?]);
        let qend = p + 4;
        let question = query.get(12..qend)?;
        let matching: Vec<&IpAddr> = answers
            .iter()
            .filter(|a| matches!((qtype, a), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(&query[0..2]);
        out.extend_from_slice(&[0x81, 0x80 | (rcode & 0x0f)]); // QR, RD, RA, rcode
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&(matching.len() as u16).to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(question);
        for a in matching {
            out.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to the question
            out.extend_from_slice(&qtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes()); // IN
            out.extend_from_slice(&60u32.to_be_bytes()); // TTL
            match a {
                IpAddr::V4(v4) => {
                    out.extend_from_slice(&4u16.to_be_bytes());
                    out.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    out.extend_from_slice(&16u16.to_be_bytes());
                    out.extend_from_slice(&v6.octets());
                }
            }
        }
        Some(out)
    }

    /// The question name of a DNS query as dotted text.
    fn dns_query_name(query: &[u8]) -> String {
        let mut p = 12;
        let mut labels = Vec::new();
        while let Some(&l) = query.get(p) {
            p += 1;
            if l == 0 {
                break;
            }
            labels.push(String::from_utf8_lossy(&query[p..p + l as usize]).into_owned());
            p += l as usize;
        }
        labels.join(".")
    }

    /// A tiny DNS server on `sock` (port 53 of the far stack): answers every query with
    /// `answers` (filtered by type) and `rcode`; records the query types it saw.
    fn fake_dns_server(
        sock: InnerUdpSocket,
        answers: Vec<IpAddr>,
        rcode: u8,
        stop: Arc<AtomicBool>,
        seen: Arc<Mutex<Vec<(String, u16)>>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok(Some(dg)) = sock.recv_timeout(Duration::from_millis(50)) else { continue };
                let qtype = {
                    let mut p = 12;
                    while dg.payload.get(p).is_some_and(|&l| l != 0) {
                        p += 1 + dg.payload[p] as usize;
                    }
                    u16::from_be_bytes([dg.payload[p + 1], dg.payload[p + 2]])
                };
                seen.lock().unwrap().push((dns_query_name(&dg.payload), qtype));
                if let Some(reply) = dns_reply(&dg.payload, rcode, &answers) {
                    sock.send_to(dg.src, &reply).unwrap();
                }
            }
        })
    }

    pub(crate) struct DnsServer {
        stop: Arc<AtomicBool>,
        /// `(question name, qtype)` of every query received.
        pub(crate) seen: Arc<Mutex<Vec<(String, u16)>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl DnsServer {
        pub(crate) fn start(stack: &InnerStack, answers: Vec<IpAddr>, rcode: u8) -> DnsServer {
            let sock = stack.bind_udp(53).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let seen = Arc::new(Mutex::new(Vec::new()));
            let thread = fake_dns_server(sock, answers, rcode, Arc::clone(&stop), Arc::clone(&seen));
            DnsServer { stop, seen, thread: Some(thread) }
        }
    }

    impl Drop for DnsServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                t.join().unwrap();
            }
        }
    }

    pub(crate) const HOST: &str = "pcscf.example.test";
    pub(crate) const ANS_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x53, 0, 0, 0, 0, 0x1);
    pub(crate) const ANS_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

    #[test]
    fn dns_reply_encoder_round_trips_with_a_real_query() {
        // Query: id 0x1234, RD, 1 question "a.b" AAAA IN.
        let q = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 1, b'b', 0, 0, 28, 0, 1];
        assert_eq!(dns_query_name(&q), "a.b");
        let r = dns_reply(&q, 0, &[IpAddr::V6(ANS_V6), IpAddr::V4(ANS_V4)]).unwrap();
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(&r[2..4], &[0x81, 0x80]);
        assert_eq!(&r[6..8], &[0, 1], "one AAAA answer, the A record filtered out");
        assert_eq!(r.len(), 12 + 9 + 2 + 2 + 2 + 4 + 2 + 16);
        assert!(dns_reply(&q[..10], 0, &[]).is_none(), "runt query");
    }

    #[test]
    fn resolve_returns_aaaa_then_a_from_a_dns_server_over_the_tunnel() {
        let p = Pair::dual();
        let server = DnsServer::start(&p.b, vec![IpAddr::V6(ANS_V6), IpAddr::V4(ANS_V4)], 0);
        let addrs = p.a.resolve(HOST, WAIT).unwrap();
        assert_eq!(addrs, vec![IpAddr::V6(ANS_V6), IpAddr::V4(ANS_V4)]);
        let seen = server.seen.lock().unwrap().clone();
        assert!(seen.contains(&(HOST.to_string(), 28)) && seen.contains(&(HOST.to_string(), 1)), "{seen:?}");
        assert_eq!(p.a.stats().dns_queries, 2);
        assert_eq!(p.a.pending_dns_queries(), 0);
        // A trailing dot is accepted; the slot is recycled for the next lookup.
        assert_eq!(p.a.resolve(&format!("{HOST}."), WAIT).unwrap().len(), 2);
    }

    #[test]
    fn resolve_skips_the_family_without_an_inner_address() {
        // A is IPv6-only: only the AAAA query is issued (the A query would fail anyway).
        let p = Pair::new(assigned(Some(A_V6), None, Some(B_V6), None), assigned(Some(B_V6), Some(B_V4), None, None));
        let server = DnsServer::start(&p.b, vec![IpAddr::V6(ANS_V6), IpAddr::V4(ANS_V4)], 0);
        let addrs = p.a.resolve(HOST, WAIT).unwrap();
        assert_eq!(addrs, vec![IpAddr::V6(ANS_V6)]);
        let seen = server.seen.lock().unwrap().clone();
        assert_eq!(seen, vec![(HOST.to_string(), 28)]);
    }

    #[test]
    fn resolve_with_only_an_a_record_still_succeeds() {
        // AAAA gets an empty NOERROR answer (smoltcp reports Failed), A answers.
        let p = Pair::dual();
        let _server = DnsServer::start(&p.b, vec![IpAddr::V4(ANS_V4)], 0);
        assert_eq!(p.a.resolve(HOST, WAIT).unwrap(), vec![IpAddr::V4(ANS_V4)]);
    }

    #[test]
    fn resolve_reports_nxdomain_as_protocol_error() {
        let p = Pair::dual();
        let _server = DnsServer::start(&p.b, vec![], 3);
        let e = p.a.resolve("nope.example.test", WAIT).unwrap_err();
        assert!(matches!(e, Error::Protocol(_)), "{e}");
        assert_eq!(p.a.pending_dns_queries(), 0);
    }

    #[test]
    fn resolve_reports_a_silent_server_as_timeout_after_smoltcp_gives_up() {
        // With a caller timeout beyond smoltcp's 10 s per-server retransmit timeout,
        // smoltcp itself reports the query as Failed; that is still a Timeout to us.
        let p = Pair::new(assigned(Some(A_V6), None, Some(B_V6), None), assigned(Some(B_V6), None, None, None));
        let started = Instant::now();
        let e = p.a.resolve(HOST, SMOLTCP_DNS_RETRANSMIT_TIMEOUT + Duration::from_secs(4)).unwrap_err();
        let elapsed = started.elapsed();
        assert!(matches!(e, Error::Timeout(_)), "{e} after {elapsed:?}");
        assert!(elapsed >= SMOLTCP_DNS_RETRANSMIT_TIMEOUT && elapsed < SMOLTCP_DNS_RETRANSMIT_TIMEOUT + Duration::from_secs(3), "{elapsed:?}");
        assert_eq!(p.a.pending_dns_queries(), 0);
        assert!(p.a.stats().tx_packets >= 2, "the query was retransmitted");
        // A negative answer within that window is still a Protocol error.
        let _server = DnsServer::start(&p.b, vec![], 3);
        assert!(matches!(p.a.resolve(HOST, WAIT).unwrap_err(), Error::Protocol(_)));
    }

    #[test]
    fn resolve_times_out_cleanly_when_nothing_answers() {
        let p = Pair::dual();
        let started = Instant::now();
        let e = p.a.resolve(HOST, Duration::from_millis(300)).unwrap_err();
        assert!(matches!(e, Error::Timeout(_)), "{e}");
        assert!(started.elapsed() < Duration::from_secs(2), "returned promptly: {:?}", started.elapsed());
        assert_eq!(p.a.pending_dns_queries(), 0, "timed-out queries are cancelled");
        assert!(p.a.stats().tx_packets >= 1, "the query was actually sent");
        // The stack is still healthy afterwards.
        let _server = DnsServer::start(&p.b, vec![IpAddr::V6(ANS_V6)], 0);
        assert_eq!(p.a.resolve(HOST, WAIT).unwrap(), vec![IpAddr::V6(ANS_V6)]);
    }

    #[test]
    fn resolve_input_errors() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        let no_dns = InnerStack::new(&assigned(Some(A_V6), None, None, None), sink.clone(), MTU, STACK_MTU).unwrap();
        assert!(matches!(no_dns.resolve(HOST, WAIT).unwrap_err(), Error::Config(_)));
        let no_addr = InnerStack::new(&assigned(None, None, Some(B_V6), None), sink.clone(), MTU, STACK_MTU).unwrap();
        assert!(matches!(no_addr.resolve(HOST, WAIT).unwrap_err(), Error::Config(_)));
        let ok = InnerStack::new(&assigned(Some(A_V6), None, Some(B_V6), None), sink, MTU, STACK_MTU).unwrap();
        assert!(matches!(ok.resolve("", WAIT).unwrap_err(), Error::Config(_)));
        assert!(matches!(ok.resolve("a..b", WAIT).unwrap_err(), Error::Config(_)));
        let long = format!("{}.example", "x".repeat(64));
        assert!(matches!(ok.resolve(&long, WAIT).unwrap_err(), Error::Config(_)));
        assert_eq!(ok.pending_dns_queries(), 0);
    }

    // ---- lifecycle ---------------------------------------------------------

    #[test]
    fn stop_fails_every_pending_operation_with_closed() {
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        // A resolve that would time out in 10 s is cut short by the stop.
        let resolver = {
            let a = p.a.clone();
            thread::spawn(move || (a.resolve(HOST, Duration::from_secs(10)), Instant::now()))
        };
        // A receiver parked on its own long timeout must wake from the close itself,
        // not from that timeout: the SIP transport above closes on this error, and the
        // registration must not hang on for another ten seconds (DESIGN §17.6).
        let receiver = {
            let sa = p.a.bind_udp(0).unwrap();
            thread::spawn(move || (sa.recv_timeout(Duration::from_secs(10)), Instant::now()))
        };
        thread::sleep(Duration::from_millis(50));
        let closed_at = Instant::now();
        p.a.close("tunnel torn down");
        assert!(p.a.is_closed());
        let (r, woke_at) = resolver.join().unwrap();
        let e = r.unwrap_err();
        assert!(matches!(e, Error::Closed(ref r) if r == "tunnel torn down"), "{e}");
        assert!(woke_at.duration_since(closed_at) < Duration::from_secs(2), "resolver woke at its own timeout");
        let (r, woke_at) = receiver.join().unwrap();
        assert!(matches!(r, Err(Error::Closed(ref r)) if r == "tunnel torn down"), "{r:?}");
        assert!(woke_at.duration_since(closed_at) < Duration::from_secs(2), "receiver woke at its own timeout");
        let e = sa.send_to(SocketAddr::new(B_V6.into(), 1), b"x").unwrap_err();
        assert!(matches!(e, Error::Closed(_)), "{e}");
        let e = sa.recv_timeout(Duration::from_millis(10)).unwrap_err();
        assert!(matches!(e, Error::Closed(ref r) if r == "tunnel torn down"), "{e}");
        assert!(matches!(p.a.bind_udp(0).unwrap_err(), Error::Closed(_)));
        assert!(matches!(p.a.resolve(HOST, WAIT).unwrap_err(), Error::Closed(_)));
        assert_eq!(p.a.stats().udp_bindings, 0);
        p.a.push_rx(vec![0x60; 40]); // ignored after close, no panic
        drop(sa);
    }

    /// Regression (finding: the close blocked behind the poll mutex): the stack thread
    /// holds `State` across its whole poll, and the poll drives the TX sink — a BLOCKING
    /// outer ESP send bounded only by the socket write timeout, several packets per poll. A close
    /// used to take that same mutex before it could drop the receive channels, so a
    /// blocked `recv_timeout` woke seconds late (or at its own timeout) although
    /// `mark_dead` promises "immediately" (DESIGN §17.6).
    #[test]
    fn close_wakes_a_blocked_receiver_while_the_stack_thread_is_in_a_slow_send() {
        let in_sink = Arc::new(AtomicBool::new(false));
        let sink: TxSink = {
            let in_sink = Arc::clone(&in_sink);
            Arc::new(move |_: &[u8]| {
                in_sink.store(true, Ordering::SeqCst);
                // Stands in for a congested outer socket blocking until its write timeout.
                thread::sleep(Duration::from_millis(1500));
                Ok(())
            })
        };
        let s = InnerStack::new(&assigned(Some(A_V6), None, Some(B_V6), None), sink, MTU, STACK_MTU).unwrap();
        let t = s.spawn().unwrap();
        let sock = s.bind_udp(0).unwrap();
        let receiver = {
            let sock = s.bind_udp(0).unwrap();
            thread::spawn(move || (sock.recv_timeout(Duration::from_secs(10)), Instant::now()))
        };
        // Get the stack thread into the sink, holding `State`.
        sock.send_to(SocketAddr::new(B_V6.into(), 5060), b"hello").unwrap();
        let deadline = Instant::now() + WAIT;
        while !in_sink.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(in_sink.load(Ordering::SeqCst), "the stack thread never reached the sink");
        let closed_at = Instant::now();
        let closer = {
            let s = s.clone();
            thread::spawn(move || {
                s.close("gateway stopped answering");
                Instant::now()
            })
        };
        let (r, woke_at) = receiver.join().unwrap();
        assert!(matches!(r, Err(Error::Closed(ref why)) if why == "gateway stopped answering"), "{r:?}");
        assert!(
            woke_at.duration_since(closed_at) < Duration::from_secs(1),
            "the receiver waited {:?} for the poll to finish",
            woke_at.duration_since(closed_at)
        );
        // The reason is readable at once too, without the poll mutex.
        assert!(s.is_closed());
        closer.join().unwrap();
        drop(sock);
        t.join().unwrap();
    }

    #[test]
    fn stack_thread_survives_a_failing_sink_and_counts_errors() {
        let errors = Arc::new(AtomicU64::new(0));
        let sink: TxSink = {
            let errors = Arc::clone(&errors);
            Arc::new(move |_: &[u8]| {
                errors.fetch_add(1, Ordering::SeqCst);
                Err(Error::Protocol("ESP not ready".into()))
            })
        };
        let s = InnerStack::new(&assigned(Some(A_V6), None, Some(B_V6), None), sink, MTU, STACK_MTU).unwrap();
        let t = s.spawn().unwrap();
        let sock = s.bind_udp(0).unwrap();
        sock.send_to(SocketAddr::new(B_V6.into(), 5060), b"hello").unwrap();
        let deadline = Instant::now() + WAIT;
        while s.stats().tx_errors == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(s.stats().tx_errors, 1);
        assert_eq!(errors.load(Ordering::SeqCst), 1);
        s.stop();
        t.join().unwrap();
    }

    #[test]
    fn stack_thread_panic_closes_the_stack_instead_of_stranding_waiters() {
        let sink: TxSink = Arc::new(|_: &[u8]| -> Result<()> { panic!("sink exploded") });
        let s = InnerStack::new(&assigned(Some(A_V6), None, Some(B_V6), None), sink, MTU, STACK_MTU).unwrap();
        let t = s.spawn().unwrap();
        let sock = s.bind_udp(0).unwrap();
        let resolver = {
            let s = s.clone();
            thread::spawn(move || s.resolve(HOST, Duration::from_secs(10)))
        };
        // The resolver's query drives the panicking sink on the stack thread.
        t.join().expect("the guard catches the panic");
        assert!(s.is_closed());
        let e = resolver.join().unwrap().unwrap_err();
        assert!(matches!(e, Error::Closed(ref r) if r.contains("panicked")), "{e}");
        let e = sock.recv_timeout(Duration::from_millis(10)).unwrap_err();
        assert!(matches!(e, Error::Closed(ref r) if r.contains("sink exploded")), "{e}");
        assert!(matches!(s.bind_udp(0).unwrap_err(), Error::Closed(_)));
    }

    #[test]
    fn garbage_and_foreign_packets_are_dropped_without_harm() {
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        p.b.push_rx(vec![]);
        p.b.push_rx(vec![0x45, 0, 0]); // runt IPv4
        p.b.push_rx(vec![0xff; 60]); // bad version nibble
        // IPv6 to an address B does not own.
        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        v6[5] = 8;
        v6[6] = 17;
        v6[7] = 64;
        v6[8..24].copy_from_slice(&A_V6.octets());
        v6[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0xc, 0, 0, 0, 0, 1).octets());
        p.b.push_rx(v6);
        // Then a real exchange still works.
        let sb = p.b.bind_udp(4444).unwrap();
        sa.send_to(SocketAddr::new(B_V6.into(), 4444), b"still alive").unwrap();
        assert_eq!(recv(&sb).payload, b"still alive");
        assert_eq!(p.b.stats().rx_packets, 5);
    }

    // ---- TCP over the loopback (§11.2) ------------------------------------------

    /// Poll `cond` every 5 ms until it holds; panics with `what` after `within`.
    fn wait_until(within: Duration, what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + within;
        while !cond() {
            assert!(Instant::now() < deadline, "{what}: not within {within:?}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// B listens on an ephemeral port, A connects to B's inner address of the family,
    /// B accepts: `(A's stream, B's stream, B's listener)`.
    fn tcp_connection(p: &Pair, v6: bool) -> (InnerTcpStream, InnerTcpStream, InnerTcpListener) {
        let listener = p.b.listen_tcp(0).unwrap();
        let b_ip: IpAddr = if v6 { B_V6.into() } else { B_V4.into() };
        let client = p.a.connect_tcp(SocketAddr::new(b_ip, listener.local_port()), WAIT).unwrap();
        let (server, peer) = listener.accept_timeout(WAIT).unwrap().expect("accepted within the wait");
        assert_eq!(peer, client.local_addr());
        (client, server, listener)
    }

    fn write_all(stream: &InnerTcpStream, mut data: &[u8]) {
        while !data.is_empty() {
            let n = stream.write(data).unwrap_or_else(|e| panic!("write with {} bytes left: {e}", data.len()));
            assert!(n > 0);
            data = &data[n..];
        }
    }

    /// Read exactly `n` bytes (EOF first panics).
    fn read_n(stream: &InnerTcpStream, n: usize) -> Vec<u8> {
        let mut got = Vec::with_capacity(n);
        let mut buf = vec![0u8; 16 * 1024];
        while got.len() < n {
            let want = (n - got.len()).min(buf.len());
            let r = stream.read(&mut buf[..want]).unwrap_or_else(|e| panic!("read after {} of {n} bytes: {e}", got.len()));
            assert_ne!(r, 0, "EOF after {} of {n} bytes", got.len());
            got.extend_from_slice(&buf[..r]);
        }
        got
    }

    /// `(flags, seq, ack?, MSS option, payload length)` of the TCP segment in `pkt`, if it
    /// is one (IPv6 or unfragmented IPv4), parsed and checksum-verified by smoltcp.
    fn tcp_summary(pkt: &[u8]) -> Option<(smoltcp::wire::TcpControl, i32, bool, Option<u16>, usize)> {
        use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, TcpRepr};
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let (src, dst, segment) = match pkt.first()? >> 4 {
            6 => {
                let ip = Ipv6Packet::new_checked(pkt).ok()?;
                (ip.next_header() == IpProtocol::Tcp).then_some(())?;
                (IpAddress::Ipv6(ip.src_addr()), IpAddress::Ipv6(ip.dst_addr()), &pkt[40..40 + usize::from(ip.payload_len())])
            }
            4 => {
                let ip = Ipv4Packet::new_checked(pkt).ok()?;
                (ip.next_header() == IpProtocol::Tcp && !ip.more_frags() && ip.frag_offset() == 0).then_some(())?;
                let range = usize::from(ip.header_len())..usize::from(ip.total_len());
                (IpAddress::Ipv4(ip.src_addr()), IpAddress::Ipv4(ip.dst_addr()), &pkt[range])
            }
            _ => return None,
        };
        let tcp = TcpPacket::new_checked(segment).ok()?;
        let r = TcpRepr::parse(&tcp, &src, &dst, &caps).ok()?;
        Some((r.control, r.seq_number.0, r.ack_number.is_some(), r.max_seg_size, r.payload.len()))
    }

    /// Hand-built IPv6 TCP SYN `src:sport -> dst:dport` with initial sequence `seq` and
    /// MSS 1220, valid checksums.
    fn ipv6_tcp_syn(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, seq: i32) -> Vec<u8> {
        use smoltcp::wire::{IpProtocol, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let tcp = TcpRepr {
            src_port: sport,
            dst_port: dport,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(seq),
            ack_number: None,
            window_len: 8192,
            window_scale: None,
            max_seg_size: Some(1220),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv6Repr { src_addr: src, dst_addr: dst, next_header: IpProtocol::Tcp, payload_len: tcp.buffer_len(), hop_limit: 64 };
        let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf));
        tcp.emit(&mut TcpPacket::new_unchecked(&mut buf[40..]), &IpAddress::Ipv6(src), &IpAddress::Ipv6(dst), &caps);
        buf
    }

    #[test]
    fn tcp_connect_accept_and_echo_both_ways_ipv6_and_ipv4() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InnerTcpStream>();
        assert_send_sync::<InnerTcpListener>();

        let p = Pair::dual();
        for v6 in [true, false] {
            let (client, server, listener) = tcp_connection(&p, v6);
            let (a_ip, b_ip): (IpAddr, IpAddr) = if v6 { (A_V6.into(), B_V6.into()) } else { (A_V4.into(), B_V4.into()) };
            // Exact endpoints on both sides: smoltcp's source address for the family, an
            // ephemeral source port, the listener's port.
            assert_eq!(client.local_addr().ip(), a_ip);
            assert!((EPHEMERAL_PORT_LO..=EPHEMERAL_PORT_HI).contains(&client.local_addr().port()));
            assert_eq!(client.peer_addr(), SocketAddr::new(b_ip, listener.local_port()));
            assert_eq!(server.local_addr(), client.peer_addr());
            assert_eq!(server.peer_addr(), client.local_addr());
            assert_eq!(listener.local_addr(), SocketAddr::new(B_V6.into(), listener.local_port()), "first inner address");
            write_all(&client, b"REGISTER sip:example.test SIP/2.0\r\n\r\n");
            assert_eq!(read_n(&server, 37), b"REGISTER sip:example.test SIP/2.0\r\n\r\n");
            write_all(&server, b"SIP/2.0 200 OK\r\n\r\n");
            assert_eq!(read_n(&client, 18), b"SIP/2.0 200 OK\r\n\r\n");
            // Echo many small messages both ways (Nagle on and off).
            client.set_nodelay(true).unwrap();
            for i in 0..50u32 {
                write_all(&client, &i.to_be_bytes());
                let got = read_n(&server, 4);
                write_all(&server, &got);
                assert_eq!(read_n(&client, 4), i.to_be_bytes());
            }
        }
        let (a, b) = (p.a.stats(), p.b.stats());
        assert_eq!((a.tcp_connections_opened, b.tcp_accepted), (2, 2), "{a:?} {b:?}");
        assert_eq!(a.tcp_tx_bytes, 2 * (37 + 200), "{a:?}");
        assert_eq!(a.tcp_rx_bytes, 2 * (18 + 200), "{a:?}");
        assert_eq!((b.tcp_tx_bytes, b.tcp_rx_bytes), (a.tcp_rx_bytes, a.tcp_tx_bytes), "{b:?}");
    }

    #[test]
    fn tcp_100_kib_each_way_fits_the_wire_mtu_without_fragmentation_and_with_backpressure() {
        let p = Pair::dual();
        for v6 in [true, false] {
            let (client, server, _listener) = tcp_connection(&p, v6);
            // Bounded, so a failed assertion below cannot leave the scope waiting forever.
            client.set_write_timeout(Some(WAIT)).unwrap();
            server.set_write_timeout(Some(WAIT)).unwrap();
            let data: Vec<u8> = (0..100 * 1024u32).map(|i| (i % 251) as u8).collect();
            let before = p.a.stats().tcp_tx_bytes;
            thread::scope(|sc| {
                let writer = sc.spawn(|| write_all(&client, &data));
                // Nobody reads yet: the writer stalls once B's receive window and then A's
                // send buffer (32 KiB each) are full — exactly 64 KiB accepted.
                thread::sleep(Duration::from_millis(300));
                assert!(!writer.is_finished(), "100 KiB cannot fit 2 x {TCP_BUFFER_BYTES} bytes of buffering");
                let queued = p.a.stats().tcp_tx_bytes - before;
                assert_eq!(queued, 2 * TCP_BUFFER_BYTES as u64, "v6={v6}: the write blocks on a full window");
                assert_eq!(read_n(&server, data.len()), data, "v6={v6}: 100 KiB intact and in order");
                writer.join().unwrap();
            });
            // And back the other way.
            thread::scope(|sc| {
                let writer = sc.spawn(|| write_all(&server, &data));
                assert_eq!(read_n(&client, data.len()), data);
                writer.join().unwrap();
            });
        }
        // Every segment fit the wire MTU (each sink asserts it) WITHOUT IP fragmentation:
        // both SYNs announced the wire MSS, so full segments are exactly 1280 bytes.
        for (name, stats, wire) in [("a", p.a.stats(), p.a_wire.lock().unwrap().clone()), ("b", p.b.stats(), p.b_wire.lock().unwrap().clone())] {
            assert_eq!((stats.tx_fragmented, stats.tx_frag_drops, stats.rx_fragments), (0, 0, 0), "{name}: {stats:?}");
            assert_eq!(wire.iter().map(Vec::len).max(), Some(MTU), "{name}: full-sized segments are wire-sized");
            let syns: Vec<_> = wire.iter().filter_map(|pkt| tcp_summary(pkt)).filter(|t| t.0 == smoltcp::wire::TcpControl::Syn).collect();
            let mss: Vec<_> = syns.iter().map(|t| t.3).collect();
            assert_eq!(mss, vec![Some(1220), Some(1240)], "{name}: one SYN (or SYN-ACK) per family, MSS clamped to the wire");
            assert_eq!(stats.tcp_mss_clamped, 2, "{name}: our own two SYNs were clamped, the peer's arrived clamped already");
            let biggest = wire.iter().filter_map(|pkt| tcp_summary(pkt)).map(|t| t.4).max();
            assert_eq!(biggest, Some(1240), "{name}: the largest payload is the IPv4 MSS");
        }
    }

    #[test]
    fn tcp_eof_after_the_peer_shuts_down_and_writes_after_shutdown_fail() {
        let p = Pair::dual();
        let (client, server, _listener) = tcp_connection(&p, true);
        write_all(&client, b"last words");
        client.shutdown().unwrap();
        client.shutdown().unwrap(); // idempotent
        // The data before the FIN is read in full, then EOF — repeatedly.
        assert_eq!(read_n(&server, 10), b"last words");
        server.set_read_timeout(Some(WAIT)).unwrap();
        assert_eq!(server.read(&mut [0u8; 16]).unwrap(), 0, "EOF after the peer's FIN");
        assert_eq!(server.read(&mut [0u8; 16]).unwrap(), 0, "EOF stays EOF");
        // The half-closed side can still write until it shuts down too...
        write_all(&server, b"bye");
        server.shutdown().unwrap();
        // ...but our own reads after shutdown are EOF and writes fail with BrokenPipe.
        assert_eq!(client.read(&mut [0u8; 16]).unwrap(), 0, "shut down: EOF");
        let e = client.write(b"x").unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::BrokenPipe), "{e}");
        let e = server.write(b"x").unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::BrokenPipe), "{e}");
        assert_eq!(server.read(&mut []).unwrap(), 0, "an empty buffer reads nothing");
    }

    #[test]
    fn tcp_read_timeout_expires_and_no_timeout_waits_for_data() {
        let p = Pair::dual();
        let (client, server, listener) = tcp_connection(&p, true);
        server.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let started = Instant::now();
        let e = server.read(&mut [0u8; 8]).unwrap_err();
        assert!(matches!(e, Error::Timeout(_)), "{e}");
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(190) && waited < Duration::from_secs(2), "{waited:?}");
        // No timeout: the read waits as long as it takes for data to arrive.
        server.set_read_timeout(None).unwrap();
        thread::scope(|sc| {
            let reader = sc.spawn(|| {
                let mut buf = [0u8; 8];
                let n = server.read(&mut buf).unwrap();
                (buf[..n].to_vec(), Instant::now())
            });
            thread::sleep(Duration::from_millis(300));
            let sent = Instant::now();
            write_all(&client, b"late");
            let (got, at) = reader.join().unwrap();
            assert_eq!(got, b"late");
            assert!(at >= sent);
        });
        // accept_timeout(Duration::MAX) is "until a connection arrives", not a panic.
        thread::scope(|sc| {
            let acceptor = sc.spawn(|| listener.accept_timeout(Duration::MAX));
            thread::sleep(Duration::from_millis(50));
            let c2 = p.a.connect_tcp(SocketAddr::new(B_V6.into(), listener.local_port()), Duration::MAX).unwrap();
            let (_s2, peer) = acceptor.join().unwrap().unwrap().expect("accepted");
            assert_eq!(peer, c2.local_addr());
        });
        // The zero timeout is refused, as by std.
        assert!(matches!(server.set_read_timeout(Some(Duration::ZERO)), Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::InvalidInput));
    }

    #[test]
    fn tcp_connect_to_a_port_nobody_listens_on_is_refused_at_once() {
        let p = Pair::dual();
        for dst in [SocketAddr::new(B_V6.into(), 5999), SocketAddr::new(B_V4.into(), 5999)] {
            let started = Instant::now();
            let e = p.a.connect_tcp(dst, WAIT).unwrap_err();
            assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::ConnectionRefused), "{dst}: {e}");
            assert!(started.elapsed() < Duration::from_secs(1), "{dst}: refused only after {:?}", started.elapsed());
        }
        let st = p.a.stats();
        assert_eq!((st.tcp_sockets, st.tcp_connections_opened), (0, 0), "a refused socket is freed at once: {st:?}");
        // No family, no address: refused up front, and so is a port of 0.
        let v6_only = Pair::new(assigned(Some(A_V6), None, None, None), assigned(Some(B_V6), Some(B_V4), None, None));
        let e = v6_only.a.connect_tcp(SocketAddr::new(B_V4.into(), 5060), WAIT).unwrap_err();
        assert!(matches!(e, Error::Config(ref m) if m.contains("IPv4")), "{e}");
        let e = p.a.connect_tcp(SocketAddr::new(B_V6.into(), 0), WAIT).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
    }

    #[test]
    fn tcp_connect_times_out_when_the_syns_are_lost() {
        let p = Pair::dual();
        let listener = p.b.listen_tcp(5060).unwrap();
        p.a_ctl.blackhole.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let e = p.a.connect_tcp(SocketAddr::new(B_V6.into(), 5060), Duration::from_millis(300)).unwrap_err();
        let waited = started.elapsed();
        assert!(matches!(e, Error::Timeout(_)), "{e}");
        assert!(waited >= Duration::from_millis(290) && waited < Duration::from_secs(2), "{waited:?}");
        let syns = p.a_wire.lock().unwrap().iter().filter_map(|pkt| tcp_summary(pkt)).filter(|t| t.0 == smoltcp::wire::TcpControl::Syn).count();
        assert!(syns >= 1, "the SYN was sent (and eaten)");
        assert_eq!(p.a.stats().tcp_sockets, 0, "the abandoned socket is freed");
        // The path comes back: the next connect works and the listener saw nothing stale.
        p.a_ctl.blackhole.store(false, Ordering::SeqCst);
        let client = p.a.connect_tcp(SocketAddr::new(B_V6.into(), 5060), WAIT).unwrap();
        let (server, peer) = listener.accept_timeout(WAIT).unwrap().expect("accepted");
        assert_eq!(peer, client.local_addr());
        write_all(&client, b"ok");
        assert_eq!(read_n(&server, 2), b"ok");
        assert!(listener.accept_timeout(Duration::from_millis(100)).unwrap().is_none(), "exactly one connection");
    }

    #[test]
    fn tcp_lost_syn_ack_is_recovered_by_retransmission_with_exactly_one_connection() {
        let p = Pair::dual();
        let listener = p.b.listen_tcp(5060).unwrap();
        let syn_acks = || {
            p.b_wire.lock().unwrap().iter().filter_map(|pkt| tcp_summary(pkt)).filter(|t| t.0 == smoltcp::wire::TcpControl::Syn && t.2).count()
        };
        // B's answers are lost until A has retransmitted its SYN.
        p.b_ctl.blackhole.store(true, Ordering::SeqCst);
        thread::scope(|sc| {
            let connector = sc.spawn(|| p.a.connect_tcp(SocketAddr::new(B_V6.into(), 5060), Duration::from_secs(15)));
            wait_until(WAIT, "B answers the first SYN", || syn_acks() >= 1);
            // A's retransmission (1 s RTO) reaches B while its first slot is in
            // SYN-RECEIVED: it must not open a second half-connection on the other slot.
            wait_until(WAIT, "A's SYN retransmission reaches B", || p.b.stats().tcp_dup_syn_drops >= 1);
            p.b_ctl.blackhole.store(false, Ordering::SeqCst);
            // B's own SYN-ACK retransmission completes the handshake.
            let client = connector.join().unwrap().expect("connected after the retransmissions");
            let (server, peer) = listener.accept_timeout(WAIT).unwrap().expect("accepted");
            assert_eq!(peer, client.local_addr());
            write_all(&client, b"one");
            assert_eq!(read_n(&server, 3), b"one");
            write_all(&server, b"two");
            assert_eq!(read_n(&client, 3), b"two");
        });
        assert!(listener.accept_timeout(Duration::from_millis(200)).unwrap().is_none(), "exactly one connection");
        let isns: Vec<i32> =
            p.b_wire.lock().unwrap().iter().filter_map(|pkt| tcp_summary(pkt)).filter(|t| t.0 == smoltcp::wire::TcpControl::Syn).map(|t| t.1).collect();
        assert!(isns.len() >= 2 && isns.iter().all(|isn| *isn == isns[0]), "every SYN-ACK of the one handshake: {isns:?}");
    }

    #[test]
    fn tcp_accept_timeout_without_a_client_returns_none() {
        let p = Pair::dual();
        let listener = p.b.listen_tcp(0).unwrap();
        let started = Instant::now();
        assert!(listener.accept_timeout(Duration::from_millis(150)).unwrap().is_none());
        assert!(started.elapsed() >= Duration::from_millis(140), "{:?}", started.elapsed());
        assert!(listener.accept_timeout(Duration::ZERO).unwrap().is_none());
        assert_eq!(p.b.stats().tcp_sockets, TCP_LISTEN_BACKLOG as u64);
    }

    #[test]
    fn tcp_listener_backlog_takes_two_connections_and_is_refilled_on_accept() {
        let p = Pair::dual();
        let listener = p.b.listen_tcp(5060).unwrap();
        let to = SocketAddr::new(B_V6.into(), 5060);
        // Both backlog slots complete their handshakes before anything is accepted...
        let c1 = p.a.connect_tcp(to, WAIT).unwrap();
        let c2 = p.a.connect_tcp(to, WAIT).unwrap();
        // ...and a third SYN finds no listening socket: RST, like a full accept queue.
        let e = p.a.connect_tcp(to, WAIT).unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::ConnectionRefused), "{e}");
        // Accepting one refills its slot at once, so the next connect succeeds.
        let (s1, peer1) = listener.accept_timeout(WAIT).unwrap().expect("first");
        let c3 = p.a.connect_tcp(to, WAIT).unwrap();
        let (s2, peer2) = listener.accept_timeout(WAIT).unwrap().expect("second");
        let (s3, peer3) = listener.accept_timeout(WAIT).unwrap().expect("third");
        assert!(listener.accept_timeout(Duration::from_millis(50)).unwrap().is_none(), "nothing else pending");
        let mut peers = vec![peer1, peer2, peer3];
        peers.sort();
        let mut locals = vec![c1.local_addr(), c2.local_addr(), c3.local_addr()];
        locals.sort();
        assert_eq!(peers, locals, "each connection accepted exactly once");
        // Each accepted stream talks to its own client.
        for (client, server) in [&c1, &c2, &c3].into_iter().filter_map(|c| {
            [&s1, &s2, &s3].into_iter().find(|s| s.peer_addr() == c.local_addr()).map(|s| (c, s))
        }) {
            write_all(client, &client.local_addr().port().to_be_bytes());
            assert_eq!(read_n(server, 2), client.local_addr().port().to_be_bytes());
        }
        let (a, b) = (p.a.stats(), p.b.stats());
        assert_eq!((a.tcp_connections_opened, b.tcp_accepted), (3, 3), "{a:?} {b:?}");
        assert_eq!(b.tcp_sockets, 3 + TCP_LISTEN_BACKLOG as u64, "three streams and a full backlog: {b:?}");
    }

    #[test]
    fn tcp_listening_on_a_taken_port_is_addr_in_use() {
        let p = Pair::dual();
        let l = p.b.listen_tcp(5060).unwrap();
        let e = p.b.listen_tcp(5060).unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::AddrInUse), "{e}");
        assert!(e.to_string().contains("already in use"), "{e}");
        // UDP and TCP port spaces are separate.
        let _udp = p.b.bind_udp(5060).unwrap();
        // Ephemeral listeners get distinct ports.
        let (e1, e2) = (p.b.listen_tcp(0).unwrap(), p.b.listen_tcp(0).unwrap());
        assert_ne!(e1.local_port(), e2.local_port());
        assert!([e1.local_port(), e2.local_port()].iter().all(|port| (EPHEMERAL_PORT_LO..=EPHEMERAL_PORT_HI).contains(port)));
        // The local port of an outbound connection is taken too.
        let out_listener = p.a.listen_tcp(0).unwrap();
        let out = p.b.connect_tcp(SocketAddr::new(A_V6.into(), out_listener.local_port()), WAIT).unwrap();
        let e = p.b.listen_tcp(out.local_addr().port()).unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::AddrInUse), "{e}");
        // Dropping the listener frees the port.
        drop(l);
        let again = p.b.listen_tcp(5060).expect("port free after drop");
        assert_eq!(again.local_port(), 5060);
    }

    #[test]
    fn tcp_dropped_streams_are_reaped_once_the_close_handshake_is_over() {
        let p = Pair::dual();
        let (client, server, listener) = tcp_connection(&p, true);
        write_all(&client, b"x");
        assert_eq!(read_n(&server, 1), b"x");
        assert_eq!((p.a.stats().tcp_sockets, p.b.stats().tcp_sockets), (1, 1 + TCP_LISTEN_BACKLOG as u64));
        // A closes first (FIN-WAIT, then TIME-WAIT); B reads EOF and closes (LAST-ACK).
        drop(client);
        server.set_read_timeout(Some(WAIT)).unwrap();
        assert_eq!(server.read(&mut [0u8; 4]).unwrap(), 0);
        drop(server);
        // B's socket is done as soon as A acknowledges its FIN.
        wait_until(Duration::from_secs(3), "B reaps its LAST-ACK socket", || p.b.stats().tcp_sockets == TCP_LISTEN_BACKLOG as u64);
        // A's waits out smoltcp's 10 s TIME-WAIT first.
        wait_until(Duration::from_secs(15), "A reaps its TIME-WAIT socket", || p.a.stats().tcp_sockets == 0);
        drop(listener);
        assert_eq!(p.b.stats().tcp_sockets, 0, "the listener's backlog slots go with it");
        let a = p.a.stats();
        assert_eq!(a.tcp_connections_opened, 1, "{a:?}");
    }

    #[test]
    fn tcp_dropping_a_listener_resets_the_connections_nobody_accepted() {
        let p = Pair::dual();
        let listener = p.b.listen_tcp(0).unwrap();
        let client = p.a.connect_tcp(SocketAddr::new(B_V6.into(), listener.local_port()), WAIT).unwrap();
        drop(listener);
        client.set_read_timeout(Some(WAIT)).unwrap();
        let e = client.read(&mut [0u8; 8]).unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::ConnectionReset), "{e}");
        let e = client.write(b"x").unwrap_err();
        assert!(matches!(e, Error::Io(ref io) if io.kind() == io::ErrorKind::ConnectionReset), "{e}");
        wait_until(Duration::from_secs(3), "B frees the reset socket", || p.b.stats().tcp_sockets == 0);
        drop(client);
        wait_until(Duration::from_secs(3), "A frees the dead socket", || p.a.stats().tcp_sockets == 0);
    }

    #[test]
    fn tcp_retransmitted_syn_never_reaches_a_listening_backlog_slot() {
        // B alone, its transmissions captured: SYNs are pushed in by hand.
        let tap = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let sink: TxSink = {
            let tap = Arc::clone(&tap);
            Arc::new(move |pkt: &[u8]| {
                tap.lock().unwrap().push(pkt.to_vec());
                Ok(())
            })
        };
        let b = InnerStack::new(&assigned(Some(B_V6), None, None, None), sink, MTU, STACK_MTU).unwrap();
        let t = b.spawn().unwrap();
        let listener = b.listen_tcp(5060).unwrap();
        let syn_acks = |port: u16| -> Vec<i32> {
            tap.lock()
                .unwrap()
                .iter()
                .filter(|pkt| u16::from_be_bytes([pkt[42], pkt[43]]) == port)
                .filter_map(|pkt| tcp_summary(pkt))
                .filter(|t| t.0 == smoltcp::wire::TcpControl::Syn && t.2)
                .map(|t| t.1)
                .collect()
        };
        let syn = ipv6_tcp_syn(A_V6, B_V6, 40000, 5060, 1000);
        b.push_rx(syn.clone());
        wait_until(WAIT, "B answers the SYN", || !syn_acks(40000).is_empty());
        // The peer retransmits its SYN (our SYN-ACK was lost): one slot is in SYN-RECEIVED
        // for that 4-tuple, the other still listens. The duplicate must not open a second
        // half-connection with another ISN.
        b.push_rx(syn.clone());
        b.push_rx(syn);
        assert_eq!(b.stats().tcp_dup_syn_drops, 2);
        // smoltcp's own SYN-ACK retransmission (1 s RTO) still comes, with the same ISN.
        wait_until(Duration::from_secs(3), "the SYN-ACK is retransmitted", || syn_acks(40000).len() >= 2);
        let isns = syn_acks(40000);
        assert!(isns.iter().all(|isn| *isn == isns[0]), "one handshake, one ISN: {isns:?}");
        // A SYN from another source port is a new connection and takes the free slot.
        b.push_rx(ipv6_tcp_syn(A_V6, B_V6, 40001, 5060, 5000));
        wait_until(WAIT, "B answers the second client", || !syn_acks(40001).is_empty());
        assert_eq!(b.stats().tcp_dup_syn_drops, 2);
        assert_ne!(syn_acks(40001)[0], isns[0]);
        drop(listener);
        b.stop();
        t.join().unwrap();
    }

    #[test]
    fn tcp_close_fails_a_blocked_read_write_accept_and_connect_at_once() {
        let p = Pair::dual();
        let (reader_side, _server, _listener) = tcp_connection(&p, true);
        let (writer_side, _silent_server, _listener2) = tcp_connection(&p, false);
        let a_listener = p.a.listen_tcp(0).unwrap();
        // Nobody owns that address, so the SYN goes unanswered. (Not `…:c::1`: smoltcp
        // 0.14's `has_solicited_node` compares only the low 16 bits of a destination with
        // its own addresses, without checking for the ff02::1:ff00:0/104 prefix, so B
        // would take any unicast `…::1` for itself and answer with RST.)
        let nowhere = SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0xc, 0, 0, 0, 0, 0x99).into(), 5060);
        let long = Duration::from_secs(10);
        reader_side.set_read_timeout(Some(long)).unwrap();
        writer_side.set_write_timeout(Some(long)).unwrap();
        let (results, closed_at) = thread::scope(|sc| {
            let read = sc.spawn(|| (reader_side.read(&mut [0u8; 8]).map(|_| ()), Instant::now()));
            let write = sc.spawn(|| {
                // The peer never reads: the buffers fill and a write parks.
                let chunk = vec![0u8; 16 * 1024];
                loop {
                    if let Err(e) = writer_side.write(&chunk) {
                        return (Err(e), Instant::now());
                    }
                }
            });
            let accept = sc.spawn(|| (a_listener.accept_timeout(long).map(|_| ()), Instant::now()));
            let connect = sc.spawn(|| (p.a.connect_tcp(nowhere, long).map(|_| ()), Instant::now()));
            thread::sleep(Duration::from_millis(300));
            let closed_at = Instant::now();
            p.a.close("tunnel torn down");
            let results: Vec<_> = [read, write, accept, connect].into_iter().map(|h| h.join().unwrap()).collect();
            (results, closed_at)
        });
        for ((r, woke_at), what) in results.into_iter().zip(["read", "write", "accept", "connect"]) {
            assert!(matches!(r, Err(Error::Closed(ref why)) if why == "tunnel torn down"), "{what}: {r:?}");
            assert!(woke_at.duration_since(closed_at) < Duration::from_secs(1), "{what} woke at its own timeout");
        }
        // Every later call fails the same way; shutdown stays idempotent.
        assert!(matches!(reader_side.read(&mut [0u8; 8]), Err(Error::Closed(_))));
        assert!(matches!(writer_side.write(b"x"), Err(Error::Closed(_))));
        assert!(matches!(reader_side.set_nodelay(true), Err(Error::Closed(_))));
        reader_side.shutdown().expect("shutdown after close is Ok");
        assert!(matches!(a_listener.accept_timeout(Duration::ZERO), Err(Error::Closed(_))));
        assert!(matches!(p.a.connect_tcp(nowhere, WAIT), Err(Error::Closed(_))));
        assert!(matches!(p.a.listen_tcp(0), Err(Error::Closed(_))));
        assert_eq!(p.a.stats().tcp_sockets, 0);
    }

    /// The TCP twin of `close_wakes_a_blocked_receiver_while_the_stack_thread_is_in_a_slow_send`:
    /// a parked read must not wait for the poll that holds `state` (DESIGN §17.6).
    #[test]
    fn tcp_close_wakes_a_blocked_reader_while_the_stack_thread_is_in_a_slow_send() {
        let p = Pair::dual();
        let (client, _server, _listener) = tcp_connection(&p, true);
        thread::scope(|sc| {
            let reader = sc.spawn(|| (client.read(&mut [0u8; 8]), Instant::now()));
            thread::sleep(Duration::from_millis(100));
            // Get A's stack thread into the sink, holding `state`, for 1.5 s.
            p.a_ctl.stall_ms.store(1500, Ordering::SeqCst);
            write_all(&client, b"x");
            wait_until(WAIT, "A's stack thread reaches the sink", || p.a_ctl.stalled.load(Ordering::SeqCst));
            let closed_at = Instant::now();
            let closer = sc.spawn(|| p.a.close("gateway stopped answering"));
            let (r, woke_at) = reader.join().unwrap();
            assert!(matches!(r, Err(Error::Closed(ref why)) if why == "gateway stopped answering"), "{r:?}");
            assert!(
                woke_at.duration_since(closed_at) < Duration::from_secs(1),
                "the reader waited {:?} for the poll to finish",
                woke_at.duration_since(closed_at)
            );
            p.a_ctl.stall_ms.store(0, Ordering::SeqCst);
            closer.join().unwrap();
        });
    }
}
