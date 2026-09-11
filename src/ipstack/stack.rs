//! [`InnerStack`] — the smoltcp inner IP stack over ESP and its single owner thread
//! (DESIGN.md §11).
//!
//! `Interface`, `SocketSet` and [`EspDevice`] are `!Sync`, so they live behind one
//! `Mutex` (+ `Condvar`) and are *driven* by exactly one thread, the stack thread
//! (`epdg-stack`, [`InnerStack::run`]):
//!
//! ```text
//! loop { lock; iface.poll(); drain UDP sockets -> per-binding channels;
//!        complete DNS queries -> waiters; delay = iface.poll_delay();
//!        condvar.wait_timeout(delay) }
//! ```
//!
//! Everyone else holds the lock only to enqueue or dequeue, then notifies the condvar:
//! the ESP rx thread pushes decapsulated packets ([`InnerStack::push_rx`]),
//! [`InnerUdpSocket::send_to`] queues a datagram on its smoltcp socket,
//! [`InnerStack::bind_udp`] adds a socket, [`InnerStack::resolve`] starts DNS queries
//! and then waits on a per-query slot (its own mutex/condvar, not the stack lock).
//! Receives never touch the stack lock: each binding has a bounded `sync_channel`
//! filled by the stack thread. All queues are bounded and every drop is counted.
//!
//! Lock rule for the TX sink: it runs on the stack thread *with the stack lock held*
//! (inside `Interface::poll`), so it must only do things that never wait on the ESP rx
//! thread — a UDP send is fine, taking another stack's lock is not (see the loopback
//! test harness, which forwards through a channel for exactly that reason).
//!
//! smoltcp 0.14 facts this module relies on (verified in the crate source):
//! - `Medium::Ip` needs no neighbour discovery: the default routes are nominal, but an
//!   off-prefix destination is still delivered (tested below).
//! - IPv4 packets larger than the MTU are fragmented (`proto-ipv4-fragmentation`) up to
//!   `FRAGMENTATION_BUFFER_SIZE`, and inbound IPv4 fragments are reassembled up to
//!   `REASSEMBLY_BUFFER_SIZE`. **IPv6 fragmentation is not implemented for `Medium::Ip`**
//!   (the `proto-ipv6-fragmentation` feature only covers 6LoWPAN): an oversize IPv6
//!   packet is dropped by smoltcp and an inbound IPv6 Fragment header is answered with
//!   an ICMPv6 Parameter Problem. `send_to` therefore refuses IPv6 payloads that would
//!   not fit in one MTU-sized packet.
//! - The DNS socket keeps at most `DNS_MAX_SERVER_COUNT` servers and returns at most
//!   `DNS_MAX_RESULT_COUNT` addresses per query (both raised via Cargo features).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use log::{debug, info, trace, warn};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{dns, udp};
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use super::device::{DEFAULT_RX_QUEUE_DEPTH, DeviceStats, EspDevice, TxSink};
use crate::ike::session::AssignedConfig;
use crate::{Error, Result};

/// Lowest port handed out by `bind_udp(0)` (IANA dynamic range).
pub const EPHEMERAL_PORT_LO: u16 = 49152;
/// Highest port handed out by `bind_udp(0)`.
pub const EPHEMERAL_PORT_HI: u16 = 65535;
/// Smallest accepted inner MTU (the IPv6 minimum link MTU, RFC 8200 §5).
pub const MIN_INNER_MTU: usize = 1280;
/// Largest accepted inner MTU (maximum IP packet).
pub const MAX_INNER_MTU: usize = 65_535;
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

/// Counters of the inner stack (device queue, UDP delivery, DNS).
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
    /// UDP datagrams delivered to a binding's channel.
    pub udp_delivered: u64,
    /// UDP datagrams dropped because the binding's channel was full.
    pub udp_queue_drops: u64,
    /// DNS queries started (`resolve` issues one per address family).
    pub dns_queries: u64,
    /// Currently bound inner UDP ports.
    pub udp_bindings: u64,
}

/// A UDP "socket" inside the tunnel, bound to one inner port on every inner address.
/// Sends go through the smoltcp stack (source address chosen by smoltcp), receives
/// come from the stack thread through a bounded channel. Dropping it unbinds the port.
pub struct InnerUdpSocket {
    port: u16,
    rx: Receiver<UdpDatagram>,
    stack: InnerStack,
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
    /// Monotonic origin of smoltcp's clock.
    epoch: Instant,
}

impl StackShared {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.epoch.elapsed().as_micros().min(i64::MAX as u128) as i64)
    }

    fn notify(&self) {
        self.cv.notify_all();
    }
}

struct UdpBinding {
    handle: SocketHandle,
    tx: SyncSender<UdpDatagram>,
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

struct DnsWaiter {
    handle: dns::QueryHandle,
    slot: Arc<DnsSlot>,
}

struct State {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: EspDevice,
    dns: SocketHandle,
    udp: HashMap<u16, UdpBinding>,
    dns_waiters: Vec<DnsWaiter>,
    has_v4: bool,
    has_v6: bool,
    dns_servers: usize,
    /// `Some(reason)` once the stack has been closed.
    closed: Option<String>,
    udp_delivered: u64,
    udp_queue_drops: u64,
    dns_queries: u64,
}

impl State {
    fn closed_error(&self) -> Option<Error> {
        self.closed.as_ref().map(|r| Error::Closed(r.clone()))
    }

    /// One stack-thread iteration: poll smoltcp, then move everything it produced out to
    /// the waiting callers.
    fn poll(&mut self, now: smoltcp::time::Instant) {
        let State { iface, sockets, device, dns, udp, dns_waiters, udp_delivered, udp_queue_drops, .. } = self;
        let _ = iface.poll(now, device, sockets);

        // UDP: smoltcp socket rx buffers -> per-binding channels.
        let mut disconnected = Vec::new();
        for (port, binding) in udp.iter() {
            let sock = sockets.get_mut::<udp::Socket>(binding.handle);
            while let Ok((payload, meta)) = sock.recv() {
                let src = SocketAddr::from(meta.endpoint);
                let dst_ip = meta.local_address.map(IpAddr::from).unwrap_or(match src.ip() {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                });
                let dg = UdpDatagram { src, dst: SocketAddr::new(dst_ip, *port), payload: payload.to_vec() };
                trace!("inner UDP rx {} -> {} ({} bytes)", dg.src, dg.dst, dg.payload.len());
                match binding.tx.try_send(dg) {
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
                w.slot.complete(Err(Error::Protocol("DNS query failed (no answer of that type, NXDOMAIN or server failure)".into())));
                false
            }
        });
    }

    /// Fail every waiter, unbind every port (their receivers see `Closed`). Idempotent.
    fn shutdown(&mut self, reason: &str) {
        let State { sockets, dns, udp, dns_waiters, closed, .. } = self;
        if closed.is_none() {
            *closed = Some(reason.to_string());
        }
        let dns_sock = sockets.get_mut::<dns::Socket>(*dns);
        for w in dns_waiters.drain(..) {
            dns_sock.cancel_query(w.handle);
            w.slot.complete(Err(Error::Closed(reason.to_string())));
        }
        for (_, b) in udp.drain() {
            sockets.remove(b.handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------

/// Pick a free inner port in `49152..=65535`, scanning upward from `start` and
/// wrapping around; `None` when every port is in use.
fn pick_free_port(used: &HashMap<u16, UdpBinding>, start: u16) -> Option<u16> {
    let range = u32::from(EPHEMERAL_PORT_HI - EPHEMERAL_PORT_LO) + 1;
    let start = start.clamp(EPHEMERAL_PORT_LO, EPHEMERAL_PORT_HI);
    let offset = u32::from(start - EPHEMERAL_PORT_LO);
    (0..range)
        .map(|i| EPHEMERAL_PORT_LO + ((offset + i) % range) as u16)
        .find(|p| !used.contains_key(p))
}

/// Largest UDP payload the stack can carry to a destination of the given family:
/// IPv4 is fragmented by smoltcp up to its fragmentation buffer, IPv6 must fit the MTU.
pub fn max_udp_payload(mtu: usize, ipv4: bool) -> usize {
    if ipv4 {
        smoltcp::config::FRAGMENTATION_BUFFER_SIZE.max(mtu).saturating_sub(IPV4_UDP_OVERHEAD)
    } else {
        mtu.saturating_sub(IPV6_UDP_OVERHEAD)
    }
}

/// Clamp a configured inner MTU into `[MIN_INNER_MTU, MAX_INNER_MTU]`.
fn effective_mtu(inner_mtu: usize) -> usize {
    inner_mtu.clamp(MIN_INNER_MTU, MAX_INNER_MTU)
}

fn udp_buffer() -> udp::PacketBuffer<'static> {
    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_PACKETS], vec![0u8; UDP_SOCKET_BYTES])
}

// ---------------------------------------------------------------------------
// InnerStack
// ---------------------------------------------------------------------------

impl InnerStack {
    /// Build the interface from the gateway-assigned configuration: every inner IPv6
    /// address with its prefix and every inner IPv4 address as /32, nominal default
    /// routes (first DNS server of the family, else the inner address itself), DNS
    /// servers of the families we have an address for. Nothing runs until
    /// [`InnerStack::run`] / [`InnerStack::spawn`].
    pub fn new(assigned: &AssignedConfig, sink: TxSink, inner_mtu: usize) -> Result<InnerStack> {
        let mtu = effective_mtu(inner_mtu);
        if mtu != inner_mtu {
            warn!("inner MTU {inner_mtu} clamped to {mtu}");
        }
        let epoch = Instant::now();
        let mut device = EspDevice::new(sink, mtu, DEFAULT_RX_QUEUE_DEPTH);
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

        // Nominal default routes (Medium::Ip has no next-hop resolution).
        if has_v6 {
            let gw = assigned.dns_ipv6.first().copied().or(v6.first().copied()).unwrap_or(Ipv6Addr::UNSPECIFIED);
            iface.routes_mut().add_default_ipv6_route(gw).map_err(|e| Error::Config(format!("inner IPv6 route: {e:?}")))?;
        }
        if has_v4 {
            let gw = assigned.dns_ipv4.first().copied().or(v4.first().copied()).unwrap_or(Ipv4Addr::UNSPECIFIED);
            iface.routes_mut().add_default_ipv4_route(gw).map_err(|e| Error::Config(format!("inner IPv4 route: {e:?}")))?;
        }

        // DNS servers of the families we can reach; smoltcp keeps the first DNS_MAX_SERVER_COUNT.
        let mut servers: Vec<IpAddress> = Vec::new();
        if has_v6 {
            servers.extend(assigned.dns_ipv6.iter().map(|a| IpAddress::Ipv6(*a)));
        }
        if has_v4 {
            servers.extend(assigned.dns_ipv4.iter().map(|a| IpAddress::Ipv4(*a)));
        }
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
            "inner stack: mtu {mtu}, addresses {:?}, dns {:?}, ipv4 fragmentation up to {} bytes",
            iface.ip_addrs(),
            servers,
            smoltcp::config::FRAGMENTATION_BUFFER_SIZE
        );
        if installed == 0 {
            warn!("inner stack has no address: sends will fail until one is assigned");
        }

        Ok(InnerStack {
            shared: Arc::new(StackShared {
                state: Mutex::new(State {
                    iface,
                    sockets,
                    device,
                    dns,
                    udp: HashMap::new(),
                    dns_waiters: Vec::new(),
                    has_v4,
                    has_v6,
                    dns_servers: servers.len(),
                    closed: None,
                    udp_delivered: 0,
                    udp_queue_drops: 0,
                    dns_queries: 0,
                }),
                cv: Condvar::new(),
                stop: AtomicBool::new(false),
                epoch,
            }),
        })
    }

    /// Spawn the stack thread (`epdg-stack`) running [`InnerStack::run`].
    pub fn spawn(&self) -> Result<JoinHandle<()>> {
        let stack = self.clone();
        thread::Builder::new().name("epdg-stack".into()).spawn(move || stack.run()).map_err(Error::Io)
    }

    /// The stack thread body: poll, hand results out, sleep until the next smoltcp
    /// deadline or an external event. Returns after [`InnerStack::stop`] / `close`.
    pub fn run(&self) {
        let sh = &*self.shared;
        let mut st = lock(&sh.state);
        let mut immediate = 0u32;
        while !sh.stop.load(Ordering::SeqCst) {
            let now = sh.now();
            st.poll(now);
            let s = &mut *st;
            let wait = match s.iface.poll_delay(now, &s.sockets) {
                Some(d) if d.total_micros() == 0 => {
                    immediate += 1;
                    if immediate < MAX_IMMEDIATE_POLLS {
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
        st.shutdown("inner stack stopped");
        debug!("stack thread stopped");
    }

    /// Stop the stack thread and fail every pending operation with `Error::Closed`.
    pub fn stop(&self) {
        self.close("inner stack stopped");
    }

    /// Like [`InnerStack::stop`] with a reason that later callers see in `Error::Closed`.
    pub fn close(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.shared.stop.store(true, Ordering::SeqCst);
        lock(&self.shared.state).shutdown(&reason);
        self.shared.notify();
    }

    pub fn is_closed(&self) -> bool {
        self.shared.stop.load(Ordering::SeqCst) || lock(&self.shared.state).closed.is_some()
    }

    /// Queue one decapsulated inner IP packet (from the ESP rx thread) and wake the
    /// stack thread. Never blocks for long: the device queue is bounded (drop-oldest).
    pub fn push_rx(&self, packet: Vec<u8>) {
        {
            let mut st = lock(&self.shared.state);
            if st.closed.is_some() {
                return;
            }
            st.device.push_rx(packet);
        }
        self.shared.notify();
    }

    /// Bind an inner UDP port on every inner address. `port == 0` picks a free port
    /// in `49152..=65535`.
    pub fn bind_udp(&self, port: u16) -> Result<InnerUdpSocket> {
        let mut st = lock(&self.shared.state);
        if let Some(e) = st.closed_error() {
            return Err(e);
        }
        let port = if port == 0 {
            let start = EPHEMERAL_PORT_LO + (rand::random::<u16>() % (EPHEMERAL_PORT_HI - EPHEMERAL_PORT_LO + 1));
            pick_free_port(&st.udp, start).ok_or_else(|| Error::Config("no free inner UDP port".into()))?
        } else {
            if st.udp.contains_key(&port) {
                return Err(Error::Config(format!("inner UDP port {port} is already bound")));
            }
            port
        };
        let mut sock = udp::Socket::new(udp_buffer(), udp_buffer());
        sock.bind(IpListenEndpoint { addr: None, port })
            .map_err(|e| Error::Config(format!("inner UDP bind to port {port}: {e}")))?;
        let handle = st.sockets.add(sock);
        let (tx, rx) = mpsc::sync_channel(UDP_QUEUE_DEPTH);
        st.udp.insert(port, UdpBinding { handle, tx });
        drop(st);
        self.shared.notify();
        debug!("inner UDP port {port} bound");
        Ok(InnerUdpSocket { port, rx, stack: self.clone() })
    }

    /// Resolve `name` over the assigned DNS servers: AAAA and A queries (a family we
    /// have no inner address for is skipped), answers AAAA first. `Error::Timeout`
    /// when nothing answered before `timeout`, `Error::Protocol` when every query
    /// failed (NXDOMAIN / no records / server failure).
    pub fn resolve(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>> {
        let deadline = Instant::now() + timeout;
        let waiters = self.start_queries(name)?;
        self.shared.notify();

        let mut answers: Vec<IpAddr> = Vec::new();
        let mut failure: Option<Error> = None;
        let mut timed_out = false;
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
        if let Some(e) = st.closed_error() {
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
        let State { iface, sockets, dns, dns_waiters, dns_queries, .. } = &mut *st;
        let sock = sockets.get_mut::<dns::Socket>(*dns);
        let mut slots = Vec::with_capacity(types.len());
        for t in types {
            match sock.start_query(iface.context(), name, t) {
                Ok(handle) => {
                    let slot = Arc::new(DnsSlot::default());
                    dns_waiters.push(DnsWaiter { handle, slot: Arc::clone(&slot) });
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

    pub fn stats(&self) -> StackStats {
        let st = lock(&self.shared.state);
        let d: DeviceStats = st.device.stats();
        StackStats {
            rx_packets: d.rx_packets,
            rx_bytes: d.rx_bytes,
            rx_queue_drops: d.rx_queue_drops,
            tx_packets: d.tx_packets,
            tx_bytes: d.tx_bytes,
            tx_errors: d.tx_errors,
            udp_delivered: st.udp_delivered,
            udp_queue_drops: st.udp_queue_drops,
            dns_queries: st.dns_queries,
            udp_bindings: st.udp.len() as u64,
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

    /// Link MTU of the inner interface.
    pub fn mtu(&self) -> usize {
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
        let mut st = lock(&self.stack.shared.state);
        if let Some(e) = st.closed_error() {
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
                "{} byte payload exceeds the {max} byte limit for inner {family} datagrams{}",
                payload.len(),
                if dst.is_ipv6() { " (smoltcp has no IPv6 fragmentation)" } else { "" }
            )));
        }
        let handle = st
            .udp
            .get(&self.port)
            .map(|b| b.handle)
            .ok_or_else(|| Error::Closed(format!("inner UDP port {} is no longer bound", self.port)))?;
        st.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(payload, IpEndpoint::from(dst))
            .map_err(|e| match e {
                udp::SendError::BufferFull => Error::Protocol(format!("inner UDP port {}: send buffer full", self.port)),
                udp::SendError::Unaddressable => Error::Config(format!("inner UDP: {dst} is not addressable")),
            })?;
        drop(st);
        self.stack.shared.notify();
        trace!("inner UDP tx port {} -> {} ({} bytes)", self.port, dst, payload.len());
        Ok(())
    }

    /// Wait up to `timeout` for a datagram addressed to this port. `Ok(None)` on
    /// timeout, `Error::Closed` once the stack is stopped.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<UdpDatagram>> {
        match self.rx.recv_timeout(timeout) {
            Ok(dg) => Ok(Some(dg)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                let st = lock(&self.stack.shared.state);
                Err(st.closed_error().unwrap_or_else(|| Error::Closed("inner stack stopped".into())))
            }
        }
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }
}

impl Drop for InnerUdpSocket {
    fn drop(&mut self) {
        {
            let mut st = lock(&self.stack.shared.state);
            if let Some(b) = st.udp.remove(&self.port) {
                st.sockets.remove(b.handle);
                debug!("inner UDP port {} unbound", self.port);
            }
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
// Tests: an in-process two-stack loopback (no ESP needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicU64;

    const A_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 1);
    const B_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xb, 0, 0, 0, 0, 1);
    const A_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const MTU: usize = 1280;
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

    /// One direction of the loopback "wire": the sink (which runs on the sending
    /// stack's thread, with that stack's lock held) only records the packet size and
    /// queues the packet; a forwarder thread pushes it into the far stack. The sink
    /// must never lock the far stack itself: the two stack threads would deadlock
    /// (A holds A, pushes into B; B holds B, replies into A). The real tunnel has the
    /// same shape — the sink does a UDP send, the far side's rx thread does `push_rx`.
    fn wire(
        name: &str,
        target: Arc<OnceLock<InnerStack>>,
        tap: Arc<Mutex<Vec<usize>>>,
        stop: Arc<AtomicBool>,
    ) -> (TxSink, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let sink: TxSink = Arc::new(move |pkt: &[u8]| {
            tap.lock().unwrap().push(pkt.len());
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

    /// Two stacks whose devices feed each other over asynchronous wires; `a_wire`
    /// records the size of every IP packet A transmitted. Stops and joins every
    /// thread on drop.
    struct Pair {
        a: InnerStack,
        b: InnerStack,
        a_wire: Arc<Mutex<Vec<usize>>>,
        stop_wires: Arc<AtomicBool>,
        threads: Vec<JoinHandle<()>>,
    }

    impl Pair {
        fn new(a_cfg: AssignedConfig, b_cfg: AssignedConfig) -> Pair {
            let a_wire = Arc::new(Mutex::new(Vec::new()));
            let b_wire = Arc::new(Mutex::new(Vec::new()));
            let stop_wires = Arc::new(AtomicBool::new(false));
            let b_slot: Arc<OnceLock<InnerStack>> = Arc::new(OnceLock::new());
            let a_slot: Arc<OnceLock<InnerStack>> = Arc::new(OnceLock::new());
            let (sink_a, wire_ab) = wire("wire-a-to-b", Arc::clone(&b_slot), Arc::clone(&a_wire), Arc::clone(&stop_wires));
            let (sink_b, wire_ba) = wire("wire-b-to-a", Arc::clone(&a_slot), b_wire, Arc::clone(&stop_wires));
            let a = InnerStack::new(&a_cfg, sink_a, MTU).unwrap();
            let b = InnerStack::new(&b_cfg, sink_b, MTU).unwrap();
            let _ = b_slot.set(b.clone());
            let _ = a_slot.set(a.clone());
            let threads = vec![a.spawn().unwrap(), b.spawn().unwrap(), wire_ab, wire_ba];
            Pair { a, b, a_wire, stop_wires, threads }
        }

        /// A(v6 + v4, DNS = B) <-> B(v6 on another /64 + v4, DNS = A).
        fn dual() -> Pair {
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
        ports
            .iter()
            .map(|p| {
                let (tx, _rx) = mpsc::sync_channel(1);
                (*p, UdpBinding { handle: SocketHandle::default(), tx })
            })
            .collect()
    }

    #[test]
    fn free_port_starts_at_requested_and_skips_used() {
        let used = bindings(&[50000, 50001]);
        assert_eq!(pick_free_port(&used, 50000), Some(50002));
        assert_eq!(pick_free_port(&used, 49999), Some(49999));
        assert_eq!(pick_free_port(&HashMap::new(), 49152), Some(49152));
    }

    #[test]
    fn free_port_wraps_and_clamps() {
        let used = bindings(&[65535]);
        assert_eq!(pick_free_port(&used, 65535), Some(49152));
        assert_eq!(pick_free_port(&HashMap::new(), 80), Some(49152));
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
        assert_eq!(max_udp_payload(1280, false), 1280 - 48);
        assert_eq!(max_udp_payload(1280, true), smoltcp::config::FRAGMENTATION_BUFFER_SIZE - 28);
        assert!(max_udp_payload(1280, true) >= 3000, "the fragmentation buffer must hold the test payload");
        assert_eq!(max_udp_payload(65535, true), 65535 - 28);
    }

    #[test]
    fn stack_installs_addresses_and_stats_start_at_zero() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        let s = InnerStack::new(&assigned(Some(A_V6), Some(A_V4), Some(B_V6), None), sink, 1400).unwrap();
        let mut addrs = s.addresses();
        addrs.sort();
        assert_eq!(addrs, vec![(IpAddr::V4(A_V4), 32), (IpAddr::V6(A_V6), 64)]);
        assert_eq!(s.mtu(), 1400);
        assert_eq!(s.stats(), StackStats::default());
        assert!(!s.is_closed());
    }

    #[test]
    fn non_unicast_addresses_are_ignored_not_fatal() {
        let sink: TxSink = Arc::new(|_: &[u8]| Ok(()));
        let cfg = AssignedConfig {
            internal_ipv6: vec![(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 64), (A_V6, 200)],
            internal_ipv4: vec![Ipv4Addr::BROADCAST, Ipv4Addr::UNSPECIFIED, A_V4],
            ..Default::default()
        };
        let s = InnerStack::new(&cfg, sink, 1280).unwrap();
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
        let wire = p.a_wire.lock().unwrap().clone();
        assert!(wire.len() >= 3, "3028 bytes need >= 3 fragments at MTU 1280, saw {wire:?}");
        assert!(wire.iter().all(|&len| len <= MTU), "every fragment fits the MTU: {wire:?}");
        assert_eq!(wire.iter().sum::<usize>(), 3000 + 8 + 20 * wire.len(), "fragments carry the whole datagram once");
        assert_eq!(p.a.stats().tx_packets as usize, wire.len());
        // And back, so B's fragmenter is exercised too.
        sb.send_to(dg.src, &payload).unwrap();
        assert_eq!(recv(&sa).payload, payload);
    }

    #[test]
    fn ipv6_payload_that_does_not_fit_the_mtu_is_refused() {
        // smoltcp 0.14 has no IPv6 fragmentation on Medium::Ip: refuse instead of losing it.
        let p = Pair::dual();
        let sa = p.a.bind_udp(0).unwrap();
        let limit = MTU - 48;
        sa.send_to(SocketAddr::new(B_V6.into(), 7000), &vec![0u8; limit]).unwrap();
        let e = sa.send_to(SocketAddr::new(B_V6.into(), 7000), &vec![0u8; limit + 1]).unwrap_err();
        assert!(matches!(e, Error::Protocol(ref m) if m.contains("IPv6 fragmentation")), "{e}");
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
        assert!(matches!(e, Error::Config(ref m) if m.contains("already bound")), "{e}");
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

    struct DnsServer {
        stop: Arc<AtomicBool>,
        seen: Arc<Mutex<Vec<(String, u16)>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl DnsServer {
        fn start(stack: &InnerStack, answers: Vec<IpAddr>, rcode: u8) -> DnsServer {
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

    const HOST: &str = "pcscf.example.test";
    const ANS_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x53, 0, 0, 0, 0, 0x1);
    const ANS_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

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
        let no_dns = InnerStack::new(&assigned(Some(A_V6), None, None, None), sink.clone(), MTU).unwrap();
        assert!(matches!(no_dns.resolve(HOST, WAIT).unwrap_err(), Error::Config(_)));
        let no_addr = InnerStack::new(&assigned(None, None, Some(B_V6), None), sink.clone(), MTU).unwrap();
        assert!(matches!(no_addr.resolve(HOST, WAIT).unwrap_err(), Error::Config(_)));
        let ok = InnerStack::new(&assigned(Some(A_V6), None, Some(B_V6), None), sink, MTU).unwrap();
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
            thread::spawn(move || a.resolve(HOST, Duration::from_secs(10)))
        };
        thread::sleep(Duration::from_millis(50));
        p.a.close("tunnel torn down");
        assert!(p.a.is_closed());
        let e = resolver.join().unwrap().unwrap_err();
        assert!(matches!(e, Error::Closed(ref r) if r == "tunnel torn down"), "{e}");
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
        let s = InnerStack::new(&assigned(Some(A_V6), None, Some(B_V6), None), sink, MTU).unwrap();
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
}
