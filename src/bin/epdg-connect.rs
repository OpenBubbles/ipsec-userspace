//! `epdg-connect` — stable-path CLI that brings up the ePDG tunnel from a carrier
//! bundle + credentials, proves it end-to-end (DNS over the tunnel, DPD, keepalives)
//! and holds it open. Exists mainly so a per-application firewall rule (Little Snitch
//! etc.) can be granted once: `cargo test` binaries get a new hash-suffixed path on
//! every build, `target/debug/epdg-connect` does not.
//!
//! Usage: epdg-connect [--activation PLIST | --bundle P --creds P --cert PEM --key PEM] [--hold SECS]
//!                      [--rebind-after SECS] [--no-dns] [--tcp-probe]
//! `--activation` (or env EPDG_ACTIVATION_CONFIG) loads the app-side activation config, which
//! carries the bundle, the credentials and the DER client certificate/key in one plist.
//! `--rebind-after SECS` forces one address update that far into the hold and then proves the
//! moved tunnel still works (DESIGN §17.9); off by default.
//! `--tcp-probe` opens one inner TCP connection (DESIGN §11.2) to the resolved P-CSCF on the
//! port of the config's `pcscf-address` and prints a `TCP-PROBE` / `TCP-PROBE-FAILED` line;
//! diagnostic only (whether the P-CSCF takes TCP is not known), it never changes the exit
//! code. Off by default.
//! Defaults point at tests/fixtures/. Set RUST_LOG=debug for hex dumps.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use epdg::{Config, EpdgTunnel, Error, NetStack};

const TARGET_HOST: &str = "ueb2bprod.pc.t-mobile.com";
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Handshake budget of `--tcp-probe`.
const TCP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// SIP's default port (RFC 3261 §19.1.2), for a `pcscf-address` that names none.
const SIP_DEFAULT_PORT: u16 = 5060;
/// How long `--rebind-after` waits for the path thread to complete the forced address
/// update. The announce runs the normal retransmit schedule (~15.5 s), and a schedule
/// that times out once is retried by the path thread rather than being fatal (the
/// library's tolerance is `NO_ROUTE_GRACE`, 30 s), so a budget of one schedule would
/// report a move that really lands at ~16-18 s as a failure. 25 s covers a full schedule
/// plus the start of the retry and still fits inside `--hold 30 --rebind-after 8`.
const ADDRESS_UPDATE_TIMEOUT: Duration = Duration::from_secs(25);
/// Poll spacing while waiting for `TunnelStats::address_updates` to move.
const ADDRESS_UPDATE_POLL: Duration = Duration::from_millis(100);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if std::env::args().nth(1).as_deref() == Some("probe-tls") {
        probe_main();
        return;
    }

    let mut bundle = fixture("tmobile_prod_bundle.plist");
    let mut creds = fixture("tmobile_creds.plist");
    let mut cert = fixture("client.crt");
    let mut key = fixture("client.key");
    let mut activation = std::env::var_os("EPDG_ACTIVATION_CONFIG").map(PathBuf::from);
    let mut hold = Duration::from_secs(25);
    let mut rebind_after: Option<Duration> = None;
    let mut do_dns = true;
    let mut tcp_probe = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| panic!("missing value for {a}"));
        match a.as_str() {
            "--bundle" => bundle = PathBuf::from(val()),
            "--creds" => creds = PathBuf::from(val()),
            "--cert" => cert = PathBuf::from(val()),
            "--key" => key = PathBuf::from(val()),
            "--activation" => activation = Some(PathBuf::from(val())),
            "--hold" => hold = Duration::from_secs(val().parse().expect("--hold seconds")),
            "--rebind-after" => {
                rebind_after = Some(Duration::from_secs(val().parse().expect("--rebind-after seconds")))
            }
            "--no-dns" => do_dns = false,
            "--tcp-probe" => tcp_probe = true,
            "-h" | "--help" => {
                println!(
                    "epdg-connect [--activation PLIST | --bundle P --creds P --cert PEM --key PEM] \
                     [--hold SECS] [--rebind-after SECS] [--no-dns] [--tcp-probe]"
                );
                println!("  --hold SECS          keep the tunnel open this long after the checks (default 25)");
                println!(
                    "  --rebind-after SECS  this far into the hold, force one address update \
                     (a fresh source port announced with UPDATE_SA_ADDRESSES) and prove the moved"
                );
                println!(
                    "                       tunnel still carries IKE and ESP; prints ADDRESS-UPDATE / \
                     POST-MOVE lines and exits non-zero if any of it fails. Off by default"
                );
                println!("  --no-dns             skip the pre-hold DNS check over the tunnel");
                println!(
                    "  --tcp-probe          after the DNS check, open one TCP connection over the tunnel to the \
                     resolved P-CSCF on the port"
                );
                println!(
                    "                       of the config's pcscf-address ({TCP_PROBE_TIMEOUT:?} budget); prints \
                     TCP-PROBE ok / TCP-PROBE-FAILED, never fails the run. Off by default"
                );
                return;
            }
            other => panic!("unknown argument {other}"),
        }
    }

    let loaded = match &activation {
        Some(p) => Config::from_activation_file(p),
        None => Config::from_plist_files(&bundle, &creds, &cert, &key),
    };
    let cfg = match loaded {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(2);
        }
    };
    println!("gateway: {} (fallback {:?})", cfg.gateway.hostname, cfg.gateway.fallback_addr);

    let t0 = Instant::now();
    let tunnel = match EpdgTunnel::connect(&cfg) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("CONNECT FAILED after {:?}: {e}", t0.elapsed());
            std::process::exit(1);
        }
    };
    let info = tunnel.info().clone();
    println!("TunnelInfo: {info:#?}");
    println!(
        "connected in {:?}: {} -> {} IKE {:#018x}/{:#018x} child in {:#010x} out {:#010x} ({} / {} / TLS {})",
        t0.elapsed(), info.local_addr, info.remote_addr, info.ike_spi_i, info.ike_spi_r,
        info.child_spi_in, info.child_spi_out, info.ike_suite, info.child_suite, info.tls_version
    );
    let a = &info.assigned;

    // The P-CSCF lookup goes through the NetStack abstraction (DESIGN.md §16), so a
    // live run covers the tunnel implementation of the trait, not only the facade.
    let stack: &dyn NetStack = &tunnel;
    println!("netstack {}: local addresses {:?}", stack.name(), stack.local_addrs());
    // The EpdgTunnel implementation of the trait has no offline test (only the
    // InnerStack one does): assert its delegation here, where a live tunnel exists.
    assert_eq!(stack.name(), "epdg-tunnel");
    let mut expected: Vec<IpAddr> = a.internal_ipv6.iter().map(|(v6, _)| IpAddr::V6(*v6)).collect();
    expected.extend(a.internal_ipv4.iter().copied().map(IpAddr::V4));
    assert_eq!(stack.local_addrs(), expected, "NetStack::local_addrs are the assigned inner addresses");
    assert!(!expected.is_empty(), "no inner address assigned");
    let probe = stack.bind_udp(0).expect("NetStack::bind_udp over the live tunnel");
    assert_eq!(probe.local_addr().ip(), expected[0], "inner socket address is the first inner address");
    assert_eq!(stack.bind_udp(probe.local_addr().port()).expect_err("port taken").kind(), std::io::ErrorKind::AddrInUse);
    drop(probe);
    let mut answers: Vec<IpAddr> = Vec::new();
    if do_dns {
        if a.dns_ipv4.is_empty() && a.dns_ipv6.is_empty() {
            println!("no DNS server assigned; skipping DNS check");
        } else {
            answers = lookup_pcscf(stack, TARGET_HOST, &format!("v6 {:?} v4 {:?}", a.dns_ipv6, a.dns_ipv4));
        }
    }
    if tcp_probe {
        if answers.is_empty() {
            answers = lookup_pcscf(stack, TARGET_HOST, "for the TCP probe");
        }
        probe_pcscf_tcp(stack, &answers, &cfg.ims.pcscf_address);
    }

    match tunnel.dpd() {
        Ok(rtt) => println!("DPD rtt {rtt:?}"),
        Err(e) => println!("DPD failed: {e}"),
    }

    println!("holding tunnel for {hold:?} (keepalives every {}s)...", cfg.ike.natt.keepalive_interval_secs);
    // `--rebind-after`: part way into the hold, move the tunnel to a fresh source port
    // through the production path monitor and prove the gateway followed it.
    let move_ok = match rebind_after {
        None => {
            std::thread::sleep(hold);
            true
        }
        Some(offset) => {
            let started = Instant::now();
            std::thread::sleep(offset.min(hold));
            let ok = forced_address_update(&tunnel);
            // The rest of the hold shows that the moved tunnel keeps living (keepalives on
            // the new port, no late death); a move that already failed is reported now
            // instead of after another half minute of sleeping. The remainder is measured
            // from the start of the hold, so the run spends `--hold` in total however long
            // the move itself took.
            if ok {
                std::thread::sleep(hold.saturating_sub(started.elapsed()));
            }
            ok
        }
    };
    let alive = tunnel.is_alive();
    let stats = tunnel.stats();
    println!("alive={alive} stats: {stats:?}");

    match tunnel.close() {
        Ok(()) => println!("closed cleanly (DELETE acknowledged)"),
        Err(e) => println!("close: {e} (best effort)"),
    }

    let verdict = match (alive, move_ok) {
        (true, true) => "PASS",
        (false, _) => "FAIL (tunnel died while idle)",
        (true, false) => "FAIL (the forced address update did not hold up)",
    };
    println!();
    println!("{verdict}: T-Mobile ePDG tunnel");
    println!("  gateway     {} ({})", info.remote_addr, cfg.gateway.hostname);
    println!("  handshake   {:?}", info.handshake_duration);
    println!("  suites      IKE {} / child {} / TLS {}", info.ike_suite, info.child_suite, info.tls_version);
    println!("  inner v4    {:?}", a.internal_ipv4);
    println!("  inner v6    {:?}", a.internal_ipv6);
    println!("  DNS         v4 {:?} v6 {:?}", a.dns_ipv4, a.dns_ipv6);
    println!("  P-CSCF      v4 {:?} v6 {:?}", a.pcscf_ipv4, a.pcscf_ipv6);
    if do_dns {
        println!("  {TARGET_HOST} -> {:?}", answers);
    }
    println!("  ESP tx/rx   {}/{} packets, keepalives {}", stats.esp_tx_packets, stats.esp_rx_packets, stats.keepalives_sent);
    println!("  addr updates {}", stats.address_updates);
    if !alive || !move_ok {
        std::process::exit(1);
    }
}

/// `--rebind-after`: exercise the real address-update path without touching the network
/// (`EpdgTunnel::force_address_update`, DESIGN §17.9) and check what it produced.
///
/// The path thread rebinds the outer socket to a fresh ephemeral port on the address it
/// is already using and announces it — `UPDATE_SA_ADDRESSES` + NAT-D over the new port
/// with a MOBIKE peer (RFC 4555 §3.5), which the gateway sees as a NAT rebinding. Every
/// fact gets one machine-checkable line so the live test can parse it:
///
/// - `ADDRESS-UPDATE old=<ip:port> new=<ip:port> updates=<n> ok` — the announce completed
///   and the source port really moved;
/// - `POST-MOVE DPD rtt=<ms>` — the gateway still answers IKE at the new 5-tuple;
/// - `POST-MOVE ESP rx delta=<n>` — ESP datagrams received AFTER the update (the DNS
///   answers below travel as ESP), i.e. proof that the gateway sends ESP to the new port.
///
/// Returns false — and prints `ADDRESS-UPDATE-FAILED <reason>` — if any of that did not
/// happen; the caller exits non-zero. The failure marker deliberately does NOT start with
/// `ADDRESS-UPDATE ` (note the hyphen): the move itself can succeed and a post-move check
/// still fail, and a scraper asking for either prefix must never be handed the other
/// verdict.
fn forced_address_update(tunnel: &EpdgTunnel) -> bool {
    let old = tunnel.local_addr();
    let before = tunnel.stats();
    println!(
        "forcing an address update: local {old}, address_updates={} esp_rx={}",
        before.address_updates, before.esp_rx_packets
    );
    if let Err(e) = tunnel.force_address_update() {
        println!("ADDRESS-UPDATE-FAILED force_address_update refused: {e}");
        return false;
    }

    // Poll for the announce the path thread runs. `address_updates` is bumped only after
    // the gateway has answered, so seeing it move is the acknowledgement itself.
    let deadline = Instant::now() + ADDRESS_UPDATE_TIMEOUT;
    let after = loop {
        let s = tunnel.stats();
        if s.address_updates > before.address_updates {
            break s;
        }
        if !tunnel.is_alive() {
            println!("ADDRESS-UPDATE-FAILED the tunnel died during the move");
            return false;
        }
        if Instant::now() >= deadline {
            println!(
                "ADDRESS-UPDATE-FAILED no address update within {ADDRESS_UPDATE_TIMEOUT:?} \
                 (updates still {})",
                s.address_updates
            );
            return false;
        }
        std::thread::sleep(ADDRESS_UPDATE_POLL);
    };
    let new = tunnel.local_addr();
    if new.port() == old.port() {
        println!("ADDRESS-UPDATE-FAILED the source port did not change (old={old} new={new})");
        return false;
    }
    println!("ADDRESS-UPDATE old={old} new={new} updates={} ok", after.address_updates);

    // IKE over the new 5-tuple.
    let rtt = match tunnel.dpd() {
        Ok(rtt) => rtt,
        Err(e) => {
            println!("ADDRESS-UPDATE-FAILED DPD after the move: {e}");
            return false;
        }
    };
    println!("POST-MOVE DPD rtt={}", rtt.as_millis());

    // ESP over the new 5-tuple: the resolver's queries go out as ESP and the answers come
    // back as ESP, so a non-zero delta against the counter read at the moment of the
    // update is proof that the gateway moved the child SA's destination port too. Run
    // whatever `--no-dns` says: this resolve is the ESP probe, not the P-CSCF lookup.
    let stack: &dyn NetStack = tunnel;
    let answers = lookup_pcscf(stack, TARGET_HOST, "post-move");
    let delta = tunnel.stats().esp_rx_packets.saturating_sub(after.esp_rx_packets);
    println!("POST-MOVE ESP rx delta={delta}");
    if delta == 0 {
        println!("ADDRESS-UPDATE-FAILED no ESP received after the move (resolve answers {answers:?})");
        return false;
    }
    true
}

/// `--tcp-probe`: one TCP handshake with the P-CSCF over the tunnel (DESIGN §11.2) — the
/// first resolved address of a family the tunnel has an inner address for, on the port of
/// the config's `pcscf-address` (35060 for T-Mobile; SIP's 5060 when it names none). One
/// machine-checkable line either way:
///
/// - `TCP-PROBE ok local=<ip:port> peer=<ip:port> in=<ms>` — the handshake completed (then
///   the connection is shut down gracefully);
/// - `TCP-PROBE-FAILED <reason>` — no usable address, a refusal, a timeout, …
///
/// Whether the P-CSCF listens on TCP at all is not known, so the caller never turns a
/// failed probe into a failed run. As with `ADDRESS-UPDATE-FAILED`, the failure marker does
/// not start with the success marker followed by a space.
fn probe_pcscf_tcp(stack: &dyn NetStack, answers: &[IpAddr], pcscf_address: &str) {
    let port = pcscf_port(pcscf_address).unwrap_or(SIP_DEFAULT_PORT);
    let inner = stack.local_addrs();
    let Some(ip) = answers.iter().copied().find(|ip| inner.iter().any(|l| l.is_ipv6() == ip.is_ipv6())) else {
        println!("TCP-PROBE-FAILED no resolved P-CSCF address of an inner address family (answers {answers:?}, inner {inner:?})");
        return;
    };
    let peer = SocketAddr::new(ip, port);
    println!("  tcp probe: connecting to {peer} over {} (port from pcscf-address {pcscf_address:?})", stack.name());
    let started = Instant::now();
    match stack.connect_tcp(peer, TCP_PROBE_TIMEOUT) {
        Ok(stream) => {
            println!("TCP-PROBE ok local={} peer={} in={}", stream.local_addr(), stream.peer_addr(), started.elapsed().as_millis());
            if let Err(e) = stream.shutdown() {
                println!("  tcp probe: shutdown: {e}");
            }
        }
        Err(e) => {
            println!("TCP-PROBE-FAILED connect to {peer}: {e} ({:?}) after {} ms", e.kind(), started.elapsed().as_millis())
        }
    }
}

/// The port of a `host:port` or `[v6]:port` P-CSCF address; `None` when it names none.
fn pcscf_port(address: &str) -> Option<u16> {
    let (host, port) = address.rsplit_once(':')?;
    // A bare IPv6 literal is all colons and no port.
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return None;
    }
    port.parse().ok()
}

/// Resolve the P-CSCF host name with the stack's own resolver (two attempts): the
/// DNS round trip proves ESP in both directions when `stack` is the tunnel.
fn lookup_pcscf(stack: &dyn NetStack, host: &str, servers: &str) -> Vec<IpAddr> {
    for attempt in 1..=2 {
        println!("  resolve {host} via {} DNS {servers} (try {attempt}/2)", stack.name());
        match stack.resolve(host, DNS_TIMEOUT) {
            Ok(v) => {
                println!("  answers: {v:?}");
                return v;
            }
            Err(e) => println!("  lookup failed: {e}"),
        }
    }
    Vec::new()
}

// ---- TLS negotiation probe (diagnostic subcommand) ----
use epdg::eap::packet::EapPacket;
use epdg::eap::tls::EapTlsData;
use epdg::ike::session::{AuthResponse, IkeInitiator, SaInitOutcome};
use epdg::ike::transport::IkeTransport;

fn u16be(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }

fn describe_tls(data: &[u8]) {
    let mut p = 0;
    while p + 5 <= data.len() {
        let ct = data[p]; let ver = u16be(&data[p + 1..]); let len = u16be(&data[p + 3..]) as usize;
        let body = &data[p + 5..(p + 5 + len).min(data.len())];
        match ct {
            0x15 if body.len() >= 2 => println!("  TLS ALERT level={} description={}", body[0], body[1]),
            0x16 if !body.is_empty() => {
                let mut q = 0;
                while q + 4 <= body.len() {
                    let ht = body[q]; let hl = u32::from_be_bytes([0, body[q+1], body[q+2], body[q+3]]) as usize;
                    let hb = &body[q + 4..(q + 4 + hl).min(body.len())];
                    if ht == 2 && hb.len() >= 38 {
                        let sv = u16be(&hb[0..2]); let sid = hb[34] as usize; let cs = u16be(&hb[35 + sid..]);
                        println!("  SERVER HELLO: version {:04x}, cipher suite {:04x}, session id {} bytes", sv, cs, sid);
                        let mut r = 35 + sid + 3; // comp(1) + extlen(2)
                        if r <= hb.len() { let mut exts = vec![]; while r + 4 <= hb.len() { let t = u16be(&hb[r..]); let l = u16be(&hb[r+2..]) as usize; exts.push(format!("{t}({l})")); r += 4 + l; } println!("  server extensions: {}", exts.join(" ")); }
                    } else { println!("  handshake msg type {} ({} bytes)", ht, hl); }
                    q += 4 + hl;
                }
            }
            _ => println!("  TLS record type 0x{:02x} version {:04x} len {}", ct, ver, len),
        }
        p += 5 + len;
    }
}

fn probe_main() {
        let hello = hex::decode(std::env::args().nth(2).expect("probe-tls <ClientHello hex>")).expect("hex");
    let cfg = Config::from_plist_files(&fixture("tmobile_prod_bundle.plist"), &fixture("tmobile_creds.plist"), &fixture("client.crt"), &fixture("client.key")).unwrap();
    let cands = cfg.gateway_candidates().unwrap();
    let remote = cands[0];
    let mut transport = IkeTransport::bind(cfg.gateway.local_addr, remote, cfg.gateway.ike_port).unwrap();
    let mut ike = IkeInitiator::new(&cfg, transport.local_addr(), transport.remote_addr()).unwrap();
    let mut cookie: Option<Vec<u8>> = None;
    loop {
        let req = ike.build_sa_init(cookie.as_deref()).unwrap();
        let resp = transport.request(&[req], 0, &cfg.ike.retransmit, &mut |_| {}, &mut |_| {}).expect("IKE_SA_INIT response");
        match ike.handle_sa_init_response(&resp[0]).expect("IKE_SA_INIT") {
            SaInitOutcome::Established { nat } => { if nat.detected || !cfg.ike.natt.disable_switch_to_natt_port { transport.switch_to_natt(cfg.gateway.natt_port); } break; }
            SaInitOutcome::RetryWithCookie(c) => cookie = Some(c),
            SaInitOutcome::RetryWithGroup(g) => panic!("INVALID_KE_PAYLOAD -> group {g}"),
        }
    }
    println!("IKE_SA_INIT ok with {remote}; sending IKE_AUTH #1");
    let m1 = ike.build_auth_initial().unwrap();
    let mid = m1.header.message_id;
    let dgs = ike.encode(&m1).unwrap();
    let resp = transport.request(&dgs, mid, &cfg.ike.retransmit, &mut |_| {}, &mut |_| {}).expect("IKE_AUTH #1 response");
    let msg = ike.decode(&resp).expect("decode IKE_AUTH #1 response");
    let eap_req = match ike.handle_auth_response(&msg).expect("IKE_AUTH #1") { AuthResponse::EapRequest(b) => b, _ => panic!("expected EAP request") };
    let req = EapPacket::decode(&eap_req).unwrap();
    println!("EAP request: code {} id {} type {:?} type_data {}", req.code, req.identifier, req.eap_type, hex::encode(&req.type_data));
    let td = EapTlsData { flags: 0, length: Some(hello.len() as u32), data: hello.clone() };
    let pkt = EapPacket::response(req.identifier, 13, td.encode());
    println!("sending probe ClientHello ({} bytes) in EAP id {}", hello.len(), req.identifier);
    let m2 = ike.build_auth_eap(&pkt.encode()).unwrap();
    let mid2 = m2.header.message_id;
    let dgs2 = ike.encode(&m2).unwrap();
    let resp2 = transport.request(&dgs2, mid2, &cfg.ike.retransmit, &mut |_| {}, &mut |_| {}).expect("EAP round response");
    let msg2 = ike.decode(&resp2).expect("decode EAP round response");
    match ike.handle_auth_response(&msg2) {
        Ok(AuthResponse::EapRequest(b)) => {
            let r = EapPacket::decode(&b).unwrap();
            println!("SERVER EAP: code {} id {} type {:?} ({} bytes type-data)", r.code, r.identifier, r.eap_type, r.type_data.len());
            if r.code == 4 { println!("  EAP-FAILURE"); }
            else if let Ok(d) = EapTlsData::decode(&r.type_data) { println!("  EAP-TLS flags 0x{:02x} len {:?} data {} bytes", d.flags, d.length, d.data.len()); describe_tls(&d.data); println!("  raw: {}", hex::encode(&d.data)); }
        }
        Ok(other) => println!("unexpected: {:?}", std::mem::discriminant(&other)),
        Err(Error::PeerNotify { notify_type, name, .. }) => println!("SERVER IKE NOTIFY: {notify_type} ({name}) -> ClientHello REJECTED"),
        Err(e) => println!("error: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::pcscf_port;

    #[test]
    fn pcscf_port_is_the_port_of_the_configured_address() {
        assert_eq!(pcscf_port("ueb2bprod.pc.t-mobile.com:35060"), Some(35060));
        assert_eq!(pcscf_port("[2001:db8::1]:5061"), Some(5061));
        assert_eq!(pcscf_port("192.0.2.1:5060"), Some(5060));
        assert_eq!(pcscf_port("2001:db8::1"), None, "a bare IPv6 literal names no port");
        assert_eq!(pcscf_port("pcscf.example.test"), None);
        assert_eq!(pcscf_port("pcscf.example.test:sip"), None);
        assert_eq!(pcscf_port(""), None);
    }
}
