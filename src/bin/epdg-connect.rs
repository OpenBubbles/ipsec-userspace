//! `epdg-connect` — stable-path CLI that brings up the ePDG tunnel from a carrier
//! bundle + credentials, proves it end-to-end (DNS over the tunnel, DPD, keepalives)
//! and holds it open. Exists mainly so a per-application firewall rule (Little Snitch
//! etc.) can be granted once: `cargo test` binaries get a new hash-suffixed path on
//! every build, `target/debug/epdg-connect` does not.
//!
//! Usage: epdg-connect [--bundle P] [--creds P] [--cert PEM] [--key PEM] [--hold SECS] [--no-dns]
//! Defaults point at tests/fixtures/. Set RUST_LOG=debug for hex dumps.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use epdg::{Config, EpdgTunnel, Error, NetStack};

const TARGET_HOST: &str = "ueb2bprod.pc.t-mobile.com";
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

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
    let mut hold = Duration::from_secs(25);
    let mut do_dns = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| panic!("missing value for {a}"));
        match a.as_str() {
            "--bundle" => bundle = PathBuf::from(val()),
            "--creds" => creds = PathBuf::from(val()),
            "--cert" => cert = PathBuf::from(val()),
            "--key" => key = PathBuf::from(val()),
            "--hold" => hold = Duration::from_secs(val().parse().expect("--hold seconds")),
            "--no-dns" => do_dns = false,
            "-h" | "--help" => {
                println!("epdg-connect [--bundle P] [--creds P] [--cert PEM] [--key PEM] [--hold SECS] [--no-dns]");
                return;
            }
            other => panic!("unknown argument {other}"),
        }
    }

    let cfg = match Config::from_plist_files(&bundle, &creds, &cert, &key) {
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

    match tunnel.dpd() {
        Ok(rtt) => println!("DPD rtt {rtt:?}"),
        Err(e) => println!("DPD failed: {e}"),
    }

    println!("holding tunnel for {hold:?} (keepalives every {}s)...", cfg.ike.natt.keepalive_interval_secs);
    std::thread::sleep(hold);
    let alive = tunnel.is_alive();
    let stats = tunnel.stats();
    println!("alive={alive} stats: {stats:?}");

    match tunnel.close() {
        Ok(()) => println!("closed cleanly (DELETE acknowledged)"),
        Err(e) => println!("close: {e} (best effort)"),
    }

    println!();
    println!("{}: T-Mobile ePDG tunnel", if alive { "PASS" } else { "FAIL (tunnel died while idle)" });
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
    if !alive {
        std::process::exit(1);
    }
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
