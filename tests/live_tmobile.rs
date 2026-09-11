//! Live end-to-end test against the T-Mobile PROD ePDG (DESIGN.md §13).
//!
//! Needs network access and the real credentials in `tests/fixtures/`. Skipped
//! (with a printed reason) when `EPDG_SKIP_LIVE` is set. Run with
//! `RUST_LOG=debug cargo test --test live_tmobile -- --nocapture` for hex dumps.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use epdg::ipstack::dns::{QType, build_query, parse_response};
use epdg::{Config, EpdgTunnel, Error, InnerUdpSocket, Result};

const TARGET_HOST: &str = "ueb2bprod.pc.t-mobile.com";
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TRIES: usize = 2;
const KEEPALIVE_OBSERVATION: Duration = Duration::from_secs(25);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

/// One DNS query over the tunnel: up to `DNS_TRIES` sends, `DNS_TIMEOUT` each.
fn resolve_over_tunnel(sock: &InnerUdpSocket, server: SocketAddr, name: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    let mut last_err: Option<Error> = None;
    for attempt in 1..=DNS_TRIES {
        let id: u16 = rand::random();
        let query = build_query(id, name, qtype)?;
        println!("  dns {:?} {} -> {} (id {:#06x}, try {}/{})", qtype, name, server, id, attempt, DNS_TRIES);
        sock.send_to(server, &query)?;
        let deadline = Instant::now() + DNS_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                last_err = Some(Error::Timeout("DNS response"));
                break;
            }
            match sock.recv_timeout(remaining)? {
                None => {
                    last_err = Some(Error::Timeout("DNS response"));
                    break;
                }
                Some(dg) => {
                    if dg.src != server || dg.payload.len() < 2 || dg.payload[..2] != id.to_be_bytes() {
                        println!("  ignoring unrelated inner datagram from {} ({} bytes)", dg.src, dg.payload.len());
                        continue;
                    }
                    match parse_response(&dg.payload) {
                        Ok(answers) => return Ok(answers),
                        Err(e) => {
                            println!("  dns response parse failed: {e}");
                            last_err = Some(e);
                            break;
                        }
                    }
                }
            }
        }
    }
    Err(last_err.unwrap_or(Error::Timeout("DNS response")))
}

#[test]
fn live_tmobile_tunnel() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).is_test(false).try_init();

    if std::env::var_os("EPDG_SKIP_LIVE").is_some() {
        println!("SKIPPED: EPDG_SKIP_LIVE is set (live T-Mobile ePDG test not run)");
        return;
    }

    // --- config -----------------------------------------------------------------
    let cfg = Config::from_plist_files(
        &fixture("tmobile_prod_bundle.plist"),
        &fixture("tmobile_creds.plist"),
        &fixture("client.crt"),
        &fixture("client.key"),
    )
    .expect("load config from fixtures");
    println!("gateway: {} (fallback {:?})", cfg.gateway.hostname, cfg.gateway.fallback_addr);

    // --- connect ------------------------------------------------------------------
    let t0 = Instant::now();
    let tunnel = EpdgTunnel::connect(&cfg).expect("EpdgTunnel::connect");
    let info = tunnel.info().clone();
    println!("TunnelInfo: {info:#?}");
    println!(
        "connected in {:?}: {} -> {} IKE {:#018x}/{:#018x} child in {:#010x} out {:#010x} ({} / {} / TLS {})",
        t0.elapsed(),
        info.local_addr,
        info.remote_addr,
        info.ike_spi_i,
        info.ike_spi_r,
        info.child_spi_in,
        info.child_spi_out,
        info.ike_suite,
        info.child_suite,
        info.tls_version
    );

    let a = &info.assigned;
    assert!(
        !a.internal_ipv4.is_empty() || !a.internal_ipv6.is_empty(),
        "no internal address assigned: {a:?}"
    );
    assert!(
        !a.pcscf_ipv4.is_empty() || !a.pcscf_ipv6.is_empty(),
        "no P-CSCF address assigned: {a:?}"
    );

    // --- DNS over the tunnel (proves ESP both ways) ---------------------------------
    // First assigned DNS server of a family we have an inner address for (IPv6 first).
    let dns_server: SocketAddr = if !a.internal_ipv6.is_empty() && !a.dns_ipv6.is_empty() {
        SocketAddr::new(IpAddr::V6(a.dns_ipv6[0]), 53)
    } else if !a.internal_ipv4.is_empty() && !a.dns_ipv4.is_empty() {
        SocketAddr::new(IpAddr::V4(a.dns_ipv4[0]), 53)
    } else {
        panic!("no DNS server of a usable family assigned: {a:?}");
    };
    let sock = tunnel.bind_udp(0).expect("bind inner UDP socket");
    println!("inner UDP port {} -> DNS {}", sock.local_port(), dns_server);

    let mut answers: Vec<IpAddr> = Vec::new();
    for qtype in [QType::AAAA, QType::A] {
        match resolve_over_tunnel(&sock, dns_server, TARGET_HOST, qtype) {
            Ok(v) => {
                println!("  {:?} answers: {:?}", qtype, v);
                answers.extend(v);
            }
            Err(e) => println!("  {:?} lookup failed: {e}", qtype),
        }
    }
    assert!(!answers.is_empty(), "no DNS answer for {TARGET_HOST} over the tunnel");
    drop(sock);

    // --- on-demand DPD -----------------------------------------------------------------
    let rtt = tunnel.dpd().expect("dpd");
    println!("DPD rtt {rtt:?}");

    // --- keepalives ---------------------------------------------------------------------
    println!("sleeping {:?} to observe NAT-T keepalives...", KEEPALIVE_OBSERVATION);
    std::thread::sleep(KEEPALIVE_OBSERVATION);
    assert!(tunnel.is_alive(), "tunnel died while idle");
    let stats = tunnel.stats();
    println!("stats: {stats:?}");
    assert!(stats.keepalives_sent >= 2, "expected >= 2 keepalives in {:?}, sent {}", KEEPALIVE_OBSERVATION, stats.keepalives_sent);

    // --- close --------------------------------------------------------------------------
    match tunnel.close() {
        Ok(()) => println!("closed cleanly (DELETE acknowledged)"),
        Err(e) => println!("close: {e} (best effort)"),
    }

    println!();
    println!("PASS: live T-Mobile ePDG tunnel");
    println!("  gateway         {} ({})", info.remote_addr, cfg.gateway.hostname);
    println!("  handshake       {:?}", info.handshake_duration);
    println!("  IKE suite       {}", info.ike_suite);
    println!("  child suite     {}", info.child_suite);
    println!("  TLS             {}", info.tls_version);
    println!("  inner v4        {:?}", a.internal_ipv4);
    println!("  inner v6        {:?}", a.internal_ipv6);
    println!("  P-CSCF          v4 {:?} v6 {:?}", a.pcscf_ipv4, a.pcscf_ipv6);
    println!("  {TARGET_HOST} -> {:?}", answers);
    println!("  DPD rtt         {rtt:?}");
    println!("  ESP tx/rx       {}/{} packets, keepalives {}", stats.esp_tx_packets, stats.esp_rx_packets, stats.keepalives_sent);
}
