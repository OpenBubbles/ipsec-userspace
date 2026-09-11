//! `epdg-connect` — stable-path CLI that brings up the ePDG tunnel from a carrier
//! bundle + credentials, proves it end-to-end (DNS over the tunnel, DPD, keepalives)
//! and holds it open. Exists mainly so a per-application firewall rule (Little Snitch
//! etc.) can be granted once: `cargo test` binaries get a new hash-suffixed path on
//! every build, `target/debug/epdg-connect` does not.
//!
//! Usage: epdg-connect [--bundle P] [--creds P] [--cert P] [--key P] [--hold SECS] [--no-dns]
//! Defaults point at tests/fixtures/. Set RUST_LOG=debug for hex dumps.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use epdg::ipstack::dns::{QType, build_query, parse_response};
use epdg::{Config, EpdgTunnel, Error, InnerUdpSocket, Result};

const TARGET_HOST: &str = "ueb2bprod.pc.t-mobile.com";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

fn resolve_over_tunnel(sock: &InnerUdpSocket, server: SocketAddr, name: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    let mut last_err: Option<Error> = None;
    for attempt in 1..=2 {
        let id: u16 = rand::random();
        let query = build_query(id, name, qtype)?;
        println!("  dns {:?} {} -> {} (id {:#06x}, try {}/2)", qtype, name, server, id, attempt);
        sock.send_to(server, &query)?;
        let deadline = Instant::now() + Duration::from_secs(5);
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
                        continue;
                    }
                    match parse_response(&dg.payload) {
                        Ok(a) => return Ok(a),
                        Err(e) => {
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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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
                println!("epdg-connect [--bundle P] [--creds P] [--cert P] [--key P] [--hold SECS] [--no-dns]");
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

    let mut answers: Vec<IpAddr> = Vec::new();
    if do_dns {
        let dns_server: Option<SocketAddr> = if !a.internal_ipv6.is_empty() && !a.dns_ipv6.is_empty() {
            Some(SocketAddr::new(IpAddr::V6(a.dns_ipv6[0]), 53))
        } else if !a.internal_ipv4.is_empty() && !a.dns_ipv4.is_empty() {
            Some(SocketAddr::new(IpAddr::V4(a.dns_ipv4[0]), 53))
        } else {
            None
        };
        match dns_server {
            None => println!("no DNS server of a usable family assigned; skipping DNS check"),
            Some(server) => match tunnel.bind_udp(0) {
                Err(e) => println!("bind inner UDP failed: {e}"),
                Ok(sock) => {
                    println!("inner UDP port {} -> DNS {}", sock.local_port(), server);
                    for qtype in [QType::AAAA, QType::A] {
                        match resolve_over_tunnel(&sock, server, TARGET_HOST, qtype) {
                            Ok(v) => {
                                println!("  {:?} answers: {:?}", qtype, v);
                                answers.extend(v);
                            }
                            Err(e) => println!("  {:?} lookup failed: {e}", qtype),
                        }
                    }
                }
            },
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
