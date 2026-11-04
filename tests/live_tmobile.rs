//! Live end-to-end test against the T-Mobile PROD ePDG (DESIGN.md §13).
//!
//! Needs network access and the real credentials in `tests/fixtures/`. Skipped
//! (with a printed reason) when `EPDG_SKIP_LIVE` is set. Run with
//! `RUST_LOG=debug cargo test --test live_tmobile -- --nocapture` for hex dumps; the tests
//! in this file serialize themselves on `LIVE`, so running them all at once is safe.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use epdg::{Config, EpdgTunnel, Error};

/// The live tests share one subscriber identity (one IMSI + APN, one EAP-AKA sequence
/// number), so two tunnels must never be established at once: an ePDG tears the older
/// session down on a duplicate PDN, and concurrent EAP-AKA runs desynchronise the SQN.
/// libtest runs the tests of one integration binary in parallel by default, so every live
/// test takes this lock for its whole run. Poisoning is irrelevant here — a panicking test
/// has already finished with the network.
static LIVE: Mutex<()> = Mutex::new(());

const TARGET_HOST: &str = "ueb2bprod.pc.t-mobile.com";
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TRIES: usize = 2;
const KEEPALIVE_OBSERVATION: Duration = Duration::from_secs(25);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

/// The tunnel brought up inside this test process (needs the firewall to allow THIS binary).
fn live_in_process() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).is_test(false).try_init();

    if std::env::var_os("EPDG_SKIP_LIVE").is_some() {
        println!("SKIPPED: EPDG_SKIP_LIVE is set (live T-Mobile ePDG test not run)");
        return;
    }

    // --- config -----------------------------------------------------------------
    // EPDG_ACTIVATION_CONFIG=<plist>: the app-side activation config (bundle + credentials +
    // DER client certificate/key in one file) instead of the fixture plists. The env var is
    // inherited by the epdg-connect child, which honours it the same way.
    let cfg = match std::env::var_os("EPDG_ACTIVATION_CONFIG") {
        Some(p) => Config::from_activation_file(std::path::Path::new(&p)).expect("load activation config"),
        None => Config::from_plist_files(
            &fixture("tmobile_prod_bundle.plist"),
            &fixture("tmobile_creds.plist"),
            &fixture("client.crt"),
            &fixture("client.key"),
        )
        .expect("load config from fixtures"),
    };
    println!("gateway: {} (fallback {:?})", cfg.gateway.hostname, cfg.gateway.fallback_addr);

    // --- connect ------------------------------------------------------------------
    let t0 = Instant::now();
    let tunnel = match EpdgTunnel::connect(&cfg) {
        Ok(t) => t,
        Err(e) => {
            if matches!(e, Error::Timeout(_)) {
                eprintln!(
                    "no IKE response from the ePDG. If a per-application firewall (e.g. Little Snitch) is active, \
                     allow outbound UDP 500/4500 for this test binary ({}) — or run target/debug/epdg-connect, \
                     whose path is stable.",
                    std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default()
                );
            }
            panic!("EpdgTunnel::connect failed: {e}");
        }
    };
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
    // The T-Mobile PROD ePDG hands out no P_CSCF_IP{4,6}_ADDRESS attributes (observed live);
    // the P-CSCF is found by resolving its hostname over the tunnel instead (below).
    if a.pcscf_ipv4.is_empty() && a.pcscf_ipv6.is_empty() {
        println!("note: no P-CSCF address in the CFG_REPLY (expected for this ePDG); resolving it via tunnel DNS");
    }
    assert!(!a.dns_ipv4.is_empty() || !a.dns_ipv6.is_empty(), "no DNS server assigned: {a:?}");

    // --- DNS over the tunnel (proves ESP both ways) ---------------------------------
    // smoltcp DNS socket over the assigned servers: AAAA then A (DESIGN §11).
    let mut answers = Vec::new();
    for attempt in 1..=DNS_TRIES {
        println!("  resolve {TARGET_HOST} via tunnel DNS v6 {:?} v4 {:?} (try {attempt}/{DNS_TRIES})", a.dns_ipv6, a.dns_ipv4);
        match tunnel.resolve(TARGET_HOST, DNS_TIMEOUT) {
            Ok(v) => {
                println!("  answers: {v:?}");
                answers = v;
                break;
            }
            Err(e) => println!("  lookup failed: {e}"),
        }
    }
    assert!(!answers.is_empty(), "no DNS answer for {TARGET_HOST} over the tunnel");

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
    assert!(stats.esp_tx_packets >= 1 && stats.esp_rx_packets >= 1, "ESP must have flowed both ways: {stats:?}");

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
    println!(
        "  ESP tx/rx       {}/{} packets, keepalives {}, inner stack tx/rx {}/{} (drops {})",
        stats.esp_tx_packets,
        stats.esp_rx_packets,
        stats.keepalives_sent,
        stats.stack.tx_packets,
        stats.stack.rx_packets,
        stats.stack.rx_queue_drops + stats.stack.udp_queue_drops
    );
}

/// Default live test: drive the crate's stable-path CLI as a subprocess.
///
/// Per-application firewalls (Little Snitch etc.) key their rules on the executable path, and cargo's
/// hash-suffixed integration-test binaries change on every rebuild — `target/debug/epdg-connect` does not.
/// Cargo builds the bin for integration tests and exposes its path as `CARGO_BIN_EXE_epdg-connect`.
/// Set `EPDG_LIVE_INPROCESS=1` to run the tunnel inside the test process instead.
#[test]
fn live_tmobile_tunnel() {
    let _live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var_os("EPDG_SKIP_LIVE").is_some() {
        println!("SKIPPED: EPDG_SKIP_LIVE is set (live T-Mobile ePDG test not run)");
        return;
    }
    if std::env::var_os("EPDG_LIVE_INPROCESS").is_some() {
        return live_in_process();
    }
    let exe = env!("CARGO_BIN_EXE_epdg-connect");
    println!("driving {exe} --hold 25 --tcp-probe (set EPDG_LIVE_INPROCESS=1 to run in-process)");
    let out = std::process::Command::new(exe)
        .args(["--hold", "25", "--tcp-probe"])
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .output()
        .expect("spawn epdg-connect");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(out.status.success(), "epdg-connect exited with {:?}", out.status);
    assert!(stdout.contains("PASS: T-Mobile ePDG tunnel"), "no PASS summary from epdg-connect");
    assert!(
        stdout.contains("ueb2bprod.pc.t-mobile.com -> [") && !stdout.contains("ueb2bprod.pc.t-mobile.com -> []"),
        "P-CSCF did not resolve over the tunnel"
    );
    // `--tcp-probe`: one inner TCP handshake with the P-CSCF (DESIGN §11.2). Reported, not
    // asserted: whether the P-CSCF accepts TCP on that port is not known.
    match stdout.lines().find(|l| l.starts_with("TCP-PROBE")) {
        Some(line) => println!("tcp probe: {line}"),
        None => println!("tcp probe: no TCP-PROBE line in the epdg-connect output"),
    }
}

/// Live MOBIKE address update: drive the same stable-path CLI, force one move part way
/// through the hold and check that the gateway followed it (DESIGN §17.9).
///
/// `--rebind-after 8` makes `epdg-connect` call `EpdgTunnel::force_address_update()` 8 s
/// into a 30 s hold: the path thread rebinds the outer socket to a fresh ephemeral port on
/// the SAME egress address and announces it through the production announce path —
/// `N(UPDATE_SA_ADDRESSES)` + NAT-D over the new port, since this ePDG announces
/// `MOBIKE_SUPPORTED` — which the gateway sees as an ordinary NAT rebinding (RFC 4555
/// §3.5). No Wi-Fi change is needed, so this runs anywhere the plain live test runs.
///
/// The binary prints one machine-checkable line per fact and exits non-zero if any of them
/// failed; this test parses them so a failure names which half of the move broke.
#[test]
fn live_tmobile_address_update() {
    let _live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var_os("EPDG_SKIP_LIVE").is_some() {
        println!("SKIPPED: EPDG_SKIP_LIVE is set (live T-Mobile ePDG test not run)");
        return;
    }
    let exe = env!("CARGO_BIN_EXE_epdg-connect");
    println!("driving {exe} --hold 30 --rebind-after 8");
    let out = std::process::Command::new(exe)
        .args(["--hold", "30", "--rebind-after", "8"])
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .output()
        .expect("spawn epdg-connect");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(out.status.success(), "epdg-connect exited with {:?}", out.status);

    // ADDRESS-UPDATE old=<ip:port> new=<ip:port> updates=<n> ok
    let line = marker(&stdout, "ADDRESS-UPDATE ");
    assert!(line.ends_with(" ok"), "address update did not complete: {line}");
    let old = field(&line, "old=");
    let new = field(&line, "new=");
    let updates: u64 = field(&line, "updates=").parse().expect("updates count");
    assert!(updates >= 1, "expected at least one address update: {line}");
    let port = |a: &str| a.rsplit_once(':').expect("ip:port").1.to_string();
    assert_ne!(port(&old), port(&new), "the outer socket kept its source port: {line}");

    // POST-MOVE DPD rtt=<ms>: the gateway still answers IKE at the new 5-tuple.
    let dpd = marker(&stdout, "POST-MOVE DPD ");
    field(&dpd, "rtt=").parse::<u64>().expect("DPD rtt in ms");

    // POST-MOVE ESP rx delta=<n>: ESP received AFTER the update — the gateway sends the
    // child SA's traffic to the new port, which is the half a NAT rebinding can break.
    let esp = marker(&stdout, "POST-MOVE ESP rx ");
    let delta: u64 = field(&esp, "delta=").parse().expect("ESP rx delta");
    assert!(delta > 0, "no ESP arrived after the address update: {esp}");

    println!();
    println!("PASS: live T-Mobile ePDG address update");
    println!("  outer socket    {old} -> {new}");
    println!("  address updates {updates}");
    println!("  post-move       {dpd}, {esp}");
}

/// The single line of `stdout` starting with `prefix`; panics with the whole output when
/// it is missing, so a failed run says what the binary did print. A second line with the
/// same prefix is a failure too, not something to resolve silently in favour of the first:
/// these markers are one fact each, so two of them mean the binary contradicted itself.
fn marker(stdout: &str, prefix: &str) -> String {
    let mut hits = stdout.lines().filter(|l| l.starts_with(prefix));
    let line = hits.next().unwrap_or_else(|| panic!("no {prefix:?} line in epdg-connect output")).to_string();
    if let Some(second) = hits.next() {
        panic!("two {prefix:?} lines in epdg-connect output: {line:?} and {second:?}");
    }
    line
}

/// The whitespace-delimited value of `key=` in a marker line.
fn field(line: &str, key: &str) -> String {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key:?} in {line:?}"))
        .to_string()
}
