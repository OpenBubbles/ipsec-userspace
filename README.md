# epdg

A pure-userspace **IKEv2 + EAP-TLS + ESP-in-UDP** client for 3GPP ePDG gateways (VoWiFi), in Rust.
Everything runs over ordinary UDP sockets — no raw sockets, no kernel IPsec, no privileges — driven by a
carrier-bundle style configuration. Verified live against T-Mobile's production ePDG (`ns.sipgeo.t-mobile.com`).

- IKEv2 initiator (RFC 7296) with **EAP-only** authentication (RFC 5998), NAT-T (RFC 3948), IKE fragmentation (RFC 7383),
  cookies, INFORMATIONAL (DPD / DELETE), CREATE_CHILD_SA rekeys, NAT-T keepalives.
- **EAP-TLS** (RFC 5216) over OpenSSL — the ePDG's EAP server only negotiates `TLS_RSA_WITH_AES_128_CBC_SHA`, which
  rustls cannot offer (see `docs/DESIGN.md` §9.3), so the TLS engine is the `openssl` crate.
- Tunnel-mode **ESP** (RFC 4303) encapsulated in UDP/4500, anti-replay window, AES-256-CBC + HMAC-SHA2-256-128.
- Inner IP stack = **smoltcp 0.14** over the ESP data plane (a `Medium::Ip` device: the tunnel-mode ESP payload *is* the IP
  packet): IPv4/IPv6, inner UDP sockets (`EpdgTunnel::bind_udp`), a DNS resolver over the assigned servers
  (`EpdgTunnel::resolve`), IPv4 fragmentation/reassembly, ICMP echo replies; a small shim (`ipstack::frag`) fragments and
  reassembles IPv6 for the wire MTU, which smoltcp 0.14 cannot do on `Medium::Ip`; TCP sockets are one method away in the same `SocketSet`.
- **Mobility and liveness** (`docs/DESIGN.md` §17): the egress route is watched (or reported by the caller through
  `EpdgTunnel::network_changed()`); an address change rebinds the outer socket — same SAs, same keys, new 5-tuple — and
  announces it with MOBIKE `UPDATE_SA_ADDRESSES` (RFC 4555) or, against a gateway without MOBIKE, with the RFC 7296
  §2.23 dynamic address update, tolerating a 30 s outage — retransmission exhaustion included — before giving up. A
  DPD-independent one-way-traffic probe notices a gateway that stopped answering, even when nothing was ever received,
  a slower idle probe covers a registration that never transmits at all, and an unrecoverable tunnel fails every inner
  socket with `NotConnected` at once, so the SIP transport above closes its connection instead of hanging. (Acting on that close — rebuilding the tunnel — is the embedder's job; see
  `docs/DESIGN.md` §17.6 for where the chain currently ends.)
- Crypto for IKE/ESP via RustCrypto (`aes`/`cbc`/`hmac`/`sha2`) and `num-bigint` MODP DH, behind a transform registry
  (`crypto::registry`) so more algorithms can be added without touching protocol code.

## Requirements

- Rust 1.85+ (edition 2024).
- OpenSSL 3 development files (macOS: `brew install openssl@3`; Linux: `libssl-dev`). Or build with
  `--features vendored` to compile OpenSSL from source.

## Configuration

`Config::from_plist_bundle` / `from_plist_files` takes the decoded carrier bundle (`imsCommonCredentials`, `CBRoot.TechSettings`
with the IKE / ChildSAs / ExtraConfigurationAttributeRequest blocks), the individual-credentials dictionary
(`imsIndividualCredentials`, `subscriberId`), and the client certificate + private key as DER (`from_plist_files`
reads PEM files and converts them once via `epdg::pem`; nothing downstream sees PEM). See
`tests/fixtures/` for the exact shape and `docs/DESIGN.md` §2 for the field mapping (`$subscriber-id` substitution,
transform names, CFG attribute order, defaults taken from the AOSP reference client).

## Usage

```rust
use epdg::{Config, EpdgTunnel};

let cfg = Config::from_plist_files(&bundle, &creds, &cert, &key)?;
let tunnel = EpdgTunnel::connect(&cfg)?;                 // IKE_SA_INIT → IKE_AUTH/EAP-TLS → child SA
let info = tunnel.info();                                // inner addresses, DNS, P-CSCF, SPIs, suites
let pcscf = tunnel.resolve("ueb2bprod.pc.t-mobile.com", Duration::from_secs(5))?; // AAAA then A via the tunnel DNS
let sock = tunnel.bind_udp(0)?;                          // an inner UDP endpoint (smoltcp socket)
sock.send_to((pcscf[0], 5060).into(), &sip_register)?;   // source address picked by smoltcp per family
let reply = sock.recv_timeout(Duration::from_secs(5))?;  // Option<UdpDatagram { src, dst, payload }>
tunnel.close()?;                                         // INFORMATIONAL DELETE(IKE), stops all threads
```

## NetStack

`epdg::NetStack` (DESIGN.md §16) is one synchronous, object-safe socket/DNS abstraction implemented by both the host
OS stack (`StdNetStack`: `std::net` sockets + the libc resolver) and the tunnel (`EpdgTunnel`: inner UDP sockets + the
smoltcp DNS socket over the gateway-assigned servers). Application code — a SIP client, say — is written once against
`&dyn NetStack` / `Arc<dyn NetStack>` and runs unchanged on either:

```rust
use std::time::Duration;
use epdg::{EpdgTunnel, NetStack, StdNetStack};

/// Resolve `host`, send `payload` to its first address on `port`, return the reply.
fn ping(stack: &dyn NetStack, host: &str, port: u16, payload: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
    let addrs = stack.resolve(host, Duration::from_secs(5))?;        // this stack's resolver; IP literals are immediate
    let sock = stack.bind_udp(0)?;                                   // ephemeral port
    println!("{} {} -> {}:{port}", stack.name(), sock.local_addr(), addrs[0]);
    sock.send_to((addrs[0], port).into(), payload)?;
    Ok(sock.recv_timeout(Duration::from_secs(5))?.map(|(_peer, data)| data))
}

let os = StdNetStack::new();                                         // dual-stack [::] (or 0.0.0.0 without IPv6)
ping(&os, "localhost", 5060, b"OPTIONS ...")?;
let tunnel = EpdgTunnel::connect(&cfg)?;
ping(&tunnel, "ueb2bprod.pc.t-mobile.com", 5060, b"OPTIONS ...")?;   // same code, inside the tunnel
```

`local_addrs()` gives the addresses the stack sources traffic from (SIP Via/Contact): the tunnel's inner addresses, or
for the OS stack the bind address / the route-selected egress address per family. TCP (`connect_tcp`, `listen_tcp`,
`TcpStreamLike` shared between a reader and a writer thread, `StreamIo` as `Read + Write` for TLS) is **std-only for
now**: the tunnel returns `ErrorKind::Unsupported` until smoltcp's TCP socket is wired to the stack thread. Crate errors
are mapped to `io::Error` by `netstack::to_io` (`Timeout` → `TimedOut`, `Closed` → `NotConnected`).

CLI (stable path — handy for per-application firewall rules):

```bash
cargo build --bin epdg-connect
RUST_LOG=info ./target/debug/epdg-connect            # connect, resolve the P-CSCF over the tunnel, DPD, hold, DELETE
./target/debug/epdg-connect probe-tls <ClientHello hex>   # diagnostic: see which TLS suite the EAP server picks
```

## Tests

```bash
cargo test                          # 354 offline unit tests + the live test
EPDG_SKIP_LIVE=1 cargo test         # skip the live test
RUST_LOG=debug cargo test --test live_tmobile -- --nocapture   # live: hex dumps of every IKE datagram
```

The inner stack is tested offline with an in-process **two-stack loopback** (`ipstack::stack::tests`): two `InnerStack`s
on different IPv6 /64s (+ a v4 /32 each) whose device sinks feed each other — UDP both ways with exact endpoints,
off-prefix routing, 3000-byte IPv4 and IPv6 datagrams fragmented at the wire MTU 1280 and reassembled, ICMP echo,
bursts and fire-and-forget sends, `resolve()` against a tiny in-process DNS server on the far stack's port 53, timeouts,
port allocation, queue bounds, shutdown semantics. The `NetStack` abstraction runs one generic UDP exercise over both
backends (loopback `StdNetStack`s and the two-stack loopback), the TCP exercise on `StdNetStack` over loopback, and the
libc resolver against `localhost` only.

`tests/live_tmobile.rs` drives `target/debug/epdg-connect` (stable path, so one firewall rule keeps working across rebuilds; set `EPDG_LIVE_INPROCESS=1` to run the tunnel inside the test process instead). It connects to the T-Mobile PROD ePDG with the fixture credentials, asserts an inner address,
resolves `ueb2bprod.pc.t-mobile.com` through `&dyn NetStack` (smoltcp DNS over ESP — proves ESP in both directions and covers the tunnel's `NetStack` implementation),
runs a DPD, observes NAT-T keepalives, and tears down cleanly. It needs UDP egress on 500/4500; a per-application
firewall (e.g. Little Snitch) must allow the test binary or `target/debug/epdg-connect`.

## Layout

`config` · `crypto` (traits, AES-CBC, HMAC-SHA2, MODP DH, registry) · `ike` (header/payload/message/fragment codecs,
keys, auth, nat, transport, `session::IkeInitiator` sans-I/O state machine) · `eap` (packet, tls) · `esp` (codec, replay)
· `ipstack` (`device::EspDevice` — smoltcp `Medium::Ip` device over ESP; `stack::InnerStack` — `Interface` + `SocketSet`
+ the single stack thread, `InnerUdpSocket`, `resolve`) · `tunnel` (threads: rx demux, stack, keepalive, DPD/rekey
timers; `EpdgTunnel` facade) · `netstack` (`NetStack` / `UdpSocketLike` / `TcpStreamLike` / `TcpListenerLike` traits,
`StdNetStack`, the tunnel implementations). Design contract and the byte-level facts mirrored from the AOSP client: `docs/DESIGN.md`,
`docs/AOSP_FACTS*.md`.

Threading of the inner stack (DESIGN.md §11): only the `epdg-stack` thread drives smoltcp (`Interface::poll`), behind
one mutex + condvar. The ESP rx thread decapsulates and pushes the inner IP packet (`push_rx`, bounded queue,
drop-oldest); `send_to` / `bind_udp` / `resolve` hold the lock only to enqueue and then notify; received datagrams
reach `InnerUdpSocket::recv_timeout` through a bounded channel without touching the lock. smoltcp's compile-time
limits are raised through Cargo features (8 addresses, 4 routes, 4 DNS servers, 8 DNS results, 8 KiB
fragmentation/reassembly buffers); `child.inner_mtu` (default 1280) is the wire MTU, `child.inner_mtu_stack` (default
16384) the MTU smoltcp sees — the device fragments outbound packets to the wire MTU and `push_rx` reassembles inbound
IPv6 fragment sets (DESIGN.md §11.1).

## Notes from the live bring-up

- The ePDG's EAP-TLS server negotiates only `TLS_RSA_WITH_AES_128_CBC_SHA` (TLS 1.2, no EMS); the server certificate is a
  public DigiCert cert for `nsp.epc.mnc260.mcc310.pub.3gppnetwork.org` (validation is off by default per the bundle's
  `ValidateRemoteCertificate=false`, but can be enabled with a CA bundle).
- It returns no `P_CSCF_IP*_ADDRESS` config attributes; resolve the P-CSCF hostname over the assigned tunnel DNS.
- NAT_DETECTION_SOURCE_IP is deliberately hashed over `192.0.2.0` (as the AOSP client does) so the gateway always
  selects UDP-encapsulated ESP — the only kind a userspace client can carry.
- smoltcp 0.14 has **no IPv6 fragmentation or reassembly on `Medium::Ip`** (its `proto-ipv6-fragmentation` feature
  only covers 6LoWPAN) and would answer an inbound IPv6 Fragment header with an ICMPv6 Parameter Problem — fatal for
  SIP, whose 200 OK / NOTIFY arrive IPv6-fragmented from the P-CSCF. `ipstack::frag` therefore fragments on the way
  out and reassembles on the way in around the device (DESIGN.md §11.1); `send_to` accepts payloads up to
  `inner_mtu_stack - 48` (v6) / `- 28` (v4). smoltcp also sets DF on every IPv4 packet it emits, so the shim ignores DF.
