# epdg

A pure-userspace **IKEv2 + EAP-TLS + ESP-in-UDP** client for 3GPP ePDG gateways (VoWiFi), in Rust.
Everything runs over ordinary UDP sockets — no raw sockets, no kernel IPsec, no privileges — driven by a
carrier-bundle style configuration. Verified live against T-Mobile's production ePDG (`ns.sipgeo.t-mobile.com`).

- IKEv2 initiator (RFC 7296) with **EAP-only** authentication (RFC 5998), NAT-T (RFC 3948), IKE fragmentation (RFC 7383),
  cookies, INFORMATIONAL (DPD / DELETE), CREATE_CHILD_SA rekeys, NAT-T keepalives.
- **EAP-TLS** (RFC 5216) over OpenSSL — the ePDG's EAP server only negotiates `TLS_RSA_WITH_AES_128_CBC_SHA`, which
  rustls cannot offer (see `docs/DESIGN.md` §9.3), so the TLS engine is the `openssl` crate.
- Tunnel-mode **ESP** (RFC 4303) encapsulated in UDP/4500, anti-replay window, AES-256-CBC + HMAC-SHA2-256-128.
- Minimal inner **IPv4/IPv6 + UDP** stack (+ IPv6 fragment reassembly, tiny DNS client) so you can talk to hosts inside the tunnel.
- Crypto for IKE/ESP via RustCrypto (`aes`/`cbc`/`hmac`/`sha2`) and `num-bigint` MODP DH, behind a transform registry
  (`crypto::registry`) so more algorithms can be added without touching protocol code.

## Requirements

- Rust 1.85+ (edition 2024).
- OpenSSL 3 development files (macOS: `brew install openssl@3`; Linux: `libssl-dev`). Or build with
  `--features vendored` to compile OpenSSL from source.

## Configuration

`Config::from_plist_bundle` / `from_plist_files` takes the decoded carrier bundle (`imsCommonCredentials`, `CBRoot.TechSettings`
with the IKE / ChildSAs / ExtraConfigurationAttributeRequest blocks), the individual-credentials dictionary
(`imsIndividualCredentials`, `subscriberId`, `token`), and the client certificate + private key PEMs. See
`tests/fixtures/` for the exact shape and `docs/DESIGN.md` §2 for the field mapping (`$subscriber-id` substitution,
transform names, CFG attribute order, defaults taken from the AOSP reference client).

## Usage

```rust
use epdg::{Config, EpdgTunnel};

let cfg = Config::from_plist_files(&bundle, &creds, &cert, &key)?;
let tunnel = EpdgTunnel::connect(&cfg)?;                 // IKE_SA_INIT → IKE_AUTH/EAP-TLS → child SA
let info = tunnel.info();                                // inner addresses, DNS, P-CSCF, SPIs, suites
let sock = tunnel.bind_udp(0)?;                          // an inner UDP endpoint
sock.send_to((info.assigned.dns_ipv6[0], 53).into(), &query)?;
let reply = sock.recv_timeout(std::time::Duration::from_secs(5))?;
tunnel.close()?;                                         // INFORMATIONAL DELETE(IKE)
```

CLI (stable path — handy for per-application firewall rules):

```bash
cargo build --bin epdg-connect
RUST_LOG=info ./target/debug/epdg-connect            # connect, resolve the P-CSCF over the tunnel, DPD, hold, DELETE
./target/debug/epdg-connect probe-tls <ClientHello hex>   # diagnostic: see which TLS suite the EAP server picks
```

## Tests

```bash
cargo test                          # 316 offline unit tests + the live test
EPDG_SKIP_LIVE=1 cargo test         # skip the live test
RUST_LOG=debug cargo test --test live_tmobile -- --nocapture   # live: hex dumps of every IKE datagram
```

`tests/live_tmobile.rs` connects to the T-Mobile PROD ePDG with the fixture credentials, asserts an inner address,
resolves `ueb2bprod.pc.t-mobile.com` through the tunnel (proves ESP in both directions), runs a DPD, observes
NAT-T keepalives, and tears down cleanly. It needs UDP egress on 500/4500; a per-application firewall
(e.g. Little Snitch) must allow the test binary or `target/debug/epdg-connect`.

## Layout

`config` · `crypto` (traits, AES-CBC, HMAC-SHA2, MODP DH, registry) · `ike` (header/payload/message/fragment codecs,
keys, auth, nat, transport, `session::IkeInitiator` sans-I/O state machine) · `eap` (packet, tls) · `esp` (codec, replay)
· `ipstack` (ipv4, ipv6, udp, dns) · `tunnel` (threads: rx demux, keepalive, DPD/rekey timers; `EpdgTunnel` facade).
Design contract and the byte-level facts mirrored from the AOSP client: `docs/DESIGN.md`, `docs/AOSP_FACTS*.md`.

## Notes from the live bring-up

- The ePDG's EAP-TLS server negotiates only `TLS_RSA_WITH_AES_128_CBC_SHA` (TLS 1.2, no EMS); the server certificate is a
  public DigiCert cert for `nsp.epc.mnc260.mcc310.pub.3gppnetwork.org` (validation is off by default per the bundle's
  `ValidateRemoteCertificate=false`, but can be enabled with a CA bundle).
- It returns no `P_CSCF_IP*_ADDRESS` config attributes; resolve the P-CSCF hostname over the assigned tunnel DNS.
- NAT_DETECTION_SOURCE_IP is deliberately hashed over `192.0.2.0` (as the AOSP client does) so the gateway always
  selects UDP-encapsulated ESP — the only kind a userspace client can carry.
