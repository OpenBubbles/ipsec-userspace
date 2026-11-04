# epdg-rs — Design & Implementation Spec

Userspace IKEv2 + EAP-TLS (EAP-only) + ESP-in-UDP client for 3GPP ePDG gateways,
in Rust. This document is the contract every module is written against. Where it
gives a byte layout or a formula, implement it exactly; where it gives a Rust
signature, implement that signature (add private helpers freely).

Reference implementation being mirrored: the AOSP `frameworks/opt/net/ike` client as
vendored in `/Users/annahagen/Downloads/epdg-test/app/src/main/java/com/epdgclient/vendor/`
(Java), which is PROVEN to interoperate with this exact ePDG. §14 records what it does
on the wire. When the RFC allows a choice, do what AOSP does.

RFCs: 7296 (IKEv2), 5998 (EAP-only auth), 3748 (EAP), 5216 (EAP-TLS), 9190 (EAP-TLS
1.3), 4303 (ESP), 3948 (UDP-encap ESP), 7383 (IKEv2 fragmentation), 3526 (MODP groups),
7651 (P-CSCF cfg attrs), 5705 (TLS exporters), 8200 (IPv6).

## 0. Scope

Implemented (exactly what the T-Mobile PROD ePDG profile negotiates):
- IKEv2 initiator: IKE_SA_INIT, IKE_AUTH (multi-round EAP), INFORMATIONAL (DPD, DELETE),
  CREATE_CHILD_SA (child + IKE rekey), NAT-T port switch, IKEv2 fragmentation (RFC 7383).
- Authentication: **EAP-only** (RFC 5998). No PSK / certificate IKE auth (extension seam only).
- EAP: Identity + EAP-TLS (rustls). No EAP-AKA.
- Crypto: ENCR_AES_CBC-256, AUTH_HMAC_SHA2_256_128, PRF_HMAC_SHA2_256, DH group 14.
  All behind traits + a registry so more can be added.
- ESP tunnel mode over UDP/4500, anti-replay, NAT-T keepalive, inner IPv4/IPv6 stack (smoltcp)
  with UDP, TCP (connections and listeners, §11.2) and a DNS client.
- Config: carrier-bundle plist model (`Config::from_plist_bundle`, or one `Config::from_activation_plist` file).

- Mobility and liveness (§17): a path monitor that rebinds the outer socket when the host's
  egress address changes and announces it with MOBIKE `UPDATE_SA_ADDRESSES` (RFC 4555) or the
  RFC 7296 §2.23 fallback; a one-way-traffic probe independent of the bundle's DPD flag.

Not implemented: responder role, PSK/cert auth, EAP-AKA, IPComp, transport mode, ESN,
3GPP notifies (constants present); on the mobility side, responder-initiated
address changes and peer address lists (`ADDITIONAL_IP4/IP6_ADDRESS` are logged and
ignored), and AOSP's `migrateAllChildSAs` child rekey on a non-MOBIKE move, which is done
only as an escalation when ESP demonstrably stalls after the move — we transmitted from the new address and nothing
came back (§17.3).

## 1. Module ownership

| File | Owner | Public surface |
|---|---|---|
| `src/config.rs` | agent:config | §2 |
| `src/crypto/{aes_cbc,hmac_sha2,dh_modp,registry}.rs` | agent:crypto | §3 (traits already in `crypto/mod.rs`) |
| `src/ike/{header,payload}.rs` | agent:codec | §4.1–4.2 |
| `src/ike/{message,fragment}.rs` | agent:message | §4.3–4.4 |
| `src/ike/{keys,auth,nat}.rs` | agent:keys | §5, §6 |
| `src/ike/transport.rs` | agent:transport | §7, §17.1 |
| `src/ike/session.rs` | agent:session | §8, §17.2 |
| `src/eap/{packet,tls}.rs` | agent:eap | §9 |
| `src/esp/{codec,replay}.rs` | agent:esp | §10 |
| `src/ipstack/{device,frag,stack}.rs` | agent:ipstack | §11, §11.1, §11.2 |
| `src/tunnel.rs` + `tests/live_tmobile.rs` | agent:tunnel | §12, §13, §17 |

Fixed already (do not change signatures): `src/lib.rs`, `src/error.rs`, `src/crypto/mod.rs`
(traits), `src/ike/constants.rs`. Use `crate::{Error, Result}` and `crate::ike::constants::*`.
Every module carries `#[cfg(test)] mod tests` with unit tests (§13).

Conventions: edition 2024; `log` crate for logging (`debug!` for wire dumps via `hex`,
`info!` for state transitions, `warn!` for tolerated anomalies); no `unwrap()` on wire
input — return `Error::Decode`; big-endian everywhere on the wire; secrets in structs that
`impl zeroize::ZeroizeOnDrop` where practical (keys, MSK, DH private).

## 2. Configuration (`config.rs`)

```rust
pub struct Config {
    pub gateway: GatewayConfig,
    pub identity: IdentityConfig,
    pub eap_tls: EapTlsCredentials,
    pub ike: IkeConfig,
    pub child: ChildConfig,
    pub ims: ImsConfig,
}
pub struct GatewayConfig {
    pub hostname: String,              // imsCommonCredentials."gateway-address"
    pub fallback_addr: Option<IpAddr>, // CBRoot.TechSettings.IKE.RemoteAddress
    pub ike_port: u16,                 // 500
    pub natt_port: u16,                // 4500
    pub local_addr: Option<IpAddr>,    // bind address override; None = OS default
}
pub struct IdentityConfig {
    pub local_id: IdSpec,          // IDi: IKE.LocalIdentifier with "$subscriber-id" -> top-level subscriberId
    pub remote_id: IdSpec,         // IDr: imsIndividualCredentials.apn as FQDN
    pub accept_any_remote_id: bool,// default true (ePDG returns its own identity, not the APN)
    pub eap_identity: Vec<u8>,     // EAP Response/Identity body; default = local_id string
}
pub struct IdSpec { pub id_type: u8 /* ID_* */, pub data: Vec<u8> }
impl IdSpec { pub fn from_string(s: &str) -> IdSpec; /* '@' -> ID_RFC822_ADDR; parses as IP -> ID_IPV4/6_ADDR; else ID_FQDN */ }
pub struct EapTlsCredentials {          // DER only — PEM is converted once, at the edge, by the `pem` module
    pub client_cert_der: Vec<u8>,      // the leaf, one DER Certificate (the only certificate sent)
    pub client_key_der: Vec<u8>,       // unencrypted PKCS#8 PrivateKeyInfo, DER
    pub server_ca_der: Vec<Vec<u8>>,   // bundle ePdgCACert (<data>, one DER cert; empty = none)
    pub validate_server_cert: bool,    // IKE.ValidateRemoteCertificate
    pub tls_server_name: Option<String>, // SNI; None = use gateway IP (no SNI sent)
    pub max_fragment_len: usize,       // outbound EAP-TLS fragment TLS-data bytes; default 1024 (AOSP)
    pub allow_tls13: bool,             // default FALSE: AOSP is TLS 1.2 only. If true, also offer 1.3 (MSK per RFC 9190)
}
pub struct IkeConfig {
    pub proposals: Vec<IkeProposal>,   // IKE.Proposals[] in order
    pub lifetime_secs: u64,            // IKE.Proposals[0].Lifetime (80000)
    pub eap_only: bool,                // AuthenticationMethod == "None" -> true (always true for now)
    pub eap_method: String,            // "EAP-TLS"
    pub dpd: DpdConfig,
    pub natt: NattConfig,
    pub retransmit: RetransmitConfig,
    pub fragmentation: bool,           // announce IKEV2_FRAGMENTATION_SUPPORTED; default true
    pub fragment_threshold: usize,     // SKF split when total IKE message > this; default 1280 (AOSP DEFAULT_FRAGMENT_SIZE)
    pub signature_hash_algorithms: bool,// send N(SIGNATURE_HASH_ALGORITHMS) in IKE_SA_INIT; default true (AOSP always does)
    pub mobike: bool,                  // announce MOBIKE_SUPPORTED in IKE_AUTH; default true (AOSP glue sets IKE_OPTION_MOBIKE)
    pub initial_contact: bool,         // default false
    pub nonce_len: usize,              // default 32
    pub rekey_margin_fraction: f64,    // rekey at lifetime*(1-margin) with jitter; default 0.1
}
pub struct IkeProposal {
    pub encryption: Vec<String>, pub integrity: Vec<String>, pub prf: Vec<String>, pub dh_groups: Vec<u16>,
}
pub struct ChildConfig {
    pub proposals: Vec<ChildProposal>, // ChildSAs.FirstChild.ChildProposals[]
    pub lifetime_secs: u64,
    pub replay_window: u32,            // ReplayWindowSize (12) — codec rounds up to >= 32
    pub cfg_requests: Vec<u16>,        // CFG attribute types to request, in emission order (§8.3)
    pub install_policies: bool,        // carried, unused
    pub inner_mtu: usize,              // inner interface MTU (bytes of IP packet); not in the bundle, default 1280 (§11)
}
pub struct ChildProposal { pub encryption: Vec<String>, pub integrity: Vec<String>, pub dh_groups: Vec<u16> /* PFS; empty */ }
pub struct DpdConfig { pub enabled: bool, pub interval_secs: u64, pub retry_interval_secs: u64, pub max_retries: u32 }
pub struct NattConfig {
    pub keepalive_interval_secs: u64,      // default 10 (AOSP IKE_NATT_KEEPALIVE_DELAY_SEC_DEFAULT); bundle NATTKeepAliveOffload only carried
    pub disable_switch_to_natt_port: bool, // bundle DisableSwitchToNATTPort (false)
    pub force_udp_encap: bool,             // default true: hash NAT_DETECTION_SOURCE_IP over the FAKE local address 192.0.2.0 (§6) so the
                                           // responder always detects a NAT and uses UDP-encapsulated ESP (AOSP needEnableForceUdpEncap for IPv4 peers)
    pub keepalive_offload: bool,           // carried
}
pub struct RetransmitConfig { pub initial_timeout_ms: u64 /* 500 */, pub backoff_multiplier: f64 /* 2.0 */, pub max_attempts: u32 /* 5 transmissions total (AOSP {500,1000,2000,4000,8000}): send at t=0, +0.5, +1.5, +3.5, +7.5 s cumulative; after the 5th send wait 8 s then Error::Timeout (15.5 s) */ }
pub struct ImsConfig { pub pcscf_address: String, pub apn: String, pub impu: String, pub sip_realm: String, pub username: String, pub password: String, pub imsi: String }

impl Config {
    /// Build from the decoded carrier bundle (root dict with imsCommonCredentials/CBRoot),
    /// the individual-credentials dict (imsIndividualCredentials/subscriberId/...), and the client
    /// certificate (DER) + private key (PKCS#8 DER).
    pub fn from_plist_bundle(bundle: &plist::Value, creds: &plist::Value, client_cert_der: &[u8], client_key_der: &[u8]) -> Result<Config>;
    /// Files: the plists plus PEM certificate/key files (the fixture format), converted via `pem`.
    pub fn from_plist_files(bundle: &Path, creds: &Path, client_cert_pem: &Path, client_key_pem: &Path) -> Result<Config>;
    /// One "activation config" plist carrying `cred` + `bundle` + `tunnel { certificate_der, key_der,
    /// subscriber_id }` — the same inputs with no PEM anywhere. `from_activation_file` reads it from disk.
    pub fn from_activation_plist(root: &plist::Value) -> Result<Config>;
    pub fn from_activation_file(path: &Path) -> Result<Config>;
    /// Resolve the gateway: DNS `hostname` (all A/AAAA), then `fallback_addr`. Prefers IPv4.
    pub fn gateway_candidates(&self) -> Result<Vec<IpAddr>>;
}
```
Mapping rules:
- `IKE.Proposals[i].EncryptionAlgorithm` is a **string** in the IKE block and an **array of
  strings** in `ChildProposals`; accept both shapes everywhere (`string_or_array`).
- Name→transform mapping lives in `crypto::registry::{cipher_by_name, integrity_by_name, prf_by_name}`;
  config keeps names, `session` resolves them. Unknown name → `Error::Unsupported` at connect.
- `cfg_requests` default (EXACT AOSP wire order, all zero-length): `[INTERNAL_IP4_ADDRESS(1), INTERNAL_IP6_ADDRESS(8),
  INTERNAL_IP4_DNS(3), INTERNAL_IP6_DNS(10), INTERNAL_IP4_NETMASK(2), P_CSCF_IP4_ADDRESS(20), P_CSCF_IP6_ADDRESS(21),
  APPLICATION_VERSION(7)]`. The P-CSCF entries come from `ExtraConfigurationAttributeRequestv4/v6` mapped by `Identifier`
  (16384→20, 16386→21; the bundle lists 16386 twice — dedupe). NETMASK(2) is what AOSP auto-appends whenever an IPv4 address is
  requested; APPLICATION_VERSION(7) is always appended last by AOSP. Keep this order for byte-exact parity (CP = 4+4+8*4 = 40 bytes).
- `eap_only = (AuthenticationMethod == "None")`; error if `EAPMethod != "EAP-TLS"` (only method implemented).
- DPD from `DeadPeerDetection{Enabled,Interval,RetryInterval,MaxRetries}`; NAT-T from
  `NATTKeepAliveOffload` (carried; we always run a software keepalive), `DisableSwitchToNATTPort`.
- Defaults not in the bundle come from §14 (AOSP `IkeSessionParams` defaults): nonce 32 B, retransmit {500 ms ×2, 5 sends, fail at 15.5 s},
  NAT-T keepalive 10 s, fragment threshold 1280, EAP-TLS fragment 1024, TLS 1.2 only, MOBIKE on, SIGNATURE_HASH_ALGORITHMS on,
  rekey at soft lifetime = `lifetime_secs * (1 - rekey_margin_fraction)` with NO jitter (AOSP has none).
- `ims.*` from `imsIndividualCredentials`; carried for the SIP layer, unused here (the creds plist's provisioning `token` is not parsed).

## 3. Crypto (`crypto/*`)

Traits are fixed in `crypto/mod.rs`. Implement:
- `aes_cbc::AesCbc { key_bits: 128|192|256 }` via `aes` + `cbc` with `NoPadding`
  (`cbc::Encryptor<aes::Aes256>` etc, `cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut}`),
  `block_len = iv_len = 16`, `key_len_attr_bits = Some(bits)`. Reject bad key/iv/len with `Error::Crypto`.
- `hmac_sha2::HmacSha256Integ` (`AUTH_HMAC_SHA2_256_128`: key 32, icv 16; verify constant-time via `subtle`),
  `HmacSha256Prf` (`PRF_HMAC_SHA2_256`: key_len 32, out 32). Also provide SHA-384/512 variants
  (`AUTH_HMAC_SHA2_384_192` key 48 icv 24; `_512_256` key 64 icv 32; PRF 384/512) — cheap and proves extensibility.
- `dh_modp::ModpGroup` with the RFC 3526 primes for groups 14 (2048), 15 (3072), 16 (4096) and
  RFC 2409 groups 2 (1024), 5 (1536); generator 2. Private exponent: uniformly random in [2, p−2]
  via `num_bigint::RandBigInt`. `public_value`/`shared_secret` are big-endian, LEFT-ZERO-PADDED to
  `public_len()` (RFC 7296 §2.14: g^ir "is represented as a string of octets in big endian order
  padded with zeros if necessary to make it the length of the modulus"). Validate peer value in [2, p−2].
  Group 14 prime hex (RFC 3526 §3) MUST be copied verbatim; unit-test `prime.bits()==2048`,
  first 8 bytes `FFFFFFFFFFFFFFFF`, last 8 bytes `FFFFFFFFFFFFFFFF`, and a KAT `2^1 mod p == 2`, plus a
  round-trip (two keypairs agree on the secret).
- `registry`:
```rust
pub fn cipher(transform_id: u16, key_len_bits: Option<u16>) -> Option<Arc<dyn Cipher>>;
pub fn integrity(transform_id: u16) -> Option<Arc<dyn Integrity>>;
pub fn prf(transform_id: u16) -> Option<Arc<dyn Prf>>;
pub fn dh(group_id: u16) -> Option<Arc<dyn DhGroup>>;
pub fn cipher_by_name(name: &str) -> Option<(u16, Option<u16>)>;   // "AES-256"->(ENCR_AES_CBC,Some(256)), "AES-128", "AES-192", "3DES"->(ENCR_3DES,None)
pub fn integrity_by_name(name: &str) -> Option<u16>;                // "SHA2-256"->AUTH_HMAC_SHA2_256_128, "SHA2-384", "SHA2-512", "SHA1"->AUTH_HMAC_SHA1_96(unimplemented->None at lookup time is fine)
pub fn prf_by_name(name: &str) -> Option<u16>;                      // "SHA2-256"->PRF_HMAC_SHA2_256, ...
pub fn transform_name(ttype: u8, id: u16) -> String;               // for logs
```
Name matching is case-insensitive and tolerant of `AES256`/`AES-CBC-256`/`SHA256`/`HMAC-SHA2-256`.

## 4. IKEv2 wire codec (`ike/header.rs`, `ike/payload.rs`, `ike/message.rs`, `ike/fragment.rs`)

### 4.1 Header (RFC 7296 §3.1), 28 bytes
```
SPIi(8) | SPIr(8) | NextPayload(1) | Version(1)=0x20 | ExchangeType(1) | Flags(1) | MessageID(4) | Length(4)
```
Flags: bit3 INITIATOR (0x08) set on all our messages, bit5 RESPONSE (0x20) on responses, VERSION 0x10 never set.
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IkeHeader { pub spi_i: u64, pub spi_r: u64, pub next_payload: u8, pub version: u8, pub exchange_type: u8, pub flags: u8, pub message_id: u32, pub length: u32 }
impl IkeHeader {
    pub const LEN: usize = 28;
    pub fn encode(&self, out: &mut Vec<u8>);
    pub fn decode(buf: &[u8]) -> Result<IkeHeader>;   // Error::Decode if <28 bytes or major version != 2
    pub fn is_response(&self) -> bool; pub fn is_initiator(&self) -> bool;
}
```
### 4.2 Payloads (§3.2ff). Generic header: `NextPayload(1) | C(1bit)+Reserved(7) | Length(2)` (length includes the 4-byte header).
```rust
pub struct Transform { pub ttype: u8, pub id: u16, pub key_len_bits: Option<u16> }
pub struct Proposal { pub number: u8, pub protocol_id: u8, pub spi: Vec<u8>, pub transforms: Vec<Transform> }
pub struct SaPayload { pub proposals: Vec<Proposal> }
pub struct KePayload { pub group: u16, pub public: Vec<u8> }
pub struct IdPayload { pub id_type: u8, pub data: Vec<u8> }
pub struct AuthPayload { pub method: u8, pub data: Vec<u8> }
pub struct NotifyPayload { pub protocol_id: u8, pub spi: Vec<u8>, pub notify_type: u16, pub data: Vec<u8> }
pub struct DeletePayload { pub protocol_id: u8, pub spis: Vec<Vec<u8>> }   // spi_size derived (0 for IKE, 4 for ESP)
pub struct TrafficSelector { pub ts_type: u8, pub ip_protocol: u8, pub start_port: u16, pub end_port: u16, pub start_addr: Vec<u8>, pub end_addr: Vec<u8> }
pub struct TsPayload { pub selectors: Vec<TrafficSelector> }
pub struct ConfigAttribute { pub attr_type: u16, pub value: Vec<u8> }
pub struct ConfigPayload { pub cfg_type: u8, pub attributes: Vec<ConfigAttribute> }
pub enum Payload {
    Sa(SaPayload), Ke(KePayload), IdI(IdPayload), IdR(IdPayload), Cert(Vec<u8>), CertReq(Vec<u8>),
    Auth(AuthPayload), Nonce(Vec<u8>), Notify(NotifyPayload), Delete(DeletePayload), Vendor(Vec<u8>),
    TsI(TsPayload), TsR(TsPayload), Cp(ConfigPayload), Eap(Vec<u8>),
    Unknown { payload_type: u8, critical: bool, body: Vec<u8> },
}
impl Payload {
    pub fn payload_type(&self) -> u8;
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<()>;               // body only (no generic header)
    pub fn decode_body(payload_type: u8, critical: bool, body: &[u8]) -> Result<Payload>;
}
/// Encode a payload chain: each generic header's NextPayload = type of the following payload, last = PT_NONE.
/// Returns the type of the FIRST payload (PT_NONE if empty) for the enclosing header.
pub fn encode_payloads(payloads: &[Payload], out: &mut Vec<u8>) -> Result<u8>;
/// Decode a chain starting with `first_type`. Unknown payload with C=1 -> Error::Decode(UNSUPPORTED_CRITICAL_PAYLOAD);
/// with C=0 -> Payload::Unknown (skipped by callers). Must consume the buffer exactly.
pub fn decode_payloads(first_type: u8, buf: &[u8]) -> Result<Vec<Payload>>;
```
Body layouts (all lengths big-endian):
- **SA** (§3.3): Proposal substructure: `0 or 2 (last/more)(1) | Reserved(1) | Length(2) | ProposalNum(1) | ProtocolID(1) | SPI Size(1) | NumTransforms(1) | SPI(spi_size) | Transforms`.
  Transform substructure: `0 or 3 (last/more)(1) | Reserved(1) | Length(2) | TransformType(1) | Reserved(1) | TransformID(2) | Attributes`.
  Key Length attribute (TV): `0x800E (AF=1,type=14)(2) | value bits(2)`. Emit it only when `key_len_bits.is_some()`.
- **KE** (§3.4): `DH Group(2) | Reserved(2) | Key Exchange Data`.
- **Nonce** (§3.9): raw bytes (16–256).
- **Notify** (§3.10): `ProtocolID(1) | SPI Size(1) | Notify Type(2) | SPI | Data`. For IKE-level notifies protocol_id=0, spi empty (AOSP uses 0/none; decode tolerates 1).
- **ID** (§3.5): `ID Type(1) | Reserved(3) | Data`. `id_payload_body()` = these bytes (used by AUTH §5.3).
- **AUTH** (§3.8): `Auth Method(1) | Reserved(3) | Data`.
- **Delete** (§3.11): `ProtocolID(1) | SPI Size(1) | Num SPIs(2) | SPIs`.
- **TS** (§3.13): `Num TS(1) | Reserved(3) | selectors`; selector: `TS Type(1) | IP Proto(1) | Selector Len(2) | Start Port(2) | End Port(2) | Start Addr | End Addr` (addr 4 or 16 bytes by type).
- **CP** (§3.15): `CFG Type(1) | Reserved(3) | attributes`; attribute: `R(1bit)+Type(15)(2) | Length(2) | Value`. Requests use Length 0.
- **EAP** (§3.16): raw EAP packet.
- **Vendor/Cert/CertReq**: raw.
- **SK/SKF**: handled in `message.rs` / `fragment.rs`, never as `Payload`.

### 4.3 Message (`message.rs`)
```rust
pub struct IkeMessage { pub header: IkeHeader, pub payloads: Vec<Payload> }
impl IkeMessage {
    pub fn new(spi_i: u64, spi_r: u64, exchange_type: u8, flags: u8, message_id: u32, payloads: Vec<Payload>) -> Self;
    /// Unencrypted (IKE_SA_INIT). Fills header.next_payload and header.length.
    pub fn encode_plain(&self) -> Result<Vec<u8>>;
    /// All payloads inside one SK payload (§3.14): header.next_payload = PT_SK;
    /// SK body = IV(iv_len) | E(inner_chain | pad | padlen(1)) | ICV(icv_len);
    /// SK generic header NextPayload = type of first inner payload. Pad so (inner+pad+1) % block == 0; pad bytes 0x00.
    /// ICV = integrity(sk_a, bytes[0 .. len-icv_len]) i.e. over the whole message from the IKE header start.
    pub fn encode_encrypted(&self, suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<Vec<u8>>;
    /// Like encode_encrypted but if the unfragmented datagram would exceed `frag_threshold` bytes, emit
    /// RFC 7383 SKF fragments instead (§4.4). Always returns >= 1 datagram.
    pub fn encode_encrypted_fragmented(&self, suite: &Suite, sk_e: &[u8], sk_a: &[u8], frag_threshold: usize) -> Result<Vec<Vec<u8>>>;
    /// Plain decode; Error::Decode if header.length != buf.len().
    pub fn decode_plain(buf: &[u8]) -> Result<IkeMessage>;
    /// Decode with SK: verify ICV (constant-time; Error::Integrity on mismatch), decrypt, strip pad, decode inner chain.
    /// Payloads before the SK payload (there should be none) are kept. Buffer must be a whole message (not an SKF fragment).
    pub fn decode_encrypted(buf: &[u8], suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<IkeMessage>;
    // Convenience accessors (return Option / iterators):
    pub fn sa(&self) -> Option<&SaPayload>; pub fn ke(&self) -> Option<&KePayload>; pub fn nonce(&self) -> Option<&[u8]>;
    pub fn notifies(&self) -> impl Iterator<Item=&NotifyPayload>; pub fn notify(&self, t: u16) -> Option<&NotifyPayload>;
    pub fn id_r(&self) -> Option<&IdPayload>; pub fn auth(&self) -> Option<&AuthPayload>; pub fn cp(&self) -> Option<&ConfigPayload>;
    pub fn ts_i(&self) -> Option<&TsPayload>; pub fn ts_r(&self) -> Option<&TsPayload>; pub fn eap(&self) -> Option<&[u8]>;
    pub fn deletes(&self) -> impl Iterator<Item=&DeletePayload>;
    /// First error notify (type < 16384), as Error::PeerNotify.
    pub fn error_notify(&self, exchange: &'static str) -> Option<Error>;
}
```
### 4.4 Fragmentation (`fragment.rs`, RFC 7383)
SKF payload body: `Fragment Number(2) | Total Fragments(2) | IV | E(fragment_data | pad | padlen) | ICV`.
Each fragment is a complete IKE message (own header with same SPIs/msgid/flags, `next_payload = PT_SKF`),
individually encrypted+MACed with the same keys. Fragment 1's SKF generic-header NextPayload = first inner payload
type; fragments 2..n carry NextPayload 0. Fragment numbers start at 1. To fragment: build the plaintext inner
chain once, split it into chunks such that each fragment datagram ≤ threshold.
```rust
pub fn is_fragment(raw: &[u8]) -> bool;                     // header.next_payload == PT_SKF
pub fn fragment_info(raw: &[u8]) -> Result<(u32 /*msgid*/, u16 /*num*/, u16 /*total*/)>;
pub struct Reassembler { /* per message_id: total, chunks by number */ }
impl Reassembler {
    pub fn new() -> Self;
    /// Verify+decrypt this fragment (per-fragment ICV), stash its plaintext. Returns Some(message) once all present:
    /// the reassembled IkeMessage has fragment 1's header (with next_payload = the inner first type) and the
    /// concatenated inner chain decoded. Duplicates ignored; mismatched total -> Error::Decode.
    pub fn push(&mut self, raw: &[u8], suite: &Suite, sk_e: &[u8], sk_a: &[u8]) -> Result<Option<IkeMessage>>;
    pub fn clear(&mut self, message_id: u32);
}
```

## 5. Key derivation & AUTH (`ike/keys.rs`, `ike/auth.rs`)

### 5.1 IKE SA keys (§2.14)
```
SKEYSEED = prf(Ni | Nr, g^ir)                       // key = Ni|Nr (concatenated nonce DATA), data = shared secret (fixed 256 bytes for group 14)
{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)   // SPIs as 8-byte big-endian
lengths: SK_d = prf.key_len (32); SK_ai/SK_ar = integrity.key_len (32); SK_ei/SK_er = cipher.key_len (32); SK_pi/SK_pr = prf.key_len (32). Total 224.
```
```rust
#[derive(zeroize::ZeroizeOnDrop)] pub struct IkeKeys { pub sk_d: Vec<u8>, pub sk_ai: Vec<u8>, pub sk_ar: Vec<u8>, pub sk_ei: Vec<u8>, pub sk_er: Vec<u8>, pub sk_pi: Vec<u8>, pub sk_pr: Vec<u8> }
pub fn derive_ike_keys(suite: &Suite, nonce_i: &[u8], nonce_r: &[u8], shared_secret: &[u8], spi_i: u64, spi_r: u64) -> IkeKeys;
/// IKE SA rekey (§2.18): SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr); then prf+ as above with the NEW SPIs.
pub fn derive_ike_keys_rekey(suite: &Suite, sk_d_old: &[u8], shared_secret_new: &[u8], nonce_i: &[u8], nonce_r: &[u8], spi_i: u64, spi_r: u64) -> IkeKeys;
```
### 5.2 Child SA keys (§2.17)
```
KEYMAT = prf+(SK_d, Ni | Nr)                       // no PFS. With PFS: prf+(SK_d, g^ir(new) | Ni | Nr)
order: [encr key init->resp][integ key init->resp][encr key resp->init][integ key resp->init]
```
For the child created in IKE_AUTH, Ni/Nr are the IKE_SA_INIT nonces. For a CREATE_CHILD_SA rekey they are that exchange's nonces.
```rust
#[derive(zeroize::ZeroizeOnDrop)] pub struct ChildKeys { pub encr_i2r: Vec<u8>, pub integ_i2r: Vec<u8>, pub encr_r2i: Vec<u8>, pub integ_r2i: Vec<u8> }
pub fn derive_child_keys(cipher: &dyn Cipher, integrity: &dyn Integrity, prf: &dyn Prf, sk_d: &[u8], nonce_i: &[u8], nonce_r: &[u8], pfs_secret: Option<&[u8]>) -> ChildKeys;
```
Initiator = us: outbound ESP uses (encr_i2r, integ_i2r) with the RESPONDER's SPI (from SAr2); inbound uses (encr_r2i, integ_r2i) with OUR SPI.

### 5.3 AUTH (§2.15, EAP MSK per §2.16 / RFC 5998)
```
InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI,  MACedIDForI = prf(SK_pi, RestOfInitIDPayload)
ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR,  MACedIDForR = prf(SK_pr, RestOfRespIDPayload)
RestOfXIDPayload = ID payload WITHOUT its 4-byte generic header = IDType(1) | Reserved(3) | IDData
RealMessage1 = the exact octets of the IKE_SA_INIT REQUEST as finally sent (if a COOKIE retry happened, the retried one)
RealMessage2 = the exact octets of the IKE_SA_INIT RESPONSE as received (marker already stripped)
NonceXData = nonce payload DATA only (no generic header)
AUTH (method 2, Shared Key MIC, keyed by the EAP MSK) = prf( prf(MSK, "Key Pad for IKEv2"), SignedOctets )
```
```rust
pub trait AuthMethod: Send + Sync {
    fn method_id(&self) -> u8;
    fn compute(&self, prf: &dyn Prf, signed_octets: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, prf: &dyn Prf, signed_octets: &[u8], auth_data: &[u8]) -> Result<()>;   // Error::AuthFailed
}
pub struct SharedKeyAuth { pub key: Vec<u8> }   // AUTH_SHARED_KEY_MIC; key = MSK for EAP-only
pub fn initiator_signed_octets(prf: &dyn Prf, sk_pi: &[u8], real_message1: &[u8], nonce_r: &[u8], id_i_body: &[u8]) -> Vec<u8>;
pub fn responder_signed_octets(prf: &dyn Prf, sk_pr: &[u8], real_message2: &[u8], nonce_i: &[u8], id_r_body: &[u8]) -> Vec<u8>;
pub fn id_payload_body(id: &IdPayload) -> Vec<u8>;
```
The extension seam: `AuthMethod` impls for PSK (same as SharedKeyAuth with the PSK) and signatures are future work.

## 6. NAT detection (`ike/nat.rs`, §2.23)
```
NAT_DETECTION_*_IP data = SHA1( SPIi(8) | SPIr(8) | IP address (4 or 16) | port(2) )
```
We send SOURCE = hash(**192.0.2.0**, our real local port) when `natt.force_udp_encap` (default; AOSP `FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4`
— this deliberately mismatches so the responder concludes we are behind a NAT and uses UDP-encapsulated ESP, which is the ONLY ESP a
userspace client can carry), else hash(our real addr:port). DESTINATION = hash(gateway addr, 500). The responder's SOURCE
notify (hash of its own addr:port) is compared to hash(gateway addr:port we sent to): mismatch → **remote** behind NAT.
Its DESTINATION notify (hash of the addr:port it saw us from) is compared to hash(our local addr:port): mismatch →
**local** behind NAT (compare with the REAL local addr:port, then FORCE `local_behind_nat = true` when `force_udp_encap`, exactly like
AOSP). SPIr in our IKE_SA_INIT request is 0 (we hash with 0); the responder's notifies are hashed with the real SPIr from its header.
If the response carries neither NAT-D notify → `detected=false` (peer doesn't support NAT-T; stay on 500 — and log loudly, ESP can't work).
If it carries only one of the two → `Error::Decode` (AOSP: INVALID_SYNTAX).
```rust
pub fn nat_detection_hash(spi_i: u64, spi_r: u64, addr: IpAddr, port: u16) -> [u8; 20];
#[derive(Clone, Copy, Debug, Default)] pub struct NatStatus { pub local_behind_nat: bool, pub remote_behind_nat: bool, pub detected: bool /* either */ }
pub fn evaluate(spi_i: u64, spi_r: u64, local: SocketAddr, remote: SocketAddr, response_notifies: &[&NotifyPayload]) -> NatStatus;
```
Local address for the hash: the socket's bound address; if bound to 0.0.0.0, discover the egress address by
`UdpSocket::connect(remote)` on a throwaway socket and `local_addr()`. If the responder omits NAT notifies → `detected=false`.

## 7. Transport (`ike/transport.rs`)
One UDP socket at a time for the whole tunnel (IKE and ESP multiplexed, RFC 3948), held as
`RwLock<Bound { Arc<UdpSocket>, SocketAddr }>` so the path monitor can swap it without stopping the rx, keepalive or
ESP-TX paths (§17.1): every operation clones the `Arc` and drops the guard, so no lock is held across a syscall.
Bound to an ephemeral port on `gateway.local_addr` or the discovered egress. Destination port starts at 500; `switch_to_natt()` moves it to 4500
and turns on the 4-byte non-ESP marker for IKE. Inbound classification on 4500 (RFC 3948 §2.2/§4):
first 4 bytes zero → IKE (strip marker); length 1 and byte 0xFF → keepalive; else → ESP (first 4 bytes = SPI ≠ 0).
```rust
pub enum Incoming { Ike(Vec<u8>), Esp(Vec<u8>), Keepalive }
pub struct IkeTransport { /* socket, remote_ip, port, use_marker, local egress */ }
impl IkeTransport {
    pub fn bind(local: Option<IpAddr>, remote: IpAddr, ike_port: u16) -> Result<Self>;
    pub fn local_addr(&self) -> SocketAddr;                // real egress addr:port (not 0.0.0.0)
    pub fn remote_addr(&self) -> SocketAddr;               // current (500 or 4500)
    pub fn switch_to_natt(&mut self, natt_port: u16);
    pub fn using_natt(&self) -> bool;
    pub fn send_ike(&self, datagram: &[u8]) -> Result<bool>; // adds marker if using_natt; false = held and dropped, not sent
    pub fn send_esp(&self, esp: &[u8]) -> Result<bool>;      // raw, must be using_natt; false as above (§17.5)
    pub fn send_keepalive(&self) -> Result<()>;
    pub fn recv(&self, timeout: Duration) -> Result<Option<Incoming>>;   // None on timeout; re-samples the current socket each
                                                            // iteration (200 ms slices) so a rebind is picked up promptly;
                                                            // datagrams from other peers are dropped, counted (`stray_sources`)
                                                            // and logged at most once per 5 s
    pub fn probe_egress(&self) -> Result<IpAddr>;           // §17.1: discover_egress at the current destination, no packets
    pub fn rebind(&self, local_ip: IpAddr) -> Result<(SocketAddr, Arc<UdpSocket>)>;  // §17.1: fresh ephemeral port on
                                                            // `local_ip`, same destination/marker/SAs; returns the new local
                                                            // address and the replaced socket (kept alive by the caller)
    pub fn stray_sources(&self) -> u64;
    /// Send a request (one datagram, or its SKF fragments) and collect the response datagrams for `message_id`:
    /// retransmit ALL datagrams on each timeout per `policy` (same bytes each time). Returns all datagrams that make up
    /// the response (1 if unfragmented; else all SKF fragments, collected until `total` seen or a per-fragment timeout).
    /// IKE datagrams that are not the awaited response (e.g. peer-initiated requests) go to `on_other`.
    /// ESP/keepalive received during a request are passed to `on_esp` (may be a no-op during the handshake).
    pub fn request(&self, datagrams: &[Vec<u8>], message_id: u32, policy: &RetransmitConfig,
                   on_other: &mut dyn FnMut(Vec<u8>), on_esp: &mut dyn FnMut(Vec<u8>)) -> Result<Vec<Vec<u8>>>;
}
```
Response matching: header.is_response() && header.message_id == message_id && header.spi_i == ours. Retransmit
schedule: `initial_timeout_ms * backoff^n`, `max_attempts` sends total; then `Error::Timeout`.
`is_path_error(&io::Error)` (free function) classifies "this socket's address or route is gone" —
`AddrNotAvailable` / `NetworkUnreachable` / `HostUnreachable` / `NetworkDown` plus a cfg'd errno fallback for
macOS/iOS and Linux, for platforms and libc paths where std still reports `Uncategorized`. `discover_egress` names
the gateway in its error (`no route to gateway 203.0.113.9:500: …`), which is what a caller sees for the commonest
connect failure; re-wrapping with `io::Error::new(e.kind(), …)` keeps `kind()`, which `is_path_error` checks first,
so the classification the path monitor depends on is unaffected. Note `send_raw` still swallows `WouldBlock`/`TimedOut` as a lost datagram rather than breaking the retransmit schedule
off on a local verdict: send errors only *accelerate* the path monitor, they are never its authority (§17.1). It
returns `false` for such a datagram, so a caller can tell a real transmission from one the kernel never took (§17.5).

## 8. Initiator state machine (`ike/session.rs`) — sans-I/O
Owns all IKE state; never touches sockets. The tunnel (§12) drives it: build → (encode) → send/recv → decode → handle.
```rust
pub enum SaInitOutcome { Established { nat: NatStatus }, RetryWithCookie(Vec<u8>), RetryWithGroup(u16) }
pub enum AuthResponse { EapRequest(Vec<u8>), Established(Box<Established>) }
pub struct Established { pub child: ChildSaInfo, pub assigned: AssignedConfig, pub id_r: IdPayload }
pub struct ChildSaInfo { pub spi_in: u32, pub spi_out: u32, pub keys: ChildKeys, pub cipher: Arc<dyn Cipher>, pub integrity: Arc<dyn Integrity>, pub replay_window: u32, pub ts_i: TsPayload, pub ts_r: TsPayload, pub created: Instant, pub lifetime: Duration }
#[derive(Clone, Debug, Default)] pub struct AssignedConfig { pub internal_ipv4: Vec<Ipv4Addr>, pub internal_ipv6: Vec<(Ipv6Addr, u8)>, pub dns_ipv4: Vec<Ipv4Addr>, pub dns_ipv6: Vec<Ipv6Addr>, pub pcscf_ipv4: Vec<Ipv4Addr>, pub pcscf_ipv6: Vec<Ipv6Addr>, pub other: Vec<ConfigAttribute> }
pub enum PeerEvent { Dpd, DeleteIke, DeleteChild(Vec<u32>), Notify(Vec<NotifyPayload>), Other }
pub struct IkeInitiator { /* cfg, suite, spis, nonces, dh, keys, real_message1/2, id bodies, msg ids, child, msk, reassembler */ }
impl IkeInitiator {
    pub fn new(cfg: &Config, local: SocketAddr, remote: SocketAddr) -> Result<Self>;   // resolves proposal names via registry; generates SPIi, Ni, DH pair
    // --- IKE_SA_INIT (msgid 0) ---
    pub fn build_sa_init(&mut self, cookie: Option<&[u8]>) -> Result<Vec<u8>>;          // records real_message1 = returned bytes
    pub fn handle_sa_init_response(&mut self, raw: &[u8]) -> Result<SaInitOutcome>;   // records real_message2 = raw; derives IkeKeys
    pub fn set_local_addr(&mut self, local: SocketAddr);                               // if egress learned late
    // --- IKE_AUTH (msgid 1..n) ---
    pub fn build_auth_initial(&mut self) -> Result<IkeMessage>;
    pub fn handle_auth_response(&mut self, msg: &IkeMessage) -> Result<AuthResponse>;
    pub fn build_auth_eap(&mut self, eap_response: &[u8]) -> Result<IkeMessage>;
    pub fn set_msk(&mut self, msk: Vec<u8>);
    pub fn build_auth_final(&mut self) -> Result<IkeMessage>;
    // --- encode/decode with the IKE SA keys (our direction sk_ei/sk_ai; theirs sk_er/sk_ar) ---
    pub fn encode(&self, msg: &IkeMessage) -> Result<Vec<Vec<u8>>>;                    // fragments per cfg.ike.fragment_threshold
    pub fn decode(&mut self, datagrams: &[Vec<u8>]) -> Result<IkeMessage>;              // single or SKF set (uses internal Reassembler)
    // --- post-establishment ---
    pub fn build_dpd(&mut self) -> Result<IkeMessage>;                                  // empty INFORMATIONAL request
    pub fn build_delete_ike(&mut self) -> Result<IkeMessage>;
    pub fn build_delete_child(&mut self, spi_in: u32) -> Result<IkeMessage>;
    pub fn handle_informational_response(&mut self, msg: &IkeMessage) -> Result<()>;
    /// Peer-initiated request (flags: !RESPONSE). Returns the response message to send and what happened.
    pub fn handle_peer_request(&mut self, msg: &IkeMessage) -> Result<(IkeMessage, PeerEvent)>;
    pub fn build_rekey_child(&mut self) -> Result<IkeMessage>;                          // CREATE_CHILD_SA: SA(new SPI), Ni, TSi, TSr, N(REKEY_SA old spi_in)
    pub fn handle_rekey_child_response(&mut self, msg: &IkeMessage) -> Result<ChildSaInfo>;   // new keys via §5.2 with this exchange's nonces; old child kept until deleted
    pub fn build_rekey_ike(&mut self) -> Result<IkeMessage>;                            // CREATE_CHILD_SA: SA(IKE, new SPIi 8 bytes), Ni, KE
    pub fn handle_rekey_ike_response(&mut self, msg: &IkeMessage) -> Result<()>;        // derives keys per §5.1 rekey; swaps to new SA (msgid restarts at 0); caller then deletes old IKE SA
    pub fn forget_old_ike(&mut self);                                                   // drop the old IKE SA whether or not its DELETE was acknowledged (§14)
    pub fn abort_request(&mut self, transmitted: bool);                                 // free the request slot; flag the id as abandoned ONLY if a datagram of it was sent (§17.2)
    // --- accessors ---
    pub fn spi_i(&self) -> u64; pub fn spi_r(&self) -> u64; pub fn next_message_id(&self) -> u32;
    pub fn nat(&self) -> Option<NatStatus>; pub fn suite(&self) -> &Suite; pub fn keys(&self) -> &IkeKeys; pub fn child(&self) -> Option<&ChildSaInfo>;
    pub fn established(&self) -> bool;
}
```
### 8.1 IKE_SA_INIT request (msgid 0, flags INITIATOR) — payloads in this order (confirm vs §14):
1. `SA`: one proposal per `cfg.ike.proposals` (number 1..), protocol IKE(1), SPI size 0, transforms in AOSP order
   **ENCR (with KeyLength attr 0x800E,0x0100) / INTEG / DH / PRF** — PRF LAST. One transform per configured name, in config order.
   For the glue suite the SA payload is exactly 48 bytes (4 + 8 + 12 + 8 + 8 + 8).
2. `KE`: first configured DH group, our public value.
3. `Nonce`: `cfg.ike.nonce_len` random bytes.
4. `N(NAT_DETECTION_SOURCE_IP)`, 5. `N(NAT_DETECTION_DESTINATION_IP)` (§6).
6. `N(IKEV2_FRAGMENTATION_SUPPORTED)` if `cfg.ike.fragmentation` (data empty; payload = 8 bytes).
7. `N(SIGNATURE_HASH_ALGORITHMS)` if `cfg.ike.signature_hash_algorithms`, data = `00 01 00 02 00 03 00 04` (AOSP sends it unconditionally even for EAP).
8. `N(COOKIE)` FIRST in the chain (before SA) when retrying with a cookie (§2.6); everything else (same SPIi, nonce, KE) unchanged.
NAT-D notifies (4,5) are only sent for an IPv4 gateway (AOSP omits them for IPv6 peers).
Response handling: must be IKE_SA_INIT, RESPONSE, msgid 0, SPIi ours. `N(COOKIE)` → `RetryWithCookie(data)` (regenerate
nothing else). `N(INVALID_KE_PAYLOAD)` (data = 2-byte group) → `RetryWithGroup` (regenerate DH pair for that group; must be
configured). Other error notify → `Error::PeerNotify`. Otherwise: take SPIr from header; parse SA (chosen proposal → build
`Suite` from transform ids via registry; reject if not a subset of what we offered), KE (group must match), Nr; compute
shared secret; `derive_ike_keys`; `nat::evaluate`; store `real_message2`; remember whether the response carried
`N(IKEV2_FRAGMENTATION_SUPPORTED)` (only then may we send SKF fragments). Return `Established{nat}`.
On `INVALID_KE_PAYLOAD` AOSP restarts from scratch (new SPIi, nonce, KE); do the same (the tunnel constructs a fresh `IkeInitiator`).

### 8.2 IKE_AUTH initial request (msgid 1), encrypted; inner payload order (confirm vs §14):
1. `IDi` (cfg.identity.local_id)  2. `IDr` (cfg.identity.remote_id)
3. `N(EAP_ONLY_AUTHENTICATION)` if `cfg.ike.eap_only`  (**no AUTH payload** — EAP)
4. `N(MOBIKE_SUPPORTED)` if `cfg.ike.mobike`; `N(INITIAL_CONTACT)` if configured (glue: not sent)
5. `SA` child proposals: protocol ESP(3), SPI size 4, SPI = our random nonzero inbound SPI, transforms **ENCR(+keylen 0x800E 0x0100) / INTEG / ESN(id 0)**
   — the ESN transform is ALWAYS present (AOSP). Single proposal → SA payload 44 bytes.
6. `TSi`, 7. `TSr`: each exactly `[IPv4 0.0.0.0–255.255.255.255, IPv6 ::–ffff:…:ffff]`, ports 0–65535, proto 0 (64 bytes each, byte-identical).
8. `CP(CFG_REQUEST)` LAST, with `cfg.child.cfg_requests` in the §2 order (zero-length values; 40 bytes).
Wire order: `IDi(35), IDr(36), N(16417), N(16396), SA(33), TSi(44), TSr(45), CP(47)`.
Response (IKE_AUTH, RESPONSE, msgid 1): error notify → `Error::PeerNotify`; `EAP` payload present → `AuthResponse::EapRequest(bytes)`.
**Record the IDr from THIS (first) response** — AOSP uses it for the post-EAP AUTH verification (§8.4), not any IDr in the final response.
If it (unexpectedly) also carries AUTH/CERT: log and do NOT fail (cert validation is off). `accept_any_remote_id` only skips comparing the
received IDr against `cfg.identity.remote_id`.
### 8.3 EAP rounds: `build_auth_eap(eap_response)` → IKE_AUTH request (next msgid) containing only `EAP`. Response: `EAP`
payload → `EapRequest`; the tunnel feeds it to `EapTlsClient`. When EAP-Success arrives it is also delivered as `EapRequest`
(the EAP module recognises code 3). `set_msk(msk)`.
### 8.4 Final: `build_auth_final()` → IKE_AUTH request with only `AUTH` (§5.3, SharedKeyAuth{MSK}). Response must contain
`AUTH`, `SA`, `TSi`, `TSr`, optionally `IDr`, `CP(CFG_REPLY)`, notifies. Verify AUTH (method MUST be 2) with `responder_signed_octets`
using the IDr captured from the FIRST IKE_AUTH response (fallback: an IDr in this response; none at all → `Error::AuthFailed`);
on mismatch → `Error::AuthFailed`. Never send a DELETE on final-response failures (AOSP doesn't). Parse chosen child proposal (SPI = spi_out; transforms ⊆ offered),
TS (accept the responder's narrowing as-is), CP reply → `AssignedConfig` (attribute value layouts: IP4 addr 4 bytes;
IP6 addr 16 bytes + 1 prefix byte (17) — tolerate 16; IP4/6 DNS and P-CSCF = bare addresses; zero-length = "none").
Derive `ChildKeys` (§5.2, IKE_SA_INIT nonces). Return `Established`.
### 8.5 Message IDs: our requests: 0 (SA_INIT), 1, 2, … strictly increasing, one outstanding at a time. Peer-initiated
requests have their own counter starting at 0; we respond with the same msgid; accept the next expected or a
retransmission of the previous (re-send our previous response).
### 8.6 Peer requests: INFORMATIONAL with no payloads = DPD → respond with empty INFORMATIONAL response, `PeerEvent::Dpd`.
`Delete(IKE)` → respond empty, `DeleteIke`. `Delete(ESP, spis)` → respond with `Delete(ESP, our matching spi_in)`, `DeleteChild`.
CREATE_CHILD_SA from peer (rekey) → respond `N(NO_ADDITIONAL_SAS)`, `Other` (not supported; log).

## 9. EAP (`eap/packet.rs`, `eap/tls.rs`)
### 9.1 Packet (RFC 3748 §4): `Code(1) | Identifier(1) | Length(2) | [Type(1) | Type-Data]`.
```rust
pub struct EapPacket { pub code: u8, pub identifier: u8, pub eap_type: Option<u8>, pub type_data: Vec<u8> }
impl EapPacket {
    pub fn decode(buf: &[u8]) -> Result<EapPacket>;   // Length must equal buf.len(); Success/Failure have no type
    pub fn encode(&self) -> Vec<u8>;
    pub fn response(identifier: u8, eap_type: u8, type_data: Vec<u8>) -> EapPacket;
    pub fn identity_response(identifier: u8, identity: &[u8]) -> EapPacket;
    pub fn nak(identifier: u8, desired: &[u8]) -> EapPacket;
}
```
### 9.2 EAP-TLS (RFC 5216 §3.1): Type 13; type_data = `Flags(1) | [TLS Message Length(4) if L] | TLS data`.
```rust
pub struct EapTlsConfig { pub identity: Vec<u8>, pub client_cert_der: Vec<u8> /* leaf, DER */, pub client_key_der: Vec<u8> /* PKCS#8 DER */,
                          pub validate_server: bool, pub server_ca_der: Vec<Vec<u8>> /* DER anchors */, pub server_name: Option<String> /* SNI; None = none */,
                          pub max_fragment_len: usize, pub allow_tls13: bool }
pub enum EapAction { Send(EapPacket), Success { msk: Vec<u8>, emsk: Vec<u8> }, Failure(String) }
pub struct EapTlsClient { /* rustls ClientConnection, rx buffer(+expected len), tx queue, state, msk */ }
impl EapTlsClient {
    pub fn new(cfg: EapTlsConfig) -> Result<Self>;
    /// Feed ANY EAP packet from the peer (Request/Identity, Request/TLS, Success, Failure) and get the action.
    pub fn handle(&mut self, packet: &EapPacket) -> Result<EapAction>;
    pub fn protocol_version(&self) -> Option<&str>;   // e.g. "TLSv1.2"
    pub fn cipher_name(&self) -> Option<&str>;        // e.g. "AES128-SHA"
    pub fn msk(&self) -> Option<&[u8]>;
}
```
Behavior:
- Request/Identity → `Send(identity_response(id, identity))`.
- Request/TLS with S flag → create `rustls::ClientConnection`, pull `write_tls` into the tx queue, send fragment 1.
- Request/TLS with data → append; if M set → `Send` an empty EAP-TLS Response (flags 0, no data) as the ACK; if not M →
  feed `read_tls` + `process_new_packets()`, drain `write_tls` into tx; if tx non-empty → send fragment 1 of it; else if
  handshake complete → `Send` empty EAP-TLS Response (the final ACK after server Finished / the TLS 1.3 commitment).
- Request/TLS with flags 0 and no data while we have queued fragments → send the next fragment.
- Fragmenting: chunks of `max_fragment_len` (1024) TLS bytes. **L (+4-byte total length) is set on the FIRST fragment AND on every
  unfragmented non-empty message** (AOSP sets L iff messageLength != 0 — so even a lone ClientHello is `0x80 <len4> <data>`).
  Continuation fragments carry NO L/length; M is set on every chunk except the last. Continuation fragments are sent only
  when the server sends an ACK request (flags 0x00, no data).
- Inbound: the server's first fragment MUST carry L (capacity = declared length); later fragments may repeat L with the same total.
  Our ACK is exactly `02 <id> 00 06 0d 00`. The last fragment is detected solely by M=0.
- Completion: after feeding the server's final flight (CCS+Finished), `is_handshaking()==false` and nothing to write → derive the MSK
  immediately, then `Send` the empty ACK. The following EAP-Success yields `Success{msk}`; EAP-Success BEFORE completion → `Failure`.
- Default TLS versions: **1.2 only** (`allow_tls13=false`), no SNI (`ServerName::IpAddress`), trust-all when `!validate_server`,
  client chain = leaf only. rustls 1.2 = ECDHE + AEAD suites only; if the server insists on RSA-kx/CBC the handshake fails —
  report that clearly (it is the one thing rustls cannot mirror from Conscrypt).
- On handshake completion derive Key_Material (128 bytes) → `msk = [..64]`, `emsk = [64..]`:
  TLS 1.2: `export_keying_material(buf, b"client EAP encryption", None)` (RFC 5216 §2.3);
  TLS 1.3: `export_keying_material(buf, b"EXPORTER_EAP_TLS_Key_Material", Some(&[0x0D]))` (RFC 9190 §2.1).
- Success (code 3) → if msk derived → `Success{msk,emsk}` else `Failure`. Failure (code 4) → `Failure`.
- Unknown request type → `Send(nak(id, &[EAP_TYPE_TLS]))`.
- Responses always echo the request identifier.
- (superseded by §9.3 — OpenSSL engine) rustls: `ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
  .with_protocol_versions(&[&TLS12, (&TLS13 if allow_tls13)])`; when `!validate_server` use
  `.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify))` where `NoVerify: rustls::client::danger::ServerCertVerifier`
  returns `ServerCertVerified::assertion()` / `HandshakeSignatureValid::assertion()` and
  `supported_verify_schemes()` = provider's; else `with_root_certificates(roots from server_ca_pem or webpki-free? -> use the PEM only)`.
  `.with_client_auth_cert(certs, key)`. Parse PEMs with `rustls_pemfile`. `server_name` = `ServerName::IpAddress(gateway ip)`
  by default (rustls sends no SNI for IPs).


### 9.3 TLS engine = OpenSSL (live finding, 2026-09-11; decision: no pluggable backend)
A live probe through the real IKE/EAP path showed the T-Mobile ePDG's EAP-TLS server negotiates ONLY
`TLS_RSA_WITH_AES_128_CBC_SHA` (0x002F), TLS 1.2, no extended-master-secret: an ECDHE+AEAD-only ClientHello (what
rustls sends) is answered with IKE `AUTHENTICATION_FAILED` before any ServerHello; a ClientHello that also lists
RSA-kx/CBC suites gets a ServerHello picking 0x002F even when ECDHE-GCM is listed first. rustls implements neither RSA
key exchange nor CBC suites by design, so **EAP-TLS uses OpenSSL (`openssl` crate 0.10) and rustls is removed from the
crate.** The `EapTlsClient` / `EapTlsConfig` / `EapAction` API in `eap/tls.rs` (§9.2) is unchanged for callers, except:
- `EapTlsConfig.server_name: ServerName<'static>` becomes `server_name: Option<String>` — SNI to send; `None` = no SNI
  (the default; AOSP sends none).
- `Error::Tls` carries a `String` (no rustls type).
- `protocol_version()` returns `Option<&str>` (OpenSSL name, e.g. `"TLSv1.2"`) and the new `cipher_name()` returns the
  negotiated suite (e.g. `"AES128-SHA"`); both are known once the ServerHello has been processed.
Engine rules: `SslMethod::tls_client()`, min/max proto TLS 1.2 (max 1.3 only when `allow_tls13`), `SslVerifyMode::NONE`
unless `validate_server` (then the DER trust anchors in `server_ca_der`), client leaf cert (DER) + key (PKCS#8 DER), cipher list
`"DEFAULT:@SECLEVEL=1"` so `AES128-SHA` (0x002F) is offered alongside modern suites, no SNI unless configured,
no session tickets required. Driving: an in-memory duplex (`Read` returns `WouldBlock` when empty, `Write` appends)
under `SslStream`; call `connect()` and treat `ErrorCode::WANT_READ` as "need more peer bytes"; after every step drain
the duplex's outbound buffer into the EAP-TLS fragment queue. Completion when `connect()` returns `Ok`. MSK/EMSK via
`SslRef::export_keying_material(&mut [0u8;128], "client EAP encryption", None)` (TLS 1.2, RFC 5705 with no context ==
RFC 5216 Key_Material) — for TLS 1.3 use label `EXPORTER_EAP_TLS_Key_Material` with context `[0x0d]` (RFC 9190).
Server certificate seen: DigiCert Global G2 TLS RSA SHA256 2020 CA1 -> CN=nsp.epc.mnc260.mcc310.pub.3gppnetwork.org
(GSM Association), valid 2026-08-10..2027-02-24 — a public-CA chain, so real validation is possible later.
Tests: the in-process end-to-end test uses an OpenSSL `SslAcceptor` (test CA + leaf, client-auth required) over the same
in-memory shuttle, configured to prefer `AES128-SHA` so the T-Mobile suite is exercised; assert MSK == server export.

## 10. ESP (`esp/codec.rs`, `esp/replay.rs`)
ESP-in-UDP datagram (no marker): `SPI(4) | Seq(4) | IV(iv_len) | E( payload | pad | PadLen(1) | NextHeader(1) ) | ICV(icv_len)`.
Pad: RFC 4303 §2.4 bytes 1,2,3,… so that (payload + pad + 2) % block_len == 0 (and ≥ 4-byte alignment). NextHeader:
4 (IPv4) or 41 (IPv6) from the inner packet's version nibble. ICV = integrity(auth_key, SPI..ciphertext).
```rust
pub struct EspSa { pub spi: u32, pub cipher: Arc<dyn Cipher>, pub integrity: Arc<dyn Integrity>, pub enc_key: Vec<u8>, pub auth_key: Vec<u8> }
pub struct EspOutbound { /* sa, seq: AtomicU32 */ }
impl EspOutbound { pub fn new(sa: EspSa) -> Self; pub fn spi(&self) -> u32; pub fn seq(&self) -> u32;
    pub fn encapsulate(&self, inner_ip_packet: &[u8]) -> Result<Vec<u8>>;   // seq starts at 1; Error::Protocol at 2^32-1 (rekey needed) }
pub struct EspInbound { /* sa, replay: ReplayWindow */ }
impl EspInbound { pub fn new(sa: EspSa, replay_window: u32) -> Self; pub fn spi(&self) -> u32;
    pub fn decapsulate(&mut self, esp: &[u8]) -> Result<Vec<u8>>;          // SPI match, ICV (const-time) BEFORE decrypt, replay check+update, strip pad, check NextHeader ∈ {4,41} }
pub enum DatagramKind { IkeMarker, Keepalive, Esp }
pub fn classify(datagram: &[u8]) -> DatagramKind;
```
`replay.rs`: RFC 4303 §3.4.3 sliding window; `ReplayWindow::new(size)` rounds size up to ≥ 32; `check(seq) -> bool` and
`update(seq)`, or `check_and_update` used AFTER ICV verification. Seq 0 is invalid.

## 11. Inner IP stack = smoltcp (`ipstack/*`) — decision 2026-09-11, replaces the hand-rolled stack

The tunnel-mode ESP payload IS a raw IP packet, so the inner network is a **smoltcp `Interface` over a `phy::Device` with
`Medium::Ip`**. The previous hand-rolled `ipstack/{ipv4,ipv6,udp,dns}.rs` is deleted; smoltcp provides IPv4/IPv6 (+ fragmentation
and reassembly), UDP, DNS, ICMP and TCP sockets. Dependency: `smoltcp = { version = "0.14", default-features = false,
features = ["std", "log", "medium-ip", "proto-ipv4", "proto-ipv6", "proto-ipv4-fragmentation", "proto-ipv6-fragmentation",
"socket-udp", "socket-tcp", "socket-dns", "socket-icmp", "auto-icmp-echo-reply"] }` (drop any feature name that 0.14 lacks;
verify on docs.rs). `auto-icmp-echo-reply` is in smoltcp's default set but NOT implied by `socket-icmp`: without it every ICMP
echo request to the inner address is silently ignored (a P-CSCF/ePDG liveness ping got no reply until 2026-09-11). `socket-tcp`
backs the inner TCP connections and listeners of §11.2; `proto-ipv6-fragmentation` is inert on `Medium::Ip` (6LoWPAN only).

```rust
// ipstack/device.rs
/// smoltcp Device backed by the ESP data plane. TX: smoltcp writes an IP packet into a scratch buffer, the token's
/// consume() encapsulates it (EspOutbound) and sends it on the IkeTransport (send_esp). RX: the tunnel rx thread
/// pushes decapsulated inner IP packets into `rx: VecDeque<Vec<u8>>` (bounded, drop-oldest + counter) and wakes the stack.
pub struct EspDevice { /* Arc<transport>, Arc<Mutex<EspOutbound>>, rx queue, mtu, stats */ }
impl smoltcp::phy::Device for EspDevice { type RxToken<'a> = ...; type TxToken<'a> = ...; fn receive(..) fn transmit(..) fn capabilities(..) }
// capabilities: medium = Medium::Ip, max_transmission_unit = cfg.child.inner_mtu (default 1280), checksum = default (smoltcp computes all).

// ipstack/stack.rs — ONE owner thread ("epdg-stack") for Interface + SocketSet + device (smoltcp is !Sync):
pub struct InnerStack { iface: Interface, sockets: SocketSet<'static>, device: EspDevice, dns: SocketHandle, udp: HashMap<u16, UdpBinding>, .. }
// Interface::new(Config::new(HardwareAddress::Ip), &mut device, now); update_ip_addrs with every assigned inner address (v6 /prefix, v4 /32);
// routes: add_default_ipv6_route(<first assigned v6 DNS server or the inner address>) and add_default_ipv4_route(..) when v4 is assigned —
// with Medium::Ip the next hop is nominal (no ND/ARP) but off-prefix destinations still need a route; verify with a unit test.
// Loop: { lock; loop { iface.poll_ingress_single(now, &mut device, &mut sockets) — after EVERY ingested packet drain UDP sockets ->
//         per-binding sync_channel and complete DNS queries -> waiters (a smoltcp udp::Socket buffers only 32 datagrams, the device
//         queue 256: draining once per poll loses the rest of a burst inside smoltcp, uncounted) }; iface.poll_egress;
//         delay = iface.poll_delay(now, &sockets) } then condvar.wait_timeout(delay). Any external event (rx packet, send, bind, query) notifies.
// Public (via tunnel.rs):
pub struct InnerUdpSocket { .. }  // bind_udp(port): udp::Socket with rx/tx buffers (e.g. 16 x 2048 B metadata/payload), bound to (any addr, port)
// Send + Sync (the mpsc receiver sits behind a Mutex taken only in recv_timeout): one thread may block in recv_timeout while others send_to.
// Drop: flush the socket's untransmitted tx buffer first (poll_egress on the caller's thread; the sink is synchronous), count what still
// could not leave in `udp_tx_drops`, then remove the socket — an Ok from send_to means the datagram WILL be transmitted.
impl InnerUdpSocket { pub fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> Result<()>;   // socket.send_slice(payload, (dst).into()) + notify;
                      // BufferFull -> Error::Protocol and `udp_send_full` += 1
                      pub fn recv_timeout(&self, t: Duration) -> Result<Option<UdpDatagram>>; pub fn local_port(&self) -> u16; }
pub struct UdpDatagram { pub src: SocketAddr, pub dst: SocketAddr, pub payload: Vec<u8> }   // dst = our inner address:port
// DNS: EpdgTunnel::resolve(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>> — dns::Socket configured with the assigned DNS
// servers (update_servers after IKE_AUTH; smoltcp caps the server count — keep the first DNS_MAX_SERVER_COUNT), start_query for Aaaa then A
// (skip a family we have no inner address for), poll until get_query_result is Ok/Err; Error::Timeout after `timeout`.
// smoltcp reports a SILENT server as `Failed` too, but only after its private RETRANSMIT_TIMEOUT (10 s) x server count (mirrored as
// `SMOLTCP_DNS_RETRANSMIT_TIMEOUT`): a `Failed` at least that long after the query started is completed as Error::Timeout, an earlier
// one (NXDOMAIN / SERVFAIL / empty answer) as Error::Protocol. Non-unicast assigned DNS servers (0.0.0.0, ::, multicast) are skipped
// with a warning — smoltcp fails every query sent to one.
// Stack thread: InnerStack::spawn wraps run() in catch_unwind and close()s the stack on a panic (waiters get Error::Closed, not silence).
// TCP (§11.2): `socket::tcp::Socket`s in the same SocketSet, driven by the same thread; InnerStack::connect_tcp / listen_tcp hand
// out blocking adapters (InnerTcpStream / InnerTcpListener) that park on the TCP event counter, never on the stack lock.
```
MTU: the wire MTU defaults to 1280 (config `child.inner_mtu`, clamped to `[1280, 65535]`); the MTU smoltcp sees is
`child.inner_mtu_stack` (§11.1). **Verified smoltcp 0.14 behaviour (amendment 2026-09-11, see §15):** outbound IPv4 larger than the
(stack) MTU is fragmented by smoltcp (up to `FRAGMENTATION_BUFFER_SIZE`) and inbound IPv4 fragments are reassembled (up to
`REASSEMBLY_BUFFER_SIZE`); **IPv6 is neither fragmented nor reassembled on `Medium::Ip`** — the `proto-ipv6-fragmentation` feature
only covers 6LoWPAN, an oversize IPv6 packet is dropped at dispatch and an inbound IPv6 Fragment header gets an ICMPv6 Parameter
Problem. Hence the §11.1 shim around the device; `InnerUdpSocket::send_to` refuses payloads above `inner_mtu_stack − 48/−28`
(`Error::Protocol`) instead of losing them silently. smoltcp's compile-time limits are set by Cargo features
(`iface-max-addr-count-8`, `iface-max-route-count-4`, `dns-max-server-count-4`, `dns-max-result-count-8`,
`fragmentation-buffer-size-8192`, `reassembly-buffer-size-8192`, `reassembly-buffer-count-4`); `smoltcp::config::*` exposes the
effective values. Unknown/ICMP traffic is handled or dropped by smoltcp (ICMP port-unreachable replies are harmless; echo requests
are answered thanks to `auto-icmp-echo-reply`). Routes: with `Medium::Ip` smoltcp never resolves a next hop, but a matching route
is still REQUIRED — `has_neighbor` is `route(addr).is_some()` (then unconditionally true for `Medium::Ip`), so without a default
route an off-prefix datagram would never leave its socket. Only the next-hop VALUE is nominal; the default routes are load-bearing
and the loopback test proves off-prefix delivery end to end.
Threading rule: only the stack thread touches `Interface`/`SocketSet`/`EspDevice` (behind one Mutex + Condvar); callers hold the lock only
to enqueue/dequeue. The ESP rx thread never blocks on the stack lock for long (push + notify). All queues bounded; drops counted in stats.

### 11.1 IP fragmentation shim around the smoltcp device (decision 2026-09-11)
smoltcp 0.14 has **no IPv6 fragmentation or reassembly for `Medium::Ip`** (`proto-ipv6-fragmentation` only serves 6LoWPAN); it
drops oversize IPv6 on send and answers an inbound Fragment header with ICMPv6 Parameter Problem. SIP over this tunnel needs both
directions (1.5–3.7 KB 200 OK / NOTIFY arrive IPv6-fragmented from the P-CSCF; INVITEs can exceed 1280 bytes), so the tunnel
wraps the device:
- **Device MTU seen by smoltcp** = `cfg.child.inner_mtu_stack` (new, default 16384; ≥ `inner_mtu`) so smoltcp never refuses a large
  UDP datagram. **Wire MTU** = `cfg.child.inner_mtu` (1280) is what fragments must fit.
- **TX (`ipstack/frag.rs::fragment_for_wire(pkt, wire_mtu, ident) -> Result<Option<Vec<Vec<u8>>>>`)**, applied inside
  `EspDevice`'s TX token before the sink (so every sink — ESP or the test wires — only ever sees wire-sized packets): an IP packet
  longer than `wire_mtu` is split — IPv6 per RFC 8200 §4.5 (insert a Fragment extension header after the base header; only the
  base header is unfragmentable when no extension headers are present — packets with other extension headers are dropped and
  counted (`tx_frag_drops`); fragment payloads are multiples of 8 except the last; 32-bit Identification from a randomly seeded
  per-device counter; M flag on all but the last; Payload Length recomputed per fragment); IPv4 per RFC 791 (split with MF/offset,
  recompute header checksum and Total Length; an already-fragmented packet keeps its Identification and its offsets are extended).
  **DF is NOT honoured (deviation, 2026-09-11):** smoltcp 0.14 sets DF on every IPv4 packet it emits and has no API to clear it, so
  honouring DF would drop every locally generated IPv4 datagram above 1252 bytes; the shim clears DF and assigns a fresh 16-bit
  Identification instead. Packets ≤ `wire_mtu` pass through untouched. Each fragment is one ESP packet.
- **RX (`ipstack/frag.rs::Ipv6Reassembler`)**, applied in `push_rx` before the device: reassemble IPv6 fragment sets keyed by
  (src, dst, Identification): TreeMap offset→chunk, complete when contiguous from 0 and the M=0 tail seen; rebuild the packet
  with the Fragment header removed, Next Header rewritten, Payload Length fixed; bounded (≤ 32 pending sets, ≤ 64 KiB each,
  30 s eviction, counters in `StackStats`: `rx_fragments`, `rx_reassembled`, `rx_reassembly_drops`; TX side `tx_fragmented`,
  `tx_frag_drops`). Exact duplicates are ignored; overlapping or malformed fragments discard the whole set. IPv4 fragments pass
  straight through — smoltcp reassembles those itself (`proto-ipv4-fragmentation`, `reassembly_timeout`).
- `InnerUdpSocket::send_to` payload cap becomes `inner_mtu_stack − 48` (v6) / `− 28` (v4); oversize → `Error::Protocol`.
- Tests: fragment→reassemble round trips (v6 sizes 1281, 1500, 3000, 8000, 16344, 65535; v4 3000 with DF set → fragmented with
  DF cleared), out-of-order/duplicate/missing fragments, eviction, set limit, overlap; and the two-stack loopback harness passes a
  3000-byte (and 8000-byte) **IPv6** UDP datagram both ways with the wire MTU 1280 (each device sink asserts every packet it emits
  is ≤ 1280).

### 11.2 Inner TCP (`InnerStack::connect_tcp` / `listen_tcp`, decision 2026-11-03)
SIP has to be able to run over TCP inside the tunnel — RFC 3261 §18.1.1: a request within 200 bytes of the path MTU (or
above 1300 bytes when it is unknown) MUST go over a congestion-controlled transport, and IMS registrations and NOTIFYs
easily get there — so the seam §11 left open is used: smoltcp `socket::tcp::Socket`s live in the same `SocketSet`,
driven by the same stack thread, and callers get blocking adapters.
```rust
impl InnerStack {
    pub fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> Result<InnerTcpStream>; // ephemeral port; Timeout / Io(ConnectionRefused) / Config
    pub fn listen_tcp(&self, port: u16) -> Result<InnerTcpListener>;                          // 0 = ephemeral; Io(AddrInUse) when taken
}
impl InnerTcpStream {   // &self throughout, Send + Sync: a reader thread and a writer thread may share one stream
    pub fn read(&self, buf: &mut [u8]) -> Result<usize>;  pub fn write(&self, data: &[u8]) -> Result<usize>;
    pub fn set_read_timeout(&self, t: Option<Duration>) -> Result<()>;  pub fn set_write_timeout(&self, t: Option<Duration>) -> Result<()>;
    pub fn set_nodelay(&self, nodelay: bool) -> Result<()>;  pub fn shutdown(&self) -> Result<()>;
    pub fn local_addr(&self) -> SocketAddr;  pub fn peer_addr(&self) -> SocketAddr;
}
impl InnerTcpListener {
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<(InnerTcpStream, SocketAddr)>>;
    pub fn local_addr(&self) -> SocketAddr;  pub fn local_port(&self) -> u16;
}
// EpdgTunnel::connect_tcp / listen_tcp forward to the stack (a dead tunnel is Error::Closed first); both are NetStack backends (§16).
```
- **Waiting.** A call takes `state` only to look at its socket or move bytes through its buffers (`recv_slice`,
  `send_slice`, a state check) and otherwise parks on `StackShared::tcp_events`: a generation counter with its own
  mutex/condvar, read *before* the socket is examined so that no event can slip in between. The stack thread bumps it
  after every poll that processed or sent a packet while TCP sockets exist; `close` bumps it right after publishing the
  reason; `shutdown` bumps it for a reader or writer blocked on the same stream. It is deliberately not a condvar on
  `state`: that mutex is held across a poll which can block in a slow outer send, and a call woken by a close must return
  `Error::Closed` without waiting for that poll (§17.6) — the guarantee a parked UDP receiver already has. Every call
  re-reads `StackShared::closed` before and after taking `state`, so it never touches a socket a close removed.
- **Connect.** A free ephemeral port (TCP ports are counted per local port — connections, backlog slots, orphans —
  independently of UDP's), `Socket::connect` (smoltcp chooses the source address of the destination's family; a family
  without an inner address is `Config`), wake the stack thread, wait for ESTABLISHED. A socket that went CLOSED first
  was refused (`Io(ConnectionRefused)`: the peer's RST, or smoltcp's own when nothing listens); the deadline is
  `Error::Timeout`. A failed or timed-out attempt is removed at once without sending anything, as an OS socket's is.
- **Listener = backlog emulation.** smoltcp has no accept queue: a socket in LISTEN takes exactly one connection, and a
  SYN that finds none is answered with RST. A listener therefore owns `TCP_LISTEN_BACKLOG` (2) listening sockets;
  `accept_timeout` hands out the first one that reached ESTABLISHED (or CLOSE-WAIT, when the peer already sent
  everything and its FIN) and puts a fresh LISTEN socket into its slot at once — so one connection can be pending while
  the next SYN still finds a listener; a SYN arriving while both slots are taken is refused, like one meeting a full
  accept queue. Slots carry smoltcp's socket timeout (`TCP_BACKLOG_TIMEOUT`, 30 s, cleared on accept): a handshake whose
  final ACK never comes, or a connection nobody accepts while its peer stays silent, is reset and the slot listens again,
  so neither occupies the backlog for good. A second listener on a port — or one on an outbound connection's local port
  — is `Io(AddrInUse)`; dropping a listener resets the connections nobody accepted (an OS listener does the same with
  its accept queue).
- **Duplicate SYNs.** smoltcp gives a segment to the FIRST socket in `SocketSet` order that accepts it, and a LISTEN
  socket accepts any SYN for its port. When our SYN-ACK is lost the peer retransmits its SYN; were the spare listening
  slot to sit before the half-open socket, it would answer with a second SYN-ACK (another ISN), and the peer's ACK —
  matching both sockets' 4-tuple — could be answered with RST, killing the connection. `push_rx` therefore drops a
  connection request whose 4-tuple already belongs to one of our sockets past SYN-SENT (`tcp_dup_syn_drops`): exactly
  what that socket does with it when it comes first (a SYN in a synchronized state is ignored; its own SYN-ACK
  retransmission completes the handshake). Only consulted while a listener exists.
- **MSS clamping.** smoltcp derives the MSS it announces — and the segment size it sends, `min(own, peer's)` — from the
  MTU it sees, which is the 16384-byte *stack* MTU of §11.1. Unclamped, every full segment would be ~16 KB and leave as
  a train of wire-MTU fragments, and an IPv4 one could not even be reassembled (smoltcp's IPv4 reassembly buffer is
  8 KiB). The device rewrites the MSS option of every SYN in both directions (`frag::clamp_tcp_mss`; checksum
  recomputed; only on a segment whose checksum verifies, so a corrupt one is not laundered) to `wire MTU − 40/20 − 20`
  (RFC 6691 §2: fixed headers only) — 1220 (IPv6) / 1240 (IPv4) at 1280. Ours tells the peer what to send; the peer's,
  lowered on the way in, caps what smoltcp sends. TCP never relies on IP fragmentation (RFC 8900), the MSS clamping any
  tunnel endpoint does (RFC 4459 §3.2); counted in `tcp_mss_clamped`.
- **Stream semantics** mirror `std::net::TcpStream` (§16): `read` → `Ok(n)`; `Ok(0)` at EOF, i.e. smoltcp's
  `RecvError::Finished` (the peer's FIN after everything before it); `Io(ConnectionReset)` for a socket closed without
  a FIN (`RecvError::InvalidState`); `Error::Timeout` per the read timeout. `write` → the bytes the send buffer took,
  waiting while it is full; on every error nothing was queued (the `io::Write` contract TLS relies on): `Timeout`,
  `Io(BrokenPipe)` after `shutdown`, `Io(ConnectionReset)` after a RST. `shutdown` = FIN (`Socket::close`), after which
  our reads are EOF and writes `BrokenPipe` (as after `shutdown(Both)`); idempotent, and `Ok` on a connection or stack
  that is already down. `set_nodelay` = `set_nagle_enabled(false)` (Nagle is on by default, as on the OS); a zero
  timeout is `InvalidInput`, as in std.
- **Buffers.** `TCP_BUFFER_BYTES` = 32 KiB each way: the advertised window stays below 64 KiB (no window scaling) and
  one `write` queues at most that much — a 64 KiB SIP message goes out in pieces as the peer acknowledges. No
  congestion controller is compiled in (smoltcp's `NoControl`), so the peer's window is the only limit and the 32 KiB
  buffer bounds a burst.
- **Reaper.** Dropping a stream closes it gracefully (FIN; queued data still goes out first) and marks its socket
  orphaned. The stack thread's per-poll TCP housekeeping frees an orphan once it is CLOSED with no 4-tuple left
  (TIME-WAIT expired — smoltcp's lasts 10 s — LAST-ACK acknowledged, reset, or its abort RST sent) and resets one still
  lingering after `TCP_ORPHAN_LINGER` (60 s): smoltcp never times out FIN-WAIT-2 or LAST-ACK on its own. The same pass
  puts a backlog slot that smoltcp closed back into LISTEN.
- **Close.** `State::shutdown` removes every TCP socket (nothing can be sent any more); the parked calls were already
  failed by `tcp_wake` (§17.6), and later ones fail from `StackShared::closed` before they look for their socket.
- **No retransmission give-up.** smoltcp retransmits unacknowledged data for ever (there is no RFC 1122 §4.2.3.5 R2)
  and no keep-alive is set, so a connection whose peer vanished without a FIN or RST — a middlebox that forgot the
  flow, say — stays ESTABLISHED: reads time out, writes go on filling the send buffer. Callers bound that themselves;
  the SIP transport over these streams (rsipstack `transport/custom_tcp.rs`) closes a connection nothing has arrived on
  for five minutes. Likewise a connection request from a 4-tuple that one of our sockets still holds (TIME-WAIT, or a
  half-open connection whose peer restarted on the same source port) is dropped until that socket is gone — smoltcp
  sends no RFC 5961 challenge ACK that would let the peer reset it.
- **Counters** (`StackStats`): `tcp_connections_opened`, `tcp_accepted`, `tcp_tx_bytes`, `tcp_rx_bytes`, `tcp_sockets`
  (gauge: streams, backlog slots, orphans), `tcp_dup_syn_drops`, `tcp_mss_clamped`.
- **A smoltcp 0.14 quirk met on the way:** `has_solicited_node` compares only the low 16 bits of a destination with each
  inner address and never checks the `ff02::1:ff00:0/104` prefix, so an IPv6 packet for ANY address ending in the same
  16 bits as one of ours is taken as ours (a SYN to it is answered with a RST from that foreign address). Harmless behind
  an ePDG, which routes only our own addresses to us; the tests avoid such addresses.
- **Tests** (two-stack loopback, `ipstack::stack::tests::tcp_*`): connect/accept and echo both ways over IPv6 and IPv4
  with exact endpoints; 100 KiB each way with every segment exactly wire-sized, no fragmentation, the clamped MSS in
  both SYNs and the writer blocked at exactly 64 KiB until the peer reads; EOF after the peer's shutdown, EOF/BrokenPipe
  after our own; the read timeout and a timeout-less read woken by data; a refused connect within a second; a connect
  timing out over a blackholed path and working once it is back; `accept_timeout` → `None`; the backlog (two pending,
  the third refused, refilled on accept); `AddrInUse`; a lost SYN-ACK recovered by retransmission with exactly one
  connection, and a retransmitted SYN injected by hand dropped with one ISN; the reaper (LAST-ACK at once, TIME-WAIT
  after 10 s); a dropped listener resetting its pending connection; a close failing a blocked read, write, accept and
  connect within a second, also while the stack thread sits in a 1.5 s sink stall. `frag`: the MSS clamp both families,
  idempotence, corrupt / non-SYN / fragment / malformed-option segments untouched. Plus the shared `exercise_tcp` and
  `exercise_tcp_write_timeout` of §16 on both backends.

## 12. Tunnel facade (`tunnel.rs`)
```rust
pub struct TunnelInfo { pub local_addr: SocketAddr, /* at establishment; see local_addr() */ pub remote_addr: SocketAddr,
    pub peer_mobike: bool, pub nat: NatStatus, pub assigned: AssignedConfig,
    pub ike_spi_i: u64, pub ike_spi_r: u64, pub child_spi_in: u32, pub child_spi_out: u32, pub ike_suite: String, pub child_suite: String,
    pub tls_version: String, pub handshake_duration: Duration }
pub struct EpdgTunnel { /* Arc<Shared>, rx thread, timer thread */ }
impl EpdgTunnel {
    pub fn connect(cfg: &Config) -> Result<EpdgTunnel>;
    pub fn info(&self) -> &TunnelInfo;
    pub fn bind_udp(&self, local_port: u16) -> Result<InnerUdpSocket>;   // 0 = pick free (49152..65535); smoltcp picks the source address by route
    pub fn resolve(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>>; // smoltcp DNS socket over the assigned servers
    pub fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> Result<InnerTcpStream>; // inner TCP (§11.2)
    pub fn listen_tcp(&self, local_port: u16) -> Result<InnerTcpListener>;                    // 0 = ephemeral (§11.2)
    pub fn is_alive(&self) -> bool;
    pub fn local_addr(&self) -> SocketAddr;                             // the outer socket's CURRENT address (moves with §17.1)
    pub fn peer_mobike(&self) -> bool;                                  // the responder announced MOBIKE_SUPPORTED (RFC 4555 §3.1)
    pub fn network_changed(&self);                                      // §17.1: an OS network-change callback; returns immediately
    pub fn dpd(&self) -> Result<Duration>;                              // on-demand liveness check (empty INFORMATIONAL), returns RTT
    pub fn stats(&self) -> TunnelStats;                                 // esp tx/rx packets+bytes, replay drops, icv fails, keepalives sent, last rx Instant,
                                                                        // address_updates, stray_sources (the current local address and
                                                                        // peer_mobike are read from local_addr() / info(), not duplicated here)
    pub fn close(self) -> Result<()>;                                   // INFORMATIONAL Delete(IKE) (best effort, short timeout), stop threads
}
pub struct InnerUdpSocket { /* port, Receiver<UdpDatagram>, Arc<Shared> */ }
impl InnerUdpSocket { pub fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> Result<()>;
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<UdpDatagram>>; pub fn local_port(&self) -> u16; }
impl Drop for EpdgTunnel /* best-effort close */ 
```
`connect` sequence: resolve gateway candidates → for each candidate (first success wins): `IkeTransport::bind` →
`IkeInitiator::new` → SA_INIT with cookie/group retry loop → if `nat.detected || !cfg.ike.natt.disable_switch_to_natt_port`
→ `switch_to_natt` (we MUST end up on 4500 because raw ESP is impossible in userspace; if the responder detected no NAT
it may reject UDP-encap — log a warning) → IKE_AUTH initial → EAP loop (`EapTlsClient`) → set_msk → AUTH final →
`Established` → build `EspOutbound`/`EspInbound` → spawn threads.
Rx thread: `recv` loop; `Esp` → `EspInbound::decapsulate` → push the inner IP packet into `EspDevice.rx` and notify the stack thread
(smoltcp then delivers UDP to the bound socket's channel); `Ike` → header: RESPONSE → hand to the pending-request slot (msgid) else
peer request → `handle_peer_request` → send response; `DeleteIke` → mark dead. `Keepalive` → ignore.
Timer thread (1 s tick): NAT-T keepalive `0xFF` every `keepalive_interval_secs` (10 s) on the SAME socket as IKE, starting right after
the switch to 4500, regardless of traffic (AOSP behaviour; RFC 3948 §4);
DPD if enabled and no IKE/ESP rx for `interval_secs` → `dpd()` with `max_retries`×`retry_interval_secs` → mark dead on
failure (torn down WITHOUT sending DELETE, like AOSP); rekey child at the soft lifetime `lifetime*(1-margin)` (no jitter) via `build_rekey_child`, then `build_delete_child(old)`;
rekey IKE at its lifetime similarly (`build_rekey_ike`, then delete old IKE SA — best effort, and **terminal for the
old SA either way**: acknowledged or not, `forget_old_ike()` drops it, because `build_delete_ike` prefers the old SA
while it is held, so a wedged one would send `close()`'s DELETE to an SA that is already gone while the live IKE SA and
its child stayed up on the gateway, and `build_rekey_ike` refuses outright while it is held, which disabled every
future IKE rekey. The gateway expires the old SA on its own). All post-establishment IKE requests go
through one `request()` helper that serialises on a mutex (one outstanding request), uses the transport's retransmit
policy, and routes the response via the rx thread's pending slot. Fragmented responses are collected there too; that
helper re-reads the transport's *current* socket for every send, so a rebind moves the remaining retransmissions to the
new source address without disturbing the request; the only thing that abandons one in flight is `close()`, within one
200 ms slice (§17.4).
Threads, spawned in this order and joined rx → keepalive → timer → path → stack: `epdg-stack`, `epdg-rx`,
`epdg-keepalive`, `epdg-timer`, `epdg-path` (§17.1). A spawn that fails part-way through (EAGAIN under thread or fd
pressure) unwinds the ones already started — `mark_dead` + `stop`/`closing`, then join — because `Drop`/`shutdown` live
on `EpdgTunnel`, which does not exist yet, and every loop runs until `stop`: returning the error without that would
leave threads, the outer socket and the inner stack running for the life of the process while `connect` moves on to the
next candidate. The timer thread also runs the one-way-traffic probe (§17.5).
Lock order, never taken in any other: `request_lock` → the transport's socket lock (brief) → `ike` → `pending`;
`path.inner` is a leaf. `stats()` takes `last_rx` and the inner stack's `state`, and never `ike` — it may be called
from a thread that already holds it. Inside the inner stack the order is `state` → `wakers`, and `tcp_events` is a leaf
(the stack thread bumps it holding `state`; a TCP call never holds it and `state` at once); `InnerStack::close` takes
`closed`, then `wakers`, then `tcp_events`, then `state`, never two of them at once across the boundary (§17.6).
Teardown: `close()` sets `closing` (not `stop`) and wakes the path thread *before* its DELETE(IKE), so closing never
waits out a retransmit schedule while the rx thread stays alive to deliver the DELETE's response; then `stop`, then
the stack is closed with the reason `"tunnel closed by request"` — see §17.6 for the whole death chain.

## 13. Tests
Unit (per module, `cargo test` offline): header/payload/message round-trips incl. every payload type; SK
encrypt→decrypt round-trip and ICV tamper → `Error::Integrity`; SKF fragment/reassemble round-trip; prf+ against a
hand-computed vector (HMAC-SHA256 KAT from RFC 4231 for the HMAC itself); AES-CBC KAT (NIST SP800-38A F.2.5);
DH group 14 checks (§3); IKE key derivation lengths/order; AUTH signed-octets construction; NAT hash KAT; EAP packet
round-trips; EAP-TLS fragmentation/reassembly with a fake peer; ESP round-trip + replay window semantics + pad/ICV
checks; inner stack (§11/§11.1): `EspDevice` capabilities / rx queue bound / tx token (exact length, fragmentation for the wire);
`frag.rs` fragment→reassemble round trips, malformed/overlap/eviction; two-stack loopback (`ipstack::stack::tests`): UDP both ways
v4+v6 with exact endpoints, off-prefix routing, IPv4 and IPv6 3000-byte datagrams fragmented at the wire MTU 1280 and reassembled
(every sink asserts ≤ 1280), payload caps, ICMPv4/v6 echo answered, a 256-datagram burst queued before the stack thread runs
delivered in full, send_to-then-drop still transmitted, send-buffer-full counted, `InnerUdpSocket` shared between a receiver
thread and senders (Send + Sync), bind_udp(0) allocation/duplicates/unbind-on-drop, queue bounds, resolve AAAA+A / family skip /
NXDOMAIN / caller timeout / silent server beyond smoltcp's 10 s give-up (Timeout, not Protocol) / non-unicast servers skipped /
input errors, stop semantics, stack-thread panic closes the stack; inner TCP (§11.2: connect/accept/echo, 100 KiB without
fragmentation, backlog, duplicate SYNs, reaper, timeouts, close semantics) and the MSS clamp;
config parsing of `tests/fixtures/tmobile_prod_bundle.plist` + `tmobile_creds.plist` (assert every mapped field);
mobility and liveness (§17, all offline): the MOBIKE notify constants and their status-vs-error range (including that
16403/16404 are *not* MOBIKE), NAT-D hashed with the real SPIr, `build_address_update` payload order and hashes (with
and without MOBIKE, with and without NAT-D), the response arm (commit, every rejection shape, malformed NAT-D
tolerated, `ADDITIONAL_*` tolerated), that an unanswered request's id is simply reused by the next one (RFC 7296 §2.1);
COOKIE2 echoed in every peer INFORMATIONAL response; `IkeTransport::rebind` over
loopback (new source port, destination kept, a blocked `recv` picks the new socket up) and `is_path_error` /
stray-source counting; the whole `PathMonitor::tick` table — including that an already-running grace still expires
while the route probe itself cannot run — the one-way-probe predicate, the idle-probe predicate, the ESP-stall
predicate (that inbound IKE does not disarm it, and that its silence is measured from the transmission) and the
address-update failure classification as pure functions with an injected clock, with a local `ENOBUFS`/`EPERM` send
failure classified transient; that ESP which fails ICV or names an unknown SPI, and IKE that does not decode, never
touch the liveness clocks; `mark_dead` waking a parked receiver and resolver at once with the right reason and keeping
the first one, including while the stack thread is inside a slow outer send; the path thread exiting on `closing`
alone; and, over a real loopback peer socket with a forced-established session, that `closing` abandons an in-flight
DPD instead of waiting out its schedule while `close()`'s own DELETE(IKE) still goes out, that a request outstanding
across a rebind retransmits from the NEW source port with the SAME message id and completes there — with the announce
following on the next id — that a request whose schedule ran out across a rebind is classified transient and kills
nothing while the grace still expires on time, and that a send the host refuses leaves nothing on the wire and spends
no escalation attempt. In `rsipstack`, `transport::custom_udp` tests a scripted fake socket: the
serve loop exits on `NotConnected`, survives other errors, reports a dead send to its caller while the receive path
ends the loop, and the connection stays unreliable UDP.
Live (`tests/live_tmobile.rs`): loads the fixtures, `EpdgTunnel::connect`, asserts an inner IPv6 (or v4) address and ≥1 DNS
server were assigned (P-CSCF attributes are optional — the PROD ePDG sends none; the P-CSCF is found via `resolve()`), prints
`TunnelInfo`; then resolves `ueb2bprod.pc.t-mobile.com` over the tunnel via the
assigned DNS (AAAA then A) and asserts ≥1 answer (proves ESP both ways); runs `dpd()` and asserts an RTT; sleeps 25 s
and asserts `is_alive()` (keepalive exercised); `close()`. Skipped (with a printed reason) when `EPDG_SKIP_LIVE=1`.
Log at `RUST_LOG=debug` includes hex dumps of every IKE datagram sent/received (redact keys).

## 14. AOSP reference facts (authoritative where they conflict with anything above)

The exhaustive, file:line-cited dump is in **`docs/AOSP_FACTS.md`** (read the section for your module). The must-replicate items:

**IKE_SA_INIT** — payloads `SA, KE, Ni, N(NAT_D_SRC 16388), N(NAT_D_DST 16389), N(FRAG_SUPPORTED 16430), N(SIG_HASH 16431: 00 01 00 02 00 03 00 04)`.
Transform order **ENCR, INTEG, DH, PRF**. KeyLength attr TV `0x800E 0x0100`. Proposal hdr: last=0/more=2; transform hdr: last=0/more=3.
SPIi = random nonzero u64; SPIr = 0; nonce 32 B; KE = group(2) | 0000 | 256-byte left-zero-padded public value; critical bit never set.
NAT_D_SRC hashed over **192.0.2.0 + real local port**; NAT_D_DST over the real gateway addr + 500. NAT is treated as detected whenever
the responder returns NAT-D notifies (local check forced true for IPv4). Retransmit waits 0.5/1/2/4/8 s after each of 5 sends (fail at 15.5 s), identical bytes each time.
Response: I flag clear, msgid 0, exchange 34, exactly one proposal ⊆ ours (ENCR compared incl. key length), KE group == ours, SA/KE/Ni required.
COOKIE: retry with N(COOKIE) first, everything else identical. INVALID_KE_PAYLOAD: full restart with the requested group.
After success switch to **4500 + 4-byte zero non-ESP marker** for all further IKE; start 0xFF keepalive every 10 s on the same socket.

**Keys** — SKEYSEED = prf(Ni|Nr, g^ir[256 B fixed]); prf+(SKEYSEED, Ni|Nr|SPIi|SPIr) → SK_d,SK_ai,SK_ar,SK_ei,SK_er,SK_pi,SK_pr (7×32 = 224 B).
Child: prf+(SK_d, Ni|Nr) → encr_i2r, integ_i2r, encr_r2i, integ_r2i (4×32). Rekey IKE: SKEYSEED = prf(SK_d_old, g^ir|Ni|Nr).

**SK payload** — `hdr(28, next=46) | SK generic hdr(next=first inner type or 0, len) | IV(16 random) | E(inner | pad | padlen) | ICV(16)`;
pad = 0..15 bytes (any value) so (inner+pad+1) % 16 == 0; ICV = HMAC-SHA256 over bytes[0..len-16] truncated to 16; SK must be the ONLY
top-level payload (length check). SKF: `| fragnum(2) | total(2) |` sits between the generic header and the IV and is authenticated;
threshold 1280 total bytes, 1196 plaintext bytes per fragment, fragment 1 carries the inner next-payload type, others 0; only when the
peer echoed FRAG_SUPPORTED; IKE_SA_INIT is never fragmented; reassembly per direction, no timeout.

**IKE_AUTH #1** — `IDi(3,UTF-8), IDr(FQDN 2, ASCII "ims.tmus"), N(16417), N(16396), SA(ESP: ENCR+keylen, INTEG, ESN 0; SPI 4 B), TSi, TSr, CP`.
TSi==TSr==[v4 any, v6 any]. CP(1) attrs `1,8,3,10,2,20,21,7` all length 0. NO AUTH. Msgid 1. Response: accepted with no AUTH (EAP-only);
IDr captured here; EAP payload required. Each EAP round = IKE_AUTH request with ONLY `EAP`; msgid +1 per round.
**Post-EAP** — request with ONLY `AUTH(method 2)` = prf(prf(MSK[64 B], "Key Pad for IKEv2"), RealMessage1 | Nr | prf(SK_pi, IDi body)).
Final response must have AUTH(method 2) verified over RealMessage2(raw bytes) | Ni | prf(SK_pr, IDr-from-first-response body), plus SA/TSi/TSr;
CP used only if CFG_REPLY(2): IP4 addrs 4 B, IP6 addr 17 B (16+prefix), DNS/P-CSCF 4/16 B; TS accepted if each responder selector ⊆ ours.
No DELETE is sent on any IKE_AUTH failure.

**EAP** — Identity response = raw ASCII identity (same string as IDi). EAP-TLS: TLS 1.2 only, no SNI, trust-all, leaf-only client cert,
1024-byte fragments, L on first/unfragmented, ACK `02 id 00 06 0d 00`, MSK = exporter("client EAP encryption", no ctx, 128)[0..64].
Nak = `02 id 00 06 03 0d`. Identifier always echoed. EAP-Success before handshake completion is fatal.

**Lifecycle** — DPD (if enabled) = empty SK INFORMATIONAL after idle; on retransmit exhaustion tear down WITHOUT DELETE. Peer DPD → empty
INFORMATIONAL response. DELETE(IKE): protocol 1, spi size 0, 0 SPIs; response must be empty. DELETE(ESP): protocol 3, spi size 4, our inbound
SPI; response carries the peer's. Rekey child: CREATE_CHILD_SA `SA(new SPI), TSi, TSr, Ni, N(REKEY_SA proto 3, spi = our inbound)`; keys via
prf+(SK_d, Ni|Nr) of THAT exchange; then DELETE old. Rekey IKE: `SA(IKE, 8-byte new SPI), KE, Ni`; new msgids start at 0; then DELETE old on old SA.
Peer CREATE_CHILD_SA we don't support → N(NO_ADDITIONAL_SAS) / TEMPORARY_FAILURE. Two msgid counters (ours/peer), window 1, cache last
response for a retransmitted peer request. AOSP rekeys at the soft lifetime with no jitter (its own defaults: IKE 7200 s, child 3600 s — the
bundle's 80000 s was never wired in; we use the bundle value with `rekey_margin_fraction`).

### 14.1 Reference byte layouts (known-answer vectors, from AOSP_FACTS_CRITIC.md #9-#11)
**IKE_SA_INIT request, IPv4 ePDG, glue suite — 456 bytes:**
```
hdr(28): iSPI(8) | 00*8 | 21 | 20 | 22 | 08 | 00000000 | len(=0x000001C8)
SA(48):  22 00 00 30 | 00 00 00 2C 01 01 00 04 | 03 00 00 0C 01 00 00 0C 80 0E 01 00 | 03 00 00 08 03 00 00 0C | 03 00 00 08 04 00 00 0E | 00 00 00 08 02 00 00 05
KE(264): 28 00 01 08 | 00 0E 00 00 | g^x (256 B, left-zero-padded)
Ni(36):  29 00 00 24 | 32 random bytes
N NAT_D_SRC(28): 29 00 00 1C | 00 00 40 04 | SHA1(iSPI || 00*8 || C0 00 02 00 || localPort(2))
N NAT_D_DST(28): 29 00 00 1C | 00 00 40 05 | SHA1(iSPI || 00*8 || remoteIPv4 || 01 F4)
N FRAG(8):       29 00 00 08 | 00 00 40 2E
N SIG_HASH(16):  00 00 00 10 | 00 00 40 2F | 00 01 00 02 00 03 00 04
```
(transform "more" byte = 3, last = 0; proposal last = 0, number 1, protocol 1, spi size 0, 4 transforms.)

**First IKE_AUTH inner plaintext (before SK), IDi 40 bytes, IDr "ims.tmus" — 292 bytes:**
```
IDi(48):  24 00 00 30 | 03 00 00 00 | "900999990302421609@prodepdg.t-mobile.com"
IDr(16):  29 00 00 10 | 02 00 00 00 | "ims.tmus"
N EAP_ONLY(8): 29 00 00 08 | 00 00 40 21
N MOBIKE(8):   21 00 00 08 | 00 00 40 0C
SA(44):   2C 00 00 2C | 00 00 00 28 01 03 04 03 | SPI(4) | 03 00 00 0C 01 00 00 0C 80 0E 01 00 | 03 00 00 08 03 00 00 0C | 00 00 00 08 05 00 00 00
TSi(64):  2D 00 00 40 | 02 00 00 00 | 07 00 00 10 00 00 FF FF 00 00 00 00 FF FF FF FF | 08 00 00 28 00 00 FF FF 00*16 FF*16
TSr(64):  2F 00 00 40 | (same body)
CP(40):   00 00 00 28 | 01 00 00 00 | 00 01 00 00 | 00 08 00 00 | 00 03 00 00 | 00 0A 00 00 | 00 02 00 00 | 00 14 00 00 | 00 15 00 00 | 00 07 00 00
```
→ pad 11 + padlen byte → 304 B ciphertext; SK = 4+16+304+16 = 340; IKE message = 368 B (never fragmented). SK next-payload = 0x23, header next = 0x2E, exchange 0x23, flags 0x08, msgid 1.

**Post-EAP IKE_AUTH request:** inner = one AUTH payload `00 00 00 28 | 02 00 00 00 | 32-byte HMAC` (40 B) → 7 pad + padlen → 48 B ciphertext; SK = 84; message = 112 B; SK next-payload 0x27.


## 16. `NetStack` — one socket/DNS abstraction over the OS stack and the tunnel (2026-09-11)

Purpose: application code (the SIP client) is written once against `epdg::netstack::NetStack` and runs unchanged over the host
OS stack or inside the ePDG tunnel. Object-safe (consumers hold `Arc<dyn NetStack>`), synchronous. UDP, TCP (connections and
listeners) and DNS on both backends: the OS sockets, or the inner stack's smoltcp sockets (TCP since 2026-11-03, §11.2).

```rust
// src/netstack/mod.rs
pub trait NetStack: Send + Sync {
    /// Bind a UDP socket on `local_port` (0 = ephemeral).
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>>;
    /// Open a TCP connection to `remote` within `timeout` (v4-mapped = IPv4): `TimedOut` unanswered, `ConnectionRefused` on a RST.
    fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>>;
    /// Listen for TCP connections on `local_port` (0 = ephemeral); a port with a listener already is `AddrInUse`.
    fn listen_tcp(&self, local_port: u16) -> io::Result<Box<dyn TcpListenerLike>>;
    /// Resolve `host` to A/AAAA addresses with THIS stack's resolver, within `timeout`. IP literals return immediately.
    fn resolve(&self, host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>>;
    /// Addresses this stack sources traffic from (SIP Via/Contact): the tunnel's inner addresses; for the OS stack the
    /// configured bind address, else the route-selected egress address per family.
    fn local_addrs(&self) -> Vec<IpAddr>;
    /// Backend name for logs: "std" / "epdg-tunnel".
    fn name(&self) -> &'static str;
}
pub trait UdpSocketLike: Send + Sync {
    fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> io::Result<()>;
    /// `Ok(None)` on timeout; `Err(NotConnected)` once the stack is closed. Any `timeout` (incl. `Duration::MAX` =
    /// wait for a datagram) is fine. Receivers are serialised (single consumer): a concurrent second `recv_timeout`
    /// waits for the first to return before its own timeout starts. A v4-mapped `dst` in `send_to` is IPv4 on both backends.
    fn recv_timeout(&self, timeout: Duration) -> io::Result<Option<(SocketAddr, Vec<u8>)>>;
    fn local_addr(&self) -> SocketAddr;
}
/// A connected TCP stream. Methods take `&self` (like `impl Read/Write for &std::net::TcpStream`) so one connection can be
/// shared by a reader thread and a writer thread through `Arc<dyn TcpStreamLike>`.
pub trait TcpStreamLike: Send + Sync {
    /// Read into `buf`; `Ok(0)` = EOF; honours the read timeout (`Err(WouldBlock|TimedOut)` on expiry).
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Partial write (`io::Write::write` contract: `Err` ⇒ nothing consumed, so TLS can retry the record).
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Provided: loops over `write` (`WriteZero` on `Ok(0)`, retries `Interrupted`).
    fn write_all(&self, buf: &[u8]) -> io::Result<()> { .. }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
    fn local_addr(&self) -> SocketAddr;
    fn peer_addr(&self) -> SocketAddr;
    /// Shut down both directions. Idempotent: `Ok(())` when already down (peer closed / shut down before).
    fn shutdown(&self) -> io::Result<()>;
}
pub trait TcpListenerLike: Send + Sync {
    /// Accept one connection, waiting at most `timeout`; `Ok(None)` on timeout. Any `timeout` (incl. `Duration::MAX`) is fine.
    fn accept_timeout(&self, timeout: Duration) -> io::Result<Option<(Box<dyn TcpStreamLike>, SocketAddr)>>;
    fn local_addr(&self) -> SocketAddr;
}
/// `std::io::Read + Write` adapter over any `&dyn TcpStreamLike` so TLS (e.g. `openssl::ssl::SslStream`) can wrap it.
/// `Debug` (so `HandshakeError<StreamIo>` is `Display + Error` and propagates with `?`); `write` = the partial write.
pub struct StreamIo<'a>(pub &'a dyn TcpStreamLike);
impl fmt::Debug for StreamIo<'_> { .. }  impl io::Read for StreamIo<'_> { .. }  impl io::Write for StreamIo<'_> { .. }
```
Implementations:
- **`StdNetStack`** (`src/netstack/std_stack.rs`): `StdNetStack::new()` binds dual-stack `[::]` (falls back to `0.0.0.0` if IPv6 is
  unavailable); `with_bind_addr(IpAddr)` pins a family/address. `bind_udp` → `std::net::UdpSocket`; v4-mapped peers (`::ffff:a.b.c.d`)
  are normalised to IPv4 on receive and mapped on send when the socket is dual-stack. `connect_tcp` → `TcpStream::connect_timeout`
  (bound to the bind address when specific, via `socket2`-free means: plain `connect_timeout`, documenting that a specific bind
  address is not applied to outgoing TCP unless trivially possible with std); `listen_tcp` → `TcpListener` on `(bind_addr, port)`,
  `accept_timeout` via `set_nonblocking(true)` + poll loop with a short sleep or `accept` under a read timeout (std listeners have no
  accept timeout: implement non-blocking accept + 10 ms sleeps until the deadline). Streams wrap `std::net::TcpStream` (read/write via
  `&TcpStream`), `set_nodelay`, `shutdown(Both)`. `resolve` → **the libc resolver** via `std::net::ToSocketAddrs`
  (`(host, 0).to_socket_addrs()` = `getaddrinfo`), executed on a helper thread so `timeout` is honoured (`Err(TimedOut)` after
  `timeout`; helper detached); results deduplicated, order kept. `local_addrs` → the bind address if specific, else the egress address
  per family found with a `connect`ed-but-silent UDP socket (no packet is ever sent; families without a route omitted).
  `recv_timeout` → `set_read_timeout` + `recv_from` into a 64 KiB buffer; `WouldBlock`/`TimedOut` → `Ok(None)`. Deadlines are
  `Instant::now().checked_add(timeout)`; `None` (e.g. `Duration::MAX`) = no deadline (`recv`/`accept` until woken). `connect_tcp`
  clamps a zero timeout to 1 ms (std rejects 0 with `InvalidInput`). `shutdown` maps `ENOTCONN` to `Ok(())`. `local_addrs` also
  omits a link-local egress address (`fe80::/10`, `169.254/16`: unusable as Via/Contact without its zone). The OS's maximum
  datagram size applies to `send_to` (macOS default 9216 bytes, `EMSGSIZE` beyond) whereas the tunnel fragments up to ~64 KiB.
- **`EpdgTunnel: NetStack`** — `bind_udp` / `resolve` / `local_addrs` / `connect_tcp` / `listen_tcp` delegate to the tunnel (DNS
  = smoltcp's DNS socket over the assigned tunnel servers — the libc resolver cannot reach tunnel-internal servers; TCP = the
  inner stack's smoltcp TCP sockets, §11.2; a v4-mapped `connect_tcp` destination is IPv4, as for `send_to`).
  `InnerUdpSocket: UdpSocketLike`, `InnerTcpStream: TcpStreamLike` (a read timeout expires as `TimedOut`),
  `InnerTcpListener: TcpListenerLike` (`local_addr` = the first inner address + port). **`InnerStack: NetStack`** too (same
  delegation) so the trait is testable offline over the two-stack loopback harness.
- Error mapping `epdg::Error → io::Error` (`netstack::to_io`): `Io(e)` → `e`; `Timeout` → `TimedOut`; `Closed` → `NotConnected`;
  `Config`/`Unsupported` → `InvalidInput`; everything else → `Other`; the crate error is kept as the payload
  (`io::Error::new(kind, e)`: `io::Error::get_ref()` / `into_inner()` downcast to `epdg::Error`; `Display` is the crate error's —
  note `std::error::Error::source()` on the `io::Error` is `None`). Conditions a caller branches on have the same kind on both
  backends: a taken port in `bind_udp` / `listen_tcp` is `AddrInUse` (`InnerStack::bind_udp` / `listen_tcp` return
  `Error::Io(AddrInUse)` for it), a refused connect `ConnectionRefused`, an unanswered one `TimedOut`, a reset connection
  `ConnectionReset`, a write after `shutdown` `BrokenPipe` (the inner stack returns those as `Error::Io` / `Error::Timeout`), a name
  that does not exist is `NotFound` (the tunnel's `Error::Protocol("DNS query failed …" | "… returned no addresses")` is mapped to
  `NotFound` by the `resolve` impls; other `Protocol` errors stay `Other`). Scoped IPv6 literals (`fe80::1%lo0`) are rejected with
  `InvalidInput` ("scoped IPv6 literal … not supported": an `IpAddr` cannot carry the zone).
- Exports: `epdg::netstack::{NetStack, UdpSocketLike, TcpStreamLike, TcpListenerLike, StreamIo, StdNetStack}` and the same from `epdg::`.

Tests: one generic `fn exercise_udp<S: NetStack + ?Sized>(a: &S, b: &S)` run over BOTH backends (bind two sockets, send both ways,
echo, `recv_timeout` → `None` on silence, `local_addr` port matches, `local_addrs` non-empty, ephemeral ports distinct, usable through
`Arc<dyn NetStack>`), and likewise a generic `exercise_tcp(a, b)` over BOTH backends (loopback `StdNetStack`s, the two-stack
loopback in both directions and through `Arc<dyn NetStack>`): `b` listens, `a` connects to `b`'s first local address while the
acceptor waits, `AddrInUse` on a second listener, the addresses on both ends, write/read both ways through `Arc<dyn TcpStreamLike>`
from two threads, read timeout → `WouldBlock|TimedOut`, a zero timeout → `InvalidInput`, EOF after peer shutdown, idempotent
shutdown, write after shutdown fails, `accept_timeout` → `None` on silence, `StreamIo` wraps a stream as `Read + Write`, connect
to a closed port → error within the timeout, a zero connect budget is not `InvalidInput`; and `exercise_tcp_write_timeout(a, b)`
(the `io::Write` contract under a write timeout, then a 1 MiB `write_all` to a draining peer) on both. std resolve:
`resolve("localhost")` contains a loopback; IP literal without the resolver; invalid label errors; a too-short timeout returns
promptly (`TimedOut` or a fast error). Tunnel: `resolve` over the fake DNS server returns the fake answer; after close
`recv_timeout`, TCP read/write/accept and new `connect_tcp` / `listen_tcp` → `Err(NotConnected)` (shutdown stays `Ok`);
NXDOMAIN → `NotFound`; a v4-mapped `send_to` destination is delivered as IPv4 and a v4-mapped `connect_tcp` connects over IPv4. std extras: `Duration::MAX` `recv_timeout`/`accept_timeout` woken by a send/connect (no panic);
a write under a write timeout never loses or duplicates bytes (delivered == reported); `shutdown` after peer EOF is `Ok`;
`connect_tcp(_, ZERO)` is not `InvalidInput`; `HandshakeError<StreamIo>: Error`. `epdg-connect` performs its P-CSCF lookup and the
DNS round trip through `&dyn NetStack` and asserts `name() == "epdg-tunnel"`, `local_addrs()` == the assigned inner addresses and
`bind_udp` (incl. `AddrInUse` on a taken port) so the live run covers the `EpdgTunnel` implementation; `--tcp-probe` (passed by
`live_tmobile_tunnel`) also opens one `connect_tcp` to the resolved P-CSCF on the `pcscf-address` port and prints `TCP-PROBE ok
local=… peer=… in=<ms>` or `TCP-PROBE-FAILED <reason>` — reported, never asserted, since whether the P-CSCF takes TCP is unknown.

## 17. Mobility and liveness (`tunnel.rs`, `ike/transport.rs`, `ike/session.rs`)

The outer socket is bound once to the egress address the OS picked at connect time (§7), but the host under it
does not hold still: Wi-Fi comes and goes, a handover changes the egress interface, an IPv6 privacy address rotates.
And because operator bundles routinely clear `dpd.enabled` (the T-Mobile one does), nothing used to notice a gateway
that had stopped answering. §17 is the three answers: a **path monitor** that moves the socket and tells the gateway,
a **one-way traffic probe** that runs whatever the bundle says about DPD, and a **death signal** that reaches the SIP
transport at once instead of at its own timeout.

### 17.1 The path monitor (`epdg-path` thread)

The authority is `IkeTransport::probe_egress()` — `discover_egress` at the transport's current destination: bind a
throwaway socket, `connect()` it (no packets leave), read back `local_addr().ip()`. That is the address the OS *would*
source from right now; comparing it with the address the transport is bound to is the whole detection.

It runs on its own thread (not on the 1 s timer tick, whose body can block for tens of seconds inside DPD retries or a
rekey) every `PATH_PROBE_INTERVAL`, and out of band when:
- an outer send fails with a path-kind error — `AddrNotAvailable` / `NetworkUnreachable` / `HostUnreachable` /
  `NetworkDown`, or the platform errno behind them (`is_path_error`, with a cfg'd errno table for macOS/iOS and Linux
  because `io::ErrorKind` does not cover every libc case). The ESP sink, the keepalive thread, `ike_request`'s sends
  and the rx thread's receive errors all report through `PathState::note_path_error`; or
- the caller calls `EpdgTunnel::network_changed()` from an OS network-change callback (`NWPathMonitor`,
  `ConnectivityManager`).
An out-of-band request is floored at `PATH_PROBE_MIN_SPACING`: a downed interface fails thousands of ESP sends per
second, and each one asks for a probe. `network_changed()` bypasses the floor, being caller-driven and rare.

The decision itself is a pure function — `PathMonitor::tick(PathInput) -> PathAction`, no clock reads, no I/O — so
every branch below is a unit test:

| probe | state | action |
|---|---|---|
| any | impaired for ≥ `NO_ROUTE_GRACE` | `Dead(reason)` |
| `Unknown` (the probe itself failed: EMFILE, sandbox EPERM…) | every send failing **and** nothing received, both for ≥ `NO_ROUTE_GRACE` | `Dead("the outer socket has been unusable for …")` — the wedge rule reads neither the probe nor a clock, and its two inputs already say nothing works. No rebind first: that needs the very socket the probe could not make |
| `Unknown` | anything else | `Idle`, **no clock started or advanced** — a denied probe socket must never tear down a working registration |
| `NoRoute` (a path-kind `Io` from the probe) | — | start/keep the impairment clock ("no route to the gateway") → `Idle` |
| `Egress(ip)` | rebound but not acknowledged | `Announce`, or `Rebind(ip)` if the route moved again meanwhile |
| `Egress(ip)`, `ip != bound` | — | `Rebind(ip)`, unless the previous move was < `MIN_ADDRESS_UPDATE_INTERVAL` ago (flap damping), in which case `Idle`. A first move after a quiet period is never delayed — that is the handover this feature exists for |
| `Egress(ip)`, `ip == bound` | impairment clock running | `Rebind(ip)` — the interface came back, possibly on the same address; the stale binding and its fresh ephemeral port are themselves the change the gateway must learn. Damped by `MIN_ADDRESS_UPDATE_INTERVAL` exactly like the row above, or a link flapping between `NoRoute` and the same address would alternate the two rows and spend one address update per blip — as often as `PATH_PROBE_MIN_SPACING`, since a failing send asks for an out-of-band probe. The impairment clock keeps running while it waits, so `NO_ROUTE_GRACE` still bounds the outage |
| `Egress(ip)`, `ip == bound` | every send failing **and** nothing received, both for ≥ `NO_ROUTE_GRACE` | one `Rebind(ip)`, then `Dead("the outer socket has been unusable for …")` |
| otherwise | — | `Idle` |

Row order is load-bearing: the grace **and the wedge rule** are evaluated before the `Unknown` shortcut. A probe that
cannot run is usually persistent (an fd limit, a sandbox policy), and letting it short-circuit an already-running clock
froze that clock forever, so nothing was left that could declare the tunnel dead while it carried nothing. The same
went for the wedge rule, which used to sit inside the `Egress` branch: a host that could never probe while every send
failed with a path errno had no route to death at all, since both liveness probes fail their *first send* and so return
`Io`, never the `Timeout` that `request_verdict` needs. `Unknown` now only refuses to *start or advance* a clock, which
is all its rationale ever justified.

One clock covers every kind of impairment (no route, a rebind that keeps failing, an address the gateway will not
acknowledge, a wedged socket); `impaired_reason` only relabels it, so the grace covers the whole outage rather than
restarting per phase. A configured `gateway.local_addr` is a promise: the monitor may rebind *on* it (a fresh port
after an outage) but never moves off it.

`IkeTransport` holds its socket as `RwLock<Bound { Arc<UdpSocket>, SocketAddr }>`; every operation clones the `Arc`
and drops the guard, so no lock is ever held across a syscall, and `recv` re-samples it each iteration with the read
timeout capped at 200 ms — a rebind under a blocked receive is picked up within a slice. `rebind(ip)` binds a fresh
ephemeral port, swaps under the write lock and hands the old socket back to the caller, which keeps it alive until the
announce that follows has finished — so the kernel cannot hand that port to another socket in this process while the
gateway's binding may still point at it. It is held across that FIRST announce attempt and released when the attempt
finishes, whatever its outcome (an announce that timed out is retried on the next tick from the socket already rebound,
with no old handle held); it is never read from, so late inbound ESP in that window is lost either way (§17.8).
Destination, non-ESP marker and both ESP SAs are untouched: same SPIs, same keys, same replay state. Only the 5-tuple
moved, which is exactly what the announce says.

### 17.2 The MOBIKE address update (RFC 4555)

`MOBIKE_SUPPORTED` (16396) is sent in IKE_AUTH #1 when `ike.mobike` (AOSP parity, unchanged); the responder's answer
is now *latched*: `IkeInitiator::peer_mobike()` is true if either IKE_AUTH response carried it (AOSP's
`maybeEnableMobility` accepts both), and `mobike_enabled() = peer_mobike && cfg.ike.mobike` is the single authority
both the builder and the tunnel's labelling read, so they cannot disagree.

After a rebind, `announce()` sends, serialised on `request_lock` like every other post-establishment request:

```
INFORMATIONAL  N(UPDATE_SA_ADDRESSES 16400), N(NAT_DETECTION_SOURCE_IP), N(NAT_DETECTION_DESTINATION_IP)
```

in that payload order (AOSP). The NAT-D hashes are `SHA-1(SPIi | SPIr | IP | port)` (RFC 7296 §2.23) with **both real
SPIs** — `nat::request_notifies` therefore takes `spi_r` now; hashing with the SA_INIT-time zero would produce a
DESTINATION the gateway cannot match. The destination hash uses the *transport's* current remote address
(gateway:4500), never `IkeInitiator::remote`, which still says `:500` because `switch_to_natt` never told the session.
The source hash keeps the crate's deliberate fake `192.0.2.0` with the real new port (§6): that is what keeps the ePDG
convinced we are behind a NAT and keeps it UDP-encapsulating ESP, the only kind a userspace client can carry. NAT-D is
included only when `mobike && remote.is_ipv4() && nat.supported` — AOSP's `needNatDetection()`, which asks whether the
NAT-T status is *not UNSUPPORTED* (`docs/AOSP_FACTS_CRITIC.md`), i.e. whether the responder answered our NAT-D at
IKE_SA_INIT at all. That is `NatStatus::supported`, a flag `nat::evaluate` now reports, and deliberately **not**
`detected`: an honest un-NATted IPv4 path detects no NAT while NAT-T is perfectly well supported, and RFC 4555 §3.8
wants the pair re-sent precisely so the responder can re-run detection for the new path.

Handling the response (`Pending::AddressUpdate`, its own arm — the `Dpd` arm deliberately checks nothing and the
catch-all arm would have reported a bogus CREATE_CHILD_SA error):
1. a real error notify (< 16384) → `Error::PeerNotify`. RFC 4555 §12 puts two of the three MOBIKE rejections here:
   `UNACCEPTABLE_ADDRESSES` (**40**) and `UNEXPECTED_NAT_DETECTION` (**41**). They need no special case at all —
   `IkeMessage::error_notify()` finds them like any other error type. (16403/16404 are *not* MOBIKE: they are
   `AUTH_LIFETIME` (RFC 4478) and `MULTIPLE_AUTH_SUPPORTED` (RFC 4739), which a responder may legitimately send and
   which must never be read as a rejection.)
2. `NO_NATS_ALLOWED` (16402) → the same error. It is the one MOBIKE rejection IANA registers in the **status** range,
   so `NotifyPayload::is_error()` / `IkeMessage::error_notify()` do not catch it and it is checked for by hand; it is
   also the one our fake source hash can provoke;
3. otherwise the move is committed first (`self.local`, and `self.remote`, which repairs the stale `:500`), and only
   then is the NAT-D block evaluated. A malformed **or missing** block is a `warn!` that keeps the previous
   `NatStatus`: RFC 4555 does not require the responder to re-run NAT detection, AOSP's `handleNatDetection` treats
   the same bare response as a successful move, and refusing it would kill a tunnel whose handover the gateway had
   already accepted.

**A move never interrupts an outstanding request.** This is the ordering rule the whole section rests on, and it is
two sentences of mechanism:

- `IkeTransport` re-reads its socket for **every** send (`RwLock<Bound>`, the guard dropped before the syscall), so a
  rebind in the middle of a request simply moves that request's remaining retransmissions — *same message id, same
  bytes* — to the new source address. The gateway answers whatever source it heard from, cached response or freshly
  processed (RFC 7296 §2.1 entitles a retransmission to the cached one), and the window stays in step by construction.
  Nothing is cancelled, so nothing has to be re-sent, re-built or re-numbered.
- `announce()` therefore does not race that request: it takes `request_lock` like every other post-establishment
  exchange and goes out once the outstanding one has **settled**. There is no reservation, no yield, no deadline and
  no message id to spend. Waiting is always affordable — the full retransmit schedule is 15.5 s, `NO_ROUTE_GRACE` is
  30 s — and if the grace expires anyway, §17.4's grace death applies unchanged.

**What a move does not fix: an id whose schedule ran out.** A move never abandons a request, but three things still do —
teardown, a send the host refused, and a retransmit schedule that is exhausted (§17.4 makes the latter *survivable*,
which is precisely what keeps it reachable on a live tunnel). `abort_request(transmitted)` frees the session's single
request slot and leaves `our_msgid` alone, because the window is one message wide and skipping an id would stall the
responder. So the **next** request,
possibly a different exchange, is built on that id, and RFC 7296 §2.1 then obliges a responder that *did* process the
abandoned one to replay its cached response for it **without processing the new request**. Nothing in the header tells
the replay from a genuine answer: same SPIs, same id, and — for an announce landing on a DPD's id, or a second
CREATE_CHILD_SA landing on the first's — the same exchange type.

§2.1's protection is therefore free only for the **same** request. The guard is one field and one check:

- `IkeInitiator::abandoned_msgid` remembers the id `abort_request(transmitted)` gave up on — **only when at least one
  datagram of it actually reached the kernel**, because only then can the gateway be holding a cached response. A
  request the host refused outright (`EACCES` from a local filter, `ENOBUFS`; the send loop breaks on the first
  failure, so on attempt 0 nothing was transmitted), a fragment set the loop never finished (an incomplete RFC 7383 set
  is never processed either) and a build whose `encode` failed all leave the id clean. Flagging one of those made the
  retry on that id refuse the gateway's *genuine* answer: one wasted exchange, an orphaned child SA behind a rekey,
  and — since the refusal is an `Error::Protocol`, which §17.3's catch-all charges — one of the two
  `ESP_MIGRATION_REKEY_ATTEMPTS` spent on our own bookkeeping. `consume_message_id()` clears the flag (an accepted
  response spends the id, so nothing can be replayed onto a later one);
- `accept_response()` refuses a response on such an id **for the exchanges that commit state on a bare
  acknowledgement** — `UPDATE_SA_ADDRESSES` / the §2.23 announce, and both rekeys. Committing a replayed acknowledgement
  would move the SA the gateway never moved (and RFC 4555 §3.8 forbids it to re-learn our address from ESP, so ESP
  would be black-holed while every IKE liveness signal stayed green), or derive child keys against the cached
  response's nonce and then DELETE the SA that still works. A DPD or a DELETE needs no guard: a replay is still the
  gateway answering *this* datagram, which is all they ask.

The id is consumed either way, so one refusal unpoisons the session and the retry runs on a fresh id — the announce
costs one extra round trip in the worst case, which the path monitor is already retrying for.

`accept_response` releases the request slot on both error paths that consume the id (this one, and a response on the
right id but the wrong exchange type), or `require_idle` would refuse every later request.

`ADDITIONAL_IP4_ADDRESS` / `ADDITIONAL_IP6_ADDRESS` / `NO_ADDITIONAL_ADDRESSES` are logged and ignored wherever they
appear (RFC 4555 §3.4 tolerance; we never use a peer address list). We do not *send* `COOKIE2` (AOSP parity) but we
echo the peer's verbatim — the whole notify, protocol id and SPI included — in every peer INFORMATIONAL response,
including the DELETE ones (RFC 4555 §3.7 return-routability). A peer-initiated `UPDATE_SA_ADDRESSES` is logged and
answered generically: RFC 4555 only lets the initiator move.

On success: `address_updates` is bumped, one NAT-T keepalive is sent straight away to re-open the gateway's binding
for the new port, and the move is logged at info with old → new.

### 17.3 Without MOBIKE (RFC 7296 §2.23)

If the responder did not announce MOBIKE the socket still moves, and the announce is an **empty INFORMATIONAL** from
the new address: because the gateway believes we are behind a NAT, §2.23 has it update its stored peer address from
the datagram it just received. On the wire that is byte-identical to a DPD; only the tunnel's log label
(`INFORMATIONAL (address update)` vs `INFORMATIONAL (UPDATE_SA_ADDRESSES)`) tells them apart.

This is a deliberate divergence from AOSP, which instead rekeys every child SA (`migrateAllChildSAs`) after a move on
a non-MOBIKE SA. The empty INFORMATIONAL is far cheaper and moves the IKE SA; what it cannot guarantee is that the
gateway also moved the child SA's encapsulation port. So the fallback carries a safety net: if the move was
acknowledged, we have **sent ESP** from the new address since, and **no ESP** has arrived for `ONE_WAY_PROBE_SILENCE`
(`esp_migration_stalled`), a child rekey runs — up to `ESP_MIGRATION_REKEY_ATTEMPTS` (2) per move. The outbound-evidence condition is what keeps an idle
tunnel out of it: a registered but silent IMS tunnel receives nothing by definition (keepalives are excluded and the
gateway sends nothing unsolicited), so without it every single move on a non-MOBIKE peer would be followed 20 s later
by a pointless CREATE_CHILD_SA + DELETE(ESP).

Both clocks are **ESP-only** (`last_esp_tx` / `last_esp_rx`, stamped by the ESP sink and by rx_loop's `Incoming::Esp`
arm), not the IKE-inclusive `first_tx_since_rx` / `last_rx_data`. The hypothesis being tested is "IKE moved, ESP did not", so
inbound IKE is what the failure case *produces* — a peer DPD, or the response to our own one-way probe, which becomes
due at the very same threshold — and counting it as evidence of health disarmed the check precisely when it was needed.
Symmetrically an IKE request of ours is not evidence that ESP was sent, or an idle tunnel with the bundle DPD enabled
would be rekeyed after every move.

The **decision** is made on the path thread; the rekey itself is handed to the timer thread through
`PathState::request_esp_rekey()` / `take_esp_rekey_request()`, and its **outcome** comes back the same way
(`note_esp_rekey_failed()` / `take_esp_rekey_failure()`, `note_esp_rekey_done()` / `take_esp_rekey_done()`). `rekey_child` holds `request_lock` across two exchanges
(up to ~31 s with the default schedule), and the path thread is the only one that enforces `NO_ROUTE_GRACE`, probes the
route and follows a second address change — it must never block for that long (§17.1 gives it its own thread for
exactly this reason). The timer thread already accepts multi-second blocking, and an escalation rekey that exhausts its
retransmissions with the socket holding still is classified by `request_verdict` like any other rekey, so a gateway
that has genuinely gone is not merely warned about. The path thread skips the escalation once `closing` is set, so it
can never hold `request_lock` against `close()`.

The escalation is armed and disarmed by the **outcome**, not by the request. The path thread's "rekeyed" flag means
"a repair is in flight", and it is set when the *request* is made, so only an outcome may clear it. Leaving it set
disarms `esp_migration_stalled` for the rest of the tunnel's life and leaves a child SA pinned to the pre-move
encapsulation port that **nothing** could see: the IKE SA did move, so it answers every DPD, which refreshes
`last_rx_data` and clears `first_tx_since_rx` and therefore satisfies both liveness probes of §17.5 forever.
`escalation_outcome(error, installed, path_unsettled)` routes what came back through the same `request_verdict`
every other caller uses, and refines it into four cases:

- **Fatal** — `RequestVerdict::GatewayGone`: retransmissions exhausted with the socket holding still. `mark_dead`, as
  for any other rekey. This is decided **before** `installed` is consulted: a gateway that went silent over a settled
  path is gone whichever half of the rekey it went silent under, and a tunnel whose gateway is gone is dead even if its
  child SA was migrated a moment earlier — exactly as for a DPD.
- **Done** — the exchange completed, *or* it failed **non-fatally** after `rekey_child` had already committed the new
  SAs (`installed` — only the DELETE of the old child SA failed, so the migration itself happened and blaming the
  gateway for it would be wrong; `installed` only ever refines a non-fatal outcome). **A completed rekey is not proof that ESP came back.** The gateway this escalation exists for answers the
  CREATE_CHILD_SA on the IKE SA, which did move, and may still derive the new child SA's encapsulation from the same
  stale state. So the path thread restarts `moved_at` at the completion instant and re-arms the check: if ESP is still
  one-way `ONE_WAY_PROBE_SILENCE` after the next ESP transmission, the escalation runs again. Treating `Ok(())` as a
  repair — the original behaviour — disarmed the check permanently for that move, which is the same invisible black
  hole as forgetting a failure.
- **Abandoned** — the narrow, enumerated set that proves nothing: an `Io` whose errno says the **route** broke
  (`is_path_failure`), `Closed` during a teardown, or a `Timeout` over an unsettled path (`GatewayGone` already took
  the settled case). Nothing left the host, or the gateway may never have been able to answer the source it left from,
  so the request is simply re-made and **no attempt is spent** (§17.4). Charging those used to kill a recoverable
  tunnel about 4 s into an outage whose advertised tolerance is `NO_ROUTE_GRACE`, with a reason blaming the gateway
  for a CREATE_CHILD_SA that never left the host.
- **Failed** — the **catch-all**, and it is this way round on purpose. The gateway was reached and refused or could not
  complete it (`N(TEMPORARY_FAILURE)` while it rekeys on its own, RFC 7296 §2.25; `NO_ADDITIONAL_SAS`; a response we
  cannot use), *or* the failure is local and **deterministic** — a transform we cannot instantiate, an encode error, a
  send the host refuses for a reason that is not a broken route (`EPERM` from a local filter, `ENOBUFS`). Re-arm and
  spend an attempt. Were the catch-all `Abandoned` instead, a deterministic failure would re-request itself once per
  timer tick forever with no attempt ever spent, so `ESP_MIGRATION_REKEY_ATTEMPTS` could never be reached and the
  tunnel would report itself alive over a permanently black-holed child SA.

Both **Done** and **Failed** spend one of this move's `ESP_MIGRATION_REKEY_ATTEMPTS` attempts. The decision to give up
is taken where the stall is re-evaluated, not where the outcome is taken: when `esp_migration_stalled` fires again and
the budget is gone, the path thread calls `mark_dead("the child SA did not survive the address update (N rekeys did
not restore ESP)")`. Deciding it at the moment the budget runs out instead would kill a tunnel whose ESP had come back
in the meantime, and — after a completed rekey — before the repair had any chance to show.

### 17.4 The grace period

Nothing transient goes through `mark_dead`: it closes the inner stack irreversibly, and there is no reopen path, so a
30-second Wi-Fi blip must not cost the SIP registration. Every impairment instead runs the one clock of §17.1 and the
tunnel is declared dead only after `NO_ROUTE_GRACE`, with a reason that says which impairment it was:

- `"no route to the gateway for 30s"`
- `"cannot bind a socket on the new egress address for 30s"`
- `"the gateway has not acknowledged our new address for 30s"`
- `"the outer socket has been unusable for 30s"`
- `"address update rejected: …"` (the gateway's own answer — a rejection notify, or a response that does not decode
  or does not authenticate; a gateway that refuses the move will refuse the retry)

`address_update_failure` therefore lists its fatal cases **explicitly** (`Error::PeerNotify`, `Error::Decode`,
`Error::Integrity`) and treats everything else as transient. Two shapes matter:

- Retransmission exhaustion is **not** fatal: a gateway that stays silent for one 15.5 s schedule (a new AP whose
  uplink is not usable yet) is the dominant announce failure and exactly what the retry machinery is for, so the
  announce is retried from the socket already rebound until the grace expires with `"the gateway has not acknowledged
  our new address for 30s"`. Otherwise the effective handover tolerance would be the retransmit schedule, not the
  advertised `NO_ROUTE_GRACE`.
- A **local send failure** is not fatal either, whatever its errno. A catch-all used to make every non-path
  `Error::Io` a rejection, so one `ENOBUFS` (errno 55, an `Uncategorized` kind `is_path_error` does not know) or one
  `EPERM` from a host firewall on the first datagram out of a brand-new interface killed the tunnel during exactly the
  handover this section exists for. `PathState::note_send_error` already treats such an error as saying nothing about
  the socket; the classifier now agrees.

The grace is evaluated at the top of a tick, and a tick cannot run while the path thread is inside a blocking
exchange. The announce is one: it waits for `request_lock` and then runs its own schedule, so death lands **after** the
nominal deadline, by the sum of

- however long `request_lock` is held by whatever was already outstanding: up to one 15.5 s schedule for a single
  exchange, and up to ~31 s for a lifetime or escalation rekey, which holds the lock across **both** of its exchanges;
- the announce's own schedule, up to a further 15.5 s;
- one `PATH_PROBE_INTERVAL`.

So the worst case is `NO_ROUTE_GRACE` + ~48.5 s (31 + 15.5 + 2), not + 15.5 s. That is deliberate. `NO_ROUTE_GRACE` is the instant from
which tearing the registration down is *allowed*, not a promise to tear it down to the millisecond, and buying
punctuality with a cutoff would mean abandoning the very `UPDATE_SA_ADDRESSES` the outage needs — which is what the
previous design did, at the cost of an abandoned message id and everything that had to be built to make one safe. Only
the pure `PathMonitor` bound is unit-tested; the composed one is reasoned about here.

**No local address change abandons an in-flight request.** §17.2's rebind moves the request's remaining
retransmissions to the new socket, and the request runs to its own conclusion there — a teardown and an exhausted
schedule are the only things that end one early. What a move changes is only how that conclusion is *read*, and that is
one pure function:

```
request_verdict(error, path_unsettled) -> Answered | GatewayGone | Transient
```

`GatewayGone` is `Error::Timeout` over a **settled** path — exhausted retransmissions while the gateway knew where we
were — and nothing else. Everything else is `Transient`: a send the host refused whatever its errno, a teardown, a
response we could not use, and a timeout taken over a path that was not settled.

"Settled" is the pair of monotonic counters `PathState::moves` / `PathState::announced`: the path thread bumps `moves`
the instant it rebinds and, when the announce is acknowledged, stores that value into `announced`. `settle_sample()`
returns `Some(moves)` while the two agree and `None` while a repair is outstanding; `unsettled_since(sample)` is true
for a `None` sample or for any move since. Counters rather than a flag precisely because they cannot be left stuck the
way a "suspended" flag could, and because they are read only to classify an outcome, never to cancel anything.

Both halves of that predicate are load-bearing, and the second one was learned the hard way. A move *during* the
request is not the only case the gateway cannot answer: a probe that runs entirely **between** the rebind and the
announce never straddles a move at all, yet the gateway has not been told where its datagrams come from. Reading its
silence as a dead gateway killed the tunnel ~16 s into an outage whose advertised tolerance is 30 s — the "new AP whose
uplink is not usable yet" case above, arriving through the liveness probes instead of through the announce. The
bracket is also deliberately a little wider than the request itself (the sample is taken before `request_lock`, so a
rebind while the caller is still queued counts): erring this way can only delay a death, never invent one.

Every site that could `mark_dead` over a request goes through it: the bundle DPD, both liveness probes of §17.5,
`EpdgTunnel::dpd()`, both lifetime rekeys and §17.3's escalation. Death over an impaired *path*, as opposed to an
answered-and-refused move, remains `NO_ROUTE_GRACE`'s job alone.

One residual is worth naming rather than papering over. Because `GatewayGone` is the only fatal verdict a request can
produce, a DPD or probe error that is **not** a settled-path timeout is never fatal — the bundle DPD used to tear the
tunnel down on any error at all. What catches such an error instead is the path monitor: `note_path_error` asks for an
out-of-band probe, and a route that is really gone starts the grace clock, while a socket whose sends keep failing
trips §17.1's wedge rule. The gap that leaves is a send that fails **persistently with an errno `is_path_error` does
not recognise** (an `EPERM` from a local filter): `note_send_error` deliberately ignores those, so neither the grace
nor the wedge rule starts, and the tunnel stays alive with nothing moving. That is the same gap an operator bundle
with `dpd.enabled = false` has always had; closing it needs a failure budget that does not exist yet.

`close()` is the one thing that abandons a request *early*: `closing_abort` fires within one 200 ms slice for every
post-establishment request, so shutdown never waits out a retransmit schedule behind `request_lock`. Its own
DELETE(IKE) is sent through `ike_request_while_closing`, the single caller that opts out. The timer's DPD retry sleep
gives way to `closing` too, and a probe a close abandoned returns `Error::Closed`, which is `Transient`, so neither the
timer nor `EpdgTunnel::dpd()` can relabel a deliberate close as a gateway failure. `rekey_child` / `rekey_ike` hold
`request_lock` across *both* of their exchanges, so an announce cannot interleave between them.

### 17.5 The one-way traffic probe

`last_rx`/`idle_for()` are touched by inbound NAT-T keepalives, so they never grow while the gateway is echoing. The
path state therefore keeps its own clocks, with keepalives excluded from the traffic ones at both ends:
`first_tx_since_rx` (the **first** IKE/ESP transmission since the last inbound IKE/ESP datagram, cleared by
`note_rx_data`), `last_rx_data`, `sends_failing_since`, and the ESP-only pair `last_esp_tx` / `last_esp_rx` that
§17.3 reads.

All three inbound clocks count only datagrams that **authenticated**: they are stamped inside `handle_esp` after
`EspInbound::decapsulate` has verified the ICV and passed the replay window, and inside `handle_ike_datagram` after
`IkeInitiator::decode` has opened the SK payload — never in `rx_loop` before the check. A gateway emitting ESP under an
SPI we no longer hold (a gateway-side restart on the same 5-tuple, a child rekey we did not apply) would otherwise
clear `first_tx_since_rx` and refresh `last_rx_data` / `last_esp_rx` on every such datagram: the one-way probe could
never arm, the idle probe would never fire, and the ESP-migration escalation would stay disarmed, so a tunnel carrying
nothing but garbage would report itself alive forever. (`last_rx`/`idle_for()` are deliberately left where they are:
that clock is the NAT-T-inclusive "anything at all arrived" one.)

The silence window is measured from `first_tx_since_rx`, and that is load-bearing: a client retransmitting into a black
hole moves its latest transmission forward every few hundred milliseconds, so anchoring the window there would hold it at zero and
the probe would never become due — which is precisely the case this check exists for (a child SA that is one-way from
the start, where `last_rx_data` is `None` forever). Once `ONE_WAY_PROBE_SILENCE` has passed since that first
transmission, the timer thread runs **one** DPD with the normal retransmit policy, regardless of `cfg.ike.dpd.enabled`.
Exhaustion is `mark_dead("gateway stopped answering")` — unless the path was unsettled (a repair the gateway has not
acknowledged yet, whether it started before the probe or under it), in which case `request_verdict` (§17.4) calls it
transient, because the silence may be ours. It does not re-fire without new one-way evidence: any inbound IKE/ESP (a successful probe's response
included) clears `first_tx_since_rx`, and the previous probe must in any case be `ONE_WAY_PROBE_SILENCE` old.

The evidence has to be a *real* transmission. `send_raw` deliberately swallows a `WouldBlock`/`TimedOut` from
`send_to` (a host firewall holding the flow pending a verdict) rather than breaking the retransmit schedule off on a
local verdict, so it reports which of the two happened: `Ok(true)` took the datagram, `Ok(false)` dropped it, and only
`true` reaches `note_data_tx` / `note_esp_tx`. Arming the window with a datagram that never left the host made the
probe fire over sends the kernel never made and `mark_dead("gateway stopped answering")` land ~37 s into a filter hold
that `NO_ROUTE_GRACE` was supposed to be the only authority over.

`sends_failing_since` — the wedge rule's only input — is started **only** by a send that failed with a path-kind error
(`is_path_failure`), and by any such send: the ESP sink, an IKE request *and* the NAT-T keepalive, which on an idle
registered tunnel is the only outbound traffic there is and therefore the only thing that can notice a socket that can
no longer send at all. An unrelated failure (ENOBUFS, a short write) must not start it: it would have an otherwise
healthy idle tunnel rebind and re-announce 30 s later for nothing. A successful send of any kind clears it, and a
keepalive clears it *without* touching `first_tx_since_rx`, so it never counts as one-way evidence.

The one-way probe needs evidence that we transmitted, which a **registered but idle** tunnel never produces — and with
the bundle's DPD disabled that left such a tunnel with no liveness check at all: the gateway could drop the SA and
nothing would notice until the next outgoing request, minutes or hours later. So the same block runs a second trigger,
`idle_probe_due`: nothing received from the gateway (IKE/ESP, keepalives excluded) for `IDLE_PROBE_SILENCE`, anchored
at establishment for a tunnel that has never received anything, and re-armed by our own probe so an unanswered but
non-fatal probe does not re-fire every tick. It is the same DPD with the same consequences. The bundle-driven idle DPD
is unchanged, except that it classifies every outcome through `request_verdict` too, so a refused send, a probe a
`close()` abandoned and a timeout across a rebind are all transient rather than a dead peer.

### 17.6 Death propagation to the SIP transport

One chain, and it must be prompt end to end:

```
mark_dead(reason)
  → dead_reason = reason        (stored FIRST: a thread woken by the next line asks for it immediately)
  → InnerStack::close(reason)   (none of the first three steps takes the stack's poll mutex)
       → StackShared::closed = reason
       → every registered DNS slot completed with Error::Closed(reason)  (its condvar wakes at once)
       → every UDP sender dropped
          → a blocked InnerUdpSocket::recv_timeout returns RecvTimeoutError::Disconnected AT ONCE
            (not at its own timeout) → Error::Closed(reason)
       → the TCP event counter moved (§11.2)
          → a TCP read / write / accept / connect parked on it re-reads `closed` AT ONCE → Error::Closed(reason)
       → State::shutdown  (cancels the smoltcp queries / sockets; may wait for the poll in progress)
  → netstack::to_io → io::ErrorKind::NotConnected, the reason still in the error's Display
  → CustomUdpConnection::serve_loop logs it and returns Ok(())
  → TransportLayer::serve_connection emits TransportEvent::Closed
```

Afterwards `InnerUdpSocket::send_to`, `InnerStack::bind_udp` / `resolve` / `connect_tcp` / `listen_tcp`, every call on an
`InnerTcpStream` / `InnerTcpListener` (but `shutdown`, which stays `Ok`) and `EpdgTunnel::bind_udp` / `resolve` /
`connect_tcp` / `listen_tcp` all fail with the same `Error::Closed(reason)`; `push_rx` is a no-op. The sender-drop wake-up is load-bearing: any
refactor that keeps a clone of a binding's `SyncSender` alive (stashing it for stats, say) silently turns an immediate
close into one that waits out the caller's timeout.

The reason and the wake-ups live **outside** the stack's `State` mutex (`StackShared::closed` and
`StackShared::wakers`) for a second load-bearing reason: the stack thread holds `State` across a whole `poll`, and a
poll drives the TX sink — a blocking outer ESP send, up to the socket's write timeout *per packet*. A close that had to
take that mutex first could not publish the death, let alone wake a parked receiver, for seconds. `recv_timeout` reads
the reason from the same place, so it never blocks behind the poll either — and so does a parked TCP call, which is why
those park on their own counter (`StackShared::tcp_events`) rather than on a condvar tied to `state` (§11.2).

That hold is bounded at both ends, because everything else on the stack — `push_rx` (the thread that also delivers IKE
responses, so a long hold eats into the 15.5 s retransmit budget of an outstanding DPD or address update), `bind_udp`,
`send_to`, and `close`'s own smoltcp cleanup — waits on it:

- the write timeout is `OUTER_SEND_TIMEOUT` (250 ms, not the socket default and not a multi-second value), so one
  datagram held by a host firewall pending a verdict costs a quarter of a second, well inside the first retransmit
  interval; `send_raw` counts such a datagram as lost and the schedule covers it;
- the stack thread **releases `State` between immediate re-polls**. `poll_delay == 0` makes it re-poll at once, up to
  `MAX_IMMEDIATE_POLLS` (64) times, and it used to `continue` while still holding the guard — so the per-poll holds
  could stack into one uninterrupted multi-second hold. It now drops the guard, yields and re-acquires.

`InnerStack::close` publishes the reason *before* it sets `stop`. The other order is a race: the stack thread wakes on
`stop`, leaves its loop and closes with its own generic reason, which would replace the tunnel's real dead reason in
the error every inner socket returns and in the SIP transport's exit log. It is idempotent and the first reason wins.

`mark_dead` is idempotent (an atomic swap guards it) and the **first** reason wins, so a tunnel that died of a real
failure keeps that reason when `close()` / `Drop` runs afterwards. A deliberate close goes through the same path with
the reason `"tunnel closed by request"` — that string is the only thing distinguishing it downstack, since the SIP
layer reconnects on any `Closed`. `close()` also sets `Shared::closing` (not `stop`) *before* its DELETE(IKE), which
releases the path thread and any in-flight address update at once; `stop` cannot be used there because the rx thread
must stay alive to deliver the DELETE's response.

On the SIP side (`rsipstack` `transport/custom_udp.rs`): `NotConnected` from `recv_timeout` ends `serve_loop` and logs
the tunnel's dead reason; every other receive error is transient — logged, backed off 50 ms, retried, so a
persistently failing socket cannot spin the loop. `send_to` cannot report liveness (its `io::ErrorKind` is flattened
into `TransportLayerError`'s string), so a `NotConnected` there is logged and returned to the caller and nothing else:
the same tunnel death has already failed the concurrent `recv_timeout` — immediately, per the chain above — so the loop
is already ending, and `TransportEvent::Closed` keeps coming from exactly one place, the loop's exit. (A private
cancellation token for the send path would only pre-empt a poll the receive side is about to fail anyway, and could
truncate the buffered-datagram drain noted in §17.8.) The connection keeps
reporting `Transport::Udp` and `is_reliable() == false`, so retransmission stays the transaction layer's job.

In the embedder (`rustpush/src/ims.rs`, out of scope for this crate) the event reaches `take_down_closed_connection`,
which treats the tunnel's `CustomUdp` connection like a dropped TCP/TLS flow: it is removed from the transport layer,
every pending transaction is ended (a client one with a synthesized 503), and `reconnect()` asks the line's connector
for a new connection — which replaces the dead tunnel with a fresh `EpdgTunnel::connect` — then moves the media sockets'
network and the SIP TCP listener (§11.2) onto it and re-registers. The SIP TCP connections of §11.2 die with the tunnel
as well; the embedder ignores their `Closed` events (rsipstack forgets each closed one itself), so the UDP socket's
death is the one signal that rebuilds the line.

### 17.7 Tunables

All `pub const` in `epdg::tunnel`, not config fields: the config structs are built with exhaustive struct literals by
embedders, so a new field there is a breaking change.

| const | default | why |
|---|---|---|
| `PATH_PROBE_INTERVAL` | 2 s | a handover is announced long before the SIP registration expires; a bind+connect probe is cheap enough to run for the tunnel's life |
| `PATH_PROBE_MIN_SPACING` | 250 ms | floor for out-of-band probe requests; a downed interface fails thousands of sends per second. `network_changed()` bypasses it |
| `NO_ROUTE_GRACE` | 30 s | survives a screen-off Wi-Fi blip without tearing down the registration. Comfortably longer than the 15.5 s retransmit schedule, which is what makes "the announce simply waits for `request_lock`" affordable (§17.2) |
| `ONE_WAY_PROBE_SILENCE` | 20 s | one-way-traffic threshold, and the ESP-stall threshold of §17.3 |
| `IDLE_PROBE_SILENCE` | 120 s | the same probe for a tunnel that never transmits, which is the only liveness check an idle registration has when the bundle disables DPD |
| `MIN_ADDRESS_UPDATE_INTERVAL` | 5 s | flap damping: a move within this window of the previous one waits it out — a move to a new address *and* the rebind that recovers from an impairment on the address we are already bound to (§17.1), which is the other half of a flap. The first move after a quiet period passes immediately, so a handover is never delayed |
| `ESP_SEND_ERROR_LOG_INTERVAL` | 5 s | the ESP sink logs per datagram; the keepalive and IKE-request error sites are rare enough to log unconditionally |
| `PROBE_ERROR_LOG_INTERVAL` | 60 s | a probe that cannot *run* (EMFILE, a sandbox/MDM EPERM on the throwaway socket) is usually permanent and deliberately never impairs the tunnel, so the warning would otherwise repeat every `PATH_PROBE_INTERVAL` for the life of the registration |
| `ESP_MIGRATION_REKEY_ATTEMPTS` | 2 | child rekeys per move for the non-MOBIKE ESP escalation (§17.3) before `mark_dead`. `N(TEMPORARY_FAILURE)` is worth one retry; a child SA still black-holed after that is invisible to every liveness check, so it must end in death. An attempt is spent unless the failure proves nothing (a broken route, a crossing teardown, silence over a path still being repaired); a completed rekey spends one, since completing is not the same as repairing, and so does a deterministic local refusal, which would otherwise re-arm forever |
| `OUTER_SEND_TIMEOUT` (`epdg::ike::transport`) | 250 ms | write timeout on every outer socket. The ESP sink runs the send synchronously under the inner stack's `state` mutex (§17.6), so it caps how long one held datagram stalls the stack; it is well inside the 500 ms first retransmit interval |

### 17.8 Known limits

- The old socket is kept alive across the announce but **not read from**: ESP the gateway sends to the old port during
  the move is lost. IKE retransmission covers the only traffic that must not be — the announce itself, and any request
  that was already outstanding, whose retransmissions moved to the new socket with it (§17.2).
- The announce waits for whatever exchange is already outstanding to settle, so a move that lands on top of a rekey
  (two exchanges, up to ~31 s) is announced that much later. Bounded by `close()`'s abort and by the grace, which
  keeps running throughout.
- Death inherits that wait. The grace is evaluated at the top of a tick and a tick cannot run while the path thread is
  blocked in `announce()`, so death lands at `NO_ROUTE_GRACE` + the lock wait (up to ~31 s behind a rekey) + the
  announce's own schedule (up to 15.5 s) + one `PATH_PROBE_INTERVAL` — ~48.5 s of overshoot in the worst case
  (31 + 15.5 + 2), not 15.5 s (§17.4). Only the pure `PathMonitor` deadline is unit-tested.
- An announce that lands on a message id an abandoned request already **transmitted** costs one extra round trip: its
  response is refused unconditionally (§17.2), because a gateway that processed the abandoned request is obliged to
  replay its cached answer instead of processing this one, and the two are indistinguishable. An id no datagram ever
  left the host on is not flagged, so it costs nothing. The refusal spends the id, so the
  retry — the next tick's, at most `PATH_PROBE_INTERVAL` later — runs clean.
- Every liveness signal runs over the IKE SA, so a black-holed child SA under a working IKE SA is invisible to all of
  them. The §17.3 escalation is the only thing that sees it, and only on a non-MOBIKE peer after a move it observed:
  it ends in `mark_dead` once `ESP_MIGRATION_REKEY_ATTEMPTS` rekeys have failed, but a child SA that stops carrying
  traffic for any other reason still leaves the SIP layer with a transport that carries no media.
- `IkeTransport::recv` still drops datagrams whose source is not the gateway. They are counted
  (`TunnelStats::stray_sources`) and logged at most once per 5 s: a gateway that moves itself must not flood the log,
  and a host that can spoof a datagram to our port must not be able to kill the tunnel.
- A responder-initiated address change is not implemented (RFC 4555 lets only the initiator move); peer address lists
  are logged and ignored.
- A family change (the only IPv4 route disappears, leaving IPv6) is not a MOBIKE move: it ends as `NoRoute` → grace →
  dead, and the caller reconnects.
- An IPv6 privacy address that rotates looks exactly like a move and is announced as one; the flap damping bounds how
  often that can happen.
- `NetStack::local_addrs()` still answers on a dead tunnel (the inner addresses it was assigned).
- Up to `UDP_QUEUE_DEPTH` (256) datagrams already buffered in a binding's channel are drained before the receiver
  observes the close, so the very next `recv_timeout` after `mark_dead` is not necessarily the one that reports it.

### 17.9 Forcing a move (`EpdgTunnel::force_address_update`)

Everything above only runs when the host's egress address actually changes, which on a developer machine means
toggling Wi-Fi — not something a test can do, and not something the live run against T-Mobile PROD could ever cover.
`EpdgTunnel::force_address_update()` is the diagnostic knob that closes that gap: it sets one flag, `PathInner::forced_move`,
and forces a probe. The next `PathMonitor::tick` latches the flag and, as soon as the probe reports an egress address,
returns `Rebind(ip)` — normally the address we are already bound to, so only the ephemeral port moves. From there it is
the production path, byte for byte: `IkeTransport::rebind`, `rebound()`, then `announce()` with
`N(UPDATE_SA_ADDRESSES)` + NAT-D hashed over the **new** source port (§17.2) or the §17.3 fallback, the immediate
keepalive, and `TunnelStats::address_updates` += 1. There is no separate rebind-and-announce routine to drift out of
step with the real one. RFC 4555 §3.5 lets the initiator move whenever it likes; from the gateway's side a new source
port on the same address is an ordinary NAT rebinding, which it has to survive anyway.

The flag is latched by the monitor rather than consumed by the tick that saw it, so a request made while there is no
route survives until the route comes back; `rebound()` clears it, so one request produces exactly one move. It is
latched with the instant it arrived and dropped again after `NO_ROUTE_GRACE`, because there is a third case besides
"the route came back" and "the grace period ended the tunnel": a host whose route probe itself cannot run (EMFILE, a
sandbox EPERM on the throwaway socket) reports `Unknown` forever, which by design neither impairs the tunnel nor lets
the forced branch act. Without the expiry that request would sit armed for the life of the tunnel and fire a real,
unrequested `UPDATE_SA_ADDRESSES` at the first probe that happened to succeed, hours after the caller gave up on it.
Every rule of §17 above it still applies — the grace verdict first, then "no route means no move", then an announce
that has not been acknowledged yet, which finishes before a second socket is bound. So does everything around it:
`close()` cancels the pending request, and an IKE exchange that is already outstanding settles before the announce goes
out, because the announce takes `request_lock` like every other post-establishment request. The one rule it
deliberately bypasses is `MIN_ADDRESS_UPDATE_INTERVAL`: that damping exists for a route that flaps on its own, and a
caller-driven one-shot must not be silently dropped because the tunnel happened to move a moment ago.

Running through the production path also means inheriting its consequences, which is the point but is worth stating
plainly: `rebound()` starts the "the gateway has not acknowledged our new address" clock, so from the moment the socket
moves a previously healthy tunnel is impaired until the announce is answered. A gateway that stays silent is retried
until `NO_ROUTE_GRACE` expires and then the tunnel is declared dead; one that answers with an error notify kills it at
once (§17.2); against a non-MOBIKE peer the §17.3 escalation applies. That is exactly what a real handover risks, so it
is the right behaviour for a knob whose job is to rehearse one — but do not call `force_address_update()` on a
registration you are not prepared to lose.

`epdg-connect --rebind-after SECS` drives it that far into `--hold` and prints one machine-checkable line per fact —
`ADDRESS-UPDATE old=<ip:port> new=<ip:port> updates=<n> ok`, `POST-MOVE DPD rtt=<ms>` and `POST-MOVE ESP rx delta=<n>`
(ESP received *after* the update, from a DNS resolve over the tunnel: proof that the gateway moved the child SA's
destination port too, which is the half a NAT rebinding can break). It exits non-zero if the update did not happen,
the port did not change, DPD failed or the ESP delta is zero, and says why on an `ADDRESS-UPDATE-FAILED <reason>` line
— a prefix of its own, because the move can land and a post-move check still fail, and neither marker may ever be
mistaken for the other. `tests/live_tmobile.rs::live_tmobile_address_update` parses those three lines (and rejects a
duplicate marker). The pure `tick` logic is unit-tested on its own (`a_forced_move_*`).

## 15. Amendment log
- 2026-11-03 (§11.2 added — inner TCP): `InnerStack::connect_tcp` / `listen_tcp` with `InnerTcpStream` / `InnerTcpListener`
  (blocking adapters over smoltcp TCP sockets in the stack's `SocketSet`, parked on a TCP event counter outside `state` so a
  close wakes them at once, §17.6), `EpdgTunnel::connect_tcp` / `listen_tcp`, and both `NetStack` impls now real for TCP
  (`TUNNEL_TCP_UNSUPPORTED` and the `Unsupported` path are gone). Listener = a 2-socket backlog refilled on accept; a reaper
  frees dropped streams after their close handshake (RST after 60 s). Two packet-path additions it needed: the device clamps
  the MSS of every TCP SYN, both directions, to the wire MTU (smoltcp sized TCP segments from the 16 KB stack MTU of §11.1,
  so every full IPv4 segment exceeded its own 8 KiB reassembly buffer), and `push_rx` drops a retransmitted SYN for a
  connection already held (smoltcp's first-match socket dispatch would otherwise let a spare listening slot answer it).
  `StackStats` gained seven `tcp_*` counters and `DeviceStats` `tcp_mss_clamped` (additive; both remain `Copy + Default`).
  `epdg-connect --tcp-probe` (used by `live_tmobile_tunnel`, reported only). The §0 "not implemented: inner TCP" is struck.
  Review: §11.2 now states smoltcp's missing retransmission give-up and challenge ACK (callers bound idle/dead streams;
  the SIP transport closes one nothing arrived on for five minutes); §17.6's account of the embedder brought up to date.
- 2026-09-15 (round-7 review of the rewrite below — no new mechanisms, seven behaviour fixes): (a)
  `abort_request(transmitted)`: a request whose send the host refused put nothing on the wire, yet its id was flagged
  as abandoned, so the retry on that id refused the gateway's *genuine* answer — a wasted exchange, an orphaned child
  SA behind a rekey, and one of the two `ESP_MIGRATION_REKEY_ATTEMPTS` spent on our own bookkeeping (§17.2). (b)
  `send_raw` now reports whether the kernel took the datagram; a held send no longer arms the one-way probe, which was
  calling `mark_dead("gateway stopped answering")` ~37 s into a local filter hold with nothing ever having left the
  host (§17.5). (c) The old IKE SA is dropped whether or not its DELETE is acknowledged (`forget_old_ike`): a wedged
  `old_ike` sent `close()`'s DELETE to a dead SA while the live one stayed up on the gateway, and blocked every future
  IKE rekey (§14). (d) The five tunnel threads unwind if one spawn fails, instead of leaking the started ones, the
  outer socket and the inner stack for the life of the process (§12). (e) `ike_request_locked` brackets build **and**
  encode, so an encode failure no longer leaves the session's request slot set for good (§17.2). (f) The wedge rule is
  evaluated before the `Unknown` probe shortcut, so a host that can never probe while every send fails has a route to
  death again (§17.1). (g) Doc corrections: `installed` only refines non-fatal escalation outcomes (§17.3), an attempt
  is spent unless the failure proves nothing (§17.7), the grace overshoot is ~48.5 s not ~46.5 s (§17.4/§17.8), and
  `tunnel.rs`'s death-reason list names the peer child DELETE, the rejected address update and the escalation death.
- 2026-09-15 (§17.2/§17.4 rewritten — a move never interrupts a request): the first §17 landed with a mechanism for
  *cancelling* an exchange the path had moved under (a `suspended` flag, a `path_abort` predicate on every request, an
  abandoned-message-id record, a reused-id refusal in three response handlers, and a spend-DPD with its own attempt
  budget to avoid needing that refusal). All of it existed to repair damage the cancellation itself caused. Since
  `IkeTransport` re-reads its socket per send, the request does not need cancelling: its remaining retransmissions
  leave the new socket unchanged, the gateway answers the source it hears, and the window stays in step. So
  `abort_unsent_request`, `next_msgid_is_abandoned`, the three per-exchange `reused_msgid` fields,
  `PathState::suspended`, `path_abort`, the `Abort` predicate type, `announce`'s grace deadline and spend block,
  `SPEND_MSGID_ATTEMPTS` and `rekey_failure_is_fatal` are all gone. What replaces them is one pure classifier,
  `request_verdict(error, path_unsettled)` (§17.4), fed by the monotonic `PathState::moves` / `announced` pair; the
  announce simply takes `request_lock` when it is free, and `NO_ROUTE_GRACE` remains the single authority for death.
  `close()`'s DELETE(IKE) is the one request that opts out of the closing abort (`ike_request_while_closing`).
- 2026-09-15 (corrections to the rewrite above, from the round-6 review): three of its claims did not survive contact
  with the code. (a) "No message id is ever abandoned" was false — a move never abandons one, but an exhausted
  retransmit schedule does, and §17.4 deliberately makes that *survivable*, so the announce or a rekey can be built on
  an id whose cached response the gateway is obliged to replay. `IkeInitiator::abandoned_msgid` is back, as **one**
  field with **one** unconditional check in `accept_response` for the exchanges that commit on a bare acknowledgement
  (§17.2), rather than the three per-exchange flags it replaced. (b) `request_verdict`'s input was "a move landed
  during this request", which left a probe that ran entirely between the rebind and the announce reading a silent
  gateway as a dead one, ~16 s into a 30 s grace; it is now "the path was not settled", from the `moves` / `announced`
  pair. (c) `escalation_outcome`'s catch-all had been inverted to `Abandoned`, which let a deterministic rekey failure
  re-arm forever with no attempt spent and no path to `ESP_MIGRATION_REKEY_ATTEMPTS`; `Failed` is the catch-all again
  and `Abandoned` is the enumerated narrow set (§17.3). The grace-overshoot bound in §17.4/§17.8 was also understated
  by a factor of three.
- 2026-09-15: §17 added — mobility and liveness: the `epdg-path` monitor (route probe, rebind, no-route grace),
  MOBIKE `UPDATE_SA_ADDRESSES` with the RFC 7296 §2.23 fallback, the one-way-traffic probe, and the death chain down
  to `TransportEvent::Closed`. §0/§7/§12 amended accordingly. Signature changes it required:
  `nat::request_notifies(spi_i, spi_r, local, remote, force_udp_encap)` and
  `nat::evaluate(what, spi_i, spi_r, local, remote, notifies, force_local_nat)` (the NAT-D hashes of a post-SA_INIT
  exchange must use the real SPIr); `NatStatus` gained `supported` ("the responder answered our NAT-D"), which is what
  gates the NAT-D pair in an address update (§17.2); `IkeTransport::socket()` was removed (it had no caller, and the
  `RwLock<Bound>` refactor left its signature meaningless — `rebind()` is what hands out a socket handle now).
  `InnerStack::close` publishes the reason before setting `stop` (§17.6), which also fixes a pre-existing race in
  which a caller's close reason could be replaced by `"inner stack stopped"`. `Error::PeerNotify` is now
  documented to carry RFC 4555's status-range rejection `NO_NATS_ALLOWED` (16402) as well as true error notifies —
  its other two rejections, `UNACCEPTABLE_ADDRESSES` (40) and `UNEXPECTED_NAT_DETECTION` (41), are ordinary error
  types and need no special case. Ten
  `pub const` tunables were added to `tunnel` (and one, `OUTER_SEND_TIMEOUT`, to `ike::transport`) rather than to the
  config structs (§17.7), which embedders build with exhaustive literals. `EpdgTunnel::nat()` was added: `TunnelInfo`
  is an establishment-time snapshot and a MOBIKE address update re-runs NAT detection, so `info().nat` goes stale
  exactly when the verdict matters most.
- 2026-09-11: §16 added — `NetStack` (UDP + TCP + DNS) with std (libc resolver, real TCP) and tunnel (UDP/DNS; TCP unsupported for now) implementations.
- 2026-09-11 (§11.1 implemented + §11 verifier fixes): (a) §11.1 lives in `ipstack/frag.rs`, applied inside `EspDevice` (TX) and
  `InnerStack::push_rx` (RX); `child.inner_mtu_stack` (default 16384) added to `ChildConfig`; DF is not honoured on TX (smoltcp
  sets it unconditionally) — see §11.1. (b) `auto-icmp-echo-reply` added to the smoltcp features (echo requests were ignored).
  (c) The stack loop ingests packet by packet (`poll_ingress_single` + drain) so a burst larger than smoltcp's 32-slot UDP socket
  buffer is no longer lost uncounted. (d) `InnerUdpSocket::drop` flushes queued datagrams before removing the socket
  (`udp_tx_drops` counts leftovers); `udp_send_full` counts refused sends. (e) A DNS `Failed` after smoltcp's 10 s x servers
  give-up is `Error::Timeout`. (f) `InnerUdpSocket` is `Send + Sync`. (g) `InnerStack::spawn` guards against panics.
  (h) Non-unicast assigned DNS servers are skipped. (i) §11 route note corrected: default routes are required, only the next hop
  is nominal. (j) §13 unit-test list and the §1 module table now describe the smoltcp stack; the live test does not assert a
  P-CSCF attribute.
- 2026-09-11: §11.1 — IP fragmentation shim around the smoltcp device (smoltcp 0.14 lacks IPv6 frag/reassembly on Medium::Ip).
- 2026-09-11 (§11 implemented, deviations): (a) smoltcp 0.14 has no IPv6 fragmentation/reassembly on `Medium::Ip` — §11's
  "IPv6 larger than the MTU is fragmented / inbound IPv6 fragments are reassembled" is false for 0.14; `send_to` refuses oversize
  IPv6 payloads instead (IPv4 fragments/reassembles as specified). (b) `InnerUdpSocket` / `UdpDatagram` live in `ipstack::stack`
  and are re-exported from `tunnel` (same public paths `epdg::InnerUdpSocket`, `epdg::tunnel::InnerUdpSocket`). (c) `resolve`
  starts the AAAA and A queries together (one per family we have an address for) and returns AAAA answers first; a family whose
  query fails is skipped, `Error::Timeout` only when nothing answered, `Error::Protocol` when every query failed. (d) smoltcp's
  compile-time limits are raised via Cargo features (see §11); `child.inner_mtu` (default 1280, bundle-independent) added to §2's
  `ChildConfig`. (e) `TunnelStats` gains `stack: StackStats` (device queue drops, UDP delivery/drops, DNS queries).
- 2026-09-11: §11 rewritten — inner IP stack is smoltcp (Medium::Ip Device over ESP); hand-rolled ipstack + DNS codec removed; `EpdgTunnel::resolve` added.
- 2026-09-11: §9.3 — ePDG EAP-TLS server requires TLS_RSA_WITH_AES_128_CBC_SHA; EAP-TLS moved from rustls to OpenSSL (no pluggable backend).
- 2026-09-11: retransmit corrected to 5 sends; §14.1 KAT layouts added from the critic pass (docs/AOSP_FACTS_CRITIC.md).
- 2026-09-11: §2/§6/§8/§9/§12 patched from the AOSP extraction (fake NAT source, transform/payload/CP order, TLS 1.2-only, IDr-from-first-response).
