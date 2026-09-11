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
- ESP tunnel mode over UDP/4500, anti-replay, NAT-T keepalive, inner IPv4/IPv6+UDP stack,
  a tiny DNS client for the live test.
- Config: carrier-bundle plist model (`Config::from_plist_bundle`).

Not implemented: responder role, PSK/cert auth, EAP-AKA, MOBIKE address updates (we only
announce `MOBIKE_SUPPORTED` if configured), IPComp, transport mode, ESN, 3GPP notifies
(constants present), inner TCP.

## 1. Module ownership

| File | Owner | Public surface |
|---|---|---|
| `src/config.rs` | agent:config | §2 |
| `src/crypto/{aes_cbc,hmac_sha2,dh_modp,registry}.rs` | agent:crypto | §3 (traits already in `crypto/mod.rs`) |
| `src/ike/{header,payload}.rs` | agent:codec | §4.1–4.2 |
| `src/ike/{message,fragment}.rs` | agent:message | §4.3–4.4 |
| `src/ike/{keys,auth,nat}.rs` | agent:keys | §5, §6 |
| `src/ike/transport.rs` | agent:transport | §7 |
| `src/ike/session.rs` | agent:session | §8 |
| `src/eap/{packet,tls}.rs` | agent:eap | §9 |
| `src/esp/{codec,replay}.rs` | agent:esp | §10 |
| `src/ipstack/{device,frag,stack}.rs` | agent:ipstack | §11, §11.1 |
| `src/tunnel.rs` + `tests/live_tmobile.rs` | agent:tunnel | §12, §13 |

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
pub struct EapTlsCredentials {
    pub client_cert_pem: String,       // may contain a chain (leaf first)
    pub client_key_pem: String,        // PKCS#8 or PKCS#1/SEC1
    pub server_ca_pem: Option<String>, // bundle ePdgCACert, if any
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
pub struct ImsConfig { pub pcscf_address: String, pub apn: String, pub impu: String, pub sip_realm: String, pub username: String, pub password: String, pub imsi: String, pub token: Option<String> }

impl Config {
    /// Build from the decoded carrier bundle (root dict with imsCommonCredentials/CBRoot),
    /// the individual-credentials dict (imsIndividualCredentials/subscriberId/...), and PEMs.
    pub fn from_plist_bundle(bundle: &plist::Value, creds: &plist::Value, client_cert_pem: &str, client_key_pem: &str) -> Result<Config>;
    pub fn from_plist_files(bundle: &Path, creds: &Path, cert: &Path, key: &Path) -> Result<Config>;
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
- `ims.*` from `imsIndividualCredentials` + top-level `token`; carried for the SIP layer, unused here.

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
One `UdpSocket` for the whole tunnel life (IKE and ESP multiplexed, RFC 3948). Bound to an ephemeral port on
`gateway.local_addr` or the discovered egress. Destination port starts at 500; `switch_to_natt()` moves it to 4500
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
    pub fn send_ike(&self, datagram: &[u8]) -> Result<()>;  // adds marker if using_natt
    pub fn send_esp(&self, esp: &[u8]) -> Result<()>;       // raw, must be using_natt
    pub fn send_keepalive(&self) -> Result<()>;
    pub fn recv(&self, timeout: Duration) -> Result<Option<Incoming>>;   // None on timeout; ignores datagrams from other peers (warn)
    pub fn socket(&self) -> &UdpSocket;                     // for try_clone in the rx thread
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
pub struct EapTlsConfig { pub identity: Vec<u8>, pub client_cert_pem: String, pub client_key_pem: String, pub validate_server: bool,
                          pub server_ca_pem: Option<String>, pub server_name: Option<String> /* SNI; None = none */, pub max_fragment_len: usize, pub allow_tls13: bool }
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
unless `validate_server` (then the PEM CA bundle), client leaf cert + key (PKCS#8/PKCS#1/SEC1 PEM), cipher list
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
and `socket-icmp` are pre-enabled for the TCP seam below; `proto-ipv6-fragmentation` is inert on `Medium::Ip` (6LoWPAN only).

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
// TCP: not exposed yet — the seam is `socket::tcp::Socket` in the same SocketSet (one method away; do NOT implement now).
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

## 12. Tunnel facade (`tunnel.rs`)
```rust
pub struct TunnelInfo { pub local_addr: SocketAddr, pub remote_addr: SocketAddr, pub nat: NatStatus, pub assigned: AssignedConfig,
    pub ike_spi_i: u64, pub ike_spi_r: u64, pub child_spi_in: u32, pub child_spi_out: u32, pub ike_suite: String, pub child_suite: String,
    pub tls_version: String, pub handshake_duration: Duration }
pub struct EpdgTunnel { /* Arc<Shared>, rx thread, timer thread */ }
impl EpdgTunnel {
    pub fn connect(cfg: &Config) -> Result<EpdgTunnel>;
    pub fn info(&self) -> &TunnelInfo;
    pub fn bind_udp(&self, local_port: u16) -> Result<InnerUdpSocket>;   // 0 = pick free (49152..65535); smoltcp picks the source address by route
    pub fn resolve(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>>; // smoltcp DNS socket over the assigned servers
    pub fn is_alive(&self) -> bool;
    pub fn dpd(&self) -> Result<Duration>;                              // on-demand liveness check (empty INFORMATIONAL), returns RTT
    pub fn stats(&self) -> TunnelStats;                                 // esp tx/rx packets+bytes, replay drops, icv fails, keepalives sent, last rx Instant
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
rekey IKE at its lifetime similarly (`build_rekey_ike`, then delete old IKE SA). All post-establishment IKE requests go
through one `request()` helper that serialises on a mutex (one outstanding request), uses the transport's retransmit
policy, and routes the response via the rx thread's pending slot. Fragmented responses are collected there too.

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
input errors, stop semantics, stack-thread panic closes the stack;
config parsing of `tests/fixtures/tmobile_prod_bundle.plist` + `tmobile_creds.plist` (assert every mapped field).
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
OS stack or inside the ePDG tunnel. Object-safe (consumers hold `Arc<dyn NetStack>`), synchronous. UDP + DNS on both backends;
TCP is real on the OS backend and **not yet supported on the tunnel** (smoltcp has `socket::tcp`, wiring it to the stack thread
is deferred).

```rust
// src/netstack/mod.rs
pub trait NetStack: Send + Sync {
    /// Bind a UDP socket on `local_port` (0 = ephemeral).
    fn bind_udp(&self, local_port: u16) -> io::Result<Box<dyn UdpSocketLike>>;
    /// Open a TCP connection to `remote` within `timeout`. Tunnel backend: `Err(ErrorKind::Unsupported)` for now.
    fn connect_tcp(&self, remote: SocketAddr, timeout: Duration) -> io::Result<Box<dyn TcpStreamLike>>;
    /// Listen for TCP connections on `local_port` (0 = ephemeral). Tunnel backend: `Err(ErrorKind::Unsupported)` for now.
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
- **`EpdgTunnel: NetStack`** — `bind_udp` / `resolve` / `local_addrs` delegate to the tunnel (DNS = smoltcp's DNS socket over the
  assigned tunnel servers; the libc resolver cannot reach tunnel-internal servers); `connect_tcp` / `listen_tcp` return
  `Err(io::ErrorKind::Unsupported, "TCP over the ePDG tunnel is not implemented yet")`. `InnerUdpSocket: UdpSocketLike`.
  **`InnerStack: NetStack`** too (same delegation) so the trait is testable offline over the two-stack loopback harness.
- Error mapping `epdg::Error → io::Error` (`netstack::to_io`): `Io(e)` → `e`; `Timeout` → `TimedOut`; `Closed` → `NotConnected`;
  `Config`/`Unsupported` → `InvalidInput`; everything else → `Other`; the crate error is kept as the payload
  (`io::Error::new(kind, e)`: `io::Error::get_ref()` / `into_inner()` downcast to `epdg::Error`; `Display` is the crate error's —
  note `std::error::Error::source()` on the `io::Error` is `None`). Conditions a caller branches on have the same kind on both
  backends: a taken port in `bind_udp` is `AddrInUse` (`InnerStack::bind_udp` returns `Error::Io(AddrInUse)` for it), a name that
  does not exist is `NotFound` (the tunnel's `Error::Protocol("DNS query failed …" | "… returned no addresses")` is mapped to
  `NotFound` by the `resolve` impls; other `Protocol` errors stay `Other`). Scoped IPv6 literals (`fe80::1%lo0`) are rejected with
  `InvalidInput` ("scoped IPv6 literal … not supported": an `IpAddr` cannot carry the zone).
- Exports: `epdg::netstack::{NetStack, UdpSocketLike, TcpStreamLike, TcpListenerLike, StreamIo, StdNetStack}` and the same from `epdg::`.

Tests: one generic `fn exercise_udp<S: NetStack + ?Sized>(a: &S, b: &S)` run over BOTH backends (bind two sockets, send both ways,
echo, `recv_timeout` → `None` on silence, `local_addr` port matches, `local_addrs` non-empty, ephemeral ports distinct, usable through
`Arc<dyn NetStack>`), plus `exercise_tcp` on std: listen on loopback, connect with timeout, write/read both ways through
`Arc<dyn TcpStreamLike>` from two threads, read timeout → `WouldBlock|TimedOut`, EOF after peer shutdown, `accept_timeout` → `None`
on silence, `StreamIo` wraps a stream as `Read + Write`, connect to a closed port → error within the timeout. std resolve:
`resolve("localhost")` contains a loopback; IP literal without the resolver; invalid label errors; a too-short timeout returns
promptly (`TimedOut` or a fast error). Tunnel: `resolve` over the fake DNS server returns the fake answer; `connect_tcp` /
`listen_tcp` → `Err(Unsupported)`; after close `recv_timeout` → `Err(NotConnected)`; NXDOMAIN → `NotFound`; a v4-mapped `send_to`
destination is delivered as IPv4. std extras: `Duration::MAX` `recv_timeout`/`accept_timeout` woken by a send/connect (no panic);
a write under a write timeout never loses or duplicates bytes (delivered == reported); `shutdown` after peer EOF is `Ok`;
`connect_tcp(_, ZERO)` is not `InvalidInput`; `HandshakeError<StreamIo>: Error`. `epdg-connect` performs its P-CSCF lookup and the
DNS round trip through `&dyn NetStack` and asserts `name() == "epdg-tunnel"`, `local_addrs()` == the assigned inner addresses and
`bind_udp` (incl. `AddrInUse` on a taken port) so the live run covers the `EpdgTunnel` implementation.

## 15. Amendment log
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
