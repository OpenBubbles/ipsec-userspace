//! IKEv2 initiator state machine (DESIGN.md §8), sans-I/O.
//!
//! [`IkeInitiator`] owns all IKE state and never touches a socket. The tunnel
//! drives it: `build_*` → [`IkeInitiator::encode`] → send / recv →
//! [`IkeInitiator::decode`] → `handle_*`. Everything it puts on the wire mirrors the
//! proven AOSP client byte for byte (§14 / `docs/AOSP_FACTS.md`):
//!
//! - IKE_SA_INIT: `SA, KE, Ni, N(NAT_D_SRC), N(NAT_D_DST), N(FRAG), N(SIG_HASH)`;
//!   transforms `ENCR / INTEG / DH / PRF`; NAT_D_SRC hashed over the fake local
//!   address `192.0.2.0` so the gateway always uses UDP-encapsulated ESP;
//!   `N(COOKIE)` first on a cookie retry, everything else byte-identical.
//! - IKE_AUTH #1: `IDi, IDr, N(EAP_ONLY), N(MOBIKE), SA(ESP: ENCR/INTEG/ESN), TSi, TSr, CP`
//!   — no AUTH (EAP-only, RFC 5998). EAP rounds carry only `EAP`; the post-EAP
//!   request carries only `AUTH(method 2)` keyed by the EAP MSK.
//! - The responder's final AUTH is verified with the IDr captured from the FIRST
//!   IKE_AUTH response.
//! - Two message-id counters (ours / the peer's), window 1, last response cached
//!   for a retransmitted peer request.
//!
//! Child SPI direction: the SPI we put in SAi2 is our INBOUND SPI (`spi_in`); the
//! responder's SAr2 SPI is our OUTBOUND SPI (`spi_out`).

use crate::config::Config;
use crate::crypto::{Cipher, DhKeyPair, Integrity, Suite, random_bytes, registry};
use crate::ike::auth::{
    AuthMethod, SharedKeyAuth, id_payload_body, initiator_signed_octets, responder_signed_octets,
};
use crate::ike::constants::*;
use crate::ike::fragment::{Reassembler, is_fragment};
use crate::ike::header::IkeHeader;
use crate::ike::keys::{ChildKeys, IkeKeys, derive_child_keys, derive_ike_keys, derive_ike_keys_rekey};
use crate::ike::message::IkeMessage;
use crate::ike::nat::{self, NatStatus};
use crate::ike::payload::*;
use crate::{Error, Result};
use log::{debug, info, warn};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `N(SIGNATURE_HASH_ALGORITHMS)` data AOSP always sends: SHA1, SHA2-256, SHA2-384, SHA2-512.
const SIGNATURE_HASH_ALGORITHMS_DATA: [u8; 8] = [0, 1, 0, 2, 0, 3, 0, 4];
/// RFC 7296 §2.6: cookie data is 1..=64 bytes (AOSP COOKIE_DATA_LEN_MIN/MAX).
const COOKIE_LEN_MIN: usize = 1;
const COOKIE_LEN_MAX: usize = 64;
/// Nonce payload data bounds (RFC 7296 §3.9).
const NONCE_LEN_MIN: usize = 16;
const NONCE_LEN_MAX: usize = 256;
/// Prefix length assumed for a 16-byte INTERNAL_IP6_ADDRESS reply (tolerated, AOSP requires 17).
const IP6_ADDRESS_DEFAULT_PREFIX: u8 = 64;

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/// Outcome of [`IkeInitiator::handle_sa_init_response`].
#[derive(Debug)]
pub enum SaInitOutcome {
    /// Keys derived; `nat` says whether to switch to port 4500.
    Established { nat: NatStatus },
    /// Peer demands a cookie: call `build_sa_init(Some(&cookie))` and resend.
    RetryWithCookie(Vec<u8>),
    /// Peer demands another DH group: the initiator has already regenerated SPIi,
    /// nonce and KE for that group (call `build_sa_init(None)` again), or build a
    /// fresh one with [`IkeInitiator::new_with_dh_group`].
    RetryWithGroup(u16),
}

/// Outcome of [`IkeInitiator::handle_auth_response`].
#[derive(Debug)]
pub enum AuthResponse {
    /// The EAP packet carried in the response (Request, or Success — the EAP layer tells them apart).
    EapRequest(Vec<u8>),
    /// The final response verified; the IKE SA and first child SA are up.
    Established(Box<Established>),
}

/// Everything the tunnel needs once IKE_AUTH completes.
#[derive(Clone, Debug)]
pub struct Established {
    pub child: ChildSaInfo,
    pub assigned: AssignedConfig,
    /// The IDr used for AUTH verification (from the first IKE_AUTH response).
    pub id_r: IdPayload,
}

/// A negotiated child (ESP) SA.
#[derive(Clone)]
pub struct ChildSaInfo {
    /// Our inbound SPI (the one we proposed) — the gateway sends ESP to us with it.
    pub spi_in: u32,
    /// The responder's SPI — we send ESP with it.
    pub spi_out: u32,
    pub keys: ChildKeys,
    pub cipher: Arc<dyn Cipher>,
    pub integrity: Arc<dyn Integrity>,
    pub replay_window: u32,
    /// Negotiated TSi (the responder's, possibly narrowed).
    pub ts_i: TsPayload,
    /// Negotiated TSr (the responder's, possibly narrowed).
    pub ts_r: TsPayload,
    pub created: Instant,
    pub lifetime: Duration,
}

impl std::fmt::Debug for ChildSaInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildSaInfo")
            .field("spi_in", &format_args!("{:#010x}", self.spi_in))
            .field("spi_out", &format_args!("{:#010x}", self.spi_out))
            .field("keys", &self.keys)
            .field("cipher", &registry::transform_name(TT_ENCR, self.cipher.transform_id()))
            .field("integrity", &registry::transform_name(TT_INTEG, self.integrity.transform_id()))
            .field("replay_window", &self.replay_window)
            .field("ts_i", &self.ts_i)
            .field("ts_r", &self.ts_r)
            .field("lifetime", &self.lifetime)
            .finish()
    }
}

/// Addresses handed out in the CFG_REPLY of the final IKE_AUTH response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssignedConfig {
    pub internal_ipv4: Vec<Ipv4Addr>,
    /// `(address, prefix length)`.
    pub internal_ipv6: Vec<(Ipv6Addr, u8)>,
    pub dns_ipv4: Vec<Ipv4Addr>,
    pub dns_ipv6: Vec<Ipv6Addr>,
    pub pcscf_ipv4: Vec<Ipv4Addr>,
    pub pcscf_ipv6: Vec<Ipv6Addr>,
    /// Every other (or malformed) non-empty attribute, verbatim.
    pub other: Vec<ConfigAttribute>,
}

/// What a peer-initiated request was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// Empty INFORMATIONAL (dead peer detection); answered with an empty response.
    Dpd,
    /// The peer deleted the IKE SA; the session is closed.
    DeleteIke,
    /// The peer deleted child SAs; carries OUR inbound SPIs of the deleted children.
    DeleteChild(Vec<u32>),
    /// INFORMATIONAL carrying only notifies (answered with an empty response).
    Notify(Vec<NotifyPayload>),
    /// Anything else (peer CREATE_CHILD_SA → rejected with NO_ADDITIONAL_SAS; retransmission).
    Other,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    New,
    SaInitSent,
    SaInitDone,
    AuthInitialSent,
    InEap,
    AuthFinalSent,
    Established,
    Closed,
}

struct RekeyChildState {
    spi_in: u32,
    nonce_i: Vec<u8>,
    proposals: Vec<Proposal>,
    ts_i: TsPayload,
    ts_r: TsPayload,
}

struct RekeyIkeState {
    spi_i: u64,
    nonce_i: Vec<u8>,
    dh_pair: Box<dyn DhKeyPair>,
    proposal: Proposal,
}

/// The one request we currently have outstanding after establishment.
enum Pending {
    None,
    Dpd,
    DeleteIke,
    DeleteChild(u32),
    RekeyChild(RekeyChildState),
    RekeyIke(RekeyIkeState),
}

/// The previous IKE SA after an IKE rekey, kept until its DELETE completes.
struct OldIkeSa {
    spi_i: u64,
    spi_r: u64,
    suite: Suite,
    keys: IkeKeys,
    our_msgid: u32,
    delete_msgid: Option<u32>,
}

fn empty_keys() -> IkeKeys {
    IkeKeys {
        sk_d: Vec::new(),
        sk_ai: Vec::new(),
        sk_ar: Vec::new(),
        sk_ei: Vec::new(),
        sk_er: Vec::new(),
        sk_pi: Vec::new(),
        sk_pr: Vec::new(),
    }
}

/// IKEv2 initiator (EAP-only authentication).
pub struct IkeInitiator {
    cfg: Config,
    local: SocketAddr,
    remote: SocketAddr,
    state: State,

    // Resolved proposals (config names → transform ids).
    ike_proposals: Vec<Proposal>,
    /// Child proposals WITHOUT SPI (filled in per request).
    child_proposals: Vec<Proposal>,

    // IKE SA
    suite: Suite,
    spi_i: u64,
    spi_r: u64,
    nonce_i: Vec<u8>,
    nonce_r: Vec<u8>,
    dh_group: u16,
    dh_pair: Box<dyn DhKeyPair>,
    keys: IkeKeys,
    /// The SA_INIT payload chain built once, reused verbatim on a COOKIE retry.
    sa_init_base: Option<Vec<Payload>>,
    real_message1: Vec<u8>,
    real_message2: Vec<u8>,
    nat: Option<NatStatus>,
    peer_fragmentation: bool,

    // Message ids
    our_msgid: u32,
    peer_msgid: u32,
    last_peer_response: Option<(u32, IkeMessage)>,

    // IKE_AUTH
    id_i: IdPayload,
    id_r_cfg: IdPayload,
    id_r_received: Option<IdPayload>,
    child_spi_in: u32,
    child_ts_i: TsPayload,
    child_ts_r: TsPayload,
    auth: Option<Box<dyn AuthMethod>>,

    // Post-establishment
    child: Option<ChildSaInfo>,
    /// Chosen child proposal (transforms only) — reused for rekeys.
    child_negotiated: Option<Proposal>,
    old_child: Option<ChildSaInfo>,
    pending: Pending,
    old_ike: Option<OldIkeSa>,
    reassembler: Reassembler,
}

impl std::fmt::Debug for IkeInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IkeInitiator")
            .field("state", &self.state)
            .field("spi_i", &format_args!("{:#018x}", self.spi_i))
            .field("spi_r", &format_args!("{:#018x}", self.spi_r))
            .field("our_msgid", &self.our_msgid)
            .field("peer_msgid", &self.peer_msgid)
            .field("nat", &self.nat)
            .field("peer_fragmentation", &self.peer_fragmentation)
            .field("child", &self.child)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Proposal resolution helpers
// ---------------------------------------------------------------------------

fn unsupported(what: &str, name: &str) -> Error {
    Error::Unsupported(format!("{what} {name:?}"))
}

fn resolve_encr(name: &str) -> Result<Transform> {
    let (id, bits) = registry::cipher_by_name(name).ok_or_else(|| unsupported("encryption algorithm", name))?;
    registry::cipher(id, bits).ok_or_else(|| unsupported("encryption algorithm", name))?;
    Ok(Transform { ttype: TT_ENCR, id, key_len_bits: bits })
}

fn resolve_integ(name: &str) -> Result<Transform> {
    let id = registry::integrity_by_name(name).ok_or_else(|| unsupported("integrity algorithm", name))?;
    registry::integrity(id).ok_or_else(|| unsupported("integrity algorithm", name))?;
    Ok(Transform::new(TT_INTEG, id))
}

fn resolve_prf(name: &str) -> Result<Transform> {
    let id = registry::prf_by_name(name).ok_or_else(|| unsupported("PRF", name))?;
    registry::prf(id).ok_or_else(|| unsupported("PRF", name))?;
    Ok(Transform::new(TT_PRF, id))
}

fn resolve_dh(group: u16) -> Result<Transform> {
    registry::dh(group).ok_or_else(|| Error::Unsupported(format!("DH group {group}")))?;
    Ok(Transform::new(TT_DH, group))
}

/// Config IKE proposals → wire proposals, transforms in AOSP order ENCR / INTEG / DH / PRF.
fn resolve_ike_proposals(cfg: &Config) -> Result<Vec<Proposal>> {
    if cfg.ike.proposals.is_empty() {
        return Err(Error::Config("no IKE proposals configured".into()));
    }
    let mut out = Vec::with_capacity(cfg.ike.proposals.len());
    for (i, p) in cfg.ike.proposals.iter().enumerate() {
        if p.encryption.is_empty() || p.integrity.is_empty() || p.prf.is_empty() || p.dh_groups.is_empty() {
            return Err(Error::Config(format!(
                "IKE proposal {} needs at least one encryption, integrity, prf and DH group",
                i + 1
            )));
        }
        let mut transforms = Vec::new();
        for n in &p.encryption {
            transforms.push(resolve_encr(n)?);
        }
        for n in &p.integrity {
            transforms.push(resolve_integ(n)?);
        }
        for g in &p.dh_groups {
            transforms.push(resolve_dh(*g)?);
        }
        for n in &p.prf {
            transforms.push(resolve_prf(n)?);
        }
        out.push(Proposal { number: (i + 1) as u8, protocol_id: PROTO_IKE, spi: Vec::new(), transforms });
    }
    Ok(out)
}

/// Config child proposals → wire proposals (no SPI yet): ENCR / INTEG / ESN(0).
/// DH (PFS) transforms are stripped for the first child exactly like AOSP.
fn resolve_child_proposals(cfg: &Config) -> Result<Vec<Proposal>> {
    if cfg.child.proposals.is_empty() {
        return Err(Error::Config("no child SA proposals configured".into()));
    }
    let mut out = Vec::with_capacity(cfg.child.proposals.len());
    for (i, p) in cfg.child.proposals.iter().enumerate() {
        if p.encryption.is_empty() || p.integrity.is_empty() {
            return Err(Error::Config(format!(
                "child proposal {} needs at least one encryption and integrity algorithm",
                i + 1
            )));
        }
        let mut transforms = Vec::new();
        for n in &p.encryption {
            transforms.push(resolve_encr(n)?);
        }
        for n in &p.integrity {
            transforms.push(resolve_integ(n)?);
        }
        if !p.dh_groups.is_empty() {
            debug!("child proposal {}: PFS groups {:?} ignored (no PFS for the first child, like AOSP)", i + 1, p.dh_groups);
        }
        transforms.push(Transform::new(TT_ESN, ESN_NO));
        out.push(Proposal { number: (i + 1) as u8, protocol_id: PROTO_ESP, spi: Vec::new(), transforms });
    }
    Ok(out)
}

/// The chosen transform of `ttype` in a responder proposal: exactly one, and it must
/// be one we offered (ENCR compared including key length). `required=false` allows
/// absence (treated as NONE).
fn chosen_transform(chosen: &Proposal, offered: &Proposal, ttype: u8, required: bool) -> Result<Option<Transform>> {
    let picked: Vec<&Transform> = chosen.transforms.iter().filter(|t| t.ttype == ttype).collect();
    let name = |t: &Transform| registry::transform_name(t.ttype, t.id);
    match picked.as_slice() {
        [] if !required => Ok(None),
        [] => Err(Error::Protocol(format!(
            "chosen proposal lacks a transform of type {ttype} ({})",
            transform_type_name(ttype)
        ))),
        [t] => {
            if offered.transforms.iter().any(|o| o == *t) {
                Ok(Some((*t).clone()))
            } else {
                Err(Error::Protocol(format!(
                    "chosen transform {} (keylen {:?}) was not offered",
                    name(t),
                    t.key_len_bits
                )))
            }
        }
        many => Err(Error::Protocol(format!(
            "chosen proposal has {} transforms of type {} (expected 1)",
            many.len(),
            transform_type_name(ttype)
        ))),
    }
}

fn transform_type_name(ttype: u8) -> &'static str {
    match ttype {
        TT_ENCR => "ENCR",
        TT_PRF => "PRF",
        TT_INTEG => "INTEG",
        TT_DH => "DH",
        TT_ESN => "ESN",
        _ => "?",
    }
}

/// The single proposal of a responder SA payload, matched against what we offered.
/// Returns `(chosen, offered)`.
fn select_response_proposal<'a>(sa: &'a SaPayload, offered: &'a [Proposal], protocol: u8) -> Result<(&'a Proposal, &'a Proposal)> {
    let chosen = match sa.proposals.as_slice() {
        [p] => p,
        other => {
            return Err(Error::Protocol(format!(
                "response SA payload carries {} proposals (expected exactly 1)",
                other.len()
            )));
        }
    };
    if chosen.protocol_id != protocol {
        return Err(Error::Protocol(format!(
            "chosen proposal protocol {} != expected {}",
            chosen.protocol_id, protocol
        )));
    }
    let ours = offered
        .iter()
        .find(|p| p.number == chosen.number)
        .ok_or_else(|| Error::Protocol(format!("chosen proposal number {} was not offered", chosen.number)))?;
    if chosen.transforms.iter().any(|t| !ours.transforms.iter().any(|o| o == t)) {
        return Err(Error::Protocol("chosen proposal contains a transform we did not offer".into()));
    }
    Ok((chosen, ours))
}

/// Build the IKE `Suite` from a chosen IKE proposal.
fn suite_from_ike_proposal(chosen: &Proposal, offered: &Proposal) -> Result<Suite> {
    let encr = chosen_transform(chosen, offered, TT_ENCR, true)?.ok_or_else(|| Error::Protocol("no ENCR".into()))?;
    let integ = chosen_transform(chosen, offered, TT_INTEG, true)?.ok_or_else(|| Error::Protocol("no INTEG".into()))?;
    let prf = chosen_transform(chosen, offered, TT_PRF, true)?.ok_or_else(|| Error::Protocol("no PRF".into()))?;
    let dh = chosen_transform(chosen, offered, TT_DH, true)?.ok_or_else(|| Error::Protocol("no DH".into()))?;
    Ok(Suite {
        cipher: registry::cipher(encr.id, encr.key_len_bits)
            .ok_or_else(|| Error::Unsupported(registry::transform_name(TT_ENCR, encr.id)))?,
        integrity: registry::integrity(integ.id)
            .ok_or_else(|| Error::Unsupported(registry::transform_name(TT_INTEG, integ.id)))?,
        prf: registry::prf(prf.id).ok_or_else(|| Error::Unsupported(registry::transform_name(TT_PRF, prf.id)))?,
        dh: Some(registry::dh(dh.id).ok_or_else(|| Error::Unsupported(registry::transform_name(TT_DH, dh.id)))?),
    })
}

/// Cipher + integrity from a chosen child proposal; ESN must be absent or 0.
fn child_algs_from_proposal(chosen: &Proposal, offered: &Proposal) -> Result<(Arc<dyn Cipher>, Arc<dyn Integrity>)> {
    let encr = chosen_transform(chosen, offered, TT_ENCR, true)?.ok_or_else(|| Error::Protocol("no ENCR".into()))?;
    let integ = chosen_transform(chosen, offered, TT_INTEG, true)?.ok_or_else(|| Error::Protocol("no INTEG".into()))?;
    if let Some(esn) = chosen_transform(chosen, offered, TT_ESN, false)?
        && esn.id != ESN_NO
    {
        return Err(Error::Unsupported("extended sequence numbers (ESN) selected by the responder".into()));
    }
    let cipher = registry::cipher(encr.id, encr.key_len_bits)
        .ok_or_else(|| Error::Unsupported(registry::transform_name(TT_ENCR, encr.id)))?;
    let integrity = registry::integrity(integ.id)
        .ok_or_else(|| Error::Unsupported(registry::transform_name(TT_INTEG, integ.id)))?;
    Ok((cipher, integrity))
}

/// Every responder selector must be contained in one of ours of the same type and
/// protocol (AOSP `IkeTsPayload.contains`). Narrowing is accepted as-is.
fn ts_contained(ours: &TsPayload, theirs: &TsPayload) -> bool {
    !theirs.selectors.is_empty()
        && theirs.selectors.iter().all(|t| {
            ours.selectors.iter().any(|o| {
                o.ts_type == t.ts_type
                    && o.ip_protocol == t.ip_protocol
                    && o.start_port <= t.start_port
                    && o.end_port >= t.end_port
                    && o.start_addr.len() == t.start_addr.len()
                    && o.end_addr.len() == t.end_addr.len()
                    && o.start_addr.as_slice() <= t.start_addr.as_slice()
                    && o.end_addr.as_slice() >= t.end_addr.as_slice()
            })
        })
}

fn spi4(spi: &[u8], what: &str) -> Result<u32> {
    let arr: [u8; 4] = spi
        .try_into()
        .map_err(|_| Error::Decode(format!("{what}: SPI is {} bytes (expected 4)", spi.len())))?;
    let v = u32::from_be_bytes(arr);
    if v == 0 {
        return Err(Error::Decode(format!("{what}: SPI is zero")));
    }
    Ok(v)
}

fn spi8(spi: &[u8], what: &str) -> Result<u64> {
    let arr: [u8; 8] = spi
        .try_into()
        .map_err(|_| Error::Decode(format!("{what}: SPI is {} bytes (expected 8)", spi.len())))?;
    let v = u64::from_be_bytes(arr);
    if v == 0 {
        return Err(Error::Decode(format!("{what}: SPI is zero")));
    }
    Ok(v)
}

fn random_nonzero_u32() -> u32 {
    loop {
        let b = random_bytes(4);
        let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if v != 0 {
            return v;
        }
    }
}

fn random_nonzero_u64() -> u64 {
    loop {
        let b = random_bytes(8);
        let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        if v != 0 {
            return v;
        }
    }
}

fn check_nonce(n: &[u8], what: &str) -> Result<()> {
    if n.len() < NONCE_LEN_MIN || n.len() > NONCE_LEN_MAX {
        return Err(Error::Decode(format!(
            "{what}: nonce of {} bytes (expected {NONCE_LEN_MIN}..={NONCE_LEN_MAX})",
            n.len()
        )));
    }
    Ok(())
}

fn v4(b: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(b).ok().map(Ipv4Addr::from)
}

fn v6(b: &[u8]) -> Option<Ipv6Addr> {
    <[u8; 16]>::try_from(b).ok().map(Ipv6Addr::from)
}

/// Parse a CFG_REPLY into [`AssignedConfig`]. Zero-length attributes mean "none";
/// malformed lengths are tolerated (kept in `other`, with a warning).
fn parse_cfg_reply(cp: &ConfigPayload) -> AssignedConfig {
    let mut out = AssignedConfig::default();
    for a in &cp.attributes {
        if a.value.is_empty() {
            debug!("CFG_REPLY: empty attribute type {} ignored", a.attr_type);
            continue;
        }
        let ok = match a.attr_type {
            CFG_INTERNAL_IP4_ADDRESS => v4(&a.value).map(|ip| out.internal_ipv4.push(ip)).is_some(),
            CFG_INTERNAL_IP6_ADDRESS => match a.value.len() {
                17 => v6(&a.value[..16]).map(|ip| out.internal_ipv6.push((ip, a.value[16]))).is_some(),
                16 => {
                    warn!("CFG_REPLY: INTERNAL_IP6_ADDRESS without prefix byte; assuming /{IP6_ADDRESS_DEFAULT_PREFIX}");
                    v6(&a.value).map(|ip| out.internal_ipv6.push((ip, IP6_ADDRESS_DEFAULT_PREFIX))).is_some()
                }
                _ => false,
            },
            CFG_INTERNAL_IP4_DNS => v4(&a.value).map(|ip| out.dns_ipv4.push(ip)).is_some(),
            CFG_INTERNAL_IP6_DNS => v6(&a.value).map(|ip| out.dns_ipv6.push(ip)).is_some(),
            CFG_P_CSCF_IP4_ADDRESS => v4(&a.value).map(|ip| out.pcscf_ipv4.push(ip)).is_some(),
            CFG_P_CSCF_IP6_ADDRESS => v6(&a.value).map(|ip| out.pcscf_ipv6.push(ip)).is_some(),
            _ => false,
        };
        if !ok {
            if matches!(
                a.attr_type,
                CFG_INTERNAL_IP4_ADDRESS
                    | CFG_INTERNAL_IP6_ADDRESS
                    | CFG_INTERNAL_IP4_DNS
                    | CFG_INTERNAL_IP6_DNS
                    | CFG_P_CSCF_IP4_ADDRESS
                    | CFG_P_CSCF_IP6_ADDRESS
            ) {
                warn!(
                    "CFG_REPLY: attribute type {} has unexpected length {}; kept verbatim",
                    a.attr_type,
                    a.value.len()
                );
            } else {
                debug!("CFG_REPLY: attribute type {} ({} bytes) kept verbatim", a.attr_type, a.value.len());
            }
            out.other.push(a.clone());
        }
    }
    info!(
        "assigned config: v4={:?} v6={:?} dns4={:?} dns6={:?} pcscf4={:?} pcscf6={:?} other={}",
        out.internal_ipv4,
        out.internal_ipv6,
        out.dns_ipv4,
        out.dns_ipv6,
        out.pcscf_ipv4,
        out.pcscf_ipv6,
        out.other.len()
    );
    out
}

// ---------------------------------------------------------------------------
// IkeInitiator
// ---------------------------------------------------------------------------

impl IkeInitiator {
    /// Resolve proposal names via the registry (unknown → `Error::Unsupported`),
    /// generate SPIi, Ni and the DH pair for the first configured group.
    pub fn new(cfg: &Config, local: SocketAddr, remote: SocketAddr) -> Result<Self> {
        let group = cfg
            .ike
            .proposals
            .first()
            .and_then(|p| p.dh_groups.first().copied())
            .ok_or_else(|| Error::Config("no IKE proposal / DH group configured".into()))?;
        Self::new_with_dh_group(cfg, local, remote, group)
    }

    /// Like [`new`](Self::new) but with an explicit DH group for the KE payload (after
    /// `INVALID_KE_PAYLOAD`). The group must appear in a configured proposal.
    pub fn new_with_dh_group(cfg: &Config, local: SocketAddr, remote: SocketAddr, group: u16) -> Result<Self> {
        let ike_proposals = resolve_ike_proposals(cfg)?;
        let child_proposals = resolve_child_proposals(cfg)?;
        if cfg.ike.nonce_len < NONCE_LEN_MIN || cfg.ike.nonce_len > NONCE_LEN_MAX {
            return Err(Error::Config(format!(
                "ike.nonce_len {} out of range {NONCE_LEN_MIN}..={NONCE_LEN_MAX}",
                cfg.ike.nonce_len
            )));
        }
        if !cfg.ike.proposals.iter().any(|p| p.dh_groups.contains(&group)) {
            return Err(Error::Config(format!("DH group {group} is not in any configured IKE proposal")));
        }
        if !cfg.ike.eap_only {
            return Err(Error::Unsupported("only EAP-only authentication (RFC 5998) is implemented".into()));
        }
        // Provisional suite = first transforms of the first proposal (replaced by the negotiated one).
        let first = &cfg.ike.proposals[0];
        let encr = resolve_encr(&first.encryption[0])?;
        let integ = resolve_integ(&first.integrity[0])?;
        let prf = resolve_prf(&first.prf[0])?;
        let dh = registry::dh(group).ok_or_else(|| Error::Unsupported(format!("DH group {group}")))?;
        let suite = Suite {
            cipher: registry::cipher(encr.id, encr.key_len_bits)
                .ok_or_else(|| unsupported("encryption algorithm", &first.encryption[0]))?,
            integrity: registry::integrity(integ.id).ok_or_else(|| unsupported("integrity algorithm", &first.integrity[0]))?,
            prf: registry::prf(prf.id).ok_or_else(|| unsupported("PRF", &first.prf[0]))?,
            dh: Some(dh.clone()),
        };
        let dh_pair = dh.generate()?;
        let spi_i = random_nonzero_u64();
        info!(
            "IkeInitiator: SPIi={:#018x} DH group {} local {} remote {} ({} IKE / {} child proposals)",
            spi_i,
            group,
            local,
            remote,
            ike_proposals.len(),
            child_proposals.len()
        );
        Ok(IkeInitiator {
            cfg: cfg.clone(),
            local,
            remote,
            state: State::New,
            ike_proposals,
            child_proposals,
            suite,
            spi_i,
            spi_r: 0,
            nonce_i: random_bytes(cfg.ike.nonce_len),
            nonce_r: Vec::new(),
            dh_group: group,
            dh_pair,
            keys: empty_keys(),
            sa_init_base: None,
            real_message1: Vec::new(),
            real_message2: Vec::new(),
            nat: None,
            peer_fragmentation: false,
            our_msgid: 0,
            peer_msgid: 0,
            last_peer_response: None,
            id_i: IdPayload { id_type: cfg.identity.local_id.id_type, data: cfg.identity.local_id.data.clone() },
            id_r_cfg: IdPayload { id_type: cfg.identity.remote_id.id_type, data: cfg.identity.remote_id.data.clone() },
            id_r_received: None,
            child_spi_in: random_nonzero_u32(),
            child_ts_i: TsPayload::any_v4_v6(),
            child_ts_r: TsPayload::any_v4_v6(),
            auth: None,
            child: None,
            child_negotiated: None,
            old_child: None,
            pending: Pending::None,
            old_ike: None,
            reassembler: Reassembler::new(),
        })
    }

    // -----------------------------------------------------------------------
    // IKE_SA_INIT (msgid 0)
    // -----------------------------------------------------------------------

    /// The SA_INIT payload chain (without cookie), built once and reused verbatim.
    fn sa_init_payloads(&mut self) -> Vec<Payload> {
        if let Some(base) = &self.sa_init_base {
            return base.clone();
        }
        let mut payloads = vec![
            Payload::Sa(SaPayload { proposals: self.ike_proposals.clone() }),
            Payload::Ke(KePayload { group: self.dh_group, public: self.dh_pair.public_value() }),
            Payload::Nonce(self.nonce_i.clone()),
        ];
        // NAT-D only for an IPv4 gateway (AOSP omits them for IPv6 peers).
        if self.remote.is_ipv4() {
            let [src, dst] = nat::request_notifies(self.spi_i, self.local, self.remote, self.cfg.ike.natt.force_udp_encap);
            payloads.push(Payload::Notify(src));
            payloads.push(Payload::Notify(dst));
        }
        if self.cfg.ike.fragmentation {
            payloads.push(Payload::Notify(NotifyPayload::status(N_IKEV2_FRAGMENTATION_SUPPORTED, Vec::new())));
        }
        if self.cfg.ike.signature_hash_algorithms {
            payloads.push(Payload::Notify(NotifyPayload::status(
                N_SIGNATURE_HASH_ALGORITHMS,
                SIGNATURE_HASH_ALGORITHMS_DATA.to_vec(),
            )));
        }
        self.sa_init_base = Some(payloads.clone());
        payloads
    }

    /// Build the IKE_SA_INIT request (msgid 0). With `cookie`, `N(COOKIE)` goes FIRST and
    /// everything else (SPIi, nonce, KE, NAT-D hashes) is byte-identical to the first
    /// attempt. Records `real_message1` = the returned bytes.
    pub fn build_sa_init(&mut self, cookie: Option<&[u8]>) -> Result<Vec<u8>> {
        match self.state {
            State::New | State::SaInitSent => {}
            s => return Err(Error::Protocol(format!("build_sa_init in state {s:?}"))),
        }
        let mut payloads = Vec::new();
        if let Some(c) = cookie {
            if c.len() < COOKIE_LEN_MIN || c.len() > COOKIE_LEN_MAX {
                return Err(Error::Decode(format!("COOKIE of {} bytes (expected 1..=64)", c.len())));
            }
            payloads.push(Payload::Notify(NotifyPayload::status(N_COOKIE, c.to_vec())));
        }
        payloads.extend(self.sa_init_payloads());
        let msg = IkeMessage::new(self.spi_i, 0, EXCH_IKE_SA_INIT, FLAG_INITIATOR, 0, payloads);
        let raw = msg.encode_plain()?;
        info!(
            "IKE_SA_INIT request: {} bytes, cookie={}, {} payloads",
            raw.len(),
            cookie.is_some(),
            msg.payloads.len()
        );
        debug!("IKE_SA_INIT request hex: {}", hex::encode(&raw));
        self.real_message1 = raw.clone();
        self.state = State::SaInitSent;
        Ok(raw)
    }

    /// Regenerate SPIi, nonce and DH pair for `group` (INVALID_KE_PAYLOAD restart).
    fn restart_with_group(&mut self, group: u16) -> Result<()> {
        let dh = registry::dh(group).ok_or_else(|| Error::Unsupported(format!("DH group {group}")))?;
        self.dh_pair = dh.generate()?;
        self.suite.dh = Some(dh);
        self.dh_group = group;
        self.spi_i = random_nonzero_u64();
        self.nonce_i = random_bytes(self.cfg.ike.nonce_len);
        self.sa_init_base = None;
        self.real_message1.clear();
        self.state = State::New;
        info!("restarting IKE_SA_INIT with DH group {} (new SPIi {:#018x})", group, self.spi_i);
        Ok(())
    }

    /// Handle the IKE_SA_INIT response (raw datagram, non-ESP marker already stripped).
    /// Records `real_message2 = raw`, derives the IKE SA keys, evaluates NAT-D.
    pub fn handle_sa_init_response(&mut self, raw: &[u8]) -> Result<SaInitOutcome> {
        if self.state != State::SaInitSent {
            return Err(Error::Protocol(format!("IKE_SA_INIT response in state {:?}", self.state)));
        }
        debug!("IKE_SA_INIT response hex: {}", hex::encode(raw));
        let msg = IkeMessage::decode_plain(raw)?;
        let h = &msg.header;
        if h.exchange_type != EXCH_IKE_SA_INIT {
            return Err(Error::Decode(format!("expected IKE_SA_INIT response, got exchange {}", h.exchange_type)));
        }
        if !h.is_response() {
            return Err(Error::Decode("IKE_SA_INIT: not a response".into()));
        }
        if h.is_initiator() {
            return Err(Error::Decode("IKE_SA_INIT response has the Initiator flag set".into()));
        }
        if h.message_id != 0 {
            return Err(Error::Decode(format!("IKE_SA_INIT response message id {} (expected 0)", h.message_id)));
        }
        if h.spi_i != self.spi_i {
            return Err(Error::Decode(format!(
                "IKE_SA_INIT response SPIi {:#018x} != ours {:#018x}",
                h.spi_i, self.spi_i
            )));
        }

        // COOKIE (§2.6): retry with the cookie first, everything else identical.
        if let Some(c) = msg.notify(N_COOKIE) {
            if c.data.len() < COOKIE_LEN_MIN || c.data.len() > COOKIE_LEN_MAX {
                return Err(Error::Decode(format!("COOKIE of {} bytes (expected 1..=64)", c.data.len())));
            }
            info!("IKE_SA_INIT: responder demands a COOKIE ({} bytes); retrying", c.data.len());
            return Ok(SaInitOutcome::RetryWithCookie(c.data.clone()));
        }
        // INVALID_KE_PAYLOAD: full restart with the requested group (if configured).
        if let Some(n) = msg.notify(N_INVALID_KE_PAYLOAD) {
            let group = match n.data.as_slice() {
                [a, b] => u16::from_be_bytes([*a, *b]),
                d => return Err(Error::Decode(format!("INVALID_KE_PAYLOAD data of {} bytes (expected 2)", d.len()))),
            };
            if !self.cfg.ike.proposals.iter().any(|p| p.dh_groups.contains(&group)) {
                return Err(Error::PeerNotify {
                    notify_type: N_INVALID_KE_PAYLOAD,
                    name: notify_name(N_INVALID_KE_PAYLOAD),
                    exchange: "IKE_SA_INIT",
                    data: n.data.clone(),
                });
            }
            info!("IKE_SA_INIT: responder requests DH group {group}");
            self.restart_with_group(group)?;
            return Ok(SaInitOutcome::RetryWithGroup(group));
        }
        if let Some(e) = msg.error_notify("IKE_SA_INIT") {
            return Err(e);
        }

        let spi_r = h.spi_r;
        if spi_r == 0 {
            return Err(Error::Decode("IKE_SA_INIT response has SPIr = 0".into()));
        }
        let sa = msg.sa().ok_or_else(|| Error::Decode("IKE_SA_INIT response lacks SA".into()))?;
        let ke = msg.ke().ok_or_else(|| Error::Decode("IKE_SA_INIT response lacks KE".into()))?;
        let nr = msg.nonce().ok_or_else(|| Error::Decode("IKE_SA_INIT response lacks Nonce".into()))?;
        check_nonce(nr, "IKE_SA_INIT response")?;

        let (chosen, offered) = select_response_proposal(sa, &self.ike_proposals, PROTO_IKE)?;
        let suite = suite_from_ike_proposal(chosen, offered)?;
        if ke.group != self.dh_group {
            return Err(Error::Decode(format!(
                "IKE_SA_INIT response KE group {} != ours {}",
                ke.group, self.dh_group
            )));
        }
        let shared = self.dh_pair.shared_secret(&ke.public)?;
        let keys = derive_ike_keys(&suite, &self.nonce_i, nr, &shared, self.spi_i, spi_r);
        drop(shared);

        let sent_nat_d = self.remote.is_ipv4();
        let nat_status = if sent_nat_d {
            let notifies: Vec<&NotifyPayload> = msg.notifies().collect();
            nat::evaluate(self.spi_i, spi_r, self.local, self.remote, &notifies, self.cfg.ike.natt.force_udp_encap)?
        } else {
            NatStatus::default()
        };
        self.peer_fragmentation = msg.notify(N_IKEV2_FRAGMENTATION_SUPPORTED).is_some();

        self.suite = suite;
        self.keys = keys;
        self.spi_r = spi_r;
        self.nonce_r = nr.to_vec();
        self.real_message2 = raw.to_vec();
        self.nat = Some(nat_status);
        self.our_msgid = 1;
        self.state = State::SaInitDone;
        info!(
            "IKE_SA_INIT done: SPIr={:#018x} suite {}/{}/{}/DH{} nat={:?} peer_frag={}",
            spi_r,
            registry::transform_name(TT_ENCR, self.suite.cipher.transform_id()),
            registry::transform_name(TT_INTEG, self.suite.integrity.transform_id()),
            registry::transform_name(TT_PRF, self.suite.prf.transform_id()),
            self.dh_group,
            nat_status,
            self.peer_fragmentation
        );
        Ok(SaInitOutcome::Established { nat: nat_status })
    }

    /// Update the local address (e.g. egress learned late); used by NAT-D evaluation.
    pub fn set_local_addr(&mut self, local: SocketAddr) {
        self.local = local;
    }

    // -----------------------------------------------------------------------
    // IKE_AUTH
    // -----------------------------------------------------------------------

    fn request(&self, exchange: u8, payloads: Vec<Payload>) -> IkeMessage {
        IkeMessage::new(self.spi_i, self.spi_r, exchange, FLAG_INITIATOR, self.our_msgid, payloads)
    }

    fn response(&self, exchange: u8, message_id: u32, payloads: Vec<Payload>) -> IkeMessage {
        IkeMessage::new(self.spi_i, self.spi_r, exchange, FLAG_INITIATOR | FLAG_RESPONSE, message_id, payloads)
    }

    /// Child proposals with the given inbound SPI filled in.
    fn child_proposals_with_spi(&self, spi_in: u32) -> Vec<Proposal> {
        self.child_proposals
            .iter()
            .map(|p| Proposal { spi: spi_in.to_be_bytes().to_vec(), ..p.clone() })
            .collect()
    }

    /// First IKE_AUTH request (msgid 1): `IDi, IDr, N(EAP_ONLY), N(MOBIKE), [N(INITIAL_CONTACT)],
    /// SA(ESP), TSi, TSr, CP(CFG_REQUEST)` — no AUTH (EAP-only).
    pub fn build_auth_initial(&mut self) -> Result<IkeMessage> {
        if self.state != State::SaInitDone {
            return Err(Error::Protocol(format!("build_auth_initial in state {:?}", self.state)));
        }
        let mut payloads = vec![Payload::IdI(self.id_i.clone()), Payload::IdR(self.id_r_cfg.clone())];
        if self.cfg.ike.eap_only {
            payloads.push(Payload::Notify(NotifyPayload::status(N_EAP_ONLY_AUTHENTICATION, Vec::new())));
        }
        if self.cfg.ike.mobike {
            payloads.push(Payload::Notify(NotifyPayload::status(N_MOBIKE_SUPPORTED, Vec::new())));
        }
        if self.cfg.ike.initial_contact {
            payloads.push(Payload::Notify(NotifyPayload::status(N_INITIAL_CONTACT, Vec::new())));
        }
        payloads.push(Payload::Sa(SaPayload { proposals: self.child_proposals_with_spi(self.child_spi_in) }));
        payloads.push(Payload::TsI(self.child_ts_i.clone()));
        payloads.push(Payload::TsR(self.child_ts_r.clone()));
        payloads.push(Payload::Cp(ConfigPayload::request(&self.cfg.child.cfg_requests)));
        let msg = self.request(EXCH_IKE_AUTH, payloads);
        info!(
            "IKE_AUTH #1 request: msgid {} child SPI_in {:#010x}, {} payloads",
            self.our_msgid,
            self.child_spi_in,
            msg.payloads.len()
        );
        self.state = State::AuthInitialSent;
        Ok(msg)
    }

    /// Common checks for an IKE_AUTH / CREATE_CHILD_SA / INFORMATIONAL response on the
    /// current SA; consumes our message id on success.
    fn accept_response(&mut self, msg: &IkeMessage, exchange: u8, what: &'static str) -> Result<()> {
        let h = &msg.header;
        if !h.is_response() {
            return Err(Error::Protocol(format!("{what}: not a response")));
        }
        if h.spi_i != self.spi_i || h.spi_r != self.spi_r {
            return Err(Error::Protocol(format!(
                "{what}: SPIs {:#018x}/{:#018x} do not match the IKE SA",
                h.spi_i, h.spi_r
            )));
        }
        if h.message_id != self.our_msgid {
            return Err(Error::Protocol(format!(
                "{what}: message id {} (expected {}){}",
                h.message_id,
                self.our_msgid,
                if self.our_msgid > 0 && h.message_id == self.our_msgid - 1 { " — retransmitted response, ignore" } else { "" }
            )));
        }
        if h.exchange_type != exchange {
            // Consumed anyway (the id was used); AOSP treats a wrong exchange as fatal.
            self.our_msgid = self.our_msgid.wrapping_add(1);
            return Err(Error::Protocol(format!(
                "{what}: exchange type {} (expected {})",
                h.exchange_type, exchange
            )));
        }
        self.our_msgid = self.our_msgid.wrapping_add(1);
        Ok(())
    }

    /// Handle an IKE_AUTH response for whichever IKE_AUTH request is outstanding.
    pub fn handle_auth_response(&mut self, msg: &IkeMessage) -> Result<AuthResponse> {
        match self.state {
            State::AuthInitialSent => {
                self.accept_response(msg, EXCH_IKE_AUTH, "IKE_AUTH #1 response")?;
                self.handle_auth_first(msg)
            }
            State::InEap => {
                self.accept_response(msg, EXCH_IKE_AUTH, "IKE_AUTH (EAP) response")?;
                self.handle_auth_eap_round(msg)
            }
            State::AuthFinalSent => {
                self.accept_response(msg, EXCH_IKE_AUTH, "IKE_AUTH final response")?;
                self.handle_auth_final(msg)
            }
            s => Err(Error::Protocol(format!("IKE_AUTH response in state {s:?}"))),
        }
    }

    fn handle_auth_first(&mut self, msg: &IkeMessage) -> Result<AuthResponse> {
        if let Some(id_r) = msg.id_r() {
            if !self.cfg.identity.accept_any_remote_id && *id_r != self.id_r_cfg {
                return Err(Error::AuthFailed(format!(
                    "responder identity {:?} does not match configured {:?}",
                    id_r, self.id_r_cfg
                )));
            }
            info!(
                "IKE_AUTH #1: IDr type {} {:?}",
                id_r.id_type,
                String::from_utf8_lossy(&id_r.data)
            );
            self.id_r_received = Some(id_r.clone());
        } else {
            warn!("IKE_AUTH #1 response carries no IDr; post-EAP AUTH verification will need one");
        }
        if let Some(e) = msg.error_notify("IKE_AUTH") {
            return Err(e);
        }
        if msg.auth().is_some() {
            warn!("IKE_AUTH #1 response unexpectedly carries AUTH (EAP-only requested); not verified (no certificate validation)");
        }
        if msg.payloads.iter().any(|p| matches!(p, Payload::Cert(_))) {
            debug!("IKE_AUTH #1 response carries CERT payload(s); ignored");
        }
        if msg.notify(N_MOBIKE_SUPPORTED).is_some() {
            debug!("responder supports MOBIKE");
        }
        let eap = msg.eap().ok_or_else(|| Error::AuthFailed("IKE_AUTH #1 response lacks an EAP payload".into()))?;
        self.state = State::InEap;
        Ok(AuthResponse::EapRequest(eap.to_vec()))
    }

    /// EAP round: IKE_AUTH request carrying only `EAP`.
    pub fn build_auth_eap(&mut self, eap_response: &[u8]) -> Result<IkeMessage> {
        if self.state != State::InEap {
            return Err(Error::Protocol(format!("build_auth_eap in state {:?}", self.state)));
        }
        let msg = self.request(EXCH_IKE_AUTH, vec![Payload::Eap(eap_response.to_vec())]);
        debug!("IKE_AUTH EAP request: msgid {} EAP {} bytes", self.our_msgid, eap_response.len());
        Ok(msg)
    }

    fn handle_auth_eap_round(&mut self, msg: &IkeMessage) -> Result<AuthResponse> {
        if let Some(e) = msg.error_notify("IKE_AUTH") {
            return Err(e);
        }
        let eap = msg.eap().ok_or_else(|| Error::AuthFailed("IKE_AUTH (EAP) response lacks an EAP payload".into()))?;
        Ok(AuthResponse::EapRequest(eap.to_vec()))
    }

    /// Install the EAP MSK: the post-EAP AUTH is `SharedKeyAuth { key: msk }` (method 2).
    pub fn set_msk(&mut self, msk: Vec<u8>) {
        debug!("MSK installed ({} bytes)", msk.len());
        self.auth = Some(Box::new(SharedKeyAuth::new(msk)));
    }

    /// Post-EAP IKE_AUTH request carrying only `AUTH` (§5.3).
    pub fn build_auth_final(&mut self) -> Result<IkeMessage> {
        if self.state != State::InEap {
            return Err(Error::Protocol(format!("build_auth_final in state {:?}", self.state)));
        }
        let auth = self.auth.as_ref().ok_or_else(|| Error::Protocol("build_auth_final before set_msk".into()))?;
        let id_i_body = id_payload_body(&self.id_i);
        let octets = initiator_signed_octets(
            self.suite.prf.as_ref(),
            &self.keys.sk_pi,
            &self.real_message1,
            &self.nonce_r,
            &id_i_body,
        );
        let data = auth.compute(self.suite.prf.as_ref(), &octets)?;
        let payload = AuthPayload { method: auth.method_id(), data };
        let msg = self.request(EXCH_IKE_AUTH, vec![Payload::Auth(payload)]);
        info!("IKE_AUTH final request: msgid {} AUTH method {}", self.our_msgid, auth.method_id());
        self.state = State::AuthFinalSent;
        Ok(msg)
    }

    fn handle_auth_final(&mut self, msg: &IkeMessage) -> Result<AuthResponse> {
        if let Some(e) = msg.error_notify("IKE_AUTH") {
            return Err(e);
        }
        // --- AUTH ---
        let auth_payload = msg.auth().ok_or_else(|| Error::AuthFailed("post-EAP AUTH payload missing".into()))?;
        let auth = self.auth.as_ref().ok_or_else(|| Error::Protocol("final response before set_msk".into()))?;
        if auth_payload.method != auth.method_id() {
            return Err(Error::AuthFailed(format!(
                "responder AUTH method {} (expected {})",
                auth_payload.method,
                auth.method_id()
            )));
        }
        let id_r = match (&self.id_r_received, msg.id_r()) {
            (Some(first), _) => first.clone(),
            (None, Some(this)) => {
                warn!("no IDr in the first IKE_AUTH response; using the IDr of the final response");
                this.clone()
            }
            (None, None) => return Err(Error::AuthFailed("no IDr received in any IKE_AUTH response".into())),
        };
        let octets = responder_signed_octets(
            self.suite.prf.as_ref(),
            &self.keys.sk_pr,
            &self.real_message2,
            &self.nonce_i,
            &id_payload_body(&id_r),
        );
        auth.verify(self.suite.prf.as_ref(), &octets, &auth_payload.data)?;
        info!("responder AUTH verified (method {})", auth_payload.method);

        // --- child SA ---
        let sa = msg.sa().ok_or_else(|| Error::Protocol("final IKE_AUTH response lacks SA".into()))?;
        let ts_i = msg.ts_i().ok_or_else(|| Error::Protocol("final IKE_AUTH response lacks TSi".into()))?;
        let ts_r = msg.ts_r().ok_or_else(|| Error::Protocol("final IKE_AUTH response lacks TSr".into()))?;
        let offered = self.child_proposals_with_spi(self.child_spi_in);
        let (chosen, ours) = select_response_proposal(sa, &offered, PROTO_ESP)?;
        let spi_out = spi4(&chosen.spi, "SAr2")?;
        let (cipher, integrity) = child_algs_from_proposal(chosen, ours)?;
        if !ts_contained(&self.child_ts_i, ts_i) {
            return Err(Error::Protocol(format!("TS_UNACCEPTABLE: responder TSi {ts_i:?} not within ours")));
        }
        if !ts_contained(&self.child_ts_r, ts_r) {
            return Err(Error::Protocol(format!("TS_UNACCEPTABLE: responder TSr {ts_r:?} not within ours")));
        }
        if msg.ke().is_some() {
            warn!("final IKE_AUTH response carries an unexpected KE payload; ignored");
        }
        let assigned = match msg.cp() {
            Some(cp) if cp.cfg_type == CFG_REPLY => parse_cfg_reply(cp),
            Some(cp) => {
                warn!("final IKE_AUTH response CP has type {} (expected CFG_REPLY); ignored", cp.cfg_type);
                AssignedConfig::default()
            }
            None => {
                warn!("final IKE_AUTH response carries no CP; no addresses assigned");
                AssignedConfig::default()
            }
        };
        let keys = derive_child_keys(
            cipher.as_ref(),
            integrity.as_ref(),
            self.suite.prf.as_ref(),
            &self.keys.sk_d,
            &self.nonce_i,
            &self.nonce_r,
            None,
        );
        let child = ChildSaInfo {
            spi_in: self.child_spi_in,
            spi_out,
            keys,
            cipher,
            integrity,
            replay_window: self.cfg.child.replay_window,
            ts_i: ts_i.clone(),
            ts_r: ts_r.clone(),
            created: Instant::now(),
            lifetime: Duration::from_secs(self.cfg.child.lifetime_secs),
        };
        info!(
            "child SA established: SPI_in {:#010x} SPI_out {:#010x} {} / {}",
            child.spi_in,
            child.spi_out,
            registry::transform_name(TT_ENCR, child.cipher.transform_id()),
            registry::transform_name(TT_INTEG, child.integrity.transform_id())
        );
        self.child_negotiated = Some(Proposal { spi: Vec::new(), ..chosen.clone() });
        self.child = Some(child.clone());
        self.state = State::Established;
        Ok(AuthResponse::Established(Box::new(Established { child, assigned, id_r })))
    }

    // -----------------------------------------------------------------------
    // encode / decode with the IKE SA keys
    // -----------------------------------------------------------------------

    fn require_keys(&self) -> Result<()> {
        if self.keys.sk_ei.is_empty() {
            return Err(Error::Protocol("IKE SA keys not derived yet".into()));
        }
        Ok(())
    }

    /// Encrypt + MAC `msg` with sk_ei/sk_ai (fragmenting per `cfg.ike.fragment_threshold`
    /// only if the peer announced IKEV2_FRAGMENTATION_SUPPORTED). A message addressed
    /// to the previous IKE SA (after an IKE rekey) is sealed with that SA's keys.
    pub fn encode(&self, msg: &IkeMessage) -> Result<Vec<Vec<u8>>> {
        let h = &msg.header;
        if let Some(old) = &self.old_ike
            && h.spi_i == old.spi_i
            && h.spi_r == old.spi_r
            && (h.spi_i != self.spi_i || h.spi_r != self.spi_r)
        {
            debug!("encode: msgid {} on the OLD IKE SA", h.message_id);
            return Ok(vec![msg.encode_encrypted(&old.suite, &old.keys.sk_ei, &old.keys.sk_ai)?]);
        }
        self.require_keys()?;
        let out = if self.peer_fragmentation && self.cfg.ike.fragmentation {
            msg.encode_encrypted_fragmented(&self.suite, &self.keys.sk_ei, &self.keys.sk_ai, self.cfg.ike.fragment_threshold)?
        } else {
            vec![msg.encode_encrypted(&self.suite, &self.keys.sk_ei, &self.keys.sk_ai)?]
        };
        debug!(
            "encode: exch {} msgid {} -> {} datagram(s), {} bytes total",
            h.exchange_type,
            h.message_id,
            out.len(),
            out.iter().map(Vec::len).sum::<usize>()
        );
        Ok(out)
    }

    /// Decrypt + verify a set of datagrams forming one message: a single SK datagram, or
    /// SKF fragments (routed through the internal `Reassembler`), using sk_er/sk_ar.
    pub fn decode(&mut self, datagrams: &[Vec<u8>]) -> Result<IkeMessage> {
        if datagrams.is_empty() {
            return Err(Error::Decode("decode: no datagrams".into()));
        }
        for d in datagrams {
            let h = IkeHeader::decode(d)?;
            let on_old = match &self.old_ike {
                Some(old) => h.spi_i == old.spi_i && h.spi_r == old.spi_r && (h.spi_i != self.spi_i || h.spi_r != self.spi_r),
                None => false,
            };
            if !on_old {
                if h.spi_i != self.spi_i {
                    return Err(Error::Decode(format!(
                        "datagram SPIi {:#018x} does not belong to this IKE SA ({:#018x})",
                        h.spi_i, self.spi_i
                    )));
                }
                self.require_keys()?;
            }
            debug!("decode: exch {} msgid {} {} bytes old_sa={}", h.exchange_type, h.message_id, d.len(), on_old);
            if is_fragment(d) {
                let done = if on_old {
                    let old = self.old_ike.as_ref().ok_or_else(|| Error::Protocol("old IKE SA vanished".into()))?;
                    self.reassembler.push(d, &old.suite, &old.keys.sk_er, &old.keys.sk_ar)?
                } else {
                    self.reassembler.push(d, &self.suite, &self.keys.sk_er, &self.keys.sk_ar)?
                };
                if let Some(m) = done {
                    return Ok(m);
                }
            } else if on_old {
                let old = self.old_ike.as_ref().ok_or_else(|| Error::Protocol("old IKE SA vanished".into()))?;
                return IkeMessage::decode_encrypted(d, &old.suite, &old.keys.sk_er, &old.keys.sk_ar);
            } else {
                return IkeMessage::decode_encrypted(d, &self.suite, &self.keys.sk_er, &self.keys.sk_ar);
            }
        }
        Err(Error::Decode(format!(
            "decode: {} fragment datagram(s) did not complete a message",
            datagrams.len()
        )))
    }

    // -----------------------------------------------------------------------
    // Post-establishment: our requests
    // -----------------------------------------------------------------------

    fn require_established(&self, what: &str) -> Result<()> {
        if self.state != State::Established {
            return Err(Error::Protocol(format!("{what} in state {:?}", self.state)));
        }
        Ok(())
    }

    fn require_idle(&self, what: &str) -> Result<()> {
        self.require_established(what)?;
        if !matches!(self.pending, Pending::None) {
            return Err(Error::Protocol(format!("{what}: another request is outstanding")));
        }
        Ok(())
    }

    /// Empty INFORMATIONAL request (DPD).
    pub fn build_dpd(&mut self) -> Result<IkeMessage> {
        self.require_idle("build_dpd")?;
        self.pending = Pending::Dpd;
        debug!("DPD request: msgid {}", self.our_msgid);
        Ok(self.request(EXCH_INFORMATIONAL, Vec::new()))
    }

    /// INFORMATIONAL request with `Delete(IKE)` (protocol 1, no SPIs). If an IKE rekey just
    /// completed, this deletes the OLD IKE SA (on the old SA, with its keys); otherwise the
    /// current one.
    pub fn build_delete_ike(&mut self) -> Result<IkeMessage> {
        let delete = Payload::Delete(DeletePayload { protocol_id: PROTO_IKE, spis: Vec::new() });
        if let Some(old) = &mut self.old_ike {
            let msgid = old.our_msgid;
            old.delete_msgid = Some(msgid);
            info!("DELETE(IKE) for the old IKE SA {:#018x}/{:#018x} msgid {}", old.spi_i, old.spi_r, msgid);
            return Ok(IkeMessage::new(old.spi_i, old.spi_r, EXCH_INFORMATIONAL, FLAG_INITIATOR, msgid, vec![delete]));
        }
        if self.state != State::Established && self.state != State::Closed {
            // Allowed from any post-SA_INIT state for best-effort teardown, but only with keys.
            self.require_keys()?;
        }
        self.pending = Pending::DeleteIke;
        info!("DELETE(IKE) request: msgid {}", self.our_msgid);
        Ok(self.request(EXCH_INFORMATIONAL, vec![delete]))
    }

    /// INFORMATIONAL request with `Delete(ESP, [spi_in])` — our inbound SPI.
    pub fn build_delete_child(&mut self, spi_in: u32) -> Result<IkeMessage> {
        self.require_idle("build_delete_child")?;
        let known = self.child.as_ref().map(|c| c.spi_in == spi_in).unwrap_or(false)
            || self.old_child.as_ref().map(|c| c.spi_in == spi_in).unwrap_or(false);
        if !known {
            warn!("build_delete_child: SPI {:#010x} is not a known inbound child SPI", spi_in);
        }
        self.pending = Pending::DeleteChild(spi_in);
        info!("DELETE(ESP {:#010x}) request: msgid {}", spi_in, self.our_msgid);
        Ok(self.request(
            EXCH_INFORMATIONAL,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_ESP, spis: vec![spi_in.to_be_bytes().to_vec()] })],
        ))
    }

    /// Handle the response to `build_dpd` / `build_delete_ike` / `build_delete_child`.
    pub fn handle_informational_response(&mut self, msg: &IkeMessage) -> Result<()> {
        let h = &msg.header;
        // Response on the old IKE SA (its DELETE after a rekey)?
        if let Some(old) = &mut self.old_ike
            && h.spi_i == old.spi_i
            && h.spi_r == old.spi_r
            && (h.spi_i != self.spi_i || h.spi_r != self.spi_r)
        {
            if !h.is_response() {
                return Err(Error::Protocol("old IKE SA: not a response".into()));
            }
            if Some(h.message_id) != old.delete_msgid {
                return Err(Error::Protocol(format!(
                    "old IKE SA: response msgid {} (expected {:?})",
                    h.message_id, old.delete_msgid
                )));
            }
            if h.exchange_type != EXCH_INFORMATIONAL {
                return Err(Error::Protocol(format!("old IKE SA: exchange {} (expected INFORMATIONAL)", h.exchange_type)));
            }
            if !msg.payloads.is_empty() {
                warn!("old IKE SA DELETE response is not empty ({} payloads)", msg.payloads.len());
            }
            info!("old IKE SA {:#018x}/{:#018x} deleted", old.spi_i, old.spi_r);
            self.old_ike = None;
            return Ok(());
        }

        self.accept_response(msg, EXCH_INFORMATIONAL, "INFORMATIONAL response")?;
        let pending = std::mem::replace(&mut self.pending, Pending::None);
        match pending {
            Pending::Dpd => {
                debug!("DPD response received (peer alive)");
                Ok(())
            }
            Pending::DeleteIke => {
                if !msg.payloads.is_empty() {
                    warn!("DELETE(IKE) response is not empty ({} payloads)", msg.payloads.len());
                }
                info!("IKE SA deleted by us");
                self.state = State::Closed;
                self.child = None;
                self.old_child = None;
                Ok(())
            }
            Pending::DeleteChild(spi_in) => {
                if let Some(e) = msg.error_notify("INFORMATIONAL") {
                    return Err(e);
                }
                let expected_out = [self.child.as_ref(), self.old_child.as_ref()]
                    .into_iter()
                    .flatten()
                    .find(|c| c.spi_in == spi_in)
                    .map(|c| c.spi_out);
                let acked = msg
                    .deletes()
                    .filter(|d| d.protocol_id == PROTO_ESP)
                    .flat_map(|d| d.spis.iter())
                    .filter_map(|s| spi4(s, "DELETE response").ok())
                    .any(|s| Some(s) == expected_out);
                if !acked {
                    warn!(
                        "DELETE(ESP) response does not carry the peer SPI {:?} for our {:#010x}",
                        expected_out.map(|s| format!("{s:#010x}")),
                        spi_in
                    );
                }
                if self.old_child.as_ref().map(|c| c.spi_in == spi_in).unwrap_or(false) {
                    self.old_child = None;
                } else if self.child.as_ref().map(|c| c.spi_in == spi_in).unwrap_or(false) {
                    self.child = self.old_child.take();
                }
                info!("child SA {:#010x} deleted", spi_in);
                Ok(())
            }
            Pending::None => {
                warn!("unsolicited INFORMATIONAL response (msgid {})", h.message_id);
                Ok(())
            }
            other => {
                // A CREATE_CHILD_SA request answered with INFORMATIONAL: an error.
                self.pending = Pending::None;
                let _ = other;
                match msg.error_notify("INFORMATIONAL") {
                    Some(e) => Err(e),
                    None => Err(Error::Protocol("INFORMATIONAL response to a CREATE_CHILD_SA request".into())),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Peer-initiated requests
    // -----------------------------------------------------------------------

    /// Handle a request from the peer (RESPONSE flag clear). Returns the response to send
    /// and what happened. A retransmitted request (msgid = expected - 1) gets the cached
    /// response with `PeerEvent::Other`.
    pub fn handle_peer_request(&mut self, msg: &IkeMessage) -> Result<(IkeMessage, PeerEvent)> {
        let h = &msg.header;
        if h.is_response() {
            return Err(Error::Protocol("handle_peer_request: message is a response".into()));
        }
        if h.spi_i != self.spi_i || h.spi_r != self.spi_r {
            return Err(Error::Protocol(format!(
                "peer request SPIs {:#018x}/{:#018x} do not match the IKE SA",
                h.spi_i, h.spi_r
            )));
        }
        if h.message_id != self.peer_msgid {
            if let Some((id, cached)) = &self.last_peer_response
                && *id == h.message_id
                && self.peer_msgid == id.wrapping_add(1)
            {
                info!("peer retransmitted request msgid {}; re-sending cached response", id);
                return Ok((cached.clone(), PeerEvent::Other));
            }
            return Err(Error::Protocol(format!(
                "peer request msgid {} (expected {})",
                h.message_id, self.peer_msgid
            )));
        }
        let msgid = h.message_id;
        let (resp, event) = match h.exchange_type {
            EXCH_INFORMATIONAL => self.handle_peer_informational(msg, msgid),
            EXCH_CREATE_CHILD_SA => {
                warn!("peer CREATE_CHILD_SA (rekey) not supported; answering NO_ADDITIONAL_SAS");
                (
                    self.response(
                        EXCH_CREATE_CHILD_SA,
                        msgid,
                        vec![Payload::Notify(NotifyPayload::status(N_NO_ADDITIONAL_SAS, Vec::new()))],
                    ),
                    PeerEvent::Other,
                )
            }
            other => {
                return Err(Error::Protocol(format!("peer request with exchange type {other} on an established SA")));
            }
        };
        self.peer_msgid = self.peer_msgid.wrapping_add(1);
        self.last_peer_response = Some((msgid, resp.clone()));
        Ok((resp, event))
    }

    fn handle_peer_informational(&mut self, msg: &IkeMessage, msgid: u32) -> (IkeMessage, PeerEvent) {
        if msg.payloads.is_empty() {
            debug!("peer DPD msgid {}", msgid);
            return (self.response(EXCH_INFORMATIONAL, msgid, Vec::new()), PeerEvent::Dpd);
        }
        let deletes: Vec<&DeletePayload> = msg.deletes().collect();
        if deletes.iter().any(|d| d.protocol_id == PROTO_IKE) {
            info!("peer deleted the IKE SA (msgid {})", msgid);
            self.state = State::Closed;
            self.child = None;
            self.old_child = None;
            self.pending = Pending::None;
            return (self.response(EXCH_INFORMATIONAL, msgid, Vec::new()), PeerEvent::DeleteIke);
        }
        if !deletes.is_empty() {
            // Peer SPIs are its inbound = our outbound SPIs.
            let peer_spis: Vec<u32> = deletes
                .iter()
                .filter(|d| d.protocol_id == PROTO_ESP)
                .flat_map(|d| d.spis.iter())
                .filter_map(|s| spi4(s, "peer DELETE").ok())
                .collect();
            let mut ours = Vec::new();
            for slot in [&mut self.child, &mut self.old_child] {
                if let Some(c) = slot
                    && peer_spis.contains(&c.spi_out)
                {
                    ours.push(c.spi_in);
                    *slot = None;
                }
            }
            if self.child.is_none() && self.old_child.is_some() {
                self.child = self.old_child.take();
            }
            info!("peer deleted child SA(s) {:?} -> ours {:?}", peer_spis, ours);
            let payloads = if ours.is_empty() {
                Vec::new()
            } else {
                vec![Payload::Delete(DeletePayload {
                    protocol_id: PROTO_ESP,
                    spis: ours.iter().map(|s| s.to_be_bytes().to_vec()).collect(),
                })]
            };
            return (self.response(EXCH_INFORMATIONAL, msgid, payloads), PeerEvent::DeleteChild(ours));
        }
        // Generic INFORMATIONAL: echo COOKIE2 if present, ignore the rest.
        let notifies: Vec<NotifyPayload> = msg.notifies().cloned().collect();
        let mut payloads = Vec::new();
        if let Some(c2) = notifies.iter().find(|n| n.notify_type == N_COOKIE2) {
            payloads.push(Payload::Notify(c2.clone()));
        }
        for n in &notifies {
            debug!("peer INFORMATIONAL notify {} ({})", n.notify_type, notify_name(n.notify_type));
        }
        (self.response(EXCH_INFORMATIONAL, msgid, payloads), PeerEvent::Notify(notifies))
    }

    // -----------------------------------------------------------------------
    // Rekeying
    // -----------------------------------------------------------------------

    /// CREATE_CHILD_SA request: `SA(new SPI), TSi, TSr, Ni, N(REKEY_SA, ESP, spi_in)`.
    pub fn build_rekey_child(&mut self) -> Result<IkeMessage> {
        self.require_idle("build_rekey_child")?;
        let current = self.child.as_ref().ok_or_else(|| Error::Protocol("build_rekey_child: no child SA".into()))?;
        let negotiated = self
            .child_negotiated
            .as_ref()
            .ok_or_else(|| Error::Protocol("build_rekey_child: no negotiated child proposal".into()))?;
        let spi_in = random_nonzero_u32();
        let nonce_i = random_bytes(self.cfg.ike.nonce_len);
        let proposals = vec![Proposal { number: 1, spi: spi_in.to_be_bytes().to_vec(), ..negotiated.clone() }];
        let ts_i = current.ts_i.clone();
        let ts_r = current.ts_r.clone();
        let old_spi_in = current.spi_in;
        let payloads = vec![
            Payload::Sa(SaPayload { proposals: proposals.clone() }),
            Payload::TsI(ts_i.clone()),
            Payload::TsR(ts_r.clone()),
            Payload::Nonce(nonce_i.clone()),
            Payload::Notify(NotifyPayload {
                protocol_id: PROTO_ESP,
                spi: old_spi_in.to_be_bytes().to_vec(),
                notify_type: N_REKEY_SA,
                data: Vec::new(),
            }),
        ];
        info!(
            "CREATE_CHILD_SA (rekey child {:#010x} -> new SPI_in {:#010x}) msgid {}",
            old_spi_in, spi_in, self.our_msgid
        );
        self.pending = Pending::RekeyChild(RekeyChildState { spi_in, nonce_i, proposals, ts_i, ts_r });
        Ok(self.request(EXCH_CREATE_CHILD_SA, payloads))
    }

    /// Handle the child rekey response: new keys via §5.2 with THIS exchange's nonces.
    /// The old child stays in place until deleted (`build_delete_child(old.spi_in)`).
    pub fn handle_rekey_child_response(&mut self, msg: &IkeMessage) -> Result<ChildSaInfo> {
        if !matches!(self.pending, Pending::RekeyChild(_)) {
            return Err(Error::Protocol("no child rekey outstanding".into()));
        }
        self.accept_response(msg, EXCH_CREATE_CHILD_SA, "CREATE_CHILD_SA (rekey child) response")?;
        let st = match std::mem::replace(&mut self.pending, Pending::None) {
            Pending::RekeyChild(s) => s,
            _ => return Err(Error::Protocol("no child rekey outstanding".into())),
        };
        if let Some(e) = msg.error_notify("CREATE_CHILD_SA") {
            return Err(e);
        }
        let sa = msg.sa().ok_or_else(|| Error::Protocol("rekey child response lacks SA".into()))?;
        let nr = msg.nonce().ok_or_else(|| Error::Protocol("rekey child response lacks Nonce".into()))?;
        check_nonce(nr, "rekey child response")?;
        let ts_i = msg.ts_i().ok_or_else(|| Error::Protocol("rekey child response lacks TSi".into()))?;
        let ts_r = msg.ts_r().ok_or_else(|| Error::Protocol("rekey child response lacks TSr".into()))?;
        let (chosen, ours) = select_response_proposal(sa, &st.proposals, PROTO_ESP)?;
        let spi_out = spi4(&chosen.spi, "rekey SAr2")?;
        let (cipher, integrity) = child_algs_from_proposal(chosen, ours)?;
        if !ts_contained(&st.ts_i, ts_i) || !ts_contained(&st.ts_r, ts_r) {
            return Err(Error::Protocol("TS_UNACCEPTABLE in rekey child response".into()));
        }
        if msg.ke().is_some() {
            warn!("rekey child response carries an unexpected KE payload (no PFS requested); ignored");
        }
        let keys = derive_child_keys(
            cipher.as_ref(),
            integrity.as_ref(),
            self.suite.prf.as_ref(),
            &self.keys.sk_d,
            &st.nonce_i,
            nr,
            None,
        );
        let lifetime = Duration::from_secs(self.cfg.child.lifetime_secs);
        let new = ChildSaInfo {
            spi_in: st.spi_in,
            spi_out,
            keys,
            cipher,
            integrity,
            replay_window: self.cfg.child.replay_window,
            ts_i: ts_i.clone(),
            ts_r: ts_r.clone(),
            created: Instant::now(),
            lifetime,
        };
        info!("child SA rekeyed: new SPI_in {:#010x} SPI_out {:#010x}", new.spi_in, new.spi_out);
        self.child_negotiated = Some(Proposal { spi: Vec::new(), ..chosen.clone() });
        self.old_child = self.child.replace(new.clone());
        Ok(new)
    }

    /// CREATE_CHILD_SA request rekeying the IKE SA: `SA(IKE, new 8-byte SPI), KE, Ni`.
    pub fn build_rekey_ike(&mut self) -> Result<IkeMessage> {
        self.require_idle("build_rekey_ike")?;
        if self.old_ike.is_some() {
            return Err(Error::Protocol("previous IKE SA not yet deleted".into()));
        }
        let dh = self.suite.dh.clone().ok_or_else(|| Error::Protocol("IKE suite has no DH group".into()))?;
        let dh_pair = dh.generate()?;
        let spi_i = random_nonzero_u64();
        let nonce_i = random_bytes(self.cfg.ike.nonce_len);
        // The negotiated IKE transforms, with an 8-byte SPI.
        let transforms = vec![
            Transform { ttype: TT_ENCR, id: self.suite.cipher.transform_id(), key_len_bits: self.suite.cipher.key_len_attr_bits() },
            Transform::new(TT_INTEG, self.suite.integrity.transform_id()),
            Transform::new(TT_DH, dh.group_id()),
            Transform::new(TT_PRF, self.suite.prf.transform_id()),
        ];
        let proposal = Proposal { number: 1, protocol_id: PROTO_IKE, spi: spi_i.to_be_bytes().to_vec(), transforms };
        let payloads = vec![
            Payload::Sa(SaPayload { proposals: vec![proposal.clone()] }),
            Payload::Ke(KePayload { group: dh.group_id(), public: dh_pair.public_value() }),
            Payload::Nonce(nonce_i.clone()),
        ];
        info!("CREATE_CHILD_SA (rekey IKE, new SPIi {:#018x}) msgid {}", spi_i, self.our_msgid);
        self.pending = Pending::RekeyIke(RekeyIkeState { spi_i, nonce_i, dh_pair, proposal });
        Ok(self.request(EXCH_CREATE_CHILD_SA, payloads))
    }

    /// Handle the IKE rekey response: derive the new SA's keys (§5.1 rekey) and swap to it
    /// (message ids restart at 0). The old SA is kept for its DELETE: call
    /// `build_delete_ike()` next — it targets the old SA — and feed the reply to
    /// `handle_informational_response`.
    pub fn handle_rekey_ike_response(&mut self, msg: &IkeMessage) -> Result<()> {
        if !matches!(self.pending, Pending::RekeyIke(_)) {
            return Err(Error::Protocol("no IKE rekey outstanding".into()));
        }
        self.accept_response(msg, EXCH_CREATE_CHILD_SA, "CREATE_CHILD_SA (rekey IKE) response")?;
        let st = match std::mem::replace(&mut self.pending, Pending::None) {
            Pending::RekeyIke(s) => s,
            _ => return Err(Error::Protocol("no IKE rekey outstanding".into())),
        };
        if let Some(e) = msg.error_notify("CREATE_CHILD_SA") {
            return Err(e);
        }
        let sa = msg.sa().ok_or_else(|| Error::Protocol("rekey IKE response lacks SA".into()))?;
        let ke = msg.ke().ok_or_else(|| Error::Protocol("rekey IKE response lacks KE".into()))?;
        let nr = msg.nonce().ok_or_else(|| Error::Protocol("rekey IKE response lacks Nonce".into()))?;
        check_nonce(nr, "rekey IKE response")?;
        let offered = std::slice::from_ref(&st.proposal);
        let (chosen, ours) = select_response_proposal(sa, offered, PROTO_IKE)?;
        let new_spi_r = spi8(&chosen.spi, "rekey SAr")?;
        let suite = suite_from_ike_proposal(chosen, ours)?;
        let group = suite.dh.as_ref().map(|d| d.group_id()).unwrap_or(0);
        if ke.group != group {
            return Err(Error::Protocol(format!("rekey IKE response KE group {} != ours {}", ke.group, group)));
        }
        let shared = st.dh_pair.shared_secret(&ke.public)?;
        let keys = derive_ike_keys_rekey(&suite, &self.keys.sk_d, &shared, &st.nonce_i, nr, st.spi_i, new_spi_r);
        drop(shared);

        let old_keys = std::mem::replace(&mut self.keys, keys);
        let old_suite = std::mem::replace(&mut self.suite, suite);
        self.old_ike = Some(OldIkeSa {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            suite: old_suite,
            keys: old_keys,
            our_msgid: self.our_msgid,
            delete_msgid: None,
        });
        self.spi_i = st.spi_i;
        self.spi_r = new_spi_r;
        self.nonce_i = st.nonce_i;
        self.nonce_r = nr.to_vec();
        self.our_msgid = 0;
        self.peer_msgid = 0;
        self.last_peer_response = None;
        self.reassembler = Reassembler::new();
        info!(
            "IKE SA rekeyed: new SPIs {:#018x}/{:#018x}; old SA kept until deleted",
            self.spi_i, self.spi_r
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn spi_i(&self) -> u64 {
        self.spi_i
    }
    pub fn spi_r(&self) -> u64 {
        self.spi_r
    }
    /// Message id the next request we build will carry.
    pub fn next_message_id(&self) -> u32 {
        self.our_msgid
    }
    /// Next message id we expect from the peer.
    pub fn peer_next_message_id(&self) -> u32 {
        self.peer_msgid
    }
    pub fn nat(&self) -> Option<NatStatus> {
        self.nat
    }
    pub fn suite(&self) -> &Suite {
        &self.suite
    }
    /// IKE SA keys (all fields empty until `handle_sa_init_response` succeeds).
    pub fn keys(&self) -> &IkeKeys {
        &self.keys
    }
    pub fn child(&self) -> Option<&ChildSaInfo> {
        self.child.as_ref()
    }
    /// The previous child SA after a rekey, until it is deleted.
    pub fn old_child(&self) -> Option<&ChildSaInfo> {
        self.old_child.as_ref()
    }
    pub fn established(&self) -> bool {
        self.state == State::Established
    }
    /// True once the peer announced IKEV2_FRAGMENTATION_SUPPORTED.
    pub fn peer_supports_fragmentation(&self) -> bool {
        self.peer_fragmentation
    }
    /// The IKE_SA_INIT request as finally sent (RealMessage1).
    pub fn real_message1(&self) -> &[u8] {
        &self.real_message1
    }
    /// The IKE_SA_INIT response as received (RealMessage2).
    pub fn real_message2(&self) -> &[u8] {
        &self.real_message2
    }
    /// Our inbound child SPI proposed in IKE_AUTH.
    pub fn child_spi_in(&self) -> u32 {
        self.child_spi_in
    }
}

// ---------------------------------------------------------------------------
// Tests: a simulated responder built from the same crypto/codec modules.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::ike::fragment::decode_datagrams;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::net::{IpAddr, SocketAddrV4};

    const LOCAL_ID: &str = "900999990302421609@prodepdg.t-mobile.com";
    const APN: &str = "ims.tmus";
    const EPDG_ID: &str = "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org";

    fn local() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 54321))
    }
    fn remote() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 500))
    }

    fn test_config() -> Config {
        Config {
            gateway: GatewayConfig {
                hostname: "ns.sipgeo.t-mobile.com".into(),
                fallback_addr: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                ike_port: PORT_IKE,
                natt_port: PORT_NATT,
                local_addr: None,
            },
            identity: IdentityConfig {
                local_id: IdSpec::from_string(LOCAL_ID),
                remote_id: IdSpec::fqdn(APN),
                accept_any_remote_id: true,
                eap_identity: LOCAL_ID.as_bytes().to_vec(),
            },
            eap_tls: EapTlsCredentials {
                client_cert_pem: String::new(),
                client_key_pem: String::new(),
                server_ca_pem: None,
                validate_server_cert: false,
                tls_server_name: None,
                max_fragment_len: 1024,
                allow_tls13: false,
            },
            ike: IkeConfig {
                proposals: vec![IkeProposal {
                    encryption: vec!["AES-256".into()],
                    integrity: vec!["SHA2-256".into()],
                    prf: vec!["SHA2-256".into()],
                    dh_groups: vec![DH_MODP_2048],
                }],
                lifetime_secs: 80000,
                eap_only: true,
                eap_method: "EAP-TLS".into(),
                dpd: DpdConfig::default(),
                natt: NattConfig::default(),
                retransmit: RetransmitConfig::default(),
                fragmentation: true,
                fragment_threshold: 1280,
                signature_hash_algorithms: true,
                mobike: true,
                initial_contact: false,
                nonce_len: 32,
                rekey_margin_fraction: 0.1,
            },
            child: ChildConfig {
                proposals: vec![ChildProposal {
                    encryption: vec!["AES-256".into()],
                    integrity: vec!["SHA2-256".into()],
                    dh_groups: vec![],
                }],
                lifetime_secs: 3600,
                replay_window: 12,
                cfg_requests: default_cfg_requests(),
                install_policies: true,
            },
            ims: ImsConfig {
                pcscf_address: String::new(),
                apn: APN.into(),
                impu: String::new(),
                sip_realm: String::new(),
                username: String::new(),
                password: String::new(),
                imsi: String::new(),
                token: None,
            },
        }
    }

    fn hmac256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256>>::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }

    fn payload_types(m: &IkeMessage) -> Vec<u8> {
        m.payloads.iter().map(Payload::payload_type).collect()
    }

    fn notify_types(m: &IkeMessage) -> Vec<u16> {
        m.notifies().map(|n| n.notify_type).collect()
    }

    /// The gateway side, using the same crypto modules.
    struct Responder {
        spi_i: u64,
        spi_r: u64,
        suite: Suite,
        keys: Option<IkeKeys>,
        ni: Vec<u8>,
        nr: Vec<u8>,
        raw2: Vec<u8>,
        id_r: IdPayload,
        msk: Vec<u8>,
        child_spi: u32,
        frag: bool,
    }

    impl Responder {
        fn new() -> Self {
            Responder {
                spi_i: 0,
                spi_r: random_nonzero_u64(),
                suite: crate::ike::message::test_support::suite(),
                keys: None,
                ni: Vec::new(),
                nr: random_bytes(32),
                raw2: Vec::new(),
                id_r: IdPayload { id_type: ID_FQDN, data: EPDG_ID.as_bytes().to_vec() },
                msk: (0u8..64).collect(),
                child_spi: 0x5a5a1234,
                frag: true,
            }
        }

        /// Answer IKE_SA_INIT: derive keys from the request, return the raw response.
        fn sa_init_reply(&mut self, raw1: &[u8]) -> Vec<u8> {
            let req = IkeMessage::decode_plain(raw1).unwrap();
            self.spi_i = req.header.spi_i;
            self.ni = req.nonce().unwrap().to_vec();
            let ke = req.ke().unwrap();
            let dh = registry::dh(ke.group).unwrap();
            let pair = dh.generate().unwrap();
            let shared = pair.shared_secret(&ke.public).unwrap();
            let chosen = req.sa().unwrap().proposals[0].clone();
            let mut payloads = vec![
                Payload::Sa(SaPayload { proposals: vec![chosen] }),
                Payload::Ke(KePayload { group: ke.group, public: pair.public_value() }),
                Payload::Nonce(self.nr.clone()),
                Payload::Notify(NotifyPayload::status(
                    N_NAT_DETECTION_SOURCE_IP,
                    nat::nat_detection_hash(self.spi_i, self.spi_r, remote().ip(), remote().port()).to_vec(),
                )),
                Payload::Notify(NotifyPayload::status(
                    N_NAT_DETECTION_DESTINATION_IP,
                    nat::nat_detection_hash(self.spi_i, self.spi_r, local().ip(), local().port()).to_vec(),
                )),
            ];
            if self.frag {
                payloads.push(Payload::Notify(NotifyPayload::status(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![])));
            }
            let resp = IkeMessage::new(self.spi_i, self.spi_r, EXCH_IKE_SA_INIT, FLAG_RESPONSE, 0, payloads);
            let raw2 = resp.encode_plain().unwrap();
            self.keys = Some(derive_ike_keys(&self.suite, &self.ni, &self.nr, &shared, self.spi_i, self.spi_r));
            self.raw2 = raw2.clone();
            raw2
        }

        fn keys(&self) -> &IkeKeys {
            self.keys.as_ref().unwrap()
        }

        /// Decrypt what the initiator sent (its direction: sk_ei / sk_ai).
        fn open(&self, datagrams: &[Vec<u8>]) -> IkeMessage {
            decode_datagrams(datagrams, &self.suite, &self.keys().sk_ei, &self.keys().sk_ai).unwrap()
        }

        /// Encrypt a response (our direction: sk_er / sk_ar).
        fn seal_response(&self, exchange: u8, msgid: u32, payloads: Vec<Payload>) -> Vec<Vec<u8>> {
            let m = IkeMessage::new(self.spi_i, self.spi_r, exchange, FLAG_RESPONSE, msgid, payloads);
            vec![m.encode_encrypted(&self.suite, &self.keys().sk_er, &self.keys().sk_ar).unwrap()]
        }

        fn seal_response_fragmented(&self, exchange: u8, msgid: u32, payloads: Vec<Payload>, threshold: usize) -> Vec<Vec<u8>> {
            let m = IkeMessage::new(self.spi_i, self.spi_r, exchange, FLAG_RESPONSE, msgid, payloads);
            m.encode_encrypted_fragmented(&self.suite, &self.keys().sk_er, &self.keys().sk_ar, threshold).unwrap()
        }

        /// Encrypt a peer-initiated request (flags: neither I nor R).
        fn seal_request(&self, exchange: u8, msgid: u32, payloads: Vec<Payload>) -> Vec<Vec<u8>> {
            let m = IkeMessage::new(self.spi_i, self.spi_r, exchange, 0, msgid, payloads);
            vec![m.encode_encrypted(&self.suite, &self.keys().sk_er, &self.keys().sk_ar).unwrap()]
        }

        /// Responder AUTH = prf(prf(MSK, pad), RealMessage2 | Ni | prf(SK_pr, IDr body)).
        fn auth_data(&self, id_r: &IdPayload) -> Vec<u8> {
            let maced = hmac256(&self.keys().sk_pr, &id_payload_body(id_r));
            let mut octets = self.raw2.clone();
            octets.extend_from_slice(&self.ni);
            octets.extend_from_slice(&maced);
            hmac256(&hmac256(&self.msk, KEY_PAD_FOR_IKEV2), &octets)
        }

        /// Expected initiator AUTH over `raw1`.
        fn expected_initiator_auth(&self, raw1: &[u8], id_i: &IdPayload) -> Vec<u8> {
            let maced = hmac256(&self.keys().sk_pi, &id_payload_body(id_i));
            let mut octets = raw1.to_vec();
            octets.extend_from_slice(&self.nr);
            octets.extend_from_slice(&maced);
            hmac256(&hmac256(&self.msk, KEY_PAD_FOR_IKEV2), &octets)
        }

        fn cfg_reply() -> ConfigPayload {
            let v6 = Ipv6Addr::new(0x2607, 0xfb90, 0x1234, 0, 0, 0, 0, 0x42);
            let mut ip6 = v6.octets().to_vec();
            ip6.push(64);
            ConfigPayload {
                cfg_type: CFG_REPLY,
                attributes: vec![
                    ConfigAttribute { attr_type: CFG_INTERNAL_IP6_ADDRESS, value: ip6 },
                    ConfigAttribute { attr_type: CFG_INTERNAL_IP4_ADDRESS, value: vec![10, 20, 30, 40] },
                    ConfigAttribute { attr_type: CFG_INTERNAL_IP6_DNS, value: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x53).octets().to_vec() },
                    ConfigAttribute { attr_type: CFG_INTERNAL_IP4_DNS, value: vec![10, 0, 0, 53] },
                    ConfigAttribute { attr_type: CFG_P_CSCF_IP6_ADDRESS, value: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99).octets().to_vec() },
                    ConfigAttribute { attr_type: CFG_P_CSCF_IP4_ADDRESS, value: vec![10, 0, 0, 99] },
                    ConfigAttribute { attr_type: CFG_INTERNAL_IP4_NETMASK, value: vec![255, 255, 255, 0] },
                    ConfigAttribute { attr_type: CFG_APPLICATION_VERSION, value: b"ePDG 1.0".to_vec() },
                    ConfigAttribute { attr_type: CFG_INTERNAL_IP4_DHCP, value: vec![] },
                ],
            }
        }

        fn narrowed_ts_i() -> TsPayload {
            let a = Ipv6Addr::new(0x2607, 0xfb90, 0x1234, 0, 0, 0, 0, 0x42).octets().to_vec();
            TsPayload {
                selectors: vec![TrafficSelector {
                    ts_type: TS_IPV6_ADDR_RANGE,
                    ip_protocol: 0,
                    start_port: 0,
                    end_port: 65535,
                    start_addr: a.clone(),
                    end_addr: a,
                }],
            }
        }

        fn narrowed_ts_r() -> TsPayload {
            TsPayload { selectors: vec![TrafficSelector::ipv6_any()] }
        }

        /// Final IKE_AUTH response payloads.
        fn final_payloads(&self, req_child: &Proposal, auth: Vec<u8>) -> Vec<Payload> {
            let chosen = Proposal { spi: self.child_spi.to_be_bytes().to_vec(), ..req_child.clone() };
            vec![
                Payload::Auth(AuthPayload { method: AUTH_SHARED_KEY_MIC, data: auth }),
                Payload::Cp(Self::cfg_reply()),
                Payload::Sa(SaPayload { proposals: vec![chosen] }),
                Payload::TsI(Self::narrowed_ts_i()),
                Payload::TsR(Self::narrowed_ts_r()),
                Payload::Notify(NotifyPayload::status(N_MOBIKE_SUPPORTED, vec![])),
            ]
        }
    }

    /// Run IKE_SA_INIT (optionally with a cookie round) and check the request shape.
    fn run_sa_init(init: &mut IkeInitiator, resp: &mut Responder, cookie: bool) -> Vec<u8> {
        let mut raw1 = init.build_sa_init(None).unwrap();
        if cookie {
            let cookie_data: Vec<u8> = (1u8..=24).collect();
            let reply = IkeMessage::new(
                init.spi_i(),
                0,
                EXCH_IKE_SA_INIT,
                FLAG_RESPONSE,
                0,
                vec![Payload::Notify(NotifyPayload::status(N_COOKIE, cookie_data.clone()))],
            )
            .encode_plain()
            .unwrap();
            match init.handle_sa_init_response(&reply).unwrap() {
                SaInitOutcome::RetryWithCookie(c) => assert_eq!(c, cookie_data),
                other => panic!("expected RetryWithCookie, got {other:?}"),
            }
            let first = IkeMessage::decode_plain(&raw1).unwrap();
            raw1 = init.build_sa_init(Some(&cookie_data)).unwrap();
            let second = IkeMessage::decode_plain(&raw1).unwrap();
            assert_eq!(second.header.spi_i, first.header.spi_i);
            assert_eq!(second.header.message_id, 0);
            assert_eq!(second.payloads[0], Payload::Notify(NotifyPayload::status(N_COOKIE, cookie_data)));
            assert_eq!(&second.payloads[1..], &first.payloads[..], "everything after N(COOKIE) must be identical");
            assert_eq!(raw1.len(), 456 + 4 + 4 + 24);
        }
        assert_eq!(init.real_message1(), &raw1[..]);
        let raw2 = resp.sa_init_reply(&raw1);
        match init.handle_sa_init_response(&raw2).unwrap() {
            SaInitOutcome::Established { nat } => {
                assert!(nat.detected);
                assert!(nat.local_behind_nat, "forced by force_udp_encap");
                assert!(!nat.remote_behind_nat);
            }
            other => panic!("expected Established, got {other:?}"),
        }
        assert_eq!(init.real_message2(), &raw2[..]);
        assert_eq!(init.keys().sk_d, resp.keys().sk_d);
        assert_eq!(init.keys().sk_pr, resp.keys().sk_pr);
        assert_eq!(init.spi_r(), resp.spi_r);
        assert_eq!(init.next_message_id(), 1);
        assert!(init.peer_supports_fragmentation());
        raw1
    }

    /// Full handshake through the final IKE_AUTH response.
    fn establish(cookie: bool) -> (IkeInitiator, Responder, Established) {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let raw1 = run_sa_init(&mut init, &mut resp, cookie);

        // --- IKE_AUTH #1 ---
        let m1 = init.build_auth_initial().unwrap();
        assert_eq!(m1.header.message_id, 1);
        assert_eq!(m1.header.flags, FLAG_INITIATOR);
        assert_eq!(m1.header.exchange_type, EXCH_IKE_AUTH);
        assert_eq!(payload_types(&m1), vec![PT_IDI, PT_IDR, PT_NOTIFY, PT_NOTIFY, PT_SA, PT_TSI, PT_TSR, PT_CP]);
        assert_eq!(notify_types(&m1), vec![N_EAP_ONLY_AUTHENTICATION, N_MOBIKE_SUPPORTED]);
        let cp = m1.cp().unwrap();
        assert_eq!(cp.cfg_type, CFG_REQUEST);
        let attr_types: Vec<u16> = cp.attributes.iter().map(|a| a.attr_type).collect();
        assert_eq!(attr_types, vec![1, 8, 3, 10, 2, 20, 21, 7]);
        assert!(cp.attributes.iter().all(|a| a.value.is_empty()));
        let sa = m1.sa().unwrap();
        assert_eq!(sa.proposals.len(), 1);
        let child_req = sa.proposals[0].clone();
        assert_eq!(child_req.protocol_id, PROTO_ESP);
        assert_eq!(child_req.spi, init.child_spi_in().to_be_bytes().to_vec());
        assert_eq!(
            child_req.transforms,
            vec![
                Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                Transform::new(TT_ESN, ESN_NO),
            ]
        );
        assert_eq!(*m1.ts_i().unwrap(), TsPayload::any_v4_v6());
        assert_eq!(*m1.ts_r().unwrap(), TsPayload::any_v4_v6());
        assert!(m1.auth().is_none());
        assert_eq!(m1.id_i().unwrap().data, LOCAL_ID.as_bytes());
        assert_eq!(m1.id_r().unwrap(), &IdPayload { id_type: ID_FQDN, data: APN.as_bytes().to_vec() });

        let d1 = init.encode(&m1).unwrap();
        assert_eq!(d1.len(), 1, "368-byte IKE_AUTH #1 is never fragmented");
        assert_eq!(d1[0].len(), 368, "§14.1 reference size");
        assert_eq!(d1[0][16], PT_SK);
        assert_eq!(d1[0][28], PT_IDI, "SK next payload = IDi");
        let seen = resp.open(&d1);
        assert_eq!(seen.payloads, m1.payloads);

        // Responder: IDr + EAP Request/Identity.
        let eap_identity_req = vec![EAP_CODE_REQUEST, 1, 0, 5, EAP_TYPE_IDENTITY];
        let r1 = resp.seal_response(
            EXCH_IKE_AUTH,
            1,
            vec![Payload::IdR(resp.id_r.clone()), Payload::Eap(eap_identity_req.clone())],
        );
        let r1m = init.decode(&r1).unwrap();
        match init.handle_auth_response(&r1m).unwrap() {
            AuthResponse::EapRequest(e) => assert_eq!(e, eap_identity_req),
            other => panic!("expected EapRequest, got {other:?}"),
        }
        assert_eq!(init.next_message_id(), 2);

        // --- EAP round ---
        let eap_identity_resp = {
            let mut v = vec![EAP_CODE_RESPONSE, 1, 0, 0, EAP_TYPE_IDENTITY];
            v.extend_from_slice(LOCAL_ID.as_bytes());
            let len = v.len() as u16;
            v[2..4].copy_from_slice(&len.to_be_bytes());
            v
        };
        let m2 = init.build_auth_eap(&eap_identity_resp).unwrap();
        assert_eq!(m2.header.message_id, 2);
        assert_eq!(m2.payloads, vec![Payload::Eap(eap_identity_resp.clone())]);
        let d2 = init.encode(&m2).unwrap();
        let seen2 = resp.open(&d2);
        assert_eq!(seen2.eap().unwrap(), &eap_identity_resp[..]);
        assert_eq!(seen2.header.message_id, 2);

        let eap_success = vec![EAP_CODE_SUCCESS, 2, 0, 4];
        let r2 = resp.seal_response(EXCH_IKE_AUTH, 2, vec![Payload::Eap(eap_success.clone())]);
        let r2m = init.decode(&r2).unwrap();
        match init.handle_auth_response(&r2m).unwrap() {
            AuthResponse::EapRequest(e) => assert_eq!(e, eap_success),
            other => panic!("expected EapRequest(Success), got {other:?}"),
        }
        assert_eq!(init.next_message_id(), 3);

        // --- post-EAP AUTH ---
        assert!(matches!(init.build_auth_final(), Err(Error::Protocol(_))), "needs the MSK first");
        init.set_msk(resp.msk.clone());
        let m3 = init.build_auth_final().unwrap();
        assert_eq!(m3.header.message_id, 3);
        assert_eq!(m3.payloads.len(), 1);
        let auth = m3.auth().unwrap();
        assert_eq!(auth.method, AUTH_SHARED_KEY_MIC);
        let id_i = IdPayload { id_type: ID_RFC822_ADDR, data: LOCAL_ID.as_bytes().to_vec() };
        assert_eq!(auth.data, resp.expected_initiator_auth(&raw1, &id_i));
        assert_eq!(auth.data.len(), 32);
        let d3 = init.encode(&m3).unwrap();
        assert_eq!(d3[0].len(), 112, "§14.1 post-EAP request size");
        assert_eq!(d3[0][28], PT_AUTH);
        let seen3 = resp.open(&d3);
        assert_eq!(seen3.payloads, m3.payloads);

        let r3 = resp.seal_response(EXCH_IKE_AUTH, 3, resp.final_payloads(&child_req, resp.auth_data(&resp.id_r)));
        let r3m = init.decode(&r3).unwrap();
        let est = match init.handle_auth_response(&r3m).unwrap() {
            AuthResponse::Established(e) => *e,
            other => panic!("expected Established, got {other:?}"),
        };
        assert!(init.established());
        assert_eq!(init.next_message_id(), 4);
        (init, resp, est)
    }

    // -----------------------------------------------------------------------

    #[test]
    fn sa_init_request_shape() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let raw = init.build_sa_init(None).unwrap();
        assert_eq!(raw.len(), 456, "§14.1 reference size for the glue suite");
        let m = IkeMessage::decode_plain(&raw).unwrap();
        assert_eq!(m.header.flags, FLAG_INITIATOR);
        assert_eq!(m.header.message_id, 0);
        assert_eq!(m.header.spi_r, 0);
        assert_eq!(m.header.spi_i, init.spi_i());
        assert_ne!(m.header.spi_i, 0);
        assert_eq!(m.header.exchange_type, EXCH_IKE_SA_INIT);
        assert_eq!(m.header.next_payload, PT_SA);
        assert_eq!(
            payload_types(&m),
            vec![PT_SA, PT_KE, PT_NONCE, PT_NOTIFY, PT_NOTIFY, PT_NOTIFY, PT_NOTIFY]
        );
        assert_eq!(
            notify_types(&m),
            vec![
                N_NAT_DETECTION_SOURCE_IP,
                N_NAT_DETECTION_DESTINATION_IP,
                N_IKEV2_FRAGMENTATION_SUPPORTED,
                N_SIGNATURE_HASH_ALGORITHMS
            ]
        );
        // SA: one proposal, ENCR(keylen 256) / INTEG / DH / PRF.
        let sa = m.sa().unwrap();
        assert_eq!(sa.proposals.len(), 1);
        let p = &sa.proposals[0];
        assert_eq!((p.number, p.protocol_id, p.spi.len()), (1, PROTO_IKE, 0));
        assert_eq!(
            p.transforms,
            vec![
                Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                Transform::new(TT_DH, DH_MODP_2048),
                Transform::new(TT_PRF, PRF_HMAC_SHA2_256),
            ]
        );
        let mut sa_body = Vec::new();
        Payload::Sa(sa.clone()).encode_body(&mut sa_body).unwrap();
        assert_eq!(sa_body.len() + 4, 48);
        // KE: group 14, 256 bytes.
        let ke = m.ke().unwrap();
        assert_eq!(ke.group, DH_MODP_2048);
        assert_eq!(ke.public.len(), 256);
        // Nonce 32.
        assert_eq!(m.nonce().unwrap().len(), 32);
        // NAT-D over the fake local address and the real remote.
        let src = m.notify(N_NAT_DETECTION_SOURCE_IP).unwrap();
        assert_eq!(
            src.data,
            nat::nat_detection_hash(init.spi_i(), 0, IpAddr::V4(nat::FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4), 54321).to_vec()
        );
        let dst = m.notify(N_NAT_DETECTION_DESTINATION_IP).unwrap();
        assert_eq!(dst.data, nat::nat_detection_hash(init.spi_i(), 0, remote().ip(), 500).to_vec());
        assert!(m.notify(N_IKEV2_FRAGMENTATION_SUPPORTED).unwrap().data.is_empty());
        assert_eq!(m.notify(N_SIGNATURE_HASH_ALGORITHMS).unwrap().data, vec![0, 1, 0, 2, 0, 3, 0, 4]);
        // Rebuilding without a cookie yields identical bytes (same nonce/KE).
        assert_eq!(init.build_sa_init(None).unwrap(), raw);
        assert_eq!(init.real_message1(), &raw[..]);
    }

    #[test]
    fn sa_init_ipv6_gateway_has_no_nat_d() {
        let cfg = test_config();
        let remote6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 500);
        let local6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 4000);
        let mut init = IkeInitiator::new(&cfg, local6, remote6).unwrap();
        let m = IkeMessage::decode_plain(&init.build_sa_init(None).unwrap()).unwrap();
        assert_eq!(notify_types(&m), vec![N_IKEV2_FRAGMENTATION_SUPPORTED, N_SIGNATURE_HASH_ALGORITHMS]);
    }

    #[test]
    fn sa_init_optional_notifies_follow_config() {
        let mut cfg = test_config();
        cfg.ike.fragmentation = false;
        cfg.ike.signature_hash_algorithms = false;
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let m = IkeMessage::decode_plain(&init.build_sa_init(None).unwrap()).unwrap();
        assert_eq!(notify_types(&m), vec![N_NAT_DETECTION_SOURCE_IP, N_NAT_DETECTION_DESTINATION_IP]);
    }

    #[test]
    fn new_rejects_unknown_algorithms() {
        let mut cfg = test_config();
        cfg.ike.proposals[0].encryption = vec!["CAMELLIA-256".into()];
        assert!(matches!(IkeInitiator::new(&cfg, local(), remote()), Err(Error::Unsupported(_))));
        let mut cfg = test_config();
        cfg.child.proposals[0].integrity = vec!["MD5".into()];
        assert!(matches!(IkeInitiator::new(&cfg, local(), remote()), Err(Error::Unsupported(_))));
        let mut cfg = test_config();
        cfg.ike.proposals[0].dh_groups = vec![99];
        assert!(matches!(IkeInitiator::new(&cfg, local(), remote()), Err(Error::Unsupported(_))));
    }

    #[test]
    fn full_flow_establishes_child_and_config() {
        let (init, resp, est) = establish(false);
        assert_eq!(est.child.spi_in, init.child_spi_in());
        assert_eq!(est.child.spi_out, resp.child_spi);
        assert_eq!(est.child.replay_window, 12);
        assert_eq!(est.child.lifetime, Duration::from_secs(3600));
        assert_eq!(est.child.cipher.transform_id(), ENCR_AES_CBC);
        assert_eq!(est.child.integrity.transform_id(), AUTH_HMAC_SHA2_256_128);
        // Keys per §5.2 with the IKE_SA_INIT nonces.
        let expected = derive_child_keys(
            resp.suite.cipher.as_ref(),
            resp.suite.integrity.as_ref(),
            resp.suite.prf.as_ref(),
            &resp.keys().sk_d,
            &resp.ni,
            &resp.nr,
            None,
        );
        assert_eq!(est.child.keys.encr_i2r, expected.encr_i2r);
        assert_eq!(est.child.keys.integ_r2i, expected.integ_r2i);
        // Narrowed TS accepted verbatim.
        assert_eq!(est.child.ts_i, Responder::narrowed_ts_i());
        assert_eq!(est.child.ts_r, Responder::narrowed_ts_r());
        // IDr from the first response.
        assert_eq!(est.id_r, resp.id_r);
        // Assigned config.
        assert_eq!(est.assigned.internal_ipv6, vec![(Ipv6Addr::new(0x2607, 0xfb90, 0x1234, 0, 0, 0, 0, 0x42), 64)]);
        assert_eq!(est.assigned.internal_ipv4, vec![Ipv4Addr::new(10, 20, 30, 40)]);
        assert_eq!(est.assigned.dns_ipv6, vec![Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x53)]);
        assert_eq!(est.assigned.dns_ipv4, vec![Ipv4Addr::new(10, 0, 0, 53)]);
        assert_eq!(est.assigned.pcscf_ipv6, vec![Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99)]);
        assert_eq!(est.assigned.pcscf_ipv4, vec![Ipv4Addr::new(10, 0, 0, 99)]);
        let other_types: Vec<u16> = est.assigned.other.iter().map(|a| a.attr_type).collect();
        assert_eq!(other_types, vec![CFG_INTERNAL_IP4_NETMASK, CFG_APPLICATION_VERSION]);
        assert_eq!(init.child().unwrap().spi_out, resp.child_spi);
        assert!(init.nat().unwrap().detected);
    }

    #[test]
    fn full_flow_with_cookie_retry() {
        let (_init, resp, est) = establish(true);
        assert_eq!(est.child.spi_out, resp.child_spi);
    }

    #[test]
    fn ip6_address_reply_of_16_bytes_tolerated() {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
        let cp = ConfigPayload {
            cfg_type: CFG_REPLY,
            attributes: vec![
                ConfigAttribute { attr_type: CFG_INTERNAL_IP6_ADDRESS, value: v6.octets().to_vec() },
                ConfigAttribute { attr_type: CFG_INTERNAL_IP6_ADDRESS, value: vec![] },
                ConfigAttribute { attr_type: CFG_INTERNAL_IP4_DNS, value: vec![1, 2, 3] },
            ],
        };
        let a = parse_cfg_reply(&cp);
        assert_eq!(a.internal_ipv6, vec![(v6, IP6_ADDRESS_DEFAULT_PREFIX)]);
        assert!(a.dns_ipv4.is_empty());
        assert_eq!(a.other.len(), 1, "malformed DNS kept verbatim");
    }

    #[test]
    fn final_response_with_bad_auth_fails() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        let m1 = init.build_auth_initial().unwrap();
        let child_req = m1.sa().unwrap().proposals[0].clone();
        let _ = init.encode(&m1).unwrap();
        let r1 = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::IdR(resp.id_r.clone()), Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let r1m = init.decode(&r1).unwrap();
        init.handle_auth_response(&r1m).unwrap();
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let _ = init.encode(&m).unwrap();
        // AUTH computed over a DIFFERENT IDr than the one sent first -> mismatch.
        let wrong_id = IdPayload { id_type: ID_FQDN, data: b"other.example".to_vec() };
        let r = resp.seal_response(EXCH_IKE_AUTH, 2, resp.final_payloads(&child_req, resp.auth_data(&wrong_id)));
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::AuthFailed(_))));
        assert!(!init.established());
    }

    #[test]
    fn final_response_wrong_auth_method_fails() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        let m1 = init.build_auth_initial().unwrap();
        let child_req = m1.sa().unwrap().proposals[0].clone();
        let r1 = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::IdR(resp.id_r.clone()), Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let r1m = init.decode(&r1).unwrap();
        init.handle_auth_response(&r1m).unwrap();
        init.set_msk(resp.msk.clone());
        init.build_auth_final().unwrap();
        let mut payloads = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        payloads[0] = Payload::Auth(AuthPayload { method: AUTH_RSA_DIGITAL_SIGNATURE, data: vec![0; 32] });
        let r = resp.seal_response(EXCH_IKE_AUTH, 2, payloads);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::AuthFailed(_))));
    }

    #[test]
    fn final_response_ts_not_contained_rejected() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        let m1 = init.build_auth_initial().unwrap();
        let child_req = m1.sa().unwrap().proposals[0].clone();
        let r1 = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::IdR(resp.id_r.clone()), Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let r1m = init.decode(&r1).unwrap();
        init.handle_auth_response(&r1m).unwrap();
        init.set_msk(resp.msk.clone());
        init.build_auth_final().unwrap();
        let mut payloads = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        // A TCP-only selector was not offered (we offered protocol 0).
        let mut tcp = TrafficSelector::ipv4_any();
        tcp.ip_protocol = 6;
        payloads[3] = Payload::TsI(TsPayload { selectors: vec![tcp] });
        let r = resp.seal_response(EXCH_IKE_AUTH, 2, payloads);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::Protocol(m)) if m.contains("TS_UNACCEPTABLE")));
    }

    #[test]
    fn ts_containment_rules() {
        let ours = TsPayload::any_v4_v6();
        assert!(ts_contained(&ours, &ours));
        assert!(ts_contained(&ours, &Responder::narrowed_ts_i()));
        assert!(!ts_contained(&ours, &TsPayload { selectors: vec![] }));
        let mut ports = TrafficSelector::ipv4_any();
        ports.start_port = 5060;
        ports.end_port = 5061;
        assert!(ts_contained(&ours, &TsPayload { selectors: vec![ports.clone()] }));
        // Ours narrower than theirs -> not contained.
        assert!(!ts_contained(&TsPayload { selectors: vec![ports] }, &ours));
    }

    #[test]
    fn sa_init_error_notify_is_peer_notify() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        init.build_sa_init(None).unwrap();
        let reply = IkeMessage::new(
            init.spi_i(),
            0,
            EXCH_IKE_SA_INIT,
            FLAG_RESPONSE,
            0,
            vec![Payload::Notify(NotifyPayload::status(N_NO_PROPOSAL_CHOSEN, vec![]))],
        )
        .encode_plain()
        .unwrap();
        match init.handle_sa_init_response(&reply) {
            Err(Error::PeerNotify { notify_type, name, exchange, .. }) => {
                assert_eq!(notify_type, N_NO_PROPOSAL_CHOSEN);
                assert_eq!(name, "NO_PROPOSAL_CHOSEN");
                assert_eq!(exchange, "IKE_SA_INIT");
            }
            other => panic!("expected PeerNotify, got {other:?}"),
        }
    }

    #[test]
    fn sa_init_invalid_ke_restarts_with_group() {
        let mut cfg = test_config();
        cfg.ike.proposals[0].dh_groups = vec![DH_MODP_2048, DH_MODP_1024];
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let raw_a = init.build_sa_init(None).unwrap();
        let spi_a = init.spi_i();
        let reply = IkeMessage::new(
            spi_a,
            0,
            EXCH_IKE_SA_INIT,
            FLAG_RESPONSE,
            0,
            vec![Payload::Notify(NotifyPayload::status(N_INVALID_KE_PAYLOAD, DH_MODP_1024.to_be_bytes().to_vec()))],
        )
        .encode_plain()
        .unwrap();
        match init.handle_sa_init_response(&reply).unwrap() {
            SaInitOutcome::RetryWithGroup(g) => assert_eq!(g, DH_MODP_1024),
            other => panic!("expected RetryWithGroup, got {other:?}"),
        }
        let raw_b = init.build_sa_init(None).unwrap();
        assert_ne!(init.spi_i(), spi_a, "full restart: new SPIi");
        let mb = IkeMessage::decode_plain(&raw_b).unwrap();
        assert_eq!(mb.ke().unwrap().group, DH_MODP_1024);
        assert_eq!(mb.ke().unwrap().public.len(), 128);
        let ma = IkeMessage::decode_plain(&raw_a).unwrap();
        assert_ne!(ma.nonce().unwrap(), mb.nonce().unwrap());
        // Unconfigured group -> PeerNotify.
        let reply = IkeMessage::new(
            init.spi_i(),
            0,
            EXCH_IKE_SA_INIT,
            FLAG_RESPONSE,
            0,
            vec![Payload::Notify(NotifyPayload::status(N_INVALID_KE_PAYLOAD, DH_MODP_4096.to_be_bytes().to_vec()))],
        )
        .encode_plain()
        .unwrap();
        assert!(matches!(init.handle_sa_init_response(&reply), Err(Error::PeerNotify { .. })));
    }

    #[test]
    fn sa_init_response_header_checks() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let raw1 = init.build_sa_init(None).unwrap();
        let mut resp = Responder::new();
        let good = resp.sa_init_reply(&raw1);
        // Initiator flag set -> rejected.
        let mut bad = good.clone();
        bad[19] = FLAG_RESPONSE | FLAG_INITIATOR;
        assert!(matches!(init.handle_sa_init_response(&bad), Err(Error::Decode(_))));
        // Wrong message id.
        let mut bad = good.clone();
        bad[23] = 1;
        assert!(matches!(init.handle_sa_init_response(&bad), Err(Error::Decode(_))));
        // Wrong SPIi.
        let mut bad = good.clone();
        bad[0] ^= 0xff;
        assert!(matches!(init.handle_sa_init_response(&bad), Err(Error::Decode(_))));
        // Not a response.
        let mut bad = good.clone();
        bad[19] = 0;
        assert!(matches!(init.handle_sa_init_response(&bad), Err(Error::Decode(_))));
        // Still fine afterwards.
        assert!(matches!(init.handle_sa_init_response(&good), Ok(SaInitOutcome::Established { .. })));
    }

    #[test]
    fn sa_init_rejects_unoffered_transform_and_wrong_group() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let raw1 = init.build_sa_init(None).unwrap();
        let req = IkeMessage::decode_plain(&raw1).unwrap();
        let ke = req.ke().unwrap();
        let pair = registry::dh(14).unwrap().generate().unwrap();
        let spi_i = init.spi_i();
        let mk = |proposal: Proposal, group: u16| {
            IkeMessage::new(
                spi_i,
                0x1111,
                EXCH_IKE_SA_INIT,
                FLAG_RESPONSE,
                0,
                vec![
                    Payload::Sa(SaPayload { proposals: vec![proposal] }),
                    Payload::Ke(KePayload { group, public: pair.public_value() }),
                    Payload::Nonce(vec![9; 32]),
                ],
            )
            .encode_plain()
            .unwrap()
        };
        let mut p = req.sa().unwrap().proposals[0].clone();
        p.transforms[0] = Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 128);
        assert!(matches!(init.handle_sa_init_response(&mk(p, 14)), Err(Error::Protocol(_))));
        let p = req.sa().unwrap().proposals[0].clone();
        let _ = ke;
        assert!(matches!(init.handle_sa_init_response(&mk(p, 15)), Err(Error::Decode(_))));
    }

    #[test]
    fn nat_d_only_one_notify_is_decode_error() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let raw1 = init.build_sa_init(None).unwrap();
        let mut resp = Responder::new();
        let good = resp.sa_init_reply(&raw1);
        let mut m = IkeMessage::decode_plain(&good).unwrap();
        m.payloads.retain(|p| !matches!(p, Payload::Notify(n) if n.notify_type == N_NAT_DETECTION_DESTINATION_IP));
        let bad = m.encode_plain().unwrap();
        assert!(matches!(init.handle_sa_init_response(&bad), Err(Error::Decode(_))));
    }

    #[test]
    fn first_auth_response_requires_eap_and_reports_errors() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        let m1 = init.build_auth_initial().unwrap();
        let _ = init.encode(&m1).unwrap();
        // Error notify.
        let r = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::Notify(NotifyPayload::status(N_AUTHENTICATION_FAILED, vec![]))]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::PeerNotify { notify_type: N_AUTHENTICATION_FAILED, .. })));
        assert_eq!(init.next_message_id(), 2, "the id was consumed even on a protected error");
    }

    #[test]
    fn first_auth_response_without_eap_fails() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        init.build_auth_initial().unwrap();
        let r = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::IdR(resp.id_r.clone())]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::AuthFailed(_))));
    }

    #[test]
    fn remote_id_mismatch_rejected_when_not_accepting_any() {
        let mut cfg = test_config();
        cfg.identity.accept_any_remote_id = false;
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        init.build_auth_initial().unwrap();
        let r = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::IdR(resp.id_r.clone()), Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::AuthFailed(_))));
    }

    #[test]
    fn response_with_wrong_message_id_rejected() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        init.build_auth_initial().unwrap();
        let r = resp.seal_response(EXCH_IKE_AUTH, 7, vec![Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::Protocol(_))));
        assert_eq!(init.next_message_id(), 1);
        // Retransmitted (previous) response id is also rejected without consuming an id.
        let r = resp.seal_response(EXCH_IKE_AUTH, 0, vec![Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::Protocol(_))));
        assert_eq!(init.next_message_id(), 1);
    }

    #[test]
    fn decode_rejects_foreign_spi_and_tampering() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        run_sa_init(&mut init, &mut resp, false);
        let r = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let mut foreign = r[0].clone();
        foreign[3] ^= 1;
        assert!(matches!(init.decode(&[foreign]), Err(Error::Decode(_))));
        let mut tampered = r[0].clone();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(matches!(init.decode(&[tampered]), Err(Error::Integrity(_))));
        assert!(matches!(init.decode(&[]), Err(Error::Decode(_))));
        assert!(init.decode(&r).is_ok());
    }

    #[test]
    fn fragmentation_both_directions() {
        let (mut init, resp, _) = establish(false);
        // A big EAP payload: our request must be split into <= 1280-byte SKF fragments.
        // (State machine is Established; use a DPD-like INFORMATIONAL carrying notifies.)
        let big = NotifyPayload::status(N_SIGNATURE_HASH_ALGORITHMS, vec![0x5a; 3000]);
        let msg = IkeMessage::new(init.spi_i(), init.spi_r(), EXCH_INFORMATIONAL, FLAG_INITIATOR, init.next_message_id(), vec![Payload::Notify(big.clone())]);
        let dgs = init.encode(&msg).unwrap();
        assert!(dgs.len() >= 3);
        assert!(dgs.iter().all(|d| d.len() <= 1280));
        assert!(dgs.iter().all(|d| is_fragment(d)));
        let seen = resp.open(&dgs);
        assert_eq!(seen.payloads, vec![Payload::Notify(big.clone())]);
        // And a fragmented response is reassembled by decode().
        let frags = resp.seal_response_fragmented(EXCH_INFORMATIONAL, 4, vec![Payload::Notify(big.clone())], 1280);
        assert!(frags.len() >= 3);
        // Feed one at a time (as the transport would) — incomplete sets are Decode errors.
        for f in &frags[..frags.len() - 1] {
            assert!(matches!(init.decode(std::slice::from_ref(f)), Err(Error::Decode(_))));
        }
        let m = init.decode(std::slice::from_ref(&frags[frags.len() - 1])).unwrap();
        assert_eq!(m.payloads, vec![Payload::Notify(big)]);
        assert_eq!(m.header.message_id, 4);
    }

    #[test]
    fn no_fragmentation_when_peer_did_not_announce_it() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        resp.frag = false;
        let raw1 = init.build_sa_init(None).unwrap();
        let raw2 = resp.sa_init_reply(&raw1);
        init.handle_sa_init_response(&raw2).unwrap();
        assert!(!init.peer_supports_fragmentation());
        init.build_auth_initial().unwrap();
        // Force InEap so build_auth_eap is allowed.
        let r = resp.seal_response(EXCH_IKE_AUTH, 1, vec![Payload::IdR(resp.id_r.clone()), Payload::Eap(vec![1, 1, 0, 5, 1])]);
        let rm = init.decode(&r).unwrap();
        init.handle_auth_response(&rm).unwrap();
        let m = init.build_auth_eap(&vec![2u8; 3000]).unwrap();
        let dgs = init.encode(&m).unwrap();
        assert_eq!(dgs.len(), 1);
        assert!(dgs[0].len() > 3000);
        assert!(!is_fragment(&dgs[0]));
    }

    #[test]
    fn dpd_round_trip_and_message_ids() {
        let (mut init, resp, _) = establish(false);
        assert_eq!(init.next_message_id(), 4);
        let dpd = init.build_dpd().unwrap();
        assert_eq!(dpd.header.exchange_type, EXCH_INFORMATIONAL);
        assert_eq!(dpd.header.message_id, 4);
        assert!(dpd.payloads.is_empty());
        assert!(matches!(init.build_dpd(), Err(Error::Protocol(_))), "one outstanding request at a time");
        let dg = init.encode(&dpd).unwrap();
        assert_eq!(dg.len(), 1);
        let seen = resp.open(&dg);
        assert!(seen.payloads.is_empty());
        assert_eq!(seen.header.next_payload, PT_NONE, "SK next payload 0 for an empty message");
        let r = resp.seal_response(EXCH_INFORMATIONAL, 4, vec![]);
        let rm = init.decode(&r).unwrap();
        init.handle_informational_response(&rm).unwrap();
        assert_eq!(init.next_message_id(), 5);
        // Second DPD continues the sequence.
        let dpd2 = init.build_dpd().unwrap();
        assert_eq!(dpd2.header.message_id, 5);
    }

    #[test]
    fn peer_dpd_and_retransmission() {
        let (mut init, resp, _) = establish(false);
        let req = resp.seal_request(EXCH_INFORMATIONAL, 0, vec![]);
        let rm = init.decode(&req).unwrap();
        assert!(!rm.header.is_response());
        let (r, ev) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev, PeerEvent::Dpd);
        assert_eq!(r.header.exchange_type, EXCH_INFORMATIONAL);
        assert_eq!(r.header.message_id, 0);
        assert_eq!(r.header.flags, FLAG_INITIATOR | FLAG_RESPONSE);
        assert!(r.payloads.is_empty());
        assert_eq!(init.peer_next_message_id(), 1);
        let dg = init.encode(&r).unwrap();
        let seen = resp.open(&dg);
        assert!(seen.header.is_response());
        // Retransmission of msgid 0 -> cached response, no counter change.
        let (r2, ev2) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev2, PeerEvent::Other);
        assert_eq!(r2, r);
        assert_eq!(init.peer_next_message_id(), 1);
        // Out-of-window id rejected.
        let bad = resp.seal_request(EXCH_INFORMATIONAL, 5, vec![]);
        let bm = init.decode(&bad).unwrap();
        assert!(matches!(init.handle_peer_request(&bm), Err(Error::Protocol(_))));
        // Our own counter is untouched by peer traffic.
        assert_eq!(init.next_message_id(), 4);
    }

    #[test]
    fn peer_delete_ike() {
        let (mut init, resp, _) = establish(false);
        let req = resp.seal_request(
            EXCH_INFORMATIONAL,
            0,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_IKE, spis: vec![] })],
        );
        let rm = init.decode(&req).unwrap();
        let (r, ev) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev, PeerEvent::DeleteIke);
        assert!(r.payloads.is_empty());
        assert_eq!(r.header.message_id, 0);
        assert!(!init.established());
        assert!(init.child().is_none());
    }

    #[test]
    fn peer_delete_child_answers_with_our_spi() {
        let (mut init, resp, est) = establish(false);
        let req = resp.seal_request(
            EXCH_INFORMATIONAL,
            0,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_ESP, spis: vec![resp.child_spi.to_be_bytes().to_vec()] })],
        );
        let rm = init.decode(&req).unwrap();
        let (r, ev) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev, PeerEvent::DeleteChild(vec![est.child.spi_in]));
        let d: Vec<&DeletePayload> = r.deletes().collect();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].protocol_id, PROTO_ESP);
        assert_eq!(d[0].spis, vec![est.child.spi_in.to_be_bytes().to_vec()]);
        assert!(init.child().is_none());
        assert!(init.established(), "IKE SA survives a child delete");
        // Unknown SPI -> empty response.
        let req = resp.seal_request(
            EXCH_INFORMATIONAL,
            1,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_ESP, spis: vec![vec![1, 2, 3, 4]] })],
        );
        let rm = init.decode(&req).unwrap();
        let (r, ev) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev, PeerEvent::DeleteChild(vec![]));
        assert!(r.payloads.is_empty());
    }

    #[test]
    fn peer_create_child_sa_rejected() {
        let (mut init, resp, _) = establish(false);
        let req = resp.seal_request(EXCH_CREATE_CHILD_SA, 0, vec![Payload::Nonce(vec![1; 32])]);
        let rm = init.decode(&req).unwrap();
        let (r, ev) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev, PeerEvent::Other);
        assert_eq!(r.header.exchange_type, EXCH_CREATE_CHILD_SA);
        assert_eq!(notify_types(&r), vec![N_NO_ADDITIONAL_SAS]);
    }

    #[test]
    fn peer_generic_informational_echoes_cookie2() {
        let (mut init, resp, _) = establish(false);
        let c2 = NotifyPayload::status(N_COOKIE2, vec![7; 8]);
        let req = resp.seal_request(EXCH_INFORMATIONAL, 0, vec![Payload::Notify(c2.clone())]);
        let rm = init.decode(&req).unwrap();
        let (r, ev) = init.handle_peer_request(&rm).unwrap();
        assert_eq!(ev, PeerEvent::Notify(vec![c2.clone()]));
        assert_eq!(r.payloads, vec![Payload::Notify(c2)]);
    }

    #[test]
    fn delete_ike_shape_and_response() {
        let (mut init, resp, _) = establish(false);
        let m = init.build_delete_ike().unwrap();
        assert_eq!(m.header.exchange_type, EXCH_INFORMATIONAL);
        assert_eq!(m.header.message_id, 4);
        assert_eq!(m.header.flags, FLAG_INITIATOR);
        assert_eq!(m.payloads, vec![Payload::Delete(DeletePayload { protocol_id: PROTO_IKE, spis: vec![] })]);
        let mut body = Vec::new();
        m.payloads[0].encode_body(&mut body).unwrap();
        assert_eq!(body, vec![PROTO_IKE, 0, 0, 0]);
        let dg = init.encode(&m).unwrap();
        assert_eq!(dg[0][28], PT_DELETE);
        let seen = resp.open(&dg);
        assert_eq!(seen.payloads, m.payloads);
        let r = resp.seal_response(EXCH_INFORMATIONAL, 4, vec![]);
        let rm = init.decode(&r).unwrap();
        init.handle_informational_response(&rm).unwrap();
        assert!(!init.established());
        assert_eq!(init.next_message_id(), 5);
    }

    #[test]
    fn delete_child_shape_and_response() {
        let (mut init, resp, est) = establish(false);
        let m = init.build_delete_child(est.child.spi_in).unwrap();
        assert_eq!(
            m.payloads,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_ESP, spis: vec![est.child.spi_in.to_be_bytes().to_vec()] })]
        );
        let mut body = Vec::new();
        m.payloads[0].encode_body(&mut body).unwrap();
        assert_eq!(&body[..4], &[PROTO_ESP, 4, 0, 1]);
        let r = resp.seal_response(
            EXCH_INFORMATIONAL,
            4,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_ESP, spis: vec![resp.child_spi.to_be_bytes().to_vec()] })],
        );
        let rm = init.decode(&r).unwrap();
        init.handle_informational_response(&rm).unwrap();
        assert!(init.child().is_none());
        assert!(init.established());
    }

    #[test]
    fn rekey_child_flow() {
        let (mut init, resp, est) = establish(false);
        let m = init.build_rekey_child().unwrap();
        assert_eq!(m.header.exchange_type, EXCH_CREATE_CHILD_SA);
        assert_eq!(m.header.message_id, 4);
        assert_eq!(payload_types(&m), vec![PT_SA, PT_TSI, PT_TSR, PT_NONCE, PT_NOTIFY]);
        let n = m.notify(N_REKEY_SA).unwrap();
        assert_eq!(n.protocol_id, PROTO_ESP);
        assert_eq!(n.spi, est.child.spi_in.to_be_bytes().to_vec());
        assert!(n.data.is_empty());
        let req_prop = m.sa().unwrap().proposals[0].clone();
        assert_eq!(req_prop.spi.len(), 4);
        assert_ne!(req_prop.spi, est.child.spi_in.to_be_bytes().to_vec());
        assert_eq!(req_prop.transforms.len(), 3);
        assert_eq!(*m.ts_i().unwrap(), est.child.ts_i);
        assert_eq!(*m.ts_r().unwrap(), est.child.ts_r);
        let ni_new = m.nonce().unwrap().to_vec();
        assert_eq!(ni_new.len(), 32);
        let dg = init.encode(&m).unwrap();
        let seen = resp.open(&dg);
        assert_eq!(seen.payloads, m.payloads);

        let nr_new = random_bytes(32);
        let new_out: u32 = 0x77778888;
        let chosen = Proposal { spi: new_out.to_be_bytes().to_vec(), ..req_prop.clone() };
        let r = resp.seal_response(
            EXCH_CREATE_CHILD_SA,
            4,
            vec![
                Payload::Sa(SaPayload { proposals: vec![chosen] }),
                Payload::Nonce(nr_new.clone()),
                Payload::TsI(est.child.ts_i.clone()),
                Payload::TsR(est.child.ts_r.clone()),
            ],
        );
        let rm = init.decode(&r).unwrap();
        let new = init.handle_rekey_child_response(&rm).unwrap();
        assert_eq!(new.spi_in.to_be_bytes().to_vec(), req_prop.spi);
        assert_eq!(new.spi_out, new_out);
        let expected = derive_child_keys(
            resp.suite.cipher.as_ref(),
            resp.suite.integrity.as_ref(),
            resp.suite.prf.as_ref(),
            &resp.keys().sk_d,
            &ni_new,
            &nr_new,
            None,
        );
        assert_eq!(new.keys.encr_i2r, expected.encr_i2r);
        assert_eq!(new.keys.integ_i2r, expected.integ_i2r);
        assert_eq!(new.keys.encr_r2i, expected.encr_r2i);
        assert_eq!(new.keys.integ_r2i, expected.integ_r2i);
        assert_ne!(new.keys.encr_i2r, est.child.keys.encr_i2r);
        assert_eq!(init.child().unwrap().spi_in, new.spi_in);
        assert_eq!(init.old_child().unwrap().spi_in, est.child.spi_in);
        assert_eq!(init.next_message_id(), 5);

        // Delete the old child.
        let d = init.build_delete_child(est.child.spi_in).unwrap();
        assert_eq!(d.header.message_id, 5);
        let r = resp.seal_response(
            EXCH_INFORMATIONAL,
            5,
            vec![Payload::Delete(DeletePayload { protocol_id: PROTO_ESP, spis: vec![est.child.spi_out.to_be_bytes().to_vec()] })],
        );
        let rm = init.decode(&r).unwrap();
        init.handle_informational_response(&rm).unwrap();
        assert!(init.old_child().is_none());
        assert_eq!(init.child().unwrap().spi_in, new.spi_in);
    }

    #[test]
    fn rekey_child_error_notify() {
        let (mut init, resp, _) = establish(false);
        init.build_rekey_child().unwrap();
        let r = resp.seal_response(
            EXCH_CREATE_CHILD_SA,
            4,
            vec![Payload::Notify(NotifyPayload::status(N_NO_ADDITIONAL_SAS, vec![]))],
        );
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_rekey_child_response(&rm), Err(Error::PeerNotify { notify_type: N_NO_ADDITIONAL_SAS, .. })));
        assert_eq!(init.next_message_id(), 5);
        // Idle again: a new request may be built.
        assert!(init.build_dpd().is_ok());
    }

    #[test]
    fn rekey_ike_flow_then_delete_old() {
        let (mut init, mut resp, _) = establish(false);
        let old_spi_i = init.spi_i();
        let old_spi_r = init.spi_r();
        let old_sk_d = init.keys().sk_d.clone();
        let m = init.build_rekey_ike().unwrap();
        assert_eq!(m.header.exchange_type, EXCH_CREATE_CHILD_SA);
        assert_eq!(m.header.message_id, 4);
        assert_eq!(payload_types(&m), vec![PT_SA, PT_KE, PT_NONCE]);
        let prop = m.sa().unwrap().proposals[0].clone();
        assert_eq!(prop.protocol_id, PROTO_IKE);
        assert_eq!(prop.spi.len(), 8);
        let new_spi_i = u64::from_be_bytes(prop.spi.clone().try_into().unwrap());
        assert_ne!(new_spi_i, old_spi_i);
        assert_eq!(
            prop.transforms,
            vec![
                Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                Transform::new(TT_DH, DH_MODP_2048),
                Transform::new(TT_PRF, PRF_HMAC_SHA2_256),
            ]
        );
        assert_eq!(m.ke().unwrap().group, DH_MODP_2048);
        let ni_new = m.nonce().unwrap().to_vec();
        let dg = init.encode(&m).unwrap();
        let seen = resp.open(&dg);
        assert_eq!(seen.payloads, m.payloads);

        // Responder side.
        let new_spi_r: u64 = 0x0badcafe_00112233;
        let pair = registry::dh(14).unwrap().generate().unwrap();
        let shared = pair.shared_secret(&m.ke().unwrap().public).unwrap();
        let nr_new = random_bytes(32);
        let chosen = Proposal { spi: new_spi_r.to_be_bytes().to_vec(), ..prop.clone() };
        let r = resp.seal_response(
            EXCH_CREATE_CHILD_SA,
            4,
            vec![
                Payload::Sa(SaPayload { proposals: vec![chosen] }),
                Payload::Ke(KePayload { group: DH_MODP_2048, public: pair.public_value() }),
                Payload::Nonce(nr_new.clone()),
            ],
        );
        let rm = init.decode(&r).unwrap();
        init.handle_rekey_ike_response(&rm).unwrap();
        assert_eq!(init.spi_i(), new_spi_i);
        assert_eq!(init.spi_r(), new_spi_r);
        assert_eq!(init.next_message_id(), 0);
        assert_eq!(init.peer_next_message_id(), 0);
        let expected = derive_ike_keys_rekey(&resp.suite, &old_sk_d, &shared, &ni_new, &nr_new, new_spi_i, new_spi_r);
        assert_eq!(init.keys().sk_d, expected.sk_d);
        assert_eq!(init.keys().sk_ei, expected.sk_ei);
        assert!(init.established());
        assert!(init.child().is_some(), "child SAs survive an IKE rekey");

        // DELETE the old SA: built on the old SPIs, sealed with the old keys.
        let d = init.build_delete_ike().unwrap();
        assert_eq!((d.header.spi_i, d.header.spi_r), (old_spi_i, old_spi_r));
        assert_eq!(d.header.message_id, 5, "old SA's counter continues");
        let dg = init.encode(&d).unwrap();
        let seen = resp.open(&dg); // resp still holds the OLD keys
        assert_eq!(seen.payloads, d.payloads);
        let r = resp.seal_response(EXCH_INFORMATIONAL, 5, vec![]);
        let rm = init.decode(&r).unwrap();
        init.handle_informational_response(&rm).unwrap();
        assert!(init.established());
        assert_eq!(init.next_message_id(), 0);

        // The new SA works: DPD sealed with the new keys.
        let old_keys = resp.keys.replace(expected);
        resp.spi_i = new_spi_i;
        resp.spi_r = new_spi_r;
        let dpd = init.build_dpd().unwrap();
        assert_eq!(dpd.header.message_id, 0);
        assert_eq!((dpd.header.spi_i, dpd.header.spi_r), (new_spi_i, new_spi_r));
        let dg = init.encode(&dpd).unwrap();
        assert!(resp.open(&dg).payloads.is_empty());
        let r = resp.seal_response(EXCH_INFORMATIONAL, 0, vec![]);
        let rm = init.decode(&r).unwrap();
        init.handle_informational_response(&rm).unwrap();
        assert_eq!(init.next_message_id(), 1);
        drop(old_keys);
    }

    #[test]
    fn state_misuse_is_protocol_error() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        assert!(matches!(init.build_auth_initial(), Err(Error::Protocol(_))));
        assert!(matches!(init.build_dpd(), Err(Error::Protocol(_))));
        assert!(matches!(init.build_rekey_child(), Err(Error::Protocol(_))));
        assert!(matches!(init.handle_sa_init_response(&[0; 28]), Err(Error::Protocol(_))));
        let m = IkeMessage::new(1, 2, EXCH_INFORMATIONAL, FLAG_INITIATOR, 0, vec![]);
        assert!(matches!(init.encode(&m), Err(Error::Protocol(_))), "no keys yet");
        assert!(init.keys().sk_d.is_empty());
        assert!(!init.established());
        assert!(init.nat().is_none());
        assert!(init.child().is_none());
    }

    #[test]
    fn cookie_length_validated() {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        init.build_sa_init(None).unwrap();
        assert!(matches!(init.build_sa_init(Some(&[])), Err(Error::Decode(_))));
        assert!(matches!(init.build_sa_init(Some(&[1; 65])), Err(Error::Decode(_))));
        let reply = IkeMessage::new(
            init.spi_i(),
            0,
            EXCH_IKE_SA_INIT,
            FLAG_RESPONSE,
            0,
            vec![Payload::Notify(NotifyPayload::status(N_COOKIE, vec![1; 65]))],
        )
        .encode_plain()
        .unwrap();
        assert!(matches!(init.handle_sa_init_response(&reply), Err(Error::Decode(_))));
    }
}
