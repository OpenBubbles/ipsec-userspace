//! IKEv2 payloads (RFC 7296 §3.2 ff.): typed structs, body encode/decode, and the
//! generic-header payload chain.
//!
//! Generic payload header (4 bytes): `NextPayload(1) | C(1 bit)+Reserved(7) | Length(2)`,
//! `Length` includes the 4-byte header. The critical bit is never set on anything
//! we send (AOSP parity).
//!
//! The Encrypted (SK, 46) and Encrypted Fragment (SKF, 53) payloads are NOT
//! modelled here — `message.rs` / `fragment.rs` own them. If either type shows up
//! inside a payload chain handed to [`decode_payloads`] it is passed through as
//! [`Payload::Unknown`] rather than rejected.

use crate::ike::constants::*;
use crate::{Error, Result};
use log::{debug, warn};

// ---------------------------------------------------------------------------
// Typed payload bodies
// ---------------------------------------------------------------------------

/// One transform inside a proposal (§3.3.2). `key_len_bits` becomes a Key Length
/// attribute in TV form (`0x800E | bits`) and is emitted only when `Some`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transform {
    pub ttype: u8,
    pub id: u16,
    pub key_len_bits: Option<u16>,
}

impl Transform {
    pub fn new(ttype: u8, id: u16) -> Self {
        Transform { ttype, id, key_len_bits: None }
    }
    pub fn with_key_len(ttype: u8, id: u16, bits: u16) -> Self {
        Transform { ttype, id, key_len_bits: Some(bits) }
    }
}

/// Proposal substructure (§3.3.1). `spi` is empty for IKE_SA_INIT proposals,
/// 4 bytes for ESP, 8 bytes for an IKE rekey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SaPayload {
    pub proposals: Vec<Proposal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KePayload {
    pub group: u16,
    pub public: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdPayload {
    pub id_type: u8,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPayload {
    pub method: u8,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyPayload {
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub notify_type: u16,
    pub data: Vec<u8>,
}

impl NotifyPayload {
    /// IKE-level notify: protocol id 0, no SPI (what AOSP emits for every status notify).
    pub fn status(notify_type: u16, data: Vec<u8>) -> Self {
        NotifyPayload { protocol_id: 0, spi: Vec::new(), notify_type, data }
    }
    /// Error notifies are types below 16384 (§3.10.1).
    pub fn is_error(&self) -> bool {
        self.notify_type < 16384
    }
}

/// Delete payload (§3.11). SPI size is derived: 0 for IKE (no SPIs), 4 for ESP/AH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePayload {
    pub protocol_id: u8,
    pub spis: Vec<Vec<u8>>,
}

/// Traffic selector substructure (§3.13.1). Address lengths: 4 for
/// `TS_IPV4_ADDR_RANGE`, 16 for `TS_IPV6_ADDR_RANGE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub ip_protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: Vec<u8>,
    pub end_addr: Vec<u8>,
}

impl TrafficSelector {
    /// `0.0.0.0-255.255.255.255`, any protocol, ports 0-65535 (AOSP default TS).
    pub fn ipv4_any() -> Self {
        TrafficSelector {
            ts_type: TS_IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0; 4],
            end_addr: vec![0xff; 4],
        }
    }
    /// `::-ffff:...:ffff`, any protocol, ports 0-65535 (AOSP default TS).
    pub fn ipv6_any() -> Self {
        TrafficSelector {
            ts_type: TS_IPV6_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0; 16],
            end_addr: vec![0xff; 16],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TsPayload {
    pub selectors: Vec<TrafficSelector>,
}

impl TsPayload {
    /// `[IPv4 any, IPv6 any]` — what AOSP sends for both TSi and TSr.
    pub fn any_v4_v6() -> Self {
        TsPayload { selectors: vec![TrafficSelector::ipv4_any(), TrafficSelector::ipv6_any()] }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigAttribute {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigPayload {
    pub cfg_type: u8,
    pub attributes: Vec<ConfigAttribute>,
}

impl ConfigPayload {
    /// `CFG_REQUEST` with zero-length attributes of the given types, in order.
    pub fn request(attr_types: &[u16]) -> Self {
        ConfigPayload {
            cfg_type: CFG_REQUEST,
            attributes: attr_types
                .iter()
                .map(|&t| ConfigAttribute { attr_type: t, value: Vec::new() })
                .collect(),
        }
    }
}

/// Every payload type this crate understands, plus a pass-through for the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Sa(SaPayload),
    Ke(KePayload),
    IdI(IdPayload),
    IdR(IdPayload),
    Cert(Vec<u8>),
    CertReq(Vec<u8>),
    Auth(AuthPayload),
    Nonce(Vec<u8>),
    Notify(NotifyPayload),
    Delete(DeletePayload),
    Vendor(Vec<u8>),
    TsI(TsPayload),
    TsR(TsPayload),
    Cp(ConfigPayload),
    Eap(Vec<u8>),
    Unknown { payload_type: u8, critical: bool, body: Vec<u8> },
}

// ---------------------------------------------------------------------------
// Wire limits
// ---------------------------------------------------------------------------

/// Proposal "last/more" byte values (§3.3.1).
const PROPOSAL_LAST: u8 = 0;
const PROPOSAL_MORE: u8 = 2;
/// Transform "last/more" byte values (§3.3.2).
const TRANSFORM_LAST: u8 = 0;
const TRANSFORM_MORE: u8 = 3;
const PROPOSAL_HEADER_LEN: usize = 8;
const TRANSFORM_HEADER_LEN: usize = 8;
const TS_SELECTOR_HEADER_LEN: usize = 8;
const CFG_ATTR_HEADER_LEN: usize = 4;
const CFG_ATTR_TYPE_MASK: u16 = 0x7fff;
const NONCE_MIN_LEN: usize = 16;
const NONCE_MAX_LEN: usize = 256;
const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

// ---------------------------------------------------------------------------
// Strict big-endian reader
// ---------------------------------------------------------------------------

/// Bounds-checked cursor over wire bytes. Every failure is `Error::Decode`
/// naming `what` so a capture can be lined up against the message.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], what: &'static str) -> Self {
        Reader { buf, pos: 0, what }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::Decode(format!(
                "{}: need {} bytes at offset {}, only {} left",
                self.what,
                n,
                self.pos,
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
    /// Fail unless everything was consumed.
    fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode(format!(
                "{}: {} trailing bytes after offset {}",
                self.what,
                self.remaining(),
                self.pos
            )))
        }
    }
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn len_u16(what: &str, len: usize) -> Result<u16> {
    u16::try_from(len).map_err(|_| Error::Encode(format!("{what}: length {len} exceeds 65535")))
}

// ---------------------------------------------------------------------------
// SA payload (§3.3)
// ---------------------------------------------------------------------------

fn encode_transform(t: &Transform, is_last: bool, out: &mut Vec<u8>) {
    out.push(if is_last { TRANSFORM_LAST } else { TRANSFORM_MORE });
    out.push(0); // reserved
    let len = TRANSFORM_HEADER_LEN + if t.key_len_bits.is_some() { 4 } else { 0 };
    put_u16(out, len as u16);
    out.push(t.ttype);
    out.push(0); // reserved
    put_u16(out, t.id);
    if let Some(bits) = t.key_len_bits {
        // TV attribute: AF=1 | type 14, value = key length in bits.
        put_u16(out, ATTR_AF_BIT | ATTR_KEY_LENGTH);
        put_u16(out, bits);
    }
}

fn encode_proposal(p: &Proposal, is_last: bool, out: &mut Vec<u8>) -> Result<()> {
    let spi_size = u8::try_from(p.spi.len())
        .map_err(|_| Error::Encode(format!("SA: SPI of {} bytes too long", p.spi.len())))?;
    let num_transforms = u8::try_from(p.transforms.len())
        .map_err(|_| Error::Encode(format!("SA: {} transforms too many", p.transforms.len())))?;
    if p.transforms.is_empty() {
        return Err(Error::Encode(format!("SA: proposal {} has no transforms", p.number)));
    }
    let start = out.len();
    out.push(if is_last { PROPOSAL_LAST } else { PROPOSAL_MORE });
    out.push(0); // reserved
    put_u16(out, 0); // length placeholder
    out.push(p.number);
    out.push(p.protocol_id);
    out.push(spi_size);
    out.push(num_transforms);
    out.extend_from_slice(&p.spi);
    let n = p.transforms.len();
    for (i, t) in p.transforms.iter().enumerate() {
        encode_transform(t, i + 1 == n, out);
    }
    let len = len_u16("SA proposal", out.len() - start)?;
    out[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

fn encode_sa(sa: &SaPayload, out: &mut Vec<u8>) -> Result<()> {
    if sa.proposals.is_empty() {
        return Err(Error::Encode("SA: no proposals".into()));
    }
    let n = sa.proposals.len();
    for (i, p) in sa.proposals.iter().enumerate() {
        encode_proposal(p, i + 1 == n, out)?;
    }
    Ok(())
}

fn decode_transform(buf: &[u8]) -> Result<Transform> {
    let mut r = Reader::new(buf, "SA transform");
    let ttype = r.u8()?;
    let _reserved = r.u8()?;
    let id = r.u16()?;
    let mut key_len_bits = None;
    while !r.is_empty() {
        let attr_type = r.u16()?;
        let is_tv = attr_type & ATTR_AF_BIT != 0;
        let atype = attr_type & !ATTR_AF_BIT;
        let value: &[u8] = if is_tv {
            r.take(2)?
        } else {
            let len = r.u16()? as usize;
            r.take(len)?
        };
        match atype {
            ATTR_KEY_LENGTH => {
                if value.len() != 2 {
                    return Err(Error::Decode(format!(
                        "SA transform: Key Length attribute value is {} bytes, expected 2",
                        value.len()
                    )));
                }
                if key_len_bits.is_some() {
                    return Err(Error::Decode("SA transform: duplicate Key Length attribute".into()));
                }
                key_len_bits = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            other => {
                return Err(Error::Decode(format!(
                    "SA transform: unknown attribute type {} ({} bytes)",
                    other,
                    value.len()
                )));
            }
        }
    }
    Ok(Transform { ttype, id, key_len_bits })
}

fn decode_transforms(buf: &[u8], expected: usize) -> Result<Vec<Transform>> {
    let mut r = Reader::new(buf, "SA transforms");
    let mut out = Vec::with_capacity(expected);
    loop {
        let last_or_more = r.u8()?;
        let _reserved = r.u8()?;
        let len = r.u16()? as usize;
        if len < TRANSFORM_HEADER_LEN {
            return Err(Error::Decode(format!(
                "SA transform: length {} shorter than header ({})",
                len, TRANSFORM_HEADER_LEN
            )));
        }
        let body = r.take(len - 4)?;
        out.push(decode_transform(body)?);
        match last_or_more {
            TRANSFORM_LAST => {
                r.finish()?;
                break;
            }
            TRANSFORM_MORE => {
                if r.is_empty() {
                    return Err(Error::Decode("SA transform: 'more' flag set on final transform".into()));
                }
            }
            v => {
                return Err(Error::Decode(format!("SA transform: invalid last/more byte {v}")));
            }
        }
    }
    if out.len() != expected {
        return Err(Error::Decode(format!(
            "SA proposal: header says {} transforms, found {}",
            expected,
            out.len()
        )));
    }
    Ok(out)
}

fn decode_sa(buf: &[u8]) -> Result<SaPayload> {
    let mut r = Reader::new(buf, "SA");
    let mut proposals = Vec::new();
    loop {
        let last_or_more = r.u8()?;
        let _reserved = r.u8()?;
        let len = r.u16()? as usize;
        if len < PROPOSAL_HEADER_LEN {
            return Err(Error::Decode(format!(
                "SA proposal: length {} shorter than header ({})",
                len, PROPOSAL_HEADER_LEN
            )));
        }
        let body = r.take(len - 4)?;
        let mut p = Reader::new(body, "SA proposal");
        let number = p.u8()?;
        let protocol_id = p.u8()?;
        let spi_size = p.u8()? as usize;
        let num_transforms = p.u8()? as usize;
        let spi = p.take(spi_size)?.to_vec();
        if num_transforms == 0 {
            return Err(Error::Decode(format!("SA proposal {number}: zero transforms")));
        }
        let transforms = decode_transforms(p.rest(), num_transforms)?;
        proposals.push(Proposal { number, protocol_id, spi, transforms });
        match last_or_more {
            PROPOSAL_LAST => {
                r.finish()?;
                break;
            }
            PROPOSAL_MORE => {
                if r.is_empty() {
                    return Err(Error::Decode("SA proposal: 'more' flag set on final proposal".into()));
                }
            }
            v => return Err(Error::Decode(format!("SA proposal: invalid last/more byte {v}"))),
        }
    }
    Ok(SaPayload { proposals })
}

// ---------------------------------------------------------------------------
// KE / Nonce / ID / AUTH / Notify / Delete
// ---------------------------------------------------------------------------

fn encode_ke(ke: &KePayload, out: &mut Vec<u8>) {
    put_u16(out, ke.group);
    put_u16(out, 0);
    out.extend_from_slice(&ke.public);
}

fn decode_ke(buf: &[u8]) -> Result<KePayload> {
    let mut r = Reader::new(buf, "KE");
    let group = r.u16()?;
    let _reserved = r.u16()?;
    let public = r.rest().to_vec();
    if public.is_empty() {
        return Err(Error::Decode("KE: empty key exchange data".into()));
    }
    Ok(KePayload { group, public })
}

fn check_nonce_len(len: usize) -> std::result::Result<(), String> {
    if (NONCE_MIN_LEN..=NONCE_MAX_LEN).contains(&len) {
        Ok(())
    } else {
        Err(format!("Nonce: {len} bytes, must be {NONCE_MIN_LEN}..={NONCE_MAX_LEN}"))
    }
}

/// `Type(1) | Reserved(3) | Data` — shared by ID and AUTH.
fn encode_type_reserved_data(t: u8, data: &[u8], out: &mut Vec<u8>) {
    out.push(t);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(data);
}

fn decode_type_reserved_data(buf: &[u8], what: &'static str) -> Result<(u8, Vec<u8>)> {
    let mut r = Reader::new(buf, what);
    let t = r.u8()?;
    let _reserved = r.take(3)?;
    Ok((t, r.rest().to_vec()))
}

fn encode_notify(n: &NotifyPayload, out: &mut Vec<u8>) -> Result<()> {
    let spi_size = u8::try_from(n.spi.len())
        .map_err(|_| Error::Encode(format!("Notify: SPI of {} bytes too long", n.spi.len())))?;
    out.push(n.protocol_id);
    out.push(spi_size);
    put_u16(out, n.notify_type);
    out.extend_from_slice(&n.spi);
    out.extend_from_slice(&n.data);
    Ok(())
}

fn decode_notify(buf: &[u8]) -> Result<NotifyPayload> {
    let mut r = Reader::new(buf, "Notify");
    let protocol_id = r.u8()?;
    let spi_size = r.u8()? as usize;
    let notify_type = r.u16()?;
    let spi = r.take(spi_size)?.to_vec();
    let data = r.rest().to_vec();
    Ok(NotifyPayload { protocol_id, spi, notify_type, data })
}

fn encode_delete(d: &DeletePayload, out: &mut Vec<u8>) -> Result<()> {
    let spi_size = d.spis.first().map(|s| s.len()).unwrap_or(0);
    if d.spis.iter().any(|s| s.len() != spi_size) {
        return Err(Error::Encode("Delete: SPIs have differing lengths".into()));
    }
    if spi_size == 0 && !d.spis.is_empty() {
        return Err(Error::Encode("Delete: zero-length SPIs".into()));
    }
    let spi_size = u8::try_from(spi_size)
        .map_err(|_| Error::Encode(format!("Delete: SPI of {spi_size} bytes too long")))?;
    let num = len_u16("Delete SPI count", d.spis.len())?;
    out.push(d.protocol_id);
    out.push(spi_size);
    put_u16(out, num);
    for s in &d.spis {
        out.extend_from_slice(s);
    }
    Ok(())
}

fn decode_delete(buf: &[u8]) -> Result<DeletePayload> {
    let mut r = Reader::new(buf, "Delete");
    let protocol_id = r.u8()?;
    let spi_size = r.u8()? as usize;
    let num = r.u16()? as usize;
    if spi_size == 0 && num != 0 {
        return Err(Error::Decode(format!("Delete: SPI size 0 but {num} SPIs")));
    }
    let mut spis = Vec::with_capacity(num.min(r.remaining() / spi_size.max(1)));
    for _ in 0..num {
        spis.push(r.take(spi_size)?.to_vec());
    }
    r.finish()?;
    Ok(DeletePayload { protocol_id, spis })
}

// ---------------------------------------------------------------------------
// Traffic selectors (§3.13)
// ---------------------------------------------------------------------------

fn ts_addr_len(ts_type: u8) -> Option<usize> {
    match ts_type {
        TS_IPV4_ADDR_RANGE => Some(4),
        TS_IPV6_ADDR_RANGE => Some(16),
        _ => None,
    }
}

fn encode_ts(ts: &TsPayload, out: &mut Vec<u8>) -> Result<()> {
    let num = u8::try_from(ts.selectors.len())
        .map_err(|_| Error::Encode(format!("TS: {} selectors too many", ts.selectors.len())))?;
    out.push(num);
    out.extend_from_slice(&[0, 0, 0]);
    for s in &ts.selectors {
        if s.start_addr.len() != s.end_addr.len() {
            return Err(Error::Encode("TS: start/end address lengths differ".into()));
        }
        if let Some(want) = ts_addr_len(s.ts_type) {
            if s.start_addr.len() != want {
                return Err(Error::Encode(format!(
                    "TS: type {} needs {}-byte addresses, got {}",
                    s.ts_type,
                    want,
                    s.start_addr.len()
                )));
            }
        }
        let len = len_u16("TS selector", TS_SELECTOR_HEADER_LEN + s.start_addr.len() + s.end_addr.len())?;
        out.push(s.ts_type);
        out.push(s.ip_protocol);
        put_u16(out, len);
        put_u16(out, s.start_port);
        put_u16(out, s.end_port);
        out.extend_from_slice(&s.start_addr);
        out.extend_from_slice(&s.end_addr);
    }
    Ok(())
}

fn decode_ts(buf: &[u8]) -> Result<TsPayload> {
    let mut r = Reader::new(buf, "TS");
    let num = r.u8()? as usize;
    let _reserved = r.take(3)?;
    let mut selectors = Vec::with_capacity(num);
    for _ in 0..num {
        let ts_type = r.u8()?;
        let ip_protocol = r.u8()?;
        let len = r.u16()? as usize;
        if len < TS_SELECTOR_HEADER_LEN {
            return Err(Error::Decode(format!(
                "TS selector: length {len} shorter than header ({TS_SELECTOR_HEADER_LEN})"
            )));
        }
        let start_port = r.u16()?;
        let end_port = r.u16()?;
        let addrs = r.take(len - TS_SELECTOR_HEADER_LEN)?;
        let addr_len = match ts_addr_len(ts_type) {
            Some(want) => {
                if addrs.len() != 2 * want {
                    return Err(Error::Decode(format!(
                        "TS selector: type {} carries {} address bytes, expected {}",
                        ts_type,
                        addrs.len(),
                        2 * want
                    )));
                }
                want
            }
            None => {
                if addrs.len() % 2 != 0 {
                    return Err(Error::Decode(format!(
                        "TS selector: unknown type {} with odd address length {}",
                        ts_type,
                        addrs.len()
                    )));
                }
                warn!("TS selector: unknown TS type {ts_type}, splitting addresses evenly");
                addrs.len() / 2
            }
        };
        selectors.push(TrafficSelector {
            ts_type,
            ip_protocol,
            start_port,
            end_port,
            start_addr: addrs[..addr_len].to_vec(),
            end_addr: addrs[addr_len..].to_vec(),
        });
    }
    r.finish()?;
    Ok(TsPayload { selectors })
}

// ---------------------------------------------------------------------------
// Configuration payload (§3.15)
// ---------------------------------------------------------------------------

fn encode_cp(cp: &ConfigPayload, out: &mut Vec<u8>) -> Result<()> {
    out.push(cp.cfg_type);
    out.extend_from_slice(&[0, 0, 0]);
    for a in &cp.attributes {
        if a.attr_type & !CFG_ATTR_TYPE_MASK != 0 {
            return Err(Error::Encode(format!("CP: attribute type {} exceeds 15 bits", a.attr_type)));
        }
        let len = len_u16("CP attribute", a.value.len())?;
        put_u16(out, a.attr_type & CFG_ATTR_TYPE_MASK);
        put_u16(out, len);
        out.extend_from_slice(&a.value);
    }
    Ok(())
}

fn decode_cp(buf: &[u8]) -> Result<ConfigPayload> {
    let mut r = Reader::new(buf, "CP");
    let cfg_type = r.u8()?;
    let _reserved = r.take(3)?;
    let mut attributes = Vec::new();
    while !r.is_empty() {
        if r.remaining() < CFG_ATTR_HEADER_LEN {
            return Err(Error::Decode(format!(
                "CP: {} trailing bytes, attribute header needs {}",
                r.remaining(),
                CFG_ATTR_HEADER_LEN
            )));
        }
        let attr_type = r.u16()? & CFG_ATTR_TYPE_MASK;
        let len = r.u16()? as usize;
        let value = r.take(len)?.to_vec();
        attributes.push(ConfigAttribute { attr_type, value });
    }
    Ok(ConfigPayload { cfg_type, attributes })
}

// ---------------------------------------------------------------------------
// Payload dispatch
// ---------------------------------------------------------------------------

impl Payload {
    pub fn payload_type(&self) -> u8 {
        match self {
            Payload::Sa(_) => PT_SA,
            Payload::Ke(_) => PT_KE,
            Payload::IdI(_) => PT_IDI,
            Payload::IdR(_) => PT_IDR,
            Payload::Cert(_) => PT_CERT,
            Payload::CertReq(_) => PT_CERTREQ,
            Payload::Auth(_) => PT_AUTH,
            Payload::Nonce(_) => PT_NONCE,
            Payload::Notify(_) => PT_NOTIFY,
            Payload::Delete(_) => PT_DELETE,
            Payload::Vendor(_) => PT_VENDOR,
            Payload::TsI(_) => PT_TSI,
            Payload::TsR(_) => PT_TSR,
            Payload::Cp(_) => PT_CP,
            Payload::Eap(_) => PT_EAP,
            Payload::Unknown { payload_type, .. } => *payload_type,
        }
    }

    /// Human-readable payload type name for logs.
    pub fn type_name(payload_type: u8) -> &'static str {
        match payload_type {
            PT_NONE => "NONE",
            PT_SA => "SA",
            PT_KE => "KE",
            PT_IDI => "IDi",
            PT_IDR => "IDr",
            PT_CERT => "CERT",
            PT_CERTREQ => "CERTREQ",
            PT_AUTH => "AUTH",
            PT_NONCE => "Nonce",
            PT_NOTIFY => "N",
            PT_DELETE => "D",
            PT_VENDOR => "V",
            PT_TSI => "TSi",
            PT_TSR => "TSr",
            PT_SK => "SK",
            PT_CP => "CP",
            PT_EAP => "EAP",
            PT_SKF => "SKF",
            _ => "?",
        }
    }

    /// Append the payload body (everything after the 4-byte generic header).
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Payload::Sa(sa) => encode_sa(sa, out)?,
            Payload::Ke(ke) => encode_ke(ke, out),
            Payload::IdI(id) | Payload::IdR(id) => encode_type_reserved_data(id.id_type, &id.data, out),
            Payload::Cert(b) | Payload::CertReq(b) | Payload::Vendor(b) | Payload::Eap(b) => {
                out.extend_from_slice(b)
            }
            Payload::Auth(a) => encode_type_reserved_data(a.method, &a.data, out),
            Payload::Nonce(n) => {
                check_nonce_len(n.len()).map_err(Error::Encode)?;
                out.extend_from_slice(n);
            }
            Payload::Notify(n) => encode_notify(n, out)?,
            Payload::Delete(d) => encode_delete(d, out)?,
            Payload::TsI(ts) | Payload::TsR(ts) => encode_ts(ts, out)?,
            Payload::Cp(cp) => encode_cp(cp, out)?,
            Payload::Unknown { body, .. } => out.extend_from_slice(body),
        }
        Ok(())
    }

    /// Decode one payload body. Unknown type with the critical bit set is an
    /// `Error::Decode` naming `UNSUPPORTED_CRITICAL_PAYLOAD`; unknown non-critical
    /// (and SK/SKF, which belong to the message layer) become [`Payload::Unknown`].
    pub fn decode_body(payload_type: u8, critical: bool, body: &[u8]) -> Result<Payload> {
        Ok(match payload_type {
            PT_SA => Payload::Sa(decode_sa(body)?),
            PT_KE => Payload::Ke(decode_ke(body)?),
            PT_IDI | PT_IDR => {
                let (id_type, data) = decode_type_reserved_data(body, "ID")?;
                let id = IdPayload { id_type, data };
                if payload_type == PT_IDI { Payload::IdI(id) } else { Payload::IdR(id) }
            }
            PT_CERT => Payload::Cert(body.to_vec()),
            PT_CERTREQ => Payload::CertReq(body.to_vec()),
            PT_AUTH => {
                let (method, data) = decode_type_reserved_data(body, "AUTH")?;
                Payload::Auth(AuthPayload { method, data })
            }
            PT_NONCE => {
                check_nonce_len(body.len()).map_err(Error::Decode)?;
                Payload::Nonce(body.to_vec())
            }
            PT_NOTIFY => Payload::Notify(decode_notify(body)?),
            PT_DELETE => Payload::Delete(decode_delete(body)?),
            PT_VENDOR => Payload::Vendor(body.to_vec()),
            PT_TSI => Payload::TsI(decode_ts(body)?),
            PT_TSR => Payload::TsR(decode_ts(body)?),
            PT_CP => Payload::Cp(decode_cp(body)?),
            PT_EAP => Payload::Eap(body.to_vec()),
            PT_SK | PT_SKF => {
                // Never an error here: the message layer strips these before we run.
                warn!("payload type {} ({}) inside a payload chain; passing through as Unknown",
                    payload_type, Payload::type_name(payload_type));
                Payload::Unknown { payload_type, critical, body: body.to_vec() }
            }
            other if critical => {
                return Err(Error::Decode(format!(
                    "UNSUPPORTED_CRITICAL_PAYLOAD: unknown payload type {other} with critical bit set"
                )));
            }
            other => {
                debug!("skipping unknown non-critical payload type {} ({} bytes)", other, body.len());
                Payload::Unknown { payload_type: other, critical: false, body: body.to_vec() }
            }
        })
    }
}

/// Append one payload with its generic header. `next_payload` is the type of the
/// payload that will follow (`PT_NONE` for the last). Critical bit always clear.
pub fn encode_payload(payload: &Payload, next_payload: u8, out: &mut Vec<u8>) -> Result<()> {
    let start = out.len();
    out.push(next_payload);
    out.push(0); // C=0, reserved
    put_u16(out, 0); // length placeholder
    payload.encode_body(out)?;
    let len = out.len() - start;
    if len > MAX_PAYLOAD_LEN {
        return Err(Error::Encode(format!(
            "payload {} is {} bytes, exceeds {}",
            Payload::type_name(payload.payload_type()),
            len,
            MAX_PAYLOAD_LEN
        )));
    }
    out[start + 2..start + 4].copy_from_slice(&(len as u16).to_be_bytes());
    Ok(())
}

/// Encode a payload chain: each generic header's NextPayload = type of the following
/// payload, last = PT_NONE. Returns the type of the FIRST payload (PT_NONE if empty)
/// for the enclosing IKE header (or SK generic header).
pub fn encode_payloads(payloads: &[Payload], out: &mut Vec<u8>) -> Result<u8> {
    for (i, p) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map(Payload::payload_type).unwrap_or(PT_NONE);
        encode_payload(p, next, out)?;
    }
    Ok(payloads.first().map(Payload::payload_type).unwrap_or(PT_NONE))
}

/// Decode a chain starting with `first_type`. Unknown payload with C=1 ->
/// `Error::Decode(UNSUPPORTED_CRITICAL_PAYLOAD ...)`; with C=0 -> [`Payload::Unknown`]
/// (skipped by callers). The buffer must be consumed exactly.
pub fn decode_payloads(first_type: u8, buf: &[u8]) -> Result<Vec<Payload>> {
    let mut r = Reader::new(buf, "payload chain");
    let mut payloads = Vec::new();
    let mut next = first_type;
    while next != PT_NONE {
        let this_type = next;
        if r.remaining() < GENERIC_PAYLOAD_HEADER_LEN {
            return Err(Error::Decode(format!(
                "payload chain: expected payload {} ({}) but only {} bytes remain",
                this_type,
                Payload::type_name(this_type),
                r.remaining()
            )));
        }
        next = r.u8()?;
        let flags = r.u8()?;
        let critical = flags & 0x80 != 0;
        let len = r.u16()? as usize;
        if len < GENERIC_PAYLOAD_HEADER_LEN {
            return Err(Error::Decode(format!(
                "payload {} ({}): length {} shorter than generic header",
                this_type,
                Payload::type_name(this_type),
                len
            )));
        }
        let body = r.take(len - GENERIC_PAYLOAD_HEADER_LEN).map_err(|e| {
            Error::Decode(format!(
                "payload {} ({}): length {} exceeds remaining ({})",
                this_type,
                Payload::type_name(this_type),
                len,
                e
            ))
        })?;
        debug!(
            "decode payload {} ({}) next={} C={} len={} body={}",
            this_type,
            Payload::type_name(this_type),
            next,
            critical as u8,
            len,
            hex::encode(body)
        );
        payloads.push(Payload::decode_body(this_type, critical, body)?);
    }
    r.finish()?;
    Ok(payloads)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '|', '\n'], "")).unwrap()
    }

    fn body(p: &Payload) -> Vec<u8> {
        let mut out = Vec::new();
        p.encode_body(&mut out).unwrap();
        out
    }

    fn chain(ps: &[Payload]) -> (u8, Vec<u8>) {
        let mut out = Vec::new();
        let first = encode_payloads(ps, &mut out).unwrap();
        (first, out)
    }

    fn round_trip(p: Payload) {
        let (first, bytes) = chain(std::slice::from_ref(&p));
        assert_eq!(first, p.payload_type());
        let back = decode_payloads(first, &bytes).unwrap();
        assert_eq!(back, vec![p]);
    }

    fn glue_ike_sa() -> SaPayload {
        SaPayload {
            proposals: vec![Proposal {
                number: 1,
                protocol_id: PROTO_IKE,
                spi: vec![],
                transforms: vec![
                    Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                    Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                    Transform::new(TT_DH, DH_MODP_2048),
                    Transform::new(TT_PRF, PRF_HMAC_SHA2_256),
                ],
            }],
        }
    }

    fn glue_child_sa(spi: [u8; 4]) -> SaPayload {
        SaPayload {
            proposals: vec![Proposal {
                number: 1,
                protocol_id: PROTO_ESP,
                spi: spi.to_vec(),
                transforms: vec![
                    Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                    Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                    Transform::new(TT_ESN, ESN_NO),
                ],
            }],
        }
    }

    // ---- §14 exact byte layouts -------------------------------------------

    #[test]
    fn ike_sa_payload_is_exactly_48_bytes_aosp_layout() {
        let p = Payload::Sa(glue_ike_sa());
        let mut out = Vec::new();
        encode_payload(&p, PT_KE, &mut out).unwrap();
        let expected = h("22 00 0030 \
            | 00 00 002C 01 01 00 04 \
            | 03 00 000C 01 00 000C 800E 0100 \
            | 03 00 0008 03 00 000C \
            | 03 00 0008 04 00 000E \
            | 00 00 0008 02 00 0005");
        assert_eq!(out.len(), 48);
        assert_eq!(hex::encode(&out), hex::encode(&expected));
        // and back
        let back = decode_payloads(PT_SA, &{
            let mut b = out.clone();
            b[0] = PT_NONE;
            b
        })
        .unwrap();
        assert_eq!(back, vec![p]);
    }

    #[test]
    fn child_sa_payload_is_exactly_44_bytes() {
        let p = Payload::Sa(glue_child_sa([0xde, 0xad, 0xbe, 0xef]));
        let mut out = Vec::new();
        encode_payload(&p, PT_TSI, &mut out).unwrap();
        let expected = h("2C 00 002C \
            | 00 00 0028 01 03 04 03 DEADBEEF \
            | 03 00 000C 01 00 000C 800E 0100 \
            | 03 00 0008 03 00 000C \
            | 00 00 0008 05 00 0000");
        assert_eq!(out.len(), 44);
        assert_eq!(hex::encode(&out), hex::encode(&expected));
        round_trip(p);
    }

    #[test]
    fn ts_payload_is_exactly_64_bytes() {
        let p = Payload::TsI(TsPayload::any_v4_v6());
        let mut out = Vec::new();
        encode_payload(&p, PT_TSR, &mut out).unwrap();
        let expected = h("2D 00 0040 | 02 00 00 00 \
            | 07 00 0010 0000 FFFF 00000000 FFFFFFFF \
            | 08 00 0028 0000 FFFF 00000000000000000000000000000000 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        assert_eq!(out.len(), 64);
        assert_eq!(hex::encode(&out), hex::encode(&expected));
        // TSr is byte-identical apart from the type
        let mut tsr = Vec::new();
        encode_payload(&Payload::TsR(TsPayload::any_v4_v6()), PT_CP, &mut tsr).unwrap();
        assert_eq!(&tsr[4..], &out[4..]);
        round_trip(p);
        round_trip(Payload::TsR(TsPayload::any_v4_v6()));
    }

    #[test]
    fn cp_request_is_exactly_40_bytes_in_aosp_order() {
        let cp = ConfigPayload::request(&[
            CFG_INTERNAL_IP4_ADDRESS,
            CFG_INTERNAL_IP6_ADDRESS,
            CFG_INTERNAL_IP4_DNS,
            CFG_INTERNAL_IP6_DNS,
            CFG_INTERNAL_IP4_NETMASK,
            CFG_P_CSCF_IP4_ADDRESS,
            CFG_P_CSCF_IP6_ADDRESS,
            CFG_APPLICATION_VERSION,
        ]);
        let p = Payload::Cp(cp);
        let mut out = Vec::new();
        encode_payload(&p, PT_NONE, &mut out).unwrap();
        assert_eq!(out.len(), 40);
        let expected = h("00 00 0028 | 01 00 00 00 | 0001 0000 | 0008 0000 | 0003 0000 | 000A 0000 \
            | 0002 0000 | 0014 0000 | 0015 0000 | 0007 0000");
        assert_eq!(hex::encode(&out), hex::encode(&expected));
        assert_eq!(
            hex::encode(body(&p)),
            "01000000000100000008000000030000000a000000020000001400000015000000070000"
        );
        round_trip(p);
    }

    #[test]
    fn status_notify_is_8_bytes() {
        let p = Payload::Notify(NotifyPayload::status(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![]));
        let mut out = Vec::new();
        encode_payload(&p, PT_NOTIFY, &mut out).unwrap();
        assert_eq!(hex::encode(&out), "290000080000402e");
        assert_eq!(out.len(), 8);
        round_trip(p);

        let sig = Payload::Notify(NotifyPayload::status(
            N_SIGNATURE_HASH_ALGORITHMS,
            h("0001 0002 0003 0004"),
        ));
        assert_eq!(hex::encode(body(&sig)), "0000402f0001000200030004");
        round_trip(sig);
    }

    #[test]
    fn ke_payload_layout() {
        let public = vec![0xAB; 256];
        let p = Payload::Ke(KePayload { group: DH_MODP_2048, public: public.clone() });
        let b = body(&p);
        assert_eq!(b.len(), 260);
        assert_eq!(&b[..4], &[0x00, 0x0E, 0x00, 0x00]);
        assert_eq!(&b[4..], &public[..]);
        round_trip(p);
        assert!(matches!(Payload::decode_body(PT_KE, false, &[0, 14, 0, 0]), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_KE, false, &[0, 14]), Err(Error::Decode(_))));
    }

    #[test]
    fn id_payload_layout() {
        let idi = Payload::IdI(IdPayload { id_type: ID_RFC822_ADDR, data: b"0@x.y".to_vec() });
        assert_eq!(hex::encode(body(&idi)), "03000000".to_owned() + &hex::encode(b"0@x.y"));
        round_trip(idi);
        let idr = Payload::IdR(IdPayload { id_type: ID_FQDN, data: b"ims.tmus".to_vec() });
        assert_eq!(hex::encode(body(&idr)), "02000000".to_owned() + &hex::encode(b"ims.tmus"));
        round_trip(idr);
        // empty data is legal on the wire
        round_trip(Payload::IdR(IdPayload { id_type: ID_KEY_ID, data: vec![] }));
        assert!(matches!(Payload::decode_body(PT_IDI, false, &[3, 0, 0]), Err(Error::Decode(_))));
    }

    #[test]
    fn auth_payload_layout() {
        let p = Payload::Auth(AuthPayload { method: AUTH_SHARED_KEY_MIC, data: vec![0x11; 32] });
        let b = body(&p);
        assert_eq!(&b[..4], &[2, 0, 0, 0]);
        assert_eq!(b.len(), 36);
        round_trip(p);
    }

    #[test]
    fn nonce_payload_limits() {
        round_trip(Payload::Nonce(vec![7; 32]));
        round_trip(Payload::Nonce(vec![7; 16]));
        round_trip(Payload::Nonce(vec![7; 256]));
        let mut out = Vec::new();
        assert!(matches!(Payload::Nonce(vec![1; 15]).encode_body(&mut out), Err(Error::Encode(_))));
        assert!(matches!(Payload::Nonce(vec![1; 257]).encode_body(&mut out), Err(Error::Encode(_))));
        assert!(matches!(Payload::decode_body(PT_NONCE, false, &[1; 15]), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_NONCE, false, &[1; 257]), Err(Error::Decode(_))));
    }

    #[test]
    fn notify_with_spi_and_data() {
        // REKEY_SA: protocol ESP, 4-byte SPI, no data
        let p = Payload::Notify(NotifyPayload {
            protocol_id: PROTO_ESP,
            spi: h("01020304"),
            notify_type: N_REKEY_SA,
            data: vec![],
        });
        assert_eq!(hex::encode(body(&p)), "0304400901020304");
        round_trip(p);
        // error notify with data, protocol 1 tolerated on decode
        let b = h("01 00 0011 000E");
        match Payload::decode_body(PT_NOTIFY, false, &b).unwrap() {
            Payload::Notify(n) => {
                assert_eq!(n.protocol_id, 1);
                assert_eq!(n.notify_type, N_INVALID_KE_PAYLOAD);
                assert!(n.is_error());
                assert_eq!(n.data, h("000E"));
                assert!(n.spi.is_empty());
            }
            other => panic!("{other:?}"),
        }
        assert!(!NotifyPayload::status(N_COOKIE, vec![]).is_error());
        // SPI size larger than the body
        assert!(matches!(Payload::decode_body(PT_NOTIFY, false, &h("00 08 4009 0102")), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_NOTIFY, false, &h("00 00 40")), Err(Error::Decode(_))));
    }

    #[test]
    fn delete_payload_layouts() {
        let ike = Payload::Delete(DeletePayload { protocol_id: PROTO_IKE, spis: vec![] });
        assert_eq!(hex::encode(body(&ike)), "01000000");
        round_trip(ike);
        let esp = Payload::Delete(DeletePayload {
            protocol_id: PROTO_ESP,
            spis: vec![h("AABBCCDD"), h("00112233")],
        });
        assert_eq!(hex::encode(body(&esp)), "03040002aabbccdd00112233");
        round_trip(esp);
        // errors
        let mut out = Vec::new();
        let bad = DeletePayload { protocol_id: PROTO_ESP, spis: vec![h("AABBCCDD"), h("0011")] };
        assert!(matches!(Payload::Delete(bad).encode_body(&mut out), Err(Error::Encode(_))));
        let bad = DeletePayload { protocol_id: PROTO_ESP, spis: vec![vec![]] };
        assert!(matches!(Payload::Delete(bad).encode_body(&mut out), Err(Error::Encode(_))));
        assert!(matches!(Payload::decode_body(PT_DELETE, false, &h("03 04 0002 aabbccdd")), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_DELETE, false, &h("03 04 0001 aabbccdd ee")), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_DELETE, false, &h("01 00 0001")), Err(Error::Decode(_))));
    }

    #[test]
    fn ts_narrowed_selectors_and_errors() {
        let p = Payload::TsR(TsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TS_IPV4_ADDR_RANGE,
                ip_protocol: 17,
                start_port: 5060,
                end_port: 5061,
                start_addr: h("0A000001"),
                end_addr: h("0A0000FF"),
            }],
        });
        assert_eq!(hex::encode(body(&p)), "01000000" .to_owned() + "0711001013c413c50a0000010a0000ff");
        round_trip(p);
        // wrong address length for the type
        let mut out = Vec::new();
        let bad = TsPayload {
            selectors: vec![TrafficSelector { start_addr: vec![0; 16], ..TrafficSelector::ipv4_any() }],
        };
        assert!(matches!(Payload::TsI(bad).encode_body(&mut out), Err(Error::Encode(_))));
        assert!(matches!(
            Payload::decode_body(PT_TSI, false, &h("01000000 07 00 000A 0000 FFFF 0000")),
            Err(Error::Decode(_))
        ));
        // count mismatch
        assert!(matches!(
            Payload::decode_body(PT_TSI, false, &h("02000000 07 00 0010 0000 FFFF 00000000 FFFFFFFF")),
            Err(Error::Decode(_))
        ));
        // trailing garbage
        assert!(matches!(
            Payload::decode_body(PT_TSI, false, &h("01000000 07 00 0010 0000 FFFF 00000000 FFFFFFFF 00")),
            Err(Error::Decode(_))
        ));
        // unknown TS type: split evenly
        match Payload::decode_body(PT_TSI, false, &h("01000000 09 00 000C 0000 FFFF 0102 0304")).unwrap() {
            Payload::TsI(ts) => {
                assert_eq!(ts.selectors[0].start_addr, h("0102"));
                assert_eq!(ts.selectors[0].end_addr, h("0304"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cp_reply_with_values_and_reserved_bit() {
        let reply = h("02000000 \
            | 0001 0004 0A010203 \
            | 0008 0011 20010db8000000000000000000000001 40 \
            | 0014 0004 C0A80001 \
            | 0007 0000");
        match Payload::decode_body(PT_CP, false, &reply).unwrap() {
            Payload::Cp(cp) => {
                assert_eq!(cp.cfg_type, CFG_REPLY);
                assert_eq!(cp.attributes.len(), 4);
                assert_eq!(cp.attributes[0], ConfigAttribute { attr_type: 1, value: h("0A010203") });
                assert_eq!(cp.attributes[1].attr_type, CFG_INTERNAL_IP6_ADDRESS);
                assert_eq!(cp.attributes[1].value.len(), 17);
                assert_eq!(cp.attributes[2].attr_type, CFG_P_CSCF_IP4_ADDRESS);
                assert_eq!(cp.attributes[3], ConfigAttribute { attr_type: 7, value: vec![] });
                round_trip(Payload::Cp(cp));
            }
            other => panic!("{other:?}"),
        }
        // R bit set on the wire is masked off
        match Payload::decode_body(PT_CP, false, &h("02000000 8001 0004 0A010203")).unwrap() {
            Payload::Cp(cp) => assert_eq!(cp.attributes[0].attr_type, 1),
            other => panic!("{other:?}"),
        }
        // truncated attribute value / header
        assert!(matches!(Payload::decode_body(PT_CP, false, &h("02000000 0001 0004 0A01")), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_CP, false, &h("02000000 0001 00")), Err(Error::Decode(_))));
        assert!(matches!(Payload::decode_body(PT_CP, false, &h("0200")), Err(Error::Decode(_))));
        // attribute type over 15 bits refused on encode
        let mut out = Vec::new();
        let bad = ConfigPayload { cfg_type: CFG_REQUEST, attributes: vec![ConfigAttribute { attr_type: 0x8001, value: vec![] }] };
        assert!(matches!(Payload::Cp(bad).encode_body(&mut out), Err(Error::Encode(_))));
    }

    #[test]
    fn raw_payloads_round_trip() {
        round_trip(Payload::Cert(h("04 3082")));
        round_trip(Payload::CertReq(h("04")));
        round_trip(Payload::Vendor(b"strongSwan".to_vec()));
        round_trip(Payload::Eap(h("01 01 0005 01")));
        round_trip(Payload::Eap(vec![]));
        round_trip(Payload::Unknown { payload_type: 200, critical: false, body: h("0102") });
    }

    // ---- SA decode strictness -----------------------------------------------

    #[test]
    fn sa_multi_proposal_round_trip_and_flags() {
        let sa = SaPayload {
            proposals: vec![
                Proposal {
                    number: 1,
                    protocol_id: PROTO_IKE,
                    spi: vec![],
                    transforms: vec![
                        Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 256),
                        Transform::with_key_len(TT_ENCR, ENCR_AES_CBC, 128),
                        Transform::new(TT_INTEG, AUTH_HMAC_SHA2_256_128),
                        Transform::new(TT_DH, DH_MODP_2048),
                        Transform::new(TT_DH, DH_MODP_3072),
                        Transform::new(TT_PRF, PRF_HMAC_SHA2_256),
                    ],
                },
                Proposal {
                    number: 2,
                    protocol_id: PROTO_IKE,
                    spi: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    transforms: vec![
                        Transform::new(TT_ENCR, ENCR_3DES),
                        Transform::new(TT_INTEG, AUTH_HMAC_SHA1_96),
                        Transform::new(TT_DH, DH_MODP_1024),
                        Transform::new(TT_PRF, PRF_HMAC_SHA1),
                    ],
                },
            ],
        };
        let p = Payload::Sa(sa);
        let b = body(&p);
        assert_eq!(b[0], 2); // first proposal: more
        let p1_len = u16::from_be_bytes([b[2], b[3]]) as usize;
        assert_eq!(b[p1_len], 0); // second proposal: last
        assert_eq!(b[p1_len + 6], 8); // spi size 8
        round_trip(p);
    }

    #[test]
    fn sa_decode_rejects_bad_structures() {
        let good = body(&Payload::Sa(glue_ike_sa()));
        let dec = |b: &[u8]| Payload::decode_body(PT_SA, false, b);
        assert!(dec(&good).is_ok());

        // last proposal flagged "more"
        let mut b = good.clone();
        b[0] = 2;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // invalid last/more byte
        let mut b = good.clone();
        b[0] = 1;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // transform count mismatch
        let mut b = good.clone();
        b[7] = 3;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // last transform flagged "more"
        let mut b = good.clone();
        let last_t = good.len() - 8;
        b[last_t] = 3;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // non-last transform flagged "last"
        let mut b = good.clone();
        b[8] = 0;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // proposal length exceeds buffer
        let mut b = good.clone();
        b[3] = 0x2D;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // proposal length too short (< 8)
        let mut b = good.clone();
        b[3] = 0x04;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // truncated buffer
        assert!(matches!(dec(&good[..good.len() - 1]), Err(Error::Decode(_))));
        assert!(matches!(dec(&good[..3]), Err(Error::Decode(_))));
        assert!(matches!(dec(&[]), Err(Error::Decode(_))));
        // trailing byte after last proposal
        let mut b = good.clone();
        b.push(0);
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // spi size larger than proposal
        let mut b = good.clone();
        b[6] = 200;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // zero transforms
        let mut b = good.clone();
        b[7] = 0;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // unknown transform attribute
        let mut b = good.clone();
        b[16] = 0x80;
        b[17] = 0x01;
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
        // TLV-form key length is accepted too
        let mut b = good.clone();
        b[3] = 0x2E; // proposal +2
        b[11] = 0x0E; // ENCR transform 14 bytes
        b.splice(16..20, h("000E 0002 0100"));
        match dec(&b).unwrap() {
            Payload::Sa(sa) => assert_eq!(sa.proposals[0].transforms[0].key_len_bits, Some(256)),
            other => panic!("{other:?}"),
        }
        // TLV key length with wrong value length
        let mut b = good.clone();
        b[3] = 0x2D;
        b[11] = 0x0D;
        b.splice(16..20, h("000E 0001 01"));
        assert!(matches!(dec(&b), Err(Error::Decode(_))));
    }

    #[test]
    fn sa_encode_errors() {
        let mut out = Vec::new();
        assert!(matches!(Payload::Sa(SaPayload::default()).encode_body(&mut out), Err(Error::Encode(_))));
        let no_transforms = SaPayload {
            proposals: vec![Proposal { number: 1, protocol_id: PROTO_IKE, spi: vec![], transforms: vec![] }],
        };
        assert!(matches!(Payload::Sa(no_transforms).encode_body(&mut out), Err(Error::Encode(_))));
    }

    // ---- Chains ---------------------------------------------------------------

    #[test]
    fn chain_next_pointers_and_first_type() {
        let ps = vec![
            Payload::Sa(glue_ike_sa()),
            Payload::Ke(KePayload { group: 14, public: vec![1; 256] }),
            Payload::Nonce(vec![2; 32]),
            Payload::Notify(NotifyPayload::status(N_NAT_DETECTION_SOURCE_IP, vec![3; 20])),
            Payload::Notify(NotifyPayload::status(N_NAT_DETECTION_DESTINATION_IP, vec![4; 20])),
            Payload::Notify(NotifyPayload::status(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![])),
            Payload::Notify(NotifyPayload::status(N_SIGNATURE_HASH_ALGORITHMS, h("0001000200030004"))),
        ];
        let (first, bytes) = chain(&ps);
        assert_eq!(first, PT_SA);
        assert_eq!(bytes.len(), 48 + 264 + 36 + 28 + 28 + 8 + 16);
        // walk the generic headers
        let mut off = 0;
        let mut types = vec![PT_SA];
        loop {
            let next = bytes[off];
            assert_eq!(bytes[off + 1], 0, "critical bit must be clear");
            let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            off += len;
            if next == PT_NONE {
                break;
            }
            types.push(next);
        }
        assert_eq!(off, bytes.len());
        assert_eq!(types, vec![PT_SA, PT_KE, PT_NONCE, PT_NOTIFY, PT_NOTIFY, PT_NOTIFY, PT_NOTIFY]);
        assert_eq!(decode_payloads(first, &bytes).unwrap(), ps);
    }

    #[test]
    fn ike_auth_first_request_chain() {
        let ps = vec![
            Payload::IdI(IdPayload { id_type: ID_RFC822_ADDR, data: b"0@nai.epc.mnc260.mcc310.3gppnetwork.org".to_vec() }),
            Payload::IdR(IdPayload { id_type: ID_FQDN, data: b"ims.tmus".to_vec() }),
            Payload::Notify(NotifyPayload::status(N_EAP_ONLY_AUTHENTICATION, vec![])),
            Payload::Notify(NotifyPayload::status(N_MOBIKE_SUPPORTED, vec![])),
            Payload::Sa(glue_child_sa([1, 2, 3, 4])),
            Payload::TsI(TsPayload::any_v4_v6()),
            Payload::TsR(TsPayload::any_v4_v6()),
            Payload::Cp(ConfigPayload::request(&[1, 8, 3, 10, 2, 20, 21, 7])),
        ];
        let (first, bytes) = chain(&ps);
        assert_eq!(first, PT_IDI);
        let back = decode_payloads(first, &bytes).unwrap();
        assert_eq!(back, ps);
        let types: Vec<u8> = back.iter().map(Payload::payload_type).collect();
        assert_eq!(types, vec![35, 36, 41, 41, 33, 44, 45, 47]);
    }

    #[test]
    fn empty_chain() {
        let (first, bytes) = chain(&[]);
        assert_eq!(first, PT_NONE);
        assert!(bytes.is_empty());
        assert!(decode_payloads(PT_NONE, &[]).unwrap().is_empty());
        // PT_NONE with leftover bytes is not exact consumption
        assert!(matches!(decode_payloads(PT_NONE, &[0, 0, 0, 4]), Err(Error::Decode(_))));
    }

    #[test]
    fn chain_unknown_payloads() {
        // unknown non-critical -> Unknown, chain continues
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[PT_NONCE, 0x00, 0, 7, 0xaa, 0xbb, 0xcc]);
        encode_payload(&Payload::Nonce(vec![5; 16]), PT_NONE, &mut bytes).unwrap();
        let back = decode_payloads(200, &bytes).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], Payload::Unknown { payload_type: 200, critical: false, body: vec![0xaa, 0xbb, 0xcc] });
        assert_eq!(back[1], Payload::Nonce(vec![5; 16]));

        // unknown critical -> Error::Decode mentioning UNSUPPORTED_CRITICAL_PAYLOAD
        bytes[1] = 0x80;
        match decode_payloads(200, &bytes) {
            Err(Error::Decode(m)) => assert!(m.contains("UNSUPPORTED_CRITICAL_PAYLOAD"), "{m}"),
            other => panic!("{other:?}"),
        }

        // known payload with critical bit set is fine
        let mut bytes = Vec::new();
        encode_payload(&Payload::Nonce(vec![5; 16]), PT_NONE, &mut bytes).unwrap();
        bytes[1] = 0x80;
        assert_eq!(decode_payloads(PT_NONCE, &bytes).unwrap(), vec![Payload::Nonce(vec![5; 16])]);

        // SK / SKF inside a chain pass through as Unknown even with C=1
        for t in [PT_SK, PT_SKF] {
            let bytes = [PT_NONE, 0x80, 0, 6, 1, 2];
            match decode_payloads(t, &bytes).unwrap().as_slice() {
                [Payload::Unknown { payload_type, body, .. }] => {
                    assert_eq!(*payload_type, t);
                    assert_eq!(body, &vec![1, 2]);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn chain_length_errors() {
        let (first, good) = chain(&[Payload::Nonce(vec![9; 32]), Payload::Vendor(vec![1, 2, 3])]);
        assert!(decode_payloads(first, &good).is_ok());

        // truncated in the middle of a body
        assert!(matches!(decode_payloads(first, &good[..good.len() - 1]), Err(Error::Decode(_))));
        // truncated inside a generic header
        assert!(matches!(decode_payloads(first, &good[..38]), Err(Error::Decode(_))));
        // trailing bytes after the last payload
        let mut b = good.clone();
        b.push(0);
        assert!(matches!(decode_payloads(first, &b), Err(Error::Decode(_))));
        // length < 4
        let mut b = good.clone();
        b[3] = 3;
        assert!(matches!(decode_payloads(first, &b), Err(Error::Decode(_))));
        // length overruns buffer
        let mut b = good.clone();
        b[3] = 0xff;
        assert!(matches!(decode_payloads(first, &b), Err(Error::Decode(_))));
        // last payload's next pointer not 0 with nothing following
        let mut b = good.clone();
        let second = 36;
        b[second] = PT_NONCE;
        assert!(matches!(decode_payloads(first, &b), Err(Error::Decode(_))));
        // empty buffer but a payload announced
        assert!(matches!(decode_payloads(PT_SA, &[]), Err(Error::Decode(_))));
    }

    #[test]
    fn oversize_payload_refused() {
        let mut out = Vec::new();
        let p = Payload::Eap(vec![0; 65532]);
        assert!(matches!(encode_payload(&p, PT_NONE, &mut out), Err(Error::Encode(_))));
        let mut out = Vec::new();
        let p = Payload::Eap(vec![0; 65531]);
        assert!(encode_payload(&p, PT_NONE, &mut out).is_ok());
        assert_eq!(out.len(), 65535);
    }

    #[test]
    fn payload_type_mapping() {
        assert_eq!(Payload::Sa(SaPayload::default()).payload_type(), 33);
        assert_eq!(Payload::Ke(KePayload { group: 0, public: vec![] }).payload_type(), 34);
        assert_eq!(Payload::IdI(IdPayload { id_type: 0, data: vec![] }).payload_type(), 35);
        assert_eq!(Payload::IdR(IdPayload { id_type: 0, data: vec![] }).payload_type(), 36);
        assert_eq!(Payload::Cert(vec![]).payload_type(), 37);
        assert_eq!(Payload::CertReq(vec![]).payload_type(), 38);
        assert_eq!(Payload::Auth(AuthPayload { method: 0, data: vec![] }).payload_type(), 39);
        assert_eq!(Payload::Nonce(vec![]).payload_type(), 40);
        assert_eq!(Payload::Notify(NotifyPayload::status(0, vec![])).payload_type(), 41);
        assert_eq!(Payload::Delete(DeletePayload { protocol_id: 1, spis: vec![] }).payload_type(), 42);
        assert_eq!(Payload::Vendor(vec![]).payload_type(), 43);
        assert_eq!(Payload::TsI(TsPayload::default()).payload_type(), 44);
        assert_eq!(Payload::TsR(TsPayload::default()).payload_type(), 45);
        assert_eq!(Payload::Cp(ConfigPayload::request(&[])).payload_type(), 47);
        assert_eq!(Payload::Eap(vec![]).payload_type(), 48);
        assert_eq!(Payload::Unknown { payload_type: 99, critical: false, body: vec![] }.payload_type(), 99);
    }
}
