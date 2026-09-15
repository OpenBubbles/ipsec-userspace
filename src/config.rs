//! Configuration model + carrier-bundle plist parsing (DESIGN.md §2).
//!
//! The model mirrors what the proven AOSP client negotiates: the values that
//! come from the carrier bundle (`imsCommonCredentials`, `CBRoot.TechSettings`)
//! and the individual credentials plist are mapped here; everything the bundle
//! does not carry takes the AOSP `IkeSessionParams` default from §14.

use std::io::Cursor;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;

use log::{debug, warn};
use plist::{Dictionary, Value};

use crate::error::{Error, Result};
use crate::ike::constants::{
    CFG_APPLICATION_VERSION, CFG_INTERNAL_IP4_ADDRESS, CFG_INTERNAL_IP4_DNS,
    CFG_INTERNAL_IP4_NETMASK, CFG_INTERNAL_IP6_ADDRESS, CFG_INTERNAL_IP6_DNS,
    CFG_P_CSCF_IP4_ADDRESS, CFG_P_CSCF_IP6_ADDRESS, ID_FQDN, ID_IPV4_ADDR, ID_IPV6_ADDR,
    ID_RFC822_ADDR, PORT_IKE, PORT_NATT,
};

/// Bundle `ExtraConfigurationAttributeRequest*` identifier for the IPv4 P-CSCF request.
const BUNDLE_EXTRA_PCSCF_IPV4: u64 = 16384;
/// Bundle `ExtraConfigurationAttributeRequest*` identifier for the IPv6 P-CSCF request.
const BUNDLE_EXTRA_PCSCF_IPV6: u64 = 16386;
/// Placeholder inside `IKE.LocalIdentifier` replaced by the top-level `subscriberId`.
const SUBSCRIBER_ID_PLACEHOLDER: &str = "$subscriber-id";
/// The only EAP method implemented.
const EAP_METHOD_TLS: &str = "EAP-TLS";

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    pub gateway: GatewayConfig,
    pub identity: IdentityConfig,
    pub eap_tls: EapTlsCredentials,
    pub ike: IkeConfig,
    pub child: ChildConfig,
    pub ims: ImsConfig,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// `imsCommonCredentials."gateway-address"`.
    pub hostname: String,
    /// `CBRoot.TechSettings.IKE.RemoteAddress`.
    pub fallback_addr: Option<IpAddr>,
    /// 500.
    pub ike_port: u16,
    /// 4500.
    pub natt_port: u16,
    /// Bind address override; `None` = OS default.
    pub local_addr: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// IDi: `IKE.LocalIdentifier` with `$subscriber-id` -> top-level `subscriberId`.
    pub local_id: IdSpec,
    /// IDr: `imsIndividualCredentials.apn` as FQDN.
    pub remote_id: IdSpec,
    /// Default true (the ePDG returns its own identity, not the APN).
    pub accept_any_remote_id: bool,
    /// EAP Response/Identity body; default = the local_id string.
    pub eap_identity: Vec<u8>,
}

/// An IKEv2 Identification payload body: `id_type` is one of the `ID_*` constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSpec {
    pub id_type: u8,
    pub data: Vec<u8>,
}

impl IdSpec {
    /// Classify a textual identity: contains `'@'` -> `ID_RFC822_ADDR`; parses as an IP
    /// address -> `ID_IPV4_ADDR` / `ID_IPV6_ADDR` (raw address bytes); else `ID_FQDN`.
    pub fn from_string(s: &str) -> IdSpec {
        if s.contains('@') {
            return IdSpec { id_type: ID_RFC822_ADDR, data: s.as_bytes().to_vec() };
        }
        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => IdSpec { id_type: ID_IPV4_ADDR, data: v4.octets().to_vec() },
            Ok(IpAddr::V6(v6)) => IdSpec { id_type: ID_IPV6_ADDR, data: v6.octets().to_vec() },
            Err(_) => IdSpec { id_type: ID_FQDN, data: s.as_bytes().to_vec() },
        }
    }

    /// Build an `ID_FQDN` identity from a host name verbatim (no IP/email classification).
    pub fn fqdn(s: &str) -> IdSpec {
        IdSpec { id_type: ID_FQDN, data: s.as_bytes().to_vec() }
    }
}

/// EAP-TLS material, DER only. PEM never enters the configuration: convert it once with
/// [`crate::pem`] where it arrives (test fixtures, a provisioning server's response).
#[derive(Clone)]
pub struct EapTlsCredentials {
    /// Client (leaf) certificate: one DER `Certificate`. Only this certificate is sent.
    pub client_cert_der: Vec<u8>,
    /// Private key matching `client_cert_der`: unencrypted PKCS#8 `PrivateKeyInfo`, DER.
    pub client_key_der: Vec<u8>,
    /// Trust anchors for the server certificate, one DER `Certificate` each (bundle
    /// `ePdgCACert`); empty = none. Used only when `validate_server_cert`.
    pub server_ca_der: Vec<Vec<u8>>,
    /// `IKE.ValidateRemoteCertificate`.
    pub validate_server_cert: bool,
    /// SNI; `None` = use gateway IP (no SNI sent).
    pub tls_server_name: Option<String>,
    /// Outbound EAP-TLS fragment TLS-data bytes; default 1024 (AOSP).
    pub max_fragment_len: usize,
    /// Default false: AOSP is TLS 1.2 only. If true, also offer 1.3 (MSK per RFC 9190).
    pub allow_tls13: bool,
}

impl std::fmt::Debug for EapTlsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EapTlsCredentials")
            .field("client_cert_der", &format_args!("<{} bytes>", self.client_cert_der.len()))
            .field("client_key_der", &"<redacted>")
            .field("server_ca_der", &format_args!("<{} certificate(s)>", self.server_ca_der.len()))
            .field("validate_server_cert", &self.validate_server_cert)
            .field("tls_server_name", &self.tls_server_name)
            .field("max_fragment_len", &self.max_fragment_len)
            .field("allow_tls13", &self.allow_tls13)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct IkeConfig {
    /// `IKE.Proposals[]` in order.
    pub proposals: Vec<IkeProposal>,
    /// `IKE.Proposals[0].Lifetime` (80000).
    pub lifetime_secs: u64,
    /// `AuthenticationMethod == "None"` -> true (always true for now).
    pub eap_only: bool,
    /// "EAP-TLS".
    pub eap_method: String,
    pub dpd: DpdConfig,
    pub natt: NattConfig,
    pub retransmit: RetransmitConfig,
    /// Announce IKEV2_FRAGMENTATION_SUPPORTED; default true.
    pub fragmentation: bool,
    /// SKF split when the total IKE message exceeds this; default 1280.
    pub fragment_threshold: usize,
    /// Send N(SIGNATURE_HASH_ALGORITHMS) in IKE_SA_INIT; default true.
    pub signature_hash_algorithms: bool,
    /// Announce MOBIKE_SUPPORTED in IKE_AUTH; default true.
    pub mobike: bool,
    /// Default false.
    pub initial_contact: bool,
    /// Default 32.
    pub nonce_len: usize,
    /// Rekey at `lifetime * (1 - margin)`; default 0.1.
    pub rekey_margin_fraction: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkeProposal {
    pub encryption: Vec<String>,
    pub integrity: Vec<String>,
    pub prf: Vec<String>,
    pub dh_groups: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct ChildConfig {
    /// `ChildSAs.FirstChild.ChildProposals[]`.
    pub proposals: Vec<ChildProposal>,
    pub lifetime_secs: u64,
    /// `ReplayWindowSize` (12) — the codec rounds up to >= 32.
    pub replay_window: u32,
    /// CFG attribute types to request, in emission order.
    pub cfg_requests: Vec<u16>,
    /// Carried, unused.
    pub install_policies: bool,
    /// Wire MTU of the inner (tunnelled) IP interface in bytes of IP packet: no ESP
    /// payload is larger. Not in the bundle, defaults to [`DEFAULT_INNER_MTU`]; the
    /// stack clamps it to `[1280, 65535]`. Larger packets are fragmented for the wire
    /// (IPv4 and IPv6) by the §11.1 shim.
    pub inner_mtu: usize,
    /// MTU the smoltcp stack sees (DESIGN.md §11.1), i.e. the largest inner IP packet
    /// one UDP datagram may occupy before fragmentation: `send_to` accepts payloads up
    /// to `inner_mtu_stack - 48` (IPv6) / `- 28` (IPv4). Not in the bundle, defaults
    /// to [`DEFAULT_INNER_MTU_STACK`]; raised to at least `inner_mtu`.
    pub inner_mtu_stack: usize,
}

/// Default inner MTU: the IPv6 minimum link MTU (RFC 8200 §5), which is also what
/// AOSP's IKE client and the ePDG assume for the tunnelled link. Bundle-independent.
pub const DEFAULT_INNER_MTU: usize = 1280;
/// Default stack MTU (§11.1): large enough for any SIP message over UDP.
pub const DEFAULT_INNER_MTU_STACK: usize = 16384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildProposal {
    pub encryption: Vec<String>,
    pub integrity: Vec<String>,
    /// PFS groups; empty for this profile.
    pub dh_groups: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub retry_interval_secs: u64,
    pub max_retries: u32,
}

impl Default for DpdConfig {
    fn default() -> Self {
        DpdConfig { enabled: false, interval_secs: 600, retry_interval_secs: 10, max_retries: 4 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NattConfig {
    /// Default 10 (AOSP IKE_NATT_KEEPALIVE_DELAY_SEC_DEFAULT).
    pub keepalive_interval_secs: u64,
    /// Bundle `DisableSwitchToNATTPort` (false).
    pub disable_switch_to_natt_port: bool,
    /// Default true: hash NAT_DETECTION_SOURCE_IP over the fake local address 192.0.2.0
    /// so the responder always detects a NAT and uses UDP-encapsulated ESP.
    pub force_udp_encap: bool,
    /// Bundle `NATTKeepAliveOffload`; carried.
    pub keepalive_offload: bool,
}

impl Default for NattConfig {
    fn default() -> Self {
        NattConfig {
            keepalive_interval_secs: 10,
            disable_switch_to_natt_port: false,
            force_udp_encap: true,
            keepalive_offload: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetransmitConfig {
    /// 500 ms.
    pub initial_timeout_ms: u64,
    /// 2.0.
    pub backoff_multiplier: f64,
    /// 5 transmissions total (AOSP {500,1000,2000,4000,8000} ms): send at t=0, +0.5, +1.5, +3.5, +7.5 s
    /// cumulative; after the 5th send wait 8 s then `Error::Timeout` (15.5 s). See DESIGN §2/§14.
    pub max_attempts: u32,
}

impl Default for RetransmitConfig {
    fn default() -> Self {
        RetransmitConfig { initial_timeout_ms: 500, backoff_multiplier: 2.0, max_attempts: 5 }
    }
}

#[derive(Clone)]
pub struct ImsConfig {
    pub pcscf_address: String,
    pub apn: String,
    pub impu: String,
    pub sip_realm: String,
    pub username: String,
    pub password: String,
    pub imsi: String,
}

impl std::fmt::Debug for ImsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImsConfig")
            .field("pcscf_address", &self.pcscf_address)
            .field("apn", &self.apn)
            .field("impu", &self.impu)
            .field("sip_realm", &self.sip_realm)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("imsi", &self.imsi)
            .finish()
    }
}

/// Exact AOSP CFG_REQUEST attribute order (§2 / §14), all zero-length.
pub fn default_cfg_requests() -> Vec<u16> {
    vec![
        CFG_INTERNAL_IP4_ADDRESS,
        CFG_INTERNAL_IP6_ADDRESS,
        CFG_INTERNAL_IP4_DNS,
        CFG_INTERNAL_IP6_DNS,
        CFG_INTERNAL_IP4_NETMASK,
        CFG_P_CSCF_IP4_ADDRESS,
        CFG_P_CSCF_IP6_ADDRESS,
        CFG_APPLICATION_VERSION,
    ]
}

// ---------------------------------------------------------------------------
// plist access helpers
// ---------------------------------------------------------------------------

fn cfg_err(msg: impl std::fmt::Display) -> Error {
    Error::Config(msg.to_string())
}

fn as_dict<'a>(v: &'a Value, what: &str) -> Result<&'a Dictionary> {
    v.as_dictionary().ok_or_else(|| cfg_err(format!("{what}: expected a dictionary")))
}

/// Walk a dotted path of dictionary keys; `Ok(None)` when any segment is absent.
fn get_path<'a>(root: &'a Value, path: &[&str]) -> Result<Option<&'a Value>> {
    let mut cur = root;
    for (i, key) in path.iter().enumerate() {
        let dict = as_dict(cur, &path[..i].join("."))?;
        match dict.get(key) {
            Some(v) => cur = v,
            None => return Ok(None),
        }
    }
    Ok(Some(cur))
}

fn get_dict<'a>(root: &'a Value, path: &[&str]) -> Result<Option<&'a Dictionary>> {
    match get_path(root, path)? {
        Some(v) => as_dict(v, &path.join(".")).map(Some),
        None => Ok(None),
    }
}

fn req_dict<'a>(root: &'a Value, path: &[&str]) -> Result<&'a Dictionary> {
    get_dict(root, path)?.ok_or_else(|| cfg_err(format!("missing {}", path.join("."))))
}

fn dict_string(d: &Dictionary, key: &str) -> Result<Option<String>> {
    match d.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_string()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| cfg_err(format!("{key}: expected a string"))),
    }
}

fn req_string(d: &Dictionary, key: &str, ctx: &str) -> Result<String> {
    dict_string(d, key)?.ok_or_else(|| cfg_err(format!("missing {ctx}.{key}")))
}

fn dict_bool(d: &Dictionary, key: &str, default: bool) -> Result<bool> {
    match d.get(key) {
        None => Ok(default),
        Some(v) => v.as_boolean().ok_or_else(|| cfg_err(format!("{key}: expected a boolean"))),
    }
}

fn value_u64(v: &Value, key: &str) -> Result<u64> {
    if let Some(u) = v.as_unsigned_integer() {
        return Ok(u);
    }
    if let Some(i) = v.as_signed_integer() {
        return u64::try_from(i).map_err(|_| cfg_err(format!("{key}: negative integer")));
    }
    if let Some(s) = v.as_string() {
        return s.trim().parse::<u64>().map_err(|_| cfg_err(format!("{key}: expected an integer")));
    }
    Err(cfg_err(format!("{key}: expected an integer")))
}

fn dict_u64(d: &Dictionary, key: &str) -> Result<Option<u64>> {
    d.get(key).map(|v| value_u64(v, key)).transpose()
}

fn dict_u64_or(d: &Dictionary, key: &str, default: u64) -> Result<u64> {
    Ok(dict_u64(d, key)?.unwrap_or(default))
}

/// Accept a plist string OR an array of strings (the bundle uses both shapes).
fn string_or_array(d: &Dictionary, key: &str) -> Result<Vec<String>> {
    match d.get(key) {
        None => Ok(Vec::new()),
        Some(v) => {
            if let Some(s) = v.as_string() {
                return Ok(vec![s.to_string()]);
            }
            let arr = v
                .as_array()
                .ok_or_else(|| cfg_err(format!("{key}: expected a string or array of strings")))?;
            arr.iter()
                .map(|e| {
                    e.as_string()
                        .map(str::to_string)
                        .ok_or_else(|| cfg_err(format!("{key}: array element is not a string")))
                })
                .collect()
        }
    }
}

/// Accept a plist integer OR an array of integers.
fn u16_or_array(d: &Dictionary, key: &str) -> Result<Vec<u16>> {
    let to_u16 = |v: &Value| -> Result<u16> {
        let n = value_u64(v, key)?;
        u16::try_from(n).map_err(|_| cfg_err(format!("{key}: value {n} out of range")))
    };
    match d.get(key) {
        None => Ok(Vec::new()),
        Some(v) => match v.as_array() {
            Some(arr) => arr.iter().map(to_u16).collect(),
            None => Ok(vec![to_u16(v)?]),
        },
    }
}

fn dict_array<'a>(d: &'a Dictionary, key: &str) -> Result<&'a [Value]> {
    match d.get(key) {
        None => Ok(&[]),
        Some(v) => v
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| cfg_err(format!("{key}: expected an array"))),
    }
}

// ---------------------------------------------------------------------------
// Bundle mapping
// ---------------------------------------------------------------------------

impl Config {
    /// Build from the decoded carrier bundle (root dict with `imsCommonCredentials`/`CBRoot`),
    /// the individual-credentials dict (`imsIndividualCredentials`/`subscriberId`/...), the
    /// client certificate (one DER `Certificate`) and its private key (PKCS#8 DER). PEM
    /// material goes through [`crate::pem`] first.
    pub fn from_plist_bundle(
        bundle: &Value,
        creds: &Value,
        client_cert_der: &[u8],
        client_key_der: &[u8],
    ) -> Result<Config> {
        let common = req_dict(bundle, &["imsCommonCredentials"])?;
        let tech = req_dict(bundle, &["CBRoot", "TechSettings"])?;
        let ike_dict = req_dict(bundle, &["CBRoot", "TechSettings", "IKE"])?;
        let creds_root = as_dict(creds, "credentials")?;
        let indiv = req_dict(creds, &["imsIndividualCredentials"])?;

        // --- gateway ---
        let hostname = req_string(common, "gateway-address", "imsCommonCredentials")?;
        let fallback_addr = match dict_string(ike_dict, "RemoteAddress")? {
            Some(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| cfg_err(format!("IKE.RemoteAddress: not an IP address: {s}")))?,
            ),
            _ => None,
        };
        let gateway = GatewayConfig {
            hostname,
            fallback_addr,
            ike_port: PORT_IKE,
            natt_port: PORT_NATT,
            local_addr: None,
        };

        // --- identity ---
        let apn = req_string(indiv, "apn", "imsIndividualCredentials")?;
        let local_id_template = req_string(ike_dict, "LocalIdentifier", "IKE")?;
        let local_id_str = if local_id_template.contains(SUBSCRIBER_ID_PLACEHOLDER) {
            let subscriber_id = match req_string(creds_root, "subscriberId", "credentials") {
                Ok(v) => v,
                Err(top) => req_string(indiv, "subscriberId", "imsIndividualCredentials").map_err(|_| top)?,
            };
            local_id_template.replace(SUBSCRIBER_ID_PLACEHOLDER, &subscriber_id)
        } else {
            local_id_template
        };
        let identity = IdentityConfig {
            local_id: IdSpec::from_string(&local_id_str),
            remote_id: IdSpec::fqdn(&apn),
            accept_any_remote_id: true,
            eap_identity: local_id_str.as_bytes().to_vec(),
        };

        // --- EAP-TLS ---
        // `ePdgCACert` is `<data>`: one DER certificate, or empty for none (both real bundles,
        // T-Mobile and Verizon, carry it empty at the root). Anything but data is an error —
        // PEM is not accepted here.
        let server_ca_der: Vec<Vec<u8>> = match [
            ike_dict.get("ePdgCACert"),
            tech.get("ePdgCACert"),
            common.get("ePdgCACert"),
            as_dict(bundle, "bundle")?.get("ePdgCACert"),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            None => Vec::new(),
            Some(Value::Data(der)) if der.is_empty() => Vec::new(),
            Some(Value::Data(der)) => vec![der.clone()],
            Some(_) => return Err(cfg_err("ePdgCACert: expected <data> holding one DER certificate (PEM is not accepted)")),
        };
        let eap_tls = EapTlsCredentials {
            client_cert_der: client_cert_der.to_vec(),
            client_key_der: client_key_der.to_vec(),
            server_ca_der,
            validate_server_cert: dict_bool(ike_dict, "ValidateRemoteCertificate", false)?,
            tls_server_name: None,
            max_fragment_len: 1024,
            allow_tls13: false,
        };

        // --- IKE proposals ---
        let proposal_values = dict_array(ike_dict, "Proposals")?;
        if proposal_values.is_empty() {
            return Err(cfg_err("IKE.Proposals: no proposals"));
        }
        let mut proposals = Vec::with_capacity(proposal_values.len());
        for (i, pv) in proposal_values.iter().enumerate() {
            let p = as_dict(pv, &format!("IKE.Proposals[{i}]"))?;
            proposals.push(IkeProposal {
                encryption: string_or_array(p, "EncryptionAlgorithm")?,
                integrity: string_or_array(p, "IntegrityAlgorithm")?,
                prf: string_or_array(p, "PRFAlgorithm")?,
                dh_groups: u16_or_array(p, "DHGroup")?,
            });
        }
        let first = as_dict(&proposal_values[0], "IKE.Proposals[0]")?;
        let lifetime_secs = dict_u64_or(first, "Lifetime", 7200)?;
        let auth_method = dict_string(first, "AuthenticationMethod")?.unwrap_or_else(|| "None".into());
        let eap_only = auth_method == "None";
        let eap_method = dict_string(first, "EAPMethod")?.unwrap_or_else(|| EAP_METHOD_TLS.into());
        if eap_method != EAP_METHOD_TLS {
            return Err(cfg_err(format!(
                "IKE.Proposals[0].EAPMethod = {eap_method:?}: only {EAP_METHOD_TLS} is implemented"
            )));
        }

        let dpd_default = DpdConfig::default();
        let dpd = DpdConfig {
            enabled: dict_bool(ike_dict, "DeadPeerDetectionEnabled", dpd_default.enabled)?,
            interval_secs: dict_u64_or(ike_dict, "DeadPeerDetectionInterval", dpd_default.interval_secs)?,
            retry_interval_secs: dict_u64_or(
                ike_dict,
                "DeadPeerDetectionRetryInterval",
                dpd_default.retry_interval_secs,
            )?,
            max_retries: u32::try_from(dict_u64_or(
                ike_dict,
                "DeadPeerDetectionMaxRetries",
                u64::from(dpd_default.max_retries),
            )?)
            .map_err(|_| cfg_err("DeadPeerDetectionMaxRetries out of range"))?,
        };
        let natt_default = NattConfig::default();
        let natt = NattConfig {
            keepalive_interval_secs: natt_default.keepalive_interval_secs,
            disable_switch_to_natt_port: dict_bool(
                ike_dict,
                "DisableSwitchToNATTPort",
                natt_default.disable_switch_to_natt_port,
            )?,
            force_udp_encap: natt_default.force_udp_encap,
            keepalive_offload: dict_bool(ike_dict, "NATTKeepAliveOffload", natt_default.keepalive_offload)?,
        };
        let ike = IkeConfig {
            proposals,
            lifetime_secs,
            eap_only,
            eap_method,
            dpd,
            natt,
            retransmit: RetransmitConfig::default(),
            fragmentation: true,
            fragment_threshold: 1280,
            signature_hash_algorithms: true,
            mobike: true,
            initial_contact: false,
            nonce_len: 32,
            rekey_margin_fraction: 0.1,
        };

        // --- child ---
        let first_child = req_dict(bundle, &["CBRoot", "TechSettings", "ChildSAs", "FirstChild"])?;
        let child_values = dict_array(first_child, "ChildProposals")?;
        if child_values.is_empty() {
            return Err(cfg_err("ChildSAs.FirstChild.ChildProposals: no proposals"));
        }
        let mut child_proposals = Vec::with_capacity(child_values.len());
        for (i, cv) in child_values.iter().enumerate() {
            let p = as_dict(cv, &format!("ChildProposals[{i}]"))?;
            child_proposals.push(ChildProposal {
                encryption: string_or_array(p, "EncryptionAlgorithm")?,
                integrity: string_or_array(p, "IntegrityAlgorithm")?,
                dh_groups: u16_or_array(p, "DHGroup")?,
            });
        }
        let child_first = as_dict(&child_values[0], "ChildProposals[0]")?;
        let child_lifetime = dict_u64_or(child_first, "Lifetime", 3600)?;
        let replay_window = u32::try_from(dict_u64_or(first_child, "ReplayWindowSize", 32)?)
            .map_err(|_| cfg_err("ReplayWindowSize out of range"))?;
        let child = ChildConfig {
            proposals: child_proposals,
            lifetime_secs: child_lifetime,
            replay_window,
            cfg_requests: build_cfg_requests(tech)?,
            install_policies: dict_bool(first_child, "InstallPolicies", false)?,
            inner_mtu: DEFAULT_INNER_MTU,
            inner_mtu_stack: DEFAULT_INNER_MTU_STACK,
        };

        // --- IMS ---
        let ims = ImsConfig {
            pcscf_address: dict_string(indiv, "pcscf-address")?.unwrap_or_default(),
            apn,
            impu: dict_string(indiv, "impu")?.unwrap_or_default(),
            sip_realm: dict_string(indiv, "sip-uri")?.unwrap_or_default(),
            username: dict_string(indiv, "username")?.unwrap_or_default(),
            password: dict_string(indiv, "password")?.unwrap_or_default(),
            imsi: dict_string(indiv, "imsi")?.unwrap_or_default(),
        };

        let cfg = Config { gateway, identity, eap_tls, ike, child, ims };
        debug!(
            "config: gateway={} fallback={:?} local_id={} remote_id={} cfg_requests={:?}",
            cfg.gateway.hostname,
            cfg.gateway.fallback_addr,
            String::from_utf8_lossy(&cfg.identity.local_id.data),
            String::from_utf8_lossy(&cfg.identity.remote_id.data),
            cfg.child.cfg_requests
        );
        Ok(cfg)
    }

    /// Read the two plists and the PEM certificate/key files — the fixture format
    /// (`tests/fixtures/client.{crt,key}`), converted to DER here via [`crate::pem`] — and
    /// call [`Config::from_plist_bundle`].
    pub fn from_plist_files(bundle: &Path, creds: &Path, client_cert_pem: &Path, client_key_pem: &Path) -> Result<Config> {
        let bundle_v = read_plist(bundle)?;
        let creds_v = read_plist(creds)?;
        let cert_pem = std::fs::read_to_string(client_cert_pem)
            .map_err(|e| cfg_err(format!("read {}: {e}", client_cert_pem.display())))?;
        let key_pem = std::fs::read_to_string(client_key_pem)
            .map_err(|e| cfg_err(format!("read {}: {e}", client_key_pem.display())))?;
        let cert_der = crate::pem::certificate_pem_to_der(&cert_pem)?;
        let key_der = crate::pem::private_key_pem_to_pkcs8_der(&key_pem)?;
        Config::from_plist_bundle(&bundle_v, &creds_v, &cert_der, &key_der)
    }

    /// Resolve the gateway: DNS `hostname` (all A/AAAA, IPv4 first), then `fallback_addr`
    /// appended if not already present. If DNS fails and a fallback exists, the fallback
    /// alone is returned; only a failed lookup with no fallback is an error.
    pub fn gateway_candidates(&self) -> Result<Vec<IpAddr>> {
        let mut out: Vec<IpAddr> = Vec::new();
        let push_unique = |ip: IpAddr, out: &mut Vec<IpAddr>| {
            if !out.contains(&ip) {
                out.push(ip);
            }
        };

        let resolved: Vec<IpAddr> = match (self.gateway.hostname.as_str(), self.gateway.ike_port)
            .to_socket_addrs()
        {
            Ok(addrs) => addrs.map(|a| a.ip()).collect(),
            Err(e) => {
                warn!("DNS lookup of {} failed: {e}", self.gateway.hostname);
                Vec::new()
            }
        };
        for ip in resolved.iter().filter(|ip| ip.is_ipv4()) {
            push_unique(*ip, &mut out);
        }
        for ip in resolved.iter().filter(|ip| ip.is_ipv6()) {
            push_unique(*ip, &mut out);
        }
        if let Some(fb) = self.gateway.fallback_addr {
            push_unique(fb, &mut out);
        }
        if out.is_empty() {
            return Err(cfg_err(format!(
                "could not resolve gateway {} and no fallback address configured",
                self.gateway.hostname
            )));
        }
        debug!("gateway candidates for {}: {:?}", self.gateway.hostname, out);
        Ok(out)
    }
}

fn read_plist(path: &Path) -> Result<Value> {
    let bytes = std::fs::read(path).map_err(|e| cfg_err(format!("read {}: {e}", path.display())))?;
    Value::from_reader(Cursor::new(bytes))
        .map_err(|e| cfg_err(format!("parse plist {}: {e}", path.display())))
}

/// `[1, 8, 3, 10, 2]` + P-CSCF attributes from `ExtraConfigurationAttributeRequestv4/v6`
/// (16384 -> 20, 16386 -> 21; deduped) + `APPLICATION_VERSION(7)` last.
fn build_cfg_requests(tech: &Dictionary) -> Result<Vec<u16>> {
    let mut out = vec![
        CFG_INTERNAL_IP4_ADDRESS,
        CFG_INTERNAL_IP6_ADDRESS,
        CFG_INTERNAL_IP4_DNS,
        CFG_INTERNAL_IP6_DNS,
        CFG_INTERNAL_IP4_NETMASK,
    ];
    for key in ["ExtraConfigurationAttributeRequestv4", "ExtraConfigurationAttributeRequestv6"] {
        for (i, entry) in dict_array(tech, key)?.iter().enumerate() {
            let d = as_dict(entry, &format!("{key}[{i}]"))?;
            let Some(id) = dict_u64(d, "Identifier")? else {
                warn!("{key}[{i}]: missing Identifier, ignored");
                continue;
            };
            let attr = match id {
                BUNDLE_EXTRA_PCSCF_IPV4 => CFG_P_CSCF_IP4_ADDRESS,
                BUNDLE_EXTRA_PCSCF_IPV6 => CFG_P_CSCF_IP6_ADDRESS,
                other => {
                    warn!("{key}[{i}]: unknown extra config attribute identifier {other}, ignored");
                    continue;
                }
            };
            if !out.contains(&attr) {
                out.push(attr);
            }
        }
    }
    out.push(CFG_APPLICATION_VERSION);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    const BUNDLE: &str = include_str!("../tests/fixtures/tmobile_prod_bundle.plist");
    const CREDS: &str = include_str!("../tests/fixtures/tmobile_creds.plist");
    const CERT_PEM: &str = include_str!("../tests/fixtures/client.crt");
    const KEY_PEM: &str = include_str!("../tests/fixtures/client.key");

    /// The fixture credentials as the configuration wants them: DER.
    fn cert_der() -> Vec<u8> {
        crate::pem::certificate_pem_to_der(CERT_PEM).expect("fixture certificate PEM")
    }

    fn key_der() -> Vec<u8> {
        crate::pem::private_key_pem_to_pkcs8_der(KEY_PEM).expect("fixture key PEM")
    }

    fn parse(xml: &str) -> Value {
        Value::from_reader(Cursor::new(xml.as_bytes())).expect("fixture plist parses")
    }

    fn fixture_config() -> Config {
        Config::from_plist_bundle(&parse(BUNDLE), &parse(CREDS), &cert_der(), &key_der()).expect("fixture config")
    }

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    const LOCAL_ID: &str = "900999990302421609@prodepdg.t-mobile.com";

    #[test]
    fn gateway_fields() {
        let c = fixture_config();
        assert_eq!(c.gateway.hostname, "ns.sipgeo.t-mobile.com");
        assert_eq!(c.gateway.fallback_addr, Some(IpAddr::V4(Ipv4Addr::new(208, 54, 40, 79))));
        assert_eq!(c.gateway.ike_port, 500);
        assert_eq!(c.gateway.natt_port, 4500);
        assert_eq!(c.gateway.local_addr, None);
    }

    #[test]
    fn identity_fields() {
        let c = fixture_config();
        assert_eq!(c.identity.local_id.id_type, ID_RFC822_ADDR);
        assert_eq!(c.identity.local_id.data, LOCAL_ID.as_bytes());
        assert_eq!(c.identity.remote_id.id_type, ID_FQDN);
        assert_eq!(c.identity.remote_id.data, b"ims.tmus");
        assert!(c.identity.accept_any_remote_id);
        assert_eq!(c.identity.eap_identity, LOCAL_ID.as_bytes());
    }

    #[test]
    fn eap_tls_fields() {
        let c = fixture_config();
        assert_eq!(c.eap_tls.client_cert_der, cert_der());
        assert_eq!(c.eap_tls.client_key_der, key_der());
        // DER, not PEM: a SEQUENCE tag up front and no PEM boundary anywhere.
        assert_eq!(c.eap_tls.client_cert_der[0], 0x30);
        assert_eq!(c.eap_tls.client_key_der[0], 0x30);
        assert!(!c.eap_tls.client_cert_der.starts_with(b"-----BEGIN"));
        assert!(c.eap_tls.server_ca_der.is_empty());
        assert!(!c.eap_tls.validate_server_cert);
        assert_eq!(c.eap_tls.tls_server_name, None);
        assert_eq!(c.eap_tls.max_fragment_len, 1024);
        assert!(!c.eap_tls.allow_tls13);
        // Debug must not leak the private key.
        let dbg = format!("{:?}", c.eap_tls);
        assert!(dbg.contains("client_key_der: \"<redacted>\""), "{dbg}");
        assert!(!dbg.contains(&format!("{:?}", c.eap_tls.client_key_der)));
    }

    #[test]
    fn epdg_ca_cert_data_is_a_der_trust_anchor() {
        // Real bundles carry `ePdgCACert` as <data> at the root (empty for T-Mobile/Verizon).
        let root_key = "<key>imsCommonCredentials</key>";
        assert_eq!(BUNDLE.matches(root_key).count(), 1);
        let with_ca = BUNDLE.replace(root_key, &format!("<key>ePdgCACert</key><data>MAMCAQA=</data>{root_key}"));
        let c = Config::from_plist_bundle(&parse(&with_ca), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert_eq!(c.eap_tls.server_ca_der, vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]]);

        let empty = BUNDLE.replace(root_key, &format!("<key>ePdgCACert</key><data></data>{root_key}"));
        let c = Config::from_plist_bundle(&parse(&empty), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert!(c.eap_tls.server_ca_der.is_empty());

        // PEM (or any string) where DER data is expected is a config error, not a fallback.
        let pem = BUNDLE.replace(root_key, &format!("<key>ePdgCACert</key><string>-----BEGIN CERTIFICATE-----</string>{root_key}"));
        let r = Config::from_plist_bundle(&parse(&pem), &parse(CREDS), &cert_der(), &key_der());
        assert!(matches!(r, Err(Error::Config(_))), "{r:?}");
    }

    #[test]
    fn ike_fields() {
        let c = fixture_config();
        assert_eq!(c.ike.proposals.len(), 1);
        assert_eq!(
            c.ike.proposals[0],
            IkeProposal {
                encryption: vec!["AES-256".into()],
                integrity: vec!["SHA2-256".into()],
                prf: vec!["SHA2-256".into()],
                dh_groups: vec![14],
            }
        );
        assert_eq!(c.ike.lifetime_secs, 80000);
        assert!(c.ike.eap_only);
        assert_eq!(c.ike.eap_method, "EAP-TLS");
        assert_eq!(
            c.ike.dpd,
            DpdConfig { enabled: false, interval_secs: 600, retry_interval_secs: 10, max_retries: 4 }
        );
        assert_eq!(
            c.ike.natt,
            NattConfig {
                keepalive_interval_secs: 10,
                disable_switch_to_natt_port: false,
                force_udp_encap: true,
                keepalive_offload: true,
            }
        );
        assert_eq!(
            c.ike.retransmit,
            RetransmitConfig { initial_timeout_ms: 500, backoff_multiplier: 2.0, max_attempts: 5 }
        );
        assert!(c.ike.fragmentation);
        assert_eq!(c.ike.fragment_threshold, 1280);
        assert!(c.ike.signature_hash_algorithms);
        assert!(c.ike.mobike);
        assert!(!c.ike.initial_contact);
        assert_eq!(c.ike.nonce_len, 32);
        assert!((c.ike.rekey_margin_fraction - 0.1).abs() < 1e-12);
    }

    #[test]
    fn child_fields() {
        let c = fixture_config();
        assert_eq!(c.child.proposals.len(), 1);
        assert_eq!(
            c.child.proposals[0],
            ChildProposal {
                encryption: vec!["AES-256".into()],
                integrity: vec!["SHA2-256".into()],
                dh_groups: vec![],
            }
        );
        assert_eq!(c.child.lifetime_secs, 80000);
        assert_eq!(c.child.replay_window, 12);
        assert_eq!(c.child.cfg_requests, vec![1, 8, 3, 10, 2, 20, 21, 7]);
        assert_eq!(c.child.cfg_requests, default_cfg_requests());
        assert!(c.child.install_policies);
        assert_eq!(c.child.inner_mtu, DEFAULT_INNER_MTU);
        assert_eq!(c.child.inner_mtu, 1280);
        assert_eq!(c.child.inner_mtu_stack, DEFAULT_INNER_MTU_STACK);
        assert_eq!(c.child.inner_mtu_stack, 16384);
        assert!(c.child.inner_mtu_stack >= c.child.inner_mtu);
    }

    #[test]
    fn ims_fields() {
        let c = fixture_config();
        assert_eq!(c.ims.pcscf_address, "ueb2bprod.pc.t-mobile.com:35060");
        assert_eq!(c.ims.apn, "ims.tmus");
        assert_eq!(c.ims.impu, "12138461451@msg.pc.t-mobile.com");
        assert_eq!(c.ims.sip_realm, "prodepdg.t-mobile.com");
        assert_eq!(c.ims.username, "999990302421609@prodepdg.t-mobile.com");
        assert_eq!(c.ims.password, "i7kBuKxGLIQRcHV");
        assert_eq!(c.ims.imsi, "999990302421609@prodepdg.t-mobile.com");
        let dbg = format!("{:?}", c.ims);
        assert!(!dbg.contains("i7kBuKxGLIQRcHV"));
    }

    #[test]
    fn from_plist_files_matches_in_memory() {
        let d = fixtures_dir();
        let c = Config::from_plist_files(
            &d.join("tmobile_prod_bundle.plist"),
            &d.join("tmobile_creds.plist"),
            &d.join("client.crt"),
            &d.join("client.key"),
        )
        .expect("from_plist_files");
        assert_eq!(c.gateway.hostname, "ns.sipgeo.t-mobile.com");
        assert_eq!(c.identity.local_id.data, LOCAL_ID.as_bytes());
        assert_eq!(c.child.cfg_requests, vec![1, 8, 3, 10, 2, 20, 21, 7]);
        assert_eq!(c.eap_tls.client_cert_der, cert_der());
        assert_eq!(c.eap_tls.client_key_der, key_der());
    }

    #[test]
    fn from_plist_files_missing_file_is_config_error() {
        let d = fixtures_dir();
        let r = Config::from_plist_files(
            &d.join("does_not_exist.plist"),
            &d.join("tmobile_creds.plist"),
            &d.join("client.crt"),
            &d.join("client.key"),
        );
        assert!(matches!(r, Err(Error::Config(_))), "{r:?}");
    }

    #[test]
    fn idspec_from_string_classification() {
        let email = IdSpec::from_string("user@example.com");
        assert_eq!(email.id_type, ID_RFC822_ADDR);
        assert_eq!(email.data, b"user@example.com");

        let fqdn = IdSpec::from_string("ims.tmus");
        assert_eq!(fqdn.id_type, ID_FQDN);
        assert_eq!(fqdn.data, b"ims.tmus");

        let v4 = IdSpec::from_string("208.54.40.79");
        assert_eq!(v4.id_type, ID_IPV4_ADDR);
        assert_eq!(v4.data, vec![208, 54, 40, 79]);

        let v6 = IdSpec::from_string("2001:db8::1");
        assert_eq!(v6.id_type, ID_IPV6_ADDR);
        assert_eq!(v6.data, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets().to_vec());
        assert_eq!(v6.data.len(), 16);

        // An '@' wins over anything that might look like an address.
        let weird = IdSpec::from_string("1.2.3.4@example.com");
        assert_eq!(weird.id_type, ID_RFC822_ADDR);
    }

    #[test]
    fn eap_method_other_than_tls_is_rejected() {
        let xml = BUNDLE.replace("<string>EAP-TLS</string>", "<string>EAP-AKA</string>");
        let r = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der());
        match r {
            Err(Error::Config(msg)) => assert!(msg.contains("EAP-AKA"), "{msg}"),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn authentication_method_not_none_clears_eap_only() {
        let xml = BUNDLE.replace(
            "<key>AuthenticationMethod</key>\n\t\t\t\t\t\t<string>None</string>",
            "<key>AuthenticationMethod</key>\n\t\t\t\t\t\t<string>Certificate</string>",
        );
        assert_ne!(xml, BUNDLE, "replacement must hit");
        let c = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert!(!c.ike.eap_only);
    }

    #[test]
    fn algorithm_arrays_accepted_in_ike_block() {
        // Swap the IKE-block string forms for arrays; result must be identical.
        let xml = BUNDLE
            .replace(
                "<key>EncryptionAlgorithm</key>\n\t\t\t\t\t\t<string>AES-256</string>",
                "<key>EncryptionAlgorithm</key>\n\t\t\t\t\t\t<array><string>AES-256</string><string>AES-128</string></array>",
            )
            .replace(
                "<key>IntegrityAlgorithm</key>\n\t\t\t\t\t\t<string>SHA2-256</string>",
                "<key>IntegrityAlgorithm</key>\n\t\t\t\t\t\t<array><string>SHA2-256</string></array>",
            )
            .replace("<key>DHGroup</key>\n\t\t\t\t\t\t<integer>14</integer>",
                     "<key>DHGroup</key>\n\t\t\t\t\t\t<array><integer>14</integer><integer>19</integer></array>");
        assert_ne!(xml, BUNDLE);
        let c = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert_eq!(c.ike.proposals[0].encryption, vec!["AES-256", "AES-128"]);
        assert_eq!(c.ike.proposals[0].integrity, vec!["SHA2-256"]);
        assert_eq!(c.ike.proposals[0].dh_groups, vec![14, 19]);
    }

    #[test]
    fn algorithm_wrong_type_is_config_error() {
        let xml = BUNDLE.replace(
            "<key>PRFAlgorithm</key>\n\t\t\t\t\t\t<string>SHA2-256</string>",
            "<key>PRFAlgorithm</key>\n\t\t\t\t\t\t<integer>5</integer>",
        );
        assert_ne!(xml, BUNDLE);
        let r = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der());
        assert!(matches!(r, Err(Error::Config(_))), "{r:?}");
    }

    #[test]
    fn missing_subscriber_id_is_error_when_placeholder_used() {
        let creds = CREDS.replace("<key>subscriberId</key>", "<key>subscriberIdX</key>");
        assert_ne!(creds, CREDS);
        let r = Config::from_plist_bundle(&parse(BUNDLE), &parse(&creds), &cert_der(), &key_der());
        assert!(matches!(r, Err(Error::Config(_))), "{r:?}");
    }

    #[test]
    fn literal_local_identifier_without_placeholder() {
        let xml = BUNDLE.replace("<string>900$subscriber-id</string>", "<string>alice@example.org</string>");
        assert_ne!(xml, BUNDLE);
        let c = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert_eq!(c.identity.local_id, IdSpec::from_string("alice@example.org"));
        assert_eq!(c.identity.eap_identity, b"alice@example.org");
    }

    #[test]
    fn cfg_requests_without_extras_omit_pcscf() {
        let xml = BUNDLE
            .replace("ExtraConfigurationAttributeRequestv4", "UnusedV4")
            .replace("ExtraConfigurationAttributeRequestv6", "UnusedV6");
        let c = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert_eq!(c.child.cfg_requests, vec![1, 8, 3, 10, 2, 7]);
    }

    #[test]
    fn cfg_requests_unknown_identifier_ignored() {
        let xml = BUNDLE.replace("<integer>16384</integer>", "<integer>16999</integer>");
        assert_ne!(xml, BUNDLE);
        let c = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der()).unwrap();
        assert_eq!(c.child.cfg_requests, vec![1, 8, 3, 10, 2, 21, 7]);
    }

    #[test]
    fn bad_remote_address_is_config_error() {
        let xml = BUNDLE.replace("<string>208.54.40.79</string>", "<string>not-an-ip</string>");
        assert_ne!(xml, BUNDLE);
        let r = Config::from_plist_bundle(&parse(&xml), &parse(CREDS), &cert_der(), &key_der());
        assert!(matches!(r, Err(Error::Config(_))), "{r:?}");
    }

    #[test]
    fn missing_bundle_sections_are_config_errors() {
        let no_common = BUNDLE.replace("<key>imsCommonCredentials</key>", "<key>nope</key>");
        assert!(matches!(
            Config::from_plist_bundle(&parse(&no_common), &parse(CREDS), &cert_der(), &key_der()),
            Err(Error::Config(_))
        ));
        let no_ike = BUNDLE.replace("<key>IKE</key>", "<key>IKEX</key>");
        assert!(matches!(
            Config::from_plist_bundle(&parse(&no_ike), &parse(CREDS), &cert_der(), &key_der()),
            Err(Error::Config(_))
        ));
        let not_dict = Value::String("x".into());
        assert!(matches!(
            Config::from_plist_bundle(&not_dict, &parse(CREDS), &cert_der(), &key_der()),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn gateway_candidates_ip_literal_plus_fallback() {
        let mut c = fixture_config();
        c.gateway.hostname = "127.0.0.1".into();
        c.gateway.fallback_addr = Some("208.54.40.79".parse().unwrap());
        assert_eq!(
            c.gateway_candidates().unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::new(208, 54, 40, 79))]
        );
    }

    #[test]
    fn gateway_candidates_dedupes_fallback() {
        let mut c = fixture_config();
        c.gateway.hostname = "127.0.0.1".into();
        c.gateway.fallback_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(c.gateway_candidates().unwrap(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn gateway_candidates_ipv6_literal_after_fallback_v4_still_listed() {
        let mut c = fixture_config();
        c.gateway.hostname = "::1".into();
        c.gateway.fallback_addr = Some("208.54.40.79".parse().unwrap());
        let got = c.gateway_candidates().unwrap();
        assert_eq!(got, vec![IpAddr::V6(Ipv6Addr::LOCALHOST), "208.54.40.79".parse().unwrap()]);
    }

    #[test]
    fn gateway_candidates_ipv4_first_for_localhost() {
        let mut c = fixture_config();
        c.gateway.hostname = "localhost".into();
        c.gateway.fallback_addr = None;
        // "localhost" resolves without network access; whatever it yields, all v4
        // entries must precede all v6 entries and there must be no duplicates.
        if let Ok(got) = c.gateway_candidates() {
            let first_v6 = got.iter().position(IpAddr::is_ipv6).unwrap_or(got.len());
            assert!(got[..first_v6].iter().all(IpAddr::is_ipv4));
            assert!(got[first_v6..].iter().all(IpAddr::is_ipv6));
            let mut dedup = got.clone();
            dedup.dedup();
            assert_eq!(dedup, got);
        }
    }

    #[test]
    fn gateway_candidates_dns_failure_uses_fallback() {
        let mut c = fixture_config();
        // RFC 6761 reserves .invalid: guaranteed NXDOMAIN, no network needed.
        c.gateway.hostname = "gateway.invalid".into();
        c.gateway.fallback_addr = Some("208.54.40.79".parse().unwrap());
        assert_eq!(c.gateway_candidates().unwrap(), vec!["208.54.40.79".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn gateway_candidates_dns_failure_without_fallback_is_error() {
        let mut c = fixture_config();
        c.gateway.hostname = "gateway.invalid".into();
        c.gateway.fallback_addr = None;
        assert!(matches!(c.gateway_candidates(), Err(Error::Config(_))));
    }
}
