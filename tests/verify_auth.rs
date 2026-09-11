//! TEMPORARY verifier scratch test (lens: AUTH / IDr / message ids / IKE_AUTH responses).
use epdg::config::*;
use epdg::crypto::{random_bytes, registry, Suite};
use epdg::ike::auth::id_payload_body;
use epdg::ike::constants::*;
use epdg::ike::fragment::decode_datagrams;
use epdg::ike::keys::{derive_ike_keys, IkeKeys};
use epdg::ike::message::IkeMessage;
use epdg::ike::nat::nat_detection_hash;
use epdg::ike::payload::*;
use epdg::ike::session::*;
use epdg::ike::transport::IkeTransport;
use epdg::Error;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

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
            proposals: vec![ChildProposal { encryption: vec!["AES-256".into()], integrity: vec!["SHA2-256".into()], dh_groups: vec![] }],
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

/// RFC 7296 §2.13 prf+ with HMAC-SHA256.
fn prf_plus(key: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut data = prev.clone();
        data.extend_from_slice(seed);
        data.push(i);
        prev = hmac256(key, &data);
        out.extend_from_slice(&prev);
        i += 1;
    }
    out.truncate(len);
    out
}

fn suite() -> Suite {
    Suite {
        cipher: registry::cipher(ENCR_AES_CBC, Some(256)).unwrap(),
        integrity: registry::integrity(AUTH_HMAC_SHA2_256_128).unwrap(),
        prf: registry::prf(PRF_HMAC_SHA2_256).unwrap(),
        dh: Some(registry::dh(DH_MODP_2048).unwrap()),
    }
}

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
    extra_sa_init_payloads: Vec<Payload>,
    mutate_raw2_reserved: bool,
}

impl Responder {
    fn new() -> Self {
        let mut spi_r = 0u64;
        while spi_r == 0 {
            let b = random_bytes(8);
            spi_r = u64::from_be_bytes(b[..8].try_into().unwrap());
        }
        Responder {
            spi_i: 0,
            spi_r,
            suite: suite(),
            keys: None,
            ni: Vec::new(),
            nr: random_bytes(32),
            raw2: Vec::new(),
            id_r: IdPayload { id_type: ID_FQDN, data: EPDG_ID.as_bytes().to_vec() },
            msk: (0u8..64).collect(),
            child_spi: 0x5a5a1234,
            extra_sa_init_payloads: Vec::new(),
            mutate_raw2_reserved: false,
        }
    }

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
                nat_detection_hash(self.spi_i, self.spi_r, remote().ip(), remote().port()).to_vec(),
            )),
            Payload::Notify(NotifyPayload::status(
                N_NAT_DETECTION_DESTINATION_IP,
                nat_detection_hash(self.spi_i, self.spi_r, local().ip(), local().port()).to_vec(),
            )),
            Payload::Notify(NotifyPayload::status(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![])),
        ];
        payloads.extend(self.extra_sa_init_payloads.clone());
        let resp = IkeMessage::new(self.spi_i, self.spi_r, EXCH_IKE_SA_INIT, FLAG_RESPONSE, 0, payloads);
        let mut raw2 = resp.encode_plain().unwrap();
        if self.mutate_raw2_reserved {
            // Set the RESERVED bits of the LAST payload's generic header (the vendor
            // payload appended above) so a re-encoding would NOT reproduce these bytes.
            let last = raw2.len() - 4 - 8; // vendor body 8 bytes -> generic hdr at len-12
            assert_eq!(raw2[last + 1], 0);
            raw2[last + 1] = 0x7f; // critical bit clear, reserved bits set
        }
        self.keys = Some(derive_ike_keys(&self.suite, &self.ni, &self.nr, &shared, self.spi_i, self.spi_r));
        self.raw2 = raw2.clone();
        raw2
    }

    fn keys(&self) -> &IkeKeys {
        self.keys.as_ref().unwrap()
    }

    fn open(&self, datagrams: &[Vec<u8>]) -> IkeMessage {
        decode_datagrams(datagrams, &self.suite, &self.keys().sk_ei, &self.keys().sk_ai).unwrap()
    }

    fn seal_response(&self, exchange: u8, msgid: u32, payloads: Vec<Payload>) -> Vec<Vec<u8>> {
        let m = IkeMessage::new(self.spi_i, self.spi_r, exchange, FLAG_RESPONSE, msgid, payloads);
        vec![m.encode_encrypted(&self.suite, &self.keys().sk_er, &self.keys().sk_ar).unwrap()]
    }

    fn seal_request(&self, exchange: u8, msgid: u32, payloads: Vec<Payload>) -> Vec<Vec<u8>> {
        let m = IkeMessage::new(self.spi_i, self.spi_r, exchange, 0, msgid, payloads);
        vec![m.encode_encrypted(&self.suite, &self.keys().sk_er, &self.keys().sk_ar).unwrap()]
    }

    fn auth_data(&self, id_r: &IdPayload) -> Vec<u8> {
        let maced = hmac256(&self.keys().sk_pr, &id_payload_body(id_r));
        let mut octets = self.raw2.clone();
        octets.extend_from_slice(&self.ni);
        octets.extend_from_slice(&maced);
        hmac256(&hmac256(&self.msk, KEY_PAD_FOR_IKEV2), &octets)
    }

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
                ConfigAttribute { attr_type: CFG_P_CSCF_IP6_ADDRESS, value: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99).octets().to_vec() },
                ConfigAttribute { attr_type: CFG_P_CSCF_IP4_ADDRESS, value: vec![10, 0, 0, 99] },
            ],
        }
    }

    fn final_payloads(&self, req_child: &Proposal, auth: Vec<u8>) -> Vec<Payload> {
        let chosen = Proposal { spi: self.child_spi.to_be_bytes().to_vec(), ..req_child.clone() };
        vec![
            Payload::Auth(AuthPayload { method: AUTH_SHARED_KEY_MIC, data: auth }),
            Payload::Cp(Self::cfg_reply()),
            Payload::Sa(SaPayload { proposals: vec![chosen] }),
            Payload::TsI(TsPayload { selectors: vec![TrafficSelector::ipv6_any()] }),
            Payload::TsR(TsPayload { selectors: vec![TrafficSelector::ipv6_any()] }),
            Payload::Notify(NotifyPayload::status(N_MOBIKE_SUPPORTED, vec![])),
        ]
    }
}

fn run_sa_init(init: &mut IkeInitiator, resp: &mut Responder, cookie: bool) -> Vec<u8> {
    let mut raw1 = init.build_sa_init(None).unwrap();
    if cookie {
        let cookie_data: Vec<u8> = (1u8..=24).collect();
        let reply = IkeMessage::new(init.spi_i(), 0, EXCH_IKE_SA_INIT, FLAG_RESPONSE, 0, vec![Payload::Notify(NotifyPayload::status(N_COOKIE, cookie_data.clone()))])
            .encode_plain()
            .unwrap();
        match init.handle_sa_init_response(&reply).unwrap() {
            SaInitOutcome::RetryWithCookie(c) => assert_eq!(c, cookie_data),
            other => panic!("expected RetryWithCookie, got {other:?}"),
        }
        raw1 = init.build_sa_init(Some(&cookie_data)).unwrap();
    }
    let raw2 = resp.sa_init_reply(&raw1);
    match init.handle_sa_init_response(&raw2).unwrap() {
        SaInitOutcome::Established { .. } => {}
        other => panic!("expected Established, got {other:?}"),
    }
    assert_eq!(init.real_message1(), &raw1[..]);
    assert_eq!(init.real_message2(), &raw2[..]);
    raw1
}

/// Through IKE_AUTH #1 (with `first_idr`) and `eap_rounds` EAP rounds; returns (raw1, child proposal).
fn through_eap(init: &mut IkeInitiator, resp: &mut Responder, cookie: bool, first_idr: Option<IdPayload>, eap_rounds: u32) -> (Vec<u8>, Proposal) {
    let raw1 = run_sa_init(init, resp, cookie);
    assert_eq!(init.next_message_id(), 1);
    let m1 = init.build_auth_initial().unwrap();
    assert_eq!(m1.header.message_id, 1);
    let child_req = m1.sa().unwrap().proposals[0].clone();
    let _ = init.encode(&m1).unwrap();
    let mut p = Vec::new();
    if let Some(id) = first_idr {
        p.push(Payload::IdR(id));
    }
    p.push(Payload::Eap(vec![EAP_CODE_REQUEST, 1, 0, 5, EAP_TYPE_IDENTITY]));
    let r1 = resp.seal_response(EXCH_IKE_AUTH, 1, p);
    let r1m = init.decode(&r1).unwrap();
    assert!(matches!(init.handle_auth_response(&r1m).unwrap(), AuthResponse::EapRequest(_)));
    assert_eq!(init.next_message_id(), 2);
    for k in 0..eap_rounds {
        let id = 2 + k;
        let m = init.build_auth_eap(&[EAP_CODE_RESPONSE, (k + 1) as u8, 0, 6, 13, 0]).unwrap();
        assert_eq!(m.header.message_id, id, "EAP round {k} msgid");
        assert_eq!(m.payloads.len(), 1);
        let d = init.encode(&m).unwrap();
        let seen = resp.open(&d);
        assert_eq!(seen.header.message_id, id);
        let r = resp.seal_response(EXCH_IKE_AUTH, id, vec![Payload::Eap(vec![EAP_CODE_REQUEST, (k + 2) as u8, 0, 6, 13, 0])]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm).unwrap(), AuthResponse::EapRequest(_)));
        assert_eq!(init.next_message_id(), id + 1);
    }
    (raw1, child_req)
}

#[test]
fn msgid_sequence_child_keys_and_spis() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    let idr0 = resp.id_r.clone();
        let (raw1, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 3);
    // ids: SA_INIT 0, AUTH#1 1, EAP 2,3,4 -> final 5
    assert_eq!(init.next_message_id(), 5);
    init.set_msk(resp.msk.clone());
    let m = init.build_auth_final().unwrap();
    assert_eq!(m.header.message_id, 5);
    let id_i = IdPayload { id_type: ID_RFC822_ADDR, data: LOCAL_ID.as_bytes().to_vec() };
    assert_eq!(m.auth().unwrap().data, resp.expected_initiator_auth(&raw1, &id_i));
    let _ = init.encode(&m).unwrap();
    let r = resp.seal_response(EXCH_IKE_AUTH, 5, resp.final_payloads(&child_req, resp.auth_data(&resp.id_r)));
    let rm = init.decode(&r).unwrap();
    let est = match init.handle_auth_response(&rm).unwrap() {
        AuthResponse::Established(e) => *e,
        other => panic!("{other:?}"),
    };
    assert_eq!(init.next_message_id(), 6);
    assert_eq!(est.child.spi_out, resp.child_spi);
    assert_eq!(est.child.spi_in, init.child_spi_in());
    assert_ne!(est.child.spi_in, 0);
    // Child KEYMAT = prf+(SK_d, Ni | Nr) with the IKE_SA_INIT nonces.
    let mut seed = resp.ni.clone();
    seed.extend_from_slice(&resp.nr);
    let keymat = prf_plus(&resp.keys().sk_d, &seed, 128);
    assert_eq!(est.child.keys.encr_i2r, &keymat[0..32]);
    assert_eq!(est.child.keys.integ_i2r, &keymat[32..64]);
    assert_eq!(est.child.keys.encr_r2i, &keymat[64..96]);
    assert_eq!(est.child.keys.integ_r2i, &keymat[96..128]);
    // Narrowed TS accepted verbatim.
    assert_eq!(est.child.ts_i.selectors.len(), 1);
    assert_eq!(est.child.ts_i.selectors[0].ts_type, TS_IPV6_ADDR_RANGE);
    // CFG_REPLY parsed; 17-byte v6 keeps prefix.
    assert_eq!(est.assigned.internal_ipv6, vec![(Ipv6Addr::new(0x2607, 0xfb90, 0x1234, 0, 0, 0, 0, 0x42), 64)]);
    assert_eq!(est.assigned.internal_ipv4, vec![Ipv4Addr::new(10, 20, 30, 40)]);
    assert_eq!(est.assigned.pcscf_ipv4, vec![Ipv4Addr::new(10, 0, 0, 99)]);
    assert_eq!(est.id_r, resp.id_r);
    // Peer counter independent of ours.
    let req = resp.seal_request(EXCH_INFORMATIONAL, 0, vec![]);
    let rq = init.decode(&req).unwrap();
    let (r0, ev) = init.handle_peer_request(&rq).unwrap();
    assert_eq!(ev, PeerEvent::Dpd);
    assert_eq!(r0.header.message_id, 0);
    assert_eq!(init.peer_next_message_id(), 1);
    assert_eq!(init.next_message_id(), 6);
    // Retransmitted peer request -> cached, unchanged.
    let (r0b, ev2) = init.handle_peer_request(&rq).unwrap();
    assert_eq!(ev2, PeerEvent::Other);
    assert_eq!(r0b, r0);
    // A stale peer request two behind is NOT served from cache.
    let req1 = resp.seal_request(EXCH_INFORMATIONAL, 1, vec![]);
    let rq1 = init.decode(&req1).unwrap();
    init.handle_peer_request(&rq1).unwrap();
    assert_eq!(init.peer_next_message_id(), 2);
    assert!(init.handle_peer_request(&rq).is_err(), "msgid 0 when expecting 2 must not be answered");
    // Our DPD continues at 6.
    let dpd = init.build_dpd().unwrap();
    assert_eq!(dpd.header.message_id, 6);
}

#[test]
fn cookie_retry_auth_covers_cookied_message1() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    let first_raw1 = {
        // capture the pre-cookie request for a negative check
        let mut i2 = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        i2.build_sa_init(None).unwrap()
    };
    let idr0 = resp.id_r.clone();
        let (raw1, child_req) = through_eap(&mut init, &mut resp, true, Some(idr0), 1);
    assert!(raw1.len() > first_raw1.len(), "cookie'd request must be longer");
    assert_eq!(IkeMessage::decode_plain(&raw1).unwrap().payloads[0].payload_type(), PT_NOTIFY);
    init.set_msk(resp.msk.clone());
    let m = init.build_auth_final().unwrap();
    let id_i = IdPayload { id_type: ID_RFC822_ADDR, data: LOCAL_ID.as_bytes().to_vec() };
    assert_eq!(m.auth().unwrap().data, resp.expected_initiator_auth(&raw1, &id_i));
    // and NOT over the un-cookie'd bytes
    let mut uncookied = raw1.clone();
    uncookied.drain(28..28 + 4 + 4 + 24);
    assert_ne!(m.auth().unwrap().data, resp.expected_initiator_auth(&uncookied, &id_i));
    let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, resp.final_payloads(&child_req, resp.auth_data(&resp.id_r)));
    let rm = init.decode(&r).unwrap();
    assert!(matches!(init.handle_auth_response(&rm).unwrap(), AuthResponse::Established(_)));
}

#[test]
fn real_message2_is_raw_bytes_not_reencoded() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    resp.extra_sa_init_payloads = vec![Payload::Vendor(vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4])];
    resp.mutate_raw2_reserved = true;
    let idr0 = resp.id_r.clone();
        let (_raw1, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
    // sanity: a re-encoding differs from the raw bytes
    let reenc = IkeMessage::decode_plain(&resp.raw2).unwrap().encode_plain().unwrap();
    assert_ne!(reenc, resp.raw2, "decoder must have tolerated reserved bits (else test is moot)");
    assert_eq!(init.real_message2(), &resp.raw2[..]);
    init.set_msk(resp.msk.clone());
    let m = init.build_auth_final().unwrap();
    let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, resp.final_payloads(&child_req, resp.auth_data(&resp.id_r)));
    let rm = init.decode(&r).unwrap();
    assert!(matches!(init.handle_auth_response(&rm).unwrap(), AuthResponse::Established(_)));
}

#[test]
fn idr_from_first_response_wins_over_final() {
    let other = IdPayload { id_type: ID_FQDN, data: b"other.epdg".to_vec() };
    // AUTH over the FIRST IDr: verifies even though final carries a different IDr.
    {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let mut p = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        p.push(Payload::IdR(other.clone()));
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
        let rm = init.decode(&r).unwrap();
        match init.handle_auth_response(&rm).unwrap() {
            AuthResponse::Established(e) => assert_eq!(e.id_r, resp.id_r),
            o => panic!("{o:?}"),
        }
    }
    // AUTH over the FINAL IDr: must fail.
    {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let mut p = resp.final_payloads(&child_req, resp.auth_data(&other));
        p.push(Payload::IdR(other.clone()));
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::AuthFailed(_))));
    }
}

#[test]
fn idr_fallback_to_final_when_first_absent() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    let (_r, child_req) = through_eap(&mut init, &mut resp, false, None, 1);
    init.set_msk(resp.msk.clone());
    let m = init.build_auth_final().unwrap();
    let mut p = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
    p.insert(0, Payload::IdR(resp.id_r.clone()));
    let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
    let rm = init.decode(&r).unwrap();
    match init.handle_auth_response(&rm).unwrap() {
        AuthResponse::Established(e) => assert_eq!(e.id_r, resp.id_r),
        o => panic!("{o:?}"),
    }
}

#[test]
fn no_idr_anywhere_is_auth_failed() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    let (_r, child_req) = through_eap(&mut init, &mut resp, false, None, 0);
    init.set_msk(resp.msk.clone());
    let m = init.build_auth_final().unwrap();
    let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, resp.final_payloads(&child_req, resp.auth_data(&resp.id_r)));
    let rm = init.decode(&r).unwrap();
    assert!(matches!(init.handle_auth_response(&rm), Err(Error::AuthFailed(_))));
    assert_eq!(init.next_message_id(), m.header.message_id + 1);
}

#[test]
fn final_response_error_notify_is_peer_notify() {
    // (a) error notify alongside an otherwise-valid final response
    {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let mut p = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        p.push(Payload::Notify(NotifyPayload::status(N_TS_UNACCEPTABLE, vec![])));
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::PeerNotify { notify_type: N_TS_UNACCEPTABLE, .. })));
        assert!(!init.established());
    }
    // (b) bare AUTHENTICATION_FAILED, no AUTH payload -> PeerNotify (not AuthFailed)
    {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, _c) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, vec![Payload::Notify(NotifyPayload::status(N_AUTHENTICATION_FAILED, vec![]))]);
        let rm = init.decode(&r).unwrap();
        assert!(matches!(init.handle_auth_response(&rm), Err(Error::PeerNotify { notify_type: N_AUTHENTICATION_FAILED, .. })));
    }
}

#[test]
fn eap_round_status_notify_ignored_error_notify_fatal() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    let idr0 = resp.id_r.clone();
        let (_r, _c) = through_eap(&mut init, &mut resp, false, Some(idr0), 1);
    let m = init.build_auth_eap(&[2, 2, 0, 6, 13, 0]).unwrap();
    let r = resp.seal_response(
        EXCH_IKE_AUTH,
        m.header.message_id,
        vec![Payload::Notify(NotifyPayload::status(N_ADDITIONAL_TS_POSSIBLE, vec![])), Payload::Eap(vec![1, 3, 0, 6, 13, 0])],
    );
    let rm = init.decode(&r).unwrap();
    assert!(matches!(init.handle_auth_response(&rm).unwrap(), AuthResponse::EapRequest(e) if e == vec![1, 3, 0, 6, 13, 0]));
    let m = init.build_auth_eap(&[2, 3, 0, 6, 13, 0]).unwrap();
    let r = resp.seal_response(
        EXCH_IKE_AUTH,
        m.header.message_id,
        vec![Payload::Eap(vec![1, 4, 0, 6, 13, 0]), Payload::Notify(NotifyPayload::status(N_AUTHENTICATION_FAILED, vec![]))],
    );
    let rm = init.decode(&r).unwrap();
    assert!(matches!(init.handle_auth_response(&rm), Err(Error::PeerNotify { notify_type: N_AUTHENTICATION_FAILED, .. })));
}

#[test]
fn first_response_with_auth_payload_and_eap_is_accepted() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    run_sa_init(&mut init, &mut resp, false);
    init.build_auth_initial().unwrap();
    let r = resp.seal_response(
        EXCH_IKE_AUTH,
        1,
        vec![
            Payload::IdR(resp.id_r.clone()),
            Payload::Cert(vec![1, 2, 3]),
            Payload::Auth(AuthPayload { method: 1, data: vec![0; 64] }),
            Payload::Eap(vec![1, 1, 0, 5, 1]),
        ],
    );
    let rm = init.decode(&r).unwrap();
    assert!(matches!(init.handle_auth_response(&rm).unwrap(), AuthResponse::EapRequest(_)));
}

#[test]
fn final_cp_type_and_missing_child_payloads() {
    // CFG_REQUEST-typed CP -> ignored, still Established with empty config.
    {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let mut p = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        let mut cp = Responder::cfg_reply();
        cp.cfg_type = CFG_REQUEST;
        p[1] = Payload::Cp(cp);
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
        let rm = init.decode(&r).unwrap();
        match init.handle_auth_response(&rm).unwrap() {
            AuthResponse::Established(e) => assert_eq!(e.assigned, AssignedConfig::default()),
            o => panic!("{o:?}"),
        }
    }
    for missing in [2usize, 3, 4] {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let mut p = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        p.remove(missing);
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
        let rm = init.decode(&r).unwrap();
        assert!(init.handle_auth_response(&rm).is_err(), "missing payload idx {missing} must fail");
        assert!(!init.established());
    }
    // 16-byte IP6 address tolerated; 3-byte v4 kept in `other`.
    {
        let cfg = test_config();
        let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
        let mut resp = Responder::new();
        let idr0 = resp.id_r.clone();
        let (_r, child_req) = through_eap(&mut init, &mut resp, false, Some(idr0), 0);
        init.set_msk(resp.msk.clone());
        let m = init.build_auth_final().unwrap();
        let mut p = resp.final_payloads(&child_req, resp.auth_data(&resp.id_r));
        let v6 = Ipv6Addr::new(0x2607, 0xfb90, 1, 2, 3, 4, 5, 6);
        p[1] = Payload::Cp(ConfigPayload {
            cfg_type: CFG_REPLY,
            attributes: vec![
                ConfigAttribute { attr_type: CFG_INTERNAL_IP6_ADDRESS, value: v6.octets().to_vec() },
                ConfigAttribute { attr_type: CFG_INTERNAL_IP4_ADDRESS, value: vec![1, 2, 3] },
                ConfigAttribute { attr_type: CFG_INTERNAL_IP4_ADDRESS, value: vec![] },
            ],
        });
        let r = resp.seal_response(EXCH_IKE_AUTH, m.header.message_id, p);
        let rm = init.decode(&r).unwrap();
        match init.handle_auth_response(&rm).unwrap() {
            AuthResponse::Established(e) => {
                assert_eq!(e.assigned.internal_ipv6.len(), 1);
                assert_eq!(e.assigned.internal_ipv6[0].0, v6);
                assert!(e.assigned.internal_ipv4.is_empty());
                assert_eq!(e.assigned.other.len(), 1);
            }
            o => panic!("{o:?}"),
        }
    }
}

#[test]
fn session_rejects_stale_response_without_consuming_id() {
    let cfg = test_config();
    let mut init = IkeInitiator::new(&cfg, local(), remote()).unwrap();
    let mut resp = Responder::new();
    let idr0 = resp.id_r.clone();
        let (_r, _c) = through_eap(&mut init, &mut resp, false, Some(idr0), 1);
    // now expecting a response to msgid 3 once we send; send EAP round
    let m = init.build_auth_eap(&[2, 2, 0, 6, 13, 0]).unwrap();
    assert_eq!(m.header.message_id, 3);
    let stale = resp.seal_response(EXCH_IKE_AUTH, 2, vec![Payload::Eap(vec![1, 2, 0, 6, 13, 0])]);
    let sm = init.decode(&stale).unwrap();
    assert!(matches!(init.handle_auth_response(&sm), Err(Error::Protocol(_))));
    assert_eq!(init.next_message_id(), 3, "stale response must not consume the id");
    let good = resp.seal_response(EXCH_IKE_AUTH, 3, vec![Payload::Eap(vec![1, 3, 0, 6, 13, 0])]);
    let gm = init.decode(&good).unwrap();
    assert!(init.handle_auth_response(&gm).is_ok());
    assert_eq!(init.next_message_id(), 4);
}

/// Transport-level: a stale (expected-1) response arriving first is skipped and the
/// matching one is returned.
#[test]
fn transport_skips_stale_response_and_returns_matching() {
    use std::net::UdpSocket;
    let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rport = responder.local_addr().unwrap().port();
    let transport = IkeTransport::bind(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), IpAddr::V4(Ipv4Addr::LOCALHOST), rport).unwrap();
    let spi_i = 0x1122334455667788u64;
    let spi_r = 0x99aabbccddeeff00u64;
    let req = IkeMessage::new(spi_i, spi_r, EXCH_INFORMATIONAL, FLAG_INITIATOR, 1, vec![]).encode_plain().unwrap();
    let stale = IkeMessage::new(spi_i, spi_r, EXCH_IKE_AUTH, FLAG_RESPONSE, 0, vec![]).encode_plain().unwrap();
    let good = IkeMessage::new(spi_i, spi_r, EXCH_INFORMATIONAL, FLAG_RESPONSE, 1, vec![]).encode_plain().unwrap();
    let good2 = good.clone();
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (_n, src) = responder.recv_from(&mut buf).unwrap();
        responder.send_to(&stale, src).unwrap();
        responder.send_to(&good2, src).unwrap();
    });
    let policy = RetransmitConfig { initial_timeout_ms: 2000, backoff_multiplier: 2.0, max_attempts: 2 };
    let mut others = 0;
    let mut on_other = |_d: Vec<u8>| others += 1;
    let mut on_esp = |_d: Vec<u8>| {};
    let got = transport.request(&[req], 1, &policy, &mut on_other, &mut on_esp).unwrap();
    t.join().unwrap();
    assert_eq!(got, vec![good]);
    assert_eq!(others, 1);
}
