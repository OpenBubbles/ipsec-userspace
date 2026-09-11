//! Diagnostic: print the exact TLS ClientHello our EAP-TLS client sends (suites/extensions).
use epdg::eap::packet::EapPacket;
use epdg::eap::tls::{EapAction, EapTlsClient, EapTlsConfig};

fn u16be(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    let allow_tls13 = std::env::args().any(|a| a == "--tls13");
    // `--sni <name>` adds a server_name extension; the default (like AOSP) sends none.
    let server_name = std::env::args().skip_while(|a| a != "--sni").nth(1);
    let cfg = EapTlsConfig {
        identity: b"900999990302421609@prodepdg.t-mobile.com".to_vec(),
        client_cert_pem: std::fs::read_to_string(format!("{dir}client.crt")).unwrap(),
        client_key_pem: std::fs::read_to_string(format!("{dir}client.key")).unwrap(),
        validate_server: false,
        server_ca_pem: None,
        server_name,
        max_fragment_len: 1024,
        allow_tls13,
    };
    let mut c = EapTlsClient::new(cfg).unwrap();
    let start = EapPacket { code: 1, identifier: 1, eap_type: Some(13), type_data: vec![0x20] };
    let EapAction::Send(pkt) = c.handle(&start).unwrap() else { panic!("expected Send") };
    let td = &pkt.type_data; // flags(1) [len(4)] data
    let data = if td[0] & 0x80 != 0 { &td[5..] } else { &td[1..] };
    println!("EAP-TLS type-data {} bytes, flags 0x{:02x}; ClientHello record {} bytes\nhex: {}", td.len(), td[0], data.len(), hex::encode(data));
    // parse record -> handshake -> ClientHello
    let hs = &data[5..]; let body = &hs[4..];
    println!("record version {:04x}, handshake type {}, client_version {:04x}", u16be(&data[1..3]), hs[0], u16be(&body[0..2]));
    let mut p = 2 + 32; let sid = body[p] as usize; p += 1 + sid;
    let cslen = u16be(&body[p..]) as usize; p += 2;
    let suites: Vec<String> = body[p..p + cslen].chunks(2).map(|c| format!("{:04x}", u16be(c))).collect(); p += cslen;
    println!("cipher suites ({}): {}", suites.len(), suites.join(" "));
    let complen = body[p] as usize; p += 1 + complen;
    let extlen = u16be(&body[p..]) as usize; p += 2;
    let end = p + extlen; let mut exts = vec![];
    while p + 4 <= end { let t = u16be(&body[p..]); let l = u16be(&body[p + 2..]) as usize; exts.push(format!("{t}({l})")); p += 4 + l; }
    println!("extensions (type(len)): {}", exts.join(" "));
}
