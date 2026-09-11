//! Tiny DNS client codec (RFC 1035): one A/AAAA query, answer-section parsing with
//! name compression and CNAME chasing. Enough for the live test.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use log::debug;

use crate::{Error, Result};

/// Query types we can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QType {
    A = 1,
    AAAA = 28,
}

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_TC: u16 = 0x0200;
const HEADER_LEN: usize = 12;
const MAX_POINTER_HOPS: usize = 64;

/// Build a standard recursive query (`RD` set, one question, class IN).
/// Invalid names (empty labels, label > 63, total > 255) are `Error::Encode`.
pub fn build_query(id: u16, name: &str, qtype: QType) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
    encode_name(name, &mut out)?;
    out.extend_from_slice(&(qtype as u16).to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Parse a response and return every A/AAAA address in the answer section that
/// belongs to the queried name or to a name reached from it through CNAME records.
/// Non-zero RCODE is `Error::Protocol`; malformed bytes are `Error::Decode`.
pub fn parse_response(buf: &[u8]) -> Result<Vec<IpAddr>> {
    if buf.len() < HEADER_LEN {
        return Err(Error::decode(format!("dns: response too short ({} bytes)", buf.len())));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & FLAG_QR == 0 {
        return Err(Error::decode("dns: QR bit not set (not a response)"));
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(Error::protocol(format!("dns: rcode {rcode} ({})", rcode_name(rcode))));
    }
    if flags & FLAG_TC != 0 {
        debug!("dns: response truncated (TC set); parsing what is present");
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = HEADER_LEN;
    let mut qnames: Vec<String> = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = read_name(buf, pos)?;
        pos = next;
        if pos + 4 > buf.len() {
            return Err(Error::decode("dns: question truncated"));
        }
        pos += 4;
        qnames.push(name);
    }

    struct Rr {
        owner: String,
        rtype: u16,
        rdata: Vec<u8>,
        rdata_pos: usize,
    }
    let mut rrs: Vec<Rr> = Vec::with_capacity(usize::from(ancount));
    for _ in 0..ancount {
        let (owner, next) = read_name(buf, pos)?;
        pos = next;
        if pos + 10 > buf.len() {
            return Err(Error::decode("dns: answer RR header truncated"));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rdlen = usize::from(u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]));
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(Error::decode("dns: RDATA truncated"));
        }
        let rdata_pos = pos;
        let rdata = buf[pos..pos + rdlen].to_vec();
        pos += rdlen;
        if rclass == CLASS_IN {
            rrs.push(Rr { owner, rtype, rdata, rdata_pos });
        }
    }

    // Names whose A/AAAA records we accept: the question name(s) plus the CNAME closure.
    // With no question section we accept everything.
    let mut accepted: Vec<String> = qnames.iter().map(|n| n.to_ascii_lowercase()).collect();
    let accept_all = accepted.is_empty();
    let mut changed = true;
    while changed {
        changed = false;
        for rr in rrs.iter().filter(|r| r.rtype == TYPE_CNAME) {
            let owner = rr.owner.to_ascii_lowercase();
            if !accept_all && !accepted.contains(&owner) {
                continue;
            }
            let (target, _) = read_name(buf, rr.rdata_pos)?;
            let target = target.to_ascii_lowercase();
            if !accepted.contains(&target) {
                accepted.push(target);
                changed = true;
            }
        }
    }

    let mut addrs = Vec::new();
    for rr in &rrs {
        if !accept_all && !accepted.contains(&rr.owner.to_ascii_lowercase()) {
            continue;
        }
        match rr.rtype {
            TYPE_A => {
                let o: [u8; 4] = rr
                    .rdata
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::decode(format!("dns: A RDATA length {}", rr.rdata.len())))?;
                addrs.push(IpAddr::V4(Ipv4Addr::from(o)));
            }
            TYPE_AAAA => {
                let o: [u8; 16] = rr.rdata.as_slice().try_into().map_err(|_| {
                    Error::decode(format!("dns: AAAA RDATA length {}", rr.rdata.len()))
                })?;
                addrs.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            _ => {}
        }
    }
    debug!("dns: {} answer RRs -> {} addresses", rrs.len(), addrs.len());
    Ok(addrs)
}

fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "other",
    }
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    if name.len() + 2 > 255 {
        return Err(Error::encode(format!("dns: name too long ({} bytes)", name.len())));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(Error::encode(format!("dns: empty label in {name:?}")));
        }
        if label.len() > 63 {
            return Err(Error::encode(format!("dns: label too long in {name:?}")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Read a (possibly compressed) name at `pos`. Returns the dotted name (no trailing
/// dot, root = "") and the position just after the name in the *original* stream.
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut end: Option<usize> = None;
    let mut hops = 0usize;
    loop {
        let &len = buf.get(pos).ok_or_else(|| Error::decode("dns: name truncated"))?;
        match len & 0xc0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    break;
                }
                let l = usize::from(len);
                let label = buf
                    .get(pos..pos + l)
                    .ok_or_else(|| Error::decode("dns: label truncated"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label));
                pos += l;
                if name.len() > 255 {
                    return Err(Error::decode("dns: name too long"));
                }
            }
            0xc0 => {
                let &lo = buf.get(pos + 1).ok_or_else(|| Error::decode("dns: pointer truncated"))?;
                let target = usize::from(u16::from_be_bytes([len & 0x3f, lo]));
                if end.is_none() {
                    end = Some(pos + 2);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(Error::decode("dns: compression pointer loop"));
                }
                if target >= buf.len() {
                    return Err(Error::decode(format!("dns: pointer {target} out of range")));
                }
                pos = target;
            }
            other => {
                return Err(Error::decode(format!("dns: unsupported label type {other:#x}")));
            }
        }
    }
    Ok((name, end.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bytes_kat() {
        let q = build_query(0xabcd, "example.com", QType::A).unwrap();
        let expected = hex::decode(
            "abcd01000001000000000000076578616d706c6503636f6d0000010001",
        )
        .unwrap();
        assert_eq!(q, expected);

        let q6 = build_query(1, "ueb2bprod.pc.t-mobile.com.", QType::AAAA).unwrap();
        assert_eq!(&q6[..2], &[0, 1]);
        assert_eq!(&q6[2..4], &[0x01, 0x00]); // RD
        assert_eq!(&q6[q6.len() - 4..], &[0, 28, 0, 1]);
        assert_eq!(q6[12], 9);
        assert_eq!(&q6[13..22], b"ueb2bprod");
        assert_eq!(q6[q6.len() - 5], 0); // root terminator
    }

    #[test]
    fn query_name_validation() {
        assert!(matches!(build_query(1, "a..b", QType::A), Err(Error::Encode(_))));
        let long = "a".repeat(64);
        assert!(matches!(build_query(1, &long, QType::A), Err(Error::Encode(_))));
        let too_long = ["abcdefghij"; 30].join(".");
        assert!(matches!(build_query(1, &too_long, QType::A), Err(Error::Encode(_))));
    }

    /// Response to `www.example.com A` with a two-hop CNAME chain and compression
    /// pointers into both the question and previous answers, plus an unrelated A
    /// record that must be ignored.
    fn cname_response() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 5, 0, 0, 0, 0]);
        // Question at offset 12: www.example.com (www @12, example.com @16)
        b.extend_from_slice(b"\x03www\x07example\x03com\x00");
        b.extend_from_slice(&[0, 1, 0, 1]);
        // RR1 @33: www.example.com CNAME cdn.example.net  (target: cdn @45, example.net @49)
        b.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 17]);
        assert_eq!(b.len(), 45);
        b.extend_from_slice(b"\x03cdn\x07example\x03net\x00");
        // RR2: cdn.example.net CNAME edge.EXAMPLE.net (owner via pointer to 45; target: 04 edge + ptr 49)
        b.extend_from_slice(&[0xc0, 45, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7]);
        let edge_pos = b.len();
        b.extend_from_slice(b"\x04edge\xc0\x31");
        // RR3: edge.example.net A 93.184.216.34 (owner via pointer)
        b.extend_from_slice(&[0xc0, edge_pos as u8, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, 34]);
        // RR4: edge.example.net AAAA 2606:2800:220:1:248:1893:25c8:1946
        b.extend_from_slice(&[0xc0, edge_pos as u8, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        b.extend_from_slice(&Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946).octets());
        // RR5: unrelated.example.com A 10.0.0.1 -> must be ignored
        b.extend_from_slice(b"\x09unrelated\xc0\x10");
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 1]);
        b
    }

    #[test]
    fn parse_response_with_compression_and_cname_chain() {
        let addrs = parse_response(&cname_response()).unwrap();
        assert_eq!(
            addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946)),
            ]
        );
    }

    #[test]
    fn read_name_decompresses() {
        let b = cname_response();
        assert_eq!(read_name(&b, 12).unwrap(), ("www.example.com".to_string(), 29));
        assert_eq!(read_name(&b, 33).unwrap(), ("www.example.com".to_string(), 35));
        let (n, _) = read_name(&b, 45).unwrap();
        assert_eq!(n, "cdn.example.net");
    }

    #[test]
    fn simple_a_response_no_compression() {
        let mut b = vec![0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(b"\x01a\x02io\x00\x00\x01\x00\x01");
        b.extend_from_slice(b"\x01a\x02io\x00");
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 1, 2, 3, 4]);
        assert_eq!(parse_response(&b).unwrap(), vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn empty_answer_and_errors() {
        // NOERROR, zero answers.
        let mut b = vec![0, 7, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(b"\x01a\x02io\x00\x00\x01\x00\x01");
        assert!(parse_response(&b).unwrap().is_empty());

        // NXDOMAIN.
        let mut nx = b.clone();
        nx[3] = 0x83;
        assert!(matches!(parse_response(&nx), Err(Error::Protocol(_))));

        // Not a response.
        let mut q = b.clone();
        q[2] = 0x01;
        assert!(matches!(parse_response(&q), Err(Error::Decode(_))));

        // Truncated.
        assert!(matches!(parse_response(&b[..5]), Err(Error::Decode(_))));
        assert!(matches!(parse_response(&b[..b.len() - 2]), Err(Error::Decode(_))));

        // Pointer loop.
        let mut lp = vec![0, 7, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        lp.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(matches!(parse_response(&lp), Err(Error::Decode(_))));

        // Bad RDATA length for an accepted A record (rdlength 4 -> 3, one byte dropped
        // so the rest of the stream stays consistent).
        let mut bad = cname_response();
        let i = bad.windows(4).position(|w| w == [93, 184, 216, 34]).unwrap();
        bad[i - 1] = 3;
        bad.remove(i + 3);
        assert!(matches!(parse_response(&bad), Err(Error::Decode(_))));
    }
}
