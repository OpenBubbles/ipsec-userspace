//! EAP packet framing (RFC 3748 §4).
//!
//! ```text
//! Code(1) | Identifier(1) | Length(2, big-endian, includes this 4-byte header) | [Type(1) | Type-Data]
//! ```
//!
//! Codes: 1 Request, 2 Response, 3 Success, 4 Failure. Success/Failure carry no
//! Type and MUST have Length exactly 4; Request/Response MUST carry a Type byte.
//! Mirrors the AOSP `EapMessage` codec (see `docs/AOSP_FACTS.md`, EAP area):
//! responses always echo the request identifier, Identity responses carry the
//! raw identity bytes, and a Nak lists the desired method types.

use crate::ike::constants::*;
use crate::{Error, Result};

/// Length of the fixed EAP header (Code, Identifier, Length).
pub const EAP_HEADER_LEN: usize = 4;

/// A decoded EAP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EapPacket {
    pub code: u8,
    pub identifier: u8,
    /// `Some` for Request/Response, `None` for Success/Failure.
    pub eap_type: Option<u8>,
    /// Type-Data (everything after the Type byte). Empty for Success/Failure.
    pub type_data: Vec<u8>,
}

impl EapPacket {
    /// Decode one EAP packet. `Length` must equal `buf.len()`; Success/Failure
    /// must be exactly 4 bytes; Request/Response must carry a Type byte.
    pub fn decode(buf: &[u8]) -> Result<EapPacket> {
        if buf.len() < EAP_HEADER_LEN {
            return Err(Error::decode(format!(
                "EAP packet too short: {} bytes (need >= {EAP_HEADER_LEN})",
                buf.len()
            )));
        }
        let code = buf[0];
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length != buf.len() {
            return Err(Error::decode(format!(
                "EAP length field {length} does not match packet size {}",
                buf.len()
            )));
        }
        match code {
            EAP_CODE_REQUEST | EAP_CODE_RESPONSE => {
                if length < EAP_HEADER_LEN + 1 {
                    return Err(Error::decode(format!(
                        "EAP code {code} packet has no Type byte (length {length})"
                    )));
                }
                Ok(EapPacket {
                    code,
                    identifier,
                    eap_type: Some(buf[4]),
                    type_data: buf[5..].to_vec(),
                })
            }
            EAP_CODE_SUCCESS | EAP_CODE_FAILURE => {
                if length != EAP_HEADER_LEN {
                    return Err(Error::decode(format!(
                        "EAP code {code} must have length 4, got {length}"
                    )));
                }
                Ok(EapPacket { code, identifier, eap_type: None, type_data: Vec::new() })
            }
            other => Err(Error::decode(format!("unknown EAP code {other}"))),
        }
    }

    /// Encode to wire bytes. Success/Failure encode as exactly 4 bytes regardless
    /// of `eap_type`/`type_data`; Request/Response emit the Type byte and data.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EAP_HEADER_LEN + 1 + self.type_data.len());
        out.push(self.code);
        out.push(self.identifier);
        out.extend_from_slice(&[0, 0]); // length placeholder
        if !matches!(self.code, EAP_CODE_SUCCESS | EAP_CODE_FAILURE) {
            if let Some(t) = self.eap_type {
                out.push(t);
                out.extend_from_slice(&self.type_data);
            }
        }
        let len = out.len().min(u16::MAX as usize) as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    /// Build a Response (code 2) echoing `identifier`.
    pub fn response(identifier: u8, eap_type: u8, type_data: Vec<u8>) -> EapPacket {
        EapPacket { code: EAP_CODE_RESPONSE, identifier, eap_type: Some(eap_type), type_data }
    }

    /// EAP-Response/Identity: Type 1, Type-Data = the raw identity bytes
    /// (no NUL terminator, no realm added).
    pub fn identity_response(identifier: u8, identity: &[u8]) -> EapPacket {
        Self::response(identifier, EAP_TYPE_IDENTITY, identity.to_vec())
    }

    /// EAP-Response/Nak: Type 3, Type-Data = one byte per desired method type.
    /// With only EAP-TLS configured this is `02 <id> 00 06 03 0d`.
    pub fn nak(identifier: u8, desired: &[u8]) -> EapPacket {
        Self::response(identifier, EAP_TYPE_NAK, desired.to_vec())
    }

    /// EAP-Response/Notification: Type 2, no data (`02 <id> 00 05 02`).
    pub fn notification_response(identifier: u8) -> EapPacket {
        Self::response(identifier, EAP_TYPE_NOTIFICATION, Vec::new())
    }

    pub fn is_request(&self) -> bool { self.code == EAP_CODE_REQUEST }
    pub fn is_success(&self) -> bool { self.code == EAP_CODE_SUCCESS }
    pub fn is_failure(&self) -> bool { self.code == EAP_CODE_FAILURE }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_request_round_trip() {
        let wire = [0x01, 0x07, 0x00, 0x0A, 0x01, b'h', b'e', b'l', b'l', b'o'];
        let p = EapPacket::decode(&wire).unwrap();
        assert_eq!(p.code, EAP_CODE_REQUEST);
        assert_eq!(p.identifier, 7);
        assert_eq!(p.eap_type, Some(EAP_TYPE_IDENTITY));
        assert_eq!(p.type_data, b"hello");
        assert_eq!(p.encode(), wire);
    }

    #[test]
    fn request_with_empty_type_data() {
        let wire = [0x01, 0x01, 0x00, 0x05, 0x01];
        let p = EapPacket::decode(&wire).unwrap();
        assert_eq!(p.eap_type, Some(1));
        assert!(p.type_data.is_empty());
        assert_eq!(p.encode(), wire);
    }

    #[test]
    fn success_failure_length_4_rule() {
        let s = EapPacket::decode(&[0x03, 0x2A, 0x00, 0x04]).unwrap();
        assert_eq!(s, EapPacket { code: 3, identifier: 0x2A, eap_type: None, type_data: vec![] });
        assert!(s.is_success());
        assert_eq!(s.encode(), [0x03, 0x2A, 0x00, 0x04]);

        let f = EapPacket::decode(&[0x04, 0x01, 0x00, 0x04]).unwrap();
        assert!(f.is_failure());
        assert_eq!(f.encode(), [0x04, 0x01, 0x00, 0x04]);

        // Success with trailing type byte is invalid (length must be exactly 4).
        assert!(matches!(EapPacket::decode(&[0x03, 0x01, 0x00, 0x05, 0x0d]), Err(Error::Decode(_))));
        // Encoding a Success ignores any stray type/data.
        let stray = EapPacket { code: 3, identifier: 9, eap_type: Some(13), type_data: vec![1, 2] };
        assert_eq!(stray.encode(), [0x03, 0x09, 0x00, 0x04]);
    }

    #[test]
    fn nak_bytes() {
        let n = EapPacket::nak(0x11, &[EAP_TYPE_TLS]);
        assert_eq!(n.encode(), [0x02, 0x11, 0x00, 0x06, 0x03, 0x0d]);
    }

    #[test]
    fn identity_response_bytes() {
        let id = b"900999990490257463@prodepdg.t-mobile.com";
        let r = EapPacket::identity_response(0x33, id);
        let wire = r.encode();
        assert_eq!(wire[0], 2);
        assert_eq!(wire[1], 0x33);
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]) as usize, 5 + id.len());
        assert_eq!(wire[4], 1);
        assert_eq!(&wire[5..], id);
        assert_eq!(EapPacket::decode(&wire).unwrap(), r);
    }

    #[test]
    fn notification_response_bytes() {
        assert_eq!(EapPacket::notification_response(5).encode(), [0x02, 0x05, 0x00, 0x05, 0x02]);
    }

    #[test]
    fn decode_errors() {
        // too short
        assert!(matches!(EapPacket::decode(&[1, 2, 0]), Err(Error::Decode(_))));
        // length mismatch (declared 6, actual 5)
        assert!(matches!(EapPacket::decode(&[1, 2, 0, 6, 1]), Err(Error::Decode(_))));
        // length mismatch (declared 4, actual 5)
        assert!(matches!(EapPacket::decode(&[1, 2, 0, 4, 1]), Err(Error::Decode(_))));
        // request without type byte
        assert!(matches!(EapPacket::decode(&[1, 2, 0, 4]), Err(Error::Decode(_))));
        // response without type byte
        assert!(matches!(EapPacket::decode(&[2, 2, 0, 4]), Err(Error::Decode(_))));
        // unknown code
        assert!(matches!(EapPacket::decode(&[9, 2, 0, 4]), Err(Error::Decode(_))));
        assert!(matches!(EapPacket::decode(&[0, 2, 0, 4]), Err(Error::Decode(_))));
        // empty
        assert!(matches!(EapPacket::decode(&[]), Err(Error::Decode(_))));
    }

    #[test]
    fn eap_tls_request_round_trip() {
        // EAP-Request/TLS Start: 01 id 00 06 0d 20
        let wire = [0x01, 0x02, 0x00, 0x06, 0x0d, 0x20];
        let p = EapPacket::decode(&wire).unwrap();
        assert_eq!(p.eap_type, Some(EAP_TYPE_TLS));
        assert_eq!(p.type_data, [0x20]);
        assert_eq!(p.encode(), wire);
    }

    #[test]
    fn large_packet_round_trip() {
        let data = vec![0xABu8; 3000];
        let p = EapPacket::response(200, EAP_TYPE_TLS, data.clone());
        let wire = p.encode();
        assert_eq!(wire.len(), 3005);
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 3005);
        assert_eq!(EapPacket::decode(&wire).unwrap(), p);
    }
}
