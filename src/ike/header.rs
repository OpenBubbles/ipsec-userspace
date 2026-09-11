//! IKEv2 fixed header (RFC 7296 §3.1), 28 bytes:
//!
//! ```text
//! SPIi(8) | SPIr(8) | NextPayload(1) | Version(1)=0x20 | ExchangeType(1) | Flags(1) | MessageID(4) | Length(4)
//! ```
//!
//! Flags: bit3 INITIATOR (0x08) is set on every message we originate, bit5 RESPONSE
//! (0x20) on responses; the VERSION bit (0x10) is never set.

use crate::ike::constants::*;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IkeHeader {
    pub spi_i: u64,
    pub spi_r: u64,
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl IkeHeader {
    pub const LEN: usize = IKE_HEADER_LEN;

    /// Append the 28 header bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(Self::LEN);
        out.extend_from_slice(&self.spi_i.to_be_bytes());
        out.extend_from_slice(&self.spi_r.to_be_bytes());
        out.push(self.next_payload);
        out.push(self.version);
        out.push(self.exchange_type);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }

    /// Parse the first 28 bytes of `buf`. `Error::Decode` if the buffer is shorter
    /// than a header or the major version is not 2. The `length` field is NOT
    /// checked against `buf.len()` here (the message layer does that, and a
    /// datagram may carry trailing bytes it wants to diagnose itself).
    pub fn decode(buf: &[u8]) -> Result<IkeHeader> {
        if buf.len() < Self::LEN {
            return Err(Error::Decode(format!(
                "IKE header: need {} bytes, got {}",
                Self::LEN,
                buf.len()
            )));
        }
        let spi_i = u64::from_be_bytes(read_array(&buf[0..8])?);
        let spi_r = u64::from_be_bytes(read_array(&buf[8..16])?);
        let next_payload = buf[16];
        let version = buf[17];
        let exchange_type = buf[18];
        let flags = buf[19];
        let message_id = u32::from_be_bytes(read_array(&buf[20..24])?);
        let length = u32::from_be_bytes(read_array(&buf[24..28])?);

        if version >> 4 != IKE_VERSION >> 4 {
            return Err(Error::Decode(format!(
                "IKE header: unsupported major version {} (version byte 0x{:02x})",
                version >> 4,
                version
            )));
        }
        if (length as usize) < Self::LEN {
            return Err(Error::Decode(format!(
                "IKE header: length field {} smaller than header ({})",
                length,
                Self::LEN
            )));
        }

        Ok(IkeHeader {
            spi_i,
            spi_r,
            next_payload,
            version,
            exchange_type,
            flags,
            message_id,
            length,
        })
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    pub fn is_initiator(&self) -> bool {
        self.flags & FLAG_INITIATOR != 0
    }
}

/// Copy a slice into a fixed-size array; the slices above are always exactly
/// sized, so this only guards against internal slicing mistakes.
fn read_array<const N: usize>(src: &[u8]) -> Result<[u8; N]> {
    src.try_into()
        .map_err(|_| Error::Decode(format!("IKE header: expected {} bytes, got {}", N, src.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> IkeHeader {
        IkeHeader {
            spi_i: 0x0102030405060708,
            spi_r: 0,
            next_payload: PT_SA,
            version: IKE_VERSION,
            exchange_type: EXCH_IKE_SA_INIT,
            flags: FLAG_INITIATOR,
            message_id: 0,
            length: 28 + 100,
        }
    }

    #[test]
    fn encode_matches_wire_layout() {
        let h = sample();
        let mut out = Vec::new();
        h.encode(&mut out);
        assert_eq!(out.len(), IkeHeader::LEN);
        let expected = hex::decode("0102030405060708 0000000000000000 21 20 22 08 00000000 00000080".replace(' ', "")).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn round_trip_request() {
        let h = sample();
        let mut out = Vec::new();
        h.encode(&mut out);
        let back = IkeHeader::decode(&out).unwrap();
        assert_eq!(back, h);
        assert!(back.is_initiator());
        assert!(!back.is_response());
    }

    #[test]
    fn round_trip_response_flags() {
        let mut h = sample();
        h.spi_r = 0xdeadbeefcafef00d;
        h.next_payload = PT_SK;
        h.exchange_type = EXCH_IKE_AUTH;
        h.flags = FLAG_RESPONSE; // responder -> I bit clear
        h.message_id = 7;
        h.length = 0x0001_0203;
        let mut out = Vec::new();
        h.encode(&mut out);
        assert_eq!(out[19], 0x20);
        let back = IkeHeader::decode(&out).unwrap();
        assert_eq!(back, h);
        assert!(back.is_response());
        assert!(!back.is_initiator());
        assert_eq!(back.message_id, 7);
        assert_eq!(back.spi_r, 0xdeadbeefcafef00d);

        // both bits set (our own response to a peer request)
        h.flags = FLAG_RESPONSE | FLAG_INITIATOR;
        let mut out = Vec::new();
        h.encode(&mut out);
        let back = IkeHeader::decode(&out).unwrap();
        assert!(back.is_response() && back.is_initiator());
    }

    #[test]
    fn decode_tolerates_trailing_bytes() {
        let h = sample();
        let mut out = Vec::new();
        h.encode(&mut out);
        out.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(IkeHeader::decode(&out).unwrap(), h);
    }

    #[test]
    fn decode_short_buffer() {
        let h = sample();
        let mut out = Vec::new();
        h.encode(&mut out);
        for n in 0..IkeHeader::LEN {
            match IkeHeader::decode(&out[..n]) {
                Err(Error::Decode(_)) => {}
                other => panic!("expected Decode error for {} bytes, got {:?}", n, other),
            }
        }
    }

    #[test]
    fn decode_wrong_major_version() {
        let h = sample();
        let mut out = Vec::new();
        h.encode(&mut out);
        out[17] = 0x10; // IKEv1
        assert!(matches!(IkeHeader::decode(&out), Err(Error::Decode(m)) if m.contains("version")));
        out[17] = 0x30;
        assert!(matches!(IkeHeader::decode(&out), Err(Error::Decode(_))));
        // minor version is ignored (RFC 7296 §3.1)
        out[17] = 0x21;
        assert_eq!(IkeHeader::decode(&out).unwrap().version, 0x21);
    }

    #[test]
    fn decode_length_below_header() {
        let mut h = sample();
        h.length = 27;
        let mut out = Vec::new();
        h.encode(&mut out);
        assert!(matches!(IkeHeader::decode(&out), Err(Error::Decode(_))));
    }
}
