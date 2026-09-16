//! IKEv2 protocol constants (RFC 7296 and IANA "IKEv2 Parameters" registry).
//! Shared vocabulary for every module; keep names identical to the registry.

pub const IKE_VERSION: u8 = 0x20; // MjVer=2, MnVer=0
pub const IKE_HEADER_LEN: usize = 28;
pub const GENERIC_PAYLOAD_HEADER_LEN: usize = 4;
pub const PORT_IKE: u16 = 500;
pub const PORT_NATT: u16 = 4500;
/// Four zero bytes prefixed to IKE messages on port 4500 (RFC 3948 §2.2).
pub const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
/// RFC 3948 §4 NAT-keepalive packet.
pub const NATT_KEEPALIVE: [u8; 1] = [0xff];

// Exchange types (§3.1)
pub const EXCH_IKE_SA_INIT: u8 = 34;
pub const EXCH_IKE_AUTH: u8 = 35;
pub const EXCH_CREATE_CHILD_SA: u8 = 36;
pub const EXCH_INFORMATIONAL: u8 = 37;

// Header flags (§3.1)
pub const FLAG_INITIATOR: u8 = 0x08;
pub const FLAG_VERSION: u8 = 0x10;
pub const FLAG_RESPONSE: u8 = 0x20;

// Payload types (§3.2)
pub const PT_NONE: u8 = 0;
pub const PT_SA: u8 = 33;
pub const PT_KE: u8 = 34;
pub const PT_IDI: u8 = 35;
pub const PT_IDR: u8 = 36;
pub const PT_CERT: u8 = 37;
pub const PT_CERTREQ: u8 = 38;
pub const PT_AUTH: u8 = 39;
pub const PT_NONCE: u8 = 40;
pub const PT_NOTIFY: u8 = 41;
pub const PT_DELETE: u8 = 42;
pub const PT_VENDOR: u8 = 43;
pub const PT_TSI: u8 = 44;
pub const PT_TSR: u8 = 45;
pub const PT_SK: u8 = 46;
pub const PT_CP: u8 = 47;
pub const PT_EAP: u8 = 48;
/// Encrypted Fragment payload (RFC 7383).
pub const PT_SKF: u8 = 53;

// Protocol IDs (§3.3.1)
pub const PROTO_IKE: u8 = 1;
pub const PROTO_AH: u8 = 2;
pub const PROTO_ESP: u8 = 3;

// Transform types (§3.3.2)
pub const TT_ENCR: u8 = 1;
pub const TT_PRF: u8 = 2;
pub const TT_INTEG: u8 = 3;
pub const TT_DH: u8 = 4;
pub const TT_ESN: u8 = 5;

// Transform IDs — ENCR
pub const ENCR_DES: u16 = 2;
pub const ENCR_3DES: u16 = 3;
pub const ENCR_NULL: u16 = 11;
pub const ENCR_AES_CBC: u16 = 12;
pub const ENCR_AES_CTR: u16 = 13;
pub const ENCR_AES_GCM_8: u16 = 18;
pub const ENCR_AES_GCM_12: u16 = 19;
pub const ENCR_AES_GCM_16: u16 = 20;
pub const ENCR_CHACHA20_POLY1305: u16 = 28;
// Transform IDs — PRF
pub const PRF_HMAC_MD5: u16 = 1;
pub const PRF_HMAC_SHA1: u16 = 2;
pub const PRF_AES128_XCBC: u16 = 4;
pub const PRF_HMAC_SHA2_256: u16 = 5;
pub const PRF_HMAC_SHA2_384: u16 = 6;
pub const PRF_HMAC_SHA2_512: u16 = 7;
// Transform IDs — INTEG
pub const AUTH_NONE: u16 = 0;
pub const AUTH_HMAC_MD5_96: u16 = 1;
pub const AUTH_HMAC_SHA1_96: u16 = 2;
pub const AUTH_AES_XCBC_96: u16 = 5;
pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
pub const AUTH_HMAC_SHA2_384_192: u16 = 13;
pub const AUTH_HMAC_SHA2_512_256: u16 = 14;
// Transform IDs — D-H groups
pub const DH_NONE: u16 = 0;
pub const DH_MODP_768: u16 = 1;
pub const DH_MODP_1024: u16 = 2;
pub const DH_MODP_1536: u16 = 5;
pub const DH_MODP_2048: u16 = 14;
pub const DH_MODP_3072: u16 = 15;
pub const DH_MODP_4096: u16 = 16;
pub const DH_ECP_256: u16 = 19;
pub const DH_ECP_384: u16 = 20;
pub const DH_CURVE25519: u16 = 31;
// Transform IDs — ESN
pub const ESN_NO: u16 = 0;
pub const ESN_YES: u16 = 1;

/// Transform attribute type: Key Length, TV format (AF bit set), value in bits (§3.3.5).
pub const ATTR_KEY_LENGTH: u16 = 14;
pub const ATTR_AF_BIT: u16 = 0x8000;

// Notify message types (§3.10.1) — errors (< 16384)
pub const N_UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
pub const N_INVALID_IKE_SPI: u16 = 4;
pub const N_INVALID_MAJOR_VERSION: u16 = 5;
pub const N_INVALID_SYNTAX: u16 = 7;
pub const N_INVALID_MESSAGE_ID: u16 = 9;
pub const N_INVALID_SPI: u16 = 11;
pub const N_NO_PROPOSAL_CHOSEN: u16 = 14;
pub const N_INVALID_KE_PAYLOAD: u16 = 17;
pub const N_AUTHENTICATION_FAILED: u16 = 24;
pub const N_SINGLE_PAIR_REQUIRED: u16 = 34;
pub const N_NO_ADDITIONAL_SAS: u16 = 35;
pub const N_INTERNAL_ADDRESS_FAILURE: u16 = 36;
pub const N_FAILED_CP_REQUIRED: u16 = 37;
pub const N_TS_UNACCEPTABLE: u16 = 38;
pub const N_INVALID_SELECTORS: u16 = 39;
/// RFC 4555 §12 (MOBIKE). An ERROR-range type: the responder refuses the address set of
/// an `UPDATE_SA_ADDRESSES` / `ADDITIONAL_*_ADDRESS`. `IkeMessage::error_notify` finds it
/// like any other error notify; no status-range special case is needed.
pub const N_UNACCEPTABLE_ADDRESSES: u16 = 40;
/// RFC 4555 §12 (MOBIKE), also an ERROR-range type: the responder's own NAT detection
/// disagrees with the NAT_DETECTION payloads of an `UPDATE_SA_ADDRESSES`.
pub const N_UNEXPECTED_NAT_DETECTION: u16 = 41;
pub const N_TEMPORARY_FAILURE: u16 = 43;
pub const N_CHILD_SA_NOT_FOUND: u16 = 44;
// Notify message types — status (>= 16384)
pub const N_INITIAL_CONTACT: u16 = 16384;
pub const N_SET_WINDOW_SIZE: u16 = 16385;
pub const N_ADDITIONAL_TS_POSSIBLE: u16 = 16386;
pub const N_IPCOMP_SUPPORTED: u16 = 16387;
pub const N_NAT_DETECTION_SOURCE_IP: u16 = 16388;
pub const N_NAT_DETECTION_DESTINATION_IP: u16 = 16389;
pub const N_COOKIE: u16 = 16390;
pub const N_USE_TRANSPORT_MODE: u16 = 16391;
pub const N_HTTP_CERT_LOOKUP_SUPPORTED: u16 = 16392;
pub const N_REKEY_SA: u16 = 16393;
pub const N_ESP_TFC_PADDING_NOT_SUPPORTED: u16 = 16394;
pub const N_NON_FIRST_FRAGMENTS_ALSO: u16 = 16395;
pub const N_MOBIKE_SUPPORTED: u16 = 16396;
pub const N_ADDITIONAL_IP4_ADDRESS: u16 = 16397;
pub const N_ADDITIONAL_IP6_ADDRESS: u16 = 16398;
pub const N_NO_ADDITIONAL_ADDRESSES: u16 = 16399;
pub const N_UPDATE_SA_ADDRESSES: u16 = 16400;
pub const N_COOKIE2: u16 = 16401;
/// RFC 4555 §12. The ONE MOBIKE rejection IANA registers in the STATUS range
/// (>= 16384): it does NOT trip [`NotifyPayload::is_error`] / `IkeMessage::error_notify`,
/// so an address-update response has to look for it by type. The other two rejections
/// ([`N_UNACCEPTABLE_ADDRESSES`] 40, [`N_UNEXPECTED_NAT_DETECTION`] 41) are ordinary
/// error types and need no special case.
///
/// [`NotifyPayload::is_error`]: crate::ike::payload::NotifyPayload::is_error
pub const N_NO_NATS_ALLOWED: u16 = 16402;
/// RFC 5998.
pub const N_EAP_ONLY_AUTHENTICATION: u16 = 16417;
/// RFC 7383.
pub const N_IKEV2_FRAGMENTATION_SUPPORTED: u16 = 16430;
/// RFC 7427.
pub const N_SIGNATURE_HASH_ALGORITHMS: u16 = 16431;
// 3GPP TS 24.302 private-use notifies (not sent; listed for the extension seam)
pub const N_3GPP_BACKOFF_TIMER: u16 = 41041;
pub const N_3GPP_DEVICE_IDENTITY: u16 = 41101;
pub const N_3GPP_N1_MODE_CAPABILITY: u16 = 51015;
pub const N_3GPP_N1_MODE_INFORMATION: u16 = 51115;

/// Human-readable name for a notify type (for errors/logs).
pub fn notify_name(t: u16) -> &'static str {
    match t {
        N_UNSUPPORTED_CRITICAL_PAYLOAD => "UNSUPPORTED_CRITICAL_PAYLOAD",
        N_INVALID_IKE_SPI => "INVALID_IKE_SPI",
        N_INVALID_MAJOR_VERSION => "INVALID_MAJOR_VERSION",
        N_INVALID_SYNTAX => "INVALID_SYNTAX",
        N_INVALID_MESSAGE_ID => "INVALID_MESSAGE_ID",
        N_INVALID_SPI => "INVALID_SPI",
        N_NO_PROPOSAL_CHOSEN => "NO_PROPOSAL_CHOSEN",
        N_INVALID_KE_PAYLOAD => "INVALID_KE_PAYLOAD",
        N_AUTHENTICATION_FAILED => "AUTHENTICATION_FAILED",
        N_SINGLE_PAIR_REQUIRED => "SINGLE_PAIR_REQUIRED",
        N_NO_ADDITIONAL_SAS => "NO_ADDITIONAL_SAS",
        N_INTERNAL_ADDRESS_FAILURE => "INTERNAL_ADDRESS_FAILURE",
        N_FAILED_CP_REQUIRED => "FAILED_CP_REQUIRED",
        N_TS_UNACCEPTABLE => "TS_UNACCEPTABLE",
        N_INVALID_SELECTORS => "INVALID_SELECTORS",
        N_UNACCEPTABLE_ADDRESSES => "UNACCEPTABLE_ADDRESSES",
        N_UNEXPECTED_NAT_DETECTION => "UNEXPECTED_NAT_DETECTION",
        N_TEMPORARY_FAILURE => "TEMPORARY_FAILURE",
        N_CHILD_SA_NOT_FOUND => "CHILD_SA_NOT_FOUND",
        N_INITIAL_CONTACT => "INITIAL_CONTACT",
        N_SET_WINDOW_SIZE => "SET_WINDOW_SIZE",
        N_ADDITIONAL_TS_POSSIBLE => "ADDITIONAL_TS_POSSIBLE",
        N_NAT_DETECTION_SOURCE_IP => "NAT_DETECTION_SOURCE_IP",
        N_NAT_DETECTION_DESTINATION_IP => "NAT_DETECTION_DESTINATION_IP",
        N_COOKIE => "COOKIE",
        N_USE_TRANSPORT_MODE => "USE_TRANSPORT_MODE",
        N_REKEY_SA => "REKEY_SA",
        N_ESP_TFC_PADDING_NOT_SUPPORTED => "ESP_TFC_PADDING_NOT_SUPPORTED",
        N_NON_FIRST_FRAGMENTS_ALSO => "NON_FIRST_FRAGMENTS_ALSO",
        N_MOBIKE_SUPPORTED => "MOBIKE_SUPPORTED",
        N_ADDITIONAL_IP4_ADDRESS => "ADDITIONAL_IP4_ADDRESS",
        N_ADDITIONAL_IP6_ADDRESS => "ADDITIONAL_IP6_ADDRESS",
        N_NO_ADDITIONAL_ADDRESSES => "NO_ADDITIONAL_ADDRESSES",
        N_UPDATE_SA_ADDRESSES => "UPDATE_SA_ADDRESSES",
        N_COOKIE2 => "COOKIE2",
        N_NO_NATS_ALLOWED => "NO_NATS_ALLOWED",
        N_EAP_ONLY_AUTHENTICATION => "EAP_ONLY_AUTHENTICATION",
        N_IKEV2_FRAGMENTATION_SUPPORTED => "IKEV2_FRAGMENTATION_SUPPORTED",
        N_SIGNATURE_HASH_ALGORITHMS => "SIGNATURE_HASH_ALGORITHMS",
        N_3GPP_BACKOFF_TIMER => "3GPP_BACKOFF_TIMER",
        N_3GPP_DEVICE_IDENTITY => "3GPP_DEVICE_IDENTITY",
        N_3GPP_N1_MODE_CAPABILITY => "3GPP_N1_MODE_CAPABILITY",
        N_3GPP_N1_MODE_INFORMATION => "3GPP_N1_MODE_INFORMATION",
        _ => "UNKNOWN",
    }
}

// Identification payload ID types (§3.5)
pub const ID_IPV4_ADDR: u8 = 1;
pub const ID_FQDN: u8 = 2;
pub const ID_RFC822_ADDR: u8 = 3;
pub const ID_IPV6_ADDR: u8 = 5;
pub const ID_DER_ASN1_DN: u8 = 9;
pub const ID_DER_ASN1_GN: u8 = 10;
pub const ID_KEY_ID: u8 = 11;

// Authentication methods (§3.8)
pub const AUTH_RSA_DIGITAL_SIGNATURE: u8 = 1;
pub const AUTH_SHARED_KEY_MIC: u8 = 2;
pub const AUTH_DSS_DIGITAL_SIGNATURE: u8 = 3;
pub const AUTH_DIGITAL_SIGNATURE: u8 = 14;
/// RFC 7296 §2.15 key pad for shared-key (and EAP MSK) AUTH.
pub const KEY_PAD_FOR_IKEV2: &[u8] = b"Key Pad for IKEv2";

// Configuration payload (§3.15)
pub const CFG_REQUEST: u8 = 1;
pub const CFG_REPLY: u8 = 2;
pub const CFG_SET: u8 = 3;
pub const CFG_ACK: u8 = 4;
// Configuration attribute types (§3.15.1 + IANA)
pub const CFG_INTERNAL_IP4_ADDRESS: u16 = 1;
pub const CFG_INTERNAL_IP4_NETMASK: u16 = 2;
pub const CFG_INTERNAL_IP4_DNS: u16 = 3;
pub const CFG_INTERNAL_IP4_NBNS: u16 = 4;
pub const CFG_INTERNAL_IP4_DHCP: u16 = 6;
pub const CFG_APPLICATION_VERSION: u16 = 7;
pub const CFG_INTERNAL_IP6_ADDRESS: u16 = 8;
pub const CFG_INTERNAL_IP6_DNS: u16 = 10;
pub const CFG_INTERNAL_IP6_DHCP: u16 = 12;
pub const CFG_INTERNAL_IP4_SUBNET: u16 = 13;
pub const CFG_SUPPORTED_ATTRIBUTES: u16 = 14;
pub const CFG_INTERNAL_IP6_SUBNET: u16 = 15;
/// RFC 7651 P-CSCF discovery attributes (3GPP ePDG).
pub const CFG_P_CSCF_IP4_ADDRESS: u16 = 20;
pub const CFG_P_CSCF_IP6_ADDRESS: u16 = 21;

// Traffic selector types (§3.13.1)
pub const TS_IPV4_ADDR_RANGE: u8 = 7;
pub const TS_IPV6_ADDR_RANGE: u8 = 8;

// EAP (RFC 3748 §4)
pub const EAP_CODE_REQUEST: u8 = 1;
pub const EAP_CODE_RESPONSE: u8 = 2;
pub const EAP_CODE_SUCCESS: u8 = 3;
pub const EAP_CODE_FAILURE: u8 = 4;
pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_TLS: u8 = 13;
pub const EAP_TYPE_AKA: u8 = 23;
// EAP-TLS flags (RFC 5216 §3.1)
pub const EAP_TLS_FLAG_L: u8 = 0x80;
pub const EAP_TLS_FLAG_M: u8 = 0x40;
pub const EAP_TLS_FLAG_S: u8 = 0x20;

// ESP next-header values for tunnel mode (RFC 4303 §2.6)
pub const NEXT_HEADER_IPV4: u8 = 4;
pub const NEXT_HEADER_IPV6: u8 = 41;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ike::payload::NotifyPayload;

    /// RFC 4555 §12 assigns MOBIKE one contiguous STATUS block (16396..=16402); a wrong
    /// value here would silently turn an address update into an unknown notify the
    /// gateway ignores. 16403/16404 are NOT MOBIKE: they are AUTH_LIFETIME (RFC 4478)
    /// and MULTIPLE_AUTH_SUPPORTED (RFC 4739), which a responder may legitimately send.
    #[test]
    fn mobike_notify_constants_match_rfc4555() {
        assert_eq!(
            [
                N_MOBIKE_SUPPORTED,
                N_ADDITIONAL_IP4_ADDRESS,
                N_ADDITIONAL_IP6_ADDRESS,
                N_NO_ADDITIONAL_ADDRESSES,
                N_UPDATE_SA_ADDRESSES,
                N_COOKIE2,
                N_NO_NATS_ALLOWED,
            ],
            [16396, 16397, 16398, 16399, 16400, 16401, 16402]
        );
        // RFC 4555 §12 puts the other two rejections in the ERROR range.
        assert_eq!([N_UNACCEPTABLE_ADDRESSES, N_UNEXPECTED_NAT_DETECTION], [40, 41]);
        for t in 16396..=16402u16 {
            assert_ne!(notify_name(t), "UNKNOWN", "notify {t} has no name");
        }
        assert_eq!(notify_name(N_UPDATE_SA_ADDRESSES), "UPDATE_SA_ADDRESSES");
        assert_eq!(notify_name(N_UNACCEPTABLE_ADDRESSES), "UNACCEPTABLE_ADDRESSES");
        assert_eq!(notify_name(N_UNEXPECTED_NAT_DETECTION), "UNEXPECTED_NAT_DETECTION");
        // 16403/16404 belong to other RFCs and must not be named as MOBIKE rejections.
        assert_eq!(notify_name(16403), "UNKNOWN");
        assert_eq!(notify_name(16404), "UNKNOWN");
    }

    /// Only `NO_NATS_ALLOWED` lives in the STATUS range, so `is_error()` (and with it
    /// `IkeMessage::error_notify`) is blind to it and the address-update response
    /// handler has to test for it by type. The other two rejections are ordinary error
    /// types and are caught by `error_notify` like any other.
    #[test]
    fn only_no_nats_allowed_is_a_status_range_rejection() {
        assert!(!NotifyPayload::status(N_NO_NATS_ALLOWED, Vec::new()).is_error());
        for t in [N_UNACCEPTABLE_ADDRESSES, N_UNEXPECTED_NAT_DETECTION] {
            assert!(NotifyPayload::status(t, Vec::new()).is_error(), "notify {t} must look like an error");
        }
        assert!(NotifyPayload::status(N_INVALID_SYNTAX, Vec::new()).is_error());
    }
}
