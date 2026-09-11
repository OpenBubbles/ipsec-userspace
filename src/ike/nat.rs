//! NAT detection (RFC 7296 §2.23), mirroring the AOSP client.
//!
//! ```text
//! NAT_DETECTION_*_IP data = SHA1( SPIi(8 BE) | SPIr(8 BE) | IP address (4 or 16) | port(2 BE) )
//! ```
//!
//! In the IKE_SA_INIT request we send `SOURCE = hash(local addr, local port)` and
//! `DESTINATION = hash(gateway addr, gateway port)` with `SPIr = 0`. When
//! `force_udp_encap` is on (the default, and what AOSP does for every IPv4 gateway)
//! the local address in SOURCE is replaced by the fake
//! [`FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4`] (`192.0.2.0`, real port kept): the
//! responder then concludes we are behind a NAT and uses UDP-encapsulated ESP — the
//! only ESP a userspace client can carry.
//!
//! The response is evaluated by [`evaluate`]: the responder's `SOURCE` notifies are
//! compared with `hash(gateway addr:port)` (mismatch → remote behind NAT) and its
//! `DESTINATION` notify with `hash(REAL local addr:port)` (mismatch → local behind
//! NAT), both hashed with the real SPIr from the response header. With
//! `force_local_nat` the local result is forced `true`, exactly like AOSP's
//! `needEnableForceUdpEncap()`.

use crate::ike::constants::{N_NAT_DETECTION_DESTINATION_IP, N_NAT_DETECTION_SOURCE_IP};
use crate::ike::payload::NotifyPayload;
use crate::{Error, Result};
use sha1::{Digest, Sha1};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// AOSP `FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4`: the address hashed into our
/// NAT_DETECTION_SOURCE_IP when forcing UDP encapsulation (RFC 5737 TEST-NET-1).
pub const FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 0);

/// Length of a NAT-D hash (SHA-1).
pub const NAT_DETECTION_HASH_LEN: usize = 20;

/// `SHA1( SPIi(8) | SPIr(8) | addr bytes | port(2) )` — big-endian throughout.
pub fn nat_detection_hash(spi_i: u64, spi_r: u64, addr: IpAddr, port: u16) -> [u8; NAT_DETECTION_HASH_LEN] {
    let mut h = Sha1::new();
    h.update(spi_i.to_be_bytes());
    h.update(spi_r.to_be_bytes());
    match addr {
        IpAddr::V4(a) => h.update(a.octets()),
        IpAddr::V6(a) => h.update(a.octets()),
    }
    h.update(port.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; NAT_DETECTION_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Result of NAT detection after IKE_SA_INIT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatStatus {
    /// We are (or are pretending to be) behind a NAT.
    pub local_behind_nat: bool,
    /// The gateway is behind a NAT.
    pub remote_behind_nat: bool,
    /// `local_behind_nat || remote_behind_nat` — switch to 4500 + UDP-encap ESP.
    pub detected: bool,
}

/// Build the two NAT-D notifies for our IKE_SA_INIT request (`SPIr = 0`), in
/// send order: `[NAT_DETECTION_SOURCE_IP, NAT_DETECTION_DESTINATION_IP]`.
///
/// `force_udp_encap` substitutes [`FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4`] for the
/// local address in SOURCE (real local port kept). AOSP only does this for an IPv4
/// gateway, and only sends NAT-D at all for IPv4 gateways; the caller decides.
pub fn request_notifies(spi_i: u64, local: SocketAddr, remote: SocketAddr, force_udp_encap: bool) -> [NotifyPayload; 2] {
    let src_addr = if force_udp_encap { IpAddr::V4(FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4) } else { local.ip() };
    let src = nat_detection_hash(spi_i, 0, src_addr, local.port());
    let dst = nat_detection_hash(spi_i, 0, remote.ip(), remote.port());
    log::debug!(
        "NAT-D request: SRC over {}:{} (fake={}) = {}, DST over {}:{} = {}",
        src_addr,
        local.port(),
        force_udp_encap,
        hex::encode(src),
        remote.ip(),
        remote.port(),
        hex::encode(dst)
    );
    [
        NotifyPayload::status(N_NAT_DETECTION_SOURCE_IP, src.to_vec()),
        NotifyPayload::status(N_NAT_DETECTION_DESTINATION_IP, dst.to_vec()),
    ]
}

/// Evaluate the responder's NAT-D notifies from the IKE_SA_INIT response (§6).
///
/// - `spi_i` / `spi_r`: SPIs from the response header (`spi_r` is the responder's real SPI).
/// - `local`: our REAL socket address (bound address / discovered egress address + port
///   we sent from); `remote`: the gateway address and port we sent to (500).
/// - `response_notifies`: every Notify payload of the response (other types are ignored).
/// - `force_local_nat`: when `true`, `local_behind_nat` is forced `true` regardless of
///   the hash comparison — pass `cfg.natt.force_udp_encap` (AOSP forces it whenever the
///   gateway is IPv4). The real comparison is still made and logged.
///
/// Returns `detected = false` (all flags clear) if the response carries neither NAT-D
/// notify (peer does not support NAT-T; stay on port 500 — logged loudly because
/// userspace ESP cannot work without UDP encapsulation). Exactly one of the two
/// present, or more than one `DESTINATION_IP`, is `Error::Decode` (AOSP:
/// INVALID_SYNTAX). Multiple `SOURCE_IP` notifies are allowed (multi-homed responder):
/// the remote is behind a NAT only if none of them matches.
pub fn evaluate(
    spi_i: u64,
    spi_r: u64,
    local: SocketAddr,
    remote: SocketAddr,
    response_notifies: &[&NotifyPayload],
    force_local_nat: bool,
) -> Result<NatStatus> {
    let sources: Vec<&[u8]> = response_notifies
        .iter()
        .filter(|n| n.notify_type == N_NAT_DETECTION_SOURCE_IP)
        .map(|n| n.data.as_slice())
        .collect();
    let dests: Vec<&[u8]> = response_notifies
        .iter()
        .filter(|n| n.notify_type == N_NAT_DETECTION_DESTINATION_IP)
        .map(|n| n.data.as_slice())
        .collect();

    if sources.is_empty() && dests.is_empty() {
        log::warn!(
            "IKE_SA_INIT response carries no NAT_DETECTION notifies: peer does not support NAT-T; \
             staying on port {} — UDP-encapsulated ESP will NOT be available",
            remote.port()
        );
        return Ok(NatStatus::default());
    }
    if sources.is_empty() || dests.is_empty() {
        return Err(Error::Decode(format!(
            "IKE_SA_INIT response has {} NAT_DETECTION_SOURCE_IP and {} NAT_DETECTION_DESTINATION_IP notifies (need both)",
            sources.len(),
            dests.len()
        )));
    }
    if dests.len() > 1 {
        return Err(Error::Decode(format!(
            "IKE_SA_INIT response has {} NAT_DETECTION_DESTINATION_IP notifies (expected 1)",
            dests.len()
        )));
    }
    for (i, d) in sources.iter().chain(dests.iter()).enumerate() {
        if d.len() != NAT_DETECTION_HASH_LEN {
            return Err(Error::Decode(format!(
                "NAT_DETECTION notify #{i} data length {} (expected {NAT_DETECTION_HASH_LEN})",
                d.len()
            )));
        }
    }

    // Remote: the responder hashed its own addr:port; compare with where we sent to.
    let expected_remote = nat_detection_hash(spi_i, spi_r, remote.ip(), remote.port());
    let remote_behind_nat = !sources.iter().any(|s| *s == &expected_remote[..]);

    // Local: the responder hashed the addr:port it saw us from; compare with our REAL address.
    let expected_local = nat_detection_hash(spi_i, spi_r, local.ip(), local.port());
    let local_measured = dests.first().map(|d| *d != &expected_local[..]).unwrap_or(false);
    let local_behind_nat = local_measured || force_local_nat;

    log::debug!(
        "NAT-D evaluate: remote {}:{} behind NAT={} ({} SOURCE notif{}), local {}:{} behind NAT={} (measured={}, forced={})",
        remote.ip(),
        remote.port(),
        remote_behind_nat,
        sources.len(),
        if sources.len() == 1 { "y" } else { "ies" },
        local.ip(),
        local.port(),
        local_behind_nat,
        local_measured,
        force_local_nat
    );

    Ok(NatStatus { local_behind_nat, remote_behind_nat, detected: local_behind_nat || remote_behind_nat })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ike::constants::N_IKEV2_FRAGMENTATION_SUPPORTED;
    use std::net::{Ipv6Addr, SocketAddrV4};

    const SPI_I: u64 = 0x0102030405060708;
    const SPI_R: u64 = 0x1112131415161718;

    fn local() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 54321))
    }
    fn remote() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 500))
    }
    fn n(t: u16, data: Vec<u8>) -> NotifyPayload {
        NotifyPayload::status(t, data)
    }

    #[test]
    fn hash_kat_ipv4_independent_sha1() {
        // SHA1(0102030405060708 | 00*8 | c0000200 | 01f4), computed with Python hashlib.
        let h = nat_detection_hash(SPI_I, 0, IpAddr::V4(FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4), 500);
        assert_eq!(hex::encode(h), "6fbe4ed8ffe2e01320204f86432efcf62e3b2219");
        // And re-derived here with the sha1 crate over the explicit byte layout.
        let mut input = Vec::new();
        input.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        input.extend_from_slice(&[0; 8]);
        input.extend_from_slice(&[0xc0, 0x00, 0x02, 0x00]);
        input.extend_from_slice(&[0x01, 0xf4]);
        assert_eq!(input.len(), 22);
        let d = Sha1::digest(&input);
        assert_eq!(&h[..], &d[..]);
    }

    #[test]
    fn hash_kat_ipv6() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let h = nat_detection_hash(SPI_I, SPI_R, IpAddr::V6(a), 4500);
        assert_eq!(hex::encode(h), "1ee24423bf8f59515e0265c6d0f08be3d038f7e5");
        let mut input = Vec::new();
        input.extend_from_slice(&SPI_I.to_be_bytes());
        input.extend_from_slice(&SPI_R.to_be_bytes());
        input.extend_from_slice(&a.octets());
        input.extend_from_slice(&4500u16.to_be_bytes());
        assert_eq!(input.len(), 34);
        assert_eq!(&h[..], &Sha1::digest(&input)[..]);
    }

    #[test]
    fn hash_sensitivity() {
        let base = nat_detection_hash(SPI_I, SPI_R, local().ip(), local().port());
        assert_ne!(base, nat_detection_hash(SPI_I ^ 1, SPI_R, local().ip(), local().port()));
        assert_ne!(base, nat_detection_hash(SPI_I, SPI_R ^ 1, local().ip(), local().port()));
        assert_ne!(base, nat_detection_hash(SPI_I, SPI_R, remote().ip(), local().port()));
        assert_ne!(base, nat_detection_hash(SPI_I, SPI_R, local().ip(), local().port() + 1));
        // Port is big-endian: 0x0100 != 0x0001.
        assert_ne!(
            nat_detection_hash(SPI_I, SPI_R, local().ip(), 0x0100),
            nat_detection_hash(SPI_I, SPI_R, local().ip(), 0x0001)
        );
    }

    #[test]
    fn request_notifies_fake_and_real_source() {
        let [src, dst] = request_notifies(SPI_I, local(), remote(), true);
        assert_eq!(src.notify_type, N_NAT_DETECTION_SOURCE_IP);
        assert_eq!(src.protocol_id, 0);
        assert!(src.spi.is_empty());
        assert_eq!(src.data, nat_detection_hash(SPI_I, 0, IpAddr::V4(FORCE_ENCAP_FAKE_LOCAL_ADDRESS_IPV4), 54321).to_vec());
        assert_eq!(dst.notify_type, N_NAT_DETECTION_DESTINATION_IP);
        assert_eq!(dst.data, nat_detection_hash(SPI_I, 0, remote().ip(), 500).to_vec());
        assert_eq!(dst.data.len(), 20);

        let [src_real, dst_real] = request_notifies(SPI_I, local(), remote(), false);
        assert_eq!(src_real.data, nat_detection_hash(SPI_I, 0, local().ip(), 54321).to_vec());
        assert_ne!(src_real.data, src.data);
        assert_eq!(dst_real.data, dst.data);
    }

    /// Notifies as an honest, un-NATed responder would send them.
    fn honest_response() -> (NotifyPayload, NotifyPayload) {
        let src = n(N_NAT_DETECTION_SOURCE_IP, nat_detection_hash(SPI_I, SPI_R, remote().ip(), remote().port()).to_vec());
        let dst = n(N_NAT_DETECTION_DESTINATION_IP, nat_detection_hash(SPI_I, SPI_R, local().ip(), local().port()).to_vec());
        (src, dst)
    }

    #[test]
    fn evaluate_no_nat_no_force() {
        let (src, dst) = honest_response();
        let frag = n(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![]);
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&frag, &src, &dst], false).unwrap();
        assert_eq!(st, NatStatus { local_behind_nat: false, remote_behind_nat: false, detected: false });
    }

    #[test]
    fn evaluate_forced_local_nat() {
        let (src, dst) = honest_response();
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &dst], true).unwrap();
        assert_eq!(st, NatStatus { local_behind_nat: true, remote_behind_nat: false, detected: true });
    }

    #[test]
    fn evaluate_local_nat_measured() {
        let (src, _) = honest_response();
        // Responder saw us from a public addr:port that differs from our local one.
        let public = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 40000));
        let dst = n(N_NAT_DETECTION_DESTINATION_IP, nat_detection_hash(SPI_I, SPI_R, public.ip(), public.port()).to_vec());
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &dst], false).unwrap();
        assert_eq!(st, NatStatus { local_behind_nat: true, remote_behind_nat: false, detected: true });
        // Forcing does not change an already-true result.
        let st2 = evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &dst], true).unwrap();
        assert_eq!(st2, st);
    }

    #[test]
    fn evaluate_remote_nat() {
        let (_, dst) = honest_response();
        let inner = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 5), 500));
        let src = n(N_NAT_DETECTION_SOURCE_IP, nat_detection_hash(SPI_I, SPI_R, inner.ip(), inner.port()).to_vec());
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &dst], false).unwrap();
        assert_eq!(st, NatStatus { local_behind_nat: false, remote_behind_nat: true, detected: true });
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &dst], true).unwrap();
        assert_eq!(st, NatStatus { local_behind_nat: true, remote_behind_nat: true, detected: true });
    }

    #[test]
    fn evaluate_multiple_sources_one_matching_is_not_remote_nat() {
        let (src_ok, dst) = honest_response();
        let src_other = n(N_NAT_DETECTION_SOURCE_IP, vec![0xee; 20]);
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&src_other, &src_ok, &dst], false).unwrap();
        assert!(!st.remote_behind_nat);
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&src_other, &dst], false).unwrap();
        assert!(st.remote_behind_nat);
    }

    #[test]
    fn evaluate_wrong_spi_r_looks_like_nat() {
        // Responder hashes with its real SPIr; evaluating with 0 must mismatch.
        let (src, dst) = honest_response();
        let st = evaluate(SPI_I, 0, local(), remote(), &[&src, &dst], false).unwrap();
        assert!(st.local_behind_nat && st.remote_behind_nat && st.detected);
    }

    #[test]
    fn evaluate_missing_notifies() {
        let frag = n(N_IKEV2_FRAGMENTATION_SUPPORTED, vec![]);
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[&frag], true).unwrap();
        assert_eq!(st, NatStatus::default());
        assert!(!st.detected);
        let st = evaluate(SPI_I, SPI_R, local(), remote(), &[], false).unwrap();
        assert!(!st.detected);
    }

    #[test]
    fn evaluate_only_one_notify_is_decode_error() {
        let (src, dst) = honest_response();
        assert!(matches!(evaluate(SPI_I, SPI_R, local(), remote(), &[&src], false), Err(Error::Decode(_))));
        assert!(matches!(evaluate(SPI_I, SPI_R, local(), remote(), &[&dst], true), Err(Error::Decode(_))));
    }

    #[test]
    fn evaluate_two_destinations_is_decode_error() {
        let (src, dst) = honest_response();
        assert!(matches!(evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &dst, &dst], false), Err(Error::Decode(_))));
    }

    #[test]
    fn evaluate_bad_hash_length_is_decode_error() {
        let (src, _) = honest_response();
        let short = n(N_NAT_DETECTION_DESTINATION_IP, vec![1; 19]);
        assert!(matches!(evaluate(SPI_I, SPI_R, local(), remote(), &[&src, &short], false), Err(Error::Decode(_))));
        let (_, dst) = honest_response();
        let long = n(N_NAT_DETECTION_SOURCE_IP, vec![1; 21]);
        assert!(matches!(evaluate(SPI_I, SPI_R, local(), remote(), &[&long, &dst], false), Err(Error::Decode(_))));
    }

    #[test]
    fn evaluate_ipv6_addresses() {
        let l6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 1234);
        let r6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 500);
        let src = n(N_NAT_DETECTION_SOURCE_IP, nat_detection_hash(SPI_I, SPI_R, r6.ip(), 500).to_vec());
        let dst = n(N_NAT_DETECTION_DESTINATION_IP, nat_detection_hash(SPI_I, SPI_R, l6.ip(), 1234).to_vec());
        let st = evaluate(SPI_I, SPI_R, l6, r6, &[&src, &dst], false).unwrap();
        assert!(!st.detected);
    }
}
