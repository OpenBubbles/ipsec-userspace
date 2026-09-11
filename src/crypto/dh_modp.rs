//! Finite-field Diffie-Hellman over the IKE MODP groups (RFC 2409 §6.2 group 2,
//! RFC 3526 groups 5, 14, 15, 16), generator 2.
//!
//! The public value and the shared secret g^ir are encoded big-endian and
//! LEFT-ZERO-PADDED to the modulus length (RFC 7296 §2.14; AOSP does the same:
//! `BigIntegerUtils.bigIntegerToUnsignedByteArray(y, 256)` for the KE payload and
//! BouncyCastle's DH `generateSecret()` for g^ir). The peer value is validated to
//! lie in `[2, p-2]`. Private exponents are uniform in `[2, p-2]` from the OS RNG
//! and zeroized on drop.
//!
//! The prime hex strings below were cross-checked against OpenSSL's `bn_dh.c` /
//! `bn_const.c` tables and Miller-Rabin tested (each p and (p-1)/2) before being
//! committed; do not "tidy" them.

use crate::crypto::{DhGroup, DhKeyPair};
use crate::ike::constants::{DH_MODP_1024, DH_MODP_1536, DH_MODP_2048, DH_MODP_3072, DH_MODP_4096};
use crate::{Error, Result};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use std::sync::Arc;
use zeroize::Zeroize;

/// RFC 2409 §6.2 "Second Oakley Default Group", 1024-bit MODP (IKE group 2).
pub const MODP_1024_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
);

/// RFC 3526 §2, 1536-bit MODP (IKE group 5).
pub const MODP_1536_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
);

/// RFC 3526 §3, 2048-bit MODP (IKE group 14).
pub const MODP_2048_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
);

/// RFC 3526 §4, 3072-bit MODP (IKE group 15).
pub const MODP_3072_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

/// RFC 3526 §5, 4096-bit MODP (IKE group 16).
pub const MODP_4096_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

/// Generator shared by every MODP group we implement.
pub const MODP_GENERATOR: u32 = 2;

/// Prime hex for a supported IKE MODP group id, or `None`.
pub fn prime_hex(group_id: u16) -> Option<&'static str> {
    match group_id {
        DH_MODP_1024 => Some(MODP_1024_PRIME_HEX),
        DH_MODP_1536 => Some(MODP_1536_PRIME_HEX),
        DH_MODP_2048 => Some(MODP_2048_PRIME_HEX),
        DH_MODP_3072 => Some(MODP_3072_PRIME_HEX),
        DH_MODP_4096 => Some(MODP_4096_PRIME_HEX),
        _ => None,
    }
}

/// Every group id this module can instantiate, in IANA order.
pub const SUPPORTED_GROUPS: [u16; 5] =
    [DH_MODP_1024, DH_MODP_1536, DH_MODP_2048, DH_MODP_3072, DH_MODP_4096];

/// A MODP Diffie-Hellman group: prime `p`, generator 2, fixed wire length.
#[derive(Debug, Clone)]
pub struct ModpGroup {
    group_id: u16,
    prime: Arc<BigUint>,
    public_len: usize,
}

impl ModpGroup {
    /// Instantiate a supported group (2, 5, 14, 15, 16). `None` for any other id.
    pub fn new(group_id: u16) -> Option<Self> {
        let hex = prime_hex(group_id)?;
        let prime = BigUint::parse_bytes(hex.as_bytes(), 16)?;
        // Every RFC prime is a whole number of bytes long (hex length is even).
        let public_len = hex.len() / 2;
        Some(ModpGroup { group_id, prime: Arc::new(prime), public_len })
    }

    /// RFC 3526 group 14 (2048-bit), the group the ePDG profile negotiates.
    pub fn group14() -> Self {
        ModpGroup::new(DH_MODP_2048).unwrap_or_else(|| unreachable!("group 14 prime is constant"))
    }

    /// The group prime.
    pub fn prime(&self) -> &BigUint {
        &self.prime
    }

    fn generator(&self) -> BigUint {
        BigUint::from(MODP_GENERATOR)
    }

    /// `x` as big-endian bytes, left-zero-padded to `public_len`.
    fn encode_fixed(&self, x: &BigUint) -> Result<Vec<u8>> {
        let raw = x.to_bytes_be();
        if raw.len() > self.public_len {
            return Err(Error::crypto(format!(
                "MODP group {}: value is {} bytes, longer than the modulus ({})",
                self.group_id,
                raw.len(),
                self.public_len
            )));
        }
        let mut out = vec![0u8; self.public_len - raw.len()];
        out.extend_from_slice(&raw);
        Ok(out)
    }

    /// Parse and validate a peer public value: exact modulus length, `2 <= y <= p-2`.
    fn parse_peer(&self, peer_public: &[u8]) -> Result<BigUint> {
        if peer_public.len() != self.public_len {
            return Err(Error::decode(format!(
                "MODP group {}: peer public value is {} bytes, expected {}",
                self.group_id,
                peer_public.len(),
                self.public_len
            )));
        }
        let y = BigUint::from_bytes_be(peer_public);
        let two = BigUint::from(2u32);
        let p_minus_2 = &*self.prime - &two;
        if y < two || y > p_minus_2 {
            return Err(Error::crypto(format!(
                "MODP group {}: peer public value out of range [2, p-2]",
                self.group_id
            )));
        }
        Ok(y)
    }
}

impl DhGroup for ModpGroup {
    fn group_id(&self) -> u16 {
        self.group_id
    }

    fn public_len(&self) -> usize {
        self.public_len
    }

    fn generate(&self) -> Result<Box<dyn DhKeyPair>> {
        let two = BigUint::from(2u32);
        let p_minus_1 = &*self.prime - BigUint::one();
        // gen_biguint_range is [lbound, ubound) => uniform in [2, p-2].
        let mut rng = rand::rngs::OsRng;
        let mut x = rng.gen_biguint_range(&two, &p_minus_1);
        let y = self.generator().modpow(&x, &self.prime);
        let public = self.encode_fixed(&y)?;
        let private = ZeroizingExponent(x.to_bytes_be());
        // Best-effort: drop the BigUint's limbs after copying out (BigUint has no Zeroize impl).
        x.set_zero();
        log::debug!(
            "MODP group {} keypair generated: public={}",
            self.group_id,
            hex::encode(&public)
        );
        Ok(Box::new(ModpKeyPair { group: self.clone(), private, public }))
    }
}

/// Private exponent bytes, zeroized on drop.
struct ZeroizingExponent(Vec<u8>);

impl Drop for ZeroizingExponent {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An ephemeral MODP key pair. The private exponent is kept as zeroizing bytes.
pub struct ModpKeyPair {
    group: ModpGroup,
    private: ZeroizingExponent,
    public: Vec<u8>,
}

impl std::fmt::Debug for ModpKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModpKeyPair")
            .field("group_id", &self.group.group_id)
            .field("public_len", &self.public.len())
            .finish_non_exhaustive()
    }
}

impl DhKeyPair for ModpKeyPair {
    fn public_value(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>> {
        let y = self.group.parse_peer(peer_public)?;
        let mut x = BigUint::from_bytes_be(&self.private.0);
        let mut s = y.modpow(&x, &self.group.prime);
        x.set_zero();
        let out = self.group.encode_fixed(&s);
        s.set_zero();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p14() -> BigUint {
        BigUint::parse_bytes(MODP_2048_PRIME_HEX.as_bytes(), 16).unwrap()
    }

    #[test]
    fn group14_prime_shape() {
        let g = ModpGroup::group14();
        assert_eq!(g.group_id(), 14);
        assert_eq!(g.public_len(), 256);
        assert_eq!(MODP_2048_PRIME_HEX.len(), 512);
        let p = g.prime();
        assert_eq!(p.bits(), 2048);
        let bytes = p.to_bytes_be();
        assert_eq!(bytes.len(), 256);
        assert_eq!(&bytes[..8], &[0xFF; 8]);
        assert_eq!(&bytes[248..], &[0xFF; 8]);
        // RFC 3526 §3 second word.
        assert_eq!(&bytes[8..12], &[0xC9, 0x0F, 0xDA, 0xA2]);
        // p is odd (a prime); p-1 is even; the top 64 bits and bottom 64 bits are all ones.
        assert_eq!(p % BigUint::from(2u32), BigUint::one());
    }

    #[test]
    fn all_groups_shape() {
        let expect = [(2u16, 1024u64), (5, 1536), (14, 2048), (15, 3072), (16, 4096)];
        for (id, bits) in expect {
            let g = ModpGroup::new(id).expect("supported group");
            assert_eq!(g.group_id(), id);
            assert_eq!(g.prime().bits(), bits);
            assert_eq!(g.public_len(), (bits / 8) as usize);
            let bytes = g.prime().to_bytes_be();
            assert_eq!(&bytes[..8], &[0xFF; 8], "group {id} head");
            assert_eq!(&bytes[bytes.len() - 8..], &[0xFF; 8], "group {id} tail");
            // All RFC 2409/3526 primes share the same leading 8 words (they are all
            // 2^n - 2^(n-64) - 1 + 2^64 * { floor(2^(n-130) * pi) + k }).
            assert_eq!(&bytes[8..16], &[0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34]);
        }
        for id in [0u16, 1, 3, 4, 13, 17, 18, 19, 20, 31] {
            assert!(ModpGroup::new(id).is_none(), "group {id} must be unsupported");
        }
        assert_eq!(SUPPORTED_GROUPS, [2, 5, 14, 15, 16]);
    }

    #[test]
    fn primes_are_probably_prime_small_factor_screen() {
        // Cheap offline sanity screen: no small prime factors, and p ≡ 3 (mod 4)
        // (true for every safe prime > 5, which all the IKE MODP primes are).
        let small: [u32; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
        for id in SUPPORTED_GROUPS {
            let p = ModpGroup::new(id).unwrap().prime().clone();
            for q in small {
                assert!(!(&p % BigUint::from(q)).is_zero(), "group {id} divisible by {q}");
            }
            assert_eq!(&p % BigUint::from(4u32), BigUint::from(3u32), "group {id} mod 4");
            // Fermat witness with base 2: 2^(p-1) ≡ 1 (mod p).
            let e = &p - BigUint::one();
            assert_eq!(BigUint::from(2u32).modpow(&e, &p), BigUint::one(), "group {id} Fermat");
        }
    }

    #[test]
    fn kat_two_to_the_one_mod_p() {
        let p = p14();
        let two = BigUint::from(2u32);
        assert_eq!(two.modpow(&BigUint::one(), &p), two);
        // Encoded through the same path as a public value: 255 zero bytes then 0x02.
        let g = ModpGroup::group14();
        let enc = g.encode_fixed(&two).unwrap();
        assert_eq!(enc.len(), 256);
        assert!(enc[..255].iter().all(|&b| b == 0));
        assert_eq!(enc[255], 2);
    }

    #[test]
    fn two_keypairs_agree() {
        let g = ModpGroup::group14();
        let a = g.generate().unwrap();
        let b = g.generate().unwrap();
        let pa = a.public_value();
        let pb = b.public_value();
        assert_eq!(pa.len(), 256);
        assert_eq!(pb.len(), 256);
        assert_ne!(pa, pb);
        let sa = a.shared_secret(&pb).unwrap();
        let sb = b.shared_secret(&pa).unwrap();
        assert_eq!(sa.len(), 256);
        assert_eq!(sa, sb);
        assert!(sa.iter().any(|&x| x != 0));
    }

    #[test]
    fn small_groups_round_trip() {
        for id in [2u16, 5] {
            let g = ModpGroup::new(id).unwrap();
            let a = g.generate().unwrap();
            let b = g.generate().unwrap();
            assert_eq!(a.public_value().len(), g.public_len());
            assert_eq!(
                a.shared_secret(&b.public_value()).unwrap(),
                b.shared_secret(&a.public_value()).unwrap()
            );
        }
    }

    #[test]
    fn public_value_is_consistent_with_private() {
        // y = 2^x mod p recomputed from the stored private exponent.
        let g = ModpGroup::group14();
        let kp = g.generate().unwrap();
        let pubv = kp.public_value();
        // Down-cast via the concrete type to read the exponent.
        let raw: Box<dyn DhKeyPair> = kp;
        // Re-generate independently: peer with known exponent 3 -> y=8; secret = pub^3.
        let three = BigUint::from(3u32);
        let peer_pub = g.encode_fixed(&BigUint::from(8u32)).unwrap();
        let secret = raw.shared_secret(&peer_pub).unwrap();
        let expected = BigUint::from_bytes_be(&pubv).modpow(&three, g.prime());
        assert_eq!(secret, g.encode_fixed(&expected).unwrap());
    }

    #[test]
    fn peer_validation() {
        let g = ModpGroup::group14();
        let kp = g.generate().unwrap();
        let p = p14();

        // y = 0 and y = 1 rejected.
        let zero = vec![0u8; 256];
        assert!(matches!(kp.shared_secret(&zero), Err(Error::Crypto(_))));
        let mut one = vec![0u8; 256];
        one[255] = 1;
        assert!(matches!(kp.shared_secret(&one), Err(Error::Crypto(_))));

        // y = p-1 and y = p rejected; y = p-2 accepted (boundary).
        let pm1 = g.encode_fixed(&(&p - BigUint::one())).unwrap();
        assert!(matches!(kp.shared_secret(&pm1), Err(Error::Crypto(_))));
        let pp = g.encode_fixed(&p).unwrap();
        assert!(matches!(kp.shared_secret(&pp), Err(Error::Crypto(_))));
        let pm2 = g.encode_fixed(&(&p - BigUint::from(2u32))).unwrap();
        assert!(kp.shared_secret(&pm2).is_ok());
        // y = 2 accepted (boundary) and equals 2^x = our own public value.
        let mut two = vec![0u8; 256];
        two[255] = 2;
        assert_eq!(kp.shared_secret(&two).unwrap(), kp.public_value());

        // All-ones (> p) rejected, wrong lengths rejected as Decode.
        let ones = vec![0xFFu8; 256];
        assert!(matches!(kp.shared_secret(&ones), Err(Error::Crypto(_))));
        assert!(matches!(kp.shared_secret(&[2u8]), Err(Error::Decode(_))));
        assert!(matches!(kp.shared_secret(&vec![0u8; 255]), Err(Error::Decode(_))));
        assert!(matches!(kp.shared_secret(&vec![0u8; 257]), Err(Error::Decode(_))));
    }

    #[test]
    fn encode_fixed_rejects_oversize() {
        let g = ModpGroup::new(2).unwrap();
        let big = BigUint::one() << 1024u32;
        assert!(matches!(g.encode_fixed(&big), Err(Error::Crypto(_))));
    }

    #[test]
    fn as_trait_object() {
        let g: Arc<dyn DhGroup> = Arc::new(ModpGroup::group14());
        assert_eq!(g.group_id(), DH_MODP_2048);
        assert_eq!(g.public_len(), 256);
        let kp = g.generate().unwrap();
        assert_eq!(kp.public_value().len(), 256);
        assert!(format!("{:?}", ModpGroup::group14()).contains("14"));
    }
}
