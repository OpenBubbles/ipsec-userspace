//! `ENCR_AES_CBC` (IKEv2 transform id 12) for 128/192/256-bit keys, RFC 3602.
//!
//! Plain CBC with **no padding**: the IKEv2 SK payload and ESP both carry their
//! own trailer (padding + pad length), so the caller always hands us a
//! block-multiple buffer. Backed by the `aes` + `cbc` crates.

use crate::crypto::Cipher;
use crate::ike::constants::ENCR_AES_CBC;
use crate::{Error, Result};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

/// AES block size and CBC IV length, in bytes.
pub const AES_BLOCK_LEN: usize = 16;

/// AES in CBC mode with a key of `key_bits` bits (128, 192 or 256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesCbc {
    pub key_bits: u16,
}

impl AesCbc {
    /// Construct for a key size in bits. Returns `None` for anything but 128/192/256.
    pub const fn new(key_bits: u16) -> Option<Self> {
        match key_bits {
            128 | 192 | 256 => Some(AesCbc { key_bits }),
            _ => None,
        }
    }

    pub const fn aes128() -> Self {
        AesCbc { key_bits: 128 }
    }

    pub const fn aes192() -> Self {
        AesCbc { key_bits: 192 }
    }

    pub const fn aes256() -> Self {
        AesCbc { key_bits: 256 }
    }

    fn check(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<()> {
        if key.len() != self.key_len() {
            return Err(Error::crypto(format!(
                "AES-CBC-{}: key length {} != {}",
                self.key_bits,
                key.len(),
                self.key_len()
            )));
        }
        if iv.len() != AES_BLOCK_LEN {
            return Err(Error::crypto(format!(
                "AES-CBC: iv length {} != {AES_BLOCK_LEN}",
                iv.len()
            )));
        }
        if !data.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(Error::crypto(format!(
                "AES-CBC: data length {} is not a multiple of {AES_BLOCK_LEN}",
                data.len()
            )));
        }
        Ok(())
    }
}

macro_rules! run_cbc {
    ($self:ident, $key:ident, $iv:ident, $data:ident, $encrypt:expr) => {{
        match $self.key_bits {
            128 => cbc_apply::<aes::Aes128>($key, $iv, $data, $encrypt),
            192 => cbc_apply::<aes::Aes192>($key, $iv, $data, $encrypt),
            256 => cbc_apply::<aes::Aes256>($key, $iv, $data, $encrypt),
            other => Err(Error::Unsupported(format!("AES-CBC key size {other} bits"))),
        }
    }};
}

/// Run CBC over `data` in place with the given AES core.
fn cbc_apply<C>(key: &[u8], iv: &[u8], data: &mut [u8], encrypt: bool) -> Result<()>
where
    C: cipher::BlockCipher + cipher::BlockEncrypt + cipher::BlockDecrypt + cipher::KeyInit,
{
    let len = data.len();
    if encrypt {
        let enc = cbc::Encryptor::<C>::new_from_slices(key, iv)
            .map_err(|e| Error::crypto(format!("AES-CBC init: {e}")))?;
        enc.encrypt_padded_mut::<NoPadding>(data, len)
            .map_err(|e| Error::crypto(format!("AES-CBC encrypt: {e}")))?;
    } else {
        let dec = cbc::Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|e| Error::crypto(format!("AES-CBC init: {e}")))?;
        dec.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|e| Error::crypto(format!("AES-CBC decrypt: {e}")))?;
    }
    Ok(())
}

impl Cipher for AesCbc {
    fn transform_id(&self) -> u16 {
        ENCR_AES_CBC
    }

    fn key_len(&self) -> usize {
        usize::from(self.key_bits) / 8
    }

    fn block_len(&self) -> usize {
        AES_BLOCK_LEN
    }

    fn iv_len(&self) -> usize {
        AES_BLOCK_LEN
    }

    fn key_len_attr_bits(&self) -> Option<u16> {
        Some(self.key_bits)
    }

    fn encrypt(&self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()> {
        self.check(key, iv, data)?;
        run_cbc!(self, key, iv, data, true)
    }

    fn decrypt(&self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()> {
        self.check(key, iv, data)?;
        run_cbc!(self, key, iv, data, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    // NIST SP 800-38A, F.2.5 CBC-AES256.Encrypt (all four blocks).
    const KEY256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";
    const PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                      ae2d8a571e03ac9c9eb76fac45af8e51\
                      30c81c46a35ce411e5fbc1191a0a52ef\
                      f69f2445df4f9b17ad2b417be66c3710";
    const CT256: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                         9cfc4e967edb808d679f777bc6702c7d\
                         39f23369a9d9bacfa530e26304231461\
                         b2eb05e2c39be9fcda6c19078c6a9d1b";

    #[test]
    fn aes256_cbc_kat_first_block() {
        let c = AesCbc::aes256();
        let mut data = h("6bc1bee22e409f96e93d7e117393172a");
        c.encrypt(&h(KEY256), &h(IV), &mut data).unwrap();
        assert_eq!(hex::encode(&data), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        c.decrypt(&h(KEY256), &h(IV), &mut data).unwrap();
        assert_eq!(hex::encode(&data), "6bc1bee22e409f96e93d7e117393172a");
    }

    #[test]
    fn aes256_cbc_kat_four_blocks() {
        let c = AesCbc::aes256();
        let mut data = h(PT);
        c.encrypt(&h(KEY256), &h(IV), &mut data).unwrap();
        assert_eq!(hex::encode(&data), CT256);
        c.decrypt(&h(KEY256), &h(IV), &mut data).unwrap();
        assert_eq!(hex::encode(&data), PT);
    }

    #[test]
    fn aes128_cbc_kat() {
        // NIST SP 800-38A F.2.1 CBC-AES128.Encrypt, first block.
        let c = AesCbc::aes128();
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let mut data = h("6bc1bee22e409f96e93d7e117393172a");
        c.encrypt(&key, &h(IV), &mut data).unwrap();
        assert_eq!(hex::encode(&data), "7649abac8119b246cee98e9b12e9197d");
    }

    #[test]
    fn aes192_cbc_kat() {
        // NIST SP 800-38A F.2.3 CBC-AES192.Encrypt, first block.
        let c = AesCbc::aes192();
        let key = h("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        let mut data = h("6bc1bee22e409f96e93d7e117393172a");
        c.encrypt(&key, &h(IV), &mut data).unwrap();
        assert_eq!(hex::encode(&data), "4f021db243bc633d7178183a9fa071e8");
    }

    #[test]
    fn trait_metadata() {
        let c = AesCbc::aes256();
        assert_eq!(c.transform_id(), ENCR_AES_CBC);
        assert_eq!(c.key_len(), 32);
        assert_eq!(c.block_len(), 16);
        assert_eq!(c.iv_len(), 16);
        assert_eq!(c.key_len_attr_bits(), Some(256));
        assert_eq!(AesCbc::aes128().key_len(), 16);
        assert_eq!(AesCbc::aes192().key_len(), 24);
        assert!(AesCbc::new(64).is_none());
        assert_eq!(AesCbc::new(192), Some(AesCbc::aes192()));
    }

    #[test]
    fn rejects_bad_lengths() {
        let c = AesCbc::aes256();
        let key = h(KEY256);
        let iv = h(IV);
        let mut ok = vec![0u8; 32];
        assert!(matches!(c.encrypt(&key[..16], &iv, &mut ok), Err(Error::Crypto(_))));
        assert!(matches!(c.encrypt(&key, &iv[..8], &mut ok), Err(Error::Crypto(_))));
        let mut odd = vec![0u8; 17];
        assert!(matches!(c.encrypt(&key, &iv, &mut odd), Err(Error::Crypto(_))));
        assert!(matches!(c.decrypt(&key, &iv, &mut odd), Err(Error::Crypto(_))));
        // Empty input is a (trivial) block multiple.
        let mut empty: Vec<u8> = Vec::new();
        c.encrypt(&key, &iv, &mut empty).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn random_round_trip() {
        let c = AesCbc::aes256();
        let key = crate::crypto::random_bytes(32);
        let iv = crate::crypto::random_bytes(16);
        let pt = crate::crypto::random_bytes(16 * 9);
        let mut buf = pt.clone();
        c.encrypt(&key, &iv, &mut buf).unwrap();
        assert_ne!(buf, pt);
        c.decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, pt);
    }
}
