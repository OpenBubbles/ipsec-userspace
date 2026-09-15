//! PEM ingestion: convert PEM text to DER once, at the boundary where PEM arrives.
//!
//! The configuration ([`crate::config::EapTlsCredentials`]) and the EAP-TLS engine
//! ([`crate::eap::tls::EapTlsConfig`]) carry certificates and keys as DER byte arrays only.
//! PEM shows up in exactly two places: test fixtures (`tests/fixtures/client.{crt,key}`) and
//! the credentials a carrier's provisioning server returns over the network. Both are
//! converted here and never travel further as PEM.
//!
//! Nothing here detects a format. Every function takes PEM and returns DER; DER (or anything
//! else) as input is an error, not a fallback.

use log::debug;
use openssl::pkey::PKey;
use openssl::x509::X509;

use crate::error::{Error, Result};

/// Every certificate in `pem`, in order, each as one DER `Certificate`.
pub fn certificates_pem_to_der(pem: &str) -> Result<Vec<Vec<u8>>> {
    let certs = X509::stack_from_pem(pem.as_bytes())
        .map_err(|e| Error::config(format!("invalid certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(Error::config("no certificate found in PEM"));
    }
    certs
        .iter()
        .map(|c| c.to_der().map_err(|e| Error::config(format!("certificate DER encoding failed: {e}"))))
        .collect()
}

/// The first certificate in `pem` as DER: the leaf, when the PEM also carries its chain.
/// EAP-TLS sends the leaf only (as AOSP does), so the rest is dropped.
pub fn certificate_pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut certs = certificates_pem_to_der(pem)?;
    if certs.len() > 1 {
        debug!("certificate PEM holds {} certificates; keeping the first (leaf)", certs.len());
    }
    Ok(certs.swap_remove(0))
}

/// A private key in PEM — PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) or SEC1
/// (`EC PRIVATE KEY`), as its PEM label states — re-encoded as unencrypted PKCS#8 DER
/// (`PrivateKeyInfo`), the one key encoding the configuration accepts.
pub fn private_key_pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>> {
    let key = PKey::private_key_from_pem(pem.as_bytes())
        .map_err(|e| Error::config(format!("invalid private key PEM: {e}")))?;
    key.private_key_to_pkcs8()
        .map_err(|e| Error::config(format!("PKCS#8 DER encoding failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::Private;

    const CERT_PEM: &str = include_str!("../tests/fixtures/client.crt");
    const KEY_PEM: &str = include_str!("../tests/fixtures/client.key");

    #[test]
    fn certificate_pem_becomes_its_der_encoding() {
        let der = certificate_pem_to_der(CERT_PEM).unwrap();
        assert_eq!(der, X509::from_pem(CERT_PEM.as_bytes()).unwrap().to_der().unwrap());
        assert_eq!(der[0], 0x30, "DER Certificate starts with a SEQUENCE tag");
        // Round trip: the DER parses back to the same certificate.
        let back = X509::from_der(&der).unwrap();
        assert_eq!(back.to_pem().unwrap(), X509::from_pem(CERT_PEM.as_bytes()).unwrap().to_pem().unwrap());
    }

    #[test]
    fn chain_pem_yields_every_certificate_and_the_leaf_first() {
        let chain = format!("{CERT_PEM}\n{CERT_PEM}");
        let all = certificates_pem_to_der(&chain).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(certificate_pem_to_der(&chain).unwrap(), all[0]);
        assert_eq!(all[0], certificate_pem_to_der(CERT_PEM).unwrap());
    }

    #[test]
    fn private_key_pem_becomes_pkcs8_der_whatever_its_pem_label() {
        let pkcs8_der = private_key_pem_to_pkcs8_der(KEY_PEM).unwrap();
        let key: PKey<Private> = PKey::private_key_from_pkcs8(&pkcs8_der).unwrap();
        let original = PKey::private_key_from_pem(KEY_PEM.as_bytes()).unwrap();
        assert!(key.public_eq(&original));

        // The same key as PKCS#1 ("BEGIN RSA PRIVATE KEY") converts to the identical PKCS#8 DER.
        let pkcs1_pem = String::from_utf8(original.rsa().unwrap().private_key_to_pem().unwrap()).unwrap();
        assert!(pkcs1_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert_eq!(private_key_pem_to_pkcs8_der(&pkcs1_pem).unwrap(), pkcs8_der);
    }

    #[test]
    fn non_pem_input_is_an_error_never_a_fallback() {
        assert!(matches!(certificates_pem_to_der(""), Err(Error::Config(_))));
        assert!(matches!(certificates_pem_to_der("not a certificate"), Err(Error::Config(_))));
        assert!(matches!(private_key_pem_to_pkcs8_der(""), Err(Error::Config(_))));
        assert!(matches!(private_key_pem_to_pkcs8_der("garbage"), Err(Error::Config(_))));
        // Base64 DER without the PEM boundaries is not PEM.
        let der = certificate_pem_to_der(CERT_PEM).unwrap();
        let bare_base64 = openssl::base64::encode_block(&der);
        assert!(matches!(certificates_pem_to_der(&bare_base64), Err(Error::Config(_))));
        // A certificate is not a private key and vice versa.
        assert!(matches!(private_key_pem_to_pkcs8_der(CERT_PEM), Err(Error::Config(_))));
        assert!(matches!(certificates_pem_to_der(KEY_PEM), Err(Error::Config(_))));
    }
}
