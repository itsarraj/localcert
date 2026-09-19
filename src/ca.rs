use anyhow::{Context, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair};

pub struct Ca {
    pub cert_pem: String,
    pub key_pem: String,
    pub key_pair: KeyPair,
    /// The signed `Certificate` object itself — this, not `CertificateParams`,
    /// is what `signed_by` needs as the issuer when minting leaf certs.
    pub cert: Certificate,
}

/// Generates a new self-signed root CA, suitable only for local
/// development — this is exactly the thing you must never let near a real
/// public-facing service, since anyone holding the private key can mint a
/// certificate for any name it trusts.
pub fn generate_ca() -> Result<Ca> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "localcert local development CA");
    params.distinguished_name.push(
        DnType::OrganizationName,
        "localcert (do not trust in production)",
    );
    // rcgen's own default validity window is absurdly wide (1975-4096) —
    // harmless for a *private* CA no browser applies CA/Browser Forum
    // policy to, but worth setting something a human would actually
    // expect: valid from a day ago (clock-skew buffer) for 10 years.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * 10);

    let key_pair = KeyPair::generate().context("generating CA key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-signing CA certificate")?;

    Ok(Ca {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        key_pair,
        cert,
    })
}

/// Reconstructs a `Ca` from a previously-saved cert+key PEM pair (what
/// `localcert init` wrote to disk), so a later `localcert cert` invocation
/// can sign new leaf certificates without regenerating the CA. The
/// resulting `Certificate` isn't byte-identical to the original (a fresh
/// serial/validity window gets stamped in by `self_signed`), but it carries
/// the same distinguished name and the same signing key, which is all a
/// leaf certificate's issuer field actually needs to be correct.
pub fn load_ca(cert_pem: &str, key_pem: &str) -> Result<Ca> {
    let key_pair = KeyPair::from_pem(key_pem).context("parsing saved CA private key")?;
    let params =
        CertificateParams::from_ca_cert_pem(cert_pem).context("parsing saved CA certificate")?;
    let cert = params
        .self_signed(&key_pair)
        .context("reconstructing CA certificate for signing")?;
    Ok(Ca {
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        key_pair,
        cert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_pem_round_trips_through_rcgens_own_parser() {
        let ca = generate_ca().unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        let reloaded = KeyPair::from_pem(&ca.key_pem).unwrap();
        assert_eq!(reloaded.public_key_der(), ca.key_pair.public_key_der());
    }

    #[test]
    fn load_ca_reconstructs_a_usable_issuer_from_saved_pem() {
        let original = generate_ca().unwrap();
        let reloaded = load_ca(&original.cert_pem, &original.key_pem).unwrap();
        assert_eq!(
            reloaded.key_pair.public_key_der(),
            original.key_pair.public_key_der()
        );
    }
}
