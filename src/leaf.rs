use anyhow::{Context, Result};
use rcgen::{CertificateParams, DnType, KeyPair};

use crate::ca::Ca;
use crate::names::classify_san;

pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Issues a leaf certificate for `names` (hostnames and/or IPs), signed by
/// `ca`. This is the certificate a local dev server actually presents —
/// the CA itself is never deployed anywhere, only trusted by whoever ran
/// `localcert install`.
pub fn issue_leaf(ca: &Ca, names: &[String]) -> Result<Leaf> {
    anyhow::ensure!(
        !names.is_empty(),
        "need at least one hostname or IP to issue a certificate for"
    );

    let sans = names.iter().map(|n| classify_san(n)).collect::<Vec<_>>();
    let mut params =
        CertificateParams::new(Vec::<String>::new()).context("building leaf cert params")?;
    params.subject_alt_names = sans;
    params
        .distinguished_name
        .push(DnType::CommonName, names[0].clone());
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * 2);

    let key_pair = KeyPair::generate().context("generating leaf key pair")?;
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .context("signing leaf certificate with the local CA")?;

    Ok(Leaf {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::generate_ca;

    #[test]
    fn rejects_empty_names() {
        let ca = generate_ca().unwrap();
        assert!(issue_leaf(&ca, &[]).is_err());
    }

    #[test]
    fn issues_a_cert_containing_all_requested_sans() {
        let ca = generate_ca().unwrap();
        let names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let leaf = issue_leaf(&ca, &names).unwrap();
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.key_pem.contains("PRIVATE KEY"));
    }
}
