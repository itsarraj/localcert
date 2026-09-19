use std::net::IpAddr;

use rcgen::SanType;

/// Classifies a user-supplied name as an IP SAN or a DNS SAN — `rcgen`
/// itself needs this distinction made explicitly rather than inferred from
/// the string, so this is the one thing worth pulling out as its own pure,
/// tested function.
pub fn classify_san(name: &str) -> SanType {
    match name.parse::<IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(name.try_into().expect("valid DNS name")),
    }
}

/// The output filename stem `mkcert` itself uses: the first name given, or
/// `name+N` when there's more than one (e.g. `localhost+2.pem` for
/// `localhost 127.0.0.1 ::1`). Matching this convention means anyone with
/// `mkcert` muscle memory already knows what files to expect.
pub fn output_stem(names: &[String]) -> String {
    match names.len() {
        0 => "cert".to_string(),
        1 => names[0].clone(),
        n => format!("{}+{}", names[0], n - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ipv4_and_ipv6_as_ip_sans() {
        assert!(matches!(classify_san("127.0.0.1"), SanType::IpAddress(_)));
        assert!(matches!(classify_san("::1"), SanType::IpAddress(_)));
    }

    #[test]
    fn classifies_hostnames_as_dns_sans() {
        assert!(matches!(classify_san("localhost"), SanType::DnsName(_)));
        assert!(matches!(classify_san("myapp.test"), SanType::DnsName(_)));
    }

    #[test]
    fn output_stem_matches_mkcert_convention() {
        assert_eq!(output_stem(&["localhost".to_string()]), "localhost");
        assert_eq!(
            output_stem(&[
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string()
            ]),
            "localhost+2"
        );
    }
}
