//! The test that actually matters for a "generates working TLS certs"
//! tool: a real `rustls` server presenting the generated leaf certificate,
//! and a real `rustls` client doing a genuine TLS handshake and trust-chain
//! validation against the generated CA — over a real loopback TCP socket,
//! not mocked. Everything here goes through the same PEM strings
//! `localcert cert` writes to disk, parsed back with `rustls-pemfile`
//! exactly as any real consumer (a dev web server) would.

use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use localcert::{ca, leaf};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn parse_cert_chain(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .expect("parsing cert PEM")
}

fn parse_key(pem: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(pem.as_bytes()))
        .expect("parsing key PEM")
        .expect("a private key must be present")
}

fn server_config(leaf: &leaf::Leaf) -> Arc<ServerConfig> {
    let chain = parse_cert_chain(&leaf.cert_pem);
    let key = parse_key(&leaf.key_pem);
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("building server config with the generated leaf cert"),
    )
}

fn client_config_trusting(ca_cert_pem: &str) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in parse_cert_chain(ca_cert_pem) {
        roots.add(cert).expect("adding CA cert to root store");
    }
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Runs one TLS handshake end to end: server accepts, sends a greeting;
/// client connects, verifies the chain, reads the greeting. Returns
/// `Ok(greeting)` on a successful handshake, `Err` if the client's trust
/// validation (or anything else) fails.
fn run_handshake(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    sni: &str,
) -> anyhow::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let server_thread = std::thread::spawn(move || -> anyhow::Result<()> {
        let (mut sock, _) = listener.accept()?;
        let mut conn = rustls::ServerConnection::new(server_cfg)?;
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(b"hello from the generated leaf cert\n")?;
        Ok(())
    });

    let mut sock = std::net::TcpStream::connect(addr)?;
    let server_name = ServerName::try_from(sni.to_string())?;
    let mut conn = rustls::ClientConnection::new(client_cfg, server_name)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let mut buf = [0u8; 256];
    let n = tls.read(&mut buf)?;
    server_thread.join().expect("server thread panicked")?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[test]
fn client_trusting_the_generated_ca_completes_the_handshake() {
    install_provider();
    let generated_ca = ca::generate_ca().unwrap();
    let issued = leaf::issue_leaf(
        &generated_ca,
        &["localhost".to_string(), "127.0.0.1".to_string()],
    )
    .unwrap();

    let result = run_handshake(
        server_config(&issued),
        client_config_trusting(&generated_ca.cert_pem),
        "localhost",
    );

    match result {
        Ok(greeting) => assert!(greeting.contains("hello from the generated leaf cert")),
        Err(e) => panic!("expected a successful handshake against a trusted CA, got: {e}"),
    }
}

#[test]
fn client_trusting_a_different_unrelated_ca_rejects_the_handshake() {
    install_provider();
    let real_ca = ca::generate_ca().unwrap();
    let issued = leaf::issue_leaf(&real_ca, &["localhost".to_string()]).unwrap();

    // A second, entirely unrelated CA — this is the negative control: the
    // leaf cert was never signed by this one, so trust must fail.
    let other_ca = ca::generate_ca().unwrap();

    let result = run_handshake(
        server_config(&issued),
        client_config_trusting(&other_ca.cert_pem),
        "localhost",
    );

    assert!(
        result.is_err(),
        "a client that doesn't trust the real CA must not complete the handshake"
    );
}

#[test]
fn hostname_not_in_the_certs_sans_is_rejected() {
    install_provider();
    let generated_ca = ca::generate_ca().unwrap();
    // Issued only for "localhost", not "impostor.test".
    let issued = leaf::issue_leaf(&generated_ca, &["localhost".to_string()]).unwrap();

    let result = run_handshake(
        server_config(&issued),
        client_config_trusting(&generated_ca.cert_pem),
        "impostor.test",
    );

    assert!(
        result.is_err(),
        "a hostname outside the cert's SANs must fail verification even with the right CA trusted"
    );
}
