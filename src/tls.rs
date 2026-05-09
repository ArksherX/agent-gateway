use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow, ensure};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError, ServerConfig,
    SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
pub use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

use crate::config::ServerConfig as AppServerConfig;

/// Build the rustls server config used by the gateway listener.
///
/// # Errors
///
/// Returns an error if certificates or private keys cannot be read, parsed, or
/// accepted by rustls.
pub fn build_server_config(config: &AppServerConfig) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_chain = load_cert_chain(&config.tls_cert_path)
        .with_context(|| format!("loading TLS cert from {}", config.tls_cert_path.display()))?;
    let private_key = load_private_key(&config.tls_key_path)
        .with_context(|| format!("loading TLS key from {}", config.tls_key_path.display()))?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(db_rooted_client_cert_verifier())
        .with_single_cert(cert_chain, private_key)
        .context("building rustls ServerConfig")?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(server_config))
}

#[must_use]
pub fn db_rooted_client_cert_verifier() -> Arc<dyn ClientCertVerifier> {
    Arc::new(DbRootedClientCertVerifier::new())
}

#[derive(Debug)]
struct DbRootedClientCertVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
    root_hint_subjects: Vec<DistinguishedName>,
}

impl DbRootedClientCertVerifier {
    fn new() -> Self {
        Self {
            supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
            root_hint_subjects: Vec::new(),
        }
    }
}

impl ClientCertVerifier for DbRootedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // The database permission row, not certificate validity metadata,
        // defines whether this subject key is currently authorized.
        parse_certificate(end_entity)?;
        for intermediate in intermediates {
            parse_certificate(intermediate)?;
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn parse_certificate(cert: &CertificateDer<'_>) -> Result<(), RustlsError> {
    match X509Certificate::from_der(cert.as_ref()) {
        Ok(([], _)) => Ok(()),
        _ => Err(RustlsError::InvalidCertificate(
            CertificateError::BadEncoding,
        )),
    }
}

fn load_cert_chain(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "no certificates in {}", path.display());
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("no private key in {}", path.display()))
}
