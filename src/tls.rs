use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow, ensure};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
pub use tokio_rustls::TlsAcceptor;

use crate::config::ServerConfig as AppServerConfig;

pub fn build_server_config(config: &AppServerConfig) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_chain = load_cert_chain(&config.tls_cert_path)
        .with_context(|| format!("loading TLS cert from {}", config.tls_cert_path.display()))?;
    let private_key = load_private_key(&config.tls_key_path)
        .with_context(|| format!("loading TLS key from {}", config.tls_key_path.display()))?;
    let client_ca_certs = load_cert_chain(&config.client_ca_path)
        .with_context(|| format!("loading client CA from {}", config.client_ca_path.display()))?;

    let mut client_ca_store = RootCertStore::empty();
    let (added, ignored) = client_ca_store.add_parsable_certificates(client_ca_certs);
    ensure!(
        ignored == 0,
        "unparseable certificates in {}",
        config.client_ca_path.display()
    );
    ensure!(
        added > 0,
        "no trust anchors in {}",
        config.client_ca_path.display()
    );

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_ca_store))
        .build()
        .context("building WebPkiClientVerifier")?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("building rustls ServerConfig")?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(server_config))
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
