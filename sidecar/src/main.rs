mod bridge;
mod identity;

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, ensure};
use clap::Parser;
use rustls::ClientConfig;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::bridge::GatewayConnector;
use crate::identity::{TpmClientIdentity, parse_tpm_key_handle};

const DEFAULT_CLIENT_IDENTITY_EXT_OID: &str = "1.3.6.1.4.1.57264.1.1";

#[derive(Parser)]
#[command(
    name = "agent_gateway_sidecar",
    about = "Local sidecar that bridges plain HTTP CONNECT to an mTLS h2 gateway"
)]
struct Cli {
    /// Local listen address
    #[arg(long, default_value = "127.0.0.1:3128")]
    listen: SocketAddr,

    /// Gateway address (host:port)
    #[arg(long)]
    gateway: String,

    /// Path to PEM client certificate (presented to the gateway)
    #[arg(long)]
    client_cert: PathBuf,

    /// Client certificate extension OID that contains the source identity
    #[arg(long, default_value = DEFAULT_CLIENT_IDENTITY_EXT_OID)]
    client_identity_ext_oid: String,

    /// TCTI string for the simulated TPM
    #[arg(long, default_value = "swtpm:host=127.0.0.1,port=2321")]
    tpm_tcti: String,

    /// Persistent TPM handle for the client signing key
    #[arg(long)]
    tpm_key_handle: String,

    /// Path to PEM CA certificate that signed the gateway's server cert
    #[arg(long)]
    ca_cert: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    if !cli.listen.ip().is_loopback() {
        warn!(
            listen = %cli.listen,
            "listening on a non-loopback address — the sidecar holds a privileged mTLS identity"
        );
    }

    let tpm_key_handle = parse_tpm_key_handle(&cli.tpm_key_handle)?;
    let identity = TpmClientIdentity::load(
        &cli.tpm_tcti,
        tpm_key_handle,
        &cli.client_cert,
        &cli.client_identity_ext_oid,
    )?;
    let source_identity = identity.source_identity().to_owned();
    let tls_config = build_client_config(identity, &cli.ca_cert)?;

    let (gateway_host, gateway_port) = parse_gateway_addr(&cli.gateway)?;
    let gateway_endpoint = format_endpoint(&gateway_host, gateway_port);
    let gateway_sni = ServerName::try_from(gateway_host.clone())
        .context("gateway hostname is not a valid SNI value")?;

    let connector = Arc::new(GatewayConnector::new(
        Arc::new(tls_config),
        gateway_sni,
        gateway_host,
        gateway_port,
        gateway_endpoint.clone(),
        source_identity.clone(),
    ));

    let listener = TcpListener::bind(cli.listen).await?;
    info!(
        source_identity = %source_identity,
        listen = %cli.listen,
        gateway_endpoint = %gateway_endpoint,
        "sidecar ready"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "TCP accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(e) = bridge::serve_connection(stream, peer, connector).await {
                error!(source_peer_addr = %peer, error = %e, "connection error");
            }
        });
    }
}

fn build_client_config(
    identity: TpmClientIdentity,
    ca_path: &Path,
) -> anyhow::Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = load_certs(ca_path)?;
    let (added, ignored) = root_store.add_parsable_certificates(ca_certs);
    ensure!(
        ignored == 0,
        "unparseable certificates in {}",
        ca_path.display()
    );
    ensure!(added > 0, "no trust anchors in {}", ca_path.display());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_cert_resolver(identity.resolver());
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(config)
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "no certificates in {}", path.display());
    Ok(certs)
}

fn parse_gateway_addr(addr: &str) -> anyhow::Result<(String, u16)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .context("missing closing ']' in IPv6 address")?;
        ensure!(!host.is_empty(), "empty host in gateway address");
        let port = after
            .strip_prefix(':')
            .context("missing port after IPv6 address")?
            .parse::<u16>()
            .context("invalid port")?;
        Ok((host.to_owned(), port))
    } else if let Some((host, port_str)) = addr.rsplit_once(':') {
        ensure!(!host.is_empty(), "empty host in gateway address");
        let port = port_str.parse::<u16>().context("invalid port")?;
        Ok((host.to_owned(), port))
    } else {
        anyhow::bail!("gateway address must be host:port, got {addr:?}");
    }
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_with_port() {
        let (host, port) = parse_gateway_addr("127.0.0.1:8443").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_hostname_with_port() {
        let (host, port) = parse_gateway_addr("gateway.example.com:443").unwrap();
        assert_eq!(host, "gateway.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_ipv6_with_port() {
        let (host, port) = parse_gateway_addr("[::1]:8443").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8443);
    }

    #[test]
    fn format_endpoint_brackets_ipv6() {
        assert_eq!(format_endpoint("127.0.0.1", 8443), "127.0.0.1:8443");
        assert_eq!(format_endpoint("::1", 8443), "[::1]:8443");
    }

    #[test]
    fn parse_rejects_missing_port() {
        assert!(parse_gateway_addr("127.0.0.1").is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_gateway_addr("").is_err());
    }

    #[test]
    fn parse_rejects_bad_port() {
        assert!(parse_gateway_addr("host:notaport").is_err());
    }

    #[test]
    fn parse_ipv6_missing_bracket() {
        assert!(parse_gateway_addr("[::1:8443").is_err());
    }

    #[test]
    fn parse_ipv6_missing_port() {
        assert!(parse_gateway_addr("[::1]").is_err());
    }

    #[test]
    fn parse_rejects_empty_host() {
        assert!(parse_gateway_addr(":443").is_err());
    }

    #[test]
    fn parse_rejects_empty_bracketed_host() {
        assert!(parse_gateway_addr("[]:443").is_err());
    }

    #[test]
    fn parses_tpm_key_handle_hex() {
        assert_eq!(parse_tpm_key_handle("0x81010004").unwrap(), 0x81010004);
        assert_eq!(parse_tpm_key_handle("81010004").unwrap(), 0x81010004);
    }

    #[test]
    fn rejects_non_persistent_tpm_key_handle() {
        assert!(parse_tpm_key_handle("0x80000000").is_err());
        assert!(parse_tpm_key_handle("not-a-handle").is_err());
    }
}
