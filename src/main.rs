use std::path::PathBuf;
use std::sync::Arc;

use agent_gateway::proxy::MakeProxyService;
use agent_gateway::{config, observability, policy, proxy, tls};
use anyhow::Context;
use clap::Parser;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tracing::{error, info};

mod rate_limit;

#[derive(Parser)]
#[command(name = "agent_gateway", about = "mTLS HTTP/2 CONNECT proxy")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");

    let cli = Cli::parse();
    let config = config::Config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;

    serve(config).await
}

async fn serve(config: config::Config) -> anyhow::Result<()> {
    observability::init(&config.observability)?;

    let server_tls = tls::build_server_config(&config.server)?;
    let tls_acceptor = tls::TlsAcceptor::from(server_tls);

    let policy_engine = policy::build_engine(&config.policy).await?;

    // Pass rate_limit config into the service — used in spawn_tunnel
    let make_service = Arc::new(MakeProxyService::new(policy_engine, config.rate_limit));

    let listen_addr: std::net::SocketAddr = config.server.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!(%listen_addr, "listening");

    tokio::select! {
        result = serve_loop(&listener, &tls_acceptor, &make_service) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    observability::shutdown();
    Ok(())
}

async fn serve_loop(
    listener: &TcpListener,
    tls_acceptor: &tls::TlsAcceptor,
    make_service: &Arc<MakeProxyService>,
) -> anyhow::Result<()> {
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "TCP accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let make_svc = make_service.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(source_peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            };

            let peer_certs = proxy::extract_peer_certs(tls_stream.get_ref().1);
            let service = make_svc.make_service(peer_certs, peer_addr);

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .http2_only()
                .serve_connection_with_upgrades(io, service)
                .await
            {
                error!(source_peer_addr = %peer_addr, error = %e, "connection error");
            }
        });
    }
}
