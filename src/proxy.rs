use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use rustls::ServerConnection;
use rustls_pki_types::CertificateDer;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::{error, info, warn};

use crate::policy::{self, PolicyDecision, PolicyEngine, RequestContext};

type ProxyBody = BoxBody<Bytes, Infallible>;

#[derive(Clone)]
pub struct ProxyService {
    policy_engine: Arc<dyn PolicyEngine>,
    peer_certs: Vec<CertificateDer<'static>>,
}

impl ProxyService {
    pub fn new(
        policy_engine: Arc<dyn PolicyEngine>,
        peer_certs: Vec<CertificateDer<'static>>,
    ) -> Self {
        Self {
            policy_engine,
            peer_certs,
        }
    }

    async fn handle(self, req: Request<Incoming>) -> Response<ProxyBody> {
        if req.method() != Method::CONNECT {
            return response(StatusCode::METHOD_NOT_ALLOWED, "only CONNECT is supported");
        }

        let dest = match Destination::from_request(&req) {
            Ok(d) => d,
            Err(reason) => return response(StatusCode::BAD_REQUEST, &reason),
        };

        let ctx = RequestContext {
            peer_certificates: self.peer_certs.clone(),
            destination: dest.authority.clone(),
        };

        match self.policy_engine.evaluate(&ctx).await {
            PolicyDecision::Allow => {
                info!(dest = %dest.authority, "CONNECT allowed");
            }
            PolicyDecision::Deny { reason } => {
                warn!(dest = %dest.authority, %reason, "CONNECT denied");
                return response(StatusCode::FORBIDDEN, "forbidden");
            }
        }

        // Connect to destination BEFORE returning 200 so the client knows
        // the tunnel is actually established.
        let mut upstream = match TcpStream::connect((&*dest.host, dest.port)).await {
            Ok(s) => s,
            Err(e) => {
                error!(dest = %dest.authority, error = %e, "TCP connect failed");
                return response(StatusCode::BAD_GATEWAY, "bad gateway");
            }
        };

        let on_upgrade = hyper::upgrade::on(req);

        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    warn!(dest = %dest.authority, error = %e, "upgrade failed");
                    return;
                }
            };

            let mut downstream = hyper_util::rt::TokioIo::new(upgraded);

            match copy_bidirectional(&mut downstream, &mut upstream).await {
                Ok((up, down)) => {
                    info!(
                        dest = %dest.authority,
                        client_to_dest = up,
                        dest_to_client = down,
                        "tunnel closed"
                    );
                }
                Err(e) => {
                    error!(dest = %dest.authority, error = %e, "tunnel error");
                }
            }
        });

        response(StatusCode::OK, "")
    }
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.handle(req).await) })
    }
}

pub struct MakeProxyService {
    policy_engine: Arc<dyn PolicyEngine>,
}

impl MakeProxyService {
    pub fn new(policy_engine: Arc<dyn PolicyEngine>) -> Self {
        Self { policy_engine }
    }

    pub fn make_service(&self, peer_certs: Vec<CertificateDer<'static>>) -> ProxyService {
        ProxyService::new(self.policy_engine.clone(), peer_certs)
    }
}

pub fn extract_peer_certs(conn: &ServerConnection) -> Vec<CertificateDer<'static>> {
    conn.peer_certificates()
        .map(|certs| certs.to_vec())
        .unwrap_or_default()
}

fn response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body: ProxyBody = if message.is_empty() {
        Empty::<Bytes>::new().boxed()
    } else {
        Full::new(Bytes::from(message.to_owned())).boxed()
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

#[derive(Clone)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub authority: String,
}

impl Destination {
    pub fn from_request(req: &Request<Incoming>) -> Result<Self, String> {
        let authority = req
            .uri()
            .authority()
            .ok_or("CONNECT request missing authority")?;
        Self::from_authority(authority)
    }

    pub fn from_authority(authority: &http::uri::Authority) -> Result<Self, String> {
        let raw_host = authority.host();
        if raw_host.is_empty() {
            return Err("empty host in CONNECT authority".into());
        }

        // Authority::host() preserves brackets for IPv6 (e.g. "[::1]").
        // Strip them so `host` is always the bare address for TcpStream::connect.
        let host = raw_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();

        let port = authority.port_u16().unwrap_or(443);

        // Reconstruct with brackets for IPv6 to feed the canonical normalizer
        let formatted = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let authority_str = policy::normalize_destination(&formatted)
            .map_err(|e| format!("bad destination: {e}"))?;

        Ok(Self {
            host,
            port,
            authority: authority_str,
        })
    }
}
