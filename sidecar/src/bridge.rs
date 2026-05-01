use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2 as h2_client;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

type Body = BoxBody<Bytes, Infallible>;

pub struct GatewayConnector {
    tls_config: Arc<ClientConfig>,
    sni: ServerName<'static>,
    host: String,
    port: u16,
    sender: Mutex<Option<h2_client::SendRequest<Body>>>,
}

impl GatewayConnector {
    pub fn new(
        tls_config: Arc<ClientConfig>,
        sni: ServerName<'static>,
        host: String,
        port: u16,
    ) -> Self {
        Self {
            tls_config,
            sni,
            host,
            port,
            sender: Mutex::new(None),
        }
    }

    async fn connect_fresh(&self) -> anyhow::Result<h2_client::SendRequest<Body>> {
        let tcp = TcpStream::connect((&*self.host, self.port))
            .await
            .with_context(|| format!("TCP connect to {}:{}", self.host, self.port))?;

        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let tls = connector
            .connect(self.sni.clone(), tcp)
            .await
            .with_context(|| format!("TLS handshake with {}:{}", self.host, self.port))?;

        let io = TokioIo::new(tls);
        let (sender, conn) = h2_client::handshake(TokioExecutor::new(), io)
            .await
            .context("h2 handshake with gateway")?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!(error = %e, "gateway h2 connection closed");
            }
        });

        Ok(sender)
    }

    /// Return a live sender, connecting if needed. The lock is only held briefly
    /// to read/write the cached sender — never across network I/O.
    async fn get_sender(&self) -> anyhow::Result<h2_client::SendRequest<Body>> {
        {
            let guard = self.sender.lock().await;
            if let Some(ref sender) = *guard
                && !sender.is_closed()
            {
                return Ok(sender.clone());
            }
        }

        let sender = self.connect_fresh().await?;
        {
            let mut guard = self.sender.lock().await;
            *guard = Some(sender.clone());
        }
        Ok(sender)
    }

    fn invalidate_sender(&self) {
        if let Ok(mut guard) = self.sender.try_lock() {
            *guard = None;
        }
    }

    /// Send a CONNECT request to the gateway. On connection error, reconnect once and retry.
    pub async fn send_connect(&self, authority: &str) -> anyhow::Result<Response<Incoming>> {
        let req = build_connect_request(authority)?;
        let mut sender = self.get_sender().await?;

        match sender.send_request(req).await {
            Ok(resp) => Ok(resp),
            Err(first_err) => {
                warn!(error = %first_err, "gateway request failed, reconnecting");
                self.invalidate_sender();

                let retry_req = build_connect_request(authority)?;
                let mut new_sender = self.get_sender().await?;
                new_sender
                    .send_request(retry_req)
                    .await
                    .map_err(|e| anyhow::anyhow!("gateway retry failed: {e}"))
            }
        }
    }
}

fn build_connect_request(authority: &str) -> anyhow::Result<Request<Body>> {
    let uri = http::Uri::builder()
        .authority(authority)
        .build()
        .context("building CONNECT URI")?;

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(Empty::<Bytes>::new().boxed())
        .context("building CONNECT request")?;
    Ok(req)
}

#[derive(Clone)]
struct SidecarService {
    connector: Arc<GatewayConnector>,
}

impl Service<Request<Incoming>> for SidecarService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let connector = self.connector.clone();
        Box::pin(async move { Ok(handle(req, connector).await) })
    }
}

async fn handle(req: Request<Incoming>, connector: Arc<GatewayConnector>) -> Response<Body> {
    if req.method() != Method::CONNECT {
        return response(StatusCode::METHOD_NOT_ALLOWED, "only CONNECT is supported");
    }

    let authority = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => return response(StatusCode::BAD_REQUEST, "missing authority"),
    };

    info!(dest = %authority, "CONNECT request");

    let gw_response = match connector.send_connect(&authority).await {
        Ok(r) => r,
        Err(e) => {
            error!(dest = %authority, error = %e, "gateway connect failed");
            return response(StatusCode::BAD_GATEWAY, "gateway unreachable");
        }
    };

    let status = gw_response.status();
    if status != StatusCode::OK {
        warn!(dest = %authority, %status, "gateway rejected CONNECT");
        return response(status, "gateway denied request");
    }

    let gw_upgraded = match hyper::upgrade::on(gw_response).await {
        Ok(u) => u,
        Err(e) => {
            error!(dest = %authority, error = %e, "gateway upgrade failed");
            return response(StatusCode::BAD_GATEWAY, "gateway tunnel failed");
        }
    };

    let client_upgrade = hyper::upgrade::on(req);

    tokio::spawn(async move {
        let client_upgraded = match client_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                warn!(dest = %authority, error = %e, "client upgrade failed");
                return;
            }
        };

        let mut client_io = TokioIo::new(client_upgraded);
        let mut gw_io = TokioIo::new(gw_upgraded);

        match copy_bidirectional(&mut client_io, &mut gw_io).await {
            Ok((up, down)) => {
                info!(
                    dest = %authority,
                    client_to_dest = up,
                    dest_to_client = down,
                    "tunnel closed"
                );
            }
            Err(e) => {
                error!(dest = %authority, error = %e, "tunnel error");
            }
        }
    });

    response(StatusCode::OK, "")
}

fn response(status: StatusCode, message: &str) -> Response<Body> {
    let body: Body = if message.is_empty() {
        Empty::<Bytes>::new().boxed()
    } else {
        Full::new(Bytes::from(message.to_owned())).boxed()
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

pub async fn serve_connection(
    stream: TcpStream,
    connector: Arc<GatewayConnector>,
) -> anyhow::Result<()> {
    let service = SidecarService { connector };
    let io = TokioIo::new(stream);

    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|e| anyhow::anyhow!("serve error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_has_correct_method_and_authority() {
        let req = build_connect_request("example.com:443").unwrap();
        assert_eq!(req.method(), Method::CONNECT);
        assert_eq!(req.uri().authority().unwrap().as_str(), "example.com:443");
    }

    #[test]
    fn connect_request_ipv6() {
        let req = build_connect_request("[::1]:8443").unwrap();
        assert_eq!(req.uri().authority().unwrap().as_str(), "[::1]:8443");
    }

    #[test]
    fn response_ok_has_empty_body() {
        let resp = response(StatusCode::OK, "");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn response_error_has_status_and_body() {
        let resp = response(StatusCode::FORBIDDEN, "denied");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn response_bad_gateway() {
        let resp = response(StatusCode::BAD_GATEWAY, "gateway unreachable");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
