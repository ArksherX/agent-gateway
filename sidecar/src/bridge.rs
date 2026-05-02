use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
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
    gateway_endpoint: String,
    source_identity: String,
    sender: Mutex<Option<h2_client::SendRequest<Body>>>,
}

impl GatewayConnector {
    pub fn new(
        tls_config: Arc<ClientConfig>,
        sni: ServerName<'static>,
        host: String,
        port: u16,
        gateway_endpoint: String,
        source_identity: String,
    ) -> Self {
        Self {
            tls_config,
            sni,
            host,
            port,
            gateway_endpoint,
            source_identity,
            sender: Mutex::new(None),
        }
    }

    fn gateway_endpoint(&self) -> &str {
        &self.gateway_endpoint
    }

    fn source_identity(&self) -> &str {
        &self.source_identity
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

        let source_identity = self.source_identity.clone();
        let gateway_endpoint = self.gateway_endpoint.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!(
                    source_identity = %source_identity,
                    gateway_endpoint = %gateway_endpoint,
                    error = %e,
                    "gateway h2 connection closed"
                );
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
    pub async fn send_connect(
        &self,
        authority: &str,
        source_peer_addr: SocketAddr,
    ) -> anyhow::Result<Response<Incoming>> {
        let req = build_connect_request(authority)?;
        info!(
            source_identity = %self.source_identity,
            source_peer_addr = %source_peer_addr,
            dest_authority = %authority,
            gateway_endpoint = %self.gateway_endpoint,
            attempt = 1,
            "gateway CONNECT request"
        );
        let mut sender = self.get_sender().await?;

        match sender.send_request(req).await {
            Ok(resp) => Ok(resp),
            Err(first_err) => {
                warn!(
                    source_identity = %self.source_identity,
                    source_peer_addr = %source_peer_addr,
                    dest_authority = %authority,
                    gateway_endpoint = %self.gateway_endpoint,
                    attempt = 1,
                    error = %first_err,
                    "gateway request failed, reconnecting"
                );
                self.invalidate_sender();

                let retry_req = build_connect_request(authority)?;
                let mut new_sender = self.get_sender().await?;
                info!(
                    source_identity = %self.source_identity,
                    source_peer_addr = %source_peer_addr,
                    dest_authority = %authority,
                    gateway_endpoint = %self.gateway_endpoint,
                    attempt = 2,
                    retried = true,
                    "gateway CONNECT request"
                );
                match new_sender.send_request(retry_req).await {
                    Ok(resp) => {
                        info!(
                            source_identity = %self.source_identity,
                            source_peer_addr = %source_peer_addr,
                            dest_authority = %authority,
                            gateway_endpoint = %self.gateway_endpoint,
                            attempt = 2,
                            retried = true,
                            "gateway retry succeeded"
                        );
                        Ok(resp)
                    }
                    Err(e) => {
                        error!(
                            source_identity = %self.source_identity,
                            source_peer_addr = %source_peer_addr,
                            dest_authority = %authority,
                            gateway_endpoint = %self.gateway_endpoint,
                            attempt = 2,
                            retried = true,
                            error = %e,
                            "gateway retry failed"
                        );
                        Err(anyhow::anyhow!("gateway retry failed: {e}"))
                    }
                }
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
    source_peer_addr: SocketAddr,
}

impl Service<Request<Incoming>> for SidecarService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let connector = self.connector.clone();
        let source_peer_addr = self.source_peer_addr;
        Box::pin(async move { Ok(handle(req, source_peer_addr, connector).await) })
    }
}

async fn handle(
    req: Request<Incoming>,
    source_peer_addr: SocketAddr,
    connector: Arc<GatewayConnector>,
) -> Response<Body> {
    if req.method() != Method::CONNECT {
        return response(StatusCode::METHOD_NOT_ALLOWED, "only CONNECT is supported");
    }

    let authority = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => return response(StatusCode::BAD_REQUEST, "missing authority"),
    };

    info!(
        source_identity = %connector.source_identity(),
        source_peer_addr = %source_peer_addr,
        dest_authority = %authority,
        gateway_endpoint = %connector.gateway_endpoint(),
        "CONNECT request"
    );

    let gw_response = match connector.send_connect(&authority, source_peer_addr).await {
        Ok(r) => r,
        Err(e) => {
            error!(
                source_identity = %connector.source_identity(),
                source_peer_addr = %source_peer_addr,
                dest_authority = %authority,
                gateway_endpoint = %connector.gateway_endpoint(),
                error = %e,
                "gateway connect failed"
            );
            return response(StatusCode::BAD_GATEWAY, "gateway unreachable");
        }
    };

    let status = gw_response.status();
    if status != StatusCode::OK {
        warn!(
            source_identity = %connector.source_identity(),
            source_peer_addr = %source_peer_addr,
            dest_authority = %authority,
            gateway_endpoint = %connector.gateway_endpoint(),
            %status,
            "gateway rejected CONNECT"
        );
        return response(status, "gateway denied request");
    }

    let gw_upgraded = match hyper::upgrade::on(gw_response).await {
        Ok(u) => u,
        Err(e) => {
            error!(
                source_identity = %connector.source_identity(),
                source_peer_addr = %source_peer_addr,
                dest_authority = %authority,
                gateway_endpoint = %connector.gateway_endpoint(),
                error = %e,
                "gateway upgrade failed"
            );
            return response(StatusCode::BAD_GATEWAY, "gateway tunnel failed");
        }
    };

    let client_upgrade = hyper::upgrade::on(req);
    let source_identity = connector.source_identity().to_owned();
    let gateway_endpoint = connector.gateway_endpoint().to_owned();

    tokio::spawn(async move {
        let client_upgraded = match client_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                warn!(
                    source_identity = %source_identity,
                    source_peer_addr = %source_peer_addr,
                    dest_authority = %authority,
                    gateway_endpoint = %gateway_endpoint,
                    error = %e,
                    "client upgrade failed"
                );
                return;
            }
        };

        let mut client_io = TokioIo::new(client_upgraded);
        let mut gw_io = TokioIo::new(gw_upgraded);

        match copy_bidirectional(&mut client_io, &mut gw_io).await {
            Ok((up, down)) => {
                info!(
                    source_identity = %source_identity,
                    source_peer_addr = %source_peer_addr,
                    dest_authority = %authority,
                    gateway_endpoint = %gateway_endpoint,
                    bytes_client_to_dest = up,
                    bytes_dest_to_client = down,
                    "tunnel closed"
                );
            }
            Err(e) => {
                error!(
                    source_identity = %source_identity,
                    source_peer_addr = %source_peer_addr,
                    dest_authority = %authority,
                    gateway_endpoint = %gateway_endpoint,
                    error = %e,
                    "tunnel error"
                );
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
    source_peer_addr: SocketAddr,
    connector: Arc<GatewayConnector>,
) -> anyhow::Result<()> {
    let service = SidecarService {
        connector,
        source_peer_addr,
    };
    let io = TokioIo::new(stream);

    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|e| anyhow::anyhow!("serve error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    #[derive(Debug)]
    struct CapturedEvent {
        message: String,
        fields: HashMap<String, String>,
    }

    type EventLog = Arc<StdMutex<Vec<CapturedEvent>>>;

    struct CaptureLayer {
        log: EventLog,
    }

    struct CaptureVisitor {
        message: Option<String>,
        fields: HashMap<String, String>,
    }

    impl tracing::field::Visit for CaptureVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = Some(format!("{value:?}").trim_matches('"').to_owned());
            } else {
                self.fields
                    .insert(field.name().to_owned(), format!("{value:?}"));
            }
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.message = Some(value.to_owned());
            } else {
                self.fields
                    .insert(field.name().to_owned(), value.to_owned());
            }
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = CaptureVisitor {
                message: None,
                fields: HashMap::new(),
            };
            event.record(&mut visitor);
            self.log.lock().unwrap().push(CapturedEvent {
                message: visitor.message.unwrap_or_default(),
                fields: visitor.fields,
            });
        }
    }

    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    fn test_connector(port: u16) -> GatewayConnector {
        let config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        GatewayConnector::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
            "127.0.0.1".to_owned(),
            port,
            format!("127.0.0.1:{port}"),
            "agent-alpha".to_owned(),
        )
    }

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

    #[tokio::test]
    async fn gateway_connect_request_logs_connection_context() {
        use tracing_subscriber::layer::SubscriberExt;

        let port = closed_port();
        let connector = test_connector(port);
        let source_peer_addr: SocketAddr = "127.0.0.1:45678".parse().unwrap();
        let log = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer { log: log.clone() });
        let _guard = tracing::subscriber::set_default(subscriber);

        let result = connector
            .send_connect("example.com:443", source_peer_addr)
            .await;
        assert!(result.is_err(), "closed gateway port should fail");

        let events = log.lock().unwrap();
        let event = events
            .iter()
            .find(|event| event.message.contains("gateway CONNECT request"))
            .expect("gateway request event should be captured");
        assert_eq!(
            event.fields.get("source_identity").map(String::as_str),
            Some("agent-alpha")
        );
        assert_eq!(
            event.fields.get("source_peer_addr").map(String::as_str),
            Some("127.0.0.1:45678")
        );
        assert_eq!(
            event.fields.get("dest_authority").map(String::as_str),
            Some("example.com:443")
        );
        assert_eq!(
            event.fields.get("gateway_endpoint").map(String::as_str),
            Some(&*format!("127.0.0.1:{port}"))
        );
        assert_eq!(event.fields.get("attempt").map(String::as_str), Some("1"));
    }
}
