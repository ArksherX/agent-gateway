use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use agent_gateway::config::PolicyConfig;
use agent_gateway::policy::TomlPolicyEngine;
use agent_gateway::proxy::MakeProxyService;

const CLIENT_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];

// ---------------------------------------------------------------------------
// PKI generation
// ---------------------------------------------------------------------------

pub fn generate_ca() -> Result<CertifiedIssuer<'static, KeyPair>, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "agent-gateway test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate()?;
    CertifiedIssuer::self_signed(params, key_pair)
}

pub fn generate_server_cert(
    issuer: &CertifiedIssuer<'_, impl rcgen::SigningKey>,
) -> Result<(rcgen::Certificate, KeyPair), rcgen::Error> {
    let mut params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((cert, key_pair))
}

pub fn generate_client_cert(
    issuer: &CertifiedIssuer<'_, impl rcgen::SigningKey>,
    extension_value: &str,
) -> Result<(rcgen::Certificate, KeyPair), rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "test client");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            CLIENT_EXTENSION_OID,
            der_encode_utf8_string(extension_value),
        ));

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((cert, key_pair))
}

/// Generate a client cert with no custom extension at all.
pub fn generate_client_cert_no_extension(
    issuer: &CertifiedIssuer<'_, impl rcgen::SigningKey>,
) -> Result<(rcgen::Certificate, KeyPair), rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "test client (no ext)");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((cert, key_pair))
}

pub struct TestPki {
    pub ca: CertifiedIssuer<'static, KeyPair>,
    pub server_cert: rcgen::Certificate,
    pub server_key: KeyPair,
    pub client_cert: rcgen::Certificate,
    pub client_key: KeyPair,
}

impl TestPki {
    pub fn new(client_extension_value: &str) -> Self {
        let ca = generate_ca().expect("generate CA");
        let (server_cert, server_key) = generate_server_cert(&ca).expect("generate server cert");
        let (client_cert, client_key) =
            generate_client_cert(&ca, client_extension_value).expect("generate client cert");

        Self {
            ca,
            server_cert,
            server_key,
            client_cert,
            client_key,
        }
    }

    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.ca.der().to_vec())
    }

    pub fn server_cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.server_cert.der().to_vec())]
    }

    pub fn server_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.server_key.serialize_der()))
    }

    pub fn client_cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.client_cert.der().to_vec())]
    }

    pub fn client_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.client_key.serialize_der()))
    }
}

fn der_encode_utf8_string(value: &str) -> Vec<u8> {
    let value_bytes = value.as_bytes();
    let len = value_bytes.len();
    let mut encoded = Vec::with_capacity(2 + len);
    encoded.push(0x0c); // UTF8String tag
    if len < 128 {
        encoded.push(len as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut remaining = len;
        while remaining > 0 {
            len_bytes.push((remaining & 0xff) as u8);
            remaining >>= 8;
        }
        len_bytes.reverse();
        encoded.push(0x80 | (len_bytes.len() as u8));
        encoded.extend_from_slice(&len_bytes);
    }
    encoded.extend_from_slice(value_bytes);
    encoded
}

// ---------------------------------------------------------------------------
// Tracing capture layer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CapturedEvent {
    pub message: String,
    pub fields: std::collections::HashMap<String, String>,
}

pub type EventLog = Arc<Mutex<Vec<CapturedEvent>>>;

pub fn new_event_log() -> EventLog {
    Arc::new(Mutex::new(Vec::new()))
}

struct CaptureLayer {
    log: EventLog,
}

struct CaptureVisitor {
    message: Option<String>,
    fields: std::collections::HashMap<String, String>,
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

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
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
            fields: std::collections::HashMap::new(),
        };
        event.record(&mut visitor);
        let captured = CapturedEvent {
            message: visitor.message.unwrap_or_default(),
            fields: visitor.fields,
        };
        self.log.lock().unwrap().push(captured);
    }
}

/// Install the capture layer as the global default subscriber for this test.
/// Returns the event log that accumulates all tracing events.
///
/// NOTE: `tracing::subscriber::set_default` is per-thread only. Since the
/// proxy runs spawned tasks on the tokio runtime, we must use `set_global_default`
/// which can only be called once per process. For test binaries that run
/// tests sequentially in a single process, this works. The `EventLog` is
/// shared across all tests in this binary.
pub fn init_tracing_capture() -> EventLog {
    use std::sync::Once;
    use tracing_subscriber::layer::SubscriberExt;

    static INIT: Once = Once::new();
    static LOG: std::sync::OnceLock<EventLog> = std::sync::OnceLock::new();

    INIT.call_once(|| {
        let log = new_event_log();
        LOG.set(log.clone()).unwrap();
        let subscriber = tracing_subscriber::registry().with(CaptureLayer { log });
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting global tracing subscriber");
    });

    LOG.get().unwrap().clone()
}

/// Drain the event log and return all events captured so far.
pub fn drain_events(log: &EventLog) -> Vec<CapturedEvent> {
    let mut guard = log.lock().unwrap();
    guard.drain(..).collect()
}

/// Find the first event with the given message substring.
pub fn find_event<'a>(events: &'a [CapturedEvent], message: &str) -> Option<&'a CapturedEvent> {
    events.iter().find(|e| e.message.contains(message))
}

/// Poll the event log until an event matching `message` appears, or time out.
/// Returns all drained events (including any captured before the match).
pub async fn wait_for_event(
    log: &EventLog,
    message: &str,
    timeout: std::time::Duration,
) -> Vec<CapturedEvent> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut collected = Vec::new();
    loop {
        collected.extend(drain_events(log));
        if find_event(&collected, message).is_some() {
            return collected;
        }
        if tokio::time::Instant::now() >= deadline {
            return collected;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Acquire an exclusive lock for e2e tests that share a global tracing subscriber.
/// Hold the returned guard for the duration of the test.
static E2E_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn serial_test_lock() -> std::sync::MutexGuard<'static, ()> {
    E2E_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// E2E harness: proxy, client, echo server
// ---------------------------------------------------------------------------

/// A handle that aborts the background accept loop when dropped.
pub struct ServerGuard {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start the real proxy in-process. Returns the bound address and a guard
/// that stops the server when dropped or explicitly shut down.
pub async fn start_proxy(pki: &TestPki, policy_config: PolicyConfig) -> (SocketAddr, ServerGuard) {
    let mut ca_store = rustls::RootCertStore::empty();
    ca_store.add(pki.ca_cert_der()).unwrap();

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(ca_store))
        .build()
        .unwrap();

    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(pki.server_cert_chain(), pki.server_key_der())
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let policy_engine: Arc<dyn agent_gateway::policy::PolicyEngine> =
        Arc::new(TomlPolicyEngine::new(policy_config).unwrap());

    let make_service = Arc::new(MakeProxyService::new(policy_engine));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let acceptor = tls_acceptor.clone();
            let svc = make_service.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "TLS handshake failed");
                        return;
                    }
                };
                let peer_certs =
                    agent_gateway::proxy::extract_peer_certs(tls_stream.get_ref().1);
                let service = svc.make_service(peer_certs);
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .http2_only()
                .serve_connection_with_upgrades(io, service)
                .await;
            });
        }
    });

    (addr, ServerGuard { task })
}

/// Connect an HTTP/2 mTLS client to the proxy. Returns a SendRequest handle.
pub async fn connect_client(
    proxy_addr: SocketAddr,
    pki: &TestPki,
) -> hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>> {
    let mut ca_store = rustls::RootCertStore::empty();
    ca_store.add(pki.ca_cert_der()).unwrap();

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(pki.client_cert_chain(), pki.client_key_der())
        .unwrap();
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (send_request, connection) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .unwrap();

    tokio::spawn(async move {
        let _ = connection.await;
    });

    send_request
}

/// Try to connect, perform HTTP/2 handshake, and send a CONNECT request using
/// the given client TLS config. Returns `Ok(response)` if everything succeeds,
/// or `Err` if any step (TLS, h2, request) fails. Used for negative mTLS tests.
pub async fn try_request_with_tls_config(
    proxy_addr: SocketAddr,
    client_config: rustls::ClientConfig,
    dest_authority: &str,
) -> Result<hyper::Response<hyper::body::Incoming>, Box<dyn std::error::Error + Send + Sync>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await?;
    let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await?;

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut send_request, connection) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await?;

    tokio::spawn(async move {
        let _ = connection.await;
    });

    let req = hyper::Request::connect(dest_authority)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = send_request.send_request(req).await?;
    Ok(resp)
}

/// Connect to the proxy with a custom client cert/key (for extension mismatch tests).
pub async fn connect_client_with_cert(
    proxy_addr: SocketAddr,
    ca_cert: CertificateDer<'static>,
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>> {
    let mut ca_store = rustls::RootCertStore::empty();
    ca_store.add(ca_cert).unwrap();

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(client_cert_chain, client_key)
        .unwrap();
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (send_request, connection) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .unwrap();

    tokio::spawn(async move {
        let _ = connection.await;
    });

    send_request
}

/// Start a TCP echo server. Returns its address and a guard that stops it.
pub async fn start_echo_server() -> (SocketAddr, ServerGuard) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (addr, ServerGuard { task })
}

/// Bind a TCP listener and immediately drop it, returning the port.
/// This guarantees the port is unoccupied and nothing is listening on it.
pub async fn allocate_closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}
