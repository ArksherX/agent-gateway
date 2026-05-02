mod common;

use agent_gateway::config::{PolicyConfig, PolicyRule};
use common::{
    TestPki, allocate_closed_port, connect_client_with_cert, drain_events, find_event,
    generate_client_cert, generate_client_cert_no_extension, init_tracing_capture,
    serial_test_lock, start_echo_server, start_proxy, try_request_with_tls_config, wait_for_event,
};
use http_body_util::Empty;
use hyper::Request;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EXT_OID: &str = "1.3.6.1.4.1.57264.1.1";
const EXT_VALUE: &str = "agent-alpha";
const EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn policy_allowing(destinations: Vec<String>) -> PolicyConfig {
    PolicyConfig {
        client_ext_oid: EXT_OID.to_owned(),
        rules: vec![PolicyRule {
            extension_value: EXT_VALUE.to_owned(),
            allowed_destinations: destinations,
        }],
    }
}

fn assert_field_eq(event: &common::CapturedEvent, field: &str, expected: &str) {
    assert_eq!(
        event.fields.get(field).map(String::as_str),
        Some(expected),
        "{field} should match"
    );
}

fn assert_field_present(event: &common::CapturedEvent, field: &str) {
    assert!(
        event.fields.get(field).is_some(),
        "{field} should be present"
    );
}

fn assert_source_peer_addr(event: &common::CapturedEvent) {
    let source_peer_addr = event
        .fields
        .get("source_peer_addr")
        .expect("source_peer_addr should be present");
    assert!(
        source_peer_addr.starts_with("127.0.0.1:"),
        "source_peer_addr should be a loopback socket address, got {source_peer_addr}"
    );
}

#[tokio::test]
async fn tunnel_echoes_data() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let (echo_addr, _echo_guard) = start_echo_server().await;

    let policy = policy_allowing(vec![format!("127.0.0.1:{}", echo_addr.port())]);
    let pki = TestPki::new(EXT_VALUE);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    let mut send_req = common::connect_client(proxy_addr, &pki).await;

    let dest = format!("127.0.0.1:{}", echo_addr.port());
    let req = Request::connect(&dest)
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200, "expected 200 OK for allowed CONNECT");

    let upgraded = hyper::upgrade::on(resp).await.unwrap();
    let mut io = hyper_util::rt::TokioIo::new(upgraded);

    io.write_all(b"hello").await.unwrap();
    io.shutdown().await.unwrap();

    let mut buf = Vec::new();
    io.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello", "echo server should return the same data");

    let events = wait_for_event(&log, "tunnel closed", EVENT_TIMEOUT).await;

    let allowed_evt =
        find_event(&events, "CONNECT allowed").expect("expected CONNECT allowed event");
    assert_field_eq(allowed_evt, "source_identity", EXT_VALUE);
    assert_source_peer_addr(allowed_evt);
    assert_field_eq(allowed_evt, "dest_authority", &dest);
    assert_field_eq(allowed_evt, "policy_decision", "allow");

    let closed_evt = find_event(&events, "tunnel closed").expect("expected tunnel closed event");
    assert_field_eq(closed_evt, "source_identity", EXT_VALUE);
    assert_source_peer_addr(closed_evt);
    assert_field_eq(closed_evt, "dest_authority", &dest);
    let c2d: u64 = closed_evt
        .fields
        .get("bytes_client_to_dest")
        .expect("tunnel closed should have bytes_client_to_dest")
        .parse()
        .unwrap();
    let d2c: u64 = closed_evt
        .fields
        .get("bytes_dest_to_client")
        .expect("tunnel closed should have bytes_dest_to_client")
        .parse()
        .unwrap();
    assert!(c2d > 0, "bytes_client_to_dest should be > 0, got {c2d}");
    assert!(d2c > 0, "bytes_dest_to_client should be > 0, got {d2c}");
}

#[tokio::test]
async fn tunnel_policy_deny() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let policy = policy_allowing(vec!["allowed.example.com:443".to_owned()]);
    let pki = TestPki::new(EXT_VALUE);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    let mut send_req = common::connect_client(proxy_addr, &pki).await;

    let req = Request::connect("127.0.0.1:9999")
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden for denied CONNECT"
    );

    let events = wait_for_event(&log, "CONNECT denied", EVENT_TIMEOUT).await;
    let denied_evt = find_event(&events, "CONNECT denied").expect("expected CONNECT denied event");
    assert_field_eq(denied_evt, "source_identity", EXT_VALUE);
    assert_source_peer_addr(denied_evt);
    assert_field_eq(denied_evt, "dest_authority", "127.0.0.1:9999");
    assert_field_eq(denied_evt, "policy_decision", "deny");
    assert_field_present(denied_evt, "deny_reason");
}

#[tokio::test]
async fn tunnel_unreachable_destination() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let closed_port = allocate_closed_port().await;
    let dest = format!("127.0.0.1:{closed_port}");

    let policy = policy_allowing(vec![dest.clone()]);
    let pki = TestPki::new(EXT_VALUE);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    let mut send_req = common::connect_client(proxy_addr, &pki).await;

    let req = Request::connect(&dest)
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        502,
        "expected 502 Bad Gateway for unreachable destination"
    );

    let events = wait_for_event(&log, "TCP connect failed", EVENT_TIMEOUT).await;
    let tcp_fail =
        find_event(&events, "TCP connect failed").expect("expected TCP connect failed event");
    assert_field_eq(tcp_fail, "source_identity", EXT_VALUE);
    assert_source_peer_addr(tcp_fail);
    assert_field_eq(tcp_fail, "dest_authority", &dest);
    assert_field_present(tcp_fail, "error");
}

#[tokio::test]
async fn non_connect_method_rejected() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let policy = policy_allowing(vec!["example.com:443".to_owned()]);
    let pki = TestPki::new(EXT_VALUE);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    let mut send_req = common::connect_client(proxy_addr, &pki).await;

    let req = Request::get("http://example.com/")
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        405,
        "expected 405 Method Not Allowed for GET"
    );

    // Brief poll to confirm no policy events for non-CONNECT
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = drain_events(&log);
    assert!(
        find_event(&events, "CONNECT allowed").is_none(),
        "should not see CONNECT allowed for non-CONNECT request"
    );
    assert!(
        find_event(&events, "CONNECT denied").is_none(),
        "should not see CONNECT denied for non-CONNECT request"
    );
}

// ---------------------------------------------------------------------------
// Extension-based policy enforcement tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tunnel_wrong_extension_denied() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let (echo_addr, _echo_guard) = start_echo_server().await;

    // Policy allows agent-alpha, but client cert has agent-beta
    let policy = policy_allowing(vec![format!("127.0.0.1:{}", echo_addr.port())]);
    let pki = TestPki::new("agent-beta");
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    let mut send_req = common::connect_client(proxy_addr, &pki).await;

    let dest = format!("127.0.0.1:{}", echo_addr.port());
    let req = Request::connect(&dest)
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "expected 403 when client extension value doesn't match policy rules"
    );

    let events = wait_for_event(&log, "CONNECT denied", EVENT_TIMEOUT).await;
    let denied = find_event(&events, "CONNECT denied").expect("expected CONNECT denied event");
    assert_field_eq(denied, "source_identity", "agent-beta");
    assert_source_peer_addr(denied);
    assert_field_eq(denied, "dest_authority", &dest);
    assert_field_eq(denied, "policy_decision", "deny");
    let reason = denied
        .fields
        .get("deny_reason")
        .expect("should have reason");
    assert!(
        reason.contains("agent-beta"),
        "denial reason should mention the unrecognized extension value; got: {reason}"
    );
}

#[tokio::test]
async fn tunnel_missing_extension_denied() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let (echo_addr, _echo_guard) = start_echo_server().await;

    // Use a client cert that has NO custom extension at all
    let pki = TestPki::new(EXT_VALUE); // base PKI for CA + server cert
    let (no_ext_cert, no_ext_key) =
        generate_client_cert_no_extension(&pki.ca).expect("generate client cert (no ext)");
    let client_cert_chain = vec![CertificateDer::from(no_ext_cert.der().to_vec())];
    let client_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(no_ext_key.serialize_der()));

    let policy = policy_allowing(vec![format!("127.0.0.1:{}", echo_addr.port())]);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    let mut send_req =
        connect_client_with_cert(proxy_addr, pki.ca_cert_der(), client_cert_chain, client_key)
            .await;

    let dest = format!("127.0.0.1:{}", echo_addr.port());
    let req = Request::connect(&dest)
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "expected 403 when client cert has no custom extension"
    );

    let events = wait_for_event(&log, "CONNECT denied", EVENT_TIMEOUT).await;
    let denied = find_event(&events, "CONNECT denied").expect("expected CONNECT denied event");
    assert!(
        !denied.fields.contains_key("source_identity"),
        "source_identity should be omitted when the client cert has no identity extension"
    );
    assert_source_peer_addr(denied);
    assert_field_eq(denied, "dest_authority", &dest);
    assert_field_eq(denied, "policy_decision", "deny");
    let reason = denied
        .fields
        .get("deny_reason")
        .expect("should have reason");
    assert!(
        reason.contains("missing required extension"),
        "denial reason should mention missing extension; got: {reason}"
    );
}

// ---------------------------------------------------------------------------
// mTLS fail-closed tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_no_client_cert_rejected() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let policy = policy_allowing(vec!["example.com:443".to_owned()]);
    let pki = TestPki::new(EXT_VALUE);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    // Client trusts the proxy's server cert CA but presents NO client cert.
    let mut ca_store = rustls::RootCertStore::empty();
    ca_store.add(pki.ca_cert_der()).unwrap();

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let result = try_request_with_tls_config(proxy_addr, client_config, "example.com:443").await;
    assert!(
        result.is_err(),
        "connection should fail without client certificate, got: {result:?}"
    );

    // Server should log the TLS handshake failure, and never reach policy evaluation
    let events = wait_for_event(&log, "TLS handshake failed", EVENT_TIMEOUT).await;
    let handshake_failed = find_event(&events, "TLS handshake failed")
        .expect("server should log TLS handshake failure");
    assert_source_peer_addr(handshake_failed);
    assert!(
        !handshake_failed.fields.contains_key("source_identity"),
        "source_identity should be omitted before client identity is authenticated"
    );
    assert!(
        find_event(&events, "CONNECT allowed").is_none(),
        "no request should reach policy evaluation"
    );
    assert!(
        find_event(&events, "CONNECT denied").is_none(),
        "no request should reach policy evaluation"
    );
}

#[tokio::test]
async fn mtls_untrusted_ca_rejected() {
    let _guard = serial_test_lock();
    let log = init_tracing_capture();
    drain_events(&log);

    let policy = policy_allowing(vec!["example.com:443".to_owned()]);
    let pki = TestPki::new(EXT_VALUE);
    let (proxy_addr, _proxy_guard) = start_proxy(&pki, policy).await;

    // Generate a completely separate CA + client cert not trusted by the proxy
    let rogue_ca = common::generate_ca().expect("generate rogue CA");
    let (rogue_cert, rogue_key) =
        generate_client_cert(&rogue_ca, EXT_VALUE).expect("generate rogue client cert");
    let rogue_cert_chain = vec![CertificateDer::from(rogue_cert.der().to_vec())];
    let rogue_key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(rogue_key.serialize_der()));

    // Client trusts the proxy's CA (for the server cert) but presents a cert
    // signed by the rogue CA that the proxy does NOT trust.
    let mut ca_store = rustls::RootCertStore::empty();
    ca_store.add(pki.ca_cert_der()).unwrap();

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(rogue_cert_chain, rogue_key_der)
        .unwrap();
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let result = try_request_with_tls_config(proxy_addr, client_config, "example.com:443").await;
    assert!(
        result.is_err(),
        "connection should fail with client cert from untrusted CA, got: {result:?}"
    );

    // Server should log the TLS handshake failure, and never reach policy evaluation
    let events = wait_for_event(&log, "TLS handshake failed", EVENT_TIMEOUT).await;
    let handshake_failed = find_event(&events, "TLS handshake failed")
        .expect("server should log TLS handshake failure");
    assert_source_peer_addr(handshake_failed);
    assert!(
        !handshake_failed.fields.contains_key("source_identity"),
        "source_identity should be omitted before client identity is authenticated"
    );
    assert!(
        find_event(&events, "CONNECT allowed").is_none(),
        "no request should reach policy evaluation"
    );
    assert!(
        find_event(&events, "CONNECT denied").is_none(),
        "no request should reach policy evaluation"
    );
}
