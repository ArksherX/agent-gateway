mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use common::{TestAuthzRegistry, TestPki, certificate_spki_der, unique_test_identity};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use agent_gateway::policy::{self, PolicyDecision, PolicyEngine, RequestContext};
use agent_gateway::proxy::Destination;

const EXT_OID: &str = "1.3.6.1.4.1.57264.1.1";

async fn eval(engine: &dyn PolicyEngine, pki: &TestPki, dest: &str) -> PolicyDecision {
    let ctx = RequestContext {
        peer_certificates: pki.client_cert_chain(),
        destination: dest.into(),
    };
    engine.evaluate(&ctx).await
}

fn assert_allow(decision: PolicyDecision) {
    if let PolicyDecision::Deny { reason, .. } = decision {
        panic!("expected Allow, got Deny: {reason}");
    }
}

fn assert_deny(decision: PolicyDecision) {
    if let PolicyDecision::Allow { .. } = decision {
        panic!("expected Deny, got Allow");
    }
}

// ---- normalize_destination unit tests ----

#[test]
fn normalize_plain_hostname_defaults_to_443() {
    assert_eq!(
        policy::normalize_destination("api.example.com").unwrap(),
        "api.example.com:443"
    );
}

#[test]
fn normalize_hostname_with_explicit_port() {
    assert_eq!(
        policy::normalize_destination("api.example.com:8080").unwrap(),
        "api.example.com:8080"
    );
}

#[test]
fn normalize_hostname_with_443() {
    assert_eq!(
        policy::normalize_destination("api.example.com:443").unwrap(),
        "api.example.com:443"
    );
}

#[test]
fn normalize_lowercases_hostname() {
    assert_eq!(
        policy::normalize_destination("API.EXAMPLE.COM:443").unwrap(),
        "api.example.com:443"
    );
    assert_eq!(
        policy::normalize_destination("API.EXAMPLE.COM").unwrap(),
        "api.example.com:443"
    );
}

#[test]
fn normalize_bracketed_ipv6_with_port() {
    assert_eq!(
        policy::normalize_destination("[::1]:8443").unwrap(),
        "[::1]:8443"
    );
}

#[test]
fn normalize_bracketed_ipv6_without_port_defaults_to_443() {
    assert_eq!(policy::normalize_destination("[::1]").unwrap(), "[::1]:443");
}

#[test]
fn normalize_bare_ipv6_defaults_to_443() {
    assert_eq!(policy::normalize_destination("::1").unwrap(), "[::1]:443");
    assert_eq!(
        policy::normalize_destination("2001:db8::1").unwrap(),
        "[2001:db8::1]:443"
    );
}

#[test]
fn normalize_bare_ipv6_lowercases() {
    assert_eq!(
        policy::normalize_destination("FE80::1").unwrap(),
        "[fe80::1]:443"
    );
}

#[test]
fn normalize_rejects_empty() {
    assert!(policy::normalize_destination("").is_err());
    assert!(policy::normalize_destination("  ").is_err());
}

#[test]
fn normalize_rejects_empty_bracketed_host() {
    assert!(policy::normalize_destination("[]").is_err());
    assert!(policy::normalize_destination("[]:443").is_err());
}

#[test]
fn normalize_rejects_missing_close_bracket() {
    assert!(policy::normalize_destination("[::1").is_err());
}

#[test]
fn normalize_rejects_non_numeric_port() {
    assert!(policy::normalize_destination("host:abc").is_err());
}

#[test]
fn normalize_rejects_port_zero() {
    assert!(policy::normalize_destination("host:0").is_err());
    assert!(policy::normalize_destination("[::1]:0").is_err());
}

#[test]
fn normalize_rejects_invalid_multi_colon() {
    assert!(policy::normalize_destination("foo:bar:baz").is_err());
    assert!(policy::normalize_destination("api.example.com:443:extra").is_err());
}

#[test]
fn normalize_rejects_invalid_bracketed_host() {
    assert!(policy::normalize_destination("[not-ipv6]:443").is_err());
}

#[test]
fn normalize_trims_whitespace() {
    assert_eq!(
        policy::normalize_destination("  api.example.com:443  ").unwrap(),
        "api.example.com:443"
    );
}

// ---- Policy: allow / deny ----

#[tokio::test]
async fn policy_allows_matching_cert_and_destination() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_allow(eval(engine.as_ref(), &pki, "api.example.com:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_allows_explicit_non_default_port() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "custom.example.com:8443")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_allow(eval(engine.as_ref(), &pki, "custom.example.com:8443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_wrong_destination() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    match eval(engine.as_ref(), &pki, "evil.example.com:443").await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert_eq!(source_identity.as_deref(), Some(subject.as_str())),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_wrong_port() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_deny(eval(engine.as_ref(), &pki, "api.example.com:8080").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_unknown_extension_value() {
    let subject = unique_test_identity("agent-alpha");
    let unknown_subject = unique_test_identity("agent-unknown");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&unknown_subject);
    let authorized_pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&authorized_pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    match eval(engine.as_ref(), &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert_eq!(source_identity.as_deref(), Some(unknown_subject.as_str())),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_same_identity_and_destination_with_different_key() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let authorized_pki = TestPki::new(&subject);
    let different_key_pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&authorized_pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    match eval(engine.as_ref(), &different_key_pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity,
            reason,
        } => {
            assert_eq!(source_identity.as_deref(), Some(subject.as_str()));
            assert!(
                reason.contains("no active signed permission"),
                "denial should be caused by missing key-bound permission, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_no_cert() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    let ctx = RequestContext {
        peer_certificates: vec![],
        destination: "api.example.com:443".into(),
    };
    match engine.evaluate(&ctx).await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert!(source_identity.is_none()),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

// ---- Default port (443) ----

#[tokio::test]
async fn policy_config_without_port_defaults_to_443() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_allow(eval(engine.as_ref(), &pki, "api.example.com:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_config_without_port_denies_non_443() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_deny(eval(engine.as_ref(), &pki, "api.example.com:8080").await);
    registry.cleanup().await;
}

// ---- IPv6 policy matching ----

#[tokio::test]
async fn policy_ipv6_config_matches_bracketed_request() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry.allow_for_pki(&pki, &subject, "[::1]:8443").await;
    let engine = registry.engine(EXT_OID);
    assert_allow(eval(engine.as_ref(), &pki, "[::1]:8443").await);
    assert_deny(eval(engine.as_ref(), &pki, "[::1]:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_bare_ipv6_config_matches_bracketed_request() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry.allow_for_pki(&pki, &subject, "::1").await;
    let engine = registry.engine(EXT_OID);
    // bare "::1" in config normalizes to "[::1]:443", request "[::1]:443" should match
    assert_allow(eval(engine.as_ref(), &pki, "[::1]:443").await);
    assert_deny(eval(engine.as_ref(), &pki, "[::1]:8080").await);
    registry.cleanup().await;
}

// ---- Case insensitivity ----

#[tokio::test]
async fn policy_destination_matching_is_case_insensitive() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_allow(eval(engine.as_ref(), &pki, "API.EXAMPLE.COM:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_tampered_permission_destination() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    let permission = registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    registry
        .tamper_permission_destination(&permission.permission_id, "evil.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_deny(eval(engine.as_ref(), &pki, "evil.example.com:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_revoked_permission() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    let permission = registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    registry.revoke_permission(&permission.permission_id).await;
    let engine = registry.engine(EXT_OID);
    match eval(engine.as_ref(), &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity,
            reason,
        } => {
            assert_eq!(source_identity.as_deref(), Some(subject.as_str()));
            assert!(
                reason.contains("no active signed permission"),
                "denial should be caused by revoked permission, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_revoked_signer() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    registry.revoke_signer().await;
    let engine = registry.engine(EXT_OID);
    match eval(engine.as_ref(), &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity,
            reason,
        } => {
            assert_eq!(source_identity.as_deref(), Some(subject.as_str()));
            assert!(
                reason.contains("is not active"),
                "denial should be caused by inactive signer, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_signer_scope_violation() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_without_signer_scope_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID);
    assert_deny(eval(engine.as_ref(), &pki, "api.example.com:443").await);
    registry.cleanup().await;
}

// ---- TLS PKI ----

#[test]
fn test_pki_generates_valid_mtls_config() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let pki = TestPki::new("agent-alpha");

    let mut ca_store = RootCertStore::empty();
    ca_store.add(pki.ca_cert_der()).unwrap();

    let _server_config = ServerConfig::builder()
        .with_client_cert_verifier(agent_gateway::tls::db_rooted_client_cert_verifier())
        .with_single_cert(pki.server_cert_chain(), pki.server_key_der())
        .unwrap();

    let _client_config = ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(pki.client_cert_chain(), pki.client_key_der())
        .unwrap();
}

#[test]
fn openssl_spki_extraction_matches_gateway_parser() {
    if Command::new("openssl").arg("version").output().is_err() {
        return;
    }

    let pki = TestPki::new("agent-alpha");
    let cert_der = pki.client_cert.der().to_vec();
    let expected = certificate_spki_der(&cert_der);
    let temp_dir = std::env::temp_dir().join(format!(
        "agent-gateway-spki-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let cert_path = temp_dir.join("client.der");
    std::fs::write(&cert_path, cert_der).unwrap();

    let pubkey = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(&cert_path)
        .args(["-pubkey", "-noout"])
        .output()
        .expect("run openssl x509");
    assert!(
        pubkey.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&pubkey.stderr)
    );

    let mut pkey = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run openssl pkey");
    pkey.stdin
        .as_mut()
        .unwrap()
        .write_all(&pubkey.stdout)
        .unwrap();
    let output = pkey.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "openssl pkey failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected);

    let _ = std::fs::remove_dir_all(temp_dir);
}

// ---- Config validation ----

#[test]
fn config_validates_oid() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "not-a-valid-oid"
database_url = "postgres://example.invalid/agent_gateway"
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_bad_oid.toml");
    std::fs::write(&path, toml).unwrap();
    assert!(agent_gateway::config::Config::load(&path).is_err());
}

#[test]
fn config_requires_exactly_one_database_url_source() {
    let make = |policy: &str| {
        let toml = format!(
            r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
{policy}
"#
        );
        let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
        std::fs::create_dir_all(&tmpdir).ok();
        let path = tmpdir.join(format!("policy_{}.toml", policy.len()));
        std::fs::write(&path, &toml).unwrap();
        agent_gateway::config::Config::load(&path)
    };

    assert!(make("").is_err());
    assert!(make("database_url = \"postgres://example.invalid/agent_gateway\"").is_ok());
    assert!(make("database_url_env = \"TEST_DATABASE_URL\"").is_ok());
    assert!(
        make(
            "database_url = \"postgres://example.invalid/agent_gateway\"\ndatabase_url_env = \"TEST_DATABASE_URL\""
        )
        .is_err()
    );
}

#[test]
fn config_rejects_removed_client_ca_path() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"
client_ca_path = "ca.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
database_url = "postgres://example.invalid/agent_gateway"
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_client_ca_path.toml");
    std::fs::write(&path, toml).unwrap();
    let result = agent_gateway::config::Config::load(&path);
    assert!(
        result.is_err(),
        "client_ca_path should be rejected as an unknown field"
    );
}

#[test]
fn config_rejects_removed_policy_rules() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
database_url = "postgres://example.invalid/agent_gateway"

[[policy.rules]]
extension_value = "x"
allowed_destinations = ["api.example.com"]
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_policy_rules.toml");
    std::fs::write(&path, toml).unwrap();
    assert!(agent_gateway::config::Config::load(&path).is_err());
}

#[test]
fn config_rejects_removed_metrics_bind_field() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"
metrics_bind = "0.0.0.0:9090"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
database_url = "postgres://example.invalid/agent_gateway"
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_metrics_bind.toml");
    std::fs::write(&path, toml).unwrap();
    let result = agent_gateway::config::Config::load(&path);
    assert!(
        result.is_err(),
        "metrics_bind should be rejected as an unknown field"
    );
}

// ---- Proxy Destination parsing ----

fn parse_dest(authority: &str) -> Result<Destination, String> {
    let authority: http::uri::Authority = authority.parse().map_err(|e| format!("{e}"))?;
    Destination::from_authority(&authority)
}

#[test]
fn proxy_dest_hostname_with_port() {
    let d = parse_dest("api.example.com:443").unwrap();
    assert_eq!(d.host, "api.example.com");
    assert_eq!(d.port, 443);
    assert_eq!(d.authority, "api.example.com:443");
}

#[test]
fn proxy_dest_hostname_without_port_defaults_443() {
    let d = parse_dest("api.example.com").unwrap();
    assert_eq!(d.host, "api.example.com");
    assert_eq!(d.port, 443);
    assert_eq!(d.authority, "api.example.com:443");
}

#[test]
fn proxy_dest_hostname_non_default_port() {
    let d = parse_dest("api.example.com:8080").unwrap();
    assert_eq!(d.host, "api.example.com");
    assert_eq!(d.port, 8080);
    assert_eq!(d.authority, "api.example.com:8080");
}

#[test]
fn proxy_dest_hostname_uppercased_is_lowered() {
    let d = parse_dest("API.EXAMPLE.COM:443").unwrap();
    assert_eq!(d.authority, "api.example.com:443");
}

#[test]
fn proxy_dest_ipv6_with_port() {
    let d = parse_dest("[::1]:8443").unwrap();
    assert_eq!(d.host, "::1");
    assert_eq!(d.port, 8443);
    assert_eq!(d.authority, "[::1]:8443");
}

#[test]
fn proxy_dest_ipv6_default_port() {
    let d = parse_dest("[::1]").unwrap();
    assert_eq!(d.host, "::1");
    assert_eq!(d.port, 443);
    assert_eq!(d.authority, "[::1]:443");
}

#[test]
fn proxy_dest_ipv6_full_address() {
    let d = parse_dest("[2001:db8::1]:443").unwrap();
    assert_eq!(d.host, "2001:db8::1");
    assert_eq!(d.port, 443);
    assert_eq!(d.authority, "[2001:db8::1]:443");
}

#[tokio::test]
async fn proxy_dest_ipv6_matches_policy() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry.allow_for_pki(&pki, &subject, "[::1]:8443").await;
    let engine = registry.engine(EXT_OID);

    // Simulate what proxy.rs produces for a CONNECT [::1]:8443 request
    let d = parse_dest("[::1]:8443").unwrap();
    assert_allow(eval(engine.as_ref(), &pki, &d.authority).await);

    // Wrong port should deny
    let d2 = parse_dest("[::1]:443").unwrap();
    assert_deny(eval(engine.as_ref(), &pki, &d2.authority).await);
    registry.cleanup().await;
}
