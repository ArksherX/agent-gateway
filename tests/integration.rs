mod common;

use std::sync::Arc;

use common::TestPki;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use agent_gateway::config::{PolicyConfig, PolicyRule};
use agent_gateway::policy::{self, PolicyDecision, PolicyEngine, RequestContext, TomlPolicyEngine};
use agent_gateway::proxy::Destination;

fn test_policy_config() -> PolicyConfig {
    PolicyConfig {
        client_ext_oid: "1.3.6.1.4.1.57264.1.1".into(),
        rules: vec![PolicyRule {
            extension_value: "agent-alpha".into(),
            allowed_destinations: vec![
                "api.example.com:443".into(),
                "custom.example.com:8443".into(),
            ],
        }],
    }
}

fn test_policy_config_default_port() -> PolicyConfig {
    PolicyConfig {
        client_ext_oid: "1.3.6.1.4.1.57264.1.1".into(),
        rules: vec![PolicyRule {
            extension_value: "agent-alpha".into(),
            allowed_destinations: vec!["api.example.com".into()],
        }],
    }
}

async fn eval(engine: &TomlPolicyEngine, pki: &TestPki, dest: &str) -> PolicyDecision {
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
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
    assert_allow(eval(&engine, &pki, "api.example.com:443").await);
}

#[tokio::test]
async fn policy_allows_explicit_non_default_port() {
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
    assert_allow(eval(&engine, &pki, "custom.example.com:8443").await);
}

#[tokio::test]
async fn policy_denies_wrong_destination() {
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
    match eval(&engine, &pki, "evil.example.com:443").await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert_eq!(source_identity.as_deref(), Some("agent-alpha")),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
}

#[tokio::test]
async fn policy_denies_wrong_port() {
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
    assert_deny(eval(&engine, &pki, "api.example.com:8080").await);
}

#[tokio::test]
async fn policy_denies_unknown_extension_value() {
    let pki = TestPki::new("agent-unknown");
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
    match eval(&engine, &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert_eq!(source_identity.as_deref(), Some("agent-unknown")),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
}

#[tokio::test]
async fn policy_denies_no_cert() {
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
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
}

// ---- Default port (443) ----

#[tokio::test]
async fn policy_config_without_port_defaults_to_443() {
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config_default_port()).unwrap();
    assert_allow(eval(&engine, &pki, "api.example.com:443").await);
}

#[tokio::test]
async fn policy_config_without_port_denies_non_443() {
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config_default_port()).unwrap();
    assert_deny(eval(&engine, &pki, "api.example.com:8080").await);
}

// ---- IPv6 policy matching ----

#[tokio::test]
async fn policy_ipv6_config_matches_bracketed_request() {
    let config = PolicyConfig {
        client_ext_oid: "1.3.6.1.4.1.57264.1.1".into(),
        rules: vec![PolicyRule {
            extension_value: "agent-alpha".into(),
            allowed_destinations: vec!["[::1]:8443".into()],
        }],
    };
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(config).unwrap();
    assert_allow(eval(&engine, &pki, "[::1]:8443").await);
    assert_deny(eval(&engine, &pki, "[::1]:443").await);
}

#[tokio::test]
async fn policy_bare_ipv6_config_matches_bracketed_request() {
    let config = PolicyConfig {
        client_ext_oid: "1.3.6.1.4.1.57264.1.1".into(),
        rules: vec![PolicyRule {
            extension_value: "agent-alpha".into(),
            allowed_destinations: vec!["::1".into()],
        }],
    };
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(config).unwrap();
    // bare "::1" in config normalizes to "[::1]:443", request "[::1]:443" should match
    assert_allow(eval(&engine, &pki, "[::1]:443").await);
    assert_deny(eval(&engine, &pki, "[::1]:8080").await);
}

// ---- Case insensitivity ----

#[tokio::test]
async fn policy_destination_matching_is_case_insensitive() {
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(test_policy_config()).unwrap();
    assert_allow(eval(&engine, &pki, "API.EXAMPLE.COM:443").await);
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

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(ca_store.clone()))
        .build()
        .unwrap();
    let _server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(pki.server_cert_chain(), pki.server_key_der())
        .unwrap();

    let _client_config = ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(pki.client_cert_chain(), pki.client_key_der())
        .unwrap();
}

// ---- Config validation ----

#[test]
fn config_validates_oid() {
    let config = PolicyConfig {
        client_ext_oid: "not-a-valid-oid".into(),
        rules: vec![PolicyRule {
            extension_value: "x".into(),
            allowed_destinations: vec!["a:443".into()],
        }],
    };
    assert!(TomlPolicyEngine::new(config).is_err());
}

#[test]
fn config_rejects_malformed_destination() {
    let make = |dest: &str| {
        let toml = format!(
            r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"
client_ca_path = "ca.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"

[[policy.rules]]
extension_value = "x"
allowed_destinations = ["{dest}"]
"#
        );
        let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
        std::fs::create_dir_all(&tmpdir).ok();
        let path = tmpdir.join(format!("bad_{}.toml", dest.replace([':', '[', ']'], "_")));
        std::fs::write(&path, &toml).unwrap();
        agent_gateway::config::Config::load(&path)
    };

    // Empty destination
    assert!(make("").is_err());
    // Non-numeric port
    assert!(make("host:abc").is_err());
    // Missing close bracket
    assert!(make("[::1").is_err());

    // Valid ones should pass
    assert!(make("api.example.com").is_ok());
    assert!(make("api.example.com:443").is_ok());
    assert!(make("[::1]:443").is_ok());
    assert!(make("[::1]").is_ok());
}

#[test]
fn config_rejects_removed_metrics_bind_field() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"
client_ca_path = "ca.pem"

[observability]
log_level = "info"
metrics_bind = "0.0.0.0:9090"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"

[[policy.rules]]
extension_value = "x"
allowed_destinations = ["api.example.com"]
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
    let config = PolicyConfig {
        client_ext_oid: "1.3.6.1.4.1.57264.1.1".into(),
        rules: vec![PolicyRule {
            extension_value: "agent-alpha".into(),
            allowed_destinations: vec!["[::1]:8443".into()],
        }],
    };
    let pki = TestPki::new("agent-alpha");
    let engine = TomlPolicyEngine::new(config).unwrap();

    // Simulate what proxy.rs produces for a CONNECT [::1]:8443 request
    let d = parse_dest("[::1]:8443").unwrap();
    assert_allow(eval(&engine, &pki, &d.authority).await);

    // Wrong port should deny
    let d2 = parse_dest("[::1]:443").unwrap();
    assert_deny(eval(&engine, &pki, &d2.authority).await);
}
