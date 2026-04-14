use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use async_trait::async_trait;
use rustls_pki_types::CertificateDer;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::config::PolicyConfig;

pub struct RequestContext {
    pub peer_certificates: Vec<CertificateDer<'static>>,
    pub destination: String,
}

pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

#[async_trait]
pub trait PolicyEngine: Send + Sync + 'static {
    async fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision;
}

pub struct TomlPolicyEngine {
    client_ext_oid: Oid<'static>,
    /// extension_value -> set of allowed "host:port" destinations (lowercase-normalized)
    rules: HashMap<String, HashSet<String>>,
}

impl TomlPolicyEngine {
    pub fn new(config: PolicyConfig) -> anyhow::Result<Self> {
        let client_ext_oid = Oid::from_str(&config.client_ext_oid)
            .map_err(|e| anyhow::anyhow!("invalid policy.client_ext_oid: {e:?}"))?;

        let mut rules = HashMap::<String, HashSet<String>>::new();
        for rule in config.rules {
            let mut normalized = HashSet::new();
            for dest in &rule.allowed_destinations {
                normalized.insert(normalize_destination(dest).map_err(|e| {
                    anyhow::anyhow!(
                        "invalid destination {dest:?} in rule {:?}: {e}",
                        rule.extension_value
                    )
                })?);
            }
            rules
                .entry(rule.extension_value.clone())
                .or_default()
                .extend(normalized);
        }

        Ok(Self {
            client_ext_oid,
            rules,
        })
    }

}

/// Parse a destination string into canonical lowercase `host:port` (or
/// `[ipv6]:port`) form.  Port defaults to 443 when omitted.
///
/// Accepted input forms:
///   - `hostname`           → `hostname:443`
///   - `hostname:port`      → `hostname:port`
///   - `[ipv6]:port`        → `[ipv6]:port`
///   - `[ipv6]`             → `[ipv6]:443`
///   - bare `ipv6` (colons, no brackets) → `[ipv6]:443`
pub fn normalize_destination(dest: &str) -> anyhow::Result<String> {
    let dest = dest.trim();
    anyhow::ensure!(!dest.is_empty(), "destination must not be empty");

    let (host, port) = if dest.starts_with('[') {
        let close = dest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("missing closing bracket in {dest:?}"))?;
        let host_inner = &dest[1..close];
        anyhow::ensure!(!host_inner.is_empty(), "empty host in bracketed address");
        host_inner
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("invalid IPv6 address in {dest:?}"))?;
        let rest = &dest[close + 1..];
        let port = if rest.is_empty() {
            443
        } else if let Some(port_str) = rest.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|e| anyhow::anyhow!("invalid port in {dest:?}: {e}"))?
        } else {
            anyhow::bail!("unexpected characters after bracket in {dest:?}");
        };
        (host_inner.to_owned(), port)
    } else if dest.matches(':').count() > 1 {
        // Multiple colons without brackets: treat as bare IPv6, validate.
        dest.parse::<std::net::Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("ambiguous multi-colon destination {dest:?}; use [ipv6]:port for IPv6 with port"))?;
        (dest.to_owned(), 443)
    } else if let Some((host, port_str)) = dest.rsplit_once(':') {
        match port_str.parse::<u16>() {
            Ok(p) => (host.to_owned(), p),
            Err(_) => anyhow::bail!("invalid port in {dest:?}"),
        }
    } else {
        (dest.to_owned(), 443)
    };

    anyhow::ensure!(!host.is_empty(), "empty host in {dest:?}");
    anyhow::ensure!(port != 0, "port 0 is not valid in {dest:?}");

    let lower_host = host.to_lowercase();
    if lower_host.contains(':') {
        Ok(format!("[{lower_host}]:{port}"))
    } else {
        Ok(format!("{lower_host}:{port}"))
    }
}

#[async_trait]
impl PolicyEngine for TomlPolicyEngine {
    async fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision {
        // The leaf (end-entity) certificate is always first in the chain;
        // remaining entries are intermediates used for chain-of-trust validation.
        let Some(peer_cert_der) = ctx.peer_certificates.first() else {
            return PolicyDecision::Deny {
                reason: "no client certificate".into(),
            };
        };

        let cert = match X509Certificate::from_der(peer_cert_der.as_ref()) {
            Ok((_, cert)) => cert,
            Err(e) => {
                return PolicyDecision::Deny {
                    reason: format!("failed to parse client certificate: {e}"),
                };
            }
        };

        let Some(ext) = cert
            .tbs_certificate
            .extensions()
            .iter()
            .find(|e| e.oid == self.client_ext_oid)
        else {
            return PolicyDecision::Deny {
                reason: format!("missing required extension {}", self.client_ext_oid),
            };
        };

        let ext_value = match x509_parser::asn1_rs::Utf8String::from_der(ext.value) {
            Ok((remaining, v)) => {
                if !remaining.is_empty() {
                    return PolicyDecision::Deny {
                        reason: "extension value contains trailing bytes".into(),
                    };
                }
                v.string()
            }
            Err(e) => {
                return PolicyDecision::Deny {
                    reason: format!("failed to decode extension as UTF8String: {e}"),
                };
            }
        };

        let Some(allowed) = self.rules.get(&ext_value) else {
            return PolicyDecision::Deny {
                reason: format!("no rules for extension value {ext_value:?}"),
            };
        };

        let normalized_dest = match normalize_destination(&ctx.destination) {
            Ok(d) => d,
            Err(e) => {
                return PolicyDecision::Deny {
                    reason: format!("invalid destination: {e}"),
                };
            }
        };
        if allowed.contains(&normalized_dest) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny {
                reason: format!(
                    "destination {:?} not allowed for {:?}",
                    ctx.destination, ext_value
                ),
            }
        }
    }
}
