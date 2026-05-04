use std::str::FromStr;

use async_trait::async_trait;
use chrono::SecondsFormat;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use rustls_pki_types::CertificateDer;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::registry::{CandidatePermission, RegistryStore};

pub struct RequestContext {
    pub peer_certificates: Vec<CertificateDer<'static>>,
    pub destination: String,
}

pub enum PolicyDecision {
    Allow {
        source_identity: String,
    },
    Deny {
        source_identity: Option<String>,
        reason: String,
    },
}

#[async_trait]
pub trait PolicyEngine: Send + Sync + 'static {
    async fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision;
}

pub struct PostgresPolicyEngine {
    client_ext_oid: Oid<'static>,
    registry: RegistryStore,
}

impl PostgresPolicyEngine {
    pub fn new(client_ext_oid: &str, registry: RegistryStore) -> anyhow::Result<Self> {
        let client_ext_oid = parse_client_ext_oid(client_ext_oid)?;

        Ok(Self {
            client_ext_oid,
            registry,
        })
    }
}

pub fn parse_client_ext_oid(value: &str) -> anyhow::Result<Oid<'static>> {
    Oid::from_str(value).map_err(|e| anyhow::anyhow!("invalid policy.client_ext_oid: {e:?}"))
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
        dest.parse::<std::net::Ipv6Addr>().map_err(|_| {
            anyhow::anyhow!(
                "ambiguous multi-colon destination {dest:?}; use [ipv6]:port for IPv6 with port"
            )
        })?;
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
impl PolicyEngine for PostgresPolicyEngine {
    async fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision {
        let source_identity =
            match certificate_identity(&ctx.peer_certificates, &self.client_ext_oid) {
                Ok(source_identity) => source_identity,
                Err(reason) => {
                    return PolicyDecision::Deny {
                        source_identity: None,
                        reason,
                    };
                }
            };

        let normalized_dest = match normalize_destination(&ctx.destination) {
            Ok(d) => d,
            Err(e) => {
                return PolicyDecision::Deny {
                    source_identity: Some(source_identity),
                    reason: format!("invalid destination: {e}"),
                };
            }
        };

        let candidates = match self
            .registry
            .candidate_permissions(&source_identity, &normalized_dest)
            .await
        {
            Ok(candidates) => candidates,
            Err(e) => {
                return PolicyDecision::Deny {
                    source_identity: Some(source_identity),
                    reason: format!("authorization registry lookup failed: {e:#}"),
                };
            }
        };

        let mut last_denial = None;
        for candidate in candidates {
            match self.evaluate_candidate(&candidate, &normalized_dest).await {
                Ok(()) => return PolicyDecision::Allow { source_identity },
                Err(reason) => last_denial = Some(reason),
            }
        }

        PolicyDecision::Deny {
            source_identity: Some(source_identity.clone()),
            reason: last_denial.unwrap_or_else(|| {
                format!(
                    "no active signed permission for destination {:?} and identity {:?}",
                    ctx.destination, source_identity
                )
            }),
        }
    }
}

impl PostgresPolicyEngine {
    async fn evaluate_candidate(
        &self,
        candidate: &CandidatePermission,
        normalized_dest: &str,
    ) -> Result<(), String> {
        if !candidate.signer_active_now {
            return Err(format!(
                "signing key {:?} is not active (not_before {}, not_after {}, revoked_at {:?})",
                candidate.signing_key_id,
                candidate.signer_not_before,
                candidate.signer_not_after,
                candidate.signer_revoked_at
            ));
        }

        verify_signature(candidate).map_err(|e| {
            format!(
                "invalid permission signature for {:?}: {e}",
                candidate.permission_id
            )
        })?;

        let has_scope = self
            .registry
            .signer_has_scope(
                &candidate.signing_key_id,
                normalized_dest,
                candidate.permission_not_before,
                candidate.permission_not_after,
            )
            .await
            .map_err(|e| format!("signer scope lookup failed: {e:#}"))?;
        if !has_scope {
            return Err(format!(
                "signing key {:?} is not allowed to delegate {:?}",
                candidate.signing_key_id, normalized_dest
            ));
        }

        Ok(())
    }
}

pub fn certificate_identity(
    peer_certificates: &[CertificateDer<'static>],
    client_ext_oid: &Oid<'_>,
) -> Result<String, String> {
    // The leaf (end-entity) certificate is always first in the chain;
    // remaining entries are intermediates used for chain-of-trust validation.
    let Some(peer_cert_der) = peer_certificates.first() else {
        return Err("no client certificate".into());
    };

    let cert = match X509Certificate::from_der(peer_cert_der.as_ref()) {
        Ok((_, cert)) => cert,
        Err(e) => return Err(format!("failed to parse client certificate: {e}")),
    };

    let Some(ext) = cert
        .tbs_certificate
        .extensions()
        .iter()
        .find(|e| e.oid == *client_ext_oid)
    else {
        return Err(format!("missing required extension {client_ext_oid}"));
    };

    match x509_parser::asn1_rs::Utf8String::from_der(ext.value) {
        Ok((remaining, v)) => {
            if !remaining.is_empty() {
                return Err("extension value contains trailing bytes".into());
            }
            Ok(v.string().to_owned())
        }
        Err(e) => Err(format!("failed to decode extension as UTF8String: {e}")),
    }
}

fn verify_signature(candidate: &CandidatePermission) -> anyhow::Result<()> {
    anyhow::ensure!(
        candidate.signer_algorithm == "ecdsa_p256_sha256",
        "unsupported signer algorithm {:?}",
        candidate.signer_algorithm
    );

    let verifying_key = VerifyingKey::from_public_key_der(&candidate.signer_public_key_spki_der)?;
    let signature = Signature::from_der(&candidate.signature)?;
    verifying_key.verify(&canonical_permission_bytes(candidate), &signature)?;
    Ok(())
}

fn canonical_permission_bytes(candidate: &CandidatePermission) -> Vec<u8> {
    format!(
        "agent-gateway-permission-v1\npermission_id={}\nsigning_key_id={}\nsubject_identity={}\ndestination={}\nnot_before={}\nnot_after={}\n",
        candidate.permission_id,
        candidate.signing_key_id,
        candidate.subject_identity,
        candidate.destination,
        candidate
            .permission_not_before
            .to_rfc3339_opts(SecondsFormat::Micros, true),
        candidate
            .permission_not_after
            .to_rfc3339_opts(SecondsFormat::Micros, true),
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn canonical_permission_bytes_are_stable() {
        let candidate = CandidatePermission {
            permission_id: "perm-1".to_owned(),
            subject_identity: "agent-alpha".to_owned(),
            destination: "api.example.com:443".to_owned(),
            signing_key_id: "org-alice".to_owned(),
            permission_not_before: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).single().unwrap(),
            permission_not_after: Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).single().unwrap(),
            signature: vec![],
            signer_algorithm: "ecdsa_p256_sha256".to_owned(),
            signer_public_key_spki_der: vec![],
            signer_not_before: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap(),
            signer_not_after: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).single().unwrap(),
            signer_revoked_at: None,
            signer_active_now: true,
        };

        assert_eq!(
            canonical_permission_bytes(&candidate),
            b"agent-gateway-permission-v1\npermission_id=perm-1\nsigning_key_id=org-alice\nsubject_identity=agent-alpha\ndestination=api.example.com:443\nnot_before=2026-05-01T00:00:00.000000Z\nnot_after=2026-06-01T00:00:00.000000Z\n"
        );
    }
}
