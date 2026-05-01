use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::policy;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub observability: ObservabilityConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub client_ca_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub otlp_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub client_ext_oid: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub extension_value: String,
    pub allowed_destinations: Vec<String>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.server
            .listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid server.listen_addr: {e}"))?;

        let _oid = x509_parser::oid_registry::Oid::from_str(&self.policy.client_ext_oid)
            .map_err(|e| anyhow::anyhow!("invalid policy.client_ext_oid: {e:?}"))?;

        for (i, rule) in self.policy.rules.iter().enumerate() {
            anyhow::ensure!(
                !rule.extension_value.is_empty(),
                "policy.rules[{i}].extension_value must not be empty"
            );
            anyhow::ensure!(
                !rule.allowed_destinations.is_empty(),
                "policy.rules[{i}].allowed_destinations must not be empty"
            );
            for (j, dest) in rule.allowed_destinations.iter().enumerate() {
                policy::normalize_destination(dest).map_err(|e| {
                    anyhow::anyhow!("policy.rules[{i}].allowed_destinations[{j}]: {e}")
                })?;
            }
        }
        Ok(())
    }
}
