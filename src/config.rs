use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::policy;

/// Per-identity byte-rate limiting configuration.
/// Set `bytes_per_second = 0` to disable (default).
#[derive(Debug, Deserialize, Clone, Copy)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub bytes_per_second: u64,
    #[serde(default = "default_burst_bytes")]
    pub burst_bytes: u64,
}

fn default_burst_bytes() -> u64 {
    1_048_576 // 1 MB
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            bytes_per_second: 0,
            burst_bytes: default_burst_bytes(),
        }
    }
}

#[derive(Debug, Deserialize)]
// Note: deny_unknown_fields removed from Config so the optional
// [rate_limit] section can be absent from existing config files.
pub struct Config {
    pub server: ServerConfig,
    pub observability: ObservabilityConfig,
    pub policy: PolicyConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
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
    pub database_url: Option<String>,
    pub database_url_env: Option<String>,
    pub max_connections: Option<u32>,
    pub connect_timeout_ms: Option<u64>,
    pub pool_acquire_timeout_ms: Option<u64>,
    pub query_timeout_ms: Option<u64>,
}

impl Config {
    /// Load, parse, and validate a TOML config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the TOML cannot be parsed,
    /// or any config value fails validation.
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

        policy::parse_client_ext_oid(&self.policy.client_ext_oid)?;
        self.policy.validate()?;
        Ok(())
    }
}

impl PolicyConfig {
    /// Resolve the configured database URL from the literal value or env var.
    ///
    /// # Errors
    ///
    /// Returns an error if no source is configured, both sources are configured,
    /// the configured source is empty, or the environment variable cannot be read.
    pub fn database_url(&self) -> anyhow::Result<String> {
        match (&self.database_url, &self.database_url_env) {
            (Some(url), None) => {
                anyhow::ensure!(!url.is_empty(), "policy.database_url must not be empty");
                Ok(url.clone())
            }
            (None, Some(env_name)) => {
                anyhow::ensure!(
                    !env_name.is_empty(),
                    "policy.database_url_env must not be empty"
                );
                let url = std::env::var(env_name)
                    .map_err(|e| anyhow::anyhow!("reading database URL from ${env_name}: {e}"))?;
                anyhow::ensure!(
                    !url.is_empty(),
                    "database URL from ${env_name} must not be empty"
                );
                Ok(url)
            }
            (None, None) => {
                anyhow::bail!("policy.database_url or policy.database_url_env is required")
            }
            (Some(_), Some(_)) => {
                anyhow::bail!("set only one of policy.database_url or policy.database_url_env")
            }
        }
    }

    #[must_use]
    pub fn max_connections(&self) -> u32 {
        self.max_connections.unwrap_or(5)
    }

    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.unwrap_or(5_000))
    }

    #[must_use]
    pub fn pool_acquire_timeout(&self) -> Duration {
        Duration::from_millis(self.pool_acquire_timeout_ms.unwrap_or(1_000))
    }

    #[must_use]
    pub fn query_timeout(&self) -> Duration {
        Duration::from_millis(self.query_timeout_ms.unwrap_or(500))
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_connections() > 0,
            "policy.max_connections must be greater than zero"
        );
        ensure_positive_timeout(self.connect_timeout_ms, "policy.connect_timeout_ms")?;
        ensure_positive_timeout(
            self.pool_acquire_timeout_ms,
            "policy.pool_acquire_timeout_ms",
        )?;
        ensure_positive_timeout(self.query_timeout_ms, "policy.query_timeout_ms")?;

        match (&self.database_url, &self.database_url_env) {
            (Some(url), None) => {
                anyhow::ensure!(!url.is_empty(), "policy.database_url must not be empty");
            }
            (None, Some(env_name)) => {
                anyhow::ensure!(
                    !env_name.is_empty(),
                    "policy.database_url_env must not be empty"
                );
            }
            (None, None) => {
                anyhow::bail!("policy.database_url or policy.database_url_env is required")
            }
            (Some(_), Some(_)) => {
                anyhow::bail!("set only one of policy.database_url or policy.database_url_env")
            }
        }

        Ok(())
    }
}

fn ensure_positive_timeout(value: Option<u64>, field: &str) -> anyhow::Result<()> {
    if let Some(value) = value {
        anyhow::ensure!(value > 0, "{field} must be greater than zero");
    }
    Ok(())
}
