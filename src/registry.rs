use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;

pub const EXPECTED_SCHEMA_VERSION: i32 = 1;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct RegistryStore {
    pool: PgPool,
    query_timeout: Duration,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CandidatePermission {
    pub permission_id: String,
    pub subject_identity: String,
    pub destination: String,
    pub signing_key_id: String,
    pub permission_not_before: DateTime<Utc>,
    pub permission_not_after: DateTime<Utc>,
    pub signature: Vec<u8>,
    pub signer_algorithm: String,
    pub signer_public_key_spki_der: Vec<u8>,
    pub signer_not_before: DateTime<Utc>,
    pub signer_not_after: DateTime<Utc>,
    pub signer_revoked_at: Option<DateTime<Utc>>,
    pub signer_active_now: bool,
}

impl RegistryStore {
    pub fn new(pool: PgPool, query_timeout: Duration) -> Self {
        Self {
            pool,
            query_timeout,
        }
    }

    pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
        MIGRATOR
            .run(pool)
            .await
            .context("running authorization registry migrations")
    }

    pub async fn verify_schema_version(pool: &PgPool) -> anyhow::Result<()> {
        let version = sqlx::query_scalar::<_, i32>(
            "SELECT version FROM agent_gateway_schema_version ORDER BY version DESC LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .context("reading authorization registry schema version")?;

        anyhow::ensure!(
            version == EXPECTED_SCHEMA_VERSION,
            "authorization registry schema version {version} does not match expected {EXPECTED_SCHEMA_VERSION}"
        );
        Ok(())
    }

    pub async fn candidate_permissions(
        &self,
        subject_identity: &str,
        destination: &str,
    ) -> anyhow::Result<Vec<CandidatePermission>> {
        let query = sqlx::query_as::<_, CandidatePermission>(
            r#"
            SELECT
                p.permission_id,
                p.subject_identity,
                p.destination,
                p.signing_key_id,
                p.not_before AS permission_not_before,
                p.not_after AS permission_not_after,
                p.signature,
                s.algorithm AS signer_algorithm,
                s.public_key_spki_der AS signer_public_key_spki_der,
                s.not_before AS signer_not_before,
                s.not_after AS signer_not_after,
                s.revoked_at AS signer_revoked_at,
                (
                    s.revoked_at IS NULL
                    AND s.not_before <= now()
                    AND s.not_after > now()
                ) AS signer_active_now
            FROM permission_registry p
            JOIN principal_signing_keys s ON s.key_id = p.signing_key_id
            WHERE p.subject_identity = $1
              AND p.destination = $2
              AND p.revoked_at IS NULL
              AND p.not_before <= now()
              AND p.not_after > now()
            ORDER BY p.not_after DESC
            LIMIT 16
            "#,
        )
        .bind(subject_identity)
        .bind(destination);

        tokio::time::timeout(self.query_timeout, query.fetch_all(&self.pool))
            .await
            .context("authorization registry permission lookup timed out")?
            .context("querying authorization registry permissions")
    }

    pub async fn signer_has_scope(
        &self,
        signing_key_id: &str,
        subject_identity: &str,
        destination: &str,
        permission_not_before: DateTime<Utc>,
        permission_not_after: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let query = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM principal_key_permissions
                WHERE signing_key_id = $1
                  AND subject_identity = $2
                  AND destination = $3
                  AND revoked_at IS NULL
                  AND not_before <= now()
                  AND not_after > now()
                  AND not_before <= $4
                  AND not_after >= $5
            )
            "#,
        )
        .bind(signing_key_id)
        .bind(subject_identity)
        .bind(destination)
        .bind(permission_not_before)
        .bind(permission_not_after);

        tokio::time::timeout(self.query_timeout, query.fetch_one(&self.pool))
            .await
            .context("authorization registry signer scope lookup timed out")?
            .context("querying authorization registry signer scope")
    }
}
