#![allow(dead_code)]
// src/rate_limit.rs
//
// Per-identity byte-rate limiting for the agent gateway.
//
// Design: token bucket (governor crate) keyed by identity string.
// State is in-memory — appropriate for single-node weight enclave
// deployment. See PR description for multi-node tradeoffs.

use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::warn;

/// Registry of per-identity rate limiters.
/// `Arc<DashMap<...>>` so it can be shared across tokio tasks without a Mutex.
pub type RateLimiterRegistry = Arc<DashMap<String, Arc<DefaultDirectRateLimiter>>>;

/// Create a new empty registry.
#[must_use]
pub fn new_registry() -> RateLimiterRegistry {
    Arc::new(DashMap::new())
}

/// Get the rate limiter for an identity, creating one if it doesn't exist.
///
/// # Panics
///
/// Panics if `bytes_per_second` is zero. The call site is responsible for
/// checking the config before calling this (0 = disabled = don't call).
#[must_use]
pub fn get_or_create(
    registry: &DashMap<String, Arc<DefaultDirectRateLimiter>>,
    identity: &str,
    bytes_per_second: u32,
    burst_bytes: u32,
) -> Arc<DefaultDirectRateLimiter> {
    if let Some(entry) = registry.get(identity) {
        return Arc::clone(entry.value());
    }

    let bps = NonZeroU32::new(bytes_per_second).expect("bytes_per_second must be > 0");
    let burst = NonZeroU32::new(burst_bytes).unwrap_or(NonZeroU32::new(1).unwrap());

    let quota = Quota::per_second(bps).allow_burst(burst);
    let limiter = Arc::new(RateLimiter::direct(quota));
    registry.insert(identity.to_string(), Arc::clone(&limiter));
    limiter
}

/// Copy data from `src` to `dst` while respecting the rate limit.
///
/// Acquires `buf.len()` tokens from the limiter, waiting if the bucket is
/// depleted, then writes the chunk to `dst`.
///
/// # Errors
///
/// Returns an `io::Error` if the write to `dst` fails.
///
/// # Panics
///
/// Will not panic in practice; the inner `unwrap` is on `NonZeroU32::new(1)`
/// which is always `Some`.
pub async fn rate_limited_write(
    limiter: &DefaultDirectRateLimiter,
    identity: &str,
    dst: &mut (impl AsyncWrite + Unpin),
    buf: &[u8],
) -> std::io::Result<()> {
    let n = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    if n == 0 {
        return Ok(());
    }

    let cells = NonZeroU32::new(n).unwrap_or(NonZeroU32::new(1).unwrap());

    match limiter.check_n(cells) {
        Ok(_) => {}
        Err(_insufficient) => {
            warn!(
                identity = %identity,
                bytes = n,
                "rate limit reached, throttling"
            );
            if let Err(_e) = limiter.until_n_ready(cells).await {
                tokio::time::sleep(Duration::from_millis(
                    (u64::from(n) * 1000) / u64::from(cells.get()).max(1),
                ))
                .await;
            }
        }
    }

    dst.write_all(buf).await
}

/// Full bidirectional copy with rate limiting on client→destination direction.
///
/// Rate limiting is applied only to outbound (agent→destination) traffic
/// since that is the exfiltration direction. Inbound (response) traffic
/// is copied without rate limiting.
///
/// Returns `(bytes_from_client, bytes_from_dest)`.
///
/// # Errors
///
/// Returns an `io::Error` if any read or write on either stream fails.
pub async fn copy_with_rate_limit<C, D>(
    client: &mut C,
    dest: &mut D,
    limiter: Arc<DefaultDirectRateLimiter>,
    identity: &str,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf = vec![0u8; 65536];
    let mut dest_buf = vec![0u8; 65536];
    let mut from_client: u64 = 0;
    let mut from_dest: u64 = 0;

    loop {
        tokio::select! {
            result = client.read(&mut client_buf) => {
                let n = result?;
                if n == 0 { break; }
                from_client += n as u64;
                rate_limited_write(&limiter, identity, dest, &client_buf[..n]).await?;
            }

            result = dest.read(&mut dest_buf) => {
                let n = result?;
                if n == 0 { break; }
                from_dest += n as u64;
                client.write_all(&dest_buf[..n]).await?;
            }
        }
    }

    Ok((from_client, from_dest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_get_or_create_returns_same_limiter() {
        let registry = DashMap::new();
        let l1 = get_or_create(&registry, "agent-1", 1000, 1000);
        let l2 = get_or_create(&registry, "agent-1", 1000, 1000);
        assert!(Arc::ptr_eq(&l1, &l2));
    }

    #[test]
    fn test_different_identities_have_different_limiters() {
        let registry = DashMap::new();
        let l1 = get_or_create(&registry, "agent-1", 1000, 1000);
        let l2 = get_or_create(&registry, "agent-2", 1000, 1000);
        assert!(!Arc::ptr_eq(&l1, &l2));
    }

    #[tokio::test]
    async fn test_rate_limit_slows_high_throughput() {
        let registry = DashMap::new();
        let limiter = get_or_create(&registry, "test-agent", 1000, 100);

        let mut sink = Vec::new();
        let data = vec![0u8; 2000];

        let start = Instant::now();
        rate_limited_write(&limiter, "test-agent", &mut sink, &data)
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(900),
            "rate limit not applied: elapsed {elapsed:?}",
        );
        assert_eq!(sink.len(), 2000);
    }
}
