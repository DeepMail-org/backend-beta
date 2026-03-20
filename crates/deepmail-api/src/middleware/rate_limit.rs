//! In-memory token-bucket rate limiter per IP address.
//!
//! # Design
//! - Uses a `DashMap` (or `std::sync::Mutex<HashMap>`) for concurrent access
//! - Each IP gets a token bucket with configurable rate and burst
//! - Tokens replenish at a fixed rate per second
//! - Requests that exceed the bucket capacity receive `429 Too Many Requests`
//!
//! # Security
//! - Prevents brute-force attacks on upload/auth endpoints
//! - Uses the connecting IP (from Axum's `ConnectInfo`)
//! - Does NOT trust X-Forwarded-For (proxy spoofing protection)
//! - Stale entries are periodically cleaned up
//!
//! # Limitations
//! - In-memory only — not shared across instances
//! - For multi-instance deployments, use Redis-based rate limiting

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum tokens (burst capacity).
    pub burst: u32,
    /// Token replenishment rate per second.
    pub rate_per_second: f64,
}

/// A token bucket for a single client.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// In-memory rate limiter using token buckets per IP.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(rate_per_second: u32, burst: u32) -> Self {
        Self {
            config: RateLimiterConfig {
                burst,
                rate_per_second: rate_per_second as f64,
            },
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a request from `ip` should be allowed.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.config.burst as f64,
            last_refill: now,
        });

        // Replenish tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.config.rate_per_second).min(self.config.burst as f64);
        bucket.last_refill = now;

        // Try to consume one token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            tracing::warn!(ip = %ip, "Rate limit exceeded");
            false
        }
    }

    /// Remove stale entries older than `max_age_secs` seconds.
    ///
    /// Call this periodically to prevent unbounded memory growth.
    pub async fn cleanup(&self, max_age_secs: u64) {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();
        let before = buckets.len();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill).as_secs() < max_age_secs);

        let removed = before - buckets.len();
        if removed > 0 {
            tracing::debug!(
                removed = removed,
                remaining = buckets.len(),
                "Rate limiter cleanup"
            );
        }
    }
}
