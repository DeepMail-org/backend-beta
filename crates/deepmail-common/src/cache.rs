//! Redis caching layer for threat intelligence lookups.
//!
//! Provides namespaced key-value caching with configurable TTL for:
//! - IP reputation lookups
//! - Domain reputation lookups
//! - Hash (file) lookups
//!
//! # Key Schema
//! `deepmail:cache:{type}:{value}` — e.g. `deepmail:cache:ip:1.2.3.4`
//!
//! # Security
//! - All values are JSON-serialized before storage
//! - Keys are sanitized to prevent injection
//! - TTL prevents stale data accumulation

use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};

use crate::errors::DeepMailError;

/// Default cache TTL in seconds (1 hour).
const DEFAULT_TTL_SECS: u64 = 3600;

/// Cache key prefix.
const KEY_PREFIX: &str = "deepmail:cache";

/// Redis-backed cache for threat intelligence data.
#[derive(Clone)]
pub struct ThreatCache {
    conn: MultiplexedConnection,
}

impl ThreatCache {
    /// Create a new cache instance from an existing Redis connection.
    pub fn new(conn: MultiplexedConnection) -> Self {
        Self { conn }
    }

    /// Store a value in the cache with the default TTL.
    pub async fn set<T: Serialize>(
        &self,
        cache_type: &str,
        key: &str,
        value: &T,
    ) -> Result<(), DeepMailError> {
        self.set_with_ttl(cache_type, key, value, DEFAULT_TTL_SECS)
            .await
    }

    /// Store a value in the cache with a custom TTL.
    pub async fn set_with_ttl<T: Serialize>(
        &self,
        cache_type: &str,
        key: &str,
        value: &T,
        ttl_secs: u64,
    ) -> Result<(), DeepMailError> {
        let cache_key = build_key(cache_type, key);
        let json = serde_json::to_string(value)?;

        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(&cache_key, &json, ttl_secs)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Cache SET failed: {e}")))?;

        tracing::debug!(
            cache_type = cache_type,
            key = key,
            ttl = ttl_secs,
            "Cache entry stored"
        );

        Ok(())
    }

    /// Retrieve a value from the cache.
    ///
    /// Returns `None` if the key doesn't exist or has expired.
    pub async fn get<T: DeserializeOwned>(
        &self,
        cache_type: &str,
        key: &str,
    ) -> Result<Option<T>, DeepMailError> {
        let cache_key = build_key(cache_type, key);

        let mut conn = self.conn.clone();
        let result: Option<String> = conn
            .get(&cache_key)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Cache GET failed: {e}")))?;

        match result {
            Some(json) => {
                let value: T = serde_json::from_str(&json)?;
                tracing::debug!(cache_type = cache_type, key = key, "Cache HIT");
                Ok(Some(value))
            }
            None => {
                tracing::debug!(cache_type = cache_type, key = key, "Cache MISS");
                Ok(None)
            }
        }
    }

    /// Check if a key exists in the cache.
    pub async fn exists(&self, cache_type: &str, key: &str) -> Result<bool, DeepMailError> {
        let cache_key = build_key(cache_type, key);
        let mut conn = self.conn.clone();
        let exists: bool = conn
            .exists(&cache_key)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Cache EXISTS failed: {e}")))?;

        Ok(exists)
    }

    /// Delete a key from the cache.
    pub async fn delete(&self, cache_type: &str, key: &str) -> Result<(), DeepMailError> {
        let cache_key = build_key(cache_type, key);
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(&cache_key)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Cache DEL failed: {e}")))?;

        Ok(())
    }

    // ─── Typed convenience methods ───────────────────────────────────────────

    /// Cache an IP lookup result.
    pub async fn cache_ip_lookup<T: Serialize>(
        &self,
        ip: &str,
        data: &T,
    ) -> Result<(), DeepMailError> {
        self.set("ip", ip, data).await
    }

    /// Get a cached IP lookup result.
    pub async fn get_ip_lookup<T: DeserializeOwned>(
        &self,
        ip: &str,
    ) -> Result<Option<T>, DeepMailError> {
        self.get("ip", ip).await
    }

    /// Cache a domain lookup result.
    pub async fn cache_domain_lookup<T: Serialize>(
        &self,
        domain: &str,
        data: &T,
    ) -> Result<(), DeepMailError> {
        self.set("domain", domain, data).await
    }

    /// Get a cached domain lookup result.
    pub async fn get_domain_lookup<T: DeserializeOwned>(
        &self,
        domain: &str,
    ) -> Result<Option<T>, DeepMailError> {
        self.get("domain", domain).await
    }

    /// Cache a hash lookup result.
    pub async fn cache_hash_lookup<T: Serialize>(
        &self,
        hash: &str,
        data: &T,
    ) -> Result<(), DeepMailError> {
        self.set("hash", hash, data).await
    }

    /// Get a cached hash lookup result.
    pub async fn get_hash_lookup<T: DeserializeOwned>(
        &self,
        hash: &str,
    ) -> Result<Option<T>, DeepMailError> {
        self.get("hash", hash).await
    }
}

/// Build a namespaced cache key.
///
/// Sanitizes the key component to prevent Redis key injection.
fn build_key(cache_type: &str, key: &str) -> String {
    // Sanitize: replace any colons or whitespace in the key to prevent
    // accidental namespace collisions
    let safe_key: String = key
        .chars()
        .map(|c| {
            if c == ':' || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect();
    format!("{KEY_PREFIX}:{cache_type}:{safe_key}")
}
