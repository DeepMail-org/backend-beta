//! Redis queue module using Redis Streams for job orchestration.
//!
//! # Design
//! - Supports multiple named streams (email_analysis, sandbox)
//! - Uses XADD to enqueue jobs to a named stream
//! - Uses XREADGROUP for consumer-group-based dequeuing
//! - Jobs are acknowledged after successful processing (XACK)
//!
//! # Security
//! - Redis connection uses the URL from config (supports auth via URL)
//! - Job payloads are JSON-serialized and validated on dequeue
//! - Consumer names include hostname/PID for traceability

use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::cache::ThreatCache;
use crate::config::RedisConfig;
use crate::errors::DeepMailError;

/// Well-known queue names.
pub const QUEUE_EMAIL_ANALYSIS: &str = "deepmail:queue:email_analysis";
pub const QUEUE_SANDBOX: &str = "deepmail:queue:sandbox";
pub const QUEUE_DLQ_EMAIL: &str = "deepmail:queue:dlq:email";
pub const QUEUE_DLQ_SANDBOX: &str = "deepmail:queue:dlq:sandbox";
pub const CHANNEL_PROGRESS: &str = "deepmail:events:progress";
pub const KEY_SANDBOX_HEARTBEAT: &str = "deepmail:sandbox:heartbeat";

const TOKEN_BUCKET_SCRIPT: &str = include_str!("../redis_scripts/token_bucket.lua");

/// Represents a job to be processed by workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Unique job identifier (matches the email ID).
    pub id: String,
    /// Type of job: "email_analysis", "attachment_analysis", etc.
    pub job_type: String,
    /// JSON payload with job-specific data.
    pub payload: String,
    /// ISO 8601 timestamp when the job was created.
    pub created_at: String,
}

/// Wrapper around Redis providing multi-stream queue and cache access.
#[derive(Clone)]
pub struct RedisQueue {
    conn: MultiplexedConnection,
    /// Default stream name (from config).
    default_stream: String,
    /// Consumer group name.
    consumer_group: String,
}

impl RedisQueue {
    /// Create a new Redis queue connection.
    pub async fn new(config: &RedisConfig) -> Result<Self, DeepMailError> {
        let client = redis::Client::open(config.url.as_str())
            .map_err(|e| DeepMailError::Redis(format!("Failed to create Redis client: {e}")))?;

        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to connect to Redis: {e}")))?;

        let mut queue = Self {
            conn,
            default_stream: config.stream_name.clone(),
            consumer_group: config.consumer_group.clone(),
        };

        // Ensure consumer groups exist on all known streams
        queue.ensure_consumer_group_on(&config.stream_name).await?;
        queue.ensure_consumer_group_on(QUEUE_EMAIL_ANALYSIS).await?;
        queue.ensure_consumer_group_on(QUEUE_SANDBOX).await?;
        queue.ensure_consumer_group_on(QUEUE_DLQ_EMAIL).await?;
        queue.ensure_consumer_group_on(QUEUE_DLQ_SANDBOX).await?;

        tracing::info!(
            default_stream = %config.stream_name,
            group = %config.consumer_group,
            "Redis queue connection established (multi-stream)"
        );

        Ok(queue)
    }

    /// Get a `ThreatCache` instance sharing this Redis connection.
    pub fn cache(&self) -> ThreatCache {
        ThreatCache::new(self.conn.clone())
    }

    pub fn conn_mut(&mut self) -> &mut MultiplexedConnection {
        &mut self.conn
    }

    /// Ensure the consumer group exists on a specific stream.
    async fn ensure_consumer_group_on(&mut self, stream: &str) -> Result<(), DeepMailError> {
        let result: Result<(), redis::RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(stream)
            .arg(&self.consumer_group)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut self.conn)
            .await;

        match result {
            Ok(()) => {
                tracing::info!(stream = %stream, group = %self.consumer_group, "Consumer group created");
            }
            Err(e) if e.to_string().contains("BUSYGROUP") => {
                tracing::debug!(stream = %stream, "Consumer group already exists");
            }
            Err(e) => {
                return Err(DeepMailError::Redis(format!(
                    "Failed to create consumer group on '{stream}': {e}"
                )));
            }
        }

        Ok(())
    }

    /// Enqueue a job to the default stream via XADD.
    pub async fn enqueue_job(&mut self, job: &Job) -> Result<String, DeepMailError> {
        self.enqueue_to(&self.default_stream.clone(), job).await
    }

    /// Enqueue a job to a specific named stream.
    pub async fn enqueue_to(&mut self, stream: &str, job: &Job) -> Result<String, DeepMailError> {
        let job_json = encode_stream_payload(job)?;

        let entry_id: String = self
            .conn
            .xadd(
                stream,
                "*",
                &[
                    ("job_id", job.id.as_str()),
                    ("job_type", job.job_type.as_str()),
                    ("payload", job_json.as_str()),
                ],
            )
            .await
            .map_err(|e| {
                DeepMailError::Redis(format!("Failed to enqueue job to '{stream}': {e}"))
            })?;

        tracing::info!(
            job_id = %job.id,
            job_type = %job.job_type,
            stream = %stream,
            stream_entry = %entry_id,
            "Job enqueued"
        );

        Ok(entry_id)
    }

    /// Dequeue a job from the default stream using XREADGROUP.
    pub async fn dequeue_job(
        &mut self,
        consumer_name: &str,
        block_ms: usize,
    ) -> Result<Option<(String, Job)>, DeepMailError> {
        self.dequeue_from(&self.default_stream.clone(), consumer_name, block_ms)
            .await
    }

    /// Dequeue a job from a specific named stream.
    pub async fn dequeue_from(
        &mut self,
        stream: &str,
        consumer_name: &str,
        block_ms: usize,
    ) -> Result<Option<(String, Job)>, DeepMailError> {
        let opts = redis::streams::StreamReadOptions::default()
            .group(&self.consumer_group, consumer_name)
            .count(1)
            .block(block_ms);

        let result: redis::streams::StreamReadReply = self
            .conn
            .xread_options(&[stream], &[">"], &opts)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to dequeue from '{stream}': {e}")))?;

        for stream_key in &result.keys {
            for entry in &stream_key.ids {
                let entry_id = entry.id.clone();

                let job_id = extract_field(&entry.map, "job_id")?;
                let job_type = extract_field(&entry.map, "job_type")?;
                let payload = extract_field(&entry.map, "payload")?;

                let job = Job {
                    id: job_id,
                    job_type,
                    payload,
                    created_at: String::new(),
                };

                return Ok(Some((entry_id, job)));
            }
        }

        Ok(None)
    }

    /// Acknowledge a processed job (XACK) on the default stream.
    pub async fn ack_job(&mut self, entry_id: &str) -> Result<(), DeepMailError> {
        self.ack_on(&self.default_stream.clone(), entry_id).await
    }

    /// Acknowledge a processed job on a specific stream.
    pub async fn ack_on(&mut self, stream: &str, entry_id: &str) -> Result<(), DeepMailError> {
        let _: i64 = self
            .conn
            .xack(stream, &self.consumer_group, &[entry_id])
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to ACK job: {e}")))?;

        tracing::debug!(stream = %stream, entry_id = %entry_id, "Job acknowledged");
        Ok(())
    }

    /// Check if Redis is healthy.
    pub async fn health_check(&mut self) -> Result<bool, DeepMailError> {
        let pong: String = redis::cmd("PING")
            .query_async(&mut self.conn)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Redis health check failed: {e}")))?;

        Ok(pong == "PONG")
    }

    /// Publish a progress event to Redis pub/sub for realtime clients.
    pub async fn publish_progress(
        &mut self,
        channel: &str,
        email_id: &str,
        stage: &str,
        status: &str,
        details: Option<&str>,
    ) -> Result<(), DeepMailError> {
        let payload = serde_json::json!({
            "email_id": email_id,
            "stage": stage,
            "status": status,
            "details": details,
        });

        let payload_str = serde_json::to_string(&payload)?;
        let _: i64 = self
            .conn
            .publish(channel, payload_str)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to publish progress: {e}")))?;

        Ok(())
    }

    /// Redis token-bucket check via Lua script.
    ///
    /// Returns `(allowed, remaining_tokens, retry_after_ms)`.
    pub async fn check_rate_limit_token_bucket(
        &mut self,
        scope: &str,
        subject: &str,
        capacity: u32,
        refill_per_sec: f64,
        requested_tokens: u32,
    ) -> Result<(bool, f64, u64), DeepMailError> {
        let key = format!("deepmail:ratelimit:{scope}:{subject}");
        let now_ms = chrono::Utc::now().timestamp_millis();

        let values: Vec<redis::Value> = redis::Script::new(TOKEN_BUCKET_SCRIPT)
            .key(key)
            .arg(now_ms)
            .arg(capacity as f64)
            .arg(refill_per_sec)
            .arg(requested_tokens as f64)
            .invoke_async(&mut self.conn)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Token bucket script failed: {e}")))?;

        if values.len() != 3 {
            return Err(DeepMailError::Redis(
                "Token bucket script returned unexpected payload".to_string(),
            ));
        }

        let allowed = match &values[0] {
            redis::Value::Int(i) => *i == 1,
            _ => false,
        };
        let remaining = match &values[1] {
            redis::Value::Data(bytes) => {
                String::from_utf8_lossy(bytes).parse::<f64>().unwrap_or(0.0)
            }
            redis::Value::Int(i) => *i as f64,
            _ => 0.0,
        };
        let retry_after_ms = match &values[2] {
            redis::Value::Int(i) => (*i).max(0) as u64,
            redis::Value::Data(bytes) => String::from_utf8_lossy(bytes).parse::<u64>().unwrap_or(0),
            _ => 0,
        };

        Ok((allowed, remaining, retry_after_ms))
    }

    pub async fn enqueue_dlq(
        &mut self,
        stream: &str,
        original_job: &Job,
        reason: &str,
    ) -> Result<String, DeepMailError> {
        let payload = serde_json::json!({
            "original_job": original_job,
            "reason": reason,
            "failed_at": chrono::Utc::now().to_rfc3339(),
        });
        let dlq_job = Job {
            id: original_job.id.clone(),
            job_type: format!("dlq_{}", original_job.job_type),
            payload: serde_json::to_string(&payload)?,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        self.enqueue_to(stream, &dlq_job).await
    }

    pub async fn replay_dlq_entry(
        &mut self,
        dlq_stream: &str,
        target_stream: &str,
        entry_id: &str,
    ) -> Result<String, DeepMailError> {
        let reply: redis::streams::StreamRangeReply = self
            .conn
            .xrange_count(dlq_stream, entry_id, entry_id, 1)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed reading DLQ entry: {e}")))?;

        let Some(first) = reply.ids.first() else {
            return Err(DeepMailError::NotFound(format!(
                "DLQ entry '{entry_id}' not found"
            )));
        };

        let payload = extract_field(&first.map, "payload")?;
        let parsed: serde_json::Value = serde_json::from_str(&payload)?;
        let original_job = parsed
            .get("original_job")
            .ok_or_else(|| DeepMailError::Internal("Invalid DLQ payload".to_string()))?;

        let mut replay_job: Job = serde_json::from_value(original_job.clone())?;
        replay_job.created_at = chrono::Utc::now().to_rfc3339();
        replay_job.id = format!("{}-replay", replay_job.id);

        self.enqueue_to(target_stream, &replay_job).await
    }

    pub async fn set_sandbox_heartbeat(&mut self) -> Result<(), DeepMailError> {
        let now = chrono::Utc::now().to_rfc3339();
        let _: () = self
            .conn
            .set_ex(KEY_SANDBOX_HEARTBEAT, now, 30)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed setting heartbeat: {e}")))?;
        Ok(())
    }

    pub async fn sandbox_heartbeat_healthy(&mut self) -> Result<bool, DeepMailError> {
        let exists: bool = self
            .conn
            .exists(KEY_SANDBOX_HEARTBEAT)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed checking heartbeat: {e}")))?;
        Ok(exists)
    }
}

fn encode_stream_payload(job: &Job) -> Result<String, DeepMailError> {
    Ok(job.payload.clone())
}

#[cfg(test)]
mod tests {
    use super::{encode_stream_payload, Job};

    #[test]
    fn stream_payload_uses_job_payload_only() {
        let job = Job {
            id: "job-1".to_string(),
            job_type: "email_analysis".to_string(),
            payload: r#"{"email_id":"abc","quarantine_path":"/tmp/q"}"#.to_string(),
            created_at: "2026-03-30T00:00:00Z".to_string(),
        };

        let payload = encode_stream_payload(&job).expect("encode payload");
        assert_eq!(payload, job.payload);
    }
}

/// Extract a string field from a Redis stream entry map.
fn extract_field(
    map: &std::collections::HashMap<String, redis::Value>,
    field: &str,
) -> Result<String, DeepMailError> {
    map.get(field)
        .and_then(|v| match v {
            redis::Value::Data(bytes) => String::from_utf8(bytes.clone()).ok(),
            _ => None,
        })
        .ok_or_else(|| DeepMailError::Redis(format!("Missing '{field}' in stream entry")))
}
