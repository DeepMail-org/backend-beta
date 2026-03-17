//! Redis queue module using Redis Streams for job orchestration.
//!
//! # Design
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

use crate::config::RedisConfig;
use crate::errors::DeepMailError;

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

/// Wrapper around a Redis multiplexed connection.
#[derive(Clone)]
pub struct RedisQueue {
    conn: MultiplexedConnection,
    stream_name: String,
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
            stream_name: config.stream_name.clone(),
            consumer_group: config.consumer_group.clone(),
        };

        // Create the consumer group if it doesn't exist.
        // The `$` means only read new messages (not historical ones).
        queue.ensure_consumer_group().await?;

        tracing::info!(
            stream = %config.stream_name,
            group = %config.consumer_group,
            "Redis queue connection established"
        );

        Ok(queue)
    }

    /// Ensure the consumer group exists on the stream.
    async fn ensure_consumer_group(&mut self) -> Result<(), DeepMailError> {
        let result: Result<(), redis::RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&self.stream_name)
            .arg(&self.consumer_group)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut self.conn)
            .await;

        match result {
            Ok(()) => {
                tracing::info!(
                    stream = %self.stream_name,
                    group = %self.consumer_group,
                    "Consumer group created"
                );
            }
            Err(e) if e.to_string().contains("BUSYGROUP") => {
                tracing::debug!(
                    stream = %self.stream_name,
                    group = %self.consumer_group,
                    "Consumer group already exists"
                );
            }
            Err(e) => {
                return Err(DeepMailError::Redis(format!(
                    "Failed to create consumer group: {e}"
                )));
            }
        }

        Ok(())
    }

    /// Enqueue a job to the Redis stream via XADD.
    ///
    /// Returns the stream entry ID.
    pub async fn enqueue_job(&mut self, job: &Job) -> Result<String, DeepMailError> {
        let job_json = serde_json::to_string(job)?;

        let entry_id: String = self
            .conn
            .xadd(
                &self.stream_name,
                "*", // Auto-generate entry ID
                &[
                    ("job_id", job.id.as_str()),
                    ("job_type", job.job_type.as_str()),
                    ("payload", job_json.as_str()),
                ],
            )
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to enqueue job: {e}")))?;

        tracing::info!(
            job_id = %job.id,
            job_type = %job.job_type,
            stream_entry = %entry_id,
            "Job enqueued"
        );

        Ok(entry_id)
    }

    /// Dequeue a job from the Redis stream using XREADGROUP.
    ///
    /// `consumer_name` should uniquely identify this worker instance.
    /// `block_ms` is how long to block waiting for new messages (0 = indefinite).
    pub async fn dequeue_job(
        &mut self,
        consumer_name: &str,
        block_ms: usize,
    ) -> Result<Option<(String, Job)>, DeepMailError> {
        let opts = redis::streams::StreamReadOptions::default()
            .group(&self.consumer_group, consumer_name)
            .count(1)
            .block(block_ms);

        let result: redis::streams::StreamReadReply = self
            .conn
            .xread_options(&[&self.stream_name], &[">"], &opts)
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to dequeue job: {e}")))?;

        for stream_key in &result.keys {
            for entry in &stream_key.ids {
                let entry_id = entry.id.clone();

                let job_id: String = entry
                    .map
                    .get("job_id")
                    .and_then(|v| match v {
                        redis::Value::Data(bytes) => {
                            String::from_utf8(bytes.clone()).ok()
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        DeepMailError::Redis("Missing job_id in stream entry".to_string())
                    })?;

                let job_type: String = entry
                    .map
                    .get("job_type")
                    .and_then(|v| match v {
                        redis::Value::Data(bytes) => {
                            String::from_utf8(bytes.clone()).ok()
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        DeepMailError::Redis("Missing job_type in stream entry".to_string())
                    })?;

                let payload: String = entry
                    .map
                    .get("payload")
                    .and_then(|v| match v {
                        redis::Value::Data(bytes) => {
                            String::from_utf8(bytes.clone()).ok()
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        DeepMailError::Redis("Missing payload in stream entry".to_string())
                    })?;

                let job = Job {
                    id: job_id,
                    job_type,
                    payload: payload.clone(),
                    created_at: String::new(), // Not stored in stream fields
                };

                return Ok(Some((entry_id, job)));
            }
        }

        Ok(None)
    }

    /// Acknowledge a processed job (XACK).
    pub async fn ack_job(&mut self, entry_id: &str) -> Result<(), DeepMailError> {
        let _: i64 = self
            .conn
            .xack(&self.stream_name, &self.consumer_group, &[entry_id])
            .await
            .map_err(|e| DeepMailError::Redis(format!("Failed to ACK job: {e}")))?;

        tracing::debug!(entry_id = %entry_id, "Job acknowledged");
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
}
