//! DeepMail Worker — async job consumer and analysis pipeline.
//!
//! Connects to Redis Streams, reads jobs from the email analysis queue,
//! runs the full analysis pipeline, and stores results in SQLite.
//!
//! # Architecture
//! - Single Tokio runtime, multi-threaded
//! - Redis Streams consumer group for reliable job delivery
//! - One `PipelineContext` per job, sharing the DB pool and `ThreatCache`
//! - All analysis stages are non-blocking async

mod pipeline;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{Mutex, Semaphore};

use deepmail_common::config::DeepMailConfig;
use deepmail_common::db;
use deepmail_common::queue::{Job, RedisQueue, QUEUE_DLQ_EMAIL, QUEUE_EMAIL_ANALYSIS};

use crate::pipeline::PipelineContext;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Load configuration ────────────────────────────────────────────────────
    let config = DeepMailConfig::load()?;

    // ── Tracing initialisation ────────────────────────────────────────────────
    deepmail_common::telemetry::init_tracing(
        &config.logging,
        &config.observability,
        "deepmail-worker",
    );

    tracing::info!("DeepMail Worker starting...");
    tracing::info!("Configuration loaded");

    if let Err(err) = pipeline::geo_intel::validate_geoip_database_freshness(&config.intel) {
        if config.intel.fail_on_stale_geoip {
            return Err(err);
        }
        tracing::warn!(error = %err, "GeoLite2 freshness check warning");
    }

    // ── Initialise database pool ──────────────────────────────────────────────
    let db_pool = db::init_pool(&config.database)?;
    tracing::info!("Database pool initialised");

    {
        let calibration_pool = db_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
            loop {
                interval.tick().await;
                if let Err(err) = pipeline::calibration::run_calibration_job(&calibration_pool) {
                    tracing::warn!(error = %err, "Calibration job failed");
                }
            }
        });
    }

    // ── Connect to Redis and set up consumer group ────────────────────────────
    let queue = Arc::new(Mutex::new(RedisQueue::new(&config.redis).await?));
    tracing::info!("Redis connection established");

    // ── Create shared ThreatCache handle (no global Mutex) ────────────────────
    let threat_cache = {
        let queue_guard = queue.lock().await;
        queue_guard.cache()
    };
    tracing::info!("Threat cache initialised");

    // ── Generate unique consumer name ─────────────────────────────────────────
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let consumer_name = format!("worker-{}-{}", hostname, std::process::id());
    tracing::info!(consumer = %consumer_name, "Worker identity established");

    let concurrency_limit = config.worker.max_concurrent_jobs.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency_limit));
    tracing::info!(concurrency_limit, "Worker concurrency limit set");

    // ── Main processing loop ──────────────────────────────────────────────────
    tracing::info!("Entering job processing loop (email_analysis queue)...");

    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        // Block up to 5 seconds for a job (XREADGROUP with BLOCK 5000)
        let job_result = {
            let mut guard = queue.lock().await;
            guard
                .dequeue_from(QUEUE_EMAIL_ANALYSIS, &consumer_name, 5000)
                .await
        };

        match job_result {
            Ok(Some((entry_id, job))) => {
                let db_pool = db_pool.clone();
                let queue = Arc::clone(&queue);
                let config = config.clone();
                let cache = threat_cache.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    tracing::info!(job_id = %job.id, job_type = %job.job_type, "Job received");

                    let payload: serde_json::Value = match parse_payload_value(&job.payload) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::error!(job_id = %job.id, error = %e, "Invalid payload");
                            let _ = pipeline::mark_failed(
                                &db_pool,
                                &job.id,
                                &format!("Invalid payload: {e}"),
                            );
                            let mut q = queue.lock().await;
                            let _ = q.ack_on(QUEUE_EMAIL_ANALYSIS, &entry_id).await;
                            return;
                        }
                    };

                    let email_id = payload["email_id"].as_str().unwrap_or(&job.id).to_string();
                    let quarantine_path = payload["quarantine_path"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let sha256 = payload["sha256"].as_str().unwrap_or("").to_string();
                    let original_name = payload["original_name"].as_str().unwrap_or("").to_string();
                    let user_id = payload["submitted_by"].as_str().map(ToString::to_string);
                    let trace_id = payload["trace_id"].as_str().map(ToString::to_string);

                    let ctx = PipelineContext {
                        email_id: email_id.clone(),
                        quarantine_path,
                        sha256,
                        original_name,
                        db_pool: db_pool.clone(),
                        cache,
                        redis: config.redis.clone(),
                        pipeline: config.pipeline.clone(),
                        intel: config.intel.clone(),
                        sandbox: config.sandbox.clone(),
                        features: config.features.clone(),
                        tenant: config.tenant.clone(),
                        circuit_breaker: config.circuit_breaker.clone(),
                        user_id,
                        trace_id,
                    };

                    match pipeline::run_pipeline(&ctx).await {
                        Ok(()) => tracing::info!(email_id = %email_id, "Pipeline completed"),
                        Err(e) => {
                            tracing::error!(email_id = %email_id, error = %e, "Pipeline failed");
                            let attempt = payload["attempt"].as_u64().unwrap_or(0) as u32;
                            let max_attempts = payload["max_attempts"]
                                .as_u64()
                                .unwrap_or(config.reliability.max_retry_attempts as u64)
                                as u32;

                            if attempt + 1 < max_attempts {
                                let backoff = (config.reliability.retry_base_backoff_ms
                                    * (1u64 << attempt))
                                    .min(config.reliability.retry_max_backoff_ms);
                                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;

                                let mut retry_payload = payload.clone();
                                retry_payload["attempt"] = serde_json::json!(attempt + 1);
                                retry_payload["max_attempts"] = serde_json::json!(max_attempts);
                                retry_payload["last_error"] = serde_json::json!(e.to_string());

                                let retry_job = Job {
                                    id: job.id.clone(),
                                    job_type: job.job_type.clone(),
                                    payload: serde_json::to_string(&retry_payload)
                                        .unwrap_or_else(|_| job.payload.clone()),
                                    created_at: deepmail_common::models::now_utc(),
                                };

                                let mut q = queue.lock().await;
                                let _ = q.enqueue_to(QUEUE_EMAIL_ANALYSIS, &retry_job).await;
                                tracing::warn!(email_id = %email_id, attempt = attempt + 1, max_attempts, "Retried email job");
                            } else {
                                let _ = pipeline::mark_failed(&db_pool, &email_id, &e.to_string());
                                let mut q = queue.lock().await;
                                let original_job = Job {
                                    id: job.id.clone(),
                                    job_type: job.job_type.clone(),
                                    payload: job.payload.clone(),
                                    created_at: deepmail_common::models::now_utc(),
                                };
                                let _ = q
                                    .enqueue_dlq(QUEUE_DLQ_EMAIL, &original_job, &e.to_string())
                                    .await;
                            }
                        }
                    }

                    let mut q = queue.lock().await;
                    if let Err(e) = q.ack_on(QUEUE_EMAIL_ANALYSIS, &entry_id).await {
                        tracing::error!(entry_id = %entry_id, error = %e, "ACK failed");
                    }
                });
            }

            Ok(None) => {
                // Block timeout expired — no job available, continue
                drop(permit);
                continue;
            }

            Err(e) => {
                drop(permit);
                tracing::error!(error = %e, "Error dequeuing job, backing off 2s...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

fn parse_payload_value(raw: &str) -> Result<serde_json::Value, serde_json::Error> {
    let parsed: serde_json::Value = serde_json::from_str(raw)?;
    if let Some(inner) = parsed.get("payload").and_then(|v| v.as_str()) {
        if let Ok(nested) = serde_json::from_str::<serde_json::Value>(inner) {
            return Ok(nested);
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::parse_payload_value;

    #[test]
    fn parses_raw_payload() {
        let payload = r#"{"email_id":"abc","quarantine_path":"/tmp/q"}"#;
        let parsed = parse_payload_value(payload).expect("parse payload");
        assert_eq!(parsed["email_id"], "abc");
    }

    #[test]
    fn parses_legacy_wrapped_payload() {
        let wrapped = r#"{"id":"job-1","job_type":"email_analysis","payload":"{\"email_id\":\"abc\",\"quarantine_path\":\"/tmp/q\"}","created_at":"2026-03-30T00:00:00Z"}"#;
        let parsed = parse_payload_value(wrapped).expect("parse wrapped payload");
        assert_eq!(parsed["email_id"], "abc");
    }
}
