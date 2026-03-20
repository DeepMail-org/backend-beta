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
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use deepmail_common::config::DeepMailConfig;
use deepmail_common::db;
use deepmail_common::queue::{RedisQueue, QUEUE_EMAIL_ANALYSIS};

use crate::pipeline::PipelineContext;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Tracing initialisation ────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deepmail_worker=info,deepmail_common=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("DeepMail Worker starting...");

    // ── Load configuration ────────────────────────────────────────────────────
    let config = DeepMailConfig::load()?;
    tracing::info!("Configuration loaded");

    // ── Initialise database pool ──────────────────────────────────────────────
    let db_pool = db::init_pool(&config.database)?;
    tracing::info!("Database pool initialised");

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

                    let payload: serde_json::Value = match serde_json::from_str(&job.payload) {
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
                        sandbox: config.sandbox.clone(),
                        features: config.features.clone(),
                        tenant: config.tenant.clone(),
                        user_id,
                        trace_id,
                    };

                    match pipeline::run_pipeline(&ctx).await {
                        Ok(()) => tracing::info!(email_id = %email_id, "Pipeline completed"),
                        Err(e) => {
                            tracing::error!(email_id = %email_id, error = %e, "Pipeline failed");
                            let _ = pipeline::mark_failed(&db_pool, &email_id, &e.to_string());
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
