//! DeepMail Worker — async job consumer and analysis pipeline.
//!
//! Connects to Redis, reads jobs from the email analysis queue,
//! runs the full analysis pipeline, and stores results in SQLite.

mod pipeline;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use deepmail_common::config::DeepMailConfig;
use deepmail_common::db;
use deepmail_common::queue::{RedisQueue, QUEUE_EMAIL_ANALYSIS};

use crate::pipeline::PipelineContext;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Initialize tracing ───────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deepmail_worker=info,deepmail_common=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("DeepMail Worker starting...");

    // ── Load configuration ───────────────────────────────────────────────────
    let config = DeepMailConfig::load()?;
    tracing::info!("Configuration loaded");

    // ── Initialize database pool ─────────────────────────────────────────────
    let db_pool = db::create_pool(&config.database)?;
    tracing::info!("Database pool initialized");

    // ── Connect to Redis ─────────────────────────────────────────────────────
    let mut queue = RedisQueue::new(&config.redis).await?;
    tracing::info!("Redis connection established");

    // ── Generate unique consumer name ────────────────────────────────────────
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let consumer_name = format!("worker-{}-{}", hostname, std::process::id());
    tracing::info!(consumer = %consumer_name, "Worker identity established");

    // ── Main processing loop ─────────────────────────────────────────────────
    tracing::info!("Entering job processing loop (email_analysis queue)...");

    loop {
        // Block for up to 5 seconds waiting for a job
        let job_result = queue
            .dequeue_from(QUEUE_EMAIL_ANALYSIS, &consumer_name, 5000)
            .await;

        match job_result {
            Ok(Some((entry_id, job))) => {
                tracing::info!(
                    job_id = %job.id,
                    job_type = %job.job_type,
                    "Job received"
                );

                // Parse the job payload
                let payload: serde_json::Value = match serde_json::from_str(&job.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(
                            job_id = %job.id,
                            error = %e,
                            "Failed to parse job payload — acknowledging and skipping"
                        );
                        pipeline::mark_failed(&db_pool, &job.id, &format!("Invalid payload: {e}"));
                        let _ = queue.ack_on(QUEUE_EMAIL_ANALYSIS, &entry_id).await;
                        continue;
                    }
                };

                // Build pipeline context
                let email_id = payload["email_id"]
                    .as_str()
                    .unwrap_or(&job.id)
                    .to_string();
                let quarantine_path = payload["quarantine_path"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let sha256 = payload["sha256"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let original_name = payload["original_name"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                let ctx = PipelineContext {
                    email_id: email_id.clone(),
                    quarantine_path,
                    sha256,
                    original_name,
                    db_pool: db_pool.clone(),
                };

                // Run the full analysis pipeline
                match pipeline::run_pipeline(&ctx).await {
                    Ok(()) => {
                        tracing::info!(
                            email_id = %email_id,
                            "Pipeline completed successfully"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            email_id = %email_id,
                            error = %e,
                            "Pipeline failed"
                        );
                        let _ = pipeline::mark_failed(&db_pool, &email_id, &e.to_string());
                    }
                }

                // Acknowledge the job regardless of success/failure
                // (failed jobs are tracked in the DB, not re-queued)
                if let Err(e) = queue.ack_on(QUEUE_EMAIL_ANALYSIS, &entry_id).await {
                    tracing::error!(
                        entry_id = %entry_id,
                        error = %e,
                        "Failed to acknowledge job"
                    );
                }
            }
            Ok(None) => {
                // No job available — continue loop (block timeout expired)
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "Error dequeuing job, backing off...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}
