//! DeepMail Worker — Async job consumer and analysis pipeline.
//!
//! Connects to Redis, reads from the `deepmail:jobs` stream using
//! consumer groups, and processes analysis jobs.
//!
//! Phase 1: Skeleton that logs received jobs.
//! Future phases: full analysis pipeline (header parsing, IOC extraction,
//! URL analysis, attachment analysis, threat intel, scoring, etc.)

use std::process;
use tracing_subscriber::EnvFilter;

use deepmail_common::config::AppConfig;
use deepmail_common::queue::RedisQueue;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = AppConfig::load()?;

    // Initialize tracing
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    match config.logging.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .pretty()
                .init();
        }
    }

    // Generate a unique consumer name for this worker instance
    let consumer_name = format!(
        "worker-{}-{}",
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        process::id()
    );

    tracing::info!(consumer = %consumer_name, "DeepMail Worker starting...");

    // Connect to Redis
    let mut queue = RedisQueue::new(&config.redis).await?;
    tracing::info!("Connected to Redis");

    // ── Main consumer loop ───────────────────────────────────────────────────
    tracing::info!("Waiting for jobs...");

    loop {
        // Block for up to 5 seconds waiting for new jobs
        match queue.dequeue_job(&consumer_name, 5000).await {
            Ok(Some((entry_id, job))) => {
                tracing::info!(
                    job_id = %job.id,
                    job_type = %job.job_type,
                    entry_id = %entry_id,
                    "Job received"
                );

                // ── Phase 1: Just log the job ──────────────────────────────
                // Future phases will implement the full analysis pipeline:
                // 1. Header parsing
                // 2. IOC extraction
                // 3. Parallel: URL analysis, attachment analysis, threat intel
                // 4. Graph correlation
                // 5. Similarity detection
                // 6. Threat scoring
                // 7. Campaign assignment
                // 8. Store results
                // 9. Emit WebSocket update

                tracing::info!(
                    job_id = %job.id,
                    payload = %job.payload,
                    "Processing job (Phase 1: skeleton)"
                );

                // Acknowledge the job
                if let Err(e) = queue.ack_job(&entry_id).await {
                    tracing::error!(
                        entry_id = %entry_id,
                        error = %e,
                        "Failed to acknowledge job"
                    );
                } else {
                    tracing::info!(
                        job_id = %job.id,
                        "Job acknowledged"
                    );
                }
            }
            Ok(None) => {
                // No jobs available, continue polling
                tracing::trace!("No jobs available, polling...");
            }
            Err(e) => {
                tracing::error!(error = %e, "Error dequeuing job");
                // Back off on errors to avoid tight error loops
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
}
