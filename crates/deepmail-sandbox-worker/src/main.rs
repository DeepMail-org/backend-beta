use std::time::{Duration, Instant};

use anyhow::Result;
use deepmail_common::config::DeepMailConfig;
use deepmail_common::db;
use deepmail_common::models::new_id;
use deepmail_common::queue::{RedisQueue, QUEUE_SANDBOX};
use deepmail_sandbox::executor::docker::{
    timed_out_report, DockerSandboxConfig, DockerSandboxExecutor,
};
use deepmail_sandbox::executor::SandboxExecutor;
use deepmail_sandbox::model::{SandboxJob, SandboxJobKind, SandboxStatus, UrlDetonationTask};
use deepmail_sandbox::security::url_guard::validate_url_for_sandbox;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deepmail_sandbox_worker=info,deepmail_common=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = DeepMailConfig::load()?;
    let db_pool = db::init_pool(&config.database)?;
    let mut queue = RedisQueue::new(&config.redis).await?;

    let executor = DockerSandboxExecutor::new(DockerSandboxConfig {
        image: config.sandbox.docker_image.clone(),
        network: config.sandbox.docker_network.clone(),
        seccomp_profile: config.sandbox.seccomp_profile.clone(),
        cpu_limit: config.sandbox.cpu_limit.clone(),
        memory_limit: config.sandbox.memory_limit.clone(),
        pids_limit: config.sandbox.pids_limit,
        timeout_ms: config.sandbox.execution_timeout_ms,
    });

    let consumer_name = format!("sandbox-worker-{}", std::process::id());
    tracing::info!(consumer = %consumer_name, "Sandbox worker running");

    loop {
        match queue
            .dequeue_from(QUEUE_SANDBOX, &consumer_name, 5000)
            .await
        {
            Ok(Some((entry_id, job))) => {
                if let Err(e) =
                    process_sandbox_job(&db_pool, &mut queue, &executor, &config, &job.payload)
                        .await
                {
                    tracing::error!(error = %e, "Sandbox job failed");
                }
                let _ = queue.ack_on(QUEUE_SANDBOX, &entry_id).await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "Sandbox dequeue error");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn process_sandbox_job(
    db_pool: &deepmail_common::db::DbPool,
    queue: &mut RedisQueue,
    executor: &DockerSandboxExecutor,
    config: &DeepMailConfig,
    payload: &str,
) -> Result<()> {
    let job: SandboxJob = serde_json::from_str(payload)?;
    queue
        .publish_progress(
            &config.sandbox.progress_channel,
            &job.email_id,
            "sandbox_execution",
            "started",
            Some("sandbox task started"),
        )
        .await?;

    let started = Instant::now();
    match job.kind {
        SandboxJobKind::Url => {
            validate_url_for_sandbox(&job.target)?;
            let task = UrlDetonationTask {
                email_id: job.email_id.clone(),
                url: job.target.clone(),
                timeout_ms: job.timeout_ms,
            };

            let timed = tokio::time::timeout(
                Duration::from_millis(executor.timeout_ms()),
                executor.execute_url(task),
            )
            .await;

            match timed {
                Ok(Ok(handle)) => {
                    let report = executor.get_report(&handle).await?;
                    store_report(
                        db_pool,
                        &report.email_id,
                        report.url.as_deref().unwrap_or(""),
                        report.final_url.as_deref(),
                        report.redirects,
                        report
                            .network_calls
                            .iter()
                            .map(|n| serde_json::to_value(n).unwrap_or(serde_json::Value::Null))
                            .collect(),
                        report.suspicious_behavior,
                        report.status,
                        report.error_message,
                        report.execution_time_ms,
                    )?;
                    queue
                        .publish_progress(
                            &config.sandbox.progress_channel,
                            &job.email_id,
                            "sandbox_execution",
                            "completed",
                            Some("sandbox url detonation completed"),
                        )
                        .await?;
                }
                Ok(Err(e)) => {
                    store_report(
                        db_pool,
                        &job.email_id,
                        &job.target,
                        None,
                        Vec::new(),
                        Vec::new(),
                        vec!["execution_failure".to_string()],
                        SandboxStatus::Failed,
                        Some(e.to_string()),
                        started.elapsed().as_millis() as u64,
                    )?;
                    queue
                        .publish_progress(
                            &config.sandbox.progress_channel,
                            &job.email_id,
                            "sandbox_execution",
                            "failed",
                            Some("sandbox url detonation failed"),
                        )
                        .await?;
                }
                Err(_) => {
                    let report = timed_out_report(
                        &job.email_id,
                        &job.target,
                        started.elapsed().as_millis() as u64,
                    );
                    store_report(
                        db_pool,
                        &report.email_id,
                        report.url.as_deref().unwrap_or(""),
                        report.final_url.as_deref(),
                        report.redirects,
                        report
                            .network_calls
                            .iter()
                            .map(|n| serde_json::to_value(n).unwrap_or(serde_json::Value::Null))
                            .collect(),
                        report.suspicious_behavior,
                        report.status,
                        report.error_message,
                        report.execution_time_ms,
                    )?;
                    queue
                        .publish_progress(
                            &config.sandbox.progress_channel,
                            &job.email_id,
                            "sandbox_execution",
                            "timed_out",
                            Some("sandbox url detonation timed out"),
                        )
                        .await?;
                }
            }
        }
        SandboxJobKind::File => {
            // File detonation placeholder for Phase 4 basic version.
            store_report(
                db_pool,
                &job.email_id,
                &job.target,
                None,
                Vec::new(),
                Vec::new(),
                vec!["file_detonation_metadata_only".to_string()],
                SandboxStatus::Completed,
                None,
                started.elapsed().as_millis() as u64,
            )?;
            queue
                .publish_progress(
                    &config.sandbox.progress_channel,
                    &job.email_id,
                    "sandbox_execution",
                    "completed",
                    Some("sandbox file metadata simulation completed"),
                )
                .await?;
        }
    }

    Ok(())
}

fn store_report(
    db_pool: &deepmail_common::db::DbPool,
    email_id: &str,
    url: &str,
    final_url: Option<&str>,
    redirects: Vec<String>,
    network_calls: Vec<serde_json::Value>,
    suspicious_behavior: Vec<String>,
    status: SandboxStatus,
    error_message: Option<String>,
    execution_time_ms: u64,
) -> Result<()> {
    let status_str = match status {
        SandboxStatus::Running => "running",
        SandboxStatus::Completed => "completed",
        SandboxStatus::Failed => "failed",
        SandboxStatus::TimedOut => "timed_out",
    };

    let conn = db_pool.get()?;
    conn.execute(
        "INSERT INTO sandbox_reports (
            id, attachment_id, email_id, sandbox_type, verdict, report_data,
            submitted_at, completed_at, url, final_url, redirects, network_calls,
            suspicious_behavior, execution_time_ms, status, error_message
        ) VALUES (?1, '', ?2, 'container', ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            new_id(),
            email_id,
            status_str,
            "{}",
            chrono::Utc::now().to_rfc3339(),
            url,
            final_url,
            serde_json::to_string(&redirects)?,
            serde_json::to_string(&network_calls)?,
            serde_json::to_string(&suspicious_behavior)?,
            execution_time_ms as i64,
            status_str,
            error_message,
        ],
    )?;
    Ok(())
}
