use std::time::{Duration, Instant};

use anyhow::Result;
use deepmail_common::circuit_breaker::CircuitBreaker;
use deepmail_common::config::DeepMailConfig;
use deepmail_common::db;
use deepmail_common::models::new_id;
use deepmail_common::queue::{Job, RedisQueue, QUEUE_DLQ_SANDBOX, QUEUE_SANDBOX};
use deepmail_common::reuse;
use deepmail_sandbox::executor::docker::{
    timed_out_report, DockerSandboxConfig, DockerSandboxExecutor,
};
use deepmail_sandbox::executor::SandboxExecutor;
use deepmail_sandbox::model::{SandboxJob, SandboxJobKind, SandboxStatus, UrlDetonationTask};
use deepmail_sandbox::security::url_guard::validate_url_for_sandbox;

#[tokio::main]
async fn main() -> Result<()> {
    let config = DeepMailConfig::load()?;
    deepmail_common::telemetry::init_tracing(
        &config.logging,
        &config.observability,
        "deepmail-sandbox-worker",
    );

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
        let _ = queue.set_sandbox_heartbeat().await;
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
                    let mut payload: serde_json::Value =
                        serde_json::from_str(&job.payload).unwrap_or(serde_json::json!({}));
                    let attempt = payload["attempt"].as_u64().unwrap_or(0) as u32;
                    let max_attempts = payload["max_attempts"]
                        .as_u64()
                        .unwrap_or(config.reliability.max_retry_attempts as u64)
                        as u32;

                    if attempt + 1 < max_attempts {
                        let backoff = (config.reliability.retry_base_backoff_ms
                            * (1u64 << attempt))
                            .min(config.reliability.retry_max_backoff_ms);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        payload["attempt"] = serde_json::json!(attempt + 1);
                        payload["max_attempts"] = serde_json::json!(max_attempts);
                        payload["last_error"] = serde_json::json!(e.to_string());
                        let retry_job = Job {
                            id: job.id.clone(),
                            job_type: job.job_type.clone(),
                            payload: serde_json::to_string(&payload)
                                .unwrap_or_else(|_| job.payload.clone()),
                            created_at: chrono::Utc::now().to_rfc3339(),
                        };
                        let _ = queue.enqueue_to(QUEUE_SANDBOX, &retry_job).await;
                    } else {
                        let dlq_job = Job {
                            id: job.id.clone(),
                            job_type: job.job_type.clone(),
                            payload: job.payload.clone(),
                            created_at: chrono::Utc::now().to_rfc3339(),
                        };
                        let _ = queue
                            .enqueue_dlq(QUEUE_DLQ_SANDBOX, &dlq_job, &e.to_string())
                            .await;
                    }
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
    tracing::info!(email_id = %job.email_id, user_id = ?job.user_id, trace_id = ?job.trace_id, attempt = job.attempt, "Sandbox job started");
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

            if let Some(hit) = reuse::lookup_reuse_entry(db_pool, "sandbox_url", &job.target)? {
                if let Some(data) = hit.result_data {
                    if let Ok(reused) = serde_json::from_str::<serde_json::Value>(&data) {
                        let final_url = reused
                            .get("final_url")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let redirects = reused
                            .get("redirects")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();

                        store_report(
                            db_pool,
                            &job.email_id,
                            &job.target,
                            final_url.as_deref(),
                            redirects,
                            Vec::new(),
                            vec!["sandbox_reused".to_string()],
                            SandboxStatus::Completed,
                            None,
                            0,
                        )?;
                        queue
                            .publish_progress(
                                &config.sandbox.progress_channel,
                                &job.email_id,
                                "sandbox_execution",
                                "completed",
                                Some("sandbox cache reuse hit"),
                            )
                            .await?;
                        return Ok(());
                    }
                }
            }

            let task = UrlDetonationTask {
                email_id: job.email_id.clone(),
                url: job.target.clone(),
                timeout_ms: job.timeout_ms,
            };

            let breaker = CircuitBreaker::new("sandbox_executor", config.circuit_breaker.clone());
            if !breaker.allow().await {
                return Err(anyhow::anyhow!("sandbox executor circuit open"));
            }

            let timed = tokio::time::timeout(
                Duration::from_millis(executor.timeout_ms()),
                executor.execute_url(task),
            )
            .await;

            match timed {
                Ok(Ok(handle)) => {
                    breaker.on_success().await;
                    let report = executor.get_report(&handle).await?;
                    let reuse_payload = serde_json::json!({
                        "final_url": report.final_url.clone(),
                        "redirects": report.redirects.clone(),
                        "suspicious_behavior": report.suspicious_behavior.clone(),
                    });
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
                    let _ = reuse::store_reuse_entry(
                        db_pool,
                        "sandbox_url",
                        &job.target,
                        Some(&job.email_id),
                        Some(&serde_json::to_string(&reuse_payload)?),
                        config.tenant.sandbox_reuse_ttl_secs,
                    );
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
                    breaker.on_failure().await;
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
                    breaker.on_failure().await;
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
