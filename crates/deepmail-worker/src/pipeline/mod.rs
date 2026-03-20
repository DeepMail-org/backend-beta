//! Analysis pipeline orchestrator.
//!
//! Coordinates the full email analysis workflow through each stage,
//! updating job status in the database at each transition.
//!
//! # Pipeline Stages
//! 1. **Parse EML** → extract headers, body parts, attachments
//! 2. **Header analysis** → Received chain, sender identity, SPF/DKIM/DMARC
//! 3. **IOC extraction** → IPs, domains, URLs, hashes, email addresses
//! 4. **Phishing keywords** → body text scan for urgency/deception language
//! 5. **URL analysis** (async, with Redis cache) → structural risk signals
//! 6. **Attachment analysis** (async, with Redis cache) → hash, entropy, MIME
//! 7. **Threat scoring** → weighted multi-dimensional score
//! 8. **Store results** → persist everything to SQLite + audit log
//!
//! # Design
//! - Fully async using Tokio — no blocking operations
//! - Cache is shared via `Arc<Mutex<ThreatCache>>` for safe concurrent access
//! - Stage start/complete events are recorded for progress tracking
//! - All errors transition the job to `Failed` with a descriptive message

pub mod attachment_analyzer;
pub mod email_parser;
pub mod header_analysis;
pub mod ioc_extractor;
pub mod phishing_keywords;
pub mod scoring;
pub mod url_analyzer;

use std::time::Duration;

use deepmail_common::audit;
use deepmail_common::cache::ThreatCache;
use deepmail_common::config::{PipelineConfig, RedisConfig, SandboxConfig};
use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::{new_id, now_utc, EmailStatus};
use deepmail_common::queue::{Job, RedisQueue, CHANNEL_PROGRESS, QUEUE_SANDBOX};
use deepmail_sandbox::model::{SandboxJob, SandboxJobKind};

use crate::pipeline::attachment_analyzer::AttachmentAnalysisResult;
use crate::pipeline::header_analysis::HeaderAnalysis;
use crate::pipeline::ioc_extractor::ExtractedIocs;
use crate::pipeline::url_analyzer::UrlAnalysisResult;

/// Context passed through the pipeline for a single email job.
///
/// Cloned per-job so that concurrent pipelines do not share mutable state
/// (except for the `ThreatCache` which is wrapped in `Arc<Mutex<>>`).
pub struct PipelineContext {
    /// Database ID of the email record.
    pub email_id: String,
    /// Path to the quarantined .eml file.
    pub quarantine_path: String,
    /// Pre-computed SHA-256 of the file (from upload).
    pub sha256: String,
    /// Original filename submitted by the user.
    pub original_name: String,
    /// Shared SQLite connection pool.
    pub db_pool: DbPool,
    /// Shared Redis cache handle for IP/domain/hash lookups.
    pub cache: ThreatCache,
    /// Redis config used for async queue publishes.
    pub redis: RedisConfig,
    /// Pipeline execution policy.
    pub pipeline: PipelineConfig,
    /// Sandbox execution policy.
    pub sandbox: SandboxConfig,
}

// ─── Pipeline entry point ─────────────────────────────────────────────────────

/// Run the full analysis pipeline for a single email.
///
/// Each stage updates the email status in the database. Any unrecoverable
/// error propagates up; the caller is responsible for marking the job failed.
pub async fn run_pipeline(ctx: &PipelineContext) -> Result<(), DeepMailError> {
    tracing::info!(email_id = %ctx.email_id, sha256 = %ctx.sha256, original_name = %ctx.original_name, "Pipeline started");

    // ── Stage 1: Parse email ──────────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::AnalyzingHeaders)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, "parse_email")?;
    let _ = audit::log_pipeline_stage(&ctx.db_pool, &ctx.email_id, "parse_email", "started");
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "parse_email",
        "started",
        None,
    )
    .await;

    let raw_bytes = tokio::fs::read(&ctx.quarantine_path).await.map_err(|e| {
        DeepMailError::Internal(format!(
            "Failed to read quarantined file '{}': {e}",
            ctx.quarantine_path
        ))
    })?;

    let parsed = email_parser::parse_email(&raw_bytes)?;

    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "parse_email",
        Some(&format!(
            "headers={}, attachments={}, body_len={}",
            parsed.headers.len(),
            parsed.attachments.len(),
            parsed.body_text.as_ref().map_or(0, |b| b.len()),
        )),
    )?;
    let _ = audit::log_pipeline_stage(&ctx.db_pool, &ctx.email_id, "parse_email", "completed");
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "parse_email",
        "completed",
        None,
    )
    .await;

    tracing::info!(
        email_id = %ctx.email_id,
        headers = parsed.headers.len(),
        attachments = parsed.attachments.len(),
        "Email parsed"
    );

    // ── Stage 2: Header analysis ──────────────────────────────────────────────
    record_stage_start(&ctx.db_pool, &ctx.email_id, "header_analysis")?;

    let header_result = header_analysis::analyze_headers(&parsed);

    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "header_analysis",
        Some(&format!(
            "hops={}, originating_ip={:?}, spf={:?}, dkim={:?}, dmarc={:?}",
            header_result.received_hops.len(),
            header_result.originating_ip,
            header_result.spf_result.as_ref().map(|r| &r.result),
            header_result.dkim_result.as_ref().map(|r| &r.result),
            header_result.dmarc_result.as_ref().map(|r| &r.result),
        )),
    )?;
    tracing::info!(email_id = %ctx.email_id, "Headers analysed");
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "header_analysis",
        "completed",
        None,
    )
    .await;

    // ── Stage 3: IOC extraction ───────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::ExtractingIocs)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, "ioc_extraction")?;

    let iocs = ioc_extractor::extract_iocs(&parsed);
    store_iocs(&ctx.db_pool, &ctx.email_id, &iocs)?;

    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "ioc_extraction",
        Some(&format!(
            "ips={}, domains={}, urls={}, emails={}, hashes={}",
            iocs.ips.len(),
            iocs.domains.len(),
            iocs.urls.len(),
            iocs.emails.len(),
            iocs.hashes.len(),
        )),
    )?;
    tracing::info!(email_id = %ctx.email_id, total_iocs = iocs.total_count(), "IOCs extracted");
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "ioc_extraction",
        "completed",
        None,
    )
    .await;

    // ── Stage 4: Phishing keyword scan ────────────────────────────────────────
    record_stage_start(&ctx.db_pool, &ctx.email_id, "phishing_keywords")?;

    let phishing =
        phishing_keywords::scan_bodies([parsed.body_text.as_deref(), parsed.body_html.as_deref()]);

    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "phishing_keywords",
        Some(&format!(
            "matches={}, score={:.1}",
            phishing.match_count, phishing.keyword_score,
        )),
    )?;
    tracing::info!(
        email_id = %ctx.email_id,
        keyword_matches = phishing.match_count,
        keyword_score   = phishing.keyword_score,
        "Phishing keywords scanned"
    );
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "phishing_keywords",
        "completed",
        None,
    )
    .await;

    // ── Stage 5 & 6: Parallel URL + Attachment analysis ───────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::UrlAnalysis)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, "url_analysis")?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, "attachment_analysis")?;
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "url_analysis",
        "started",
        None,
    )
    .await;
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "attachment_analysis",
        "started",
        None,
    )
    .await;

    let mut url_results = Vec::new();
    let mut attachment_results = Vec::new();
    let url_timeout = Duration::from_millis(ctx.pipeline.url_analysis_timeout_ms);
    let attachment_timeout = Duration::from_millis(ctx.pipeline.attachment_analysis_timeout_ms);
    let retries = ctx.pipeline.stage_retry_attempts.max(1);

    for attempt in 1..=retries {
        let cache = ctx.cache.clone();
        match tokio::time::timeout(
            url_timeout,
            url_analyzer::analyze_urls(&iocs.urls, Some(&cache)),
        )
        .await
        {
            Ok(Ok(results)) => {
                url_results = results;
                break;
            }
            Ok(Err(e)) => {
                if attempt == retries {
                    let _ = record_stage_soft_failed(
                        &ctx.db_pool,
                        &ctx.email_id,
                        "url_analysis",
                        &e.to_string(),
                    );
                }
            }
            Err(_) => {
                if attempt == retries {
                    let _ = record_stage_soft_failed(
                        &ctx.db_pool,
                        &ctx.email_id,
                        "url_analysis",
                        "timeout",
                    );
                }
            }
        }
    }

    for attempt in 1..=retries {
        let cache = ctx.cache.clone();
        match tokio::time::timeout(
            attachment_timeout,
            attachment_analyzer::analyze_attachments(
                &ctx.db_pool,
                &ctx.email_id,
                &parsed.attachments,
                Some(&cache),
            ),
        )
        .await
        {
            Ok(Ok(results)) => {
                attachment_results = results;
                break;
            }
            Ok(Err(e)) => {
                if attempt == retries {
                    let _ = record_stage_soft_failed(
                        &ctx.db_pool,
                        &ctx.email_id,
                        "attachment_analysis",
                        &e.to_string(),
                    );
                }
            }
            Err(_) => {
                if attempt == retries {
                    let _ = record_stage_soft_failed(
                        &ctx.db_pool,
                        &ctx.email_id,
                        "attachment_analysis",
                        "timeout",
                    );
                }
            }
        }
    }

    update_status(
        &ctx.db_pool,
        &ctx.email_id,
        &EmailStatus::AttachmentAnalysis,
    )?;

    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "url_analysis",
        Some(&format!("urls_analysed={}", url_results.len())),
    )?;
    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "attachment_analysis",
        Some(&format!(
            "attachments_analysed={}",
            attachment_results.len()
        )),
    )?;

    tracing::info!(
        email_id   = %ctx.email_id,
        urls       = url_results.len(),
        attachments = attachment_results.len(),
        "Parallel analysis complete"
    );
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "url_analysis",
        "completed",
        None,
    )
    .await;
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "attachment_analysis",
        "completed",
        None,
    )
    .await;

    if ctx.sandbox.enabled {
        let _ = enqueue_sandbox_jobs(ctx, &url_results, &attachment_results).await;
    }

    // ── Stage 7: Threat scoring ───────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::Scoring)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, "threat_scoring")?;

    let threat_score = scoring::calculate_threat_score(
        &header_result,
        &iocs,
        &url_results,
        &attachment_results,
        &phishing,
    );

    record_stage_complete(
        &ctx.db_pool,
        &ctx.email_id,
        "threat_scoring",
        Some(&format!(
            "total={:.1}, confidence={:.2}, identity={:.1}, infra={:.1}, content={:.1}, attachment={:.1}",
            threat_score.total,
            threat_score.confidence,
            threat_score.breakdown.identity,
            threat_score.breakdown.infrastructure,
            threat_score.breakdown.content,
            threat_score.breakdown.attachment,
        )),
    )?;

    tracing::info!(
        email_id   = %ctx.email_id,
        score      = threat_score.total,
        confidence = threat_score.confidence,
        "Threat score calculated"
    );
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "threat_scoring",
        "completed",
        None,
    )
    .await;

    // ── Stage 8: Persist results ──────────────────────────────────────────────
    store_analysis_results(
        &ctx.db_pool,
        &ctx.email_id,
        &header_result,
        &iocs,
        &phishing,
        &threat_score,
    )?;

    // ── Mark complete ─────────────────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::Completed)?;
    mark_completed(&ctx.db_pool, &ctx.email_id)?;

    // Audit log — always fire-and-forget so failures do not affect the job
    let _ = audit::log_analysis_complete(&ctx.db_pool, &ctx.email_id, threat_score.total);

    tracing::info!(email_id = %ctx.email_id, "Pipeline completed successfully");
    let _ = publish_progress_event(
        &ctx.redis,
        &ctx.sandbox.progress_channel,
        &ctx.email_id,
        "pipeline",
        "completed",
        None,
    )
    .await;
    Ok(())
}

// ─── Database helpers ─────────────────────────────────────────────────────────

/// Update the email status field (and current_stage + stage_started_at).
fn update_status(pool: &DbPool, email_id: &str, status: &EmailStatus) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE emails SET status = ?1, current_stage = ?1, stage_started_at = ?2 WHERE id = ?3",
        rusqlite::params![status.to_string(), now_utc(), email_id],
    )?;
    Ok(())
}

/// Mark an email as fully completed (sets completed_at timestamp).
fn mark_completed(pool: &DbPool, email_id: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE emails SET completed_at = ?1 WHERE id = ?2",
        rusqlite::params![now_utc(), email_id],
    )?;
    Ok(())
}

/// Mark an email as failed with an error message.
///
/// Called by the worker loop when `run_pipeline` returns an error.
pub fn mark_failed(pool: &DbPool, email_id: &str, error: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE emails SET status = 'failed', error_message = ?1, completed_at = ?2 WHERE id = ?3",
        rusqlite::params![error, now_utc(), email_id],
    )?;
    // Also audit the failure
    let _ = audit::log_error(pool, email_id, error);
    Ok(())
}

/// Record the start of a named pipeline stage.
fn record_stage_start(pool: &DbPool, email_id: &str, stage: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO job_progress (id, email_id, stage, status, started_at) \
         VALUES (?1, ?2, ?3, 'started', ?4)",
        rusqlite::params![new_id(), email_id, stage, now_utc()],
    )?;
    Ok(())
}

/// Record the successful completion of a named pipeline stage.
fn record_stage_complete(
    pool: &DbPool,
    email_id: &str,
    stage: &str,
    details: Option<&str>,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE job_progress \
         SET status = 'completed', completed_at = ?1, details = ?2 \
         WHERE email_id = ?3 AND stage = ?4 AND status = 'started'",
        rusqlite::params![now_utc(), details, email_id, stage],
    )?;
    Ok(())
}

fn record_stage_soft_failed(
    pool: &DbPool,
    email_id: &str,
    stage: &str,
    error: &str,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE job_progress \
         SET status = 'failed_soft', completed_at = ?1, details = ?2 \
         WHERE email_id = ?3 AND stage = ?4 AND status = 'started'",
        rusqlite::params![now_utc(), error, email_id, stage],
    )?;
    Ok(())
}

async fn enqueue_sandbox_jobs(
    ctx: &PipelineContext,
    url_results: &[UrlAnalysisResult],
    attachment_results: &[AttachmentAnalysisResult],
) -> Result<(), DeepMailError> {
    let mut queue = RedisQueue::new(&ctx.redis).await?;
    for url in url_results
        .iter()
        .filter(|u| u.has_ip_host || u.suspicious_tld || u.url_length > 200)
    {
        let job = SandboxJob {
            id: new_id(),
            email_id: ctx.email_id.clone(),
            kind: SandboxJobKind::Url,
            target: url.url.clone(),
            timeout_ms: ctx.sandbox.execution_timeout_ms,
        };
        let wrapped = Job {
            id: job.id.clone(),
            job_type: "sandbox_url".to_string(),
            payload: serde_json::to_string(&job)?,
            created_at: now_utc(),
        };
        let _ = queue.enqueue_to(QUEUE_SANDBOX, &wrapped).await;
        let _ = publish_progress_event(
            &ctx.redis,
            &ctx.sandbox.progress_channel,
            &ctx.email_id,
            "sandbox_queue",
            "queued",
            Some("url detonation queued"),
        )
        .await;
    }

    for attachment in attachment_results
        .iter()
        .filter(|a| a.suspicious_type || a.entropy > 7.5)
    {
        let job = SandboxJob {
            id: new_id(),
            email_id: ctx.email_id.clone(),
            kind: SandboxJobKind::File,
            target: attachment.filename.clone(),
            timeout_ms: ctx.sandbox.execution_timeout_ms,
        };
        let wrapped = Job {
            id: job.id.clone(),
            job_type: "sandbox_file".to_string(),
            payload: serde_json::to_string(&job)?,
            created_at: now_utc(),
        };
        let _ = queue.enqueue_to(QUEUE_SANDBOX, &wrapped).await;
        let _ = publish_progress_event(
            &ctx.redis,
            &ctx.sandbox.progress_channel,
            &ctx.email_id,
            "sandbox_queue",
            "queued",
            Some("file detonation queued"),
        )
        .await;
    }

    Ok(())
}

async fn publish_progress_event(
    redis: &RedisConfig,
    channel: &str,
    email_id: &str,
    stage: &str,
    status: &str,
    details: Option<&str>,
) -> Result<(), DeepMailError> {
    let mut queue = RedisQueue::new(redis).await?;
    queue
        .publish_progress(
            if channel.is_empty() {
                CHANNEL_PROGRESS
            } else {
                channel
            },
            email_id,
            stage,
            status,
            details,
        )
        .await
}

/// Upsert IOC nodes and create email→IOC relations in the graph tables.
fn store_iocs(pool: &DbPool, email_id: &str, iocs: &ExtractedIocs) -> Result<(), DeepMailError> {
    let conn = pool.get()?;

    // Insert or update a single IOC and return its DB id.
    let insert_ioc = |ioc_type: &str, value: &str| -> Result<String, DeepMailError> {
        let now = now_utc();
        conn.execute(
            "INSERT INTO ioc_nodes (id, ioc_type, value, first_seen, last_seen) \
             VALUES (?1, ?2, ?3, ?4, ?4) \
             ON CONFLICT(ioc_type, value) DO UPDATE SET last_seen = ?4",
            rusqlite::params![new_id(), ioc_type, value, now],
        )?;
        let id: String = conn.query_row(
            "SELECT id FROM ioc_nodes WHERE ioc_type = ?1 AND value = ?2",
            rusqlite::params![ioc_type, value],
            |row| row.get(0),
        )?;
        Ok(id)
    };

    let mut ioc_ids: Vec<String> = Vec::new();

    for ip in &iocs.ips {
        if let Ok(id) = insert_ioc("ip", ip) {
            ioc_ids.push(id);
        }
    }
    for domain in &iocs.domains {
        if let Ok(id) = insert_ioc("domain", domain) {
            ioc_ids.push(id);
        }
    }
    for url in &iocs.urls {
        if let Ok(id) = insert_ioc("url", url) {
            ioc_ids.push(id);
        }
    }
    for email in &iocs.emails {
        if let Ok(id) = insert_ioc("email", email) {
            ioc_ids.push(id);
        }
    }
    for hash in &iocs.hashes {
        if let Ok(id) = insert_ioc("sha256", hash) {
            ioc_ids.push(id);
        }
    }

    // Create email → IOC relations
    for ioc_id in &ioc_ids {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO ioc_relations \
             (id, source_id, target_id, relation_type, email_id) \
             VALUES (?1, ?2, ?3, 'extracted_from', ?4)",
            rusqlite::params![new_id(), ioc_id, ioc_id, email_id],
        );
    }

    tracing::debug!(
        email_id = email_id,
        ioc_count = ioc_ids.len(),
        "IOCs stored"
    );
    Ok(())
}

/// Persist analysis results to the `analysis_results` table.
fn store_analysis_results(
    pool: &DbPool,
    email_id: &str,
    headers: &HeaderAnalysis,
    iocs: &ExtractedIocs,
    phishing: &phishing_keywords::PhishingKeywordResult,
    score: &deepmail_common::models::ThreatScore,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let now = now_utc();

    // Header analysis JSON
    conn.execute(
        "INSERT INTO analysis_results \
         (id, email_id, result_type, data, threat_score, confidence, created_at) \
         VALUES (?1, ?2, 'header_analysis', ?3, ?4, ?5, ?6)",
        rusqlite::params![
            new_id(),
            email_id,
            serde_json::to_string(headers).unwrap_or_default(),
            score.breakdown.identity,
            score.confidence,
            now,
        ],
    )?;

    // IOC summary JSON
    conn.execute(
        "INSERT INTO analysis_results \
         (id, email_id, result_type, data, threat_score, confidence, created_at) \
         VALUES (?1, ?2, 'ioc_extraction', ?3, ?4, ?5, ?6)",
        rusqlite::params![
            new_id(),
            email_id,
            serde_json::to_string(iocs).unwrap_or_default(),
            score.breakdown.content,
            score.confidence,
            now,
        ],
    )?;

    // Phishing keyword scan JSON
    conn.execute(
        "INSERT INTO analysis_results \
         (id, email_id, result_type, data, threat_score, confidence, created_at) \
         VALUES (?1, ?2, 'phishing_keywords', ?3, ?4, ?5, ?6)",
        rusqlite::params![
            new_id(),
            email_id,
            serde_json::to_string(phishing).unwrap_or_default(),
            phishing.keyword_score,
            score.confidence,
            now,
        ],
    )?;

    // Overall threat score JSON
    conn.execute(
        "INSERT INTO analysis_results \
         (id, email_id, result_type, data, threat_score, confidence, created_at) \
         VALUES (?1, ?2, 'threat_score', ?3, ?4, ?5, ?6)",
        rusqlite::params![
            new_id(),
            email_id,
            serde_json::to_string(score).unwrap_or_default(),
            score.total,
            score.confidence,
            now,
        ],
    )?;

    Ok(())
}
