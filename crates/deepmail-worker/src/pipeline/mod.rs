//! Analysis pipeline orchestrator.
//!
//! Coordinates the full email analysis workflow through each stage,
//! updating job status in the database at each transition.
//!
//! # Pipeline Stages
//! 1. Parse email (.eml) → extract headers, body, attachments
//! 2. Analyze headers → Received chain, auth results, originating IP
//! 3. Extract IOCs → IPs, domains, URLs, hashes
//! 4. URL analysis (parallel) — placeholder for Phase 3
//! 5. Attachment analysis (parallel) — hash, entropy, MIME
//! 6. Threat scoring → weighted multi-dimensional score
//! 7. Store all results

pub mod attachment_analyzer;
pub mod email_parser;
pub mod header_analysis;
pub mod ioc_extractor;
pub mod scoring;
pub mod url_analyzer;

use crate::graph::GraphService;
use crate::similarity;
use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::{new_id, now_utc, EmailStatus};

use crate::pipeline::email_parser::ParsedEmail;
use crate::pipeline::header_analysis::HeaderAnalysis;
use crate::pipeline::ioc_extractor::ExtractedIocs;

/// Context passed through the pipeline for a single job.
pub struct PipelineContext {
    pub email_id: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub original_name: String,
    pub db_pool: DbPool,
}

/// Run the full analysis pipeline for an email.
///
/// Each stage updates the email status in the database. If any stage
/// fails, the email is marked as `Failed` with the error message.
pub async fn run_pipeline(ctx: &PipelineContext) -> Result<(), DeepMailError> {
    tracing::info!(email_id = %ctx.email_id, \"Pipeline started\");

    // ── Stage 1: Parse email ─────────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::AnalyzingHeaders)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, \"parse_email\")?;

    let raw_bytes = std::fs::read(&ctx.quarantine_path).map_err(|e| {
        DeepMailError::Internal(format!(\"Failed to read quarantined file: {e}\"))
    })?;

    let parsed = email_parser::parse_email(&raw_bytes)?;

    record_stage_complete(&ctx.db_pool, &ctx.email_id, \"parse_email\", Some(&format!(
        \"headers={}, attachments={}, body_len={}\",
        parsed.headers.len(),
        parsed.attachments.len(),
        parsed.body_text.as_ref().map_or(0, |b| b.len()),
    )))?;

    tracing::info!(
        email_id = %ctx.email_id,
        headers = parsed.headers.len(),
        attachments = parsed.attachments.len(),
        \"Email parsed\"
    );

    // ── Stage 2: Header analysis ─────────────────────────────────────────────
    record_stage_start(&ctx.db_pool, &ctx.email_id, \"header_analysis\")?;

    let header_result = header_analysis::analyze_headers(&parsed);

    record_stage_complete(&ctx.db_pool, &ctx.email_id, \"header_analysis\", Some(&format!(
        \"hops={}, originating_ip={:?}, spf={:?}, dkim={:?}, dmarc={:?}\",
        header_result.received_hops.len(),
        header_result.originating_ip,
        header_result.spf_result,
        header_result.dkim_result,
        header_result.dmarc_result,
    )))?;

    tracing::info!(email_id = %ctx.email_id, \"Headers analyzed\");

    // ── Stage 3: IOC extraction & Graph Ingestion ────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::ExtractingIocs)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, \"ioc_extraction\")?;

    let iocs = ioc_extractor::extract_iocs(&parsed);

    // 🚀 NEW: Graph Ingestion & Correlation
    let graph_service = GraphService::new(ctx.db_pool.clone());
    graph_service.ingest_iocs(&ctx.email_id, &iocs)?;
    graph_service.correlate_campaign(&ctx.email_id)?;

    record_stage_complete(&ctx.db_pool, &ctx.email_id, \"ioc_extraction\", Some(&format!(
        \"ips={}, domains={}, urls={}, emails={}, hashes={}\",
        iocs.ips.len(), iocs.domains.len(), iocs.urls.len(),
        iocs.emails.len(), iocs.hashes.len(),
    )))?;

    tracing::info!(
        email_id = %ctx.email_id,
        total_iocs = iocs.total_count(),
        \"IOCs extracted and graphed\"
    );

    // ── Stage 4 & 5: Parallel URL + Attachment analysis ──────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::UrlAnalysis)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, \"url_analysis\")?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, \"attachment_analysis\")?;

    // Run URL and attachment analysis in parallel
    let url_future = url_analyzer::analyze_urls(&iocs.urls);
    let attachment_future = attachment_analyzer::analyze_attachments(
        &ctx.db_pool,
        &ctx.email_id,
        &parsed.attachments,
    );

    let (url_results, attachment_results) = tokio::join!(url_future, attachment_future);
    let url_results = url_results?;
    let attachment_results = attachment_results?;

    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::AttachmentAnalysis)?;

    record_stage_complete(&ctx.db_pool, &ctx.email_id, \"url_analysis\", Some(&format!(
        \"urls_analyzed={}\", url_results.len(),
    )))?;
    record_stage_complete(&ctx.db_pool, &ctx.email_id, \"attachment_analysis\", Some(&format!(
        \"attachments_analyzed={}\", attachment_results.len(),
    )))?;

    // 🚀 NEW: Similarity Calculation
    let body_simhash = similarity::calculate_simhash(parsed.body_text.as_deref().unwrap_or(\"\"));
    let html_struct_hash = similarity::calculate_html_structure_hash(parsed.body_html.as_deref().unwrap_or(\"\"));

    // ── Stage 6: Threat scoring ──────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::Scoring)?;
    record_stage_start(&ctx.db_pool, &ctx.email_id, \"threat_scoring\")?;

    let threat_score = scoring::calculate_threat_score(
        &header_result,
        &iocs,
        &url_results,
        &attachment_results,
    );

    record_stage_complete(&ctx.db_pool, &ctx.email_id, \"threat_scoring\", Some(&format!(
        \"total={:.1}, confidence={:.2}, identity={:.1}, infra={:.1}, content={:.1}, attachment={:.1}\",
        threat_score.total,
        threat_score.confidence,
        threat_score.breakdown.identity,
        threat_score.breakdown.infrastructure,
        threat_score.breakdown.content,
        threat_score.breakdown.attachment,
    )))?;

    tracing::info!(
        email_id = %ctx.email_id,
        score = threat_score.total,
        confidence = threat_score.confidence,
        \"Threat score calculated\"
    );

    // ── Stage 7: Store analysis results ──────────────────────────────────────
    store_analysis_results(&ctx.db_pool, &ctx.email_id, &header_result, &iocs, &threat_score)?;

    // Store Similarity metadata (optional, best effort)
    if let Ok(conn) = ctx.db_pool.get() {
        let _ = conn.execute(
            \"UPDATE analysis_results SET data = json_insert(data, '$.simhash', ?1, '$.html_struct_hash', ?2) WHERE email_id = ?3 AND result_type = 'threat_score'\",
            rusqlite::params![body_simhash.to_string(), html_struct_hash, &ctx.email_id]
        );
    }

    // ── Mark complete ────────────────────────────────────────────────────────
    update_status(&ctx.db_pool, &ctx.email_id, &EmailStatus::Completed)?;
    mark_completed(&ctx.db_pool, &ctx.email_id)?;

    // Audit log
    let _ = deepmail_common::audit::log_analysis_complete(
        &ctx.db_pool,
        &ctx.email_id,
        threat_score.total,
    );

    tracing::info!(email_id = %ctx.email_id, \"Pipeline completed successfully\");
    Ok(())
}

// ─── Database helpers ─────────────────────────────────────────────────────────

/// Update the email status in the database.
fn update_status(pool: &DbPool, email_id: &str, status: &EmailStatus) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        \"UPDATE emails SET status = ?1, current_stage = ?1, stage_started_at = ?2 WHERE id = ?3\",
        rusqlite::params![status.to_string(), now_utc(), email_id],
    )?;
    Ok(())
}

/// Mark an email as completed.
fn mark_completed(pool: &DbPool, email_id: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        \"UPDATE emails SET completed_at = ?1 WHERE id = ?2\",
        rusqlite::params![now_utc(), email_id],
    )?;
    Ok(())
}

/// Mark an email as failed with an error message.
pub fn mark_failed(pool: &DbPool, email_id: &str, error: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        \"UPDATE emails SET status = 'failed', error_message = ?1, completed_at = ?2 WHERE id = ?3\",
        rusqlite::params![error, now_utc(), email_id],
    )?;
    Ok(())
}

/// Record the start of a pipeline stage.
fn record_stage_start(pool: &DbPool, email_id: &str, stage: &str) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let id = new_id();
    conn.execute(
        \"INSERT INTO job_progress (id, email_id, stage, status, started_at) VALUES (?1, ?2, ?3, 'started', ?4)\",
        rusqlite::params![id, email_id, stage, now_utc()],
    )?;
    Ok(())
}

/// Record the completion of a pipeline stage.
fn record_stage_complete(pool: &DbPool, email_id: &str, stage: &str, details: Option<&str>) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        \"UPDATE job_progress SET status = 'completed', completed_at = ?1, details = ?2 WHERE email_id = ?3 AND stage = ?4 AND status = 'started'\",
        rusqlite::params![now_utc(), details, email_id, stage],
    )?;
    Ok(())
}

/// Store extracted IOCs in the database.
fn store_iocs(pool: &DbPool, email_id: &str, iocs: &ExtractedIocs) -> Result<(), DeepMailError> {
    let conn = pool.get()?;

    let insert_ioc = |ioc_type: &str, value: &str| -> Result<String, DeepMailError> {
        let now = now_utc();
        // Upsert: insert or update last_seen
        conn.execute(
            \"INSERT INTO ioc_nodes (id, ioc_type, value, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(ioc_type, value) DO UPDATE SET last_seen = ?4\",
            rusqlite::params![new_id(), ioc_type, value, now],
        )?;
        // Get the ID
        let id: String = conn.query_row(
            \"SELECT id FROM ioc_nodes WHERE ioc_type = ?1 AND value = ?2\",
            rusqlite::params![ioc_type, value],
            |row| row.get(0),
        )?;
        Ok(id)
    };

    let mut ioc_ids: Vec<String> = Vec::new();

    for ip in &iocs.ips {
        if let Ok(id) = insert_ioc(\"ip\", ip) {
            ioc_ids.push(id);
        }
    }
    for domain in &iocs.domains {
        if let Ok(id) = insert_ioc(\"domain\", domain) {
            ioc_ids.push(id);
        }
    }
    for url in &iocs.urls {
        if let Ok(id) = insert_ioc(\"url\", url) {
            ioc_ids.push(id);
        }
    }
    for email in &iocs.emails {
        if let Ok(id) = insert_ioc(\"email\", email) {
            ioc_ids.push(id);
        }
    }
    for hash in &iocs.hashes {
        if let Ok(id) = insert_ioc(\"sha256\", hash) {
            ioc_ids.push(id);
        }
    }

    // Create relations: email → each IOC
    for ioc_id in &ioc_ids {
        let _ = conn.execute(
            \"INSERT OR IGNORE INTO ioc_relations (id, source_id, target_id, relation_type, email_id)
             VALUES (?1, ?2, ?3, 'extracted_from', ?4)\",
            rusqlite::params![new_id(), ioc_id, ioc_id, email_id],
        );
    }

    tracing::debug!(
        email_id = email_id,
        ioc_count = ioc_ids.len(),
        \"IOCs stored in database\"
    );

    Ok(())
}

/// Store final analysis results in the database.
fn store_analysis_results(
    pool: &DbPool,
    email_id: &str,
    headers: &HeaderAnalysis,
    iocs: &ExtractedIocs,
    score: &deepmail_common::models::ThreatScore,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let now = now_utc();

    // Store header analysis
    conn.execute(
        \"INSERT INTO analysis_results (id, email_id, result_type, data, threat_score, confidence, created_at)
         VALUES (?1, ?2, 'header_analysis', ?3, ?4, ?5, ?6)\",
        rusqlite::params![
            new_id(), email_id,
            serde_json::to_string(headers).unwrap_or_default(),
            score.breakdown.identity,
            score.confidence,
            now,
        ],
    )?;

    // Store IOC summary
    conn.execute(
        \"INSERT INTO analysis_results (id, email_id, result_type, data, threat_score, confidence, created_at)
         VALUES (?1, ?2, 'ioc_extraction', ?3, ?4, ?5, ?6)\",
        rusqlite::params![
            new_id(), email_id,
            serde_json::to_string(iocs).unwrap_or_default(),
            score.breakdown.content,
            score.confidence,
            now,
        ],
    )?;

    // Store overall threat score
    conn.execute(
        \"INSERT INTO analysis_results (id, email_id, result_type, data, threat_score, confidence, created_at)
         VALUES (?1, ?2, 'threat_score', ?3, ?4, ?5, ?6)\",
        rusqlite::params![
            new_id(), email_id,
            serde_json::to_string(score).unwrap_or_default(),
            score.total,
            score.confidence,
            now,
        ],
    )?;

    Ok(())
}
