//! Results query endpoint — retrieve the full analysis report for an email.
//!
//! # Endpoint
//! `GET /api/v1/results/:email_id`
//!
//! # Data Flow
//! 1. Validate `email_id` format
//! 2. Query `emails` table for the record
//! 3. Query `analysis_results` for all stage outputs
//! 4. Query `job_progress` for stage timing data
//! 5. Query `ioc_nodes` linked to this email via `ioc_relations`
//! 6. Assemble and return a structured `EmailAnalysisReport`
//!
//! # Security
//! - Database queries use prepared statements only
//! - No raw user input is interpolated into SQL
//! - Missing records return 404, not 500

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use deepmail_common::errors::DeepMailError;

use crate::auth::AuthUser;
use crate::state::AppState;

const RESULTS_ROUTE: &str = "/results/:email_id";

// ─── Response types ───────────────────────────────────────────────────────────

/// Full analysis report for a single email submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailAnalysisReport {
    /// Core email metadata.
    pub email: EmailSummary,
    /// Per-stage analysis outputs (JSON blobs with scores).
    pub analysis_results: Vec<AnalysisResultEntry>,
    /// Stage-by-stage pipeline timing.
    pub job_progress: Vec<JobProgressEntry>,
    /// IOC nodes linked to this email.
    pub iocs: Vec<IocEntry>,
    /// Geo-resolved points used by map UI.
    pub geo_points: Vec<GeoPoint>,
    /// Ordered sender-to-recipient received hops.
    pub hop_timeline: Vec<HopPoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeoPoint {
    pub id: String,
    pub ip: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub risk: String,
    pub abuse_confidence: Option<u8>,
    pub is_tor: bool,
    pub is_proxy: bool,
    pub confidence_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HopPoint {
    pub hop: usize,
    pub from_host: Option<String>,
    pub by_host: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IocGeoMetadata {
    lat: f64,
    lon: f64,
    country: String,
    city: Option<String>,
    region: Option<String>,
    asn: Option<u32>,
    org: Option<String>,
    abuse_confidence: Option<u8>,
    is_tor: Option<bool>,
    is_proxy: Option<bool>,
    confidence_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct HeaderAnalysisData {
    received_hops: Vec<HeaderHop>,
}

#[derive(Debug, Deserialize)]
struct HeaderHop {
    hop: usize,
    from_host: Option<String>,
    by_host: Option<String>,
    ip: Option<String>,
}

/// Core email record.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailSummary {
    pub id: String,
    pub original_name: String,
    pub sha256_hash: String,
    pub file_size: i64,
    pub submitted_at: String,
    pub status: String,
    pub current_stage: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
}

/// A single analysis result entry (one per stage that produces output).
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResultEntry {
    pub id: String,
    pub result_type: String,
    /// JSON-serialised stage output (headers, IOC list, score, etc.).
    pub data: serde_json::Value,
    pub threat_score: Option<f64>,
    pub confidence: Option<f64>,
    pub created_at: String,
}

/// Pipeline stage timing record.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobProgressEntry {
    pub id: String,
    pub stage: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub details: Option<String>,
}

/// An IOC node linked to this email.
#[derive(Debug, Serialize, Deserialize)]
pub struct IocEntry {
    pub id: String,
    pub ioc_type: String,
    pub value: String,
    pub first_seen: String,
    pub last_seen: String,
    pub metadata: Option<String>,
}

// ─── Route registration ───────────────────────────────────────────────────────

/// Register results routes under the shared router.
pub fn routes() -> Router<AppState> {
    Router::new().route(RESULTS_ROUTE, get(results_handler))
}

// ─── Handler ─────────────────────────────────────────────────────────────────

/// `GET /api/v1/results/:email_id`
///
/// Returns the full analysis report for the given email ID.
/// Responds with 404 if the email does not exist.
async fn results_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    auth: AuthUser,
    Path(email_id): Path<String>,
) -> Result<(StatusCode, Json<EmailAnalysisReport>), DeepMailError> {
    let user_id = auth.user_id;
    enforce_rate_limits(&state, &user_id, addr.ip().to_string(), "results").await?;

    let conn = state.db_pool().get()?;

    // ── 1. Fetch email record ──────────────────────────────────────────────────
    let email: Option<EmailSummary> = {
        let mut stmt = conn.prepare(
            "SELECT id, original_name, sha256_hash, file_size, submitted_at, \
                    status, current_stage, completed_at, error_message \
             FROM emails
             WHERE id = ?1 AND submitted_by = ?2 AND is_deleted = 0 AND archived_at IS NULL",
        )?;

        stmt.query_row(rusqlite::params![email_id, user_id], |row| {
            Ok(EmailSummary {
                id: row.get(0)?,
                original_name: row.get(1)?,
                sha256_hash: row.get(2)?,
                file_size: row.get(3)?,
                submitted_at: row.get(4)?,
                status: row.get(5)?,
                current_stage: row.get(6)?,
                completed_at: row.get(7)?,
                error_message: row.get(8)?,
            })
        })
        .ok()
    };

    let email =
        email.ok_or_else(|| DeepMailError::NotFound(format!("Email '{email_id}' not found")))?;

    // ── 2. Fetch analysis results ──────────────────────────────────────────────
    let analysis_results: Vec<AnalysisResultEntry> = {
        let mut stmt = conn.prepare(
            "SELECT id, result_type, data, threat_score, confidence, created_at \
             FROM analysis_results \
             WHERE email_id = ?1 \
             ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map(rusqlite::params![email_id], |row| {
            let data_str: String = row.get(2)?;
            Ok(AnalysisResultEntry {
                id: row.get(0)?,
                result_type: row.get(1)?,
                data: serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null),
                threat_score: row.get(3)?,
                confidence: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;

        rows.filter_map(|r| r.ok()).collect()
    };

    // ── 3. Fetch job progress ─────────────────────────────────────────────────
    let job_progress: Vec<JobProgressEntry> = {
        let mut stmt = conn.prepare(
            "SELECT id, stage, status, started_at, completed_at, details \
             FROM job_progress \
             WHERE email_id = ?1 \
             ORDER BY started_at ASC",
        )?;

        let rows = stmt.query_map(rusqlite::params![email_id], |row| {
            Ok(JobProgressEntry {
                id: row.get(0)?,
                stage: row.get(1)?,
                status: row.get(2)?,
                started_at: row.get(3)?,
                completed_at: row.get(4)?,
                details: row.get(5)?,
            })
        })?;

        rows.filter_map(|r| r.ok()).collect()
    };

    // ── 4. Fetch linked IOC nodes ─────────────────────────────────────────────
    let iocs: Vec<IocEntry> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT n.id, n.ioc_type, n.value, n.first_seen, n.last_seen, n.metadata \
             FROM ioc_nodes n \
             INNER JOIN ioc_relations r ON r.source_id = n.id OR r.target_id = n.id \
             WHERE r.email_id = ?1 \
             ORDER BY n.ioc_type, n.value",
        )?;

        let rows = stmt.query_map(rusqlite::params![email_id], |row| {
            Ok(IocEntry {
                id: row.get(0)?,
                ioc_type: row.get(1)?,
                value: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                metadata: row.get(5)?,
            })
        })?;

        rows.filter_map(|r| r.ok()).collect()
    };

    let geo_points = build_geo_points(&conn, &iocs)?;
    let hop_timeline = build_hop_timeline(&analysis_results);

    let report = EmailAnalysisReport {
        email,
        analysis_results,
        job_progress,
        iocs,
        geo_points,
        hop_timeline,
    };

    tracing::info!(email_id = %email_id, "Results fetched");
    Ok((StatusCode::OK, Json(report)))
}

fn risk_for_ioc_type(ioc_type: &str) -> String {
    match ioc_type {
        "ip" => "medium".to_string(),
        "url" | "domain" => "high".to_string(),
        _ => "low".to_string(),
    }
}

fn build_geo_points(conn: &rusqlite::Connection, iocs: &[IocEntry]) -> Result<Vec<GeoPoint>, DeepMailError> {
    let mut points = Vec::new();
    for ioc in iocs {
        if ioc.ioc_type != "ip" {
            continue;
        }

        let mut from_meta: Option<IocGeoMetadata> = None;
        if let Some(raw_meta) = &ioc.metadata {
            from_meta = serde_json::from_str::<IocGeoMetadata>(raw_meta).ok();
        }

        let fallback = conn
            .query_row(
                "SELECT lat, lon, country, city, region, asn, org,
                        abuse_confidence, is_tor, is_proxy, confidence_score
                 FROM ip_geo_intel WHERE ip = ?1",
                rusqlite::params![ioc.value],
                |row| {
                    Ok(IocGeoMetadata {
                        lat: row.get(0)?,
                        lon: row.get(1)?,
                        country: row.get(2)?,
                        city: row.get(3)?,
                        region: row.get(4)?,
                        asn: row.get(5)?,
                        org: row.get(6)?,
                        abuse_confidence: row.get(7)?,
                        is_tor: Some(row.get::<_, i64>(8)? == 1),
                        is_proxy: Some(row.get::<_, i64>(9)? == 1),
                        confidence_score: row.get(10).ok(),
                    })
                },
            )
            .ok();

        let geo = match from_meta.or(fallback) {
            Some(g) => g,
            None => continue,
        };

        points.push(GeoPoint {
            id: ioc.id.clone(),
            ip: ioc.value.clone(),
            lat: geo.lat,
            lon: geo.lon,
            country: geo.country,
            city: geo.city,
            region: geo.region,
            asn: geo.asn,
            org: geo.org,
            risk: risk_for_ioc_type(&ioc.ioc_type),
            abuse_confidence: geo.abuse_confidence,
            is_tor: geo.is_tor.unwrap_or(false),
            is_proxy: geo.is_proxy.unwrap_or(false),
            confidence_score: geo.confidence_score.unwrap_or(0.6),
        });
    }

    Ok(points)
}

fn build_hop_timeline(analysis_results: &[AnalysisResultEntry]) -> Vec<HopPoint> {
    let header_data = analysis_results
        .iter()
        .find(|entry| entry.result_type == "header_analysis")
        .and_then(|entry| serde_json::from_value::<HeaderAnalysisData>(entry.data.clone()).ok());

    let mut hops: Vec<HopPoint> = header_data
        .map(|header| {
            header
                .received_hops
                .into_iter()
                .map(|hop| HopPoint {
                    hop: hop.hop,
                    from_host: hop.from_host,
                    by_host: hop.by_host,
                    ip: hop.ip,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    hops.sort_by_key(|hop| std::cmp::Reverse(hop.hop));
    hops
}

async fn enforce_rate_limits(
    state: &AppState,
    user_id: &str,
    ip: String,
    endpoint: &str,
) -> Result<(), DeepMailError> {
    let mut queue = state.redis_queue().await;
    let (user_allowed, _, _) = queue
        .check_rate_limit_token_bucket(
            "user",
            &format!("{user_id}:{endpoint}"),
            state.config().reliability.rate_limit_capacity,
            state.config().reliability.rate_limit_refill_per_sec,
            1,
        )
        .await?;
    if !user_allowed {
        return Err(DeepMailError::RateLimited);
    }
    let (ip_allowed, _, _) = queue
        .check_rate_limit_token_bucket(
            "ip",
            &format!("{ip}:{endpoint}"),
            state.config().reliability.rate_limit_capacity,
            state.config().reliability.rate_limit_refill_per_sec,
            1,
        )
        .await?;
    if !ip_allowed {
        return Err(DeepMailError::RateLimited);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::util::ServiceExt;

    use super::{
        AnalysisResultEntry, EmailAnalysisReport, EmailSummary, GeoPoint, HopPoint, IocEntry,
        JobProgressEntry, RESULTS_ROUTE,
    };

    #[tokio::test]
    async fn results_route_matches_email_id_path() {
        let app = Router::new().route(RESULTS_ROUTE, get(|| async { StatusCode::OK }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/results/test-id")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("run request");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn results_payload_contract_contains_geo_and_hops() {
        let report = EmailAnalysisReport {
            email: EmailSummary {
                id: "e1".to_string(),
                original_name: "mail.eml".to_string(),
                sha256_hash: "abc".to_string(),
                file_size: 10,
                submitted_at: "2026-01-01T00:00:00Z".to_string(),
                status: "completed".to_string(),
                current_stage: None,
                completed_at: None,
                error_message: None,
            },
            analysis_results: vec![AnalysisResultEntry {
                id: "a1".to_string(),
                result_type: "header_analysis".to_string(),
                data: serde_json::json!({}),
                threat_score: None,
                confidence: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
            }],
            job_progress: vec![JobProgressEntry {
                id: "j1".to_string(),
                stage: "parse_email".to_string(),
                status: "completed".to_string(),
                started_at: "2026-01-01T00:00:00Z".to_string(),
                completed_at: None,
                details: None,
            }],
            iocs: vec![IocEntry {
                id: "i1".to_string(),
                ioc_type: "ip".to_string(),
                value: "8.8.8.8".to_string(),
                first_seen: "2026-01-01T00:00:00Z".to_string(),
                last_seen: "2026-01-01T00:00:00Z".to_string(),
                metadata: None,
            }],
            geo_points: vec![GeoPoint {
                id: "i1".to_string(),
                ip: "8.8.8.8".to_string(),
                lat: 1.0,
                lon: 2.0,
                country: "US".to_string(),
                city: Some("X".to_string()),
                region: Some("Y".to_string()),
                asn: Some(15169),
                org: Some("Google".to_string()),
                risk: "medium".to_string(),
                abuse_confidence: Some(10),
                is_tor: false,
                is_proxy: false,
                confidence_score: 0.9,
            }],
            hop_timeline: vec![HopPoint {
                hop: 1,
                from_host: Some("from".to_string()),
                by_host: Some("by".to_string()),
                ip: Some("8.8.8.8".to_string()),
            }],
        };

        let value = serde_json::to_value(report).expect("serialize report");
        assert!(value.get("geo_points").is_some());
        assert!(value.get("hop_timeline").is_some());
    }
}
