use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use deepmail_common::errors::DeepMailError;

use crate::auth::AuthUser;
use crate::state::AppState;

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardData {
    pub stats: DashboardStats,
    pub trend: Vec<TrendDataPoint>,
    pub recent_analyses: Vec<RecentAnalysis>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardStats {
    pub global_24h: i64,
    pub malicious: i64,
    pub suspicious: i64,
    pub safe: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrendDataPoint {
    pub hour: String,
    pub safe: i64,
    pub suspicious: i64,
    pub malicious: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecentAnalysis {
    pub id: String,
    pub original_name: String,
    pub sender: Option<String>,
    pub status: String,
    pub submitted_at: String,
    pub risk_level: String,
    pub score: f64,
}

// ─── Route registration ───────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new().route("/dashboard", get(dashboard_handler))
}

// ─── Handler ─────────────────────────────────────────────────────────────────

async fn dashboard_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    auth: AuthUser,
) -> Result<(StatusCode, Json<DashboardData>), DeepMailError> {
    enforce_rate_limits(&state, &auth.user_id, addr.ip().to_string(), "dashboard").await?;

    let conn = state.db_pool().get()?;

    // ── 1. Stats (Last 24h) ────────────────────────────────────────────────────
    let mut stats = DashboardStats {
        global_24h: 0,
        malicious: 0,
        suspicious: 0,
        safe: 0,
    };

    let stats_query = "
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN ar.threat_score >= 80 THEN 1 ELSE 0 END) as malicious,
            SUM(CASE WHEN ar.threat_score >= 40 AND ar.threat_score < 80 THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN ar.threat_score < 40 THEN 1 ELSE 0 END) as safe
        FROM emails e
        LEFT JOIN analysis_results ar ON e.id = ar.email_id AND ar.result_type = 'final_score'
        WHERE e.submitted_at >= datetime('now', '-1 day') AND e.submitted_by = ?1 AND e.is_deleted = 0
    ";

    if let Some(row) = conn.query_row(stats_query, rusqlite::params![auth.user_id], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(Some(0)).unwrap_or(0),
            row.get::<_, Option<i64>>(1).unwrap_or(Some(0)).unwrap_or(0),
            row.get::<_, Option<i64>>(2).unwrap_or(Some(0)).unwrap_or(0),
            row.get::<_, Option<i64>>(3).unwrap_or(Some(0)).unwrap_or(0),
        ))
    }).optional()? {
        stats.global_24h = row.0;
        stats.malicious = row.1;
        stats.suspicious = row.2;
        stats.safe = row.3;
    }

    // ── 2. Trend (Last 24h grouped by hour) ────────────────────────────────────
    let mut trend = Vec::new();
    let trend_query = "
        SELECT
            strftime('%Y-%m-%d %H:00', e.submitted_at) as hour,
            SUM(CASE WHEN ar.threat_score < 40 THEN 1 ELSE 0 END) as safe,
            SUM(CASE WHEN ar.threat_score >= 40 AND ar.threat_score < 80 THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN ar.threat_score >= 80 THEN 1 ELSE 0 END) as malicious
        FROM emails e
        LEFT JOIN analysis_results ar ON e.id = ar.email_id AND ar.result_type = 'final_score'
        WHERE e.submitted_at >= datetime('now', '-1 day') AND e.submitted_by = ?1 AND e.is_deleted = 0
        GROUP BY hour
        ORDER BY hour ASC
    ";

    let mut stmt = conn.prepare(trend_query)?;
    let trend_rows = stmt.query_map(rusqlite::params![auth.user_id], |row| {
        Ok(TrendDataPoint {
            hour: row.get(0)?,
            safe: row.get::<_, Option<i64>>(1).unwrap_or(Some(0)).unwrap_or(0),
            suspicious: row.get::<_, Option<i64>>(2).unwrap_or(Some(0)).unwrap_or(0),
            malicious: row.get::<_, Option<i64>>(3).unwrap_or(Some(0)).unwrap_or(0),
        })
    })?;

    for tr in trend_rows {
        if let Ok(data_point) = tr {
            trend.push(data_point);
        }
    }

    // ── 3. Recent Analyses (Top 10 max) ────────────────────────────────────────
    let mut recent_analyses = Vec::new();
    let recent_query = "
        SELECT
            e.id,
            e.original_name,
            e.status,
            e.submitted_at,
            ar.threat_score
        FROM emails e
        LEFT JOIN analysis_results ar ON e.id = ar.email_id AND ar.result_type = 'final_score'
        WHERE e.submitted_by = ?1 AND e.is_deleted = 0
        ORDER BY e.submitted_at DESC
        LIMIT 10
    ";

    let mut stmt_recent = conn.prepare(recent_query)?;
    let recent_rows = stmt_recent.query_map(rusqlite::params![auth.user_id], |row| {
        let score: Option<f64> = row.get(4)?;
        let score_val = score.unwrap_or(0.0);
        let risk_level = if score_val >= 80.0 {
            "Critical".to_string()
        } else if score_val >= 40.0 {
            "Suspicious".to_string()
        } else {
            "Safe".to_string()
        };

        Ok(RecentAnalysis {
            id: row.get(0)?,
            original_name: row.get(1)?,
            sender: Some("Unknown".to_string()), // Could parse from headers later
            status: row.get(2)?,
            submitted_at: row.get(3)?,
            risk_level,
            score: score_val,
        })
    })?;

    for ra in recent_rows {
        if let Ok(analysis) = ra {
            recent_analyses.push(analysis);
        }
    }

    Ok((StatusCode::OK, Json(DashboardData {
        stats,
        trend,
        recent_analyses,
    })))
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
