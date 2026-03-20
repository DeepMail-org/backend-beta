use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use deepmail_common::errors::DeepMailError;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub jobs_processed_total: i64,
    pub failed_jobs_total: i64,
    pub stage_latency_avg_seconds: serde_json::Value,
    pub sandbox_execution_avg_ms: f64,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics_handler))
}

async fn metrics_handler(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<MetricsSnapshot>), DeepMailError> {
    let conn = state.db_pool().get()?;

    let jobs_processed_total: i64 = conn
        .query_row("SELECT COUNT(*) FROM emails", [], |row| row.get(0))
        .unwrap_or(0);
    let failed_jobs_total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM emails WHERE status = 'failed'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut stage_stmt = conn.prepare(
        "SELECT stage, AVG((julianday(completed_at) - julianday(started_at)) * 86400.0)
         FROM job_progress
         WHERE completed_at IS NOT NULL
         GROUP BY stage",
    )?;
    let mut stage_map = serde_json::Map::new();
    let rows = stage_stmt.query_map([], |row| {
        let stage: String = row.get(0)?;
        let avg: f64 = row.get(1)?;
        Ok((stage, avg))
    })?;
    for row in rows.flatten() {
        stage_map.insert(row.0, serde_json::json!(row.1));
    }

    let sandbox_execution_avg_ms: f64 = conn
        .query_row(
            "SELECT COALESCE(AVG(execution_time_ms), 0.0) FROM sandbox_reports",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0.0);

    Ok((
        StatusCode::OK,
        Json(MetricsSnapshot {
            jobs_processed_total,
            failed_jobs_total,
            stage_latency_avg_seconds: serde_json::Value::Object(stage_map),
            sandbox_execution_avg_ms,
        }),
    ))
}
