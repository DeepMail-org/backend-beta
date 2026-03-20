use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use deepmail_common::errors::DeepMailError;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics_handler))
}

async fn metrics_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, DeepMailError> {
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
    let rows = stage_stmt.query_map([], |row| {
        let stage: String = row.get(0)?;
        let avg: f64 = row.get(1)?;
        Ok((stage, avg))
    })?;

    let sandbox_execution_avg_seconds: f64 = conn
        .query_row(
            "SELECT COALESCE(AVG(execution_time_ms), 0.0) / 1000.0 FROM sandbox_reports",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0.0);

    let mut body = String::new();
    body.push_str("# HELP deepmail_jobs_processed_total Total jobs processed\n");
    body.push_str("# TYPE deepmail_jobs_processed_total counter\n");
    body.push_str(&format!(
        "deepmail_jobs_processed_total {}\n",
        jobs_processed_total
    ));
    body.push_str("# HELP deepmail_jobs_failed_total Total jobs failed\n");
    body.push_str("# TYPE deepmail_jobs_failed_total counter\n");
    body.push_str(&format!(
        "deepmail_jobs_failed_total {}\n",
        failed_jobs_total
    ));

    body.push_str("# HELP deepmail_stage_latency_seconds Average stage latency seconds\n");
    body.push_str("# TYPE deepmail_stage_latency_seconds gauge\n");
    for row in rows.flatten() {
        body.push_str(&format!(
            "deepmail_stage_latency_seconds{{stage=\"{}\"}} {}\n",
            row.0, row.1
        ));
    }

    body.push_str("# HELP deepmail_sandbox_execution_seconds Average sandbox execution seconds\n");
    body.push_str("# TYPE deepmail_sandbox_execution_seconds gauge\n");
    body.push_str(&format!(
        "deepmail_sandbox_execution_seconds {}\n",
        sandbox_execution_avg_seconds
    ));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/plain; version=0.0.4"
            .parse()
            .unwrap_or_else(|_| "text/plain".parse().expect("valid plain content type")),
    );
    Ok((StatusCode::OK, headers, body))
}
