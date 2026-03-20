//! Health check endpoint.
//!
//! Returns the health status of the API, database, and Redis connections.
//! Used by load balancers, monitoring, and readiness probes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use deepmail_common::models::HealthResponse;

use crate::state::AppState;

/// Register health check routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/health/deep", get(health_deep))
}

/// `GET /api/v1/health`
///
/// Returns JSON with connectivity status for database and Redis.
async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    // Check database connectivity
    let db_healthy = state
        .db_pool()
        .get()
        .map(|conn| conn.execute_batch("SELECT 1").is_ok())
        .unwrap_or(false);

    // Check Redis connectivity
    let redis_healthy = {
        let mut queue = state.redis_queue().await;
        queue.health_check().await.unwrap_or(false)
    };

    let overall_status = if db_healthy && redis_healthy {
        "healthy"
    } else {
        "degraded"
    };

    Json(HealthResponse {
        status: overall_status.to_string(),
        database: db_healthy,
        redis: redis_healthy,
        timestamp: deepmail_common::models::now_utc(),
    })
}

async fn health_live() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok")
}

async fn health_ready(State(state): State<AppState>) -> Json<HealthResponse> {
    health_check(State(state)).await
}

#[derive(Debug, Serialize)]
struct DeepHealth {
    status: String,
    database: bool,
    redis: bool,
    sandbox_worker: bool,
    timestamp: String,
}

async fn health_deep(State(state): State<AppState>) -> Json<DeepHealth> {
    let db_healthy = state
        .db_pool()
        .get()
        .map(|conn| conn.execute_batch("SELECT 1").is_ok())
        .unwrap_or(false);

    let (redis_healthy, sandbox_healthy) = {
        let mut queue = state.redis_queue().await;
        let redis_ok = queue.health_check().await.unwrap_or(false);
        let sandbox_ok = queue.sandbox_heartbeat_healthy().await.unwrap_or(false);
        (redis_ok, sandbox_ok)
    };

    let overall_status = if db_healthy && redis_healthy && sandbox_healthy {
        "healthy"
    } else {
        "degraded"
    };

    Json(DeepHealth {
        status: overall_status.to_string(),
        database: db_healthy,
        redis: redis_healthy,
        sandbox_worker: sandbox_healthy,
        timestamp: deepmail_common::models::now_utc(),
    })
}
