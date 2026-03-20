//! Health check endpoint.
//!
//! Returns the health status of the API, database, and Redis connections.
//! Used by load balancers, monitoring, and readiness probes.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use deepmail_common::models::HealthResponse;

use crate::state::AppState;

/// Register health check routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/health", get(health_check))
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
