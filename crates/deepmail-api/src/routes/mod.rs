//! API route definitions.
//!
//! All routes are under `/api/v1/`.

pub mod admin_replay;
pub mod health;
pub mod metrics;
pub mod results;
pub mod upload;
pub mod ws_results;

use axum::Router;

use crate::state::AppState;

/// Build the `/api/v1` route tree.
pub fn api_routes(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(upload::routes())
        .merge(results::routes())
        .merge(metrics::routes())
        .merge(admin_replay::routes())
        .merge(ws_results::routes())
        .with_state(state)
}
