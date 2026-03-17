//! API route definitions.
//!
//! All routes are under `/api/v1/`.

pub mod health;
pub mod upload;

use axum::Router;

use crate::state::AppState;

/// Build the `/api/v1` route tree.
pub fn api_routes(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(upload::routes())
        .with_state(state)
}
