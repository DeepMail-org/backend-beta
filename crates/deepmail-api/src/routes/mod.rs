//! API route definitions.
//!
//! All routes are under `/api/v1/`.

pub mod admin_abuse;
pub mod admin_backup;
pub mod admin_replay;
pub mod auth_tokens;
pub mod dashboard;
pub mod health;
pub mod metrics;
pub mod results;
pub mod upload;
pub mod ws_results;

use axum::middleware;
use axum::Router;

use crate::middleware::ip_allowlist;
use crate::state::AppState;

/// Build the `/api/v1` route tree.
pub fn api_routes(state: AppState) -> Router {
    let admin_allowlist = state.config().security.admin_ip_allowlist.clone();
    let admin_routes = Router::new()
        .merge(admin_abuse::routes())
        .merge(admin_replay::routes())
        .merge(admin_backup::routes())
        .route_layer(middleware::from_fn_with_state(
            admin_allowlist,
            ip_allowlist::enforce_admin_ip_allowlist,
        ));

    Router::new()
        .merge(dashboard::routes())
        .merge(health::routes())
        .merge(upload::routes())
        .merge(auth_tokens::routes())
        .merge(results::routes())
        .merge(metrics::routes())
        .merge(admin_routes)
        .merge(ws_results::routes())
        .with_state(state)
}
