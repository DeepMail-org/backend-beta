//! DeepMail API Server — Axum-based HTTP layer.
//!
//! This is the lightweight API gateway. It handles:
//! - File uploads with security validation
//! - Job dispatch to Redis
//! - Health checks
//! - Rate limiting and request size constraints
//!
//! **No heavy processing happens here.** All analysis is delegated to workers.

mod auth;
mod middleware;
mod routes;
mod state;

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use deepmail_common::config::AppConfig;
use deepmail_common::db;
use deepmail_common::queue::RedisQueue;
use deepmail_common::retention;
use deepmail_common::upload::quarantine;

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = AppConfig::load()?;

    // Initialize structured logging
    deepmail_common::telemetry::init_tracing(
        &config.logging,
        &config.observability,
        "deepmail-api",
    );

    tracing::info!("DeepMail API Server starting...");

    // Initialize SQLite connection pool (WAL mode, migrations auto-applied)
    let db_pool = db::init_pool(&config.database)?;
    tracing::info!("Database initialized");

    // Initialize Redis connection
    let redis_queue = RedisQueue::new(&config.redis).await?;
    tracing::info!("Redis queue connected");

    // Initialize quarantine directory
    let quarantine_dir = quarantine::init_quarantine_dir(&config.upload.quarantine_path)?;
    tracing::info!(path = %quarantine_dir.display(), "Quarantine directory ready");

    // Build application state
    let app_state = AppState::new(db_pool, redis_queue, config.clone(), quarantine_dir);

    // Start retention cleanup background loop
    {
        let db_pool = app_state.db_pool().clone();
        let retention_cfg = config.retention.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = retention::run_retention_cleanup(&db_pool, &retention_cfg) {
                    tracing::error!(error = %e, "Retention cleanup failed");
                }
                tokio::time::sleep(Duration::from_secs(retention_cfg.cleanup_interval_secs)).await;
            }
        });
    }

    // Build the router with middleware stack
    let app = build_router(app_state, &config);

    // Bind and serve
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid server address: {e}"))?;

    tracing::info!(%addr, "DeepMail API listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Server shut down gracefully");
    Ok(())
}

/// Build the Axum router with all routes and middleware.
fn build_router(state: AppState, config: &AppConfig) -> Router {
    let api_routes = routes::api_routes(state.clone());

    Router::new()
        .nest("/api/v1", api_routes)
        // ── Middleware stack (applied bottom-to-top) ──
        // Request body size limit
        .layer(RequestBodyLimitLayer::new(config.server.max_body_size))
        // CORS (restrictive in production — adjust origins as needed)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
                .max_age(Duration::from_secs(3600)),
        )
        // Request tracing
        .layer(TraceLayer::new_for_http())
}

/// Graceful shutdown signal handler.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down..."),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down..."),
    }
}
