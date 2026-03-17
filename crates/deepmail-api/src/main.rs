//! DeepMail API Server — Axum-based HTTP layer.
//!
//! This is the lightweight API gateway. It handles:
//! - File uploads with security validation
//! - Job dispatch to Redis
//! - Health checks
//! - Rate limiting and request size constraints
//!
//! **No heavy processing happens here.** All analysis is delegated to workers.

mod middleware;
mod routes;
mod state;

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use deepmail_common::config::AppConfig;
use deepmail_common::db;
use deepmail_common::queue::RedisQueue;
use deepmail_common::upload::quarantine;

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = AppConfig::load()?;

    // Initialize structured logging
    init_tracing(&config.logging.level, &config.logging.format);

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

    // Build the router with middleware stack
    let app = build_router(app_state, &config);

    // Bind and serve
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid server address: {e}"))?;

    tracing::info!(%addr, "DeepMail API listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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

/// Initialize the tracing subscriber for structured logging.
fn init_tracing(level: &str, format: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .pretty()
                .init();
        }
    }
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
