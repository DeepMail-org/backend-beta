mod config;

use crate::config::Config;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

/// Re-exported gRPC types from deepmail-common proto definitions.
use deepmail_common::proto::dkim::v1::{
    dkim_analyzer_server::{DkimAnalyzer, DkimAnalyzerServer},
    DkimAnalysisRequest, DkimAnalysisResult, KeyRotationRequest, KeyRotationResult,
};

// ─── Service Implementation (stub) ─────────────────────────────────────────

/// The DkimAnalyzerService holds all shared state: DB pool, DNS resolver config,
/// NATS client, and service configuration.
#[allow(dead_code)] // Fields used once TODO stubs are implemented.
pub struct DkimAnalyzerService {
    pool: sqlx::PgPool,
    config: Config,
}

impl DkimAnalyzerService {
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        Self { pool, config }
    }
}

#[tonic::async_trait]
impl DkimAnalyzer for DkimAnalyzerService {
    async fn analyze_dkim(
        &self,
        request: tonic::Request<DkimAnalysisRequest>,
    ) -> Result<tonic::Response<DkimAnalysisResult>, tonic::Status> {
        let req = request.into_inner();
        info!(email_id = %req.email_id, "Starting DKIM analysis");

        // TODO: Implement full DKIM replay analysis pipeline:
        //   1. Parse all DKIM-Signature headers from raw_headers
        //   2. For each signature:
        //      a. Resolve DNS TXT record at {selector}._domainkey.{domain}
        //      b. Apply canonicalization (simple/relaxed) from c= tag
        //      c. Recompute body hash and compare with bh= tag
        //      d. Verify cryptographic signature (RSA/Ed25519)
        //      e. Compute timestamp deltas
        //   3. Aggregate signal weights → replay_confidence
        //   4. Publish result to NATS deepmail.events.dkim.{email_id}

        Err(tonic::Status::unimplemented(
            "DKIM analysis not yet implemented",
        ))
    }

    async fn check_key_rotation(
        &self,
        request: tonic::Request<KeyRotationRequest>,
    ) -> Result<tonic::Response<KeyRotationResult>, tonic::Status> {
        let req = request.into_inner();
        info!(
            selector = %req.selector,
            domain = %req.domain,
            "Checking DKIM key rotation"
        );

        // TODO: Implement key rotation check:
        //   1. Resolve current DNS TXT record for the selector
        //   2. Compare against cached key at signing_timestamp
        //   3. Return rotation status

        Err(tonic::Status::unimplemented(
            "Key rotation check not yet implemented",
        ))
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Initialize tracing with JSON output ──────────────────────────
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("deepmail-dkim starting up");

    // ── 2. Load configuration ───────────────────────────────────────────
    let config = Config::load().map_err(|e| {
        error!(error = %e, "Failed to load configuration");
        e
    })?;
    info!(grpc_addr = %config.grpc_addr, "Configuration loaded");

    // ── 3. Create PostgreSQL connection pool ─────────────────────────────
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to connect to PostgreSQL");
            e
        })?;
    info!("PostgreSQL connection pool established");

    // ── 4. Run database migrations ──────────────────────────────────────
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Database migration failed");
            e
        })?;
    info!("Database migrations applied");

    // ── 5. Build gRPC service ───────────────────────────────────────────
    let grpc_addr = config.grpc_addr;
    let service = DkimAnalyzerService::new(pool, config);
    let server = DkimAnalyzerServer::new(service);

    info!(addr = %grpc_addr, "Starting gRPC server");

    // ── 6. Start server with graceful shutdown ──────────────────────────
    Server::builder()
        .add_service(server)
        .serve_with_shutdown(grpc_addr, async {
            // Wait for SIGTERM (container orchestrator) or Ctrl+C.
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");

            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => info!("Received Ctrl+C, shutting down"),
                _ = sigterm.recv() => info!("Received SIGTERM, shutting down"),
            }

            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
                info!("Received Ctrl+C, shutting down");
            }
        })
        .await?;

    info!("deepmail-dkim shut down gracefully");
    Ok(())
}
