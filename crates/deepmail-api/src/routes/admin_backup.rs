use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use deepmail_common::backup::{self, BackupManifest};
use deepmail_common::db::migrations::MIGRATION_COUNT;
use deepmail_common::errors::DeepMailError;

use crate::state::AppState;

#[derive(Debug, Serialize)]
struct BackupResponse {
    backup_path: String,
    manifest: BackupManifest,
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    backup_path: String,
    passphrase: String,
}

#[derive(Debug, Serialize)]
struct RestoreResponse {
    manifest: BackupManifest,
    message: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/backup", post(backup_handler))
        .route("/admin/restore", post(restore_handler))
}

async fn backup_handler(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<BackupResponse>), DeepMailError> {
    let result = backup::create_backup(state.db_pool(), &state.config().backup, MIGRATION_COUNT)?;

    let _ = deepmail_common::audit::log_audit(
        state.db_pool(),
        "admin_backup_create",
        "database",
        Some(&result.backup_path),
        Some("00000000-0000-0000-0000-000000000000"),
        None,
    );

    Ok((
        StatusCode::OK,
        Json(BackupResponse {
            backup_path: result.backup_path,
            manifest: result.manifest,
        }),
    ))
}

async fn restore_handler(
    State(state): State<AppState>,
    Json(request): Json<RestoreRequest>,
) -> Result<(StatusCode, Json<RestoreResponse>), DeepMailError> {
    let manifest = backup::restore_backup(
        state.db_pool(),
        &request.backup_path,
        &request.passphrase,
        MIGRATION_COUNT,
    )?;

    let _ = deepmail_common::audit::log_audit(
        state.db_pool(),
        "admin_backup_restore",
        "database",
        Some(&request.backup_path),
        Some("00000000-0000-0000-0000-000000000000"),
        None,
    );

    Ok((
        StatusCode::OK,
        Json(RestoreResponse {
            manifest,
            message: "Restore completed. Restart services to ensure full consistency.".to_string(),
        }),
    ))
}
