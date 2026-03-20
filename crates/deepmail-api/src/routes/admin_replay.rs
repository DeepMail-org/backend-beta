use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::Serialize;

use deepmail_common::errors::DeepMailError;
use deepmail_common::queue::{
    QUEUE_DLQ_EMAIL, QUEUE_DLQ_SANDBOX, QUEUE_EMAIL_ANALYSIS, QUEUE_SANDBOX,
};

use crate::auth::RequireAdmin;
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct ReplayResponse {
    stream_entry_id: String,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/admin/replay/{queue}/{entry_id}", post(replay_handler))
}

async fn replay_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Path((queue_name, entry_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<ReplayResponse>), DeepMailError> {
    let (dlq, target) = match queue_name.as_str() {
        "email" => (QUEUE_DLQ_EMAIL, QUEUE_EMAIL_ANALYSIS),
        "sandbox" => (QUEUE_DLQ_SANDBOX, QUEUE_SANDBOX),
        _ => {
            return Err(DeepMailError::Validation(
                "queue must be email or sandbox".to_string(),
            ))
        }
    };

    let stream_entry_id = {
        let mut queue = state.redis_queue().await;
        queue.replay_dlq_entry(dlq, target, &entry_id).await?
    };

    Ok((StatusCode::OK, Json(ReplayResponse { stream_entry_id })))
}
