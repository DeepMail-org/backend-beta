use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use deepmail_common::abuse;
use deepmail_common::errors::DeepMailError;

use crate::auth::RequireAdmin;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct ListQuery {
    user_id: Option<String>,
    severity: Option<String>,
    reviewed: Option<bool>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AbuseEventDto {
    id: String,
    user_id: String,
    event_type: String,
    severity: String,
    details: Option<String>,
    auto_flagged: bool,
    reviewed_by: Option<String>,
    reviewed_at: Option<String>,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

#[derive(Debug, Deserialize)]
struct FlagRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ReviewRequest {
    notes: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/abuse/events", get(list_events))
        .route("/admin/abuse/events/{id}", get(get_event))
        .route("/admin/abuse/events/{id}/review", post(review_event))
        .route("/admin/abuse/flag/{user_id}", post(flag_user))
        .route("/admin/abuse/unflag/{user_id}", post(unflag_user))
}

async fn list_events(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<AbuseEventDto>>, DeepMailError> {
    let conn = state.db_pool().get()?;
    let mut sql = "SELECT id, user_id, event_type, severity, details, auto_flagged, reviewed_by, reviewed_at, created_at FROM abuse_events WHERE 1=1".to_string();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(user_id) = query.user_id {
        sql.push_str(&format!(" AND user_id = ?{}", params.len() + 1));
        params.push(Box::new(user_id));
    }
    if let Some(severity) = query.severity {
        sql.push_str(&format!(" AND severity = ?{}", params.len() + 1));
        params.push(Box::new(severity));
    }
    if let Some(reviewed) = query.reviewed {
        if reviewed {
            sql.push_str(" AND reviewed_at IS NOT NULL");
        } else {
            sql.push_str(" AND reviewed_at IS NULL");
        }
    }

    let limit = query.limit.unwrap_or(100).min(500) as i64;
    sql.push_str(&format!(
        " ORDER BY created_at DESC LIMIT ?{}",
        params.len() + 1
    ));
    params.push(Box::new(limit));

    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(refs.as_slice(), |row| {
        Ok(AbuseEventDto {
            id: row.get(0)?,
            user_id: row.get(1)?,
            event_type: row.get(2)?,
            severity: row.get(3)?,
            details: row.get(4)?,
            auto_flagged: row.get::<_, i64>(5)? == 1,
            reviewed_by: row.get(6)?,
            reviewed_at: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;

    Ok(Json(rows.filter_map(|r| r.ok()).collect()))
}

async fn get_event(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Path(id): Path<String>,
) -> Result<Json<AbuseEventDto>, DeepMailError> {
    let conn = state.db_pool().get()?;
    let event = conn
        .query_row(
            "SELECT id, user_id, event_type, severity, details, auto_flagged, reviewed_by, reviewed_at, created_at
             FROM abuse_events WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(AbuseEventDto {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    event_type: row.get(2)?,
                    severity: row.get(3)?,
                    details: row.get(4)?,
                    auto_flagged: row.get::<_, i64>(5)? == 1,
                    reviewed_by: row.get(6)?,
                    reviewed_at: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        )
        .map_err(|_| DeepMailError::NotFound("Abuse event not found".to_string()))?;

    Ok(Json(event))
}

async fn flag_user(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(user_id): Path<String>,
    Json(body): Json<FlagRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), DeepMailError> {
    abuse::flag_user(state.db_pool(), &user_id, &body.reason)?;
    let _ = abuse::record_abuse_event(
        state.db_pool(),
        &user_id,
        "manual_flag",
        "critical",
        Some(&body.reason),
        false,
    );
    let _ = deepmail_common::audit::log_audit(
        state.db_pool(),
        "admin_abuse_flag",
        "users",
        Some(&format!("target_user={user_id}, reason={}", body.reason)),
        Some(&admin.user_id),
        None,
    );

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: format!("User {user_id} flagged"),
        }),
    ))
}

async fn unflag_user(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(user_id): Path<String>,
) -> Result<(StatusCode, Json<MessageResponse>), DeepMailError> {
    abuse::unflag_user(state.db_pool(), &user_id)?;
    let _ = deepmail_common::audit::log_audit(
        state.db_pool(),
        "admin_abuse_unflag",
        "users",
        Some(&format!("target_user={user_id}")),
        Some(&admin.user_id),
        None,
    );

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: format!("User {user_id} unflagged"),
        }),
    ))
}

async fn review_event(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(id): Path<String>,
    Json(body): Json<ReviewRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), DeepMailError> {
    let conn = state.db_pool().get()?;
    conn.execute(
        "UPDATE abuse_events SET reviewed_by = ?1, reviewed_at = ?2 WHERE id = ?3",
        rusqlite::params![admin.user_id, chrono::Utc::now().to_rfc3339(), id],
    )?;
    let _ = deepmail_common::audit::log_audit(
        state.db_pool(),
        "admin_abuse_review",
        "abuse_events",
        body.notes.as_deref(),
        Some(&admin.user_id),
        None,
    );
    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "Event marked as reviewed".to_string(),
        }),
    ))
}
