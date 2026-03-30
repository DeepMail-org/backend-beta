use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;

use deepmail_common::errors::DeepMailError;

use crate::auth::AuthUser;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/ws/results/:email_id", get(ws_handler))
}

async fn ws_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: AuthUser,
    Path(email_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, DeepMailError> {
    let user_id = auth.user_id;
    {
        let conn = state.db_pool().get()?;
        let owns: Option<String> = conn
            .query_row(
                "SELECT id FROM emails
                 WHERE id = ?1 AND submitted_by = ?2 AND is_deleted = 0 AND archived_at IS NULL",
                rusqlite::params![email_id, user_id],
                |row| row.get(0),
            )
            .ok();
        if owns.is_none() {
            return Err(DeepMailError::NotFound("Email not found".to_string()));
        }
    }

    {
        let mut queue = state.redis_queue().await;
        let (user_allowed, _, _) = queue
            .check_rate_limit_token_bucket(
                "user",
                &format!("{user_id}:ws_results"),
                state.config().reliability.rate_limit_capacity,
                state.config().reliability.rate_limit_refill_per_sec,
                1,
            )
            .await?;
        if !user_allowed {
            return Err(DeepMailError::RateLimited);
        }
        let (ip_allowed, _, _) = queue
            .check_rate_limit_token_bucket(
                "ip",
                &format!("{}:ws_results", addr.ip()),
                state.config().reliability.rate_limit_capacity,
                state.config().reliability.rate_limit_refill_per_sec,
                1,
            )
            .await?;
        if !ip_allowed {
            return Err(DeepMailError::RateLimited);
        }
    }

    let redis_url = state.config().redis.url.clone();
    let channel = state.config().sandbox.progress_channel.clone();
    Ok(ws.on_upgrade(move |socket| stream_progress(socket, email_id, redis_url, channel)))
}

async fn stream_progress(
    mut socket: WebSocket,
    email_id: String,
    redis_url: String,
    channel: String,
) {
    let client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            let _ = socket
                .send(Message::Text(
                    format!("{{\"error\":\"redis client: {e}\"}}").into(),
                ))
                .await;
            return;
        }
    };

    let mut pubsub = match client.get_async_pubsub().await {
        Ok(c) => c,
        Err(e) => {
            let _ = socket
                .send(Message::Text(
                    format!("{{\"error\":\"redis connection: {e}\"}}").into(),
                ))
                .await;
            return;
        }
    };

    if let Err(e) = pubsub.subscribe(&channel).await {
        let _ = socket
            .send(Message::Text(
                format!("{{\"error\":\"subscribe: {e}\"}}").into(),
            ))
            .await;
        return;
    }

    let mut messages = pubsub.on_message();

    loop {
        tokio::select! {
            maybe_msg = messages.next() => {
                let Some(msg) = maybe_msg else {
                    break;
                };
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let parsed: serde_json::Value = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let event_email = parsed.get("email_id").and_then(|v| v.as_str()).unwrap_or("");
                if event_email == email_id {
                    if socket.send(Message::Text(payload.into())).await.is_err() {
                        break;
                    }
                }
            }
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}
