use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;

use crate::auth::extract_user_id;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/ws/results/{email_id}", get(ws_handler))
}

async fn ws_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(email_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let user_id =
        extract_user_id(&headers, state.config()).map_err(|_| StatusCode::UNAUTHORIZED)?;
    {
        let conn = state
            .db_pool()
            .get()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let owns: Option<String> = conn
            .query_row(
                "SELECT id FROM emails WHERE id = ?1 AND submitted_by = ?2",
                rusqlite::params![email_id, user_id],
                |row| row.get(0),
            )
            .ok();
        if owns.is_none() {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    {
        let mut queue = state.redis_queue().await;
        let (user_allowed, _) = queue
            .check_rate_limit(
                "user",
                &format!("{user_id}:ws_results"),
                state.config().security.rate_limit_burst,
                60,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !user_allowed {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let (ip_allowed, _) = queue
            .check_rate_limit(
                "ip",
                &format!("{}:ws_results", addr.ip()),
                state.config().security.rate_limit_burst,
                60,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !ip_allowed {
            return Err(StatusCode::TOO_MANY_REQUESTS);
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
