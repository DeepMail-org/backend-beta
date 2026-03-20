use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/ws/results/{email_id}", get(ws_handler))
}

async fn ws_handler(
    State(state): State<AppState>,
    Path(email_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
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
