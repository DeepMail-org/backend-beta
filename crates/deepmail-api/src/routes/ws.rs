//! WebSocket handler for real-time analysis updates.

use axum::{
    extract::{Path, State, ws::{Message, WebSocket, WebSocketUpgrade}},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use crate::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(email_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, email_id, state))
}

async fn handle_socket(socket: WebSocket, email_id: String, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    tracing::info!(email_id = %email_id, "WebSocket client connected");

    // Subscribe to Redis pub/sub channel for this email
    // Channel: deepmail:updates:{email_id}
    let mut pubsub = state.redis_conn.clone().into_pubsub();
    let channel = format!("deepmail:updates:{}", email_id);
    
    if let Ok(_) = pubsub.subscribe(&channel).await {
        let mut msg_stream = pubsub.on_message();
        
        while let Some(msg) = msg_stream.next().await {
            if let Ok(payload) = msg.get_payload::<String>() {
                if sender.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!(email_id = %email_id, "WebSocket client disconnected");
}
