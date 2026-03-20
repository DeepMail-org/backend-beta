use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use deepmail_common::errors::DeepMailError;

pub async fn enforce_admin_ip_allowlist(
    State(allowlist): State<Vec<String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, DeepMailError> {
    if allowlist.is_empty() {
        return Ok(next.run(request).await);
    }

    let forwarded_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());

    let client_ip = forwarded_ip.unwrap_or_else(|| addr.ip().to_string());
    if allowlist.iter().any(|ip| ip == &client_ip) {
        return Ok(next.run(request).await);
    }

    Err(DeepMailError::Forbidden(format!(
        "IP {client_ip} is not allowed for admin endpoints"
    )))
}
