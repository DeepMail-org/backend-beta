use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use deepmail_common::errors::DeepMailError;

use crate::state::AppState;

pub async fn enforce_mtls_for_auth_admin(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, DeepMailError> {
    if !state.config().security.mtls_required_for_auth_admin {
        return Ok(next.run(req).await);
    }

    let path = req.uri().path();
    let protected = path.starts_with("/api/v1/admin/") || path.starts_with("/api/v1/auth/");
    if !protected {
        return Ok(next.run(req).await);
    }

    let fingerprint = req
        .headers()
        .get("x-client-cert-fingerprint")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DeepMailError::Forbidden("mTLS fingerprint required".to_string()))?;

    let trusted = state
        .config()
        .security
        .trusted_client_cert_fingerprints
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(fingerprint));

    if !trusted {
        return Err(DeepMailError::Forbidden(
            "mTLS fingerprint not trusted".to_string(),
        ));
    }

    Ok(next.run(req).await)
}
