use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use deepmail_common::errors::DeepMailError;

use crate::auth::RequireAdmin;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/otp/issue", post(issue_otp))
        .route("/auth/redeem", post(redeem_otp))
        .route("/admin/auth/tokens", get(list_tokens))
        .route("/admin/auth/revoke/:jti", post(revoke_token))
        .route("/admin/auth/rotate-weekly", post(rotate_weekly))
}

#[derive(Debug, Deserialize)]
struct IssueOtpRequest {
    username: String,
    email: String,
    phone: String,
    role: Option<String>,
}

#[derive(Debug, Serialize)]
struct IssueOtpResponse {
    code: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct RedeemRequest {
    username: String,
    email: String,
    phone: String,
    code: String,
    device_fingerprint: String,
}

#[derive(Debug, Serialize)]
struct RedeemResponse {
    token: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct TokenRecord {
    jti: String,
    user_id: String,
    role: String,
    status: String,
    issued_at: String,
    expires_at: String,
    revoked_at: Option<String>,
    device_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokensResponse {
    tokens: Vec<TokenRecord>,
}

#[derive(Debug, Serialize)]
struct SimpleMessage {
    message: String,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
    role: String,
    jti: String,
    iss: String,
    aud: String,
    cnf: String,
}

async fn issue_otp(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    RequireAdmin(admin): RequireAdmin,
    Json(req): Json<IssueOtpRequest>,
) -> Result<(StatusCode, Json<IssueOtpResponse>), DeepMailError> {
    enforce_mtls_header(&state, &headers)?;

    let username = req.username.trim();
    let email = req.email.trim();
    let phone = req.phone.trim();
    if username.is_empty() || email.is_empty() || phone.is_empty() {
        return Err(DeepMailError::Validation(
            "username, email, and phone are required".to_string(),
        ));
    }

    let role = req.role.unwrap_or_else(|| "analyst".to_string());
    if role != "analyst" && role != "admin" && role != "superadmin" {
        return Err(DeepMailError::Validation("invalid role".to_string()));
    }

    let code = generate_otp_code();
    let code_hash = hash_value(&code);
    let expires_at = (Utc::now() + Duration::minutes(state.config().security.otp_ttl_minutes as i64))
        .to_rfc3339();

    let conn = state.db_pool().get()?;
    conn.execute(
        "INSERT INTO auth_otp_codes (id, username, email, phone, code_hash, issued_by, expires_at, max_attempts, requester_ip)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            Uuid::new_v4().to_string(),
            username,
            email,
            phone,
            code_hash,
            admin.user_id,
            expires_at,
            state.config().security.otp_max_attempts,
            addr.ip().to_string(),
        ],
    )?;

    log_auth_audit(
        state.db_pool(),
        "otp_issued",
        Some(username),
        None,
        Some(&addr.ip().to_string()),
        Some("one-time code issued"),
    )?;

    Ok((StatusCode::CREATED, Json(IssueOtpResponse { code, expires_at })))
}

async fn redeem_otp(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RedeemRequest>,
) -> Result<(StatusCode, Json<RedeemResponse>), DeepMailError> {
    enforce_mtls_header(&state, &headers)?;

    enforce_otp_rate_limits(&state, req.username.trim(), addr.ip().to_string()).await?;

    let username = req.username.trim();
    let email = req.email.trim();
    let phone = req.phone.trim();
    let code = req.code.trim();
    let fp = req.device_fingerprint.trim();
    if username.is_empty() || email.is_empty() || phone.is_empty() || code.is_empty() || fp.is_empty() {
        return Err(DeepMailError::Validation(
            "username, email, phone, code, and device_fingerprint are required".to_string(),
        ));
    }

    let conn = state.db_pool().get()?;
    let row = conn
        .query_row(
            "SELECT id, code_hash, attempts, max_attempts, lockout_until
             FROM auth_otp_codes
             WHERE username = ?1 AND email = ?2 AND phone = ?3
               AND used_at IS NULL AND expires_at > datetime('now')
             ORDER BY issued_at DESC
             LIMIT 1",
            rusqlite::params![username, email, phone],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .map_err(|_| DeepMailError::Auth("token is used".to_string()))?;

    if let Some(lockout_until) = row.4.as_ref() {
        let locked = conn.query_row(
            "SELECT (?1 > datetime('now'))",
            rusqlite::params![lockout_until],
            |r| r.get::<_, i64>(0),
        )?;
        if locked == 1 {
            return Err(DeepMailError::Auth("token is used".to_string()));
        }
    }

    if row.1 != hash_value(code) {
        let new_attempts = row.2 + 1;
        let lockout_until = if new_attempts >= row.3 {
            Some((Utc::now() + Duration::seconds(state.config().security.otp_lockout_secs as i64)).to_rfc3339())
        } else {
            None
        };
        conn.execute(
            "UPDATE auth_otp_codes SET attempts = ?1, lockout_until = ?2 WHERE id = ?3",
            rusqlite::params![new_attempts, lockout_until, row.0],
        )?;
        if new_attempts >= row.3 {
            tracing::warn!(username = username, ip = %addr.ip(), "OTP lockout triggered");
        }
        log_auth_audit(
            state.db_pool(),
            "otp_redeem_failed",
            Some(username),
            None,
            Some(&addr.ip().to_string()),
            Some("invalid one-time code"),
        )?;
        return Err(DeepMailError::Auth("token is used".to_string()));
    }

    conn.execute(
        "UPDATE auth_otp_codes SET used_at = datetime('now') WHERE id = ?1",
        rusqlite::params![row.0],
    )?;

    ensure_user_exists(&conn, username, email)?;

    let jti = Uuid::new_v4().to_string();
    let expires_at_dt = Utc::now() + Duration::days(state.config().security.token_ttl_days as i64);
    let expires_at = expires_at_dt.to_rfc3339();

    let claims = JwtClaims {
        sub: username.to_string(),
        exp: expires_at_dt.timestamp() as usize,
        role: "analyst".to_string(),
        jti: jti.clone(),
        iss: state.config().security.jwt_issuer.clone(),
        aud: state.config().security.jwt_audience.clone(),
        cnf: fp.to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config().security.jwt_secret.as_bytes()),
    )
    .map_err(|e| DeepMailError::Auth(format!("Failed to sign token: {e}")))?;

    conn.execute(
        "INSERT INTO auth_tokens (jti, user_id, token_hash, role, expires_at, status, device_fingerprint, first_seen_ip, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, datetime('now'))",
        rusqlite::params![
            jti,
            username,
            hash_value(&token),
            "analyst",
            expires_at,
            fp,
            addr.ip().to_string(),
        ],
    )?;

    log_auth_audit(
        state.db_pool(),
        "otp_redeemed",
        Some(username),
        Some(&claims.jti),
        Some(&addr.ip().to_string()),
        Some("jwt issued"),
    )?;

    Ok((StatusCode::OK, Json(RedeemResponse { token, expires_at })))
}

async fn list_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    RequireAdmin(_admin): RequireAdmin,
) -> Result<Json<TokensResponse>, DeepMailError> {
    enforce_mtls_header(&state, &headers)?;
    let conn = state.db_pool().get()?;
    let mut stmt = conn.prepare(
        "SELECT jti, user_id, role, status, issued_at, expires_at, revoked_at, device_fingerprint
         FROM auth_tokens
         ORDER BY issued_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TokenRecord {
            jti: r.get(0)?,
            user_id: r.get(1)?,
            role: r.get(2)?,
            status: r.get(3)?,
            issued_at: r.get(4)?,
            expires_at: r.get(5)?,
            revoked_at: r.get(6)?,
            device_fingerprint: r.get(7)?,
        })
    })?;
    let tokens = rows.collect::<Result<Vec<_>, _>>()?;
    log_auth_audit(
        state.db_pool(),
        "token_listed",
        None,
        None,
        Some(&addr.ip().to_string()),
        Some("admin listed tokens"),
    )?;
    Ok(Json(TokensResponse { tokens }))
}

async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    RequireAdmin(_admin): RequireAdmin,
    Path(jti): Path<String>,
) -> Result<Json<SimpleMessage>, DeepMailError> {
    enforce_mtls_header(&state, &headers)?;
    let conn = state.db_pool().get()?;
    conn.execute(
        "UPDATE auth_tokens SET status = 'revoked', revoked_at = datetime('now') WHERE jti = ?1",
        rusqlite::params![jti],
    )?;
    log_auth_audit(
        state.db_pool(),
        "token_revoked",
        None,
        Some(&jti),
        Some(&addr.ip().to_string()),
        Some("admin revoked token"),
    )?;
    Ok(Json(SimpleMessage {
        message: "token revoked".to_string(),
    }))
}

async fn rotate_weekly(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    RequireAdmin(_admin): RequireAdmin,
) -> Result<Json<SimpleMessage>, DeepMailError> {
    enforce_mtls_header(&state, &headers)?;
    let conn = state.db_pool().get()?;
    conn.execute(
        "UPDATE auth_tokens
         SET status = 'expired'
         WHERE status = 'active' AND expires_at <= datetime('now')",
        [],
    )?;
    log_auth_audit(
        state.db_pool(),
        "token_rotated_weekly",
        None,
        None,
        Some(&addr.ip().to_string()),
        Some("weekly rotation applied"),
    )?;
    Ok(Json(SimpleMessage {
        message: "weekly rotation completed".to_string(),
    }))
}

async fn enforce_otp_rate_limits(
    state: &AppState,
    username: &str,
    ip: String,
) -> Result<(), DeepMailError> {
    let mut queue = state.redis_queue().await;
    let cap = state.config().reliability.rate_limit_capacity;
    let refill = state.config().reliability.rate_limit_refill_per_sec;

    let (user_allowed, _, _) = queue
        .check_rate_limit_token_bucket("otp_user", username, cap, refill, 1)
        .await?;
    if !user_allowed {
        return Err(DeepMailError::RateLimited);
    }

    let (ip_allowed, _, _) = queue
        .check_rate_limit_token_bucket("otp_ip", &ip, cap, refill, 1)
        .await?;
    if !ip_allowed {
        return Err(DeepMailError::RateLimited);
    }
    Ok(())
}

fn enforce_mtls_header(state: &AppState, headers: &HeaderMap) -> Result<(), DeepMailError> {
    if !state.config().security.mtls_required_for_auth_admin {
        return Ok(());
    }
    let fingerprint = headers
        .get("x-client-cert-fingerprint")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DeepMailError::Forbidden("mTLS fingerprint required".to_string()))?;
    if state
        .config()
        .security
        .trusted_client_cert_fingerprints
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(fingerprint))
    {
        Ok(())
    } else {
        Err(DeepMailError::Forbidden(
            "mTLS fingerprint not trusted".to_string(),
        ))
    }
}

fn generate_otp_code() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn hash_value(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn ensure_user_exists(conn: &rusqlite::Connection, user_id: &str, email: &str) -> Result<(), DeepMailError> {
    let exists = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
            rusqlite::params![user_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value == 1)?;

    if exists {
        return Ok(());
    }

    conn.execute(
        "INSERT INTO users (id, username, email, password_hash, role, is_active)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        rusqlite::params![user_id, user_id, email, "external-auth", "analyst"],
    )?;
    Ok(())
}

fn log_auth_audit(
    db_pool: &deepmail_common::db::DbPool,
    event_type: &str,
    user_id: Option<&str>,
    jti: Option<&str>,
    source_ip: Option<&str>,
    detail: Option<&str>,
) -> Result<(), DeepMailError> {
    let conn = db_pool.get()?;
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT immutable_hash FROM auth_audit ORDER BY created_at DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();

    let material = format!(
        "{}|{}|{}|{}|{}|{}",
        prev_hash.clone().unwrap_or_default(),
        event_type,
        user_id.unwrap_or_default(),
        jti.unwrap_or_default(),
        source_ip.unwrap_or_default(),
        detail.unwrap_or_default()
    );
    let immutable_hash = hash_value(&material);

    conn.execute(
        "INSERT INTO auth_audit (id, event_type, user_id, jti, source_ip, detail, immutable_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            Uuid::new_v4().to_string(),
            event_type,
            user_id,
            jti,
            source_ip,
            detail,
            immutable_hash,
        ],
    )?;

    tracing::info!(
        target: "siem.auth",
        event_type = event_type,
        user_id = user_id.unwrap_or(""),
        jti = jti.unwrap_or(""),
        source_ip = source_ip.unwrap_or(""),
        detail = detail.unwrap_or(""),
        "Auth audit event"
    );
    Ok(())
}
