use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use deepmail_common::auth::UserRole;
use deepmail_common::errors::DeepMailError;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct Claims {
    pub sub: String,
    #[serde(rename = "exp")]
    pub _exp: usize,
    #[serde(default = "default_role")]
    pub role: String,
    pub jti: String,
    #[serde(rename = "iss")]
    pub _iss: String,
    #[serde(rename = "aud")]
    pub _aud: String,
    pub cnf: String,
}

fn default_role() -> String {
    "analyst".to_string()
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub role: UserRole,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DeepMailError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let config = app_state.config();

        let token = extract_token(parts)?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.set_issuer(&[config.security.jwt_issuer.clone()]);
        validation.set_audience(&[config.security.jwt_audience.clone()]);

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(config.security.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| DeepMailError::Auth(format!("Invalid token: {e}")))?;

        if decoded.claims.sub.trim().is_empty() {
            return Err(DeepMailError::Auth("Token missing subject".to_string()));
        }
        if decoded.claims.jti.trim().is_empty() {
            return Err(DeepMailError::Auth("token is used".to_string()));
        }

        let device_fingerprint = parts
            .headers
            .get("x-device-fingerprint")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if decoded.claims.cnf != device_fingerprint {
            return Err(DeepMailError::Auth("token is used".to_string()));
        }

        let conn = app_state.db_pool().get()?;
        let token_hash = {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            hex::encode(hasher.finalize())
        };
        let is_active = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM auth_tokens
                    WHERE jti = ?1
                      AND user_id = ?2
                      AND token_hash = ?3
                      AND status = 'active'
                      AND revoked_at IS NULL
                      AND expires_at > datetime('now')
                      AND (device_fingerprint IS NULL OR device_fingerprint = ?4)
                )",
                rusqlite::params![
                    decoded.claims.jti,
                    decoded.claims.sub,
                    token_hash,
                    device_fingerprint,
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|v| v == 1)?;

        if !is_active {
            return Err(DeepMailError::Auth("token is used".to_string()));
        }

        let _ = conn.execute(
            "UPDATE auth_tokens SET last_seen_at = datetime('now') WHERE jti = ?1",
            rusqlite::params![decoded.claims.jti],
        );

        let role: UserRole = decoded.claims.role.parse().map_err(DeepMailError::Auth)?;

        Ok(Self {
            user_id: decoded.claims.sub,
            role,
        })
    }
}

fn extract_token(parts: &Parts) -> Result<String, DeepMailError> {
    if let Some(auth) = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        let token = auth
            .strip_prefix("Bearer ")
            .ok_or_else(|| DeepMailError::Auth("Invalid auth scheme".to_string()))?;
        return Ok(token.to_string());
    }

    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            let mut it = pair.splitn(2, '=');
            let key = it.next().unwrap_or("");
            let value = it.next().unwrap_or("");
            if key == "token" && !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    Err(DeepMailError::Auth(
        "Missing Authorization header".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::extract_token;

    #[test]
    fn extracts_token_from_query_parameter() {
        let (mut parts, _) = Request::builder()
            .uri("/api/v1/ws/results/abc?token=query-token")
            .body(())
            .expect("build request")
            .into_parts();

        let token = extract_token(&parts).expect("extract token");
        assert_eq!(token, "query-token");

        parts
            .headers
            .insert("authorization", "Bearer header-token".parse().unwrap());
        let token = extract_token(&parts).expect("extract token from header");
        assert_eq!(token, "header-token");
    }
}

#[derive(Debug, Clone)]
pub struct RequireAdmin(pub AuthUser);

#[async_trait]
impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DeepMailError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.role.has_at_least(&UserRole::Admin) {
            return Err(DeepMailError::Forbidden("Admin role required".to_string()));
        }
        Ok(Self(user))
    }
}

#[derive(Debug, Clone)]
pub struct RequireSuperadmin(pub AuthUser);

#[async_trait]
impl<S> FromRequestParts<S> for RequireSuperadmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = DeepMailError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.role.has_at_least(&UserRole::Superadmin) {
            return Err(DeepMailError::Forbidden(
                "Superadmin role required".to_string(),
            ));
        }
        Ok(Self(user))
    }
}
