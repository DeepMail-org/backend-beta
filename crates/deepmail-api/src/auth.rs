use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

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

        let auth = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| DeepMailError::Auth("Missing Authorization header".to_string()))?;

        let token = auth
            .strip_prefix("Bearer ")
            .ok_or_else(|| DeepMailError::Auth("Invalid auth scheme".to_string()))?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(config.security.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| DeepMailError::Auth(format!("Invalid token: {e}")))?;

        if decoded.claims.sub.trim().is_empty() {
            return Err(DeepMailError::Auth("Token missing subject".to_string()));
        }

        let role: UserRole = decoded.claims.role.parse().map_err(DeepMailError::Auth)?;

        Ok(Self {
            user_id: decoded.claims.sub,
            role,
        })
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
