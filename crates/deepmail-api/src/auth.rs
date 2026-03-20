use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use deepmail_common::config::AppConfig;
use deepmail_common::errors::DeepMailError;

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(rename = "exp")]
    pub _exp: usize,
}

pub fn extract_user_id(headers: &HeaderMap, config: &AppConfig) -> Result<String, DeepMailError> {
    let auth = headers
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

    Ok(decoded.claims.sub)
}
