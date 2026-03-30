//! Unified error types for the DeepMail platform.
//!
//! All modules return `DeepMailError` variants. The error type implements
//! `IntoResponse` for Axum so that handler functions can use `?` and errors
//! are automatically converted to structured JSON error responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Central error enum for all DeepMail operations.
#[derive(Debug, thiserror::Error)]
pub enum DeepMailError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Redis error: {0}")]
    Redis(String),

    #[error("Upload validation failed: {0}")]
    Validation(String),

    #[error("Upload error: {0}")]
    Upload(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for DeepMailError {
    fn into_response(self) -> Response {
        let (status, error_type) = match &self {
            DeepMailError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            DeepMailError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
            DeepMailError::Redis(_) => (StatusCode::SERVICE_UNAVAILABLE, "redis_error"),
            DeepMailError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            DeepMailError::Upload(_) => (StatusCode::BAD_REQUEST, "upload_error"),
            DeepMailError::Auth(_) => (StatusCode::UNAUTHORIZED, "auth_error"),
            DeepMailError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            DeepMailError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            DeepMailError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            DeepMailError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        // SECURITY: Never leak internal error details in production.
        // Log the full error server-side, return a safe message to clients.
        let safe_message = match &self {
            DeepMailError::Validation(msg) => msg.clone(),
            DeepMailError::Upload(msg) => msg.clone(),
            DeepMailError::Auth(msg) if msg == "token is used" => msg.clone(),
            DeepMailError::Auth(_) => "Authentication failed".to_string(),
            DeepMailError::RateLimited => "Rate limit exceeded. Try again later.".to_string(),
            DeepMailError::NotFound(msg) => msg.clone(),
            DeepMailError::Forbidden(msg) => msg.clone(),
            // For all server-side errors, return a generic message
            _ => "An internal error occurred".to_string(),
        };

        tracing::error!(error_type = error_type, details = %self, "Request error");

        let body = json!({
            "error": {
                "type": error_type,
                "message": safe_message,
            }
        });

        (status, axum::Json(body)).into_response()
    }
}

// Convenience conversions from common error types

impl From<rusqlite::Error> for DeepMailError {
    fn from(e: rusqlite::Error) -> Self {
        DeepMailError::Database(e.to_string())
    }
}

impl From<r2d2::Error> for DeepMailError {
    fn from(e: r2d2::Error) -> Self {
        DeepMailError::Database(format!("Connection pool error: {e}"))
    }
}

impl From<redis::RedisError> for DeepMailError {
    fn from(e: redis::RedisError) -> Self {
        DeepMailError::Redis(e.to_string())
    }
}

impl From<std::io::Error> for DeepMailError {
    fn from(e: std::io::Error) -> Self {
        DeepMailError::Internal(format!("I/O error: {e}"))
    }
}

impl From<serde_json::Error> for DeepMailError {
    fn from(e: serde_json::Error) -> Self {
        DeepMailError::Internal(format!("Serialization error: {e}"))
    }
}
