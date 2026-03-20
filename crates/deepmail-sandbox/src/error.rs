use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("io failed: {0}")]
    Io(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

impl From<std::io::Error> for SandboxError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for SandboxError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}
