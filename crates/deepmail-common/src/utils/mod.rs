//! General utility functions for the DeepMail platform.
//!
//! These are security-conscious helpers used across modules.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::errors::DeepMailError;

/// Generate a new UUID v4 string.
pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

/// Compute the SHA-256 hash of a byte slice, returning the hex-encoded result.
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Sanitize a filename by removing path components and dangerous characters.
///
/// Returns only the basename (no directories) with control characters stripped.
pub fn sanitize_filename(filename: &str) -> Result<String, DeepMailError> {
    if filename.is_empty() {
        return Err(DeepMailError::Validation("Filename is empty".to_string()));
    }

    // Extract the last path component (handles both Unix and Windows separators)
    let basename = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| DeepMailError::Validation("Invalid filename".to_string()))?;

    // Strip control characters and null bytes
    let cleaned: String = basename
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();

    if cleaned.is_empty() {
        return Err(DeepMailError::Validation(
            "Filename consists only of invalid characters".to_string(),
        ));
    }

    Ok(cleaned)
}

/// Resolve and validate a canonical path.
///
/// Ensures the resolved path is within the expected `base_dir` to prevent
/// path traversal attacks.
pub fn canonical_path(path: &Path, base_dir: &Path) -> Result<PathBuf, DeepMailError> {
    let canonical = path.canonicalize().map_err(|e| {
        DeepMailError::Internal(format!(
            "Failed to canonicalize path '{}': {e}",
            path.display()
        ))
    })?;

    let canonical_base = base_dir.canonicalize().map_err(|e| {
        DeepMailError::Internal(format!(
            "Failed to canonicalize base directory '{}': {e}",
            base_dir.display()
        ))
    })?;

    if !canonical.starts_with(&canonical_base) {
        return Err(DeepMailError::Validation(format!(
            "Path '{}' is outside allowed directory '{}'",
            canonical.display(),
            canonical_base.display()
        )));
    }

    Ok(canonical)
}
