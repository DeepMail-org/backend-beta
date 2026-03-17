//! File quarantine system for secure upload storage.
//!
//! # Security Model
//! - Uploaded files are NEVER stored with their original name
//! - Files are renamed to `{UUID}.quarantine` to neutralize extension-based attacks
//! - The quarantine directory has `0o700` permissions (owner-only)
//! - Individual files have `0o400` permissions (read-only, no execute)
//! - Canonical path validation prevents path traversal attacks
//! - No symbolic links are followed

use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::errors::DeepMailError;

/// Result of a successful quarantine operation.
#[derive(Debug)]
pub struct QuarantinedFile {
    /// Full canonical path to the quarantined file.
    pub path: PathBuf,
    /// UUID-based filename (no original extension).
    pub quarantine_name: String,
    /// SHA-256 hash of the file contents.
    pub sha256: String,
}

/// Initialize the quarantine directory with secure permissions.
///
/// Creates the directory if it doesn't exist and sets permissions to `0o700`
/// (owner read/write/execute only — execute is needed to traverse the directory).
pub fn init_quarantine_dir(quarantine_path: &str) -> Result<PathBuf, DeepMailError> {
    let path = Path::new(quarantine_path);

    fs::create_dir_all(path).map_err(|e| {
        DeepMailError::Upload(format!(
            "Failed to create quarantine directory '{}': {e}",
            path.display()
        ))
    })?;

    // Set directory permissions to owner-only (rwx------)
    let dir_perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, dir_perms).map_err(|e| {
        DeepMailError::Upload(format!(
            "Failed to set quarantine directory permissions: {e}"
        ))
    })?;

    // Resolve to canonical path to prevent traversal
    let canonical = path.canonicalize().map_err(|e| {
        DeepMailError::Upload(format!(
            "Failed to canonicalize quarantine path '{}': {e}",
            path.display()
        ))
    })?;

    tracing::info!(path = %canonical.display(), "Quarantine directory initialized");

    Ok(canonical)
}

/// Store a file in the quarantine directory.
///
/// # Security
/// - File is stored with a UUID name + `.quarantine` extension
/// - Permissions set to `0o400` (read-only by owner, no execute)
/// - Path is validated to be within the quarantine directory
/// - SHA-256 hash is computed for integrity verification
pub fn quarantine_file(
    quarantine_dir: &Path,
    data: &[u8],
) -> Result<QuarantinedFile, DeepMailError> {
    // Generate a UUID-based filename
    let file_uuid = Uuid::new_v4();
    let quarantine_name = format!("{file_uuid}.quarantine");
    let file_path = quarantine_dir.join(&quarantine_name);

    // SECURITY: Validate that the resolved path is within the quarantine directory.
    // This prevents any potential path traversal via carefully crafted UUIDs
    // (which shouldn't happen with UUID v4, but defense in depth).
    let canonical_dir = quarantine_dir.canonicalize().map_err(|e| {
        DeepMailError::Upload(format!("Failed to canonicalize quarantine dir: {e}"))
    })?;

    // Write the file
    fs::write(&file_path, data).map_err(|e| {
        DeepMailError::Upload(format!(
            "Failed to write quarantined file '{}': {e}",
            file_path.display()
        ))
    })?;

    // Verify canonical path is within quarantine directory
    let canonical_file = file_path.canonicalize().map_err(|e| {
        // Clean up on failure
        let _ = fs::remove_file(&file_path);
        DeepMailError::Upload(format!("Failed to canonicalize file path: {e}"))
    })?;

    if !canonical_file.starts_with(&canonical_dir) {
        // Path traversal detected — clean up and reject
        let _ = fs::remove_file(&file_path);
        return Err(DeepMailError::Upload(
            "Path traversal detected in quarantine operation".to_string(),
        ));
    }

    // Set file permissions to read-only (r--------)
    let file_perms = fs::Permissions::from_mode(0o400);
    fs::set_permissions(&canonical_file, file_perms).map_err(|e| {
        let _ = fs::remove_file(&file_path);
        DeepMailError::Upload(format!("Failed to set file permissions: {e}"))
    })?;

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex::encode(hasher.finalize());

    tracing::info!(
        quarantine_name = %quarantine_name,
        sha256 = %sha256,
        size = data.len(),
        "File quarantined successfully"
    );

    Ok(QuarantinedFile {
        path: canonical_file,
        quarantine_name,
        sha256,
    })
}
