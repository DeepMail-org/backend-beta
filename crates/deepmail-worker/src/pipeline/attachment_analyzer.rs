//! Attachment analysis module — static analysis of email attachments.
//!
//! # Responsibilities
//! - Compute SHA-256 hash
//! - Measure file size
//! - Calculate Shannon entropy (randomness indicator)
//! - Detect MIME type via magic bytes
//! - Store attachment records in database
//!
//! # Security
//! - No execution of attachment content
//! - Attachments are quarantined with UUID names
//! - High entropy may indicate encrypted/packed content
//!
//! # Future (Dynamic Sandbox)
//! - Submit suspicious attachments to sandbox queue for detonation

use sha2::{Digest, Sha256};
use serde::Serialize;

use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::{new_id, now_utc};

use crate::pipeline::email_parser::ParsedAttachment;

/// Result of attachment analysis.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentAnalysisResult {
    pub attachment_id: String,
    pub filename: String,
    pub content_type: String,
    pub sha256: String,
    pub file_size: usize,
    pub entropy: f64,
    pub detected_mime: Option<String>,
    /// True if the file type is commonly used in malware delivery.
    pub suspicious_type: bool,
}

/// Analyze all attachments from a parsed email.
///
/// Stores attachment records in the database and returns analysis results.
pub async fn analyze_attachments(
    pool: &DbPool,
    email_id: &str,
    attachments: &[ParsedAttachment],
) -> Result<Vec<AttachmentAnalysisResult>, DeepMailError> {
    let mut results = Vec::with_capacity(attachments.len());

    for attachment in attachments {
        let result = analyze_single(pool, email_id, attachment)?;
        results.push(result);
    }

    tracing::debug!(
        email_id = email_id,
        count = results.len(),
        "Attachments analyzed"
    );

    Ok(results)
}

/// Analyze a single attachment.
fn analyze_single(
    pool: &DbPool,
    email_id: &str,
    attachment: &ParsedAttachment,
) -> Result<AttachmentAnalysisResult, DeepMailError> {
    let attachment_id = new_id();

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&attachment.data);
    let sha256 = hex::encode(hasher.finalize());

    // Calculate Shannon entropy
    let entropy = calculate_entropy(&attachment.data);

    // Detect MIME type via magic bytes
    let detected_mime = infer::get(&attachment.data)
        .map(|kind| kind.mime_type().to_string());

    // Check if the file type is suspicious
    let suspicious_type = is_suspicious_type(
        &attachment.filename,
        &attachment.content_type,
        detected_mime.as_deref(),
    );

    // Store in database
    {
        let conn = pool.get()?;
        conn.execute(
            "INSERT INTO attachments (id, email_id, filename, content_type, sha256_hash, file_size, quarantine_path, entropy, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                attachment_id,
                email_id,
                attachment.filename,
                attachment.content_type,
                sha256,
                attachment.data.len() as i64,
                "", // Embedded attachments don't have separate quarantine paths
                entropy,
                now_utc(),
            ],
        )?;
    }

    Ok(AttachmentAnalysisResult {
        attachment_id,
        filename: attachment.filename.clone(),
        content_type: attachment.content_type.clone(),
        sha256,
        file_size: attachment.data.len(),
        entropy,
        detected_mime,
        suspicious_type,
    })
}

/// Calculate Shannon entropy of a byte sequence.
///
/// Returns a value between 0.0 (perfectly uniform) and 8.0 (maximum randomness).
/// Values above 7.0 may indicate encrypted or compressed content.
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a file type is commonly used in malware delivery.
fn is_suspicious_type(
    filename: &str,
    content_type: &str,
    detected_mime: Option<&str>,
) -> bool {
    let suspicious_extensions = [
        ".exe", ".scr", ".pif", ".cmd", ".bat", ".ps1", ".vbs", ".js",
        ".wsf", ".hta", ".cpl", ".msi", ".dll", ".com",
        ".jar", ".lnk", ".iso", ".img", ".vhd",
        ".docm", ".xlsm", ".pptm", // Macro-enabled Office
    ];

    let filename_lower = filename.to_lowercase();
    let is_suspicious_ext = suspicious_extensions
        .iter()
        .any(|ext| filename_lower.ends_with(ext));

    let suspicious_mimes = [
        "application/x-executable",
        "application/x-dosexec",
        "application/x-msdos-program",
        "application/x-elf",
        "application/x-sharedlib",
        "application/x-mach-binary",
        "application/java-archive",
    ];

    let is_suspicious_mime =
        suspicious_mimes.contains(&content_type) ||
        detected_mime
            .map(|m| suspicious_mimes.contains(&m))
            .unwrap_or(false);

    is_suspicious_ext || is_suspicious_mime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // Single byte repeated — entropy = 0
        let data = vec![0u8; 1000];
        assert!(calculate_entropy(&data) < 0.01);
    }

    #[test]
    fn test_entropy_random() {
        // All byte values represented equally
        let data: Vec<u8> = (0..=255).cycle().take(2560).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.9); // Near maximum (8.0)
    }

    #[test]
    fn test_suspicious_extension() {
        assert!(is_suspicious_type("payload.exe", "application/octet-stream", None));
        assert!(is_suspicious_type("report.docm", "application/octet-stream", None));
        assert!(!is_suspicious_type("report.pdf", "application/pdf", None));
    }
}
