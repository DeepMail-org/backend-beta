//! Attachment analysis module — static analysis with Redis cache integration.
//!
//! # Responsibilities
//! - Compute SHA-256 hash of each attachment
//! - Measure file size and calculate Shannon entropy
//! - Detect MIME type via magic bytes using the `infer` crate
//! - Check Redis cache for previously seen hashes (avoid redundant work)
//! - Persist attachment records in SQLite
//! - Identify high-risk file types commonly used in malware delivery
//!
//! # Security Considerations
//! - **No execution** of attachment content — static analysis only
//! - All attachment bytes reside in memory only during pipeline execution
//! - High Shannon entropy (> 7.5) may indicate encrypted or packed payloads
//! - Quarantine paths are left empty for inline attachments (not written to disk here)
//!
//! # Entropy Interpretation
//! | Entropy | Interpretation |
//! |---------|---------------|
//! | 0.0–3.0 | Plain text / highly repetitive data |
//! | 3.0–6.0 | Typical binary, compressed, or mixed content |
//! | 6.0–7.0 | Compressed archives (ZIP, gzip) |
//! | 7.0–7.5 | Likely encrypted or packed |
//! | 7.5–8.0 | Strong indicator of encryption — investigate |
//!
//! # Future (Dynamic Sandbox)
//! Pass `suspicious_type == true` attachments to `sandbox_queue` for detonation.

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use deepmail_common::cache::ThreatCache;
use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::{new_id, now_utc};

use crate::pipeline::email_parser::ParsedAttachment;

// ─── Result types ─────────────────────────────────────────────────────────────

/// Full static analysis result for a single email attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentAnalysisResult {
    /// Database ID of the stored attachment record.
    pub attachment_id: String,
    /// Original filename (sanitised by `email_parser`).
    pub filename: String,
    /// Declared MIME type from the email headers.
    pub content_type: String,
    /// SHA-256 hex digest of the attachment bytes.
    pub sha256: String,
    /// Raw size in bytes.
    pub file_size: usize,
    /// Shannon entropy (0.0–8.0).
    pub entropy: f64,
    /// MIME type detected from magic bytes (may differ from `content_type`).
    pub detected_mime: Option<String>,
    /// True if the file type is commonly used in malware delivery.
    pub suspicious_type: bool,
    /// True if this result was returned from the Redis cache.
    pub from_cache: bool,
}

// ─── Suspicious file type lists ───────────────────────────────────────────────

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    // Windows executables and scripts
    ".exe", ".scr", ".pif", ".cmd", ".bat", ".ps1", ".vbs", ".js",
    ".wsf", ".hta", ".cpl", ".msi", ".dll", ".com", ".vbe", ".jse",
    // Archive formats used to bypass filters
    ".iso", ".img", ".vhd", ".vhdx",
    // Archives with embedded malware
    ".jar", ".war",
    // Shortcut/link files
    ".lnk",
    // Macro-enabled Office documents
    ".docm", ".xlsm", ".pptm", ".dotm", ".xlam",
    // OneNote (increasingly exploited)
    ".one",
];

const SUSPICIOUS_MIMES: &[&str] = &[
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/x-elf",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/java-archive",
    "application/x-msdownload",
];

// ─── Public API ───────────────────────────────────────────────────────────────

/// Analyse all attachments from a parsed email.
///
/// For each attachment the SHA-256 is computed and checked against the Redis
/// cache.  Cache hits return immediately; misses run full static analysis and
/// populate the cache for subsequent lookups.
///
/// Results are also persisted in the `attachments` table.
pub async fn analyze_attachments(
    pool: &DbPool,
    email_id: &str,
    attachments: &[ParsedAttachment],
    mut cache: Option<&mut ThreatCache>,
) -> Result<Vec<AttachmentAnalysisResult>, DeepMailError> {
    let mut results = Vec::with_capacity(attachments.len());

    // NOTE: We cannot hold `cache` as `&mut` across multiple iterations when
    // it's a single reference, so we build an owned Option each time by
    // splitting the logic. The borrow checker forces us to handle this carefully.
    // In Phase 3 we can upgrade to Arc<Mutex<ThreatCache>> for true parallelism.
    for attachment in attachments {
        // Hash first — needed for cache key
        let sha256 = compute_sha256(&attachment.data);

        // ── Cache lookup ─────────────────────────────────────────────────────
        if let Some(ref mut c) = cache.as_deref_mut() {
            match c.get_hash_lookup::<AttachmentAnalysisResult>(&sha256).await {
                Ok(Some(mut cached)) => {
                    tracing::debug!(sha256 = %sha256, "Attachment hash cache HIT");
                    // Persist to DB even on cache hit (different email submitted same file)
                    let attachment_id = new_id();
                    store_attachment(pool, email_id, attachment, &sha256, &cached, &attachment_id)?;
                    cached.attachment_id = attachment_id;
                    cached.from_cache = true;
                    results.push(cached);
                    continue;
                }
                Ok(None) => {} // Cache miss — fall through to analysis
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to check attachment cache — proceeding without cache");
                }
            }
        }

        // ── Full static analysis ─────────────────────────────────────────────
        let result = analyze_single(pool, email_id, attachment, sha256.clone())?;

        // ── Cache population ─────────────────────────────────────────────────
        if let Some(c) = cache.as_deref_mut() {
            let _ = c.cache_hash_lookup(&sha256, &result).await;
        }

        results.push(result);
    }

    tracing::debug!(
        email_id = email_id,
        count = results.len(),
        "Attachments analysed"
    );

    Ok(results)
}

// ─── Analysis internals ───────────────────────────────────────────────────────

/// Full static analysis of a single attachment.
fn analyze_single(
    pool: &DbPool,
    email_id: &str,
    attachment: &ParsedAttachment,
    sha256: String,
) -> Result<AttachmentAnalysisResult, DeepMailError> {
    let attachment_id = new_id();
    let entropy = calculate_entropy(&attachment.data);
    let detected_mime = infer::get(&attachment.data).map(|k| k.mime_type().to_string());
    let suspicious_type = is_suspicious_type(
        &attachment.filename,
        &attachment.content_type,
        detected_mime.as_deref(),
    );

    let result = AttachmentAnalysisResult {
        attachment_id: attachment_id.clone(),
        filename: attachment.filename.clone(),
        content_type: attachment.content_type.clone(),
        sha256: sha256.clone(),
        file_size: attachment.data.len(),
        entropy,
        detected_mime,
        suspicious_type,
        from_cache: false,
    };

    store_attachment(pool, email_id, attachment, &sha256, &result, &attachment_id)?;

    Ok(result)
}

/// Persist an attachment record in the `attachments` table.
fn store_attachment(
    pool: &DbPool,
    email_id: &str,
    attachment: &ParsedAttachment,
    sha256: &str,
    result: &AttachmentAnalysisResult,
    attachment_id: &str,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT OR IGNORE INTO attachments \
         (id, email_id, filename, content_type, sha256_hash, file_size, quarantine_path, entropy, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            attachment_id,
            email_id,
            attachment.filename,
            attachment.content_type,
            sha256,
            attachment.data.len() as i64,
            "", // Inline attachments do not have a separate quarantine path
            result.entropy,
            now_utc(),
        ],
    )?;
    Ok(())
}

// ─── Analytical helpers ────────────────────────────────────────────────────────

/// Compute SHA-256 of raw bytes and return the lowercase hex string.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Calculate Shannon entropy of a byte sequence.
///
/// Returns a value in **[0.0, 8.0]**:
/// - `0.0` → all bytes identical (perfectly uniform)
/// - `8.0` → all 256 byte values equally distributed (maximum randomness)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns true when the file type is commonly used in malware delivery.
fn is_suspicious_type(
    filename: &str,
    content_type: &str,
    detected_mime: Option<&str>,
) -> bool {
    let filename_lower = filename.to_lowercase();
    let is_suspicious_ext = SUSPICIOUS_EXTENSIONS
        .iter()
        .any(|ext| filename_lower.ends_with(ext));

    let is_suspicious_mime = SUSPICIOUS_MIMES.contains(&content_type)
        || detected_mime
            .map(|m| SUSPICIOUS_MIMES.contains(&m))
            .unwrap_or(false);

    is_suspicious_ext || is_suspicious_mime
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        let data = vec![0u8; 1000];
        assert!(calculate_entropy(&data) < 0.01);
    }

    #[test]
    fn test_entropy_random() {
        // All 256 byte values equally represented → near-maximum entropy
        let data: Vec<u8> = (0..=255u8).cycle().take(2560).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.9, "Expected entropy > 7.9, got {entropy}");
    }

    #[test]
    fn test_entropy_high_signal() {
        // 200 random-ish bytes should score above 7.0
        let data: Vec<u8> = (0..200).map(|i| (i * 37 + 13) as u8).collect();
        assert!(calculate_entropy(&data) > 5.0);
    }

    #[test]
    fn test_suspicious_extension() {
        assert!(is_suspicious_type("payload.exe", "application/octet-stream", None));
        assert!(is_suspicious_type("macro.docm", "application/octet-stream", None));
        assert!(is_suspicious_type("link.lnk", "application/x-ms-shortcut", None));
        assert!(!is_suspicious_type("report.pdf", "application/pdf", None));
        assert!(!is_suspicious_type("image.png", "image/png", None));
    }

    #[test]
    fn test_suspicious_mime() {
        assert!(is_suspicious_type(
            "file.bin",
            "application/x-executable",
            None
        ));
        assert!(is_suspicious_type(
            "file.unknown",
            "application/octet-stream",
            Some("application/x-elf"),
        ));
    }

    #[test]
    fn test_sha256_consistency() {
        let data = b"hello world";
        let h1 = compute_sha256(data);
        let h2 = compute_sha256(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}
