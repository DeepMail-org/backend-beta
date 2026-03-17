//! Multi-layer file validation for secure upload processing.
//!
//! # Validation Pipeline
//! Each uploaded file passes through ALL of these checks before being accepted:
//!
//! 1. **Filename sanitization** — strip path components, decode, normalize
//! 2. **Extension validation** — only allowed extensions (`.eml`, `.msg`)
//! 3. **Size validation** — reject files exceeding the configured maximum
//! 4. **Magic byte verification** — check file signatures match expected types
//! 5. **MIME type detection** — use `infer` crate to detect actual content type
//! 6. **Zip bomb protection** — reject archives with suspicious compression ratios
//!
//! # Security
//! - All checks run BEFORE writing anything to disk
//! - Validation operates on in-memory bytes
//! - Errors are descriptive but do not leak internal paths

use crate::config::UploadConfig;
use crate::errors::DeepMailError;

/// Maximum filename length after sanitization.
const MAX_FILENAME_LEN: usize = 255;

/// Known magic bytes for supported file types.
/// EML files are plain text (RFC 5322) — they don't have fixed magic bytes,
/// so we validate via content heuristics instead.
/// MSG files (OLE2 Compound Binary) start with D0 CF 11 E0 A1 B1 1A E1.
const MSG_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// ZIP magic bytes (for zip bomb detection).
const ZIP_MAGIC: &[u8] = &[0x50, 0x4B, 0x03, 0x04];

/// Maximum compression ratio allowed (uncompressed:compressed).
const MAX_COMPRESSION_RATIO: f64 = 10.0;

/// Result of successful validation.
#[derive(Debug)]
pub struct ValidatedFile {
    /// Sanitized filename (basename only, no path components).
    pub sanitized_name: String,
    /// Detected file extension (lowercase, no dot).
    pub extension: String,
    /// File size in bytes.
    pub size: usize,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

/// Validate an uploaded file through the full security pipeline.
///
/// Returns `ValidatedFile` on success, `DeepMailError::Validation` on failure.
pub fn validate_upload(
    filename: &str,
    data: &[u8],
    config: &UploadConfig,
) -> Result<ValidatedFile, DeepMailError> {
    // Step 1: Sanitize filename
    let sanitized = sanitize_filename(filename)?;
    tracing::debug!(original = %filename, sanitized = %sanitized, "Filename sanitized");

    // Step 2: Validate extension
    let extension = validate_extension(&sanitized, &config.allowed_extensions)?;
    tracing::debug!(extension = %extension, "Extension validated");

    // Step 3: Validate size
    validate_size(data.len(), config.max_file_size)?;
    tracing::debug!(size = data.len(), max = config.max_file_size, "Size validated");

    // Step 4: Validate magic bytes
    validate_magic_bytes(data, &extension)?;
    tracing::debug!(extension = %extension, "Magic bytes validated");

    // Step 5: MIME type detection
    validate_mime_type(data, &extension)?;
    tracing::debug!(extension = %extension, "MIME type validated");

    // Step 6: Zip bomb protection (if applicable)
    check_zip_bomb(data)?;
    tracing::debug!("Zip bomb check passed");

    Ok(ValidatedFile {
        sanitized_name: sanitized,
        extension,
        size: data.len(),
        data: data.to_vec(),
    })
}

/// Sanitize a filename by stripping path components and dangerous characters.
fn sanitize_filename(filename: &str) -> Result<String, DeepMailError> {
    if filename.is_empty() {
        return Err(DeepMailError::Validation("Filename is empty".to_string()));
    }

    // Extract basename — strip any directory components (Unix and Windows)
    let basename = filename
        .rsplit('/')
        .next()
        .and_then(|s| s.rsplit('\\').next())
        .ok_or_else(|| DeepMailError::Validation("Invalid filename".to_string()))?;

    if basename.is_empty() {
        return Err(DeepMailError::Validation("Filename is empty after stripping path".to_string()));
    }

    // Remove null bytes and control characters
    let cleaned: String = basename
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();

    if cleaned.is_empty() {
        return Err(DeepMailError::Validation(
            "Filename contains only control characters".to_string(),
        ));
    }

    // Enforce maximum length
    if cleaned.len() > MAX_FILENAME_LEN {
        return Err(DeepMailError::Validation(format!(
            "Filename exceeds maximum length of {MAX_FILENAME_LEN} characters"
        )));
    }

    // Reject path traversal attempts
    if cleaned.contains("..") {
        return Err(DeepMailError::Validation(
            "Filename contains path traversal sequence".to_string(),
        ));
    }

    Ok(cleaned)
}

/// Validate that the file extension is in the allowed list.
fn validate_extension(
    filename: &str,
    allowed: &[String],
) -> Result<String, DeepMailError> {
    let extension = filename
        .rsplit('.')
        .next()
        .map(|e| e.to_lowercase())
        .ok_or_else(|| {
            DeepMailError::Validation("File has no extension".to_string())
        })?;

    // Guard against files with no actual extension (just a dot at the end)
    if extension.is_empty() || extension == filename.to_lowercase() {
        return Err(DeepMailError::Validation(
            "File has no valid extension".to_string(),
        ));
    }

    if !allowed.iter().any(|a| a.to_lowercase() == extension) {
        return Err(DeepMailError::Validation(format!(
            "File extension '.{extension}' is not allowed. Accepted: {}",
            allowed
                .iter()
                .map(|e| format!(".{e}"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok(extension)
}

/// Validate file size against the configured maximum.
fn validate_size(size: usize, max_size: usize) -> Result<(), DeepMailError> {
    if size == 0 {
        return Err(DeepMailError::Validation("File is empty (0 bytes)".to_string()));
    }

    if size > max_size {
        return Err(DeepMailError::Validation(format!(
            "File size ({} bytes) exceeds maximum allowed size ({} bytes)",
            size, max_size
        )));
    }

    Ok(())
}

/// Validate magic bytes match the expected file type.
fn validate_magic_bytes(data: &[u8], extension: &str) -> Result<(), DeepMailError> {
    match extension {
        "msg" => {
            if data.len() < MSG_MAGIC.len() {
                return Err(DeepMailError::Validation(
                    "File too small to be a valid .msg file".to_string(),
                ));
            }
            if &data[..MSG_MAGIC.len()] != MSG_MAGIC {
                return Err(DeepMailError::Validation(
                    "File does not have valid .msg (OLE2) magic bytes".to_string(),
                ));
            }
        }
        "eml" => {
            // EML files are plain text (RFC 5322). Validate content heuristics:
            // Must contain common email headers like "From:", "To:", "Subject:", etc.
            validate_eml_heuristics(data)?;
        }
        _ => {
            return Err(DeepMailError::Validation(format!(
                "No magic byte validation defined for extension '.{extension}'"
            )));
        }
    }

    Ok(())
}

/// Heuristic validation for .eml files (RFC 5322 plain text).
fn validate_eml_heuristics(data: &[u8]) -> Result<(), DeepMailError> {
    // Check that the file is valid UTF-8 or at least ASCII-compatible
    let text = std::str::from_utf8(data).or_else(|_| {
        // Try to decode as lossy — some emails have mixed encodings
        Ok::<&str, DeepMailError>(std::str::from_utf8(&data[..data.len().min(8192)])
            .unwrap_or(""))
    })?;

    if text.is_empty() {
        return Err(DeepMailError::Validation(
            "EML file appears to be empty or binary".to_string(),
        ));
    }

    // Check for at least one RFC 5322 header pattern
    let header_patterns = [
        "From:", "from:",
        "To:", "to:",
        "Subject:", "subject:",
        "Date:", "date:",
        "Received:", "received:",
        "MIME-Version:", "mime-version:",
        "Message-ID:", "message-id:",
    ];

    let has_header = header_patterns.iter().any(|h| text.contains(h));
    if !has_header {
        return Err(DeepMailError::Validation(
            "File does not appear to be a valid email (no RFC 5322 headers found)".to_string(),
        ));
    }

    Ok(())
}

/// Validate MIME type using content detection (infer crate).
fn validate_mime_type(data: &[u8], extension: &str) -> Result<(), DeepMailError> {
    match extension {
        "msg" => {
            // OLE2 files are detected by `infer` as various Microsoft formats.
            // The magic byte check above is sufficient for .msg files.
            // Additional validation: check that the infer crate doesn't detect
            // something obviously wrong (like an image or executable).
            if let Some(kind) = infer::get(data) {
                let mime = kind.mime_type();
                // Reject if detected as an executable or script
                if mime.starts_with("application/x-executable")
                    || mime.starts_with("application/x-sharedlib")
                    || mime == "application/x-elf"
                {
                    return Err(DeepMailError::Validation(format!(
                        "File detected as executable type '{mime}', not a valid .msg file"
                    )));
                }
            }
        }
        "eml" => {
            // EML files are plain text — infer won't detect them as a specific type.
            // The heuristic check above handles validation.
            // Just reject if detected as a known binary format.
            if let Some(kind) = infer::get(data) {
                let mime = kind.mime_type();
                if !mime.starts_with("text/")
                    && mime != "application/octet-stream"
                {
                    return Err(DeepMailError::Validation(format!(
                        "File detected as '{mime}', which is inconsistent with .eml format"
                    )));
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Check for potential zip bombs.
///
/// A zip bomb is a compressed file designed to expand to an enormous size.
/// We check if the data starts with ZIP magic bytes and if so, calculate
/// the compression ratio from the local file header.
fn check_zip_bomb(data: &[u8]) -> Result<(), DeepMailError> {
    if data.len() < 30 {
        return Ok(()); // Too small to be a ZIP
    }

    if &data[..ZIP_MAGIC.len()] != ZIP_MAGIC {
        return Ok(()); // Not a ZIP file
    }

    // Read the local file header to get compressed and uncompressed sizes.
    // Local file header format (after 4-byte signature):
    //   offset 18: compressed size (4 bytes, little-endian)
    //   offset 22: uncompressed size (4 bytes, little-endian)
    if data.len() < 26 + 4 {
        return Ok(());
    }

    let compressed_size =
        u32::from_le_bytes([data[18], data[19], data[20], data[21]]) as f64;
    let uncompressed_size =
        u32::from_le_bytes([data[22], data[23], data[24], data[25]]) as f64;

    if compressed_size > 0.0 {
        let ratio = uncompressed_size / compressed_size;
        if ratio > MAX_COMPRESSION_RATIO {
            return Err(DeepMailError::Validation(format!(
                "Potential zip bomb detected: compression ratio {ratio:.1} \
                 exceeds maximum allowed ratio of {MAX_COMPRESSION_RATIO:.1}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> UploadConfig {
        UploadConfig {
            max_file_size: 1024 * 1024, // 1 MB
            allowed_extensions: vec!["eml".into(), "msg".into()],
            quarantine_path: "/tmp/quarantine".into(),
        }
    }

    #[test]
    fn test_sanitize_filename_strips_path() {
        // "..evil..eml" contains ".." in the filename itself → rejected
        assert!(sanitize_filename("..evil..eml").unwrap_err().to_string()
            .contains("path traversal"));

        // Pure ".." as filename → caught by traversal check
        assert!(sanitize_filename("..").is_err());

        // Path traversal in directory components is stripped by basename extraction
        // so the final basename is safe
        let result = sanitize_filename("/etc/passwd/../evil.eml").unwrap();
        assert_eq!(result, "evil.eml");

        // Windows-style traversal, basename is extracted
        let result = sanitize_filename("C:\\Users\\..\\evil.eml").unwrap();
        assert_eq!(result, "evil.eml");
    }

    #[test]
    fn test_sanitize_filename_strips_windows_path() {
        let result = sanitize_filename("C:\\Users\\evil\\test.eml").unwrap();
        assert_eq!(result, "test.eml");
    }

    #[test]
    fn test_validate_extension_rejects_bad() {
        let allowed = vec!["eml".into(), "msg".into()];
        assert!(validate_extension("test.exe", &allowed).is_err());
        assert!(validate_extension("test.txt", &allowed).is_err());
    }

    #[test]
    fn test_validate_extension_accepts_good() {
        let allowed = vec!["eml".into(), "msg".into()];
        assert_eq!(validate_extension("test.eml", &allowed).unwrap(), "eml");
        assert_eq!(validate_extension("test.MSG", &allowed).unwrap(), "msg");
    }

    #[test]
    fn test_validate_size_rejects_empty() {
        assert!(validate_size(0, 1024).is_err());
    }

    #[test]
    fn test_validate_size_rejects_oversized() {
        assert!(validate_size(2048, 1024).is_err());
    }

    #[test]
    fn test_validate_size_accepts_valid() {
        assert!(validate_size(512, 1024).is_ok());
    }

    #[test]
    fn test_eml_heuristics_valid() {
        let data = b"From: test@example.com\r\nTo: victim@example.com\r\nSubject: Test\r\n\r\nBody";
        assert!(validate_eml_heuristics(data).is_ok());
    }

    #[test]
    fn test_eml_heuristics_invalid() {
        let data = b"This is not an email file at all";
        assert!(validate_eml_heuristics(data).is_err());
    }
}
