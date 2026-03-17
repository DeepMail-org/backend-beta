//! Email parser module — parses .eml (RFC 5322) files.
//!
//! # Responsibilities
//! - Parse raw .eml bytes into structured `ParsedEmail`
//! - Extract all headers as key-value pairs
//! - Extract plain text and HTML body parts
//! - Extract embedded attachments with metadata
//!
//! # Security
//! - Uses `mailparse` crate for robust RFC 5322 parsing
//! - Handles malformed emails gracefully (returns errors, not panics)
//! - Attachment bytes are kept in memory only during pipeline execution

use deepmail_common::errors::DeepMailError;
use serde::Serialize;

/// A fully parsed email.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedEmail {
    /// All headers as (name, value) pairs.
    pub headers: Vec<EmailHeader>,
    /// Plain text body (if present).
    pub body_text: Option<String>,
    /// HTML body (if present).
    pub body_html: Option<String>,
    /// Extracted attachments.
    pub attachments: Vec<ParsedAttachment>,
    /// Raw subject line.
    pub subject: Option<String>,
    /// From address.
    pub from: Option<String>,
    /// To addresses.
    pub to: Vec<String>,
    /// Reply-To address.
    pub reply_to: Option<String>,
    /// Message-ID.
    pub message_id: Option<String>,
    /// Date header.
    pub date: Option<String>,
}

/// A single email header.
#[derive(Debug, Clone, Serialize)]
pub struct EmailHeader {
    pub name: String,
    pub value: String,
}

/// An extracted email attachment.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedAttachment {
    pub filename: String,
    pub content_type: String,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
    pub size: usize,
}

/// Parse raw .eml bytes into a structured `ParsedEmail`.
pub fn parse_email(raw: &[u8]) -> Result<ParsedEmail, DeepMailError> {
    let parsed = mailparse::parse_mail(raw).map_err(|e| {
        DeepMailError::Internal(format!("Failed to parse email: {e}"))
    })?;

    // Extract headers
    let headers: Vec<EmailHeader> = parsed
        .headers
        .iter()
        .map(|h| EmailHeader {
            name: h.get_key().to_lowercase(),
            value: h.get_value(),
        })
        .collect();

    // Extract key header values
    let subject = get_header_value(&headers, "subject");
    let from = get_header_value(&headers, "from");
    let reply_to = get_header_value(&headers, "reply-to");
    let message_id = get_header_value(&headers, "message-id");
    let date = get_header_value(&headers, "date");

    let to: Vec<String> = headers
        .iter()
        .filter(|h| h.name == "to")
        .map(|h| h.value.clone())
        .collect();

    // Extract body parts and attachments
    let mut body_text = None;
    let mut body_html = None;
    let mut attachments = Vec::new();

    extract_parts(&parsed, &mut body_text, &mut body_html, &mut attachments);

    Ok(ParsedEmail {
        headers,
        body_text,
        body_html,
        attachments,
        subject,
        from,
        to,
        reply_to,
        message_id,
        date,
    })
}

/// Recursively extract body parts and attachments from a parsed mail.
fn extract_parts(
    mail: &mailparse::ParsedMail<'_>,
    body_text: &mut Option<String>,
    body_html: &mut Option<String>,
    attachments: &mut Vec<ParsedAttachment>,
) {
    let content_type = mail.ctype.mimetype.to_lowercase();

    if mail.subparts.is_empty() {
        // Leaf node — check what type it is
        let content_disposition = mail
            .headers
            .iter()
            .find(|h| h.get_key().to_lowercase() == "content-disposition")
            .map(|h| h.get_value().to_lowercase())
            .unwrap_or_default();

        let is_attachment = content_disposition.starts_with("attachment")
            || (!content_type.starts_with("text/") && !content_type.starts_with("multipart/"));

        if is_attachment {
            // Extract as attachment
            let filename = extract_filename(mail).unwrap_or_else(|| "unnamed".to_string());
            if let Ok(body) = mail.get_body_raw() {
                attachments.push(ParsedAttachment {
                    filename,
                    content_type: content_type.clone(),
                    size: body.len(),
                    data: body,
                });
            }
        } else if content_type == "text/plain" && body_text.is_none() {
            if let Ok(text) = mail.get_body() {
                *body_text = Some(text);
            }
        } else if content_type == "text/html" && body_html.is_none() {
            if let Ok(html) = mail.get_body() {
                *body_html = Some(html);
            }
        }
    } else {
        // Multipart — recurse into subparts
        for subpart in &mail.subparts {
            extract_parts(subpart, body_text, body_html, attachments);
        }
    }
}

/// Extract the filename from an attachment's Content-Disposition or Content-Type.
fn extract_filename(mail: &mailparse::ParsedMail<'_>) -> Option<String> {
    // Try Content-Disposition: attachment; filename="foo.pdf"
    for header in &mail.headers {
        if header.get_key().to_lowercase() == "content-disposition" {
            let value = header.get_value();
            if let Some(fname) = extract_param(&value, "filename") {
                return Some(fname);
            }
        }
    }
    // Try Content-Type: application/pdf; name="foo.pdf"
    if let Some(ref name) = mail.ctype.params.get("name") {
        return Some(name.to_string());
    }
    None
}

/// Extract a parameter value from a header value string.
/// e.g., from `attachment; filename="report.pdf"` extract `report.pdf`.
fn extract_param(header_value: &str, param_name: &str) -> Option<String> {
    let pattern = format!("{param_name}=");
    if let Some(pos) = header_value.to_lowercase().find(&pattern) {
        let start = pos + pattern.len();
        let rest = &header_value[start..];
        let value = if rest.starts_with('"') {
            // Quoted value
            rest[1..].split('"').next().unwrap_or("").to_string()
        } else {
            // Unquoted value
            rest.split(';').next().unwrap_or("").trim().to_string()
        };
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

/// Get the first header value matching a given name.
fn get_header_value(headers: &[EmailHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name == name)
        .map(|h| h.value.clone())
}
