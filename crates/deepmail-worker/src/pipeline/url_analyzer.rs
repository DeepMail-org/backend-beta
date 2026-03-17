//! URL analysis module (Phase 2 placeholder).
//!
//! # Responsibilities (current)
//! - Extract domain from URL
//! - Check Redis cache for previous lookups
//! - Return basic URL structure info
//!
//! # Future (Phase 3)
//! - Redirect chain resolution (follow 301/302)
//! - Domain age and WHOIS lookup
//! - Phishing detection (visual similarity, brand impersonation)
//! - Domain reputation scoring via threat intel feeds
//! - URL shortener expansion
//!
//! # Security
//! - SSRF protection: no outbound requests in Phase 2
//! - All URL parsing is offline-only

use serde::Serialize;

use deepmail_common::errors::DeepMailError;

/// Result of URL analysis.
#[derive(Debug, Clone, Serialize)]
pub struct UrlAnalysisResult {
    pub url: String,
    pub domain: Option<String>,
    pub scheme: String,
    pub has_ip_host: bool,
    pub suspicious_tld: bool,
    pub url_length: usize,
    /// Placeholder for future reputation score.
    pub reputation_score: Option<f64>,
}

/// Analyze a list of URLs.
///
/// Phase 2: offline analysis only (no network calls).
pub async fn analyze_urls(urls: &[String]) -> Result<Vec<UrlAnalysisResult>, DeepMailError> {
    let mut results = Vec::with_capacity(urls.len());

    for url in urls {
        let result = analyze_single_url(url);
        results.push(result);
    }

    tracing::debug!(count = results.len(), "URLs analyzed");
    Ok(results)
}

/// Analyze a single URL (offline).
fn analyze_single_url(url: &str) -> UrlAnalysisResult {
    let scheme = if url.starts_with("https://") {
        "https"
    } else if url.starts_with("http://") {
        "http"
    } else if url.starts_with("ftp://") {
        "ftp"
    } else {
        "unknown"
    };

    let domain = extract_domain(url);
    let has_ip_host = domain
        .as_ref()
        .map(|d| d.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .unwrap_or(false);

    let suspicious_tld = domain
        .as_ref()
        .map(|d| is_suspicious_tld(d))
        .unwrap_or(false);

    UrlAnalysisResult {
        url: url.to_string(),
        domain,
        scheme: scheme.to_string(),
        has_ip_host,
        suspicious_tld,
        url_length: url.len(),
        reputation_score: None, // Phase 3
    }
}

/// Extract domain from URL.
fn extract_domain(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ftp://"))
        .unwrap_or(url);

    let domain: String = rest
        .chars()
        .take_while(|c| *c != '/' && *c != ':' && *c != '?')
        .collect();

    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// Check if a domain has a suspicious TLD commonly used in phishing.
fn is_suspicious_tld(domain: &str) -> bool {
    let suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs
        ".buzz", ".xyz", ".top", ".club",   // Cheap TLDs often abused
        ".work", ".click", ".link", ".info", // Commonly abused
        ".zip", ".mov",                      // New TLDs that confuse users
    ];
    suspicious_tlds.iter().any(|tld| domain.ends_with(tld))
}
