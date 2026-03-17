//! IOC (Indicator of Compromise) extraction engine.
//!
//! # Responsibilities
//! - Extract IPv4 addresses (excluding private/reserved ranges)
//! - Extract domain names (with basic TLD validation)
//! - Extract URLs (http/https/ftp)
//! - Extract email addresses
//! - Extract cryptographic hashes (MD5, SHA1, SHA256)
//! - Deduplicate results
//!
//! # Security
//! - All regex patterns are pre-compiled (lazy_static) for performance
//! - Private IPs are filtered out to reduce noise
//! - Extraction is read-only — no network calls

use std::collections::HashSet;

use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;

use crate::pipeline::email_parser::ParsedEmail;

lazy_static! {
    /// IPv4 address pattern.
    static ref RE_IPV4: Regex = Regex::new(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    ).expect("Invalid IPv4 regex");

    /// URL pattern (http/https/ftp).
    static ref RE_URL: Regex = Regex::new(
        r"(https?://[^\s<>\"\'\)\]\}]+|ftp://[^\s<>\"\'\)\]\}]+)"
    ).expect("Invalid URL regex");

    /// Domain name pattern.
    static ref RE_DOMAIN: Regex = Regex::new(
        r"\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})\b"
    ).expect("Invalid domain regex");

    /// Email address pattern.
    static ref RE_EMAIL: Regex = Regex::new(
        r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
    ).expect("Invalid email regex");

    /// MD5 hash pattern (32 hex chars).
    static ref RE_MD5: Regex = Regex::new(
        r"\b([a-fA-F0-9]{32})\b"
    ).expect("Invalid MD5 regex");

    /// SHA1 hash pattern (40 hex chars).
    static ref RE_SHA1: Regex = Regex::new(
        r"\b([a-fA-F0-9]{40})\b"
    ).expect("Invalid SHA1 regex");

    /// SHA256 hash pattern (64 hex chars).
    static ref RE_SHA256: Regex = Regex::new(
        r"\b([a-fA-F0-9]{64})\b"
    ).expect("Invalid SHA256 regex");
}

/// Collection of extracted IOCs.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ExtractedIocs {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub emails: Vec<String>,
    pub hashes: Vec<String>,
}

impl ExtractedIocs {
    /// Total number of unique IOCs found.
    pub fn total_count(&self) -> usize {
        self.ips.len() + self.domains.len() + self.urls.len()
            + self.emails.len() + self.hashes.len()
    }
}

/// Extract all IOCs from a parsed email.
///
/// Searches through headers, body text, and body HTML.
pub fn extract_iocs(email: &ParsedEmail) -> ExtractedIocs {
    let mut text = String::new();

    // Collect all text to search
    for header in &email.headers {
        text.push_str(&header.value);
        text.push('\n');
    }

    if let Some(ref body) = email.body_text {
        text.push_str(body);
        text.push('\n');
    }

    if let Some(ref body) = email.body_html {
        text.push_str(body);
        text.push('\n');
    }

    let ips = extract_ips(&text);
    let urls = extract_urls(&text);
    let domains = extract_domains(&text, &urls);
    let emails = extract_emails(&text);
    let hashes = extract_hashes(&text);

    tracing::debug!(
        ips = ips.len(),
        domains = domains.len(),
        urls = urls.len(),
        emails = emails.len(),
        hashes = hashes.len(),
        "IOCs extracted"
    );

    ExtractedIocs {
        ips,
        domains,
        urls,
        emails,
        hashes,
    }
}

/// Extract and deduplicate IPv4 addresses, filtering out private/reserved.
fn extract_ips(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for cap in RE_IPV4.captures_iter(text) {
        if let Some(ip) = cap.get(1) {
            let ip_str = ip.as_str().to_string();
            if is_valid_public_ip(&ip_str) && seen.insert(ip_str.clone()) {
                result.push(ip_str);
            }
        }
    }

    result
}

/// Extract and deduplicate URLs.
fn extract_urls(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for cap in RE_URL.captures_iter(text) {
        if let Some(url) = cap.get(1) {
            let url_str = url.as_str().to_string();
            // Clean trailing punctuation
            let cleaned = url_str
                .trim_end_matches('.')
                .trim_end_matches(',')
                .trim_end_matches(';')
                .to_string();
            if seen.insert(cleaned.clone()) {
                result.push(cleaned);
            }
        }
    }

    result
}

/// Extract and deduplicate domain names, excluding those already in URLs.
fn extract_domains(text: &str, urls: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    // Pre-collect URL domains to avoid duplicates
    let url_domains: HashSet<String> = urls
        .iter()
        .filter_map(|u| extract_domain_from_url(u))
        .collect();

    for cap in RE_DOMAIN.captures_iter(text) {
        if let Some(domain) = cap.get(1) {
            let domain_str = domain.as_str().to_lowercase();

            // Skip if already covered by a URL
            if url_domains.contains(&domain_str) {
                continue;
            }

            // Skip common non-IOC domains
            if is_noise_domain(&domain_str) {
                continue;
            }

            if seen.insert(domain_str.clone()) {
                result.push(domain_str);
            }
        }
    }

    result
}

/// Extract and deduplicate email addresses.
fn extract_emails(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for cap in RE_EMAIL.captures_iter(text) {
        if let Some(email) = cap.get(1) {
            let email_str = email.as_str().to_lowercase();
            if seen.insert(email_str.clone()) {
                result.push(email_str);
            }
        }
    }

    result
}

/// Extract and deduplicate hashes (SHA256 > SHA1 > MD5 priority).
fn extract_hashes(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    // SHA256 first (superset of SHA1 and MD5 by length)
    for cap in RE_SHA256.captures_iter(text) {
        if let Some(h) = cap.get(1) {
            let hash = h.as_str().to_lowercase();
            if seen.insert(hash.clone()) {
                result.push(hash);
            }
        }
    }

    // SHA1 (only if not already a substring of a SHA256)
    for cap in RE_SHA1.captures_iter(text) {
        if let Some(h) = cap.get(1) {
            let hash = h.as_str().to_lowercase();
            if !seen.contains(&hash) && seen.insert(hash.clone()) {
                result.push(hash);
            }
        }
    }

    // MD5 (only if not already a substring of longer hashes)
    for cap in RE_MD5.captures_iter(text) {
        if let Some(h) = cap.get(1) {
            let hash = h.as_str().to_lowercase();
            if !seen.contains(&hash) && seen.insert(hash.clone()) {
                result.push(hash);
            }
        }
    }

    result
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Validate that an IP is a public (non-private, non-reserved) IPv4 address.
fn is_valid_public_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }

    // Reject private / reserved ranges
    !matches!(
        (parts[0], parts[1]),
        (10, _)
        | (172, 16..=31)
        | (192, 168)
        | (127, _)
        | (0, _)
        | (169, 254)
        | (255, _)
        | (224..=239, _) // multicast
    )
}

/// Extract domain from a URL.
fn extract_domain_from_url(url: &str) -> Option<String> {
    // Strip protocol
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ftp://"))
        .unwrap_or(url);

    // Take until port/path
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

/// Filter out common noise domains (MIME boundaries, RFC examples, etc.).
fn is_noise_domain(domain: &str) -> bool {
    let noise = [
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "schema.org",
        "w3.org",
        "www.w3.org",
        "schemas.microsoft.com",
        "ns.adobe.com",
    ];
    noise.contains(&domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ips() {
        let text = "Contact server at 8.8.8.8 and 1.1.1.1 but not 192.168.1.1 or 10.0.0.1";
        let ips = extract_ips(text);
        assert!(ips.contains(&"8.8.8.8".to_string()));
        assert!(ips.contains(&"1.1.1.1".to_string()));
        assert!(!ips.contains(&"192.168.1.1".to_string()));
        assert!(!ips.contains(&"10.0.0.1".to_string()));
    }

    #[test]
    fn test_extract_urls() {
        let text = "Visit https://malicious.example.com/phish?id=1 and http://evil.net/payload";
        let urls = extract_urls(text);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("malicious.example.com"));
        assert!(urls[1].contains("evil.net"));
    }

    #[test]
    fn test_extract_emails() {
        let text = "From attacker@evil.com to victim@company.com";
        let emails = extract_emails(text);
        assert_eq!(emails.len(), 2);
    }

    #[test]
    fn test_extract_hashes() {
        let text = "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hashes = extract_hashes(text);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].len(), 64); // SHA256
    }

    #[test]
    fn test_dedup() {
        let text = "Visit 8.8.8.8 and 8.8.8.8 and 8.8.8.8";
        let ips = extract_ips(text);
        assert_eq!(ips.len(), 1);
    }
}
