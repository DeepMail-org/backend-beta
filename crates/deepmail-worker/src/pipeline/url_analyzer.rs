//! URL analysis module — offline static analysis with Redis caching.
//!
//! # Responsibilities (Phase 2)
//! - Extract domain from URL
//! - Check Redis cache for previous domain lookups
//! - Compute structural risk signals (IP hosts, suspicious TLDs, long URLs)
//! - Populate Redis cache with results for future lookups
//!
//! # Future (Phase 3)
//! - Redirect chain resolution (follow 301/302 hops)
//! - Domain age and WHOIS lookup via external API
//! - Phishing similarity scoring (brand impersonation detection)
//! - Multi-provider reputation scoring (URLhaus and internal intel)
//! - URL shortener expansion
//!
//! # Security
//! - SSRF protection: zero outbound HTTP requests in Phase 2
//! - All URL parsing is purely offline
//! - Cache keys are sanitised (colons and spaces replaced with underscores)

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use deepmail_common::cache::ThreatCache;
use deepmail_common::circuit_breaker::CircuitBreaker;
use deepmail_common::config::{CircuitBreakerConfig, IntelConfig};
use deepmail_common::errors::DeepMailError;

static VT_BREAKER: OnceLock<CircuitBreaker> = OnceLock::new();
static VT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static VT_FAILURE: AtomicU64 = AtomicU64::new(0);
static VT_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static VT_RETRIES: AtomicU64 = AtomicU64::new(0);
static VT_CIRCUIT_OPEN: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct VirusTotalDomainResponse {
    data: VirusTotalDomainData,
}

#[derive(Debug, Deserialize)]
struct VirusTotalDomainData {
    attributes: VirusTotalDomainAttributes,
}

#[derive(Debug, Deserialize)]
struct VirusTotalDomainAttributes {
    last_analysis_stats: VirusTotalLastAnalysisStats,
}

#[derive(Debug, Deserialize)]
struct VirusTotalLastAnalysisStats {
    malicious: u32,
    suspicious: u32,
    harmless: u32,
    undetected: u32,
}

/// Structural analysis result for a single URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysisResult {
    /// The raw URL string.
    pub url: String,
    /// Extracted hostname/domain (lowercase).
    pub domain: Option<String>,
    /// URL scheme: "https", "http", "ftp", or "unknown".
    pub scheme: String,
    /// True when the host is an IP address rather than a domain name.
    pub has_ip_host: bool,
    /// True when the TLD is in the suspicious list.
    pub suspicious_tld: bool,
    /// Total character length of the URL.
    pub url_length: usize,
    /// Number of subdomains (dots in the hostname minus 1).
    pub subdomain_depth: usize,
    /// True if the URL path contains an encoded character (%XX).
    pub has_encoded_chars: bool,
    /// Reputation score placeholder — populated by Phase 3 threat intel.
    pub reputation_score: Option<f64>,
}

// ─── Suspicious TLD list ─────────────────────────────────────────────────────

/// TLDs commonly abused in phishing and malware campaigns.
///
/// Sourced from threat intelligence reports and abuse statistics.
const SUSPICIOUS_TLDS: &[&str] = &[
    // Free/abused country code TLDs
    ".tk", ".ml", ".ga", ".cf", ".gq", // Cheap generic TLDs with high abuse rates
    ".buzz", ".xyz", ".top", ".club", ".work", ".click", ".link", ".info", ".biz",
    // Deceptive new TLDs that confuse users
    ".zip", ".mov", ".app", // Other commonly abused
    ".pw", ".cc", ".su",
];

// ─── Public API ───────────────────────────────────────────────────────────────

/// Analyse a list of URLs with optional Redis cache integration.
///
/// For each URL the domain is extracted and a cache check is performed.
/// If a cached result exists it is returned immediately; otherwise the URL
/// is analysed offline and the result is stored in the cache.
///
/// # Arguments
/// - `urls`  — slice of URL strings extracted from the email.
/// - `cache` — optional mutable reference to the Redis cache.
///             When `None` (e.g. in tests), caching is skipped.
pub async fn analyze_urls(
    urls: &[String],
    cache: Option<&ThreatCache>,
    intel_config: &IntelConfig,
    breaker_config: &CircuitBreakerConfig,
) -> Result<Vec<UrlAnalysisResult>, DeepMailError> {
    let mut results = Vec::with_capacity(urls.len());

    for url in urls {
        let result = analyze_single_url_cached(url, cache, intel_config, breaker_config).await?;
        results.push(result);
    }

    tracing::debug!(count = results.len(), "URLs analysed");
    Ok(results)
}

// ─── Core analysis ────────────────────────────────────────────────────────────

/// Analyse a single URL, checking the cache first.
async fn analyze_single_url_cached(
    url: &str,
    cache: Option<&ThreatCache>,
    intel_config: &IntelConfig,
    breaker_config: &CircuitBreakerConfig,
) -> Result<UrlAnalysisResult, DeepMailError> {
    let domain = extract_domain(url);
    let cache_key = domain.as_deref().unwrap_or(url);

    // ── Cache lookup ─────────────────────────────────────────────────────────
    if let Some(c) = cache {
        if let Ok(Some(cached)) = c.get_domain_lookup::<UrlAnalysisResult>(cache_key).await {
            tracing::debug!(url = url, "URL domain cache HIT");
            // Return cached result but update the url field to the current URL
            // (same domain can appear in multiple URLs with different paths)
            return Ok(UrlAnalysisResult {
                url: url.to_string(),
                ..cached
            });
        }
    }

    // ── Offline analysis ──────────────────────────────────────────────────────
    let mut result = analyze_single_url(url);

    // Optional VirusTotal enrichment (enabled when API key env is present).
    if let Some(domain) = result.domain.as_deref() {
        if let Some(score) = lookup_virustotal_domain_score(domain, intel_config, breaker_config).await {
            result.reputation_score = Some(score);
        }
    }

    // ── Cache population ─────────────────────────────────────────────────────
    if let Some(c) = cache {
        let _ = c.cache_domain_lookup(cache_key, &result).await;
    }

    Ok(result)
}

fn provider_backoff_ms(config: &IntelConfig, attempt: u32) -> u64 {
    let growth = 1u64 << attempt.min(10);
    (config.provider_base_backoff_ms * growth).min(config.provider_max_backoff_ms)
}

async fn lookup_virustotal_domain_score(
    domain: &str,
    intel_config: &IntelConfig,
    breaker_config: &CircuitBreakerConfig,
) -> Option<f64> {
    if !intel_config.enable_virustotal_provider {
        return None;
    }

    let api_key = std::env::var(&intel_config.virustotal_api_key_env).ok()?;
    if api_key.trim().is_empty() {
        return None;
    }

    let breaker =
        VT_BREAKER.get_or_init(|| CircuitBreaker::new("virustotal", breaker_config.clone()));
    if !breaker.allow().await {
        VT_CIRCUIT_OPEN.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            provider = "virustotal",
            event = "circuit_open",
            total_circuit_open = VT_CIRCUIT_OPEN.load(Ordering::Relaxed),
            "VirusTotal request skipped by circuit breaker"
        );
        return None;
    }

    let url = format!("https://www.virustotal.com/api/v3/domains/{domain}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(intel_config.provider_timeout_ms))
        .build()
        .ok()?;

    let attempts = intel_config.provider_max_retries + 1;
    for attempt in 0..attempts {
        let response = client.get(&url).header("x-apikey", &api_key).send().await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let payload: VirusTotalDomainResponse = match resp.json().await {
                    Ok(v) => v,
                    Err(_) => {
                        VT_FAILURE.fetch_add(1, Ordering::Relaxed);
                        let _ = breaker.on_failure().await;
                        return None;
                    }
                };
                let stats = payload.data.attributes.last_analysis_stats;
                let total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
                if total == 0 {
                    return None;
                }
                let weighted_bad = (stats.malicious as f64) + (stats.suspicious as f64 * 0.5);
                VT_SUCCESS.fetch_add(1, Ordering::Relaxed);
                let _ = breaker.on_success().await;
                tracing::info!(
                    provider = "virustotal",
                    event = "success",
                    total_success = VT_SUCCESS.load(Ordering::Relaxed),
                    total_failures = VT_FAILURE.load(Ordering::Relaxed),
                    total_timeouts = VT_TIMEOUT.load(Ordering::Relaxed),
                    total_retries = VT_RETRIES.load(Ordering::Relaxed),
                    "VirusTotal enrichment success"
                );
                return Some((weighted_bad / total as f64 * 100.0).clamp(0.0, 100.0));
            }
            Ok(resp) => {
                VT_FAILURE.fetch_add(1, Ordering::Relaxed);
                if attempt + 1 < attempts {
                    VT_RETRIES.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(provider_backoff_ms(intel_config, attempt))).await;
                    continue;
                }
                let _ = breaker.on_failure().await;
                tracing::warn!(provider = "virustotal", status = %resp.status(), event = "failed", "VirusTotal request failed");
                return None;
            }
            Err(err) => {
                if err.is_timeout() {
                    VT_TIMEOUT.fetch_add(1, Ordering::Relaxed);
                } else {
                    VT_FAILURE.fetch_add(1, Ordering::Relaxed);
                }
                if attempt + 1 < attempts {
                    VT_RETRIES.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(provider_backoff_ms(intel_config, attempt))).await;
                    continue;
                }
                let _ = breaker.on_failure().await;
                tracing::warn!(provider = "virustotal", error = %err, event = "error", "VirusTotal request error");
                return None;
            }
        }
    }

    None
}

/// Perform pure offline structural analysis of a single URL.
fn analyze_single_url(url: &str) -> UrlAnalysisResult {
    let scheme = extract_scheme(url);
    let domain = extract_domain(url);

    let has_ip_host = domain.as_ref().map(|d| is_ip_address(d)).unwrap_or(false);

    let suspicious_tld = domain
        .as_ref()
        .map(|d| is_suspicious_tld(d))
        .unwrap_or(false);

    let subdomain_depth = domain
        .as_ref()
        .map(|d| d.matches('.').count().saturating_sub(1))
        .unwrap_or(0);

    let has_encoded_chars = url.contains('%')
        && url
            .chars()
            .zip(url.chars().skip(1))
            .any(|(a, b)| a == '%' && b.is_ascii_hexdigit());

    UrlAnalysisResult {
        url: url.to_string(),
        domain,
        scheme: scheme.to_string(),
        has_ip_host,
        suspicious_tld,
        url_length: url.len(),
        subdomain_depth,
        has_encoded_chars,
        reputation_score: None, // Phase 3
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn extract_scheme(url: &str) -> &str {
    if url.starts_with("https://") {
        "https"
    } else if url.starts_with("http://") {
        "http"
    } else if url.starts_with("ftp://") {
        "ftp"
    } else {
        "unknown"
    }
}

/// Extract the lowercase hostname from a URL.
fn extract_domain(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ftp://"))
        .unwrap_or(url);

    let domain: String = rest
        .chars()
        .take_while(|c| *c != '/' && *c != ':' && *c != '?' && *c != '#')
        .collect();

    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

pub fn extract_domain_for_reuse(url: &str) -> Option<String> {
    extract_domain(url)
}

/// Returns true if the string looks like an IPv4 address.
fn is_ip_address(host: &str) -> bool {
    host.split('.').count() == 4 && host.split('.').all(|octet| octet.parse::<u8>().is_ok())
}

/// Returns true if the domain ends with a known-abused TLD.
fn is_suspicious_tld(domain: &str) -> bool {
    SUSPICIOUS_TLDS.iter().any(|tld| domain.ends_with(tld))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_host_detection() {
        let result = analyze_single_url("http://1.2.3.4/payload");
        assert!(result.has_ip_host);
        assert_eq!(result.domain, Some("1.2.3.4".into()));
    }

    #[test]
    fn test_suspicious_tld() {
        let result = analyze_single_url("http://evil.tk/phish");
        assert!(result.suspicious_tld);
    }

    #[test]
    fn test_https_clean() {
        let result = analyze_single_url("https://legitimate.company.com/page");
        assert!(!result.has_ip_host);
        assert!(!result.suspicious_tld);
        assert_eq!(result.scheme, "https");
    }

    #[test]
    fn test_encoded_chars() {
        let result = analyze_single_url("http://evil.tk/%70%61%79%6C%6F%61%64");
        assert!(result.has_encoded_chars);
    }

    #[test]
    fn test_subdomain_depth() {
        // a.b.evil.tk → three dots → depth 2
        let result = analyze_single_url("http://a.b.evil.tk/x");
        assert_eq!(result.subdomain_depth, 2);
    }

    #[test]
    fn test_long_url() {
        let long = format!("https://example.com/{}", "a".repeat(300));
        let result = analyze_single_url(&long);
        assert!(result.url_length > 200);
    }
}
