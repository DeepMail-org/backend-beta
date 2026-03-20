//! Threat scoring engine — multi-dimensional weighted threat score.
//!
//! # Scoring Dimensions
//!
//! | Dimension      | Weight | What it captures |
//! |----------------|--------|-----------------|
//! | Identity       | 0.25   | SPF/DKIM/DMARC failures, Reply-To spoofing |
//! | Infrastructure | 0.25   | Suspicious IPs, IOC density, domain count |
//! | Content        | 0.25   | URLs, phishing keywords, hash-in-body |
//! | Attachment     | 0.25   | High entropy, suspicious file types, count |
//!
//! # Output
//! - `total` — weighted aggregate: **0.0–100.0**
//! - `confidence` — data completeness indicator: **0.0–1.0**
//! - `breakdown` — per-dimension scores for UI display
//!
//! # Security
//! - Purely computational — zero external calls
//! - All inputs are treated as untrusted data
//! - Scores are clamped to [0, 100] to prevent abuse via extreme values

use deepmail_common::models::{ScoreBreakdown, ThreatScore};

use crate::pipeline::attachment_analyzer::AttachmentAnalysisResult;
use crate::pipeline::header_analysis::HeaderAnalysis;
use crate::pipeline::ioc_extractor::ExtractedIocs;
use crate::pipeline::phishing_keywords::PhishingKeywordResult;
use crate::pipeline::url_analyzer::UrlAnalysisResult;

// ─── Dimension weights ────────────────────────────────────────────────────────

const WEIGHT_IDENTITY: f64 = 0.25;
const WEIGHT_INFRASTRUCTURE: f64 = 0.25;
const WEIGHT_CONTENT: f64 = 0.25;
const WEIGHT_ATTACHMENT: f64 = 0.25;

// ─── Public entry point ───────────────────────────────────────────────────────

/// Calculate the overall multi-dimensional threat score.
///
/// # Arguments
/// - `headers`      — header analysis result (auth, Received chain, sender)
/// - `iocs`         — extracted IOCs
/// - `url_results`  — per-URL structural analysis
/// - `attachment_results` — per-attachment static analysis
/// - `phishing`     — phishing keyword scan result for the email body
pub fn calculate_threat_score(
    headers: &HeaderAnalysis,
    iocs: &ExtractedIocs,
    url_results: &[UrlAnalysisResult],
    attachment_results: &[AttachmentAnalysisResult],
    phishing: &PhishingKeywordResult,
) -> ThreatScore {
    let identity = score_identity(headers);
    let infrastructure = score_infrastructure(iocs);
    let content = score_content(iocs, url_results, phishing);
    let attachment = score_attachment(attachment_results);

    let total = identity * WEIGHT_IDENTITY
        + infrastructure * WEIGHT_INFRASTRUCTURE
        + content * WEIGHT_CONTENT
        + attachment * WEIGHT_ATTACHMENT;

    let confidence = calculate_confidence(headers, iocs, attachment_results, phishing);

    tracing::debug!(
        total = total,
        confidence = confidence,
        identity = identity,
        infrastructure = infrastructure,
        content = content,
        attachment = attachment,
        keyword_matches = phishing.match_count,
        "Threat score calculated"
    );

    ThreatScore {
        total: clamp(total),
        confidence,
        breakdown: ScoreBreakdown {
            identity: clamp(identity),
            infrastructure: clamp(infrastructure),
            content: clamp(content),
            attachment: clamp(attachment),
        },
    }
}

// ─── Dimension scorers ────────────────────────────────────────────────────────

/// Score identity dimension (0–100).
///
/// Penalises SPF/DKIM/DMARC failures and Reply-To mismatch.
fn score_identity(headers: &HeaderAnalysis) -> f64 {
    let mut score = 0.0;

    // SPF
    match headers.spf_result.as_ref().map(|r| r.result.as_str()) {
        Some("fail") => score += 30.0,
        Some("softfail") => score += 15.0,
        Some("neutral") => score += 5.0,
        Some("temperror") | Some("permerror") => score += 10.0,
        Some("none") => score += 8.0,
        None => score += 5.0, // missing = slightly suspicious
        _ => {}               // "pass" → 0
    }

    // DKIM
    match headers.dkim_result.as_ref().map(|r| r.result.as_str()) {
        Some("fail") => score += 25.0,
        Some("temperror") | Some("permerror") => score += 10.0,
        Some("none") => score += 5.0,
        None => score += 3.0,
        _ => {}
    }

    // DMARC
    match headers.dmarc_result.as_ref().map(|r| r.result.as_str()) {
        Some("fail") => score += 30.0,
        Some("none") => score += 10.0,
        None => score += 3.0,
        _ => {}
    }

    // Reply-To ≠ From domain → likely spoofing
    if headers.sender.reply_to_mismatch {
        score += 15.0;
    }

    score
}

/// Score infrastructure dimension (0–100).
///
/// Penalises high IOC density and suspicious hop count.
fn score_infrastructure(iocs: &ExtractedIocs) -> f64 {
    let mut score = 0.0;

    // Many unique public IPs suggest relay abuse or botnet infrastructure
    let ip_count = iocs.ips.len();
    score += match ip_count {
        0 => 0.0,
        1..=5 => ip_count as f64 * 1.0,
        6..=10 => 10.0,
        _ => 20.0,
    };

    // Many unique domains
    let domain_count = iocs.domains.len();
    score += match domain_count {
        0 => 0.0,
        1..=8 => domain_count as f64 * 0.5,
        9..=15 => 8.0,
        _ => 15.0,
    };

    // Overall IOC density
    let total_iocs = iocs.total_count();
    score += match total_iocs {
        0 => 0.0,
        1..=10 => 5.0,
        11..=20 => 15.0,
        21..=50 => 20.0,
        _ => 25.0,
    };

    score
}

/// Score content dimension (0–100).
///
/// Penalises suspicious URLs and phishing keyword matches.
fn score_content(
    iocs: &ExtractedIocs,
    url_results: &[UrlAnalysisResult],
    phishing: &PhishingKeywordResult,
) -> f64 {
    let mut score = 0.0;

    // URL count
    let url_count = iocs.urls.len();
    score += match url_count {
        0 => 0.0,
        1..=5 => 3.0,
        6..=10 => 10.0,
        _ => 20.0,
    };

    // Suspicious TLDs
    let suspicious_tld_count = url_results.iter().filter(|u| u.suspicious_tld).count();
    score += suspicious_tld_count as f64 * 10.0;

    // IP-based URLs (e.g. http://1.2.3.4/payload) — very suspicious
    let ip_url_count = url_results.iter().filter(|u| u.has_ip_host).count();
    score += ip_url_count as f64 * 15.0;

    // Very long URLs often indicate obfuscation or tracking params
    let long_url_count = url_results.iter().filter(|u| u.url_length > 200).count();
    score += long_url_count as f64 * 5.0;

    // Percent-encoded chars in URL paths — common obfuscation technique
    let encoded_url_count = url_results.iter().filter(|u| u.has_encoded_chars).count();
    score += encoded_url_count as f64 * 3.0;

    // Hashes in email body (unusual for legitimate email)
    if !iocs.hashes.is_empty() {
        score += 5.0;
    }

    // Phishing keyword contribution (up to 30 bonus points on top of URL score)
    // We cap this contribution so it doesn't dominate the content dimension.
    let keyword_contribution = (phishing.keyword_score / 100.0) * 30.0;
    score += keyword_contribution;

    score
}

/// Score attachment dimension (0–100).
///
/// Penalises high-entropy or suspicious-type attachments.
fn score_attachment(attachments: &[AttachmentAnalysisResult]) -> f64 {
    if attachments.is_empty() {
        return 0.0;
    }

    let mut score = 0.0;

    for att in attachments {
        // High entropy → likely encrypted/packed content
        if att.entropy > 7.5 {
            score += 20.0;
        } else if att.entropy > 7.0 {
            score += 10.0;
        } else if att.entropy > 6.5 {
            score += 5.0;
        }

        // Suspicious file type
        if att.suspicious_type {
            score += 30.0;
        }

        // Large file (> 5 MB) with no clear reason
        if att.file_size > 5 * 1024 * 1024 {
            score += 5.0;
        }
    }

    // Multiple attachments compound risk
    if attachments.len() > 3 {
        score += 10.0;
    }

    score
}

// ─── Confidence calculation ────────────────────────────────────────────────────

/// Estimate scoring confidence based on available data signals.
///
/// Higher confidence when more pipeline stages produced meaningful data.
/// Returns a value in [0.0, 1.0].
fn calculate_confidence(
    headers: &HeaderAnalysis,
    iocs: &ExtractedIocs,
    attachments: &[AttachmentAnalysisResult],
    phishing: &PhishingKeywordResult,
) -> f64 {
    let mut signals: f64 = 0.0;
    let mut possible: f64 = 0.0;

    // Signal: Received chain present
    possible += 1.0;
    if !headers.received_hops.is_empty() {
        signals += 1.0;
    }

    // Signal: Auth results available
    possible += 1.0;
    if headers.spf_result.is_some()
        || headers.dkim_result.is_some()
        || headers.dmarc_result.is_some()
    {
        signals += 1.0;
    }

    // Signal: Sender identity resolved
    possible += 1.0;
    if headers.sender.from.is_some() {
        signals += 1.0;
    }

    // Signal: IOCs found
    possible += 1.0;
    if iocs.total_count() > 0 {
        signals += 1.0;
    }

    // Signal: Body available for keyword scan
    possible += 1.0;
    // Even 0 keywords is a valid result if we had text to scan
    // We treat phishing scanner as successful if it ran (match_count >= 0)
    // Check: if score > 0 OR scanned something meaningful (we always run it)
    signals += 1.0; // Scanner always runs — always contributes signal

    // Signal: Attachment analysis (optional — don't penalise clean emails)
    if !attachments.is_empty() {
        possible += 1.0;
        signals += 1.0;
    }

    // Phishing keyword richness bonus (non-penalising)
    let _ = phishing; // signals already counted above

    if possible > 0.0 {
        (signals / possible).min(1.0)
    } else {
        0.5
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/// Clamp a raw score to the valid [0.0, 100.0] range.
fn clamp(score: f64) -> f64 {
    score.clamp(0.0, 100.0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::header_analysis::{AuthResult, ReceivedHop, SenderInfo};
    use crate::pipeline::phishing_keywords::PhishingKeywordResult;

    fn clean_headers() -> HeaderAnalysis {
        HeaderAnalysis {
            received_hops: vec![ReceivedHop {
                hop: 1,
                from_host: Some("mail.google.com".into()),
                ip: Some("209.85.220.41".into()),
                by_host: Some("mx.company.com".into()),
                raw: String::new(),
            }],
            originating_ip: Some("209.85.220.41".into()),
            spf_result: Some(AuthResult {
                method: "spf".into(),
                result: "pass".into(),
                details: None,
            }),
            dkim_result: Some(AuthResult {
                method: "dkim".into(),
                result: "pass".into(),
                details: None,
            }),
            dmarc_result: Some(AuthResult {
                method: "dmarc".into(),
                result: "pass".into(),
                details: None,
            }),
            sender: SenderInfo {
                from: Some("sender@example.com".into()),
                reply_to: None,
                return_path: Some("sender@example.com".into()),
                reply_to_mismatch: false,
            },
        }
    }

    fn failed_headers() -> HeaderAnalysis {
        HeaderAnalysis {
            received_hops: vec![],
            originating_ip: None,
            spf_result: Some(AuthResult {
                method: "spf".into(),
                result: "fail".into(),
                details: None,
            }),
            dkim_result: Some(AuthResult {
                method: "dkim".into(),
                result: "fail".into(),
                details: None,
            }),
            dmarc_result: Some(AuthResult {
                method: "dmarc".into(),
                result: "fail".into(),
                details: None,
            }),
            sender: SenderInfo {
                from: Some("ceo@company.com".into()),
                reply_to: Some("attacker@evil.tk".into()),
                return_path: None,
                reply_to_mismatch: true,
            },
        }
    }

    #[test]
    fn test_clean_email_low_score() {
        let headers = clean_headers();
        let iocs = ExtractedIocs::default();
        let phishing = PhishingKeywordResult::default();
        let score = calculate_threat_score(&headers, &iocs, &[], &[], &phishing);

        assert!(
            score.total < 10.0,
            "Clean email score should be < 10, got {}",
            score.total
        );
        assert!(
            score.confidence > 0.5,
            "Confidence should be high for complete data"
        );
    }

    #[test]
    fn test_suspicious_email_high_score() {
        let headers = failed_headers();
        let iocs = ExtractedIocs {
            ips: vec!["1.2.3.4".into()],
            domains: vec!["evil.tk".into()],
            urls: vec!["http://1.2.3.4/payload".into()],
            emails: vec!["attacker@evil.tk".into()],
            hashes: vec![],
        };
        let url_results = vec![UrlAnalysisResult {
            url: "http://1.2.3.4/payload".into(),
            domain: Some("1.2.3.4".into()),
            scheme: "http".into(),
            has_ip_host: true,
            suspicious_tld: false,
            url_length: 25,
            subdomain_depth: 0,
            has_encoded_chars: false,
            reputation_score: None,
        }];
        let phishing = PhishingKeywordResult {
            matched_keywords: vec!["verify your account".into()],
            keyword_score: 22.0,
            match_count: 1,
        };

        let score = calculate_threat_score(&headers, &iocs, &url_results, &[], &phishing);
        assert!(
            score.total > 30.0,
            "Suspicious email score should be > 30, got {}",
            score.total
        );
    }

    #[test]
    fn test_score_is_clamped() {
        // Even with absurd input, score must stay in [0, 100]
        let headers = failed_headers();
        let iocs = ExtractedIocs {
            ips: (0..50).map(|i| format!("{i}.{i}.{i}.{i}")).collect(),
            domains: (0..50).map(|i| format!("evil{i}.tk")).collect(),
            urls: (0..50)
                .map(|i| format!("http://evil{i}.tk/bad{i}"))
                .collect(),
            emails: vec![],
            hashes: vec!["aabbcc".into()],
        };
        let phishing = PhishingKeywordResult {
            matched_keywords: vec![],
            keyword_score: 100.0,
            match_count: 10,
        };
        let score = calculate_threat_score(&headers, &iocs, &[], &[], &phishing);
        assert!(
            score.total <= 100.0,
            "Score must be clamped to 100, got {}",
            score.total
        );
        assert!(score.total >= 0.0);
    }
}
