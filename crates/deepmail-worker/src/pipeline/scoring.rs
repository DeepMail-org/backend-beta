//! Threat scoring engine — multi-dimensional weighted scoring.
//!
//! # Scoring Categories
//! 1. **Identity** (weight: 0.25) — SPF/DKIM/DMARC failures, sender mismatch
//! 2. **Infrastructure** (weight: 0.25) — suspicious IPs, IOC density
//! 3. **Content** (weight: 0.25) — URL count, phishing keywords, IOC density
//! 4. **Attachment** (weight: 0.25) — high entropy, suspicious types, count
//!
//! # Output
//! - Total weighted score: 0.0 - 100.0
//! - Confidence: 0.0 - 1.0 (based on data completeness)
//! - Per-category breakdown
//!
//! # Security
//! - Scoring is purely computational (no external calls)
//! - All inputs are treated as untrusted

use deepmail_common::models::{ScoreBreakdown, ThreatScore};

use crate::pipeline::attachment_analyzer::AttachmentAnalysisResult;
use crate::pipeline::header_analysis::HeaderAnalysis;
use crate::pipeline::ioc_extractor::ExtractedIocs;
use crate::pipeline::url_analyzer::UrlAnalysisResult;

/// Scoring weights for each category.
const WEIGHT_IDENTITY: f64 = 0.25;
const WEIGHT_INFRASTRUCTURE: f64 = 0.25;
const WEIGHT_CONTENT: f64 = 0.25;
const WEIGHT_ATTACHMENT: f64 = 0.25;

/// Calculate the overall threat score.
pub fn calculate_threat_score(
    headers: &HeaderAnalysis,
    iocs: &ExtractedIocs,
    url_results: &[UrlAnalysisResult],
    attachment_results: &[AttachmentAnalysisResult],
) -> ThreatScore {
    let identity = score_identity(headers);
    let infrastructure = score_infrastructure(iocs);
    let content = score_content(iocs, url_results);
    let attachment = score_attachment(attachment_results);

    let total = identity * WEIGHT_IDENTITY
        + infrastructure * WEIGHT_INFRASTRUCTURE
        + content * WEIGHT_CONTENT
        + attachment * WEIGHT_ATTACHMENT;

    let confidence = calculate_confidence(headers, iocs, attachment_results);

    tracing::debug!(
        total = total,
        confidence = confidence,
        identity = identity,
        infrastructure = infrastructure,
        content = content,
        attachment = attachment,
        "Threat score calculated"
    );

    ThreatScore {
        total: clamp_score(total),
        confidence,
        breakdown: ScoreBreakdown {
            identity: clamp_score(identity),
            infrastructure: clamp_score(infrastructure),
            content: clamp_score(content),
            attachment: clamp_score(attachment),
        },
    }
}

/// Score identity indicators (0-100).
fn score_identity(headers: &HeaderAnalysis) -> f64 {
    let mut score = 0.0;

    // SPF failure
    if let Some(ref spf) = headers.spf_result {
        match spf.result.as_str() {
            "fail" => score += 30.0,
            "softfail" => score += 15.0,
            "neutral" => score += 5.0,
            "temperror" | "permerror" => score += 10.0,
            "none" => score += 8.0,
            _ => {} // "pass" = 0 additional score
        }
    } else {
        // No SPF result at all — slightly suspicious
        score += 5.0;
    }

    // DKIM failure
    if let Some(ref dkim) = headers.dkim_result {
        match dkim.result.as_str() {
            "fail" => score += 25.0,
            "temperror" | "permerror" => score += 10.0,
            "none" => score += 5.0,
            _ => {}
        }
    } else {
        score += 3.0;
    }

    // DMARC failure
    if let Some(ref dmarc) = headers.dmarc_result {
        match dmarc.result.as_str() {
            "fail" => score += 30.0,
            "none" => score += 10.0,
            _ => {}
        }
    } else {
        score += 3.0;
    }

    // Reply-To mismatch (potential spoofing)
    if headers.sender.reply_to_mismatch {
        score += 15.0;
    }

    score
}

/// Score infrastructure indicators (0-100).
fn score_infrastructure(iocs: &ExtractedIocs) -> f64 {
    let mut score = 0.0;

    // Many unique IPs suggest forwarding/relay abuse
    let ip_count = iocs.ips.len();
    if ip_count > 10 {
        score += 20.0;
    } else if ip_count > 5 {
        score += 10.0;
    }

    // Many unique domains
    let domain_count = iocs.domains.len();
    if domain_count > 15 {
        score += 15.0;
    } else if domain_count > 8 {
        score += 8.0;
    }

    // High IOC density overall
    let total = iocs.total_count();
    if total > 50 {
        score += 25.0;
    } else if total > 20 {
        score += 15.0;
    } else if total > 10 {
        score += 5.0;
    }

    score
}

/// Score content indicators (0-100).
fn score_content(iocs: &ExtractedIocs, url_results: &[UrlAnalysisResult]) -> f64 {
    let mut score = 0.0;

    // URL count
    let url_count = iocs.urls.len();
    if url_count > 10 {
        score += 20.0;
    } else if url_count > 5 {
        score += 10.0;
    } else if url_count > 0 {
        score += 3.0;
    }

    // Suspicious TLDs in URLs
    let suspicious_url_count = url_results
        .iter()
        .filter(|u| u.suspicious_tld)
        .count();
    score += (suspicious_url_count as f64) * 10.0;

    // IP-based URLs (e.g., http://1.2.3.4/payload)
    let ip_url_count = url_results.iter().filter(|u| u.has_ip_host).count();
    score += (ip_url_count as f64) * 15.0;

    // Very long URLs (often obfuscation)
    let long_url_count = url_results.iter().filter(|u| u.url_length > 200).count();
    score += (long_url_count as f64) * 5.0;

    // Hashes in email body (unusual for legitimate emails)
    if !iocs.hashes.is_empty() {
        score += 5.0;
    }

    score
}

/// Score attachment indicators (0-100).
fn score_attachment(attachments: &[AttachmentAnalysisResult]) -> f64 {
    if attachments.is_empty() {
        return 0.0;
    }

    let mut score = 0.0;

    for attachment in attachments {
        // High entropy (> 7.0) — possible encrypted/packed content
        if attachment.entropy > 7.5 {
            score += 20.0;
        } else if attachment.entropy > 7.0 {
            score += 10.0;
        }

        // Suspicious file type
        if attachment.suspicious_type {
            score += 30.0;
        }

        // Large file (> 5MB)
        if attachment.file_size > 5 * 1024 * 1024 {
            score += 5.0;
        }
    }

    // Multiple attachments
    if attachments.len() > 3 {
        score += 10.0;
    }

    score
}

/// Calculate confidence based on data completeness.
///
/// Higher confidence when more analysis stages produced data.
fn calculate_confidence(
    headers: &HeaderAnalysis,
    iocs: &ExtractedIocs,
    attachments: &[AttachmentAnalysisResult],
) -> f64 {
    let mut signals = 0.0;
    let mut total_signals = 5.0;

    // Header analysis produced results
    if !headers.received_hops.is_empty() {
        signals += 1.0;
    }

    // Auth results available
    if headers.spf_result.is_some() || headers.dkim_result.is_some() || headers.dmarc_result.is_some() {
        signals += 1.0;
    }

    // IOCs found
    if iocs.total_count() > 0 {
        signals += 1.0;
    }

    // Sender info complete
    if headers.sender.from.is_some() {
        signals += 1.0;
    }

    // Attachment analysis (if applicable)
    if !attachments.is_empty() {
        signals += 1.0;
    } else {
        total_signals -= 1.0; // Don't penalize for no attachments
    }

    if total_signals > 0.0 {
        (signals / total_signals).min(1.0)
    } else {
        0.5
    }
}

/// Clamp a score to the 0-100 range.
fn clamp_score(score: f64) -> f64 {
    score.max(0.0).min(100.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::header_analysis::*;

    fn empty_headers() -> HeaderAnalysis {
        HeaderAnalysis {
            received_hops: vec![],
            originating_ip: None,
            spf_result: None,
            dkim_result: None,
            dmarc_result: None,
            sender: SenderInfo {
                from: None,
                reply_to: None,
                return_path: None,
                reply_to_mismatch: false,
            },
        }
    }

    #[test]
    fn test_clean_email_low_score() {
        let headers = HeaderAnalysis {
            received_hops: vec![ReceivedHop {
                hop: 1,
                from_host: Some("mail.google.com".into()),
                ip: Some("209.85.220.41".into()),
                by_host: Some("mx.company.com".into()),
                raw: String::new(),
            }],
            originating_ip: Some("209.85.220.41".into()),
            spf_result: Some(AuthResult { method: "spf".into(), result: "pass".into(), details: None }),
            dkim_result: Some(AuthResult { method: "dkim".into(), result: "pass".into(), details: None }),
            dmarc_result: Some(AuthResult { method: "dmarc".into(), result: "pass".into(), details: None }),
            sender: SenderInfo {
                from: Some("sender@example.com".into()),
                reply_to: None,
                return_path: Some("sender@example.com".into()),
                reply_to_mismatch: false,
            },
        };

        let iocs = ExtractedIocs::default();
        let score = calculate_threat_score(&headers, &iocs, &[], &[]);

        // Clean email with passing auth → low score
        assert!(score.total < 10.0, "Clean email score should be < 10, got {}", score.total);
        assert!(score.confidence > 0.5);
    }

    #[test]
    fn test_suspicious_email_high_score() {
        let headers = HeaderAnalysis {
            received_hops: vec![],
            originating_ip: None,
            spf_result: Some(AuthResult { method: "spf".into(), result: "fail".into(), details: None }),
            dkim_result: Some(AuthResult { method: "dkim".into(), result: "fail".into(), details: None }),
            dmarc_result: Some(AuthResult { method: "dmarc".into(), result: "fail".into(), details: None }),
            sender: SenderInfo {
                from: Some("ceo@company.com".into()),
                reply_to: Some("attacker@evil.tk".into()),
                return_path: None,
                reply_to_mismatch: true,
            },
        };

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
            reputation_score: None,
        }];

        let score = calculate_threat_score(&headers, &iocs, &url_results, &[]);

        // SPF+DKIM+DMARC fail + reply-to mismatch + IP-based URL → high score
        assert!(score.total > 30.0, "Suspicious email score should be > 30, got {}", score.total);
    }
}
