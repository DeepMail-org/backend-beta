//! Phishing keyword scanner — detects urgency and deception language.
//!
//! # Responsibilities
//! - Maintain a curated list of phishing-indicative keyword patterns
//! - Scan email body text (plain-text and HTML) for matches
//! - Return matched keywords and a normalised score contribution
//!
//! # Design Decisions
//! - Case-insensitive substring matching (no regex overhead)
//! - Weighted keywords: high-confidence phrases score more than generic terms
//! - Score is 0.0–100.0 and is later combined with other dimensions
//!
//! # Security Considerations
//! - All scanning is read-only (no modification of input)
//! - HTML is scanned as raw text — no DOM parsing required at this stage
//! - Keyword list is compiled-in (no external file I/O)

use serde::Serialize;

// ─── Weighted keyword definitions ────────────────────────────────────────────

/// A keyword/phrase and its weight contribution to the phishing score.
struct WeightedKeyword {
    phrase: &'static str,
    /// Score points awarded per match (capped at total 100.0).
    weight: f64,
}

/// Curated list of phishing-indicative phrases, grouped by category.
///
/// Weights are tuned empirically:
/// - Highly specific phrases (banking/credential theft) → 20–25 pts
/// - Urgency/action language → 10–15 pts
/// - Generic suspicious language → 5–8 pts
static KEYWORDS: &[WeightedKeyword] = &[
    // ── Credential theft ────────────────────────────────────────────────────
    WeightedKeyword { phrase: "verify your account",       weight: 22.0 },
    WeightedKeyword { phrase: "verify your identity",      weight: 22.0 },
    WeightedKeyword { phrase: "confirm your account",      weight: 22.0 },
    WeightedKeyword { phrase: "confirm your password",     weight: 22.0 },
    WeightedKeyword { phrase: "update your payment",       weight: 20.0 },
    WeightedKeyword { phrase: "enter your credentials",    weight: 20.0 },
    WeightedKeyword { phrase: "enter your password",       weight: 20.0 },
    WeightedKeyword { phrase: "login credentials",         weight: 18.0 },
    WeightedKeyword { phrase: "reset your password",       weight: 15.0 },

    // ── Account suspension / urgency ────────────────────────────────────────
    WeightedKeyword { phrase: "account has been suspended", weight: 22.0 },
    WeightedKeyword { phrase: "account suspended",          weight: 20.0 },
    WeightedKeyword { phrase: "account has been limited",   weight: 20.0 },
    WeightedKeyword { phrase: "unusual activity",           weight: 18.0 },
    WeightedKeyword { phrase: "unauthorized access",        weight: 18.0 },
    WeightedKeyword { phrase: "suspicious activity",        weight: 18.0 },
    WeightedKeyword { phrase: "your account will be closed", weight: 22.0 },
    WeightedKeyword { phrase: "we noticed unusual",         weight: 15.0 },

    // ── Action urgency ───────────────────────────────────────────────────────
    WeightedKeyword { phrase: "click here immediately",     weight: 20.0 },
    WeightedKeyword { phrase: "click here now",             weight: 18.0 },
    WeightedKeyword { phrase: "act now",                    weight: 12.0 },
    WeightedKeyword { phrase: "act immediately",            weight: 14.0 },
    WeightedKeyword { phrase: "immediate action required",  weight: 18.0 },
    WeightedKeyword { phrase: "action required",            weight: 12.0 },
    WeightedKeyword { phrase: "urgent action",              weight: 14.0 },
    WeightedKeyword { phrase: "respond immediately",        weight: 14.0 },

    // ── Financial bait ───────────────────────────────────────────────────────
    WeightedKeyword { phrase: "you have won",               weight: 20.0 },
    WeightedKeyword { phrase: "congratulations! you",       weight: 18.0 },
    WeightedKeyword { phrase: "claim your prize",           weight: 20.0 },
    WeightedKeyword { phrase: "wire transfer",              weight: 15.0 },
    WeightedKeyword { phrase: "bank account details",       weight: 18.0 },
    WeightedKeyword { phrase: "payment information",        weight: 10.0 },
    WeightedKeyword { phrase: "gift card",                  weight: 15.0 },
    WeightedKeyword { phrase: "investment opportunity",     weight: 12.0 },

    // ── Impersonation indicators ─────────────────────────────────────────────
    WeightedKeyword { phrase: "your apple id",              weight: 12.0 },
    WeightedKeyword { phrase: "your paypal",                weight: 12.0 },
    WeightedKeyword { phrase: "your amazon account",        weight: 12.0 },
    WeightedKeyword { phrase: "microsoft account",          weight: 10.0 },
    WeightedKeyword { phrase: "irs notice",                 weight: 15.0 },

    // ── Generic suspicious language ──────────────────────────────────────────
    WeightedKeyword { phrase: "do not ignore",              weight: 8.0  },
    WeightedKeyword { phrase: "do not share this",          weight: 8.0  },
    WeightedKeyword { phrase: "confidential",               weight: 5.0  },
    WeightedKeyword { phrase: "dear customer",              weight: 5.0  },
    WeightedKeyword { phrase: "dear valued customer",       weight: 8.0  },
    WeightedKeyword { phrase: "verify now",                 weight: 10.0 },
];

// ─── Result type ─────────────────────────────────────────────────────────────

/// Result of scanning an email body for phishing keywords.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PhishingKeywordResult {
    /// All phrases that matched (lowercase, deduplicated).
    pub matched_keywords: Vec<String>,
    /// Normalised score contribution from keyword hits (0.0–100.0).
    pub keyword_score: f64,
    /// Number of distinct keyword matches.
    pub match_count: usize,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Scan one or more text bodies for phishing keyword patterns.
///
/// Accepts multiple text blocks (e.g., plain-text body, HTML body) and
/// scans them as a single concatenated string to avoid redundant matches.
///
/// # Arguments
/// - `bodies` — iterator of optional text blocks; `None` entries are skipped.
///
/// # Returns
/// A `PhishingKeywordResult` with all matches and a capped score.
pub fn scan_bodies<'a>(
    bodies: impl IntoIterator<Item = Option<&'a str>>,
) -> PhishingKeywordResult {
    // Merge all provided text into a single lowercase buffer
    let combined: String = bodies
        .into_iter()
        .flatten()
        .flat_map(|s| {
            let mut v = s.to_lowercase();
            v.push('\n');
            v.into_bytes()
        })
        .map(|b| b as char)
        .collect();

    scan_text(&combined)
}

/// Scan a single pre-normalised text string for keyword matches.
pub fn scan_text(text: &str) -> PhishingKeywordResult {
    let text_lower = text.to_lowercase();
    let mut matched = Vec::new();
    let mut total_score: f64 = 0.0;

    for kw in KEYWORDS {
        if text_lower.contains(kw.phrase) {
            matched.push(kw.phrase.to_string());
            total_score += kw.weight;
        }
    }

    let match_count = matched.len();

    // Cap at 100.0; phishing language is highly repetitive so we avoid double-counting
    let keyword_score = total_score.min(100.0);

    if match_count > 0 {
        tracing::debug!(
            matches = match_count,
            score = keyword_score,
            "Phishing keywords detected"
        );
    }

    PhishingKeywordResult {
        matched_keywords: matched,
        keyword_score,
        match_count,
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_body() {
        let result = scan_text("");
        assert_eq!(result.match_count, 0);
        assert_eq!(result.keyword_score, 0.0);
    }

    #[test]
    fn test_clean_email() {
        let result = scan_text("Hello, please review the attached quarterly report. Thanks.");
        assert_eq!(result.match_count, 0);
    }

    #[test]
    fn test_single_keyword_hit() {
        let result = scan_text("Please verify your account to continue.");
        assert_eq!(result.match_count, 1);
        assert!(result.keyword_score > 0.0);
        assert!(result.matched_keywords.contains(&"verify your account".to_string()));
    }

    #[test]
    fn test_multiple_keywords_capped() {
        // Stack many high-weight keywords — score must be capped at 100.0
        let text = "verify your account suspended unusual activity click here now \
                    you have won claim your prize wire transfer gift card";
        let result = scan_text(text);
        assert!(result.match_count > 3);
        assert!(result.keyword_score <= 100.0, "score={}", result.keyword_score);
    }

    #[test]
    fn test_case_insensitive() {
        let result = scan_text("VERIFY YOUR ACCOUNT has been SUSPENDED");
        // Should match both "verify your account" and "account has been suspended"
        assert!(result.match_count >= 1);
    }

    #[test]
    fn test_scan_bodies_multiple_parts() {
        let plain = Some("Dear customer, verify now.");
        let html  = Some("<html>Account suspended.</html>");
        let result = scan_bodies([plain, html, None]);
        // "dear customer" + "verify now" + "account suspended" → multiple hits
        assert!(result.match_count >= 2);
    }
}
