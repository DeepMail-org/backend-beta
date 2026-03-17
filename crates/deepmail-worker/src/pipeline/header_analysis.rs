//! Email header analysis module.
//!
//! # Responsibilities
//! - Parse the `Received:` header chain to trace email hops
//! - Extract the originating IP (first external hop)
//! - Parse `Authentication-Results:` for SPF/DKIM/DMARC status
//! - Extract sender identity info (From, Reply-To, Return-Path)
//!
//! # Security
//! - Headers are treated as untrusted input
//! - IP extraction uses regex to prevent injection
//! - Auth result parsing is best-effort (not cryptographic verification)
//!
//! # Note
//! Full cryptographic DKIM verification and DNS-based SPF/DMARC checks
//! require DNS resolution and are deferred to Phase 3.

use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;

use crate::pipeline::email_parser::ParsedEmail;

lazy_static! {
    /// Regex to extract IP addresses from Received headers.
    static ref IP_IN_RECEIVED: Regex = Regex::new(
        r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?"
    ).expect("Invalid IP regex");

    /// Regex to extract domain from "from" clause in Received header.
    static ref DOMAIN_IN_RECEIVED: Regex = Regex::new(
        r"from\s+([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"
    ).expect("Invalid domain regex");
}

/// Result of header analysis.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderAnalysis {
    /// Parsed Received chain hops (newest first).
    pub received_hops: Vec<ReceivedHop>,
    /// Originating IP (first external hop).
    pub originating_ip: Option<String>,
    /// SPF check result from Authentication-Results.
    pub spf_result: Option<AuthResult>,
    /// DKIM check result from Authentication-Results.
    pub dkim_result: Option<AuthResult>,
    /// DMARC check result from Authentication-Results.
    pub dmarc_result: Option<AuthResult>,
    /// Sender info.
    pub sender: SenderInfo,
}

/// A single hop in the Received chain.
#[derive(Debug, Clone, Serialize)]
pub struct ReceivedHop {
    /// Hop number (1 = closest to recipient).
    pub hop: usize,
    /// "from" domain/IP.
    pub from_host: Option<String>,
    /// IP address in the hop.
    pub ip: Option<String>,
    /// "by" domain.
    pub by_host: Option<String>,
    /// Raw header value.
    pub raw: String,
}

/// Authentication result (SPF/DKIM/DMARC).
#[derive(Debug, Clone, Serialize)]
pub struct AuthResult {
    pub method: String,
    pub result: String, // "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"
    pub details: Option<String>,
}

/// Sender identity information.
#[derive(Debug, Clone, Serialize)]
pub struct SenderInfo {
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub return_path: Option<String>,
    /// True if From and Reply-To domains differ (potential spoofing indicator).
    pub reply_to_mismatch: bool,
}

/// Analyze email headers and return structured results.
pub fn analyze_headers(email: &ParsedEmail) -> HeaderAnalysis {
    let received_hops = parse_received_chain(email);
    let originating_ip = extract_originating_ip(&received_hops);

    let (spf_result, dkim_result, dmarc_result) = parse_authentication_results(email);

    let return_path = email
        .headers
        .iter()
        .find(|h| h.name == "return-path")
        .map(|h| h.value.clone());

    let reply_to_mismatch = check_reply_to_mismatch(
        email.from.as_deref(),
        email.reply_to.as_deref(),
    );

    let sender = SenderInfo {
        from: email.from.clone(),
        reply_to: email.reply_to.clone(),
        return_path,
        reply_to_mismatch,
    };

    HeaderAnalysis {
        received_hops,
        originating_ip,
        spf_result,
        dkim_result,
        dmarc_result,
        sender,
    }
}

/// Parse the Received header chain.
///
/// Headers are in reverse order (newest first) as per RFC 5321.
fn parse_received_chain(email: &ParsedEmail) -> Vec<ReceivedHop> {
    let received_headers: Vec<&str> = email
        .headers
        .iter()
        .filter(|h| h.name == "received")
        .map(|h| h.value.as_str())
        .collect();

    received_headers
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let from_host = DOMAIN_IN_RECEIVED
                .captures(raw)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            let ip = IP_IN_RECEIVED
                .captures(raw)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            let by_host = extract_by_host(raw);

            ReceivedHop {
                hop: i + 1,
                from_host,
                ip,
                by_host,
                raw: raw.to_string(),
            }
        })
        .collect()
}

/// Extract the "by" host from a Received header.
fn extract_by_host(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();
    if let Some(pos) = lower.find("by ") {
        let rest = &raw[pos + 3..];
        let host: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-')
            .collect();
        if !host.is_empty() {
            return Some(host);
        }
    }
    None
}

/// Extract the originating IP — the first external (non-private) IP in the chain.
fn extract_originating_ip(hops: &[ReceivedHop]) -> Option<String> {
    // Walk from the last hop (oldest, closest to sender) towards the first
    for hop in hops.iter().rev() {
        if let Some(ref ip) = hop.ip {
            if !is_private_ip(ip) {
                return Some(ip.clone());
            }
        }
    }
    // If all are private, return the last one
    hops.last().and_then(|h| h.ip.clone())
}

/// Check if an IP address is in a private/reserved range.
fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();

    if parts.len() != 4 {
        return false;
    }

    matches!(
        (parts[0], parts[1]),
        (10, _)                         // 10.0.0.0/8
        | (172, 16..=31)                // 172.16.0.0/12
        | (192, 168)                    // 192.168.0.0/16
        | (127, _)                      // 127.0.0.0/8
        | (0, _)                        // 0.0.0.0/8
        | (169, 254)                    // 169.254.0.0/16 (link-local)
    )
}

/// Parse Authentication-Results header for SPF/DKIM/DMARC.
fn parse_authentication_results(
    email: &ParsedEmail,
) -> (Option<AuthResult>, Option<AuthResult>, Option<AuthResult>) {
    let auth_headers: Vec<&str> = email
        .headers
        .iter()
        .filter(|h| h.name == "authentication-results")
        .map(|h| h.value.as_str())
        .collect();

    let mut spf = None;
    let mut dkim = None;
    let mut dmarc = None;

    for header in &auth_headers {
        let lower = header.to_lowercase();

        if spf.is_none() {
            if let Some(result) = extract_auth_method(&lower, "spf") {
                spf = Some(result);
            }
        }
        if dkim.is_none() {
            if let Some(result) = extract_auth_method(&lower, "dkim") {
                dkim = Some(result);
            }
        }
        if dmarc.is_none() {
            if let Some(result) = extract_auth_method(&lower, "dmarc") {
                dmarc = Some(result);
            }
        }
    }

    (spf, dkim, dmarc)
}

/// Extract a single authentication method result from an Authentication-Results value.
fn extract_auth_method(header: &str, method: &str) -> Option<AuthResult> {
    // Look for patterns like "spf=pass" or "dkim=fail (details here)"
    let pattern = format!("{method}=");
    if let Some(pos) = header.find(&pattern) {
        let rest = &header[pos + pattern.len()..];
        let result: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic())
            .collect();

        if !result.is_empty() {
            // Extract details in parentheses if present
            let details = rest
                .find('(')
                .and_then(|start| {
                    rest[start + 1..].find(')').map(|end| {
                        rest[start + 1..start + 1 + end].to_string()
                    })
                });

            return Some(AuthResult {
                method: method.to_string(),
                result,
                details,
            });
        }
    }
    None
}

/// Check if From and Reply-To domains differ.
fn check_reply_to_mismatch(from: Option<&str>, reply_to: Option<&str>) -> bool {
    match (from, reply_to) {
        (Some(from), Some(reply_to)) => {
            let from_domain = extract_domain_from_email_addr(from);
            let reply_domain = extract_domain_from_email_addr(reply_to);
            match (from_domain, reply_domain) {
                (Some(fd), Some(rd)) => fd.to_lowercase() != rd.to_lowercase(),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Extract domain from an email address string (handles "Name <addr>" format).
fn extract_domain_from_email_addr(addr: &str) -> Option<String> {
    let email = if let Some(start) = addr.find('<') {
        if let Some(end) = addr.find('>') {
            &addr[start + 1..end]
        } else {
            addr
        }
    } else {
        addr
    };
    email.split('@').nth(1).map(|d| d.trim().to_string())
}
