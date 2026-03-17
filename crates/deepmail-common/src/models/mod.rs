//! Data models for the DeepMail platform.
//!
//! These structs represent the domain objects used across the API and worker
//! layers. They map to database tables but are not ORM-coupled — all DB
//! access uses explicit prepared statements.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Email ────────────────────────────────────────────────────────────────────

/// Represents a submitted email file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    pub id: String,
    pub original_name: String,
    pub quarantine_path: String,
    pub sha256_hash: String,
    pub file_size: i64,
    pub submitted_by: Option<String>,
    pub submitted_at: String,
    pub status: EmailStatus,
    pub current_stage: Option<String>,
    pub stage_started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
}

/// Processing status of an email — full state machine.
///
/// State transitions:
/// ```text
/// Queued → Processing → AnalyzingHeaders → ExtractingIocs
///   → UrlAnalysis (parallel) → AttachmentAnalysis (parallel)
///   → Scoring → Completed
///
/// Any state → Failed (on error)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmailStatus {
    Queued,
    Processing,
    AnalyzingHeaders,
    ExtractingIocs,
    UrlAnalysis,
    AttachmentAnalysis,
    Scoring,
    Completed,
    Failed,
}

impl std::fmt::Display for EmailStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailStatus::Queued => write!(f, "queued"),
            EmailStatus::Processing => write!(f, "processing"),
            EmailStatus::AnalyzingHeaders => write!(f, "analyzing_headers"),
            EmailStatus::ExtractingIocs => write!(f, "extracting_iocs"),
            EmailStatus::UrlAnalysis => write!(f, "url_analysis"),
            EmailStatus::AttachmentAnalysis => write!(f, "attachment_analysis"),
            EmailStatus::Scoring => write!(f, "scoring"),
            EmailStatus::Completed => write!(f, "completed"),
            EmailStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for EmailStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(EmailStatus::Queued),
            "processing" => Ok(EmailStatus::Processing),
            "analyzing_headers" => Ok(EmailStatus::AnalyzingHeaders),
            "extracting_iocs" => Ok(EmailStatus::ExtractingIocs),
            "url_analysis" => Ok(EmailStatus::UrlAnalysis),
            "attachment_analysis" => Ok(EmailStatus::AttachmentAnalysis),
            "scoring" => Ok(EmailStatus::Scoring),
            "completed" => Ok(EmailStatus::Completed),
            "failed" => Ok(EmailStatus::Failed),
            other => Err(format!("Unknown email status: {other}")),
        }
    }
}

impl EmailStatus {
    /// Validate that a state transition is allowed.
    pub fn can_transition_to(&self, next: &EmailStatus) -> bool {
        matches!(
            (self, next),
            // Normal forward progression
            (EmailStatus::Queued, EmailStatus::Processing)
                | (EmailStatus::Processing, EmailStatus::AnalyzingHeaders)
                | (EmailStatus::AnalyzingHeaders, EmailStatus::ExtractingIocs)
                | (EmailStatus::ExtractingIocs, EmailStatus::UrlAnalysis)
                | (EmailStatus::ExtractingIocs, EmailStatus::AttachmentAnalysis)
                | (EmailStatus::UrlAnalysis, EmailStatus::AttachmentAnalysis)
                | (EmailStatus::UrlAnalysis, EmailStatus::Scoring)
                | (EmailStatus::AttachmentAnalysis, EmailStatus::UrlAnalysis)
                | (EmailStatus::AttachmentAnalysis, EmailStatus::Scoring)
                | (EmailStatus::Scoring, EmailStatus::Completed)
                // Any state can transition to Failed
                | (_, EmailStatus::Failed)
        )
    }
}

// ─── Job Progress ─────────────────────────────────────────────────────────────

/// Tracks progress of an individual pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    pub id: String,
    pub email_id: String,
    pub stage: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub details: Option<String>,
}

// ─── Attachment ───────────────────────────────────────────────────────────────

/// Represents a file attached to an email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub email_id: String,
    pub filename: String,
    pub content_type: Option<String>,
    pub sha256_hash: String,
    pub file_size: i64,
    pub quarantine_path: String,
    pub entropy: Option<f64>,
    pub created_at: String,
}

// ─── IOC ──────────────────────────────────────────────────────────────────────

/// Type of Indicator of Compromise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::Ip => write!(f, "ip"),
            IocType::Domain => write!(f, "domain"),
            IocType::Url => write!(f, "url"),
            IocType::Md5 => write!(f, "md5"),
            IocType::Sha1 => write!(f, "sha1"),
            IocType::Sha256 => write!(f, "sha256"),
            IocType::Email => write!(f, "email"),
        }
    }
}

/// An IOC node in the threat intelligence graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocNode {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub first_seen: String,
    pub last_seen: String,
    pub metadata: Option<String>,
}

/// A relationship between two IOC nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRelation {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relation_type: String,
    pub email_id: Option<String>,
    pub created_at: String,
}

// ─── Analysis ─────────────────────────────────────────────────────────────────

/// Result of an analysis step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub id: String,
    pub email_id: String,
    pub result_type: String,
    pub data: String,
    pub threat_score: Option<f64>,
    pub confidence: Option<f64>,
    pub created_at: String,
}

// ─── Campaign ─────────────────────────────────────────────────────────────────

/// A cluster of related emails (campaign).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCluster {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ─── Threat Score ─────────────────────────────────────────────────────────────

/// Multi-dimensional threat score output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    /// Overall weighted score (0.0 - 100.0).
    pub total: f64,
    /// Confidence in the score (0.0 - 1.0).
    pub confidence: f64,
    /// Per-category breakdown.
    pub breakdown: ScoreBreakdown,
}

/// Per-category score breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    /// SPF/DKIM/DMARC failures, sender spoofing.
    pub identity: f64,
    /// Suspicious IPs, known-bad domains.
    pub infrastructure: f64,
    /// IOC density, phishing keywords.
    pub content: f64,
    /// High entropy files, suspicious types.
    pub attachment: f64,
}

// ─── API Response Types ───────────────────────────────────────────────────────

/// Response for a successful upload.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadResponse {
    pub email_id: String,
    pub job_id: String,
    pub status: String,
    pub message: String,
    /// True if this file was already analyzed (dedup hit).
    pub deduplicated: bool,
}

/// Response for health check.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub database: bool,
    pub redis: bool,
    pub timestamp: String,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Generate a new UUID v4 string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Get the current UTC timestamp as ISO 8601 string.
pub fn now_utc() -> String {
    Utc::now().to_rfc3339()
}
