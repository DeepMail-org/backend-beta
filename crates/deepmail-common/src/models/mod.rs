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
}

/// Processing status of an email.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmailStatus {
    Queued,
    Processing,
    Completed,
    Failed,
}

impl std::fmt::Display for EmailStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailStatus::Queued => write!(f, "queued"),
            EmailStatus::Processing => write!(f, "processing"),
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
            "completed" => Ok(EmailStatus::Completed),
            "failed" => Ok(EmailStatus::Failed),
            other => Err(format!("Unknown email status: {other}")),
        }
    }
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

// ─── API Response Types ───────────────────────────────────────────────────────

/// Response for a successful upload.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadResponse {
    pub email_id: String,
    pub job_id: String,
    pub status: String,
    pub message: String,
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
