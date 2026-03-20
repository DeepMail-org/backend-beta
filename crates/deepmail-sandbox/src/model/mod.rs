use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlDetonationTask {
    pub email_id: String,
    pub url: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDetonationTask {
    pub email_id: String,
    pub file_path: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxJobKind {
    Url,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxJob {
    pub id: String,
    pub email_id: String,
    pub kind: SandboxJobKind,
    pub target: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionHandle {
    pub task_id: String,
    pub backend: String,
    pub runtime_id: String,
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStatus {
    Running,
    Completed,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCall {
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub email_id: String,
    pub url: Option<String>,
    pub final_url: Option<String>,
    pub redirects: Vec<String>,
    pub network_calls: Vec<NetworkCall>,
    pub suspicious_behavior: Vec<String>,
    pub execution_time_ms: u64,
    pub status: SandboxStatus,
    pub error_message: Option<String>,
}
