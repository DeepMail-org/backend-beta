use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::sync::RwLock;

use crate::error::SandboxError;
use crate::executor::SandboxExecutor;
use crate::model::{
    ExecutionHandle, FileDetonationTask, NetworkCall, SandboxReport, SandboxStatus,
    UrlDetonationTask,
};

#[derive(Debug, Clone)]
pub struct DockerSandboxConfig {
    pub image: String,
    pub network: String,
    pub seccomp_profile: String,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub pids_limit: u32,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DockerSandboxExecutor {
    config: DockerSandboxConfig,
    reports: Arc<RwLock<std::collections::HashMap<String, SandboxReport>>>,
}

impl DockerSandboxExecutor {
    pub fn new(config: DockerSandboxConfig) -> Self {
        Self {
            config,
            reports: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn base_args(&self) -> Vec<String> {
        vec![
            "run".to_string(),
            "--rm".to_string(),
            "--read-only".to_string(),
            "--cap-drop=ALL".to_string(),
            "--security-opt=no-new-privileges".to_string(),
            format!("--security-opt=seccomp={}", self.config.seccomp_profile),
            format!("--cpus={}", self.config.cpu_limit),
            format!("--memory={}", self.config.memory_limit),
            format!("--pids-limit={}", self.config.pids_limit),
            "--tmpfs".to_string(),
            "/tmp:rw,noexec,nosuid,size=64m".to_string(),
            format!("--network={}", self.config.network),
        ]
    }

    async fn execute_target(
        &self,
        mode: &str,
        target: &str,
        email_id: &str,
        timeout_ms: u64,
    ) -> Result<ExecutionHandle, SandboxError> {
        let started_at = chrono::Utc::now().to_rfc3339();
        let started = std::time::Instant::now();
        let task_id = uuid::Uuid::new_v4().to_string();
        let runtime_id = format!("sandbox-{}", &task_id[..12]);

        let mut args = self.base_args();
        args.extend([
            "--name".to_string(),
            runtime_id.clone(),
            self.config.image.clone(),
            "--mode".to_string(),
            mode.to_string(),
            "--target".to_string(),
            target.to_string(),
            "--email-id".to_string(),
            email_id.to_string(),
            "--timeout-ms".to_string(),
            timeout_ms.to_string(),
        ]);

        let output = Command::new("docker")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SandboxError::Execution(format!("docker invocation failed: {e}")))?;

        if !output.status.success() {
            return Err(SandboxError::Execution(format!(
                "docker sandbox run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let execution_time_ms = started.elapsed().as_millis() as u64;
        let report = parse_report_from_stdout(email_id, target, &output.stdout, execution_time_ms);
        self.reports.write().await.insert(task_id.clone(), report);

        Ok(ExecutionHandle {
            task_id,
            backend: "docker".to_string(),
            runtime_id,
            started_at,
        })
    }
}

#[async_trait]
impl SandboxExecutor for DockerSandboxExecutor {
    async fn execute_url(&self, task: UrlDetonationTask) -> Result<ExecutionHandle, SandboxError> {
        self.execute_target("url", &task.url, &task.email_id, task.timeout_ms)
            .await
    }

    async fn execute_file(
        &self,
        task: FileDetonationTask,
    ) -> Result<ExecutionHandle, SandboxError> {
        self.execute_target("file", &task.file_path, &task.email_id, task.timeout_ms)
            .await
    }

    async fn get_report(&self, handle: &ExecutionHandle) -> Result<SandboxReport, SandboxError> {
        self.reports
            .read()
            .await
            .get(&handle.task_id)
            .cloned()
            .ok_or_else(|| SandboxError::Execution("sandbox report not found".to_string()))
    }
}

impl DockerSandboxExecutor {
    pub fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }
}

pub fn timed_out_report(email_id: &str, target: &str, execution_time_ms: u64) -> SandboxReport {
    SandboxReport {
        email_id: email_id.to_string(),
        url: Some(target.to_string()),
        final_url: None,
        redirects: Vec::new(),
        network_calls: Vec::new(),
        suspicious_behavior: vec!["execution_timeout".to_string()],
        execution_time_ms,
        status: SandboxStatus::TimedOut,
        error_message: Some("sandbox execution timed out".to_string()),
    }
}

fn parse_report_from_stdout(
    email_id: &str,
    target: &str,
    stdout: &[u8],
    execution_time_ms: u64,
) -> SandboxReport {
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(stdout);
    if let Ok(v) = parsed {
        let redirects = v
            .get("redirects")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let suspicious_behavior = v
            .get("suspicious_behavior")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let network_calls = v
            .get("network_calls")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| {
                        Some(NetworkCall {
                            method: entry.get("method")?.as_str()?.to_string(),
                            url: entry.get("url")?.as_str()?.to_string(),
                            status: entry
                                .get("status")
                                .and_then(|s| s.as_u64())
                                .map(|n| n as u16),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        return SandboxReport {
            email_id: email_id.to_string(),
            url: Some(target.to_string()),
            final_url: v
                .get("final_url")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .or(Some(target.to_string())),
            redirects,
            network_calls,
            suspicious_behavior,
            execution_time_ms,
            status: SandboxStatus::Completed,
            error_message: None,
        };
    }

    SandboxReport {
        email_id: email_id.to_string(),
        url: Some(target.to_string()),
        final_url: Some(target.to_string()),
        redirects: Vec::new(),
        network_calls: Vec::new(),
        suspicious_behavior: Vec::new(),
        execution_time_ms,
        status: SandboxStatus::Completed,
        error_message: None,
    }
}
