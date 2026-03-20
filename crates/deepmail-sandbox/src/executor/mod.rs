pub mod docker;

use async_trait::async_trait;

use crate::error::SandboxError;
use crate::model::{ExecutionHandle, FileDetonationTask, SandboxReport, UrlDetonationTask};

#[async_trait]
pub trait SandboxExecutor: Send + Sync {
    async fn execute_url(&self, task: UrlDetonationTask) -> Result<ExecutionHandle, SandboxError>;
    async fn execute_file(&self, task: FileDetonationTask)
        -> Result<ExecutionHandle, SandboxError>;
    async fn get_report(&self, handle: &ExecutionHandle) -> Result<SandboxReport, SandboxError>;
}
