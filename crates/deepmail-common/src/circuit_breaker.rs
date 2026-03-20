use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::config::CircuitBreakerConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: CircuitState,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    half_open_probes: u32,
}

#[derive(Clone)]
pub struct CircuitBreaker {
    name: String,
    cfg: CircuitBreakerConfig,
    inner: Arc<Mutex<Inner>>,
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>, cfg: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            cfg,
            inner: Arc::new(Mutex::new(Inner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                opened_at: None,
                half_open_probes: 0,
            })),
        }
    }

    pub async fn allow(&self) -> bool {
        let mut inner = self.inner.lock().await;
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(opened_at) = inner.opened_at {
                    if opened_at.elapsed() >= Duration::from_secs(self.cfg.cooldown_secs) {
                        inner.state = CircuitState::HalfOpen;
                        inner.half_open_probes = 0;
                        tracing::warn!(breaker = %self.name, "Circuit moved OPEN->HALF_OPEN");
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if inner.half_open_probes < self.cfg.half_open_max_probes {
                    inner.half_open_probes += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub async fn on_success(&self) {
        let mut inner = self.inner.lock().await;
        inner.consecutive_failures = 0;
        if inner.state != CircuitState::Closed {
            inner.state = CircuitState::Closed;
            inner.opened_at = None;
            inner.half_open_probes = 0;
            tracing::info!(breaker = %self.name, "Circuit moved to CLOSED");
        }
    }

    pub async fn on_failure(&self) {
        let mut inner = self.inner.lock().await;
        inner.consecutive_failures += 1;
        if inner.state == CircuitState::HalfOpen
            || inner.consecutive_failures >= self.cfg.failure_threshold
        {
            inner.state = CircuitState::Open;
            inner.opened_at = Some(Instant::now());
            tracing::warn!(breaker = %self.name, failures = inner.consecutive_failures, "Circuit moved to OPEN");
        }
    }
}
