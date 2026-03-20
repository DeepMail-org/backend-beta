use chrono::Utc;

use crate::db::DbPool;
use crate::errors::DeepMailError;
use crate::models::new_id;

#[derive(Debug, Clone)]
pub struct QuotaDecision {
    pub allowed: bool,
    pub used: i64,
    pub limit: i64,
}

pub fn enforce_daily_quota(
    pool: &DbPool,
    user_id: &str,
    metric: &str,
    default_limit: i64,
) -> Result<QuotaDecision, DeepMailError> {
    let conn = pool.get()?;
    let bucket = Utc::now().format("%Y-%m-%d").to_string();

    let limit: i64 = match metric {
        "uploads" => conn
            .query_row(
                "SELECT uploads_per_day FROM user_quotas WHERE user_id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )
            .unwrap_or(default_limit),
        "sandbox_executions" => conn
            .query_row(
                "SELECT sandbox_executions_per_day FROM user_quotas WHERE user_id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )
            .unwrap_or(default_limit),
        _ => default_limit,
    };

    conn.execute(
        "INSERT INTO usage_counters (id, user_id, metric, day_bucket, count, updated_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5)
         ON CONFLICT(user_id, metric, day_bucket) DO NOTHING",
        rusqlite::params![new_id(), user_id, metric, bucket, Utc::now().to_rfc3339()],
    )?;

    let current: i64 = conn.query_row(
        "SELECT count FROM usage_counters WHERE user_id = ?1 AND metric = ?2 AND day_bucket = ?3",
        rusqlite::params![user_id, metric, bucket],
        |row| row.get(0),
    )?;

    if current >= limit {
        return Ok(QuotaDecision {
            allowed: false,
            used: current,
            limit,
        });
    }

    conn.execute(
        "UPDATE usage_counters
         SET count = count + 1, updated_at = ?1
         WHERE user_id = ?2 AND metric = ?3 AND day_bucket = ?4",
        rusqlite::params![Utc::now().to_rfc3339(), user_id, metric, bucket],
    )?;

    Ok(QuotaDecision {
        allowed: true,
        used: current + 1,
        limit,
    })
}
