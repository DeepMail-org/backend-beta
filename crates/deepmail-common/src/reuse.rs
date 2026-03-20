use chrono::{Duration, Utc};

use crate::db::DbPool;
use crate::errors::DeepMailError;
use crate::models::new_id;

#[derive(Debug, Clone)]
pub struct ReuseEntry {
    pub result_email_id: Option<String>,
    pub result_data: Option<String>,
}

pub fn lookup_reuse_entry(
    pool: &DbPool,
    key_type: &str,
    key_value: &str,
) -> Result<Option<ReuseEntry>, DeepMailError> {
    let conn = pool.get()?;
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT result_email_id, result_data
         FROM result_reuse_index
         WHERE key_type = ?1 AND key_value = ?2 AND (expires_at IS NULL OR expires_at > ?3)",
    )?;

    let hit = stmt
        .query_row(rusqlite::params![key_type, key_value, now], |row| {
            Ok(ReuseEntry {
                result_email_id: row.get(0)?,
                result_data: row.get(1)?,
            })
        })
        .ok();

    Ok(hit)
}

pub fn store_reuse_entry(
    pool: &DbPool,
    key_type: &str,
    key_value: &str,
    result_email_id: Option<&str>,
    result_data: Option<&str>,
    ttl_secs: u64,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let now = Utc::now();
    let expires = now + Duration::seconds(ttl_secs as i64);
    conn.execute(
        "INSERT INTO result_reuse_index
         (id, key_type, key_value, result_email_id, result_data, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(key_type, key_value)
         DO UPDATE SET
            result_email_id = excluded.result_email_id,
            result_data = excluded.result_data,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at",
        rusqlite::params![
            new_id(),
            key_type,
            key_value,
            result_email_id,
            result_data,
            now.to_rfc3339(),
            expires.to_rfc3339(),
        ],
    )?;
    Ok(())
}
