use redis::aio::MultiplexedConnection;

use crate::config::AbuseConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;
use crate::models::{new_id, now_utc};

const ABUSE_VELOCITY_SCRIPT: &str = include_str!("redis_scripts/abuse_velocity.lua");

pub async fn check_velocity(
    conn: &mut MultiplexedConnection,
    user_id: &str,
    action: &str,
    threshold: u32,
    window_ms: u64,
) -> Result<bool, DeepMailError> {
    let key = format!("deepmail:abuse:{action}:{user_id}");
    let now_ms = chrono::Utc::now().timestamp_millis();

    let values: Vec<redis::Value> = redis::Script::new(ABUSE_VELOCITY_SCRIPT)
        .key(key)
        .arg(now_ms)
        .arg(window_ms as i64)
        .arg(threshold as i64)
        .invoke_async(conn)
        .await
        .map_err(|e| DeepMailError::Redis(format!("Abuse velocity script failed: {e}")))?;

    if values.len() != 2 {
        return Err(DeepMailError::Redis(
            "Abuse velocity script returned unexpected payload".to_string(),
        ));
    }

    let exceeded = match &values[1] {
        redis::Value::Int(i) => *i == 1,
        redis::Value::Data(bytes) => String::from_utf8_lossy(bytes) == "1",
        _ => false,
    };

    Ok(exceeded)
}

pub async fn is_user_flagged(
    pool: &DbPool,
    conn: &mut MultiplexedConnection,
    user_id: &str,
) -> Result<bool, DeepMailError> {
    use redis::AsyncCommands;

    let cache_key = format!("deepmail:abuse:flagged:{user_id}");
    let cached: Option<String> = conn.get(&cache_key).await.ok();
    if let Some(val) = cached {
        return Ok(val == "1");
    }

    let db = pool.get()?;
    let flagged = db
        .query_row(
            "SELECT is_flagged FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|v| v == 1)
        .unwrap_or(false);

    let _: Result<(), _> = conn
        .set_ex(&cache_key, if flagged { "1" } else { "0" }, 60)
        .await;

    Ok(flagged)
}

pub fn flag_user(pool: &DbPool, user_id: &str, reason: &str) -> Result<(), DeepMailError> {
    let db = pool.get()?;
    db.execute(
        "UPDATE users SET is_flagged = 1, flagged_at = ?1, flagged_reason = ?2 WHERE id = ?3",
        rusqlite::params![now_utc(), reason, user_id],
    )?;
    Ok(())
}

pub fn unflag_user(pool: &DbPool, user_id: &str) -> Result<(), DeepMailError> {
    let db = pool.get()?;
    db.execute(
        "UPDATE users SET is_flagged = 0, flagged_at = NULL, flagged_reason = NULL WHERE id = ?1",
        rusqlite::params![user_id],
    )?;
    Ok(())
}

pub fn record_abuse_event(
    pool: &DbPool,
    user_id: &str,
    event_type: &str,
    severity: &str,
    details: Option<&str>,
    auto_flagged: bool,
) -> Result<String, DeepMailError> {
    let id = new_id();
    let db = pool.get()?;
    db.execute(
        "INSERT INTO abuse_events (id, user_id, event_type, severity, details, auto_flagged)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            id,
            user_id,
            event_type,
            severity,
            details,
            auto_flagged as i64
        ],
    )?;
    Ok(id)
}

pub fn run_pattern_scan(pool: &DbPool, cfg: &AbuseConfig) -> Result<(), DeepMailError> {
    let db = pool.get()?;
    let threshold = cfg.repeated_malicious_hash_threshold as i64;

    let mut stmt = db.prepare(
        "SELECT submitted_by, sha256_hash, COUNT(*)
         FROM emails
         WHERE submitted_by IS NOT NULL
           AND submitted_at > datetime('now', '-1 day')
           AND is_deleted = 0
         GROUP BY submitted_by, sha256_hash
         HAVING COUNT(*) >= ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![threshold], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    for row in rows.flatten() {
        let (user_id, hash, count) = row;
        let high_score = db
            .query_row(
                "SELECT COUNT(*)
                 FROM analysis_results ar
                 JOIN emails e ON e.id = ar.email_id
                 WHERE e.sha256_hash = ?1 AND ar.threat_score >= 80.0",
                rusqlite::params![hash],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v > 0)
            .unwrap_or(false);
        if high_score {
            let details = format!("Repeated malicious hash upload: hash={hash}, count={count}");
            let _ = flag_user(pool, &user_id, &details);
            let _ = record_abuse_event(
                pool,
                &user_id,
                "repeated_malicious",
                "critical",
                Some(&details),
                true,
            );
        }
    }

    let mut stmt = db.prepare(
        "SELECT user_id, count
         FROM usage_counters
         WHERE metric = 'sandbox_executions'
           AND day_bucket = ?1
           AND count >= ?2",
    )?;
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let rows = stmt.query_map(
        rusqlite::params![day, cfg.sandbox_harvest_threshold as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?;
    for row in rows.flatten() {
        let (user_id, count) = row;
        let details = format!("Sandbox harvest detected: count={count}");
        let _ = flag_user(pool, &user_id, &details);
        let _ = record_abuse_event(
            pool,
            &user_id,
            "sandbox_harvest",
            "critical",
            Some(&details),
            true,
        );
    }

    Ok(())
}
