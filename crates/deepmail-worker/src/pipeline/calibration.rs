use chrono::{Duration, Utc};

use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::ThreatScore;

pub fn run_calibration_job(pool: &DbPool) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let cutoff = (Utc::now() - Duration::days(30)).to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT
            SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END) AS false_pos,
            SUM(CASE WHEN verdict = 'confirmed_malicious' THEN 1 ELSE 0 END) AS confirmed
         FROM analyst_feedback
         WHERE feedback_at >= ?1",
    )?;

    let (false_pos, confirmed): (i64, i64) = stmt.query_row(rusqlite::params![cutoff], |row| {
        Ok((
            row.get::<_, Option<i64>>(0)?.unwrap_or(0),
            row.get::<_, Option<i64>>(1)?.unwrap_or(0),
        ))
    })?;

    let total = (false_pos + confirmed).max(1) as f64;
    let precision = confirmed as f64 / total;
    let multiplier = (0.75 + precision * 0.5).clamp(0.75, 1.25);

    conn.execute(
        "INSERT INTO intel_calibration (id, window_days, sample_count, false_positive_count,
                                        confirmed_malicious_count, score_multiplier, created_at)
         VALUES (?1, 30, ?2, ?3, ?4, ?5, datetime('now'))",
        rusqlite::params![
            deepmail_common::models::new_id(),
            false_pos + confirmed,
            false_pos,
            confirmed,
            multiplier,
        ],
    )?;

    tracing::info!(
        sample_count = false_pos + confirmed,
        false_positive_count = false_pos,
        confirmed_count = confirmed,
        score_multiplier = multiplier,
        "Threat intel calibration completed"
    );

    Ok(())
}

pub fn apply_latest_calibration(
    pool: &DbPool,
    score: &mut ThreatScore,
) -> Result<(), DeepMailError> {
    let conn = pool.get()?;
    let multiplier: Option<f64> = conn
        .query_row(
            "SELECT score_multiplier FROM intel_calibration ORDER BY created_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    if let Some(multiplier) = multiplier {
        score.total = (score.total * multiplier).clamp(0.0, 100.0);
        score.breakdown.infrastructure =
            (score.breakdown.infrastructure * multiplier).clamp(0.0, 100.0);
        score.confidence = (score.confidence * (0.9 + multiplier / 10.0)).clamp(0.0, 1.0);
    }

    Ok(())
}
