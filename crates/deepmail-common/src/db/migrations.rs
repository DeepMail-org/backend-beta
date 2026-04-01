//! Database schema migrations for DeepMail.
//!
//! Migrations are applied in order and tracked via a `_migrations` table.
//! Each migration is idempotent — it checks before applying.
//!
//! # Security
//! - All DDL uses parameterized patterns where applicable
//! - Indexes are created for common query patterns
//! - Timestamps use ISO 8601 format

use rusqlite::Connection;

use crate::errors::DeepMailError;

/// A single migration with a unique name and SQL statements.
struct Migration {
    name: &'static str,
    sql: &'static str,
}

/// All migrations in order. Append new migrations to the end — never modify existing ones.
const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "001_create_migrations_table",
        sql: "
            CREATE TABLE IF NOT EXISTS _migrations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL UNIQUE,
                applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
        ",
    },
    Migration {
        name: "002_create_users",
        sql: "
            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY NOT NULL,
                username        TEXT NOT NULL UNIQUE,
                email           TEXT NOT NULL UNIQUE,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'analyst',
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        ",
    },
    Migration {
        name: "003_create_emails",
        sql: "
            CREATE TABLE IF NOT EXISTS emails (
                id              TEXT PRIMARY KEY NOT NULL,
                original_name   TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                sha256_hash     TEXT NOT NULL,
                file_size       INTEGER NOT NULL,
                submitted_by    TEXT,
                submitted_at    TEXT NOT NULL DEFAULT (datetime('now')),
                status          TEXT NOT NULL DEFAULT 'queued',
                FOREIGN KEY (submitted_by) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_emails_submitted_at ON emails(submitted_at);
            CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
            CREATE INDEX IF NOT EXISTS idx_emails_sha256 ON emails(sha256_hash);
        ",
    },
    Migration {
        name: "004_create_attachments",
        sql: "
            CREATE TABLE IF NOT EXISTS attachments (
                id              TEXT PRIMARY KEY NOT NULL,
                email_id        TEXT NOT NULL,
                filename        TEXT NOT NULL,
                content_type    TEXT,
                sha256_hash     TEXT NOT NULL,
                file_size       INTEGER NOT NULL,
                quarantine_path TEXT NOT NULL,
                entropy         REAL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);
            CREATE INDEX IF NOT EXISTS idx_attachments_sha256 ON attachments(sha256_hash);
        ",
    },
    Migration {
        name: "005_create_ioc_nodes",
        sql: "
            CREATE TABLE IF NOT EXISTS ioc_nodes (
                id          TEXT PRIMARY KEY NOT NULL,
                ioc_type    TEXT NOT NULL,
                value       TEXT NOT NULL,
                first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
                metadata    TEXT,
                UNIQUE(ioc_type, value)
            );
            CREATE INDEX IF NOT EXISTS idx_ioc_nodes_type ON ioc_nodes(ioc_type);
            CREATE INDEX IF NOT EXISTS idx_ioc_nodes_value ON ioc_nodes(value);
        ",
    },
    Migration {
        name: "006_create_ioc_relations",
        sql: "
            CREATE TABLE IF NOT EXISTS ioc_relations (
                id              TEXT PRIMARY KEY NOT NULL,
                source_id       TEXT NOT NULL,
                target_id       TEXT NOT NULL,
                relation_type   TEXT NOT NULL,
                email_id        TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (source_id) REFERENCES ioc_nodes(id) ON DELETE CASCADE,
                FOREIGN KEY (target_id) REFERENCES ioc_nodes(id) ON DELETE CASCADE,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ioc_relations_source ON ioc_relations(source_id);
            CREATE INDEX IF NOT EXISTS idx_ioc_relations_target ON ioc_relations(target_id);
            CREATE INDEX IF NOT EXISTS idx_ioc_relations_email ON ioc_relations(email_id);
        ",
    },
    Migration {
        name: "007_create_analysis_results",
        sql: "
            CREATE TABLE IF NOT EXISTS analysis_results (
                id              TEXT PRIMARY KEY NOT NULL,
                email_id        TEXT NOT NULL,
                result_type     TEXT NOT NULL,
                data            TEXT NOT NULL,
                threat_score    REAL,
                confidence      REAL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_analysis_results_email ON analysis_results(email_id);
            CREATE INDEX IF NOT EXISTS idx_analysis_results_type ON analysis_results(result_type);
        ",
    },
    Migration {
        name: "008_create_campaign_clusters",
        sql: "
            CREATE TABLE IF NOT EXISTS campaign_clusters (
                id              TEXT PRIMARY KEY NOT NULL,
                name            TEXT,
                description     TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS campaign_members (
                cluster_id  TEXT NOT NULL,
                email_id    TEXT NOT NULL,
                similarity  REAL,
                added_at    TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (cluster_id, email_id),
                FOREIGN KEY (cluster_id) REFERENCES campaign_clusters(id) ON DELETE CASCADE,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );
        ",
    },
    Migration {
        name: "009_create_sandbox_reports",
        sql: "
            CREATE TABLE IF NOT EXISTS sandbox_reports (
                id              TEXT PRIMARY KEY NOT NULL,
                attachment_id   TEXT NOT NULL,
                sandbox_type    TEXT NOT NULL,
                verdict         TEXT,
                report_data     TEXT,
                submitted_at    TEXT NOT NULL DEFAULT (datetime('now')),
                completed_at    TEXT,
                FOREIGN KEY (attachment_id) REFERENCES attachments(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_sandbox_reports_attachment ON sandbox_reports(attachment_id);
        ",
    },
    Migration {
        name: "010_create_audit_logs",
        sql: "
            CREATE TABLE IF NOT EXISTS audit_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
                user_id     TEXT,
                action      TEXT NOT NULL,
                resource    TEXT NOT NULL,
                details     TEXT,
                ip_address  TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
        ",
    },
    Migration {
        name: "011_add_job_progress_to_emails",
        sql: "
            ALTER TABLE emails ADD COLUMN current_stage TEXT;
            ALTER TABLE emails ADD COLUMN stage_started_at TEXT;
            ALTER TABLE emails ADD COLUMN completed_at TEXT;
            ALTER TABLE emails ADD COLUMN error_message TEXT;
        ",
    },
    Migration {
        name: "012_create_job_progress",
        sql: "
            CREATE TABLE IF NOT EXISTS job_progress (
                id              TEXT PRIMARY KEY NOT NULL,
                email_id        TEXT NOT NULL,
                stage           TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'started',
                started_at      TEXT NOT NULL DEFAULT (datetime('now')),
                completed_at    TEXT,
                details         TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_job_progress_email ON job_progress(email_id);
            CREATE INDEX IF NOT EXISTS idx_job_progress_stage ON job_progress(stage);
        ",
    },
    Migration {
        name: "013_add_performance_indexes",
        sql: "
            -- Composite index for audit log queries by resource + time window
            CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_timestamp
                ON audit_logs(resource, timestamp);

            -- Composite index for campaign membership lookups by email
            CREATE INDEX IF NOT EXISTS idx_campaign_members_email
                ON campaign_members(email_id, cluster_id);

            -- Composite index for analysis results ordered by time
            CREATE INDEX IF NOT EXISTS idx_analysis_results_email_type
                ON analysis_results(email_id, result_type, created_at);

            -- Covering index for deduplication check path
            CREATE INDEX IF NOT EXISTS idx_emails_sha256_status
                ON emails(sha256_hash, status);
        ",
    },
    Migration {
        name: "014_expand_sandbox_reports",
        sql: "
            ALTER TABLE sandbox_reports ADD COLUMN email_id TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN url TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN final_url TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN redirects TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN network_calls TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN suspicious_behavior TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN execution_time_ms INTEGER;
            ALTER TABLE sandbox_reports ADD COLUMN status TEXT DEFAULT 'completed';
            ALTER TABLE sandbox_reports ADD COLUMN error_message TEXT;

            CREATE INDEX IF NOT EXISTS idx_sandbox_reports_email_id ON sandbox_reports(email_id);
            CREATE INDEX IF NOT EXISTS idx_sandbox_reports_status ON sandbox_reports(status);
            CREATE INDEX IF NOT EXISTS idx_sandbox_reports_submitted_at ON sandbox_reports(submitted_at);
        ",
    },
    Migration {
        name: "015_add_enterprise_tenancy_observability",
        sql: "
            ALTER TABLE emails ADD COLUMN reused_from_email_id TEXT;
            ALTER TABLE emails ADD COLUMN trace_id TEXT;

            CREATE TABLE IF NOT EXISTS user_quotas (
                user_id                  TEXT PRIMARY KEY NOT NULL,
                uploads_per_day          INTEGER NOT NULL,
                sandbox_executions_per_day INTEGER NOT NULL,
                updated_at               TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS usage_counters (
                id          TEXT PRIMARY KEY NOT NULL,
                user_id     TEXT NOT NULL,
                metric      TEXT NOT NULL,
                day_bucket  TEXT NOT NULL,
                count       INTEGER NOT NULL DEFAULT 0,
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_id, metric, day_bucket),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_usage_counters_user_metric_day
                ON usage_counters(user_id, metric, day_bucket);

            CREATE TABLE IF NOT EXISTS result_reuse_index (
                id              TEXT PRIMARY KEY NOT NULL,
                key_type        TEXT NOT NULL,
                key_value       TEXT NOT NULL,
                result_email_id TEXT,
                result_data     TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at      TEXT,
                UNIQUE(key_type, key_value)
            );
            CREATE INDEX IF NOT EXISTS idx_result_reuse_lookup
                ON result_reuse_index(key_type, key_value, expires_at);
            CREATE INDEX IF NOT EXISTS idx_emails_submitted_by_status
                ON emails(submitted_by, status, submitted_at);
        ",
    },
    Migration {
        name: "016_add_production_hardening",
        sql: "
            -- Soft-delete lifecycle columns on emails
            ALTER TABLE emails ADD COLUMN archived_at TEXT;
            ALTER TABLE emails ADD COLUMN deleted_at TEXT;
            ALTER TABLE emails ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete lifecycle columns on attachments
            ALTER TABLE attachments ADD COLUMN archived_at TEXT;
            ALTER TABLE attachments ADD COLUMN deleted_at TEXT;
            ALTER TABLE attachments ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete lifecycle columns on analysis_results
            ALTER TABLE analysis_results ADD COLUMN archived_at TEXT;
            ALTER TABLE analysis_results ADD COLUMN deleted_at TEXT;
            ALTER TABLE analysis_results ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Soft-delete lifecycle columns on sandbox_reports
            ALTER TABLE sandbox_reports ADD COLUMN archived_at TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN deleted_at TEXT;
            ALTER TABLE sandbox_reports ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;

            -- Indexes on emails soft-delete columns
            CREATE INDEX IF NOT EXISTS idx_emails_archived_at ON emails(archived_at);
            CREATE INDEX IF NOT EXISTS idx_emails_deleted_at ON emails(deleted_at);
            CREATE INDEX IF NOT EXISTS idx_emails_is_deleted ON emails(is_deleted);

            -- User flagging columns
            ALTER TABLE users ADD COLUMN is_flagged INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE users ADD COLUMN flagged_at TEXT;
            ALTER TABLE users ADD COLUMN flagged_reason TEXT;

            -- Abuse events table
            CREATE TABLE IF NOT EXISTS abuse_events (
                id            TEXT PRIMARY KEY,
                user_id       TEXT NOT NULL,
                event_type    TEXT NOT NULL,
                severity      TEXT NOT NULL DEFAULT 'critical',
                details       TEXT,
                auto_flagged  INTEGER NOT NULL DEFAULT 0,
                reviewed_by   TEXT,
                reviewed_at   TEXT,
                created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_abuse_events_user_id
                ON abuse_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_abuse_events_event_type_created_at
                ON abuse_events(event_type, created_at);
            CREATE INDEX IF NOT EXISTS idx_abuse_events_severity_reviewed_at
                ON abuse_events(severity, reviewed_at);
        ",
    },
    Migration {
        name: "017_add_auth_token_security",
        sql: "
            CREATE TABLE IF NOT EXISTS auth_otp_codes (
                id              TEXT PRIMARY KEY,
                username        TEXT NOT NULL,
                email           TEXT NOT NULL,
                phone           TEXT NOT NULL,
                code_hash       TEXT NOT NULL,
                issued_by       TEXT,
                issued_at       TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at      TEXT NOT NULL,
                used_at         TEXT,
                attempts        INTEGER NOT NULL DEFAULT 0,
                lockout_until   TEXT,
                max_attempts    INTEGER NOT NULL DEFAULT 5,
                requester_ip    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_auth_otp_lookup
                ON auth_otp_codes(username, email, phone, expires_at, used_at);
            CREATE INDEX IF NOT EXISTS idx_auth_otp_lockout
                ON auth_otp_codes(lockout_until);

            CREATE TABLE IF NOT EXISTS auth_tokens (
                jti                 TEXT PRIMARY KEY,
                user_id             TEXT NOT NULL,
                token_hash          TEXT NOT NULL,
                role                TEXT NOT NULL,
                issued_at           TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at          TEXT NOT NULL,
                revoked_at          TEXT,
                status              TEXT NOT NULL DEFAULT 'active',
                device_fingerprint  TEXT,
                first_seen_ip       TEXT,
                last_seen_at        TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_status
                ON auth_tokens(user_id, status, expires_at);
            CREATE INDEX IF NOT EXISTS idx_auth_tokens_device
                ON auth_tokens(device_fingerprint);

            CREATE TABLE IF NOT EXISTS auth_audit (
                id              TEXT PRIMARY KEY,
                event_type      TEXT NOT NULL,
                user_id         TEXT,
                jti             TEXT,
                source_ip       TEXT,
                detail          TEXT,
                immutable_hash  TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_auth_audit_created_at
                ON auth_audit(created_at);
             CREATE INDEX IF NOT EXISTS idx_auth_audit_event_user
                 ON auth_audit(event_type, user_id, created_at);
        ",
    },
    Migration {
        name: "018_add_ip_geo_intel_cache",
        sql: "
            CREATE TABLE IF NOT EXISTS ip_geo_intel (
                ip                  TEXT PRIMARY KEY,
                lat                 REAL NOT NULL,
                lon                 REAL NOT NULL,
                country             TEXT NOT NULL,
                city                TEXT,
                region              TEXT,
                asn                 INTEGER,
                org                 TEXT,
                abuse_confidence    INTEGER,
                is_tor              INTEGER NOT NULL DEFAULT 0,
                is_proxy            INTEGER NOT NULL DEFAULT 0,
                is_hosting          INTEGER NOT NULL DEFAULT 0,
                confidence_score    REAL NOT NULL DEFAULT 0.0,
                source              TEXT NOT NULL,
                provider_version    TEXT,
                first_seen_at       TEXT NOT NULL DEFAULT (datetime('now')),
                last_resolved_at    TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ip_geo_intel_expires_at
                ON ip_geo_intel(expires_at);
            CREATE INDEX IF NOT EXISTS idx_ip_geo_intel_country
                ON ip_geo_intel(country);
            CREATE INDEX IF NOT EXISTS idx_ip_geo_intel_confidence
                ON ip_geo_intel(confidence_score DESC);
        ",
    },
    Migration {
        name: "019_add_intel_feedback_and_calibration",
        sql: "
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                id          TEXT PRIMARY KEY,
                email_id    TEXT NOT NULL,
                verdict     TEXT NOT NULL,
                note        TEXT,
                feedback_by TEXT,
                feedback_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_analyst_feedback_email
                ON analyst_feedback(email_id, feedback_at);
            CREATE INDEX IF NOT EXISTS idx_analyst_feedback_verdict
                ON analyst_feedback(verdict, feedback_at);

            CREATE TABLE IF NOT EXISTS intel_calibration (
                id                          TEXT PRIMARY KEY,
                window_days                 INTEGER NOT NULL,
                sample_count                INTEGER NOT NULL,
                false_positive_count        INTEGER NOT NULL,
                confirmed_malicious_count   INTEGER NOT NULL,
                score_multiplier            REAL NOT NULL,
                created_at                  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_intel_calibration_created
                ON intel_calibration(created_at DESC);
        ",
    },
];

pub const MIGRATION_COUNT: u32 = (MIGRATIONS.len() - 1) as u32;

/// Run all pending migrations in order.
pub fn run_migrations(conn: &Connection) -> Result<(), DeepMailError> {
    // First, ensure the migrations tracking table exists
    conn.execute_batch(MIGRATIONS[0].sql)
        .map_err(|e| DeepMailError::Database(format!("Failed to create migrations table: {e}")))?;

    for migration in MIGRATIONS.iter().skip(1) {
        let already_applied: bool = {
            let mut stmt = conn
                .prepare("SELECT COUNT(*) FROM _migrations WHERE name = ?1")
                .map_err(|e| {
                    DeepMailError::Database(format!("Failed to check migration status: {e}"))
                })?;
            stmt.query_row(rusqlite::params![migration.name], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count > 0)
            .map_err(|e| {
                DeepMailError::Database(format!("Failed to query migration status: {e}"))
            })?
        };

        if already_applied {
            tracing::debug!(
                migration = migration.name,
                "Migration already applied, skipping"
            );
            continue;
        }

        tracing::info!(migration = migration.name, "Applying migration");

        conn.execute_batch(migration.sql).map_err(|e| {
            DeepMailError::Database(format!(
                "Failed to apply migration '{}': {e}",
                migration.name
            ))
        })?;

        conn.execute(
            "INSERT INTO _migrations (name) VALUES (?1)",
            rusqlite::params![migration.name],
        )
        .map_err(|e| {
            DeepMailError::Database(format!(
                "Failed to record migration '{}': {e}",
                migration.name
            ))
        })?;

        tracing::info!(migration = migration.name, "Migration applied successfully");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_rollback_smoke() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        run_migrations(&conn).expect("run migrations");

        let tx = conn.unchecked_transaction().expect("start tx");
        tx.execute(
            "INSERT INTO intel_calibration (
                id, window_days, sample_count, false_positive_count,
                confirmed_malicious_count, score_multiplier, created_at
            ) VALUES (?1, 30, 10, 2, 8, 1.05, datetime('now'))",
            rusqlite::params!["smoke-row"],
        )
        .expect("insert calibration row");
        tx.rollback().expect("rollback tx");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM intel_calibration WHERE id = 'smoke-row'",
                [],
                |row| row.get(0),
            )
            .expect("count calibration rows");
        assert_eq!(count, 0);
    }
}
