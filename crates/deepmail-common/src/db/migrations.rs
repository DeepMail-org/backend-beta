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
];

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
            stmt.query_row(rusqlite::params![migration.name], |row| row.get::<_, i64>(0))
                .map(|count| count > 0)
                .map_err(|e| {
                    DeepMailError::Database(format!("Failed to query migration status: {e}"))
                })?
        };

        if already_applied {
            tracing::debug!(migration = migration.name, "Migration already applied, skipping");
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
