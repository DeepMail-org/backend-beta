//! IOC Graph Engine for infrastructure intelligence and correlation.

use deepmail_common::db::DbPool;
use deepmail_common::errors::DeepMailError;
use deepmail_common::models::new_id;
use crate::pipeline::ioc_extractor::ExtractedIocs;

/// Service for managing IOC nodes and relations.
pub struct GraphService {
    db_pool: DbPool,
}

impl GraphService {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }

    /// Insert IOCs and link them to the email.
    pub fn ingest_iocs(&self, email_id: &str, iocs: &ExtractedIocs) -> Result<(), DeepMailError> {
        let conn = self.db_pool.get()?;
        
        let mut ioc_ids = Vec::new();
        
        // Helper to insert and get ID
        let mut insert_node = |ioc_type: &str, value: &str| -> Result<String, DeepMailError> {
            conn.execute(
                "INSERT INTO ioc_nodes (id, ioc_type, value, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, datetime('now'), datetime('now'))
                 ON CONFLICT(ioc_type, value) DO UPDATE SET last_seen = datetime('now')",
                rusqlite::params![new_id(), ioc_type, value],
            )?;
            
            let id: String = conn.query_row(
                "SELECT id FROM ioc_nodes WHERE ioc_type = ?1 AND value = ?2",
                rusqlite::params![ioc_type, value],
                |row| row.get(0),
            )?;
            Ok(id)
        };

        // Batch insert for performance
        for ip in &iocs.ips { if let Ok(id) = insert_node("ip", ip) { ioc_ids.push(id); } }
        for domain in &iocs.domains { if let Ok(id) = insert_node("domain", domain) { ioc_ids.push(id); } }
        for url in &iocs.urls { if let Ok(id) = insert_node("url", url) { ioc_ids.push(id); } }
        for hash in &iocs.hashes { if let Ok(id) = insert_node("sha256", hash) { ioc_ids.push(id); } }

        // Create relations
        for node_id in ioc_ids {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO ioc_relations (id, source_id, target_id, relation_type, email_id)
                 VALUES (?1, ?2, ?3, 'extracted_from', ?4)",
                rusqlite::params![new_id(), node_id, node_id, email_id],
            );
        }

        Ok(())
    }

    /// Correlate email to existing campaigns or create new ones.
    pub fn correlate_campaign(&self, email_id: &str) -> Result<(), DeepMailError> {
        let conn = self.db_pool.get()?;
        
        // Find shared IOCs with other emails
        let matched_email_id: Option<String> = conn.query_row(
            "SELECT r2.email_id 
             FROM ioc_relations r1
             JOIN ioc_relations r2 ON r1.source_id = r2.source_id
             WHERE r1.email_id = ?1 AND r2.email_id != ?1
             LIMIT 1",
            rusqlite::params![email_id],
            |row| row.get(0),
        ).optional().map_err(DeepMailError::from)?;

        if let Some(other_id) = matched_email_id {
            // Find existing cluster
            let cluster_id: Option<String> = conn.query_row(
                "SELECT cluster_id FROM campaign_members WHERE email_id = ?1",
                rusqlite::params![other_id],
                |row| row.get(0),
            ).optional().map_err(DeepMailError::from)?;

            let final_cluster_id = match cluster_id {
                Some(id) => id,
                None => {
                    // Create new cluster
                    let new_cluster_id = new_id();
                    conn.execute(
                        "INSERT INTO campaign_clusters (id, name, created_at, updated_at)
                         VALUES (?1, ?2, datetime('now'), datetime('now'))",
                        rusqlite::params![new_cluster_id, format!("Campaign-{}", &new_cluster_id[..8])],
                    )?;
                    // Add the other email
                    conn.execute(
                        "INSERT INTO campaign_members (cluster_id, email_id, similarity)
                         VALUES (?1, ?2, 1.0)",
                        rusqlite::params![new_cluster_id, other_id],
                    )?;
                    new_cluster_id
                }
            };

            // Add current email to cluster
            let _ = conn.execute(
                "INSERT OR IGNORE INTO campaign_members (cluster_id, email_id)
                 VALUES (?1, ?2)",
                rusqlite::params![final_cluster_id, email_id],
            );
        }

        Ok(())
    }
}
