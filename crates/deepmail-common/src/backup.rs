use std::fs;
use std::io::Read;
use std::path::PathBuf;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::BackupConfig;
use crate::db::DbPool;
use crate::errors::DeepMailError;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub created_at: String,
    pub migration_count: u32,
    pub db_sha256: String,
    pub db_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupResult {
    pub backup_path: String,
    pub manifest: BackupManifest,
}

pub fn create_backup(
    pool: &DbPool,
    cfg: &BackupConfig,
    migration_count: u32,
) -> Result<BackupResult, DeepMailError> {
    fs::create_dir_all(&cfg.backup_dir)?;
    let passphrase = std::env::var(&cfg.passphrase_env_var).map_err(|_| {
        DeepMailError::Config(format!(
            "Missing backup passphrase env var {}",
            cfg.passphrase_env_var
        ))
    })?;

    let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let temp_db = PathBuf::from(&cfg.backup_dir).join(format!("temp-{ts}.db"));
    let conn = pool.get()?;
    let mut dst = rusqlite::Connection::open(&temp_db)?;
    let backup = rusqlite::backup::Backup::new(&conn, &mut dst)
        .map_err(|e| DeepMailError::Database(format!("Backup init failed: {e}")))?;
    backup
        .run_to_completion(20, std::time::Duration::from_millis(50), None)
        .map_err(|e| DeepMailError::Database(format!("Backup copy failed: {e}")))?;

    let db_bytes = fs::read(&temp_db)?;
    let db_sha256 = hex::encode(Sha256::digest(&db_bytes));
    let manifest = BackupManifest {
        version: "1.0".to_string(),
        created_at: Utc::now().to_rfc3339(),
        migration_count,
        db_sha256,
        db_size_bytes: db_bytes.len() as u64,
    };

    let manifest_json = serde_json::to_vec(&manifest)?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut encoder);
        let mut hdr = tar::Header::new_gnu();
        hdr.set_mode(0o644);
        hdr.set_size(manifest_json.len() as u64);
        hdr.set_cksum();
        tar.append_data(&mut hdr, "manifest.json", manifest_json.as_slice())?;

        let mut db_hdr = tar::Header::new_gnu();
        db_hdr.set_mode(0o600);
        db_hdr.set_size(db_bytes.len() as u64);
        db_hdr.set_cksum();
        tar.append_data(&mut db_hdr, "deepmail.db", db_bytes.as_slice())?;
        tar.finish()?;
    }
    let archive = encoder.finish()?;
    let encrypted = encrypt_archive(&archive, &passphrase, cfg)?;

    let out = PathBuf::from(&cfg.backup_dir).join(format!("deepmail-backup-{ts}.tar.gz.enc"));
    fs::write(&out, encrypted)?;
    let _ = fs::remove_file(&temp_db);

    Ok(BackupResult {
        backup_path: out.to_string_lossy().to_string(),
        manifest,
    })
}

pub fn restore_backup(
    pool: &DbPool,
    backup_path: &str,
    passphrase: &str,
    max_migration_count: u32,
) -> Result<BackupManifest, DeepMailError> {
    let encrypted = fs::read(backup_path)?;
    let archive = decrypt_archive(&encrypted, passphrase)?;
    let mut tar = tar::Archive::new(GzDecoder::new(archive.as_slice()));

    let mut manifest: Option<BackupManifest> = None;
    let mut db_bytes: Option<Vec<u8>> = None;

    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        match path.as_str() {
            "manifest.json" => {
                manifest = Some(serde_json::from_slice(&bytes)?);
            }
            "deepmail.db" => db_bytes = Some(bytes),
            _ => {}
        }
    }

    let manifest = manifest
        .ok_or_else(|| DeepMailError::Internal("Backup missing manifest.json".to_string()))?;
    let db_bytes = db_bytes
        .ok_or_else(|| DeepMailError::Internal("Backup missing deepmail.db".to_string()))?;

    if manifest.migration_count > max_migration_count {
        return Err(DeepMailError::Validation(format!(
            "Backup migration count {} exceeds binary supported {}",
            manifest.migration_count, max_migration_count
        )));
    }

    let actual_sha = hex::encode(Sha256::digest(&db_bytes));
    if actual_sha != manifest.db_sha256 {
        return Err(DeepMailError::Validation(
            "Backup integrity check failed".to_string(),
        ));
    }

    let temp_db =
        PathBuf::from("/tmp").join(format!("deepmail-restore-{}.db", Utc::now().timestamp()));
    fs::write(&temp_db, db_bytes)?;
    let src = rusqlite::Connection::open(&temp_db)?;
    let mut dst = pool.get()?;
    let backup = rusqlite::backup::Backup::new(&src, &mut dst)
        .map_err(|e| DeepMailError::Database(format!("Restore init failed: {e}")))?;
    backup
        .run_to_completion(20, std::time::Duration::from_millis(50), None)
        .map_err(|e| DeepMailError::Database(format!("Restore copy failed: {e}")))?;
    let _ = fs::remove_file(temp_db);

    Ok(manifest)
}

fn encrypt_archive(
    archive: &[u8],
    passphrase: &str,
    cfg: &BackupConfig,
) -> Result<Vec<u8>, DeepMailError> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt, cfg)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| DeepMailError::Internal(format!("Cipher init failed: {e}")))?;
    let ciphertext = cipher
        .encrypt(nonce, archive)
        .map_err(|e| DeepMailError::Internal(format!("Encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_archive(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, DeepMailError> {
    if encrypted.len() <= SALT_LEN + NONCE_LEN {
        return Err(DeepMailError::Validation(
            "Encrypted backup is too short".to_string(),
        ));
    }
    let salt = &encrypted[..SALT_LEN];
    let nonce_bytes = &encrypted[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext = &encrypted[(SALT_LEN + NONCE_LEN)..];

    let cfg = BackupConfig {
        backup_dir: String::new(),
        passphrase_env_var: String::new(),
        argon2_memory_kib: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
    };
    let key = derive_key(passphrase, salt, &cfg)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| DeepMailError::Internal(format!("Cipher init failed: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| DeepMailError::Validation(format!("Backup decryption failed: {e}")))
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    cfg: &BackupConfig,
) -> Result<[u8; 32], DeepMailError> {
    let params = argon2::Params::new(
        cfg.argon2_memory_kib,
        cfg.argon2_iterations,
        cfg.argon2_parallelism,
        Some(32),
    )
    .map_err(|e| DeepMailError::Internal(format!("Invalid Argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| DeepMailError::Internal(format!("Key derivation failed: {e}")))?;
    Ok(out)
}
