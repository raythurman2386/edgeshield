//! Audit logging for API requests.
//!
//! Logs every API request (except `/health`) to a file in JSON-lines
//! format. Each line is a JSON object with the request method, path,
//! response status, key hash prefix (for identifying which key was
//! used), and duration.
//!
//! # Format
//!
//! ```json
//! {"timestamp":"2026-07-19T15:00:00.123Z","method":"GET","path":"/devices","status":200,"key_prefix":"a1b2","duration_ms":3}
//! ```
//!
//! # Security
//!
//! The audit log records the first 4 hex characters of the SHA-256
//! hash of the key used (not the key itself). This is enough to
//! distinguish which key was used (read vs admin) without revealing
//! the key. Failed auth attempts are logged with `key_prefix: null`.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{error, info};

/// Audit log entry (serialized as JSON).
#[derive(Serialize)]
struct AuditEntry {
    timestamp: String,
    method: String,
    path: String,
    status: u16,
    key_prefix: Option<String>,
    duration_ms: u64,
}

/// Audit log writer. Opens the file once and appends entries.
/// Uses a `Mutex` to serialize writes (audit logs are low-volume).
pub struct AuditLogger {
    file: Mutex<tokio::fs::File>,
    log_path: PathBuf,
}

impl AuditLogger {
    /// Create a new audit logger, opening (or creating) the log file.
    pub async fn new(log_path: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(log_path);

        // Create parent directories if needed.
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;

        info!(path = %path.display(), "audit log opened");

        Ok(Self {
            file: Mutex::new(file),
            log_path: path,
        })
    }

    /// Write an audit entry.
    pub async fn write(
        &self,
        method: &str,
        path: &str,
        status: u16,
        key_prefix: Option<&str>,
        duration_ms: u64,
    ) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            method: method.to_string(),
            path: path.to_string(),
            status,
            key_prefix: key_prefix.map(String::from),
            duration_ms,
        };

        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "failed to serialize audit entry");
                return;
            }
        };

        let mut file = self.file.lock().await;
        if let Err(e) = file.write_all(format!("{json}\n").as_bytes()).await {
            error!(error = %e, path = %self.log_path.display(), "failed to write audit entry");
        }
    }
}

/// Compute the 4-character prefix of the SHA-256 hash of a key.
/// Used for audit logging — identifies which key was used without
/// revealing the key itself.
pub fn key_hash_prefix(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..2]) // first 2 bytes = 4 hex chars
}

/// Axum middleware: audit-log every request (except `/health`).
///
/// The `Option<Arc<AuditLogger>>` is passed via `from_fn_with_state`.
pub async fn audit_middleware(
    State(audit_logger): State<Option<Arc<AuditLogger>>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Skip health checks (too noisy).
    if path == "/health" {
        return next.run(request).await;
    }

    // Extract the key prefix for audit (if auth is enabled and a key
    // was provided). We compute the prefix from the raw Bearer token.
    let key_prefix = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(key_hash_prefix);

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    // Write the audit entry (fire-and-forget — don't block the
    // response).
    if let Some(ref audit) = audit_logger {
        let audit = Arc::clone(audit);
        let method = method.to_string();
        let key_prefix = key_prefix.clone();
        tokio::spawn(async move {
            audit
                .write(&method, &path, status, key_prefix.as_deref(), duration_ms)
                .await;
        });
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hash_prefix_is_4_chars() {
        let prefix = key_hash_prefix("test-key");
        assert_eq!(prefix.len(), 4);
        assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_key_hash_prefix_different_keys_differ() {
        let p1 = key_hash_prefix("key-one");
        let p2 = key_hash_prefix("key-two");
        assert_ne!(p1, p2);
    }

    #[tokio::test]
    async fn test_audit_logger_writes_entries() {
        let path = format!("/tmp/edgeshield-audit-test-{}.log", std::process::id());
        let _ = std::fs::remove_file(&path);

        let logger = AuditLogger::new(&path).await.unwrap();
        logger.write("GET", "/devices", 200, Some("a1b2"), 5).await;
        logger
            .write("POST", "/alerts/1/acknowledge", 401, None, 2)
            .await;

        // Read the file and verify.
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let entry1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry1["method"], "GET");
        assert_eq!(entry1["path"], "/devices");
        assert_eq!(entry1["status"], 200);
        assert_eq!(entry1["key_prefix"], "a1b2");

        let entry2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(entry2["method"], "POST");
        assert_eq!(entry2["status"], 401);
        assert!(entry2["key_prefix"].is_null());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_audit_logger_creates_parent_dirs() {
        let dir = format!("/tmp/edgeshield-audit-dir-{}/", std::process::id());
        let path = format!("{}audit.log", dir);
        let _ = std::fs::remove_dir_all(&dir);

        let logger = AuditLogger::new(&path).await.unwrap();
        logger.write("GET", "/health", 200, None, 1).await;

        assert!(tokio::fs::metadata(&path).await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
