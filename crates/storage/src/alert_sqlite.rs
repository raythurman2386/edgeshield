//! SQLite-backed alert store for EdgeShield.
//!
//! Persists alerts to a SQLite database so alert history survives
//! daemon restarts. Uses the same `rusqlite` + `bundled` setup as the
//! device store. The alerts table is created in the same database
//! file as the devices table.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS alerts (
//!     id INTEGER PRIMARY KEY AUTOINCREMENT,
//!     rule_name TEXT NOT NULL,
//!     severity TEXT NOT NULL,
//!     event_type TEXT NOT NULL,
//!     mac TEXT NOT NULL,
//!     message TEXT NOT NULL,
//!     device_snapshot TEXT NOT NULL,
//!     timestamp TEXT NOT NULL,
//!     acknowledged INTEGER NOT NULL DEFAULT 0
//! );
//! ```
//!
//! # Concurrency
//!
//! Same as `SqliteStore` — `Mutex<Connection>` serializes access.
//! Alert writes are infrequent (only on rule matches), so contention
//! is not a concern.

use std::sync::Mutex;

use edgeshield_common::{
    Alert, AlertEventType, AlertFilter, AlertId, AlertStore, Device, Severity, StorageError,
};
use mac_address::MacAddress;
use rusqlite::{Connection, params};
use tracing::{info, trace};

/// A SQLite-backed alert store.
///
/// Creates the `alerts` table on construction. Shares the database
/// file with `SqliteStore` (devices table) — pass the same path.
pub struct SqliteAlertStore {
    conn: Mutex<Connection>,
}

impl SqliteAlertStore {
    /// Open or create a SQLite alert database at the given path.
    ///
    /// If `path` is empty, returns `None` (caller falls back to
    /// `InMemoryAlertStore`).
    pub fn open(path: &str) -> Result<Option<Self>, StorageError> {
        if path.is_empty() {
            return Ok(None);
        }

        let conn = Connection::open(path)
            .map_err(|e| StorageError::Internal(format!("failed to open alert database: {e}")))?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| StorageError::Internal(format!("failed to set pragmas: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                mac TEXT NOT NULL,
                message TEXT NOT NULL,
                device_snapshot TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_mac ON alerts(mac);
            CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);",
        )
        .map_err(|e| StorageError::Internal(format!("failed to create alerts schema: {e}")))?;

        info!(path = %path, "SQLite alert store opened");
        Ok(Some(Self {
            conn: Mutex::new(conn),
        }))
    }

    /// Convert a SQLite row to an Alert.
    fn row_to_alert(row: &rusqlite::Row) -> Result<Alert, rusqlite::Error> {
        let id: i64 = row.get(0)?;
        let rule_name: String = row.get(1)?;
        let severity_str: String = row.get(2)?;
        let event_type_str: String = row.get(3)?;
        let mac_str: String = row.get(4)?;
        let message: String = row.get(5)?;
        let device_snapshot_str: String = row.get(6)?;
        let timestamp_str: String = row.get(7)?;
        let acknowledged_int: i64 = row.get(8)?;

        let mac = mac_str
            .parse::<MacAddress>()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let severity: Severity = std::str::FromStr::from_str(&severity_str).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            )))
        })?;

        let event_type = parse_event_type(&event_type_str);

        let device: Device = serde_json::from_str(&device_snapshot_str)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let timestamp: edgeshield_common::Timestamp = timestamp_str
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map(edgeshield_common::Timestamp::from_datetime)
            .unwrap_or_else(|_| edgeshield_common::Timestamp::now());

        Ok(Alert {
            id: id as AlertId,
            rule_name,
            severity,
            event_type,
            mac,
            message,
            device_snapshot: device,
            timestamp,
            acknowledged: acknowledged_int != 0,
        })
    }

    /// Build a WHERE clause and params from a filter.
    fn build_filter(filter: &AlertFilter) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(ref sev) = filter.severity {
            params.push(Box::new(sev.to_string()));
            clauses.push(format!("severity = ?{}", params.len()));
        }
        if let Some(ref ack) = filter.acknowledged {
            params.push(Box::new(if *ack { 1i64 } else { 0i64 }));
            clauses.push(format!("acknowledged = ?{}", params.len()));
        }
        if let Some(ref name) = filter.rule_name {
            params.push(Box::new(name.clone()));
            clauses.push(format!("rule_name = ?{}", params.len()));
        }

        let where_clause = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };
        (where_clause, params)
    }
}

/// Parse an `AlertEventType` from its string form.
fn parse_event_type(s: &str) -> AlertEventType {
    match s {
        "new_device" => AlertEventType::NewDevice,
        "device_offline" => AlertEventType::DeviceOffline,
        "protocol_change" => AlertEventType::ProtocolChange,
        other => AlertEventType::Custom(other.to_string()),
    }
}

impl AlertStore for SqliteAlertStore {
    fn insert_alert(&self, alert: &Alert) -> Result<AlertId, StorageError> {
        trace!(rule = %alert.rule_name, mac = %alert.mac, "sqlite alert store: insert");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let device_json = serde_json::to_string(&alert.device_snapshot)
            .map_err(|e| StorageError::Internal(format!("device serialize failed: {e}")))?;

        conn.execute(
            "INSERT INTO alerts (rule_name, severity, event_type, mac, message, device_snapshot, timestamp, acknowledged)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                alert.rule_name,
                alert.severity.to_string(),
                alert.event_type.to_string(),
                alert.mac.to_string(),
                alert.message,
                device_json,
                alert.timestamp.to_string(),
                if alert.acknowledged { 1i64 } else { 0i64 },
            ],
        )
        .map_err(|e| StorageError::Internal(format!("alert insert failed: {e}")))?;

        let id = conn.last_insert_rowid() as AlertId;
        Ok(id)
    }

    fn list_alerts(&self, filter: AlertFilter) -> Result<Vec<Alert>, StorageError> {
        trace!("sqlite alert store: list");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let (where_clause, params) = Self::build_filter(&filter);
        let limit_clause = filter
            .limit
            .map(|l| format!(" LIMIT {l}"))
            .unwrap_or_default();

        let sql = format!(
            "SELECT id, rule_name, severity, event_type, mac, message, device_snapshot, timestamp, acknowledged
             FROM alerts{where_clause} ORDER BY id DESC{limit_clause}"
        );

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Internal(format!("query prepare failed: {e}")))?;
        let rows = stmt
            .query_map(param_refs.as_slice(), Self::row_to_alert)
            .map_err(|e| StorageError::Internal(format!("query failed: {e}")))?;

        let mut alerts = Vec::new();
        for row in rows {
            alerts.push(row.map_err(|e| StorageError::Internal(format!("row parse failed: {e}")))?);
        }
        Ok(alerts)
    }

    fn get_alert(&self, id: AlertId) -> Result<Option<Alert>, StorageError> {
        trace!(id, "sqlite alert store: get");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, rule_name, severity, event_type, mac, message, device_snapshot, timestamp, acknowledged
                 FROM alerts WHERE id = ?1",
            )
            .map_err(|e| StorageError::Internal(format!("query prepare failed: {e}")))?;

        let mut rows = stmt
            .query(params![id as i64])
            .map_err(|e| StorageError::Internal(format!("query failed: {e}")))?;

        match rows
            .next()
            .map_err(|e| StorageError::Internal(format!("row fetch failed: {e}")))?
        {
            Some(row) => Ok(Some(Self::row_to_alert(row).map_err(|e| {
                StorageError::Internal(format!("row parse failed: {e}"))
            })?)),
            None => Ok(None),
        }
    }

    fn acknowledge_alert(&self, id: AlertId) -> Result<(), StorageError> {
        trace!(id, "sqlite alert store: acknowledge");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let affected = conn
            .execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?1",
                params![id as i64],
            )
            .map_err(|e| StorageError::Internal(format!("acknowledge failed: {e}")))?;

        if affected == 0 {
            return Err(StorageError::Internal(format!("alert {id} not found")));
        }
        Ok(())
    }

    fn delete_alert(&self, id: AlertId) -> Result<(), StorageError> {
        trace!(id, "sqlite alert store: delete");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        conn.execute("DELETE FROM alerts WHERE id = ?1", params![id as i64])
            .map_err(|e| StorageError::Internal(format!("delete failed: {e}")))?;
        Ok(())
    }

    fn is_acknowledged(&self, rule_name: &str, mac: &MacAddress) -> Result<bool, StorageError> {
        trace!(rule = rule_name, mac = %mac, "sqlite alert store: is_acknowledged");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE rule_name = ?1 AND mac = ?2 AND acknowledged = 1",
                params![rule_name, mac.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::Internal(format!("is_acknowledged query failed: {e}")))?;

        Ok(count > 0)
    }

    fn count_alerts(&self) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alerts", [], |row| row.get(0))
            .map_err(|e| StorageError::Internal(format!("count query failed: {e}")))?;

        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::AlertEventType;
    use std::str::FromStr;

    fn sample_alert(rule_name: &str, mac_str: &str) -> Alert {
        let mac = MacAddress::from_str(mac_str).unwrap();
        let device = Device::new(mac);
        Alert::new(
            rule_name.to_string(),
            Severity::Info,
            AlertEventType::NewDevice,
            device,
            "test alert".to_string(),
        )
    }

    fn open_test_store() -> SqliteAlertStore {
        SqliteAlertStore::open(":memory:").unwrap().unwrap()
    }

    #[test]
    fn test_sqlite_alert_insert_and_get() {
        let store = open_test_store();
        let alert = sample_alert("new-device", "00:11:22:33:44:55");
        let id = store.insert_alert(&alert).unwrap();
        assert!(id > 0);
        let retrieved = store.get_alert(id).unwrap().unwrap();
        assert_eq!(retrieved.rule_name, "new-device");
        assert_eq!(retrieved.severity, Severity::Info);
        assert!(!retrieved.acknowledged);
    }

    #[test]
    fn test_sqlite_alert_list_most_recent_first() {
        let store = open_test_store();
        let a1 = sample_alert("rule-a", "00:11:22:33:44:55");
        let a2 = sample_alert("rule-b", "00:11:22:33:44:66");
        store.insert_alert(&a1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.insert_alert(&a2).unwrap();

        let alerts = store.list_alerts(AlertFilter::default()).unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].rule_name, "rule-b");
    }

    #[test]
    fn test_sqlite_alert_filter_by_severity() {
        let store = open_test_store();
        let mut a1 = sample_alert("info-rule", "00:11:22:33:44:55");
        a1.severity = Severity::Info;
        let mut a2 = sample_alert("warn-rule", "00:11:22:33:44:66");
        a2.severity = Severity::Warning;
        store.insert_alert(&a1).unwrap();
        store.insert_alert(&a2).unwrap();

        let filter = AlertFilter {
            severity: Some(Severity::Warning),
            ..Default::default()
        };
        let alerts = store.list_alerts(filter).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "warn-rule");
    }

    #[test]
    fn test_sqlite_alert_acknowledge_and_suppression() {
        let store = open_test_store();
        let alert = sample_alert("new-device", "00:11:22:33:44:55");
        let id = store.insert_alert(&alert).unwrap();

        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        assert!(!store.is_acknowledged("new-device", &mac).unwrap());

        store.acknowledge_alert(id).unwrap();
        assert!(store.is_acknowledged("new-device", &mac).unwrap());
    }

    #[test]
    fn test_sqlite_alert_delete() {
        let store = open_test_store();
        let alert = sample_alert("new-device", "00:11:22:33:44:55");
        let id = store.insert_alert(&alert).unwrap();
        assert_eq!(store.count_alerts().unwrap(), 1);

        store.delete_alert(id).unwrap();
        assert_eq!(store.count_alerts().unwrap(), 0);
        assert!(store.get_alert(id).unwrap().is_none());
    }

    #[test]
    fn test_sqlite_alert_persistence_across_reopen() {
        let path = format!("/tmp/edgeshield-alert-test-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);

        {
            let store = SqliteAlertStore::open(&path).unwrap().unwrap();
            let alert = sample_alert("persistent-rule", "00:11:22:33:44:55");
            store.insert_alert(&alert).unwrap();
        }

        {
            let store = SqliteAlertStore::open(&path).unwrap().unwrap();
            assert_eq!(store.count_alerts().unwrap(), 1);
            let alerts = store.list_alerts(AlertFilter::default()).unwrap();
            assert_eq!(alerts[0].rule_name, "persistent-rule");
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_sqlite_alert_filter_by_acknowledged() {
        let store = open_test_store();
        let a1 = sample_alert("ack-rule", "00:11:22:33:44:55");
        let id1 = store.insert_alert(&a1).unwrap();
        let a2 = sample_alert("unack-rule", "00:11:22:33:44:66");
        store.insert_alert(&a2).unwrap();

        store.acknowledge_alert(id1).unwrap();

        let filter = AlertFilter {
            acknowledged: Some(true),
            ..Default::default()
        };
        let alerts = store.list_alerts(filter).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "ack-rule");
    }

    #[test]
    fn test_sqlite_alert_filter_by_rule_name() {
        let store = open_test_store();
        store
            .insert_alert(&sample_alert("rule-a", "00:11:22:33:44:55"))
            .unwrap();
        store
            .insert_alert(&sample_alert("rule-b", "00:11:22:33:44:66"))
            .unwrap();

        let filter = AlertFilter {
            rule_name: Some("rule-b".to_string()),
            ..Default::default()
        };
        let alerts = store.list_alerts(filter).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "rule-b");
    }

    #[test]
    fn test_sqlite_alert_list_limit() {
        let store = open_test_store();
        for i in 0..10 {
            let mac = MacAddress::from_str(&format!("00:11:22:33:44:{i:02x}")).unwrap();
            let alert = Alert::new(
                "rule".to_string(),
                Severity::Info,
                AlertEventType::NewDevice,
                Device::new(mac),
                "test".to_string(),
            );
            store.insert_alert(&alert).unwrap();
        }
        let filter = AlertFilter {
            limit: Some(3),
            ..Default::default()
        };
        let alerts = store.list_alerts(filter).unwrap();
        assert_eq!(alerts.len(), 3);
    }
}
