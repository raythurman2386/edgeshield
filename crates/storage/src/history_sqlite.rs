//! SQLite-backed device history store for EdgeShield.
//!
//! Stores daily snapshots of device state in the `device_history`
//! table. Each row is a full copy of the device's state at snapshot
//! time, keyed by `(mac, snapshot_date)` with a `UNIQUE` constraint
//! so the latest snapshot for a given day wins (upsert).
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS device_history (
//!     id INTEGER PRIMARY KEY AUTOINCREMENT,
//!     mac TEXT NOT NULL,
//!     snapshot_date TEXT NOT NULL,
//!     snapshot_timestamp TEXT NOT NULL,
//!     ips TEXT NOT NULL DEFAULT '[]',
//!     hostname TEXT,
//!     vendor TEXT,
//!     dhcp_vendor_class TEXT,
//!     packet_count INTEGER NOT NULL,
//!     bytes_sent INTEGER NOT NULL,
//!     bytes_received INTEGER NOT NULL,
//!     protocols TEXT NOT NULL DEFAULT '[]',
//!     protocol_stats TEXT NOT NULL DEFAULT '{}',
//!     first_seen TEXT NOT NULL,
//!     last_seen TEXT NOT NULL,
//!     UNIQUE(mac, snapshot_date)
//! );
//! ```

use std::sync::Mutex;

use edgeshield_common::{
    DeviceHistorySnapshot, DeviceHistoryStore, Protocol, StorageError, Timestamp,
};
use mac_address::MacAddress;
use rusqlite::{Connection, params};
use tracing::{info, trace};

/// A SQLite-backed device history store.
///
/// Creates the `device_history` table on construction. Shares the
/// database file with `SqliteStore` (devices table) and
/// `SqliteAlertStore` (alerts table) — pass the same path.
pub struct SqliteHistoryStore {
    conn: Mutex<Connection>,
}

impl SqliteHistoryStore {
    /// Open or create a SQLite history database at the given path.
    ///
    /// If `path` is empty, returns `None` (caller should skip
    /// history when running in-memory).
    pub fn open(path: &str) -> Result<Option<Self>, StorageError> {
        if path.is_empty() {
            return Ok(None);
        }

        let conn = Connection::open(path)
            .map_err(|e| StorageError::Internal(format!("failed to open history database: {e}")))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| StorageError::Internal(format!("failed to set pragmas: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS device_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                snapshot_date TEXT NOT NULL,
                snapshot_timestamp TEXT NOT NULL,
                ips TEXT NOT NULL DEFAULT '[]',
                hostname TEXT,
                vendor TEXT,
                dhcp_vendor_class TEXT,
                packet_count INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                protocols TEXT NOT NULL DEFAULT '[]',
                protocol_stats TEXT NOT NULL DEFAULT '{}',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(mac, snapshot_date)
            );
            CREATE INDEX IF NOT EXISTS idx_history_mac ON device_history(mac);
            CREATE INDEX IF NOT EXISTS idx_history_date ON device_history(snapshot_date);",
        )
        .map_err(|e| StorageError::Internal(format!("failed to create history schema: {e}")))?;

        info!(path = %path, "SQLite history store opened");
        Ok(Some(Self {
            conn: Mutex::new(conn),
        }))
    }

    /// Serialize a set of IP addresses to JSON.
    fn ips_to_json(ips: &std::collections::BTreeSet<std::net::IpAddr>) -> String {
        let v: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string())
    }

    /// Deserialize IP addresses from JSON.
    fn ips_from_json(s: &str) -> std::collections::BTreeSet<std::net::IpAddr> {
        let v: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        v.iter().filter_map(|ip| ip.parse().ok()).collect()
    }

    /// Serialize protocols to JSON.
    fn protocols_to_json(protocols: &std::collections::BTreeSet<Protocol>) -> String {
        let v: Vec<String> = protocols.iter().map(|p| p.to_string()).collect();
        serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string())
    }

    /// Deserialize protocols from JSON.
    fn protocols_from_json(s: &str) -> std::collections::BTreeSet<Protocol> {
        let v: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        v.iter()
            .filter_map(|p| match p.as_str() {
                "ARP" => Some(Protocol::Arp),
                "IPv4" => Some(Protocol::Ipv4),
                "ICMP" => Some(Protocol::Icmp),
                "TCP" => Some(Protocol::Tcp),
                "UDP" => Some(Protocol::Udp),
                "DNS" => Some(Protocol::Dns),
                "DHCP" => Some(Protocol::Dhcp),
                "HTTP" => Some(Protocol::Http),
                "HTTPS" => Some(Protocol::Https),
                "mDNS" => Some(Protocol::Mdns),
                "NTP" => Some(Protocol::Ntp),
                _ => p
                    .strip_prefix("UNKNOWN(")
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|n| n.parse().ok())
                    .map(Protocol::Other),
            })
            .collect()
    }

    /// Serialize per-protocol stats to JSON.
    fn stats_to_json(stats: &std::collections::BTreeMap<Protocol, u64>) -> String {
        let v: Vec<(String, u64)> = stats.iter().map(|(p, c)| (p.to_string(), *c)).collect();
        serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserialize per-protocol stats from JSON.
    fn stats_from_json(s: &str) -> std::collections::BTreeMap<Protocol, u64> {
        let v: Vec<(String, u64)> = serde_json::from_str(s).unwrap_or_default();
        let mut map = std::collections::BTreeMap::new();
        for (p_str, count) in v {
            let proto = match p_str.as_str() {
                "ARP" => Some(Protocol::Arp),
                "IPv4" => Some(Protocol::Ipv4),
                "ICMP" => Some(Protocol::Icmp),
                "TCP" => Some(Protocol::Tcp),
                "UDP" => Some(Protocol::Udp),
                "DNS" => Some(Protocol::Dns),
                "DHCP" => Some(Protocol::Dhcp),
                "HTTP" => Some(Protocol::Http),
                "HTTPS" => Some(Protocol::Https),
                "mDNS" => Some(Protocol::Mdns),
                "NTP" => Some(Protocol::Ntp),
                _ => p_str
                    .strip_prefix("UNKNOWN(")
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|n| n.parse().ok())
                    .map(Protocol::Other),
            };
            if let Some(p) = proto {
                map.insert(p, count);
            }
        }
        map
    }

    /// Parse a timestamp from an ISO 8601 string.
    fn parse_timestamp(s: &str) -> Timestamp {
        s.parse::<chrono::DateTime<chrono::Utc>>()
            .map(Timestamp::from_datetime)
            .unwrap_or_else(|_| Timestamp::now())
    }

    /// Convert a SQLite row to a `DeviceHistorySnapshot`.
    fn row_to_snapshot(row: &rusqlite::Row) -> Result<DeviceHistorySnapshot, rusqlite::Error> {
        let mac_str: String = row.get(0)?;
        let snapshot_date: String = row.get(1)?;
        let snapshot_timestamp_str: String = row.get(2)?;
        let ips_str: String = row.get(3)?;
        let hostname: Option<String> = row.get(4)?;
        let vendor: Option<String> = row.get(5)?;
        let dhcp_vendor_class: Option<String> = row.get(6)?;
        let packet_count: u64 = row.get(7)?;
        let bytes_sent: u64 = row.get(8)?;
        let bytes_received: u64 = row.get(9)?;
        let protocols_str: String = row.get(10)?;
        let protocol_stats_str: String = row.get(11)?;
        let first_seen_str: String = row.get(12)?;
        let last_seen_str: String = row.get(13)?;

        let mac = mac_str
            .parse::<MacAddress>()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        Ok(DeviceHistorySnapshot {
            mac,
            snapshot_date,
            snapshot_timestamp: Self::parse_timestamp(&snapshot_timestamp_str),
            ips: Self::ips_from_json(&ips_str),
            hostname,
            vendor,
            dhcp_vendor_class,
            packet_count,
            bytes_sent,
            bytes_received,
            protocols: Self::protocols_from_json(&protocols_str),
            protocol_stats: Self::stats_from_json(&protocol_stats_str),
            first_seen: Self::parse_timestamp(&first_seen_str),
            last_seen: Self::parse_timestamp(&last_seen_str),
        })
    }
}

impl DeviceHistoryStore for SqliteHistoryStore {
    fn insert_snapshot(&self, snapshot: &DeviceHistorySnapshot) -> Result<(), StorageError> {
        trace!(mac = %snapshot.mac, date = %snapshot.snapshot_date, "history: insert snapshot");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let ips_json = Self::ips_to_json(&snapshot.ips);
        let protocols_json = Self::protocols_to_json(&snapshot.protocols);
        let stats_json = Self::stats_to_json(&snapshot.protocol_stats);

        conn.execute(
            "INSERT INTO device_history (
                mac, snapshot_date, snapshot_timestamp, ips, hostname, vendor,
                dhcp_vendor_class, packet_count, bytes_sent, bytes_received,
                protocols, protocol_stats, first_seen, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            ON CONFLICT(mac, snapshot_date) DO UPDATE SET
                snapshot_timestamp = excluded.snapshot_timestamp,
                ips = excluded.ips,
                hostname = excluded.hostname,
                vendor = excluded.vendor,
                dhcp_vendor_class = excluded.dhcp_vendor_class,
                packet_count = excluded.packet_count,
                bytes_sent = excluded.bytes_sent,
                bytes_received = excluded.bytes_received,
                protocols = excluded.protocols,
                protocol_stats = excluded.protocol_stats,
                last_seen = excluded.last_seen",
            params![
                snapshot.mac.to_string(),
                snapshot.snapshot_date,
                snapshot.snapshot_timestamp.to_string(),
                ips_json,
                snapshot.hostname,
                snapshot.vendor,
                snapshot.dhcp_vendor_class,
                snapshot.packet_count,
                snapshot.bytes_sent,
                snapshot.bytes_received,
                protocols_json,
                stats_json,
                snapshot.first_seen.to_string(),
                snapshot.last_seen.to_string(),
            ],
        )
        .map_err(|e| StorageError::Internal(format!("snapshot upsert failed: {e}")))?;

        Ok(())
    }

    fn list_history(
        &self,
        mac: &MacAddress,
        from: Option<&str>,
        to: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<DeviceHistorySnapshot>, StorageError> {
        trace!(mac = %mac, "history: list");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        // Build the query dynamically based on the date filters.
        let mut sql = String::from(
            "SELECT mac, snapshot_date, snapshot_timestamp, ips, hostname, vendor,
                    dhcp_vendor_class, packet_count, bytes_sent, bytes_received,
                    protocols, protocol_stats, first_seen, last_seen
             FROM device_history WHERE mac = ?1",
        );
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(mac.to_string())];
        let mut param_idx = 2;

        if let Some(from_date) = from {
            sql.push_str(&format!(" AND snapshot_date >= ?{param_idx}"));
            params_vec.push(Box::new(from_date.to_string()));
            param_idx += 1;
        }
        if let Some(to_date) = to {
            sql.push_str(&format!(" AND snapshot_date <= ?{param_idx}"));
            params_vec.push(Box::new(to_date.to_string()));
        }

        sql.push_str(" ORDER BY snapshot_date ASC");

        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }

        let param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Internal(format!("query prepare failed: {e}")))?;
        let rows = stmt
            .query_map(param_refs.as_slice(), Self::row_to_snapshot)
            .map_err(|e| StorageError::Internal(format!("query failed: {e}")))?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots
                .push(row.map_err(|e| StorageError::Internal(format!("row parse failed: {e}")))?);
        }
        Ok(snapshots)
    }

    fn delete_before(&self, before_date: &str) -> Result<usize, StorageError> {
        trace!(before_date, "history: delete before");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        let deleted = conn
            .execute(
                "DELETE FROM device_history WHERE snapshot_date < ?1",
                params![before_date],
            )
            .map_err(|e| StorageError::Internal(format!("delete failed: {e}")))?;

        Ok(deleted)
    }

    fn vacuum(&self) -> Result<(), StorageError> {
        trace!("history: incremental vacuum");
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))?;

        // `incremental_vacuum` is a no-op if `auto_vacuum` is not
        // enabled on the database. Safe to call unconditionally.
        conn.execute_batch("PRAGMA incremental_vacuum;")
            .map_err(|e| StorageError::Internal(format!("vacuum failed: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::Device;
    use std::str::FromStr;

    fn sample_device(mac_str: &str, packets: u64) -> Device {
        let mac = MacAddress::from_str(mac_str).unwrap();
        let mut device = Device::new(mac);
        let now = Timestamp::now();
        for _ in 0..packets {
            device.record_sent(100, Protocol::Tcp, now);
        }
        device.hostname = Some("test-device".to_string());
        device.vendor = Some("TestVendor".to_string());
        device
    }

    fn open_test_store() -> SqliteHistoryStore {
        SqliteHistoryStore::open(":memory:").unwrap().unwrap()
    }

    #[test]
    fn test_insert_and_list_snapshot() {
        let store = open_test_store();
        let device = sample_device("00:11:22:33:44:55", 10);
        let snapshot = DeviceHistorySnapshot::from_device(&device, "2026-07-19".to_string());
        store.insert_snapshot(&snapshot).unwrap();

        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let history = store.list_history(&mac, None, None, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].snapshot_date, "2026-07-19");
        assert_eq!(history[0].packet_count, 10);
        assert_eq!(history[0].hostname.as_deref(), Some("test-device"));
    }

    #[test]
    fn test_upsert_same_day_replaces() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device1 = sample_device("00:11:22:33:44:55", 10);
        let snapshot1 = DeviceHistorySnapshot::from_device(&device1, "2026-07-19".to_string());
        store.insert_snapshot(&snapshot1).unwrap();

        // Insert a second snapshot for the same day with more packets.
        let device2 = sample_device("00:11:22:33:44:55", 50);
        let snapshot2 = DeviceHistorySnapshot::from_device(&device2, "2026-07-19".to_string());
        store.insert_snapshot(&snapshot2).unwrap();

        let history = store.list_history(&mac, None, None, None).unwrap();
        assert_eq!(history.len(), 1); // still one row for this day
        assert_eq!(history[0].packet_count, 50); // latest state wins
    }

    #[test]
    fn test_multiple_days() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

        for (day, packets) in [("2026-07-18", 10), ("2026-07-19", 20), ("2026-07-20", 30)] {
            let device = sample_device("00:11:22:33:44:55", packets);
            let snapshot = DeviceHistorySnapshot::from_device(&device, day.to_string());
            store.insert_snapshot(&snapshot).unwrap();
        }

        let history = store.list_history(&mac, None, None, None).unwrap();
        assert_eq!(history.len(), 3);
        // Ordered ascending by date.
        assert_eq!(history[0].snapshot_date, "2026-07-18");
        assert_eq!(history[2].snapshot_date, "2026-07-20");
    }

    #[test]
    fn test_list_history_date_range() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

        for day in ["2026-07-18", "2026-07-19", "2026-07-20", "2026-07-21"] {
            let device = sample_device("00:11:22:33:44:55", 5);
            let snapshot = DeviceHistorySnapshot::from_device(&device, day.to_string());
            store.insert_snapshot(&snapshot).unwrap();
        }

        let history = store
            .list_history(&mac, Some("2026-07-19"), Some("2026-07-20"), None)
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].snapshot_date, "2026-07-19");
        assert_eq!(history[1].snapshot_date, "2026-07-20");
    }

    #[test]
    fn test_list_history_limit() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

        for i in 0..10 {
            let day = format!("2026-07-{i:02}");
            let device = sample_device("00:11:22:33:44:55", 5);
            let snapshot = DeviceHistorySnapshot::from_device(&device, day);
            store.insert_snapshot(&snapshot).unwrap();
        }

        let history = store.list_history(&mac, None, None, Some(3)).unwrap();
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_delete_before() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

        for day in ["2026-07-18", "2026-07-19", "2026-07-20", "2026-07-21"] {
            let device = sample_device("00:11:22:33:44:55", 5);
            let snapshot = DeviceHistorySnapshot::from_device(&device, day.to_string());
            store.insert_snapshot(&snapshot).unwrap();
        }

        let deleted = store.delete_before("2026-07-20").unwrap();
        assert_eq!(deleted, 2); // 2026-07-18 and 2026-07-19

        let history = store.list_history(&mac, None, None, None).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].snapshot_date, "2026-07-20");
    }

    #[test]
    fn test_persistence_across_reopen() {
        let path = format!("/tmp/edgeshield-history-test-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);

        {
            let store = SqliteHistoryStore::open(&path).unwrap().unwrap();
            let device = sample_device("00:11:22:33:44:55", 42);
            let snapshot = DeviceHistorySnapshot::from_device(&device, "2026-07-19".to_string());
            store.insert_snapshot(&snapshot).unwrap();
        }

        {
            let store = SqliteHistoryStore::open(&path).unwrap().unwrap();
            let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
            let history = store.list_history(&mac, None, None, None).unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].packet_count, 42);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_vacuum_no_error() {
        // Vacuum should not error even on a fresh in-memory DB.
        let store = open_test_store();
        store.vacuum().unwrap();
    }
}
