//! SQLite-backed device store for EdgeShield.
//!
//! Persists the device inventory to a SQLite database so devices survive
//! daemon restarts. Uses `rusqlite` with the `bundled` feature so no
//! system SQLite library is required.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS devices (
//!     mac TEXT PRIMARY KEY,
//!     ips TEXT NOT NULL DEFAULT '[]',
//!     hostname TEXT,
//!     first_seen TEXT NOT NULL,
//!     last_seen TEXT NOT NULL,
//!     packet_count INTEGER NOT NULL DEFAULT 0,
//!     bytes_sent INTEGER NOT NULL DEFAULT 0,
//!     bytes_received INTEGER NOT NULL DEFAULT 0,
//!     protocols TEXT NOT NULL DEFAULT '[]',
//!     vendor TEXT
//! );
//! ```
//!
//! # Concurrency
//!
//! `rusqlite::Connection` is `Send` but not `Sync`. We wrap it in a
//! `Mutex` to allow shared access from the capture pipeline and API
//! server. For the expected throughput (thousands of packets/sec, not
//! millions), this is more than adequate. A future optimization could
//! use a connection pool or WAL mode for concurrent reads.

use std::sync::Mutex;

use mac_address::MacAddress;
use rusqlite::{params, Connection};
use tracing::{info, trace};

use edgeshield_common::{Device, Protocol, StorageError, Timestamp};

use crate::store::DeviceStore;

/// A SQLite-backed device store.
///
/// Creates the database and schema on construction. All device operations
/// are serialized through a `Mutex<Connection>`.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path.
    ///
    /// If `path` is empty, this returns `None` (caller should fall back
    /// to `MemoryStore`).
    pub fn open(path: &str) -> Result<Option<Self>, StorageError> {
        if path.is_empty() {
            return Ok(None);
        }

        let conn = Connection::open(path)
            .map_err(|e| StorageError::Internal(format!("failed to open database: {}", e)))?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| StorageError::Internal(format!("failed to set pragmas: {}", e)))?;

        // Create schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ips TEXT NOT NULL DEFAULT '[]',
                hostname TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                protocols TEXT NOT NULL DEFAULT '[]',
                vendor TEXT
            );"
        ).map_err(|e| StorageError::Internal(format!("failed to create schema: {}", e)))?;

        info!(path = %path, "SQLite store opened");
        Ok(Some(Self { conn: Mutex::new(conn) }))
    }

    /// Serialize a set of IP addresses to a JSON string for storage.
    fn ips_to_json(ips: &std::collections::BTreeSet<std::net::IpAddr>) -> String {
        let v: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string())
    }

    /// Deserialize a JSON string back to a set of IP addresses.
    fn ips_from_json(s: &str) -> std::collections::BTreeSet<std::net::IpAddr> {
        let v: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        v.iter().filter_map(|ip| ip.parse().ok()).collect()
    }

    /// Serialize a set of protocols to a JSON string for storage.
    fn protocols_to_json(protocols: &std::collections::BTreeSet<Protocol>) -> String {
        let v: Vec<String> = protocols.iter().map(|p| p.to_string()).collect();
        serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string())
    }

    /// Deserialize a JSON string back to a set of protocols.
    fn protocols_from_json(s: &str) -> std::collections::BTreeSet<Protocol> {
        let v: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        v.iter().filter_map(|p| match p.as_str() {
            "ARP" => Some(Protocol::Arp),
            "IPv4" => Some(Protocol::Ipv4),
            "ICMP" => Some(Protocol::Icmp),
            "TCP" => Some(Protocol::Tcp),
            "UDP" => Some(Protocol::Udp),
            "DNS" => Some(Protocol::Dns),
            _ => {
                if let Some(n) = p.strip_prefix("UNKNOWN(").and_then(|s| s.strip_suffix(')')) {
                    n.parse().ok().map(Protocol::Other)
                } else {
                    None
                }
            }
        }).collect()
    }

    /// Convert a SQLite row to a Device.
    fn row_to_device(row: &rusqlite::Row) -> Result<Device, rusqlite::Error> {
        let mac_str: String = row.get(0)?;
        let ips_str: String = row.get(1)?;
        let hostname: Option<String> = row.get(2)?;
        let first_seen_str: String = row.get(3)?;
        let last_seen_str: String = row.get(4)?;
        let packet_count: u64 = row.get(5)?;
        let bytes_sent: u64 = row.get(6)?;
        let bytes_received: u64 = row.get(7)?;
        let protocols_str: String = row.get(8)?;
        let vendor: Option<String> = row.get(9)?;

        let mac = mac_str.parse::<MacAddress>()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let first_seen: Timestamp = first_seen_str.parse::<chrono::DateTime<chrono::Utc>>()
            .map(Timestamp::from_datetime)
            .unwrap_or_else(|_| Timestamp::now());
        let last_seen: Timestamp = last_seen_str.parse::<chrono::DateTime<chrono::Utc>>()
            .map(Timestamp::from_datetime)
            .unwrap_or_else(|_| Timestamp::now());

        Ok(Device {
            mac,
            ips: Self::ips_from_json(&ips_str),
            hostname,
            first_seen,
            last_seen,
            packet_count,
            bytes_sent,
            bytes_received,
            protocols: Self::protocols_from_json(&protocols_str),
            vendor,
        })
    }
}

impl DeviceStore for SqliteStore {
    fn get(&self, mac: &MacAddress) -> Result<Option<Device>, StorageError> {
        trace!(%mac, "sqlite store: get");
        let conn = self.conn.lock().map_err(|e| {
            StorageError::Internal(format!("mutex poisoned: {}", e))
        })?;

        let mut stmt = conn
            .prepare("SELECT mac, ips, hostname, first_seen, last_seen, packet_count, bytes_sent, bytes_received, protocols, vendor FROM devices WHERE mac = ?1")
            .map_err(|e| StorageError::Internal(format!("query prepare failed: {}", e)))?;

        let mut rows = stmt.query(params![mac.to_string()])
            .map_err(|e| StorageError::Internal(format!("query failed: {}", e)))?;

        match rows.next().map_err(|e| StorageError::Internal(format!("row fetch failed: {}", e)))? {
            Some(row) => Ok(Some(Self::row_to_device(row).map_err(|e| {
                StorageError::Internal(format!("row parse failed: {}", e))
            })?)),
            None => Ok(None),
        }
    }

    fn upsert(&self, device: Device) -> Result<(), StorageError> {
        trace!(mac = %device.mac, "sqlite store: upsert");
        let conn = self.conn.lock().map_err(|e| {
            StorageError::Internal(format!("mutex poisoned: {}", e))
        })?;

        conn.execute(
            "INSERT INTO devices (mac, ips, hostname, first_seen, last_seen, packet_count, bytes_sent, bytes_received, protocols, vendor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(mac) DO UPDATE SET
                ips = excluded.ips,
                hostname = excluded.hostname,
                last_seen = excluded.last_seen,
                packet_count = excluded.packet_count,
                bytes_sent = excluded.bytes_sent,
                bytes_received = excluded.bytes_received,
                protocols = excluded.protocols,
                vendor = excluded.vendor",
            params![
                device.mac.to_string(),
                Self::ips_to_json(&device.ips),
                device.hostname,
                device.first_seen.to_string(),
                device.last_seen.to_string(),
                device.packet_count,
                device.bytes_sent,
                device.bytes_received,
                Self::protocols_to_json(&device.protocols),
                device.vendor,
            ],
        ).map_err(|e| StorageError::Internal(format!("upsert failed: {}", e)))?;

        Ok(())
    }

    fn list(&self) -> Result<Vec<Device>, StorageError> {
        trace!("sqlite store: list");
        let conn = self.conn.lock().map_err(|e| {
            StorageError::Internal(format!("mutex poisoned: {}", e))
        })?;

        let mut stmt = conn
            .prepare("SELECT mac, ips, hostname, first_seen, last_seen, packet_count, bytes_sent, bytes_received, protocols, vendor FROM devices ORDER BY mac")
            .map_err(|e| StorageError::Internal(format!("query prepare failed: {}", e)))?;
        let rows = stmt
            .query_map([], Self::row_to_device)
            .map_err(|e| StorageError::Internal(format!("query failed: {}", e)))?;

        let mut devices = Vec::new();
        for row in rows {
            devices.push(row.map_err(|e| {
                StorageError::Internal(format!("row fetch failed: {}", e))
            })?);
        }

        Ok(devices)
    }

    fn count(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock().map_err(|e| {
            StorageError::Internal(format!("mutex poisoned: {}", e))
        })?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
            .map_err(|e| StorageError::Internal(format!("count query failed: {}", e)))?;

        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_device(mac_str: &str) -> Device {
        let mac = MacAddress::from_str(mac_str).unwrap();
        Device::new(mac)
    }

    fn open_test_store() -> SqliteStore {
        SqliteStore::open(":memory:").unwrap().unwrap()
    }

    #[test]
    fn test_sqlite_store_upsert_and_get() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = test_device("00:11:22:33:44:55");

        store.upsert(device.clone()).unwrap();
        let retrieved = store.get(&mac).unwrap().unwrap();
        assert_eq!(retrieved.mac, mac);
    }

    #[test]
    fn test_sqlite_store_get_nonexistent() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let result = store.get(&mac).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_sqlite_store_list() {
        let store = open_test_store();
        store.upsert(test_device("00:11:22:33:44:55")).unwrap();
        store.upsert(test_device("00:11:22:33:44:66")).unwrap();

        let devices = store.list().unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn test_sqlite_store_count() {
        let store = open_test_store();
        assert_eq!(store.count().unwrap(), 0);
        store.upsert(test_device("00:11:22:33:44:55")).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_sqlite_store_update_existing() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

        let mut device = test_device("00:11:22:33:44:55");
        device.record_sent(100, Protocol::Tcp);
        store.upsert(device).unwrap();

        let mut device2 = test_device("00:11:22:33:44:55");
        device2.record_sent(200, Protocol::Udp);
        store.upsert(device2).unwrap();

        let retrieved = store.get(&mac).unwrap().unwrap();
        // UPSERT merges: packet_count and bytes_sent should be from the second write
        assert_eq!(retrieved.packet_count, 1);
        assert_eq!(retrieved.bytes_sent, 200);
    }

    #[test]
    fn test_sqlite_store_roundtrip_protocols() {
        let store = open_test_store();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp);
        device.record_sent(200, Protocol::Udp);
        device.record_sent(300, Protocol::Dns);
        device.add_ip("192.168.1.10".parse().unwrap());

        store.upsert(device.clone()).unwrap();
        let retrieved = store.get(&mac).unwrap().unwrap();

        assert_eq!(retrieved.protocols.len(), 3);
        assert!(retrieved.protocols.contains(&Protocol::Tcp));
        assert!(retrieved.protocols.contains(&Protocol::Udp));
        assert!(retrieved.protocols.contains(&Protocol::Dns));
        assert!(retrieved.ips.contains(&"192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn test_sqlite_store_persistence() {
        // Open, write, close, reopen — verify data survives
        let path = format!("/tmp/edgeshield-test-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);

        {
            let store = SqliteStore::open(&path).unwrap().unwrap();
            store.upsert(test_device("00:11:22:33:44:55")).unwrap();
            store.upsert(test_device("00:11:22:33:44:66")).unwrap();
        } // connection drops, file persists

        {
            let store = SqliteStore::open(&path).unwrap().unwrap();
            assert_eq!(store.count().unwrap(), 2);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_serde_ips_roundtrip() {
        let mut ips = std::collections::BTreeSet::new();
        ips.insert("192.168.1.10".parse().unwrap());
        ips.insert("10.0.0.1".parse().unwrap());

        let json = SqliteStore::ips_to_json(&ips);
        let recovered = SqliteStore::ips_from_json(&json);
        assert_eq!(ips, recovered);
    }

    #[test]
    fn test_serde_protocols_roundtrip() {
        let mut protocols = std::collections::BTreeSet::new();
        protocols.insert(Protocol::Tcp);
        protocols.insert(Protocol::Dns);
        protocols.insert(Protocol::Other(42));

        let json = SqliteStore::protocols_to_json(&protocols);
        let recovered = SqliteStore::protocols_from_json(&json);
        assert_eq!(protocols, recovered);
    }
}
