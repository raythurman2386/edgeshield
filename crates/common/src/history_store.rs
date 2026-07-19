//! Device history storage trait — the abstraction boundary for
//! device history snapshots.
//!
//! This trait lives in `edgeshield-common` (same pattern as
//! `AlertStore`) to avoid circular dependencies. The SQLite
//! implementation lives in `edgeshield-storage`.
//!
//! # Design
//!
//! The `devices` table tracks the *current* state of each device
//! (updated on every packet via UPSERT). The `device_history` table
//! tracks *daily snapshots* — one row per device per day, reflecting
//! the device's state at the time of the last snapshot for that day.
//! This enables trend analysis: "how has this device's packet count
//! grown day over day?"

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::{Device, Protocol, StorageError, Timestamp};

/// A snapshot of a device's state at a point in time, stored in the
/// `device_history` table.
///
/// This is a denormalized copy of the `Device` struct at snapshot
/// time, plus the snapshot date and timestamp. We store a full copy
/// rather than a delta because:
/// - SQLite handles the storage cost trivially (a few KB per row).
/// - Querying is simpler (no need to reconstruct state from deltas).
/// - The `UNIQUE(mac, snapshot_date)` constraint means at most one
///   row per device per day, so the table grows linearly with
///   `devices × days`, not `devices × packets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHistorySnapshot {
    /// The MAC address of the device.
    pub mac: MacAddress,
    /// The date of the snapshot in `YYYY-MM-DD` format. One row per
    /// device per day (upserted on each snapshot).
    pub snapshot_date: String,
    /// The full ISO 8601 timestamp of the last snapshot for this day.
    pub snapshot_timestamp: Timestamp,
    /// Observed IP addresses at snapshot time.
    pub ips: BTreeSet<IpAddr>,
    /// Hostname at snapshot time.
    pub hostname: Option<String>,
    /// OUI vendor at snapshot time.
    pub vendor: Option<String>,
    /// DHCP vendor class at snapshot time.
    pub dhcp_vendor_class: Option<String>,
    /// Total packets observed at snapshot time.
    pub packet_count: u64,
    /// Total bytes sent at snapshot time.
    pub bytes_sent: u64,
    /// Total bytes received at snapshot time.
    pub bytes_received: u64,
    /// Protocols detected at snapshot time.
    pub protocols: BTreeSet<Protocol>,
    /// Per-protocol packet counts at snapshot time.
    pub protocol_stats: BTreeMap<Protocol, u64>,
    /// When the device was first seen.
    pub first_seen: Timestamp,
    /// When the device was last seen at snapshot time.
    pub last_seen: Timestamp,
}

impl DeviceHistorySnapshot {
    /// Create a snapshot from a `Device` and a snapshot date.
    ///
    /// The `snapshot_date` should be in `YYYY-MM-DD` format. The
    /// `snapshot_timestamp` is set to the current time.
    #[must_use]
    pub fn from_device(device: &Device, snapshot_date: String) -> Self {
        Self {
            mac: device.mac,
            snapshot_date,
            snapshot_timestamp: Timestamp::now(),
            ips: device.ips.clone(),
            hostname: device.hostname.clone(),
            vendor: device.vendor.clone(),
            dhcp_vendor_class: device.dhcp_vendor_class.clone(),
            packet_count: device.packet_count,
            bytes_sent: device.bytes_sent,
            bytes_received: device.bytes_received,
            protocols: device.protocols.clone(),
            protocol_stats: device.protocol_stats.clone(),
            first_seen: device.first_seen,
            last_seen: device.last_seen,
        }
    }
}

/// A storage backend for device history snapshots.
pub trait DeviceHistoryStore: Send + Sync {
    /// Insert or update a daily snapshot for a device. If a snapshot
    /// for the same device and date already exists, it is replaced
    /// (upsert).
    fn insert_snapshot(&self, snapshot: &DeviceHistorySnapshot) -> Result<(), StorageError>;

    /// List history snapshots for a device, optionally filtered by
    /// date range. Returns snapshots ordered by `snapshot_date`
    /// ascending.
    ///
    /// # Arguments
    ///
    /// * `mac` — The device MAC address.
    /// * `from` — Optional start date (`YYYY-MM-DD`, inclusive). `None` = no lower bound.
    /// * `to` — Optional end date (`YYYY-MM-DD`, inclusive). `None` = no upper bound.
    /// * `limit` — Optional maximum number of snapshots to return.
    fn list_history(
        &self,
        mac: &MacAddress,
        from: Option<&str>,
        to: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<DeviceHistorySnapshot>, StorageError>;

    /// Delete all snapshots older than the given date. Returns the
    /// number of deleted rows.
    ///
    /// # Arguments
    ///
    /// * `before_date` — Delete rows where `snapshot_date < before_date` (`YYYY-MM-DD`).
    fn delete_before(&self, before_date: &str) -> Result<usize, StorageError>;

    /// Run incremental vacuum to reclaim freed pages. This is a no-op
    /// if `auto_vacuum` is not enabled on the database.
    fn vacuum(&self) -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_device() -> Device {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp, Timestamp::now());
        device.add_ip("192.168.1.10".parse().unwrap());
        device.vendor = Some("TP-Link".to_string());
        device.hostname = Some("living-room-plug".to_string());
        device
    }

    #[test]
    fn test_snapshot_from_device() {
        let device = sample_device();
        let snapshot = DeviceHistorySnapshot::from_device(&device, "2026-07-19".to_string());
        assert_eq!(snapshot.mac, device.mac);
        assert_eq!(snapshot.snapshot_date, "2026-07-19");
        assert_eq!(snapshot.packet_count, 1);
        assert_eq!(snapshot.bytes_sent, 100);
        assert_eq!(snapshot.hostname.as_deref(), Some("living-room-plug"));
        assert_eq!(snapshot.vendor.as_deref(), Some("TP-Link"));
        assert!(snapshot.ips.contains(&"192.168.1.10".parse().unwrap()));
        assert!(snapshot.protocols.contains(&Protocol::Tcp));
    }

    #[test]
    fn test_snapshot_serde_roundtrip() {
        let device = sample_device();
        let snapshot = DeviceHistorySnapshot::from_device(&device, "2026-07-19".to_string());
        let json = serde_json::to_string(&snapshot).unwrap();
        let recovered: DeviceHistorySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.mac, snapshot.mac);
        assert_eq!(recovered.snapshot_date, snapshot.snapshot_date);
        assert_eq!(recovered.packet_count, snapshot.packet_count);
        assert_eq!(recovered.hostname, snapshot.hostname);
        assert_eq!(recovered.protocols, snapshot.protocols);
    }

    #[test]
    fn test_snapshot_independent_of_device_changes() {
        // A snapshot should be independent of later changes to the device.
        let device = sample_device();
        let snapshot = DeviceHistorySnapshot::from_device(&device, "2026-07-19".to_string());
        let mut device = device;
        device.record_sent(999, Protocol::Udp, Timestamp::now());
        device.hostname = Some("changed".to_string());
        // The snapshot should be unchanged.
        assert_eq!(snapshot.packet_count, 1);
        assert_eq!(snapshot.hostname.as_deref(), Some("living-room-plug"));
    }
}
