//! Storage abstraction for EdgeShield.
//!
//! This module defines the `DeviceStore` trait and provides an
//! in-memory implementation backed by `DashMap`.
//!
//! # Design
//!
//! The `DeviceStore` trait abstracts the storage backend. The MVP
//! uses an in-memory `DashMap` for lock-free concurrent access.
//! Future backends (SQLite, SurrealDB) can implement the same trait
//! without changing the discovery or API layers.

use std::sync::Arc;

use dashmap::DashMap;
use mac_address::MacAddress;
use tracing::trace;

use edgeshield_common::{Device, StorageError};

/// A storage backend for device records.
///
/// This trait is the abstraction boundary between the discovery layer
/// and persistence. The MVP only has an in-memory implementation, but
/// the trait exists from day one to guide the architecture.
pub trait DeviceStore: Send + Sync {
    /// Get a device by MAC address.
    fn get(&self, mac: &MacAddress) -> Result<Option<Device>, StorageError>;

    /// Insert or update a device.
    fn upsert(&self, device: Device) -> Result<(), StorageError>;

    /// List all devices.
    fn list(&self) -> Result<Vec<Device>, StorageError>;

    /// Get the total number of devices.
    fn count(&self) -> Result<usize, StorageError>;
}

/// An in-memory device store backed by `DashMap`.
///
/// # Concurrency
///
/// `DashMap` provides lock-free concurrent access via sharded internal
/// locks. Reads and writes to different MAC addresses can proceed in
/// parallel. This is ideal for our use case where the capture pipeline
/// and API server access the device table concurrently.
#[derive(Clone)]
pub struct MemoryStore {
    devices: Arc<DashMap<MacAddress, Device>>,
}

impl MemoryStore {
    /// Create a new empty memory store.
    pub fn new() -> Self {
        Self {
            devices: Arc::new(DashMap::new()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceStore for MemoryStore {
    fn get(&self, mac: &MacAddress) -> Result<Option<Device>, StorageError> {
        trace!(%mac, "memory store: get");
        Ok(self.devices.get(mac).map(|r| r.value().clone()))
    }

    fn upsert(&self, device: Device) -> Result<(), StorageError> {
        trace!(mac = %device.mac, "memory store: upsert");
        self.devices.insert(device.mac, device);
        Ok(())
    }

    fn list(&self) -> Result<Vec<Device>, StorageError> {
        trace!("memory store: list");
        let mut devices: Vec<Device> = self.devices.iter().map(|r| r.value().clone()).collect();
        devices.sort_by_key(|d| d.mac.to_string());
        Ok(devices)
    }

    fn count(&self) -> Result<usize, StorageError> {
        Ok(self.devices.len())
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

    #[test]
    fn test_memory_store_upsert_and_get() {
        let store = MemoryStore::new();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = test_device("00:11:22:33:44:55");

        store.upsert(device.clone()).unwrap();
        let retrieved = store.get(&mac).unwrap().unwrap();
        assert_eq!(retrieved.mac, mac);
    }

    #[test]
    fn test_memory_store_get_nonexistent() {
        let store = MemoryStore::new();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let result = store.get(&mac).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_memory_store_list() {
        let store = MemoryStore::new();
        store.upsert(test_device("00:11:22:33:44:55")).unwrap();
        store.upsert(test_device("00:11:22:33:44:66")).unwrap();

        let devices = store.list().unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn test_memory_store_count() {
        let store = MemoryStore::new();
        assert_eq!(store.count().unwrap(), 0);
        store.upsert(test_device("00:11:22:33:44:55")).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_memory_store_update_existing() {
        let store = MemoryStore::new();
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

        let mut device = test_device("00:11:22:33:44:55");
        device.record_sent(
            100,
            edgeshield_common::Protocol::Tcp,
            edgeshield_common::Timestamp::now(),
        );
        store.upsert(device).unwrap();

        let mut device2 = test_device("00:11:22:33:44:55");
        device2.record_sent(
            200,
            edgeshield_common::Protocol::Udp,
            edgeshield_common::Timestamp::now(),
        );
        store.upsert(device2).unwrap();

        let retrieved = store.get(&mac).unwrap().unwrap();
        // The second upsert replaces the first (DashMap insert)
        assert_eq!(retrieved.packet_count, 1);
        assert_eq!(retrieved.bytes_sent, 200);
    }
}
