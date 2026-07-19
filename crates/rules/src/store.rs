//! Alert storage — in-memory implementation and re-exports.
//!
//! The `AlertStore` trait and `AlertFilter` live in `edgeshield-common`
//! to avoid a circular dependency between `edgeshield-rules` and
//! `edgeshield-storage`. This module provides the in-memory
//! implementation (for tests) and re-exports the trait.

pub use edgeshield_common::{AlertFilter, AlertStore};

use std::sync::Arc;

use dashmap::DashMap;
use edgeshield_common::{Alert, AlertId, StorageError};
use mac_address::MacAddress;

/// An in-memory `AlertStore` backed by `DashMap`. Used for tests and
/// as a fallback when SQLite is not configured.
pub struct InMemoryAlertStore {
    alerts: Arc<DashMap<AlertId, Alert>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl InMemoryAlertStore {
    /// Create a new empty in-memory alert store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(DashMap::new()),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }
}

impl Default for InMemoryAlertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertStore for InMemoryAlertStore {
    fn insert_alert(&self, alert: &Alert) -> Result<AlertId, StorageError> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut alert = alert.clone();
        alert.id = id;
        self.alerts.insert(id, alert);
        Ok(id)
    }

    fn list_alerts(&self, filter: AlertFilter) -> Result<Vec<Alert>, StorageError> {
        let mut alerts: Vec<Alert> = self
            .alerts
            .iter()
            .map(|r| r.value().clone())
            .filter(|a| {
                if let Some(sev) = filter.severity
                    && a.severity != sev
                {
                    return false;
                }
                if let Some(ack) = filter.acknowledged
                    && a.acknowledged != ack
                {
                    return false;
                }
                if let Some(ref name) = filter.rule_name
                    && a.rule_name != *name
                {
                    return false;
                }
                true
            })
            .collect();

        // Most-recent first (by timestamp descending).
        alerts.sort_by_key(|b| std::cmp::Reverse(b.timestamp));

        if let Some(limit) = filter.limit {
            alerts.truncate(limit);
        }
        Ok(alerts)
    }

    fn get_alert(&self, id: AlertId) -> Result<Option<Alert>, StorageError> {
        Ok(self.alerts.get(&id).map(|r| r.value().clone()))
    }

    fn acknowledge_alert(&self, id: AlertId) -> Result<(), StorageError> {
        if let Some(mut alert) = self.alerts.get_mut(&id) {
            alert.acknowledged = true;
            Ok(())
        } else {
            Err(StorageError::Internal(format!("alert {id} not found")))
        }
    }

    fn delete_alert(&self, id: AlertId) -> Result<(), StorageError> {
        self.alerts.remove(&id);
        Ok(())
    }

    fn is_acknowledged(&self, rule_name: &str, mac: &MacAddress) -> Result<bool, StorageError> {
        Ok(self.alerts.iter().any(|r| {
            r.value().rule_name == rule_name && r.value().mac == *mac && r.value().acknowledged
        }))
    }

    fn count_alerts(&self) -> Result<usize, StorageError> {
        Ok(self.alerts.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::{AlertEventType, Device, Severity};
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

    #[test]
    fn test_insert_and_get() {
        let store = InMemoryAlertStore::new();
        let alert = sample_alert("new-device", "00:11:22:33:44:55");
        let id = store.insert_alert(&alert).unwrap();
        assert_eq!(id, 1);
        let retrieved = store.get_alert(id).unwrap().unwrap();
        assert_eq!(retrieved.rule_name, "new-device");
    }

    #[test]
    fn test_list_alerts_most_recent_first() {
        let store = InMemoryAlertStore::new();
        let a1 = sample_alert("rule-a", "00:11:22:33:44:55");
        let a2 = sample_alert("rule-b", "00:11:22:33:44:66");
        store.insert_alert(&a1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.insert_alert(&a2).unwrap();

        let alerts = store.list_alerts(AlertFilter::default()).unwrap();
        assert_eq!(alerts.len(), 2);
        // Most recent first.
        assert_eq!(alerts[0].rule_name, "rule-b");
    }

    #[test]
    fn test_list_alerts_filter_by_severity() {
        let store = InMemoryAlertStore::new();
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
    fn test_acknowledge_and_suppression() {
        let store = InMemoryAlertStore::new();
        let alert = sample_alert("new-device", "00:11:22:33:44:55");
        let id = store.insert_alert(&alert).unwrap();

        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        assert!(!store.is_acknowledged("new-device", &mac).unwrap());

        store.acknowledge_alert(id).unwrap();
        assert!(store.is_acknowledged("new-device", &mac).unwrap());
    }

    #[test]
    fn test_delete_alert() {
        let store = InMemoryAlertStore::new();
        let alert = sample_alert("new-device", "00:11:22:33:44:55");
        let id = store.insert_alert(&alert).unwrap();
        assert_eq!(store.count_alerts().unwrap(), 1);

        store.delete_alert(id).unwrap();
        assert_eq!(store.count_alerts().unwrap(), 0);
        assert!(store.get_alert(id).unwrap().is_none());
    }

    #[test]
    fn test_list_alerts_limit() {
        let store = InMemoryAlertStore::new();
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
