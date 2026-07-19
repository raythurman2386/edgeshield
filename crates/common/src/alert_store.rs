//! Alert storage trait — the abstraction boundary for alert persistence.
//!
//! This trait lives in `edgeshield-common` (not `edgeshield-rules`) to
//! avoid a circular dependency: `storage` needs to implement the
//! trait, but `rules` needs `discovery` which needs `storage`. By
//! keeping the trait in `common`, both `rules` and `storage` can
//! depend on `common` without a cycle.
//!
//! Implementations:
//! - `InMemoryAlertStore` (in `edgeshield-rules`) — for tests
//! - `SqliteAlertStore` (in `edgeshield-storage`) — for production

use mac_address::MacAddress;

use crate::{Alert, AlertId, Severity, StorageError};

/// A storage backend for alert records.
pub trait AlertStore: Send + Sync {
    /// Insert a new alert. Returns the assigned alert ID.
    fn insert_alert(&self, alert: &Alert) -> Result<AlertId, StorageError>;

    /// List alerts, optionally filtered. Returns most-recent first.
    fn list_alerts(&self, filter: AlertFilter) -> Result<Vec<Alert>, StorageError>;

    /// Get a single alert by ID.
    fn get_alert(&self, id: AlertId) -> Result<Option<Alert>, StorageError>;

    /// Mark an alert as acknowledged. Returns an error if the alert
    /// doesn't exist.
    fn acknowledge_alert(&self, id: AlertId) -> Result<(), StorageError>;

    /// Delete an alert by ID.
    fn delete_alert(&self, id: AlertId) -> Result<(), StorageError>;

    /// Check if there's an acknowledged alert for the given
    /// rule/device combination. Used by the rule engine for
    /// acknowledgment-based suppression.
    fn is_acknowledged(&self, rule_name: &str, mac: &MacAddress) -> Result<bool, StorageError>;

    /// Get the total alert count.
    fn count_alerts(&self) -> Result<usize, StorageError>;
}

/// Filter for listing alerts. All fields are optional.
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    /// Filter by severity (exact match).
    pub severity: Option<Severity>,
    /// Filter by acknowledged status.
    pub acknowledged: Option<bool>,
    /// Filter by rule name (exact match).
    pub rule_name: Option<String>,
    /// Maximum number of alerts to return. `None` = no limit.
    pub limit: Option<usize>,
}
