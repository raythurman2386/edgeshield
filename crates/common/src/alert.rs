//! Alert types for EdgeShield's rule engine.
//!
//! An `Alert` is produced when a rule's condition is met. Alerts flow
//! from the rule engine to all configured notifiers (ntfy, MQTT,
//! webhook, email) and are persisted to the `alerts` SQLite table for
//! the `/alerts` API endpoint.
//!
//! # Lifecycle
//!
//! 1. The rule engine evaluates a `DiscoveryEvent` against all rules.
//! 2. If a rule matches (and its cooldown has elapsed), an `Alert` is
//!    created with a snapshot of the device at alert time.
//! 3. The alert is persisted to the `AlertStore` (assigned an `id`).
//! 4. The alert is sent to all notifiers via the fanout.
//! 5. A user can acknowledge the alert via `POST /alerts/:id/acknowledge`.
//!    Acknowledging suppresses future alerts for the same device/rule
//!    combination until the alert is un-acknowledged or deleted.

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::time::Timestamp;
use crate::types::Device;

/// The severity of an alert. Notifiers may use this to set priority
/// headers (e.g., ntfy `Priority`, email subject prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — no action required. Default for new-device
    /// alerts on a trusted network.
    Info,
    /// Warning — worth investigating. Default for device-offline
    /// alerts and new devices matching a vendor filter.
    Warning,
    /// Critical — act now. Reserved for future use (e.g., rogue DHCP
    /// server, MAC spoofing).
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!(
                "invalid severity '{s}': expected info, warning, or critical"
            )),
        }
    }
}

/// The type of event that triggered an alert. Used by notifiers and
/// the API to filter/route alerts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertEventType {
    /// A new MAC address was seen on the network for the first time.
    NewDevice,
    /// A previously-seen device has been silent for longer than the
    /// rule's threshold.
    DeviceOffline,
    /// A device started using a protocol it hadn't used before.
    ProtocolChange,
    /// A custom rule type (for user-defined conditions we don't have
    /// a dedicated variant for yet).
    Custom(String),
}

impl std::fmt::Display for AlertEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertEventType::NewDevice => write!(f, "new_device"),
            AlertEventType::DeviceOffline => write!(f, "device_offline"),
            AlertEventType::ProtocolChange => write!(f, "protocol_change"),
            AlertEventType::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// The unique identifier for an alert. Assigned by the `AlertStore`
/// when the alert is persisted. `0` means not yet persisted.
pub type AlertId = u64;

/// An alert produced by the rule engine.
///
/// This is the central data model for Phase 5. It carries enough
/// context for a notifier to render a useful message and for the API
/// to display the full alert history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique ID assigned by the `AlertStore`. `0` until persisted.
    pub id: AlertId,
    /// The name of the rule that fired (from the TOML config).
    pub rule_name: String,
    /// The severity of the alert.
    pub severity: Severity,
    /// The type of event that triggered the alert.
    pub event_type: AlertEventType,
    /// The MAC address of the device that triggered the alert.
    pub mac: MacAddress,
    /// A human-readable summary of the alert.
    pub message: String,
    /// A full snapshot of the device record at the time the alert
    /// fired. This is important because the device may change later
    /// (new IPs, new protocols), but the alert should show the state
    /// at the time it was raised.
    pub device_snapshot: Device,
    /// When the alert was raised.
    pub timestamp: Timestamp,
    /// Whether a user has acknowledged the alert. Acknowledged alerts
    /// suppress future alerts for the same device/rule combination.
    pub acknowledged: bool,
}

impl Alert {
    /// Create a new unpersisted alert (id = 0).
    #[must_use]
    pub fn new(
        rule_name: String,
        severity: Severity,
        event_type: AlertEventType,
        device: Device,
        message: String,
    ) -> Self {
        Self {
            id: 0,
            rule_name,
            severity,
            event_type,
            mac: device.mac,
            message,
            device_snapshot: device,
            timestamp: Timestamp::now(),
            acknowledged: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_device() -> Device {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        Device::new(mac)
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Info), "info");
        assert_eq!(format!("{}", Severity::Warning), "warning");
        assert_eq!(format!("{}", Severity::Critical), "critical");
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("info").unwrap(), Severity::Info);
        assert_eq!(Severity::from_str("warning").unwrap(), Severity::Warning);
        assert_eq!(Severity::from_str("warn").unwrap(), Severity::Warning);
        assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
        assert_eq!(
            Severity::from_str("CRITICAL").unwrap(),
            Severity::Critical
        );
    }

    #[test]
    fn test_severity_from_str_invalid() {
        assert!(Severity::from_str("urgent").is_err());
    }

    #[test]
    fn test_severity_serde_roundtrip() {
        let json = serde_json::to_string(&Severity::Warning).unwrap();
        assert_eq!(json, "\"warning\"");
        let recovered: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, Severity::Warning);
    }

    #[test]
    fn test_alert_event_type_display() {
        assert_eq!(format!("{}", AlertEventType::NewDevice), "new_device");
        assert_eq!(
            format!("{}", AlertEventType::DeviceOffline),
            "device_offline"
        );
        assert_eq!(
            format!("{}", AlertEventType::ProtocolChange),
            "protocol_change"
        );
        assert_eq!(
            format!("{}", AlertEventType::Custom("rogue_dhcp".to_string())),
            "rogue_dhcp"
        );
    }

    #[test]
    fn test_alert_new() {
        let device = sample_device();
        let alert = Alert::new(
            "new-device-alert".to_string(),
            Severity::Info,
            AlertEventType::NewDevice,
            device.clone(),
            "New device 00:11:22:33:44:55 discovered".to_string(),
        );
        assert_eq!(alert.id, 0);
        assert_eq!(alert.rule_name, "new-device-alert");
        assert_eq!(alert.severity, Severity::Info);
        assert_eq!(alert.event_type, AlertEventType::NewDevice);
        assert_eq!(alert.mac, device.mac);
        assert!(!alert.acknowledged);
    }

    #[test]
    fn test_alert_serde_roundtrip() {
        let device = sample_device();
        let alert = Alert::new(
            "device-offline".to_string(),
            Severity::Warning,
            AlertEventType::DeviceOffline,
            device,
            "Device silent for 30 min".to_string(),
        );
        let json = serde_json::to_string(&alert).unwrap();
        let recovered: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.rule_name, alert.rule_name);
        assert_eq!(recovered.severity, alert.severity);
        assert_eq!(recovered.event_type, alert.event_type);
        assert_eq!(recovered.mac, alert.mac);
        assert_eq!(recovered.message, alert.message);
    }
}