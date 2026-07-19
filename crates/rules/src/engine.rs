//! Rule engine for EdgeShield.
//!
//! Consumes `DiscoveryEvent`s from the discovery pipeline, evaluates
//! each configured rule against the event, and emits `Alert`s when a
//! rule's condition is met (and its cooldown has elapsed).
//!
//! # Architecture
//!
//! ```text
//! DiscoveryEvent rx → RuleEngine → Alert tx → NotifierFanout
//!                                      ↓
//!                                  AlertStore
//! ```
//!
//! The rule engine owns the `DiscoveryEvent` receiver. It is the
//! single consumer of discovery events. Notifiers no longer consume
//! `DiscoveryEvent` directly — they consume `Alert`s from the engine's
//! output channel.
//!
//! # Cooldown
//!
//! Each rule has a `cooldown_seconds` field. After a rule fires for a
//! given device, it will not fire again for that device until the
//! cooldown elapses. This prevents alert floods when a chatty device
//! triggers a rule repeatedly. Cooldown is tracked per-device per-rule.
//!
//! # Acknowledgment suppression
//!
//! If an alert for a device/rule combination has been acknowledged
//! (via `POST /alerts/:id/acknowledge`), the rule engine suppresses
//! future alerts for that combination. The suppression is lifted when
//! the alert is deleted or un-acknowledged. This is checked against
//! the `AlertStore` at fire time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edgeshield_common::{Alert, AlertEventType, Device, Severity};
use edgeshield_discovery::discovery::DiscoveryEvent;
use mac_address::MacAddress;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

use crate::store::AlertStore;

/// A rule condition — the predicate that determines when a rule fires.
#[derive(Debug, Clone)]
pub enum RuleCondition {
    /// Fires for every new device (any MAC not previously seen).
    NewDevice,
    /// Fires for a new device whose OUI vendor matches the given
    /// string (case-insensitive substring match).
    NewDeviceByVendor(String),
    /// Fires for a new device whose MAC address starts with the given
    /// prefix (e.g., "8C:85:90" for Apple). The prefix is compared
    /// case-insensitively against the colon-separated MAC form.
    NewDeviceByMacPrefix(String),
    /// Fires when a known device has been silent for at least
    /// `after_seconds`. Evaluated by the background scanner, not
    /// per-packet.
    DeviceOffline { after_seconds: u64 },
    /// Fires when a device starts using a protocol it hadn't used
    /// before. The alert carries the new protocol in the message.
    ProtocolChange,
}

/// A user-configured rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Human-readable name (from TOML config). Used in alert
    /// `rule_name` and in logs.
    pub name: String,
    /// Whether the rule is enabled. Disabled rules are skipped.
    pub enabled: bool,
    /// The condition that triggers the rule.
    pub condition: RuleCondition,
    /// The severity assigned to alerts produced by this rule.
    pub severity: Severity,
    /// Minimum seconds between alerts for the same device from this
    /// rule. `0` means no cooldown (fire on every match).
    pub cooldown_seconds: u64,
    /// Per-device last-fired timestamps for cooldown tracking.
    /// Not serialized — runtime state only.
    last_fired: HashMap<MacAddress, Instant>,
}

impl Rule {
    /// Create a new rule with empty cooldown state.
    #[must_use]
    pub fn new(
        name: String,
        enabled: bool,
        condition: RuleCondition,
        severity: Severity,
        cooldown_seconds: u64,
    ) -> Self {
        Self {
            name,
            enabled,
            condition,
            severity,
            cooldown_seconds,
            last_fired: HashMap::new(),
        }
    }

    /// Check if this rule can fire for `mac` right now (cooldown
    /// elapsed). If so, record the fire time and return true.
    fn check_and_record_cooldown(&mut self, mac: MacAddress) -> bool {
        if self.cooldown_seconds == 0 {
            return true;
        }
        let now = Instant::now();
        if let Some(&last) = self.last_fired.get(&mac)
            && now.duration_since(last) < Duration::from_secs(self.cooldown_seconds)
        {
            trace!(rule = %self.name, %mac, "rule on cooldown");
            return false;
        }
        self.last_fired.insert(mac, now);
        true
    }
}

/// The rule engine — evaluates rules against discovery events and
/// emits alerts.
pub struct RuleEngine {
    rules: Vec<Rule>,
    event_rx: mpsc::Receiver<DiscoveryEvent>,
    alert_tx: mpsc::Sender<Alert>,
    alert_store: Arc<dyn AlertStore>,
}

impl RuleEngine {
    /// Create a new rule engine.
    ///
    /// Takes ownership of the `DiscoveryEvent` receiver — the engine
    /// is the single consumer of discovery events.
    #[must_use]
    pub fn new(
        rules: Vec<Rule>,
        event_rx: mpsc::Receiver<DiscoveryEvent>,
        alert_tx: mpsc::Sender<Alert>,
        alert_store: Arc<dyn AlertStore>,
    ) -> Self {
        Self {
            rules,
            event_rx,
            alert_tx,
            alert_store,
        }
    }

    /// Run the rule engine loop until the event sender is dropped.
    pub async fn run(mut self) {
        info!(rule_count = self.rules.len(), "rule engine starting");
        loop {
            let Some(event) = self.event_rx.recv().await else {
                info!("event channel closed; rule engine stopping");
                break;
            };
            if let Err(e) = self.process_event(event).await {
                warn!(error = %e, "rule engine error processing event");
            }
        }
        info!("rule engine stopped");
    }

    /// Process a single discovery event against all rules.
    async fn process_event(
        &mut self,
        event: DiscoveryEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Collect alerts from all rules first, then fire them. We
        // split the mutable borrow of `self.rules` (for cooldown
        // state) from the immutable borrow of `self.alert_store` by
        // snapshotting the alert_store reference before the loop.
        let alert_store = self.alert_store.clone();
        let mut alerts = Vec::new();
        for rule in &mut self.rules {
            if !rule.enabled {
                continue;
            }
            if let Some(alert) = evaluate_rule(rule, &event, &alert_store)? {
                alerts.push(alert);
            }
        }
        for alert in alerts {
            self.fire_alert(alert).await?;
        }
        Ok(())
    }

    /// Send an alert to the notifier fanout.
    async fn fire_alert(
        &self,
        alert: Alert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            rule = %alert.rule_name,
            mac = %alert.mac,
            severity = %alert.severity,
            "alert fired"
        );
        if self.alert_tx.send(alert).await.is_err() {
            warn!("alert channel closed; notifier may have stopped");
        }
        Ok(())
    }
}

/// Evaluate a single rule against an event. Returns `Some(alert)` if
/// the rule matches and cooldown/acknowledgment checks pass.
///
/// This is a free function (not a method) to avoid borrow conflicts
/// between `&mut self.rules` (for cooldown state) and `&self.alert_store`.
fn evaluate_rule(
    rule: &mut Rule,
    event: &DiscoveryEvent,
    alert_store: &Arc<dyn AlertStore>,
) -> Result<Option<Alert>, Box<dyn std::error::Error + Send + Sync>> {
    let (device, event_type) = match event {
        DiscoveryEvent::DeviceDiscovered(d) => (d.clone(), AlertEventType::NewDevice),
        DiscoveryEvent::DeviceUpdated(d) => (d.clone(), AlertEventType::ProtocolChange),
        DiscoveryEvent::DeviceOffline(d) => (d.clone(), AlertEventType::DeviceOffline),
    };

    let matches = match &rule.condition {
        RuleCondition::NewDevice => matches!(event, DiscoveryEvent::DeviceDiscovered(_)),
        RuleCondition::NewDeviceByVendor(vendor_filter) => {
            matches!(event, DiscoveryEvent::DeviceDiscovered(_))
                && device
                    .vendor
                    .as_deref()
                    .map(|v| {
                        v.to_ascii_lowercase()
                            .contains(&vendor_filter.to_ascii_lowercase())
                    })
                    .unwrap_or(false)
        }
        RuleCondition::NewDeviceByMacPrefix(prefix) => {
            matches!(event, DiscoveryEvent::DeviceDiscovered(_))
                && mac_matches_prefix(&device.mac, prefix)
        }
        RuleCondition::DeviceOffline { .. } => {
            matches!(event, DiscoveryEvent::DeviceOffline(_))
        }
        RuleCondition::ProtocolChange => {
            matches!(event, DiscoveryEvent::DeviceUpdated(_))
        }
    };

    if !matches {
        return Ok(None);
    }

    // Cooldown check (mutates rule state).
    if !rule.check_and_record_cooldown(device.mac) {
        return Ok(None);
    }

    // Snapshot the fields we need from the rule so we don't hold
    // a borrow of `rule` (which is borrowed from the caller's
    // `self.rules`) when we call `alert_store` below.
    let rule_name = rule.name.clone();
    let rule_severity = rule.severity;

    // Acknowledgment suppression: if there's an acknowledged alert
    // for this device/rule combo, suppress.
    if alert_store.is_acknowledged(&rule_name, &device.mac)? {
        trace!(rule = %rule_name, mac = %device.mac, "alert suppressed (acknowledged)");
        return Ok(None);
    }

    let message = build_message(&rule_name, &device, &event_type);
    let mut alert = Alert::new(rule_name, rule_severity, event_type, device, message);

    // Persist the alert and assign its ID.
    match alert_store.insert_alert(&alert) {
        Ok(id) => alert.id = id,
        Err(e) => {
            warn!(error = %e, "failed to persist alert; delivering unpersisted");
        }
    }

    Ok(Some(alert))
}

/// Check if a MAC address starts with the given prefix.
///
/// The prefix is compared case-insensitively against the
/// colon-separated MAC form (e.g., "8C:85:90" matches
/// "8c:85:90:12:34:56"). Partial prefixes (fewer than 6 bytes) are
/// supported.
fn mac_matches_prefix(mac: &MacAddress, prefix: &str) -> bool {
    let mac_str = mac.to_string().to_ascii_lowercase();
    mac_str.starts_with(&prefix.to_ascii_lowercase())
}

/// Build a human-readable alert message from the rule name, device,
/// and event type.
fn build_message(rule_name: &str, device: &Device, event_type: &AlertEventType) -> String {
    let _ = rule_name; // available for future templating.
    let name = device
        .hostname
        .clone()
        .or_else(|| device.vendor.clone())
        .unwrap_or_else(|| device.mac.to_string());
    match event_type {
        AlertEventType::NewDevice => {
            format!("New device discovered: {name} ({})", device.mac)
        }
        AlertEventType::DeviceOffline => {
            format!("Device offline: {name} ({})", device.mac)
        }
        AlertEventType::ProtocolChange => {
            format!("Protocol change for {name} ({})", device.mac)
        }
        AlertEventType::Custom(s) => format!("{s}: {name} ({})", device.mac),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryAlertStore;
    use std::str::FromStr;

    fn sample_device() -> Device {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.vendor = Some("TP-Link Technologies".to_string());
        device.hostname = Some("living-room-plug".to_string());
        device
    }

    fn setup_engine(
        rules: Vec<Rule>,
    ) -> (
        RuleEngine,
        mpsc::Sender<DiscoveryEvent>,
        mpsc::Receiver<Alert>,
    ) {
        let alert_store = Arc::new(InMemoryAlertStore::new()) as Arc<dyn AlertStore>;
        let (event_tx, event_rx) = mpsc::channel::<DiscoveryEvent>(100);
        let (alert_tx, alert_rx) = mpsc::channel::<Alert>(100);
        let engine = RuleEngine::new(rules, event_rx, alert_tx, alert_store);
        (engine, event_tx, alert_rx)
    }

    #[test]
    fn test_mac_matches_prefix_case_insensitive() {
        let mac = MacAddress::from_str("8C:85:90:12:34:56").unwrap();
        assert!(mac_matches_prefix(&mac, "8C:85:90"));
        assert!(mac_matches_prefix(&mac, "8c:85:90"));
        assert!(mac_matches_prefix(&mac, "8c:85"));
        assert!(!mac_matches_prefix(&mac, "8c:86"));
    }

    #[tokio::test]
    async fn test_new_device_rule_fires() {
        let rule = Rule::new(
            "new-device".to_string(),
            true,
            RuleCondition::NewDevice,
            Severity::Info,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device();

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();

        let alert = alert_rx.recv().await.expect("should receive alert");
        assert_eq!(alert.rule_name, "new-device");
        assert_eq!(alert.severity, Severity::Info);
        assert_eq!(alert.event_type, AlertEventType::NewDevice);
    }

    #[tokio::test]
    async fn test_disabled_rule_does_not_fire() {
        let rule = Rule::new(
            "disabled".to_string(),
            false,
            RuleCondition::NewDevice,
            Severity::Info,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device();

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();

        // No alert should arrive (channel stays open but empty).
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_new_device_by_vendor_fires_on_match() {
        let rule = Rule::new(
            "new-iot".to_string(),
            true,
            RuleCondition::NewDeviceByVendor("TP-Link".to_string()),
            Severity::Warning,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device(); // vendor = "TP-Link Technologies"

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();

        let alert = alert_rx.recv().await.expect("should receive alert");
        assert_eq!(alert.rule_name, "new-iot");
        assert_eq!(alert.severity, Severity::Warning);
    }

    #[tokio::test]
    async fn test_new_device_by_vendor_no_match() {
        let rule = Rule::new(
            "new-apple".to_string(),
            true,
            RuleCondition::NewDeviceByVendor("Apple".to_string()),
            Severity::Info,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device(); // vendor = "TP-Link Technologies"

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_new_device_by_mac_prefix_fires() {
        let rule = Rule::new(
            "new-apple-mac".to_string(),
            true,
            RuleCondition::NewDeviceByMacPrefix("00:11:22".to_string()),
            Severity::Info,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device(); // mac = 00:11:22:33:44:55

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();

        let alert = alert_rx.recv().await.expect("should receive alert");
        assert_eq!(alert.rule_name, "new-apple-mac");
    }

    #[tokio::test]
    async fn test_device_offline_rule_fires() {
        let rule = Rule::new(
            "offline-30min".to_string(),
            true,
            RuleCondition::DeviceOffline {
                after_seconds: 1800,
            },
            Severity::Warning,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device();

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceOffline(device))
            .await
            .unwrap();

        let alert = alert_rx.recv().await.expect("should receive alert");
        assert_eq!(alert.event_type, AlertEventType::DeviceOffline);
        assert_eq!(alert.severity, Severity::Warning);
    }

    #[tokio::test]
    async fn test_cooldown_suppresses_second_alert() {
        let rule = Rule::new(
            "cooldown-test".to_string(),
            true,
            RuleCondition::NewDevice,
            Severity::Info,
            3600, // 1 hour cooldown
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);

        tokio::spawn(async move {
            engine.run().await;
        });

        // First event fires.
        let device = sample_device();
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device.clone()))
            .await
            .unwrap();
        let alert = alert_rx.recv().await.expect("first alert should arrive");
        assert_eq!(alert.rule_name, "cooldown-test");

        // Second event for the same device is suppressed by cooldown.
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_acknowledgment_suppresses_alert() {
        let alert_store = Arc::new(InMemoryAlertStore::new()) as Arc<dyn AlertStore>;
        let (event_tx, event_rx) = mpsc::channel::<DiscoveryEvent>(100);
        let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(100);

        let rule = Rule::new(
            "ack-test".to_string(),
            true,
            RuleCondition::NewDevice,
            Severity::Info,
            0,
        );
        let engine = RuleEngine::new(vec![rule], event_rx, alert_tx, alert_store.clone());
        tokio::spawn(async move {
            engine.run().await;
        });

        let device = sample_device();
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device.clone()))
            .await
            .unwrap();
        let alert = alert_rx.recv().await.expect("first alert");
        // Acknowledge it.
        alert_store.acknowledge_alert(alert.id).unwrap();

        // Second event for the same device/rule is suppressed.
        event_tx
            .send(DiscoveryEvent::DeviceDiscovered(device))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_protocol_change_rule_fires_on_update() {
        let rule = Rule::new(
            "proto-change".to_string(),
            true,
            RuleCondition::ProtocolChange,
            Severity::Info,
            0,
        );
        let (engine, event_tx, mut alert_rx) = setup_engine(vec![rule]);
        let device = sample_device();

        tokio::spawn(async move {
            engine.run().await;
        });
        event_tx
            .send(DiscoveryEvent::DeviceUpdated(device))
            .await
            .unwrap();

        let alert = alert_rx.recv().await.expect("should receive alert");
        assert_eq!(alert.event_type, AlertEventType::ProtocolChange);
    }
}
