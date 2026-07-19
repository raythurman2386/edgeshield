//! MQTT notifier — publishes new-device events to an MQTT broker.
//!
//! # Lifecycle
//!
//! `MqttNotifier::run()` is intended to be spawned as a tokio task. It
//! owns the `DiscoveryEvent` receiver and the MQTT connection for the
//! lifetime of the daemon. On shutdown, the sender is dropped (by the
//! daemon), `recv().await` returns `None`, and the task exits cleanly.
//!
//! # Connection management
//!
//! `rumqttc` handles reconnection internally. We drive the connection
//! by polling its `Event` stream in a `select!` alongside the event
//! receiver. This keeps the connection alive and lets us observe
//! broker disconnects in the logs.
//!
//! # Backpressure
//!
//! The notifier never blocks the capture pipeline. If the broker is
//! slow or down, `publish` calls fail and events are dropped (with a
//! log). The discovery engine uses `try_send` on the event channel,
//! so a slow notifier causes events to be dropped at the channel
//! rather than stalling the pipeline.

use edgeshield_common::{Alert, Device};
use edgeshield_config::config::MqttConfig;
use rumqttc::{AsyncClient, MqttOptions, QoS};
use serde::Serialize;
use tracing::{info, warn};

use crate::fanout::{Notifier, NotifierError};

/// The JSON payload published to MQTT for each new-device event.
///
/// This is a stable, documented contract for Home Assistant / Node-RED
/// consumers. Fields are additive only — never rename or remove a
/// field without a topic version bump.
#[derive(Debug, Serialize)]
pub struct NewDevicePayload {
    /// The event type. Always "new_device" for this topic.
    /// Lets a consumer route one topic to multiple handlers.
    pub event: &'static str,
    /// The MAC address in colon-separated form (00:11:22:33:44:55).
    pub mac: String,
    /// First observed IP address, if one was seen in the triggering packet.
    pub ip: Option<String>,
    /// Hostname, if discovered via DHCP in the triggering packet.
    pub hostname: Option<String>,
    /// Vendor name from the MAC OUI (IEEE registry), if known.
    /// Populated by the discovery engine on first sight via the
    /// `edgeshield-oui` crate. This is what turns a bare MAC into an
    /// actionable alert ("TP-Link" vs "00:11:22:33:44:55").
    pub vendor: Option<String>,
    /// Protocol of the first packet that triggered the event.
    pub protocol: String,
    /// ISO 8601 timestamp of when the device was first seen.
    pub first_seen: String,
}

impl NewDevicePayload {
    /// Build the payload from a freshly-discovered `Device`.
    ///
    /// We take the first IP (BTreeSet is sorted, so this is deterministic)
    /// rather than the full set to keep the MQTT message small. The full
    /// device record is available via the REST API for consumers that
    /// need it.
    pub fn from_device(device: &Device, protocol: &str) -> Self {
        Self {
            event: "new_device",
            mac: device.mac.to_string(),
            ip: device.ips.iter().next().map(|ip| ip.to_string()),
            hostname: device.hostname.clone(),
            vendor: device.vendor.clone(),
            protocol: protocol.to_string(),
            first_seen: device.first_seen.to_string(),
        }
    }
}

/// An MQTT-backed notifier for new-device events.
///
/// Created from an `MqttConfig`. Call `run()` to start the consumer
/// loop; spawn it on a tokio task.
pub struct MqttNotifier {
    config: MqttConfig,
    client: AsyncClient,
}

impl MqttNotifier {
    /// Create a new MQTT notifier.
    ///
    /// Connects to the broker immediately (rumqttc handles
    /// reconnection internally). The connection's event stream is
    /// polled in a background task to keep it alive.
    pub fn new(config: MqttConfig) -> Self {
        let mqtt_options = Self::build_mqtt_options(&config);
        let (client, mut connection) = AsyncClient::new(mqtt_options.clone(), 10);

        // Spawn a background task to drive the MQTT connection's
        // event stream. This keeps the connection alive and logs
        // disconnects. rumqttc reconnects automatically.
        let client_id = mqtt_options.client_id().to_string();
        tokio::spawn(async move {
            loop {
                match connection.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_))) => {
                        info!(client_id = %client_id, "MQTT connected");
                    }
                    Ok(rumqttc::Event::Outgoing(_)) => {}
                    Ok(_) => {}
                    Err(e) => {
                        warn!(error = %e, client_id = %client_id, "MQTT connection error");
                    }
                }
            }
        });

        Self { config, client }
    }

    /// Build `rumqttc::MqttOptions` from our config.
    fn build_mqtt_options(config: &MqttConfig) -> MqttOptions {
        let mut opts = MqttOptions::new(config.client_id.clone(), config.host.clone(), config.port);
        opts.set_clean_session(true);
        if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            opts.set_credentials(user, pass);
        }
        opts
    }
}

#[async_trait::async_trait]
impl Notifier for MqttNotifier {
    async fn deliver(&self, alert: &Alert) -> Result<(), NotifierError> {
        let device = &alert.device_snapshot;
        let protocol = device
            .protocols
            .iter()
            .next()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let payload = NewDevicePayload::from_device(device, &protocol);
        let json = serde_json::to_string(&payload)
            .map_err(|e| NotifierError::Delivery(format!("serialize failed: {e}")))?;

        let qos = match self.config.qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            _ => QoS::ExactlyOnce,
        };

        self.client
            .publish(self.config.topic.clone(), qos, false, json)
            .await
            .map_err(|e| NotifierError::Delivery(format!("MQTT publish failed: {e}")))?;

        info!(
            mac = %alert.mac,
            topic = %self.config.topic,
            "alert published to MQTT"
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "mqtt"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::{Device, Protocol};
    use mac_address::MacAddress;
    use std::str::FromStr;

    fn sample_device() -> Device {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp);
        device.add_ip("192.168.1.10".parse().unwrap());
        device.vendor = Some("TP-Link Technologies".to_string());
        device
    }

    #[test]
    fn test_payload_from_device_with_ip() {
        let device = sample_device();
        let payload = NewDevicePayload::from_device(&device, "TCP");
        assert_eq!(payload.event, "new_device");
        assert_eq!(payload.mac, "00:11:22:33:44:55");
        assert_eq!(payload.ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(payload.vendor.as_deref(), Some("TP-Link Technologies"));
        assert_eq!(payload.protocol, "TCP");
        assert!(payload.first_seen.contains('T'));
    }

    #[test]
    fn test_payload_from_device_without_ip() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = Device::new(mac);
        let payload = NewDevicePayload::from_device(&device, "ARP");
        assert_eq!(payload.mac, "00:11:22:33:44:55");
        assert!(payload.ip.is_none());
        assert!(payload.vendor.is_none());
        assert_eq!(payload.protocol, "ARP");
    }

    #[test]
    fn test_payload_serializes_to_json() {
        let device = sample_device();
        let payload = NewDevicePayload::from_device(&device, "TCP");
        let json = serde_json::to_string(&payload).unwrap();
        // Verify the JSON is well-formed and has the expected fields.
        assert!(json.contains("\"event\":\"new_device\""));
        assert!(json.contains("\"mac\":\"00:11:22:33:44:55\""));
        assert!(json.contains("\"vendor\":\"TP-Link Technologies\""));
        assert!(json.contains("\"protocol\":\"TCP\""));
    }
}
