//! ntfy.sh notifier — POSTs new-device events to an ntfy server.
//!
//! # Lifecycle
//!
//! `NtfyNotifier::run()` is intended to be spawned as a tokio task.
//! It owns the `DiscoveryEvent` receiver for the lifetime of the
//! daemon. On shutdown, the sender is dropped (by the daemon),
//! `recv().await` returns `None`, and the task exits cleanly.
//!
//! # Connection management
//!
//! Unlike MQTT, ntfy is stateless HTTP — there is no persistent
//! connection to keep alive. Each event triggers a single POST to
//! `{base_url}/{topic}`. A `reqwest::Client` is reused across
//! events (connection-pooled) for efficiency.
//!
//! # Backpressure
//!
//! The notifier never blocks the capture pipeline. If the ntfy
//! server is slow or down, the POST fails and the event is dropped
//! (with a log). The discovery engine uses `try_send` on the event
//! channel, so a slow notifier causes events to be dropped at the
//! channel rather than stalling the pipeline.
//!
//! # Message format
//!
//! ntfy supports both plain-text and JSON bodies. We POST the same
//! `NewDevicePayload` JSON used by the MQTT notifier so consumers
//! can switch transports without changing their parsers. The ntfy
//! `Title` header is set to a human-readable summary so the
//! notification card is useful even before the body is expanded.

use edgeshield_common::Alert;
use edgeshield_config::config::NtfyConfig;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use tracing::{info, warn};

use crate::fanout::{Notifier, NotifierError};
use crate::mqtt::NewDevicePayload;

/// An ntfy-backed notifier for alert delivery.
///
/// Created from an `NtfyConfig`. Implements the `Notifier` trait so
/// it can be used with the `NotifierFanout`. Each `deliver()` call
/// POSTs the alert as JSON to the ntfy topic URL.
pub struct NtfyNotifier {
    client: reqwest::Client,
    url: String,
    base_headers: HeaderMap,
}

impl NtfyNotifier {
    /// Create a new ntfy notifier.
    ///
    /// Builds the HTTP client and pre-computes the URL and static
    /// headers (auth, priority, tags). Returns an error if the HTTP
    /// client can't be built.
    pub fn new(config: NtfyConfig) -> Result<Self, NotifierError> {
        let url = format!("{}/{}", config.base_url, config.topic);
        let base_headers = Self::build_headers_static(&config);
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| NotifierError::Config(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            client,
            url,
            base_headers,
        })
    }

    /// Build the static header set (auth, priority, tags) once.
    fn build_headers_static(config: &NtfyConfig) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if let Some(ref token) = config.token
            && let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}"))
        {
            headers.insert(AUTHORIZATION, value);
        } else if config.token.is_some() {
            warn!(topic = %config.topic, "ntfy token contains invalid header chars; ignoring");
        }

        if let Some(priority) = config.priority
            && let Ok(value) = HeaderValue::from_str(&priority.to_string())
        {
            headers.insert("Priority", value);
        }

        if let Some(ref tags) = config.tags
            && let Ok(value) = HeaderValue::from_str(tags)
        {
            headers.insert("Tags", value);
        }

        headers
    }
}

#[async_trait::async_trait]
impl Notifier for NtfyNotifier {
    async fn deliver(&self, alert: &Alert) -> Result<(), NotifierError> {
        // Build the JSON payload from the alert's device snapshot.
        // We reuse the MQTT NewDevicePayload shape so consumers can
        // switch transports without changing parsers.
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

        // Human-readable title for the notification card. Includes
        // the alert severity for at-a-glance triage.
        let name = device
            .hostname
            .clone()
            .or_else(|| device.vendor.clone())
            .unwrap_or_else(|| device.mac.to_string());
        let title = format!(
            "[{}] {}: {name} ({})",
            alert.severity, alert.message, device.mac
        );

        let mut headers = self.base_headers.clone();
        if let Ok(value) = HeaderValue::from_str(&title) {
            headers.insert("Title", value);
        }

        match self
            .client
            .post(&self.url)
            .headers(headers)
            .body(json)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!(mac = %alert.mac, url = %self.url, "alert published to ntfy");
                Ok(())
            }
            Ok(resp) => Err(NotifierError::Delivery(format!(
                "ntfy returned status {}",
                resp.status()
            ))),
            Err(e) => Err(NotifierError::Delivery(format!("ntfy POST failed: {e}"))),
        }
    }

    fn name(&self) -> &str {
        "ntfy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::{Device, Protocol};
    use mac_address::MacAddress;
    use std::str::FromStr;

    fn sample_config() -> NtfyConfig {
        NtfyConfig {
            base_url: "https://ntfy.example.com".to_string(),
            topic: "edgeshield".to_string(),
            token: None,
            priority: None,
            tags: None,
        }
    }

    #[test]
    fn test_build_headers_no_auth() {
        let notifier = NtfyNotifier::new(sample_config()).unwrap();
        assert!(notifier.base_headers.get(AUTHORIZATION).is_none());
        assert!(notifier.base_headers.get("Priority").is_none());
        assert!(notifier.base_headers.get("Tags").is_none());
    }

    #[test]
    fn test_build_headers_with_auth_and_options() {
        let mut config = sample_config();
        config.token = Some("tok_abc123".to_string());
        config.priority = Some(2);
        config.tags = Some("warning,desktop".to_string());
        let notifier = NtfyNotifier::new(config).unwrap();
        assert_eq!(
            notifier.base_headers.get(AUTHORIZATION).unwrap(),
            "Bearer tok_abc123"
        );
        assert_eq!(notifier.base_headers.get("Priority").unwrap(), "2");
        assert_eq!(
            notifier.base_headers.get("Tags").unwrap(),
            "warning,desktop"
        );
    }

    #[test]
    fn test_build_headers_invalid_token_ignored() {
        let mut config = sample_config();
        // A newline is invalid in an HTTP header value.
        config.token = Some("bad\ntoken".to_string());
        let notifier = NtfyNotifier::new(config).unwrap();
        assert!(notifier.base_headers.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn test_payload_reused_from_mqtt_notifier() {
        // Verify the ntfy notifier reuses the same payload shape as
        // MQTT — consumers should be able to switch transports
        // without changing their parsers.
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp, edgeshield_common::Timestamp::now());
        device.add_ip("192.168.1.10".parse().unwrap());
        device.vendor = Some("TP-Link Technologies".to_string());

        let payload = NewDevicePayload::from_device(&device, "TCP");
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event\":\"new_device\""));
        assert!(json.contains("\"mac\":\"00:11:22:33:44:55\""));
        assert!(json.contains("\"vendor\":\"TP-Link Technologies\""));
    }
}
