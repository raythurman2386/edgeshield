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

use edgeshield_config::config::NtfyConfig;
use edgeshield_discovery::discovery::DiscoveryEvent;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::mqtt::NewDevicePayload;

/// An ntfy-backed notifier for new-device events.
///
/// Created from an `NtfyConfig`. Call `run()` to start the consumer
/// loop; spawn it on a tokio task.
pub struct NtfyNotifier {
    config: NtfyConfig,
    event_rx: mpsc::Receiver<DiscoveryEvent>,
}

impl NtfyNotifier {
    /// Create a new notifier.
    ///
    /// Takes ownership of the event receiver — only one consumer may
    /// exist. The daemon ensures at most one notifier (MQTT *or*
    /// ntfy) holds the receiver.
    #[must_use]
    pub fn new(config: NtfyConfig, event_rx: mpsc::Receiver<DiscoveryEvent>) -> Self {
        Self { config, event_rx }
    }

    /// Build the static header set (auth, priority, tags) once.
    ///
    /// Per-event headers (Title) are added on each request.
    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if let Some(ref token) = self.config.token {
            // ntfy accepts `Authorization: Bearer <token>`.
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, value);
            } else {
                warn!(topic = %self.config.topic, "ntfy token contains invalid header chars; ignoring");
            }
        }

        if let Some(priority) = self.config.priority {
            if let Ok(value) = HeaderValue::from_str(&priority.to_string()) {
                headers.insert("Priority", value);
            }
        }

        if let Some(ref tags) = self.config.tags {
            if let Ok(value) = HeaderValue::from_str(tags) {
                headers.insert("Tags", value);
            }
        }

        headers
    }

    /// Run the notifier loop until the event sender is dropped.
    ///
    /// This is the task body. It builds a pooled HTTP client, then
    /// loops receiving `DiscoveryEvent`s and POSTing new-device
    /// events to the ntfy topic URL.
    ///
    /// # Errors
    ///
    /// POST errors are logged, not returned. The notifier retries on
    /// the next event — there is no persistent connection to lose. If
    /// the ntfy server is unreachable at startup, the task still runs
    /// and keeps trying — capture and the API are unaffected.
    pub async fn run(mut self) {
        let url = format!("{}/{}", self.config.base_url, self.config.topic);
        let base_headers = self.build_headers();

        // Build a pooled client. ntfy.sh uses HTTPS; we rely on the
        // system root certs via rustls-tls.
        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to build ntfy HTTP client; notifier disabled");
                return;
            }
        };

        info!(
            url = %url,
            topic = %self.config.topic,
            "ntfy notifier starting"
        );

        loop {
            let Some(event) = self.event_rx.recv().await else {
                info!("event channel closed; ntfy notifier stopping");
                break;
            };

            // Only publish new-device events. DeviceUpdated fires on
            // every packet and would flood the ntfy server.
            let DiscoveryEvent::DeviceDiscovered(device) = event else {
                continue;
            };

            let protocol = device
                .protocols
                .iter()
                .next()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            let payload = NewDevicePayload::from_device(&device, &protocol);
            let json = match serde_json::to_string(&payload) {
                Ok(j) => j,
                Err(e) => {
                    error!(error = %e, "failed to serialize new-device payload");
                    continue;
                }
            };

            // Human-readable title for the notification card.
            let title = format!(
                "New device: {} ({})",
                device
                    .hostname
                    .clone()
                    .or_else(|| device.vendor.clone())
                    .unwrap_or_else(|| device.mac.to_string()),
                device.mac
            );

            let mut headers = base_headers.clone();
            if let Ok(value) = HeaderValue::from_str(&title) {
                headers.insert("Title", value);
            }

            match client
                .post(&url)
                .headers(headers)
                .body(json)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    info!(mac = %device.mac, url = %url, "new-device event published to ntfy");
                }
                Ok(resp) => {
                    warn!(
                        status = %resp.status(),
                        mac = %device.mac,
                        "ntfy publish returned non-success status"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        mac = %device.mac,
                        "failed to publish new-device event to ntfy"
                    );
                }
            }
        }
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
        let notifier = NtfyNotifier {
            config: sample_config(),
            event_rx: mpsc::channel::<DiscoveryEvent>(1).1,
        };
        let headers = notifier.build_headers();
        assert!(headers.get(AUTHORIZATION).is_none());
        assert!(headers.get("Priority").is_none());
        assert!(headers.get("Tags").is_none());
    }

    #[test]
    fn test_build_headers_with_auth_and_options() {
        let mut config = sample_config();
        config.token = Some("tok_abc123".to_string());
        config.priority = Some(2);
        config.tags = Some("warning,desktop".to_string());
        let notifier = NtfyNotifier {
            config,
            event_rx: mpsc::channel::<DiscoveryEvent>(1).1,
        };
        let headers = notifier.build_headers();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "Bearer tok_abc123"
        );
        assert_eq!(headers.get("Priority").unwrap(), "2");
        assert_eq!(headers.get("Tags").unwrap(), "warning,desktop");
    }

    #[test]
    fn test_build_headers_invalid_token_ignored() {
        let mut config = sample_config();
        // A newline is invalid in an HTTP header value.
        config.token = Some("bad\ntoken".to_string());
        let notifier = NtfyNotifier {
            config,
            event_rx: mpsc::channel::<DiscoveryEvent>(1).1,
        };
        let headers = notifier.build_headers();
        assert!(headers.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn test_payload_reused_from_mqtt_notifier() {
        // Verify the ntfy notifier reuses the same payload shape as
        // MQTT — consumers should be able to switch transports
        // without changing their parsers.
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp);
        device.add_ip("192.168.1.10".parse().unwrap());
        device.vendor = Some("TP-Link Technologies".to_string());

        let payload = NewDevicePayload::from_device(&device, "TCP");
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event\":\"new_device\""));
        assert!(json.contains("\"mac\":\"00:11:22:33:44:55\""));
        assert!(json.contains("\"vendor\":\"TP-Link Technologies\""));
    }
}