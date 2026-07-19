//! Webhook notifier — POSTs alerts as JSON to an HTTP endpoint.
//!
//! Supports Slack, Discord, Microsoft Teams, and any generic webhook
//! that accepts a JSON POST body. Optional Bearer token auth and
//! custom headers.

use std::time::Duration;

use edgeshield_common::Alert;
use edgeshield_config::config::WebhookConfig;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use tracing::info;

use crate::fanout::{Notifier, NotifierError};

/// A webhook-backed notifier. POSTs each alert as JSON to the
/// configured URL.
pub struct WebhookNotifier {
    client: reqwest::Client,
    config: WebhookConfig,
    headers: HeaderMap,
}

impl WebhookNotifier {
    /// Create a new webhook notifier.
    pub fn new(config: WebhookConfig) -> Result<Self, NotifierError> {
        let mut headers = HeaderMap::new();

        if let Some(ref token) = config.token
            && let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}"))
        {
            headers.insert(AUTHORIZATION, value);
        }

        // Custom headers from config.
        for (key, value) in &config.headers {
            if let (Ok(hname), Ok(hval)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hname, hval);
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| NotifierError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            config,
            headers,
        })
    }
}

#[async_trait::async_trait]
impl Notifier for WebhookNotifier {
    async fn deliver(&self, alert: &Alert) -> Result<(), NotifierError> {
        let json = serde_json::to_string(alert)
            .map_err(|e| NotifierError::Delivery(format!("serialize failed: {e}")))?;

        let response = self
            .client
            .post(&self.config.url)
            .headers(self.headers.clone())
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await
            .map_err(|e| NotifierError::Delivery(format!("webhook POST failed: {e}")))?;

        let status = response.status();
        if status.is_success() {
            info!(url = %self.config.url, status = %status, "alert posted to webhook");
            Ok(())
        } else {
            Err(NotifierError::Delivery(format!(
                "webhook returned status {status}"
            )))
        }
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::{AlertEventType, Device, Severity};
    use mac_address::MacAddress;
    use std::collections::HashMap;
    use std::str::FromStr;

    fn sample_alert() -> Alert {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = Device::new(mac);
        Alert::new(
            "test-rule".to_string(),
            Severity::Info,
            AlertEventType::NewDevice,
            device,
            "test alert".to_string(),
        )
    }

    fn sample_config() -> WebhookConfig {
        WebhookConfig {
            url: "https://hooks.slack.com/services/test".to_string(),
            token: None,
            headers: HashMap::new(),
            timeout_seconds: 10,
        }
    }

    #[test]
    fn test_webhook_notifier_creation() {
        let notifier = WebhookNotifier::new(sample_config()).unwrap();
        assert!(notifier.headers.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn test_webhook_notifier_with_token() {
        let mut config = sample_config();
        config.token = Some("tok_abc".to_string());
        let notifier = WebhookNotifier::new(config).unwrap();
        assert_eq!(
            notifier.headers.get(AUTHORIZATION).unwrap(),
            "Bearer tok_abc"
        );
    }

    #[test]
    fn test_webhook_notifier_with_custom_headers() {
        let mut config = sample_config();
        config.headers.insert("X-Custom".to_string(), "value".to_string());
        let notifier = WebhookNotifier::new(config).unwrap();
        assert_eq!(notifier.headers.get("X-Custom").unwrap(), "value");
    }

    #[test]
    fn test_webhook_alert_serialization() {
        let alert = sample_alert();
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"rule_name\":\"test-rule\""));
        assert!(json.contains("\"severity\":\"info\""));
    }
}