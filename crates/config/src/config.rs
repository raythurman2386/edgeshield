//! Configuration parsing for EdgeShield.
//!
//! Reads and validates the TOML configuration file.

use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

use edgeshield_common::Severity;

/// Top-level configuration for EdgeShield.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Network interface to capture packets on.
    pub interface: String,

    /// Port for the REST API server.
    #[serde(default = "default_api_port")]
    pub api_port: u16,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Size of the packet capture buffer in bytes.
    #[serde(default = "default_capture_buffer")]
    pub capture_buffer: usize,

    /// Path to the SQLite database file (empty = in-memory only).
    #[serde(default = "default_database_path")]
    pub database_path: String,

    /// MQTT notification settings. When present, EdgeShield publishes
    /// new-device events to the configured broker. When absent, MQTT
    /// is disabled and EdgeShield behaves as before.
    #[serde(default)]
    pub mqtt: Option<MqttConfig>,

    /// ntfy.sh notification settings. When present, EdgeShield POSTs a
    /// JSON event to the configured ntfy server every time a **new
    /// device** is discovered. When absent, ntfy is disabled.
    ///
    /// ntfy is an HTTP-based pub/sub service (https://ntfy.sh). Unlike
    /// MQTT, it requires no broker — you POST to a topic URL and any
    /// subscriber receives the message. This makes it a good fit for
    /// homelabs without an MQTT broker.
    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,

    /// Webhook notification settings. When present, EdgeShield POSTs
    /// each alert as JSON to the configured URL. Supports Slack,
    /// Discord, Teams, and any generic webhook.
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,

    /// Email notification settings. When present, EdgeShield sends
    /// each alert as an email via SMTP.
    #[serde(default)]
    pub email: Option<EmailConfig>,

    /// Alerting rules. Each rule defines a condition, severity, and
    /// cooldown. When the rule engine matches a condition against a
    /// discovery event, it produces an `Alert` that is delivered to
    /// all configured notifiers.
    ///
    /// If no rules are configured, a default `new_device` rule is
    /// used (preserving the pre-Phase-5 behavior).
    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    /// Background scanner settings for device-offline detection.
    /// The scanner wakes periodically, lists all devices, and emits
    /// `DeviceOffline` events for devices that have been silent
    /// longer than any `device_offline` rule's threshold.
    #[serde(default)]
    pub scanner: ScannerConfig,
}

/// MQTT broker configuration for new-device alerting.
///
/// EdgeShield is a *publisher* only — it never subscribes. It connects
/// to the broker, publishes `DiscoveryEvent`s as JSON to `topic`, and
/// keeps the connection alive. If the broker is unreachable at startup,
/// EdgeShield still runs (capture + API work); the notifier retries
/// in the background.
///
/// # Security
///
/// The password is read from the config file in plaintext. For
/// production, prefer a broker that accepts anonymous clients on a
/// trusted VLAN, or run EdgeShield under systemd with
/// `LoadCredential=` and a config that reads the password from a
/// protected path. Do not commit credentials to version control.
#[derive(Debug, Clone, Deserialize)]
pub struct MqttConfig {
    /// Broker host (e.g., "homeassistant.local" or "192.168.1.10").
    pub host: String,

    /// Broker port (default 1883; 8883 for TLS — not yet supported).
    #[serde(default = "default_mqtt_port")]
    pub port: u16,

    /// MQTT topic to publish new-device events to
    /// (e.g., "edgeshield/devices/new").
    #[serde(default = "default_mqtt_topic")]
    pub topic: String,

    /// Client ID to identify this EdgeShield instance on the broker.
    /// Useful when multiple EdgeShield nodes share a broker.
    #[serde(default = "default_mqtt_client_id")]
    pub client_id: String,

    /// Optional username for broker authentication.
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for broker authentication.
    #[serde(default)]
    pub password: Option<String>,

    /// QoS level for published messages (0 = at-most-once, 1 =
    /// at-least-once, 2 = exactly-once). Default 1 — we want alerts
    /// to survive a broker restart, but not the cost of QoS 2.
    #[serde(default = "default_mqtt_qos")]
    pub qos: u8,
}

fn default_mqtt_port() -> u16 {
    1883
}

fn default_mqtt_topic() -> String {
    "edgeshield/devices/new".to_string()
}

fn default_mqtt_client_id() -> String {
    "edgeshield".to_string()
}

fn default_mqtt_qos() -> u8 {
    1
}

/// ntfy.sh notification configuration.
///
/// EdgeShield is a *publisher* only — it POSTs JSON to the topic URL
/// (`{base_url}/{topic}`) for each new-device event. If the ntfy
/// server is unreachable at startup, EdgeShield still runs (capture
/// + API work); the notifier retries on each event.
///
/// # Security
///
/// The access token is read from the config file in plaintext. For
/// production, prefer a public topic on a trusted ntfy instance, or
/// run EdgeShield under systemd with `LoadCredential=` and a config
/// that reads the token from a protected path. Do not commit
/// credentials to version control.
#[derive(Debug, Clone, Deserialize)]
pub struct NtfyConfig {
    /// Base URL of the ntfy server, without a trailing slash
    /// (e.g., "https://ntfy.example.com" or "https://ntfy.sh").
    pub base_url: String,

    /// Topic name to publish to. The full publish URL becomes
    /// `{base_url}/{topic}` (e.g., "https://ntfy.sh/edgeshield").
    pub topic: String,

    /// Optional access token for authenticated ntfy servers. Sent as
    /// the `Authorization: Bearer <token>` header. When absent, the
    /// topic is published anonymously (the ntfy server must allow
    /// anonymous publishes for that topic).
    #[serde(default)]
    pub token: Option<String>,

    /// Optional priority header (1–5, where 1 = max, 5 = min).
    /// Mapped to the ntfy `Priority` header. When absent, ntfy uses
    /// its default (3).
    #[serde(default)]
    pub priority: Option<u8>,

    /// Optional tags header (comma-separated emoji shortcodes, e.g.
    /// "warning,desktop"). Mapped to the ntfy `Tags` header.
    #[serde(default)]
    pub tags: Option<String>,
}

/// Webhook notification configuration.
///
/// POSTs each alert as JSON to the configured URL. Compatible with
/// Slack, Discord, Microsoft Teams, and any generic webhook that
/// accepts a JSON POST body.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// The webhook URL (e.g.,
    /// `https://hooks.slack.com/services/...`).
    pub url: String,

    /// Optional Bearer token for authentication. Sent as
    /// `Authorization: Bearer <token>`.
    #[serde(default)]
    pub token: Option<String>,

    /// Optional custom HTTP headers (e.g., for webhook services that
    /// require specific headers).
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request timeout in seconds. Default 10.
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,
}

/// Email notification configuration via SMTP.
///
/// Sends each alert as a plain-text email. Uses the `lettre` crate
/// for SMTP delivery (no local MTA required).
#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname (e.g., `smtp.gmail.com`).
    pub host: String,

    /// SMTP server port. Default 587 (STARTTLS).
    #[serde(default = "default_email_port")]
    pub port: u16,

    /// Username for SMTP authentication.
    pub username: String,

    /// Password for SMTP authentication.
    pub password: String,

    /// From email address.
    pub from: String,

    /// To email address (recipient).
    pub to: String,

    /// Whether to use STARTTLS. Default true.
    #[serde(default = "default_email_starttls")]
    pub starttls: bool,

    /// Subject prefix for alert emails. Default `[EdgeShield]`.
    #[serde(default = "default_email_subject_prefix")]
    pub subject_prefix: String,
}

fn default_webhook_timeout() -> u64 {
    10
}

fn default_email_port() -> u16 {
    587
}

fn default_email_starttls() -> bool {
    true
}

fn default_email_subject_prefix() -> String {
    "[EdgeShield]".to_string()
}

/// A user-configured alerting rule.
///
/// Rules are defined inline in `config.toml` as `[[rules]]` tables.
/// Each rule has a condition, severity, and cooldown. When the rule
/// engine matches the condition against a discovery event, it
/// produces an `Alert`.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Human-readable name (shown in alerts and logs).
    pub name: String,

    /// Whether the rule is enabled. Default `true`.
    #[serde(default = "default_rule_enabled")]
    pub enabled: bool,

    /// The condition that triggers the rule.
    pub condition: RuleConditionConfig,

    /// Severity: "info", "warning", or "critical". Default "info".
    #[serde(default = "default_rule_severity")]
    pub severity: String,

    /// Minimum seconds between alerts for the same device from this
    /// rule. `0` = no cooldown. Default `0`.
    #[serde(default)]
    pub cooldown_seconds: u64,
}

/// The condition for a rule, parsed from TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RuleConditionConfig {
    /// Simple string conditions: "new_device", "protocol_change".
    Simple(String),
    /// Table conditions with parameters.
    NewDeviceByVendor { new_device_by_vendor: String },
    NewDeviceByMacPrefix { new_device_by_mac_prefix: String },
    DeviceOffline { device_offline: DeviceOfflineCondition },
}

/// Parameters for the `device_offline` condition.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceOfflineCondition {
    /// Emit an offline alert after the device has been silent for
    /// this many seconds.
    pub after_seconds: u64,
}

/// Background scanner settings for device-offline detection.
#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    /// How often (in seconds) the scanner wakes to check for offline
    /// devices. Default 60s. Set to 0 to disable the scanner entirely.
    #[serde(default = "default_scanner_interval")]
    pub interval_seconds: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_scanner_interval(),
        }
    }
}

fn default_rule_enabled() -> bool {
    true
}

fn default_rule_severity() -> String {
    "info".to_string()
}

const fn default_scanner_interval() -> u64 {
    60
}

const fn default_api_port() -> u16 {
    8080
}

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_capture_buffer() -> usize {
    4096
}

fn default_database_path() -> String {
    String::new()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: String::new(),
            api_port: default_api_port(),
            log_level: default_log_level(),
            capture_buffer: default_capture_buffer(),
            database_path: default_database_path(),
            mqtt: None,
            ntfy: None,
            webhook: None,
            email: None,
            rules: Vec::new(),
            scanner: ScannerConfig::default(),
        }
    }
}

impl FromStr for Config {
    type Err = crate::ConfigError;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let mut config: Config = toml::from_str(content)
            .map_err(|e| crate::ConfigError::Parse(e.to_string()))?;

        if config.interface.trim().is_empty() {
            return Err(crate::ConfigError::EmptyInterface(config.interface));
        }

        // Validate MQTT config if present. We validate here (at parse
        // time) so a misconfigured broker fails fast at startup rather
        // than silently dropping alerts at runtime.
        if let Some(ref mqtt) = config.mqtt {
            if mqtt.host.trim().is_empty() {
                return Err(crate::ConfigError::EmptyMqttHost);
            }
            if mqtt.qos > 2 {
                return Err(crate::ConfigError::InvalidMqttQos(mqtt.qos));
            }
        }

        // Validate ntfy config if present. Same fail-fast rationale as
        // MQTT: a misconfigured ntfy server should be visible at
        // startup, not silently drop alerts at runtime.
        if let Some(ref mut ntfy) = config.ntfy {
            if ntfy.base_url.trim().is_empty() {
                return Err(crate::ConfigError::EmptyNtfyBaseUrl);
            }
            if ntfy.topic.trim().is_empty() {
                return Err(crate::ConfigError::EmptyNtfyTopic);
            }
            // Normalize: strip a trailing slash so callers can write
            // either "https://ntfy.sh" or "https://ntfy.sh/".
            if let Some(stripped) = ntfy.base_url.strip_suffix('/') {
                ntfy.base_url = stripped.to_string();
            }
        }

        // Validate rules: each rule name must be non-empty, and the
        // severity must be a valid value.
        for rule in &config.rules {
            if rule.name.trim().is_empty() {
                return Err(crate::ConfigError::EmptyRuleName);
            }
            // Validate severity string (parse to check, discard result).
            let _ = Severity::from_str(&rule.severity)
                .map_err(crate::ConfigError::InvalidSeverity)?;
        }

        Ok(config)
    }
}

impl Config {
    /// Load configuration from a TOML file path.
    pub fn from_file(path: &str) -> Result<Self, crate::ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::ConfigError::Read {
                path: path.to_string(),
                source: Box::new(e),
            })?;
        content.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.api_port, 8080);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.capture_buffer, 4096);
    }

    #[test]
    fn test_parse_valid_config() {
        let toml = r#"
            interface = "eth0"
            api_port = 9090
            log_level = "debug"
            capture_buffer = 8192
        "#;
        let config: Config = toml.parse().unwrap();
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.api_port, 9090);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.capture_buffer, 8192);
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
            interface = "eth0"
        "#;
        let config: Config = toml.parse().unwrap();
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.api_port, 8080); // default
        assert_eq!(config.log_level, "info"); // default
    }

    #[test]
    fn test_parse_empty_interface() {
        let toml = r#"
            interface = ""
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_toml() {
        let toml = r#"
            interface = 123
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_mqtt_disabled_by_default() {
        let toml = r#"
            interface = "eth0"
        "#;
        let config: Config = toml.parse().unwrap();
        assert!(config.mqtt.is_none());
    }

    #[test]
    fn test_mqtt_config_with_defaults() {
        let toml = r#"
            interface = "eth0"
            [mqtt]
            host = "homeassistant.local"
        "#;
        let config: Config = toml.parse().unwrap();
        let mqtt = config.mqtt.expect("mqtt config should be present");
        assert_eq!(mqtt.host, "homeassistant.local");
        assert_eq!(mqtt.port, 1883); // default
        assert_eq!(mqtt.topic, "edgeshield/devices/new"); // default
        assert_eq!(mqtt.client_id, "edgeshield"); // default
        assert_eq!(mqtt.qos, 1); // default
        assert!(mqtt.username.is_none());
        assert!(mqtt.password.is_none());
    }

    #[test]
    fn test_mqtt_config_full() {
        let toml = r#"
            interface = "eth0"
            [mqtt]
            host = "broker.example.com"
            port = 8883
            topic = "home/edgeshield/new"
            client_id = "edgeshield-livingroom"
            username = "edgeshield"
            password = "secret"
            qos = 2
        "#;
        let config: Config = toml.parse().unwrap();
        let mqtt = config.mqtt.unwrap();
        assert_eq!(mqtt.host, "broker.example.com");
        assert_eq!(mqtt.port, 8883);
        assert_eq!(mqtt.topic, "home/edgeshield/new");
        assert_eq!(mqtt.client_id, "edgeshield-livingroom");
        assert_eq!(mqtt.username.as_deref(), Some("edgeshield"));
        assert_eq!(mqtt.password.as_deref(), Some("secret"));
        assert_eq!(mqtt.qos, 2);
    }

    #[test]
    fn test_mqtt_empty_host_rejected() {
        let toml = r#"
            interface = "eth0"
            [mqtt]
            host = ""
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(matches!(
            result,
            Err(crate::ConfigError::EmptyMqttHost)
        ));
    }

    #[test]
    fn test_mqtt_invalid_qos_rejected() {
        let toml = r#"
            interface = "eth0"
            [mqtt]
            host = "broker.example.com"
            qos = 3
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(matches!(
            result,
            Err(crate::ConfigError::InvalidMqttQos(3))
        ));
    }

    #[test]
    fn test_ntfy_disabled_by_default() {
        let toml = r#"
            interface = "eth0"
        "#;
        let config: Config = toml.parse().unwrap();
        assert!(config.ntfy.is_none());
    }

    #[test]
    fn test_ntfy_config_minimal() {
        let toml = r#"
            interface = "eth0"
            [ntfy]
            base_url = "https://ntfy.sh"
            topic = "edgeshield"
        "#;
        let config: Config = toml.parse().unwrap();
        let ntfy = config.ntfy.expect("ntfy config should be present");
        assert_eq!(ntfy.base_url, "https://ntfy.sh");
        assert_eq!(ntfy.topic, "edgeshield");
        assert!(ntfy.token.is_none());
        assert!(ntfy.priority.is_none());
        assert!(ntfy.tags.is_none());
    }

    #[test]
    fn test_ntfy_config_full() {
        let toml = r#"
            interface = "eth0"
            [ntfy]
            base_url = "https://ntfy.example.com"
            topic = "edgeshield-new-device"
            token = "tok_abc123"
            priority = 2
            tags = "warning,desktop"
        "#;
        let config: Config = toml.parse().unwrap();
        let ntfy = config.ntfy.unwrap();
        assert_eq!(ntfy.base_url, "https://ntfy.example.com");
        assert_eq!(ntfy.topic, "edgeshield-new-device");
        assert_eq!(ntfy.token.as_deref(), Some("tok_abc123"));
        assert_eq!(ntfy.priority, Some(2));
        assert_eq!(ntfy.tags.as_deref(), Some("warning,desktop"));
    }

    #[test]
    fn test_ntfy_trailing_slash_normalized() {
        let toml = r#"
            interface = "eth0"
            [ntfy]
            base_url = "https://ntfy.example.com/"
            topic = "edgeshield"
        "#;
        let config: Config = toml.parse().unwrap();
        let ntfy = config.ntfy.unwrap();
        assert_eq!(ntfy.base_url, "https://ntfy.example.com");
    }

    #[test]
    fn test_ntfy_empty_base_url_rejected() {
        let toml = r#"
            interface = "eth0"
            [ntfy]
            base_url = ""
            topic = "edgeshield"
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(matches!(result, Err(crate::ConfigError::EmptyNtfyBaseUrl)));
    }

    #[test]
    fn test_ntfy_empty_topic_rejected() {
        let toml = r#"
            interface = "eth0"
            [ntfy]
            base_url = "https://ntfy.sh"
            topic = ""
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(matches!(result, Err(crate::ConfigError::EmptyNtfyTopic)));
    }

    #[test]
    fn test_rules_default_empty() {
        let toml = r#"
            interface = "eth0"
        "#;
        let config: Config = toml.parse().unwrap();
        assert!(config.rules.is_empty());
        assert_eq!(config.scanner.interval_seconds, 60);
    }

    #[test]
    fn test_rules_parse_simple_new_device() {
        let toml = r#"
            interface = "eth0"
            [[rules]]
            name = "new-device-alert"
            condition = "new_device"
            severity = "info"
            cooldown_seconds = 300
        "#;
        let config: Config = toml.parse().unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "new-device-alert");
        assert_eq!(config.rules[0].severity, "info");
        assert_eq!(config.rules[0].cooldown_seconds, 300);
        assert!(config.rules[0].enabled); // default true
    }

    #[test]
    fn test_rules_parse_device_offline() {
        let toml = r#"
            interface = "eth0"
            [[rules]]
            name = "offline-30min"
            condition = { device_offline = { after_seconds = 1800 } }
            severity = "warning"
        "#;
        let config: Config = toml.parse().unwrap();
        assert_eq!(config.rules.len(), 1);
        match &config.rules[0].condition {
            RuleConditionConfig::DeviceOffline { device_offline } => {
                assert_eq!(device_offline.after_seconds, 1800);
            }
            other => panic!("expected DeviceOffline, got {other:?}"),
        }
    }

    #[test]
    fn test_rules_parse_new_device_by_vendor() {
        let toml = r#"
            interface = "eth0"
            [[rules]]
            name = "new-iot"
            condition = { new_device_by_vendor = "TP-Link" }
        "#;
        let config: Config = toml.parse().unwrap();
        match &config.rules[0].condition {
            RuleConditionConfig::NewDeviceByVendor { new_device_by_vendor } => {
                assert_eq!(new_device_by_vendor, "TP-Link");
            }
            other => panic!("expected NewDeviceByVendor, got {other:?}"),
        }
    }

    #[test]
    fn test_rules_parse_disabled() {
        let toml = r#"
            interface = "eth0"
            [[rules]]
            name = "disabled-rule"
            enabled = false
            condition = "new_device"
        "#;
        let config: Config = toml.parse().unwrap();
        assert!(!config.rules[0].enabled);
    }

    #[test]
    fn test_rules_empty_name_rejected() {
        let toml = r#"
            interface = "eth0"
            [[rules]]
            name = ""
            condition = "new_device"
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(matches!(result, Err(crate::ConfigError::EmptyRuleName)));
    }

    #[test]
    fn test_rules_invalid_severity_rejected() {
        let toml = r#"
            interface = "eth0"
            [[rules]]
            name = "bad-severity"
            condition = "new_device"
            severity = "urgent"
        "#;
        let result: Result<Config, _> = toml.parse();
        assert!(matches!(result, Err(crate::ConfigError::InvalidSeverity(_))));
    }

    #[test]
    fn test_scanner_custom_interval() {
        let toml = r#"
            interface = "eth0"
            [scanner]
            interval_seconds = 120
        "#;
        let config: Config = toml.parse().unwrap();
        assert_eq!(config.scanner.interval_seconds, 120);
    }
}
