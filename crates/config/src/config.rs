//! Configuration parsing for EdgeShield.
//!
//! Reads and validates the TOML configuration file.

use serde::Deserialize;
use std::str::FromStr;

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
        }
    }
}

impl FromStr for Config {
    type Err = crate::ConfigError;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let config: Config = toml::from_str(content)
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
}
