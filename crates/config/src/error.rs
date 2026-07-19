//! Error types for the config crate.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Read {
        path: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("failed to parse config: {0}")]
    Parse(String),

    #[error("invalid interface '{0}': interface name cannot be empty")]
    EmptyInterface(String),

    #[error("invalid MQTT config: host cannot be empty")]
    EmptyMqttHost,

    #[error("invalid MQTT QoS {0}: must be 0, 1, or 2")]
    InvalidMqttQos(u8),

    #[error("invalid ntfy config: base_url cannot be empty")]
    EmptyNtfyBaseUrl,

    #[error("invalid ntfy config: topic cannot be empty")]
    EmptyNtfyTopic,

    #[error("invalid rule config: name cannot be empty")]
    EmptyRuleName,

    #[error("invalid severity: {0}")]
    InvalidSeverity(String),

    #[error("invalid API auth config: read_key_hash cannot be empty")]
    EmptyAuthKeyHash,

    #[error("invalid API auth config: key hash must be 64 hex characters (SHA-256)")]
    InvalidKeyHashFormat,

    #[error("invalid TLS config: cert_path cannot be empty")]
    EmptyTlsCertPath,

    #[error("invalid TLS config: key_path cannot be empty")]
    EmptyTlsKeyPath,
}
