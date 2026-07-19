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
}
