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
}

fn default_api_port() -> u16 {
    8080
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_capture_buffer() -> usize {
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
}
