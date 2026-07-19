//! Error types for EdgeShield.
//!
//! We use `thiserror` for all error types. Each subsystem has its own
//! error enum that implements `std::error::Error` and can be converted
//! to `anyhow::Error` at the boundary.
//!
//! # Design
//!
//! - Errors are grouped by subsystem (packet, protocol, config, etc.)
//! - Each variant carries enough context to diagnose the issue
//! - We avoid stringly-typed errors — every variant is explicit

use thiserror::Error;

/// Errors that can occur during packet capture and decoding.
#[derive(Error, Debug)]
pub enum PacketError {
    #[error("failed to open capture interface '{interface}': {source}")]
    CaptureOpen {
        interface: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("packet too short: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(u8),

    #[error("capture error: {0}")]
    Capture(String),
}

/// Errors that can occur during configuration parsing.
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

/// Errors that can occur in the storage layer.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    #[error("storage error: {0}")]
    Internal(String),
}

/// Errors that can occur in the API layer.
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    #[error("internal error: {0}")]
    Internal(String),
}
