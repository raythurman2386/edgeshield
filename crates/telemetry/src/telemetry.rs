//! Telemetry and observability for EdgeShield.
//!
//! This crate sets up structured JSON logging via `tracing-subscriber`
//! and provides metrics collection primitives.

use anyhow::Result;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;

/// Initialize the tracing subscriber with structured JSON logging.
///
/// # Arguments
///
/// * `log_level` - The log level filter (trace, debug, info, warn, error)
///
/// # Design
///
/// We use `tracing-subscriber` with the JSON layer for production logging.
/// The `EnvFilter` allows runtime log level control. Layers are composed
/// using the `Registry` as the base subscriber.
pub fn init(log_level: &str) -> Result<()> {
    let env_filter = EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_file(true)
        .with_line_number(true);

    let subscriber = Registry::default()
        .with(env_filter)
        .with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow::anyhow!("failed to set global subscriber: {}", e))?;

    Ok(())
}
