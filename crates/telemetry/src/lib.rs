//! Telemetry and observability for EdgeShield.
//!
//! This crate sets up structured JSON logging via `tracing-subscriber`
//! and provides metrics collection primitives.

pub mod telemetry;

pub use telemetry::*;
