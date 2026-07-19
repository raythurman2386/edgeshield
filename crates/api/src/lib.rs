//! REST API for EdgeShield.
//!
//! This crate provides the Axum-based HTTP server that exposes
//! device inventory, health checks, and metrics.

pub mod api;
pub mod routes;

pub use api::*;
pub use routes::*;
