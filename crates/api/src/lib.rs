//! REST API for EdgeShield.
//!
//! This crate provides the Axum-based HTTP server that exposes
//! device inventory, health checks, and metrics. It includes
//! authentication (Bearer token with SHA-256 hashing), TLS support,
//! and audit logging.

pub mod api;
pub mod audit;
pub mod auth;
pub mod routes;

pub use api::*;
pub use audit::*;
pub use auth::*;
pub use routes::*;
