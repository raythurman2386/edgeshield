//! EdgeShield daemon — the main application orchestrator.
//!
//! This crate wires together all subsystems: packet capture, protocol
//! classification, device discovery, storage, and the REST API.

pub mod daemon;

pub use daemon::*;
