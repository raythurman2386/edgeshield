//! Shared types, error definitions, and re-exports for EdgeShield.
//!
//! This crate is the foundation of the workspace. It defines:
//! - Domain types (MAC address, IP address, protocol identifiers)
//! - Error types used across crate boundaries
//! - Timestamp wrappers for consistent time handling
//!
//! # Design decisions
//!
//! - We use `mac_address::MacAddress` and `std::net::IpAddr` rather than
//!   defining our own, because they're well-tested, widely used, and serde-
//!   compatible.
//! - `chrono::DateTime<Utc>` for timestamps because it's the de facto standard
//!   in the Rust ecosystem and has serde support built in.
//! - Error types use `thiserror` for ergonomic `From` implementations and
//!   display formatting.
//! - This crate has zero dependencies on other workspace crates, making it
//!   a stable foundation.

pub mod alert;
pub mod alert_store;
pub mod error;
pub mod time;
pub mod types;

pub use alert::*;
pub use alert_store::{AlertFilter, AlertStore};
pub use error::*;
pub use time::*;
pub use types::*;
