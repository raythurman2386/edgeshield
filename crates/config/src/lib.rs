//! Configuration parsing for EdgeShield.
//!
//! This crate is responsible for reading, validating, and providing
//! access to the TOML configuration file.

pub mod config;
pub mod error;

pub use config::*;
pub use error::*;
