//! Device discovery for EdgeShield.
//!
//! This crate maintains the device inventory — mapping MAC addresses
//! to device records, tracking first/last seen, and updating counters.

pub mod discovery;

pub use discovery::*;
