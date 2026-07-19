//! Packet capture and decoding for EdgeShield.
//!
//! This crate owns the packet buffer lifecycle — from raw capture
//! via pnet through zero-copy Ethernet/IP/transport header parsing.

pub mod capture;
pub mod decode;

pub use capture::*;
pub use decode::*;
