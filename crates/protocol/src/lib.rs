//! Protocol classification for EdgeShield.
//!
//! This crate takes decoded packets and classifies them into
//! application-layer protocols (ARP, IPv4, ICMP, TCP, UDP, DNS,
//! DHCP, HTTP, mDNS, NTP). It also provides payload parsers for
//! protocols like DHCP that carry useful metadata.

pub mod classifier;
pub mod dhcp;
pub mod mdns;
pub mod ntp;

pub use classifier::*;
pub use dhcp::*;
pub use mdns::*;
pub use ntp::*;
