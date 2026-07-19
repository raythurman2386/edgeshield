//! Core domain types for EdgeShield.
//!
//! This module defines the fundamental types used across the entire
//! application: MAC addresses, IP addresses, protocol identifiers,
//! and the device model.
//!
//! # Design
//!
//! - All types implement `Serialize`/`Deserialize` for JSON API responses
//! - Types are `Send + Sync` for concurrent access
//! - We use newtypes to make the domain explicit rather than passing
//!   raw strings or integers around

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::time::Timestamp;

/// A protocol detected on the network.
///
/// This enum is intentionally flat for the MVP. As we add protocol
/// detection, variants are added here. The `Other` variant captures
/// unknown protocols by their numeric identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Arp,
    Ipv4,
    Icmp,
    Tcp,
    Udp,
    Dns,
    Dhcp,
    Http,
    Https,
    Mdns,
    Ntp,
    /// Unknown protocol identified by its IP protocol number.
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Arp => write!(f, "ARP"),
            Protocol::Ipv4 => write!(f, "IPv4"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Dhcp => write!(f, "DHCP"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Https => write!(f, "HTTPS"),
            Protocol::Mdns => write!(f, "mDNS"),
            Protocol::Ntp => write!(f, "NTP"),
            Protocol::Other(n) => write!(f, "UNKNOWN({})", n),
        }
    }
}

/// A network device discovered on the local network.
///
/// This is the central data model. Every field is optional except `mac`
/// because we may not see all traffic types from every device.
///
/// # Concurrency
///
/// `Device` is `Send + Sync` and will be stored in a `DashMap`. Updates
/// are atomic per-device — we read, modify, and write back under a shard
/// lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// MAC address (always present — this is our primary key)
    pub mac: MacAddress,
    /// Observed IP addresses (BTreeSet for deterministic ordering)
    pub ips: BTreeSet<IpAddr>,
    /// Hostname if discovered via DHCP or reverse DNS (future)
    pub hostname: Option<String>,
    /// When the device was first seen
    pub first_seen: Timestamp,
    /// When the device was last seen
    pub last_seen: Timestamp,
    /// Total packets observed from/to this device
    pub packet_count: u64,
    /// Total bytes sent by this device
    pub bytes_sent: u64,
    /// Total bytes received by this device
    pub bytes_received: u64,
    /// Protocols detected for this device
    pub protocols: BTreeSet<Protocol>,
    /// OUI vendor string (populated from MAC OUI lookup — future)
    pub vendor: Option<String>,
}

impl Device {
    /// Create a new device from a MAC address.
    ///
    /// This is the only constructor. All counters start at zero.
    pub fn new(mac: MacAddress) -> Self {
        let now = Timestamp::now();
        Self {
            mac,
            ips: BTreeSet::new(),
            hostname: None,
            first_seen: now,
            last_seen: now,
            packet_count: 0,
            bytes_sent: 0,
            bytes_received: 0,
            protocols: BTreeSet::new(),
            vendor: None,
        }
    }

    /// Record a packet sent by this device.
    ///
    /// Uses `saturating_add` so counters never panic on overflow (debug)
    /// nor wrap silently (release). A long-running appliance must not
    /// crash or corrupt counters under adversarial traffic.
    pub fn record_sent(&mut self, bytes: u64, protocol: Protocol) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.protocols.insert(protocol);
        self.last_seen = Timestamp::now();
    }

    /// Record a packet received by this device.
    ///
    /// See `record_sent` for the saturating-arithmetic rationale.
    pub fn record_received(&mut self, bytes: u64, protocol: Protocol) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.protocols.insert(protocol);
        self.last_seen = Timestamp::now();
    }

    /// Add an IP address to this device.
    pub fn add_ip(&mut self, ip: IpAddr) {
        self.ips.insert(ip);
    }
}

/// A summary of device activity for the `/metrics` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub total_devices: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub uptime_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_device_new() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = Device::new(mac);
        assert_eq!(device.mac, mac);
        assert_eq!(device.packet_count, 0);
        assert_eq!(device.bytes_sent, 0);
        assert_eq!(device.bytes_received, 0);
        assert!(device.protocols.is_empty());
        assert!(device.ips.is_empty());
    }

    #[test]
    fn test_device_record_sent() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp);
        assert_eq!(device.packet_count, 1);
        assert_eq!(device.bytes_sent, 100);
        assert!(device.protocols.contains(&Protocol::Tcp));
    }

    #[test]
    fn test_device_record_received() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_received(200, Protocol::Udp);
        assert_eq!(device.packet_count, 1);
        assert_eq!(device.bytes_received, 200);
        assert!(device.protocols.contains(&Protocol::Udp));
    }

    #[test]
    fn test_device_add_ip() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        device.add_ip(ip);
        assert!(device.ips.contains(&ip));
        assert_eq!(device.ips.len(), 1);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Arp), "ARP");
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Dns), "DNS");
        assert_eq!(format!("{}", Protocol::Other(42)), "UNKNOWN(42)");
    }

    #[test]
    fn test_device_serde_roundtrip() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, Protocol::Tcp);
        device.record_received(200, Protocol::Udp);
        device.add_ip("192.168.1.10".parse().unwrap());

        let json = serde_json::to_string_pretty(&device).unwrap();
        let deserialized: Device = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.mac, device.mac);
        assert_eq!(deserialized.packet_count, device.packet_count);
        assert_eq!(deserialized.bytes_sent, device.bytes_sent);
        assert_eq!(deserialized.bytes_received, device.bytes_received);
        assert_eq!(deserialized.protocols, device.protocols);
        assert_eq!(deserialized.ips, device.ips);
    }
}
