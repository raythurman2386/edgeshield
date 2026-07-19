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
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::time::Timestamp;

/// Serialize a `BTreeMap<Protocol, u64>` as a JSON object with string
/// keys (since serde_json requires string keys, but `Protocol` is an
/// enum). The keys are the `Display` form of each protocol (e.g.,
/// "TCP", "mDNS", "UNKNOWN(42)").
fn serialize_protocol_stats<S>(
    stats: &BTreeMap<Protocol, u64>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(stats.len()))?;
    for (proto, count) in stats {
        map.serialize_entry(&proto.to_string(), count)?;
    }
    map.end()
}

/// Deserialize a `BTreeMap<Protocol, u64>` from a JSON object with
/// string keys. Parses each key back to a `Protocol` via `FromStr`.
fn deserialize_protocol_stats<'de, D>(deserializer: D) -> Result<BTreeMap<Protocol, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use std::str::FromStr;
    let raw: std::collections::HashMap<String, u64> = Deserialize::deserialize(deserializer)?;
    let mut map = BTreeMap::new();
    for (key, count) in raw {
        if let Ok(proto) = Protocol::from_str(&key) {
            map.insert(proto, count);
        }
    }
    Ok(map)
}

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

impl std::str::FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ARP" => Ok(Protocol::Arp),
            "IPv4" => Ok(Protocol::Ipv4),
            "ICMP" => Ok(Protocol::Icmp),
            "TCP" => Ok(Protocol::Tcp),
            "UDP" => Ok(Protocol::Udp),
            "DNS" => Ok(Protocol::Dns),
            "DHCP" => Ok(Protocol::Dhcp),
            "HTTP" => Ok(Protocol::Http),
            "HTTPS" => Ok(Protocol::Https),
            "mDNS" => Ok(Protocol::Mdns),
            "NTP" => Ok(Protocol::Ntp),
            _ => {
                if let Some(n) = s
                    .strip_prefix("UNKNOWN(")
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|n| n.parse().ok())
                {
                    Ok(Protocol::Other(n))
                } else {
                    Err(format!("unknown protocol: {s}"))
                }
            }
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
    /// DHCP vendor class identifier (option 60). Populated from
    /// DHCP DISCOVER/REQUEST packets. This is the client's self-reported
    /// vendor class (e.g., "MSFT 5.0", "android-dhcp") — distinct from
    /// the OUI vendor which comes from the MAC address registry.
    pub dhcp_vendor_class: Option<String>,
    /// Per-protocol packet counts. Maps each detected protocol to the
    /// number of packets observed for that protocol. Useful for
    /// fingerprinting (e.g., a device that only does mDNS + DNS is
    /// likely an IoT appliance; one doing HTTPS + NTP is likely a
    /// workstation). Stored as a JSON object in SQLite with string
    /// keys (Protocol's Display form).
    #[serde(
        serialize_with = "serialize_protocol_stats",
        deserialize_with = "deserialize_protocol_stats"
    )]
    pub protocol_stats: BTreeMap<Protocol, u64>,
}

impl Device {
    /// Create a new device from a MAC address.
    ///
    /// This is the only constructor. All counters start at zero.
    #[must_use]
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
            dhcp_vendor_class: None,
            protocol_stats: BTreeMap::new(),
        }
    }

    /// Record a packet sent by this device.
    ///
    /// Uses `saturating_add` so counters never panic on overflow (debug)
    /// nor wrap silently (release). A long-running appliance must not
    /// crash or corrupt counters under adversarial traffic.
    ///
    /// The caller supplies `now` so a single packet that updates both
    /// the source and destination devices can share one timestamp
    /// read (one `clock_gettime` syscall per packet instead of two).
    pub fn record_sent(&mut self, bytes: u64, protocol: Protocol, now: Timestamp) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.protocols.insert(protocol.clone());
        let entry = self.protocol_stats.entry(protocol).or_insert(0);
        *entry = entry.saturating_add(1);
        self.last_seen = now;
    }

    /// Record a packet received by this device.
    ///
    /// See `record_sent` for the saturating-arithmetic and shared-
    /// timestamp rationale.
    pub fn record_received(&mut self, bytes: u64, protocol: Protocol, now: Timestamp) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.protocols.insert(protocol.clone());
        let entry = self.protocol_stats.entry(protocol).or_insert(0);
        *entry = entry.saturating_add(1);
        self.last_seen = now;
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
        device.record_sent(100, Protocol::Tcp, Timestamp::now());
        assert_eq!(device.packet_count, 1);
        assert_eq!(device.bytes_sent, 100);
        assert!(device.protocols.contains(&Protocol::Tcp));
    }

    #[test]
    fn test_device_record_received() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_received(200, Protocol::Udp, Timestamp::now());
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
        let now = Timestamp::now();
        device.record_sent(100, Protocol::Tcp, now);
        device.record_received(200, Protocol::Udp, now);
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

    #[test]
    fn test_protocol_stats_incremented_on_record_sent() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        let now = Timestamp::now();
        device.record_sent(100, Protocol::Tcp, now);
        device.record_sent(200, Protocol::Tcp, now);
        device.record_sent(50, Protocol::Udp, now);
        assert_eq!(device.protocol_stats.get(&Protocol::Tcp), Some(&2));
        assert_eq!(device.protocol_stats.get(&Protocol::Udp), Some(&1));
        assert_eq!(device.protocol_stats.get(&Protocol::Dns), None);
    }

    #[test]
    fn test_protocol_stats_incremented_on_record_received() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        let now = Timestamp::now();
        device.record_received(100, Protocol::Dns, now);
        device.record_received(100, Protocol::Dns, now);
        device.record_received(100, Protocol::Dns, now);
        assert_eq!(device.protocol_stats.get(&Protocol::Dns), Some(&3));
    }

    #[test]
    fn test_dhcp_vendor_class_default_none() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = Device::new(mac);
        assert!(device.dhcp_vendor_class.is_none());
        assert!(device.protocol_stats.is_empty());
    }

    #[test]
    fn test_protocol_stats_serde_roundtrip() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        let now = Timestamp::now();
        device.record_sent(100, Protocol::Tcp, now);
        device.record_sent(200, Protocol::Mdns, now);
        device.dhcp_vendor_class = Some("MSFT 5.0".to_string());

        let json = serde_json::to_string(&device).unwrap();
        let deserialized: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.protocol_stats, device.protocol_stats);
        assert_eq!(deserialized.dhcp_vendor_class, device.dhcp_vendor_class);
    }
}
