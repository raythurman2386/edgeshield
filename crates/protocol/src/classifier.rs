//! Protocol classification for EdgeShield.
//!
//! This module classifies decoded packets into application-layer
//! protocols (ARP, IPv4, ICMP, TCP, UDP, DNS, DHCP, HTTP, mDNS, NTP).
//!
//! # Design
//!
//! Classification is pure logic — no I/O, no state. It takes a
//! `DecodedPacket` and returns a `Protocol` enum. This makes it
//! trivially testable with synthetic packet fixtures.
//!
//! # Extension
//!
//! To add a new protocol:
//! 1. Add a variant to `edgeshield_common::Protocol`
//! 2. Add a port check in the appropriate match arm below
//! 3. Add a test fixture

use edgeshield_common::Protocol;
use edgeshield_packet::decode::{DecodedPacket, TransportHeader};
use tracing::{trace, Level};

/// Well-known UDP ports for protocol classification.
mod udp_ports {
    pub const DNS: u16 = 53;
    pub const DHCP_SERVER: u16 = 67;
    pub const DHCP_CLIENT: u16 = 68;
    pub const MDNS: u16 = 5353;
    pub const NTP: u16 = 123;
}

/// Well-known TCP ports for protocol classification.
mod tcp_ports {
    pub const DNS: u16 = 53;
    pub const HTTP: u16 = 80;
    pub const HTTPS: u16 = 443;
}

/// Classify a decoded packet into a protocol.
///
/// This is the main entry point. It examines the Ethernet type and
/// transport-layer ports to determine the protocol.
///
/// # Returns
///
/// A `Protocol` variant. Unknown protocols return `Protocol::Other(n)`.
pub fn classify(packet: &DecodedPacket<'_>) -> Protocol {
    let span = tracing::span!(Level::TRACE, "classify");
    let _guard = span.enter();

    // Check for ARP first (non-IP traffic)
    if packet.ethernet.ethertype == 0x0806 {
        trace!("classified as ARP");
        return Protocol::Arp;
    }

    // Must have IPv4 for further classification
    let _ip = match packet.ipv4 {
        Some(ref ip) => ip,
        None => {
            trace!("unknown ethertype: 0x{:04x}", packet.ethernet.ethertype);
            return Protocol::Other(0);
        }
    };

    // Classify by transport protocol
    match packet.transport {
        Some(ref transport) => match transport {
            TransportHeader::Tcp(tcp) => {
                classify_tcp(tcp.source_port, tcp.destination_port)
            }
            TransportHeader::Udp(udp) => {
                classify_udp(udp.source_port, udp.destination_port)
            }
            TransportHeader::Icmp(_) => {
                trace!("classified as ICMP");
                Protocol::Icmp
            }
        },
        None => {
            trace!("classified as IPv4 (no transport)");
            Protocol::Ipv4
        }
    }
}

/// Classify a TCP packet by its source and destination ports.
fn classify_tcp(src_port: u16, dst_port: u16) -> Protocol {
    if src_port == tcp_ports::DNS || dst_port == tcp_ports::DNS {
        trace!("classified as DNS (TCP)");
        return Protocol::Dns;
    }
    if src_port == tcp_ports::HTTP || dst_port == tcp_ports::HTTP {
        trace!("classified as HTTP");
        return Protocol::Http;
    }
    if src_port == tcp_ports::HTTPS || dst_port == tcp_ports::HTTPS {
        trace!("classified as HTTPS");
        return Protocol::Https;
    }
    trace!(src_port, dst_port, "classified as TCP");
    Protocol::Tcp
}

/// Classify a UDP packet by its source and destination ports.
fn classify_udp(src_port: u16, dst_port: u16) -> Protocol {
    if src_port == udp_ports::DNS || dst_port == udp_ports::DNS {
        trace!("classified as DNS (UDP)");
        return Protocol::Dns;
    }
    if src_port == udp_ports::DHCP_SERVER || dst_port == udp_ports::DHCP_SERVER
        || src_port == udp_ports::DHCP_CLIENT || dst_port == udp_ports::DHCP_CLIENT
    {
        trace!("classified as DHCP");
        return Protocol::Dhcp;
    }
    if src_port == udp_ports::MDNS || dst_port == udp_ports::MDNS {
        trace!("classified as mDNS");
        return Protocol::Mdns;
    }
    if src_port == udp_ports::NTP || dst_port == udp_ports::NTP {
        trace!("classified as NTP");
        return Protocol::Ntp;
    }
    trace!(src_port, dst_port, "classified as UDP");
    Protocol::Udp
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_packet::capture::PacketBuf;
    use edgeshield_packet::decode::decode_packet;

    fn build_udp_packet(src_port: u16, dst_port: u16) -> PacketBuf {
        let mut buf = Vec::with_capacity(42);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x08, 0x00]);
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x2a]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x40, 0x00]);
        buf.push(0x40);
        buf.push(0x11);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x10]);
        buf.extend_from_slice(&[0x00, 0x00]);
        PacketBuf::new(buf, 14)
    }

    fn build_tcp_packet(src_port: u16, dst_port: u16) -> PacketBuf {
        let mut buf = Vec::with_capacity(54);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x08, 0x00]);
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x34]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x40, 0x00]);
        buf.push(0x40);
        buf.push(0x06);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.push(0x50);
        buf.push(0x02);
        buf.extend_from_slice(&[0xff, 0xff]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]);
        PacketBuf::new(buf, 14)
    }

    fn build_arp_packet() -> PacketBuf {
        let mut buf = Vec::with_capacity(42);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x08, 0x06]);
        buf.extend_from_slice(&[0x00; 28]);
        PacketBuf::new(buf, 14)
    }

    fn build_icmp_packet() -> PacketBuf {
        let mut buf = Vec::with_capacity(42);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x00; 6]);
        buf.extend_from_slice(&[0x08, 0x00]);
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x1c]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x40, 0x00]);
        buf.push(0x40);
        buf.push(0x01);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);
        buf.push(0x08);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x00]);
        PacketBuf::new(buf, 14)
    }

    #[test]
    fn test_classify_arp() {
        let buf = build_arp_packet();
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Arp);
    }

    #[test]
    fn test_classify_udp() {
        let buf = build_udp_packet(12345, 54321);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Udp);
    }

    #[test]
    fn test_classify_dns_udp() {
        let buf = build_udp_packet(53, 12345);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Dns);
    }

    #[test]
    fn test_classify_dns_tcp() {
        let buf = build_tcp_packet(12345, 53);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Dns);
    }

    #[test]
    fn test_classify_dhcp_server() {
        let buf = build_udp_packet(67, 12345);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Dhcp);
    }

    #[test]
    fn test_classify_dhcp_client() {
        let buf = build_udp_packet(12345, 68);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Dhcp);
    }

    #[test]
    fn test_classify_http() {
        let buf = build_tcp_packet(12345, 80);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Http);
    }

    #[test]
    fn test_classify_https() {
        let buf = build_tcp_packet(12345, 443);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Https);
    }

    #[test]
    fn test_classify_mdns() {
        let buf = build_udp_packet(5353, 12345);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Mdns);
    }

    #[test]
    fn test_classify_ntp() {
        let buf = build_udp_packet(123, 12345);
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Ntp);
    }

    #[test]
    fn test_classify_icmp() {
        let buf = build_icmp_packet();
        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(classify(&decoded), Protocol::Icmp);
    }
}
