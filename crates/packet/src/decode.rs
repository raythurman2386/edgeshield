//! Packet decoding for EdgeShield.
//!
//! This module provides parsing of Ethernet, IPv4, and transport-layer
//! headers from raw packet buffers.
//!
//! # Design
//!
//! We copy header fields into owned structs rather than borrowing from
//! the packet buffer. This is the right tradeoff because:
//!
//! 1. Header fields are small (MAC: 6 bytes, IP: 4 bytes, ports: 2 bytes)
//! 2. Owned structs are `Send + Sync` and can cross tokio task boundaries
//! 3. The packet buffer can be dropped immediately after decoding
//! 4. No lifetime complexity in the pipeline
//!
//! The payload is referenced via the original buffer, not through
//! temporary pnet packet structs, to avoid lifetime issues.

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use tracing::trace;

use edgeshield_common::PacketError;

use crate::capture::PacketBuf;

/// A fully decoded packet with owned header fields.
///
/// # Ownership
///
/// All header fields are owned (copied from the buffer). The `payload`
/// field borrows from the `PacketBuf` and is only valid during the
/// decode+classify step.
#[derive(Debug)]
pub struct DecodedPacket<'buf> {
    /// Reference to the raw packet buffer.
    pub raw: &'buf PacketBuf,
    /// Parsed Ethernet header.
    pub ethernet: EthernetHeader,
    /// Optional parsed IPv4 header.
    pub ipv4: Option<Ipv4Header>,
    /// Optional parsed transport-layer header.
    pub transport: Option<TransportHeader>,
    /// The network-layer payload (after IP header).
    pub payload: &'buf [u8],
}

/// Parsed Ethernet header fields (owned).
#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ethertype: u16,
}

/// Parsed IPv4 header fields (owned).
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub total_length: u16,
    /// Offset from the start of the Ethernet frame to the transport payload.
    pub header_length: u8,
}

/// Parsed transport-layer header (owned).
#[derive(Debug, Clone)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
}

/// Parsed TCP header fields (owned).
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
}

/// Parsed UDP header fields (owned).
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
}

/// Parsed ICMP header fields (owned).
#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
}

/// Decode a raw packet buffer into parsed headers.
///
/// This is the entry point for the decode pipeline. It parses the
/// Ethernet header, then optionally parses IPv4 and transport headers.
///
/// # Errors
///
/// Returns `PacketError::Truncated` if the packet is too short for
/// the expected headers.
///
/// # Performance
///
/// Header fields are copied (they're small). The payload reference
/// borrows from the input buffer for zero-copy protocol classification.
pub fn decode_packet(buf: &PacketBuf) -> Result<DecodedPacket<'_>, PacketError> {
    let span = tracing::span!(tracing::Level::TRACE, "decode");
    let _guard = span.enter();

    let ethernet = decode_ethernet(buf)?;
    let (ipv4, transport, payload) = if ethernet.ethertype == EtherTypes::Ipv4.0 {
        let ip_header = decode_ipv4(&buf.raw[14..])?;
        let transport_offset = 14 + ip_header.header_length as usize;
        let (transport, payload_end) = decode_transport(&ip_header, &buf.raw[transport_offset..])?;
        let payload = &buf.raw[transport_offset + payload_end..];
        (Some(ip_header), transport, payload)
    } else {
        (None, None, &[][..])
    };

    trace!(
        ethertype = format_args!("0x{:04x}", ethernet.ethertype),
        has_ip = ipv4.is_some(),
        has_transport = transport.is_some(),
        "packet decoded"
    );

    Ok(DecodedPacket {
        raw: buf,
        ethernet,
        ipv4,
        transport,
        payload,
    })
}

/// Decode the Ethernet header from a packet buffer.
fn decode_ethernet(buf: &PacketBuf) -> Result<EthernetHeader, PacketError> {
    let ethernet = EthernetPacket::new(&buf.raw).ok_or(PacketError::Truncated {
        expected: 14,
        actual: buf.raw.len(),
    })?;

    Ok(EthernetHeader {
        source: ethernet.get_source().into(),
        destination: ethernet.get_destination().into(),
        ethertype: ethernet.get_ethertype().0,
    })
}

/// Decode the IPv4 header from the Ethernet payload.
fn decode_ipv4(data: &[u8]) -> Result<Ipv4Header, PacketError> {
    let ipv4 = Ipv4Packet::new(data).ok_or(PacketError::Truncated {
        expected: 20,
        actual: data.len(),
    })?;

    Ok(Ipv4Header {
        source: IpAddr::V4(ipv4.get_source()),
        destination: IpAddr::V4(ipv4.get_destination()),
        protocol: ipv4.get_next_level_protocol().0,
        total_length: ipv4.get_total_length(),
        header_length: ipv4.get_header_length() * 4, // IHL is in 32-bit words
    })
}

/// Decode the transport-layer header.
///
/// Returns (transport_header, payload_offset_from_transport_start).
/// The payload offset tells the caller where the transport payload begins
/// relative to the start of the transport header data.
fn decode_transport(
    ip: &Ipv4Header,
    transport_data: &[u8],
) -> Result<(Option<TransportHeader>, usize), PacketError> {
    match ip.protocol {
        p if p == IpNextHeaderProtocols::Tcp.0 => {
            let tcp = TcpPacket::new(transport_data).ok_or(PacketError::Truncated {
                expected: 20,
                actual: transport_data.len(),
            })?;
            let header = TcpHeader {
                source_port: tcp.get_source(),
                destination_port: tcp.get_destination(),
            };
            let data_offset = tcp.get_data_offset() as usize * 4;
            Ok((Some(TransportHeader::Tcp(header)), data_offset))
        }
        p if p == IpNextHeaderProtocols::Udp.0 => {
            let udp = UdpPacket::new(transport_data).ok_or(PacketError::Truncated {
                expected: 8,
                actual: transport_data.len(),
            })?;
            let header = UdpHeader {
                source_port: udp.get_source(),
                destination_port: udp.get_destination(),
            };
            Ok((Some(TransportHeader::Udp(header)), 8))
        }
        p if p == IpNextHeaderProtocols::Icmp.0 => {
            let icmp = IcmpPacket::new(transport_data).ok_or(PacketError::Truncated {
                expected: 4,
                actual: transport_data.len(),
            })?;
            let header = IcmpHeader {
                icmp_type: icmp.get_icmp_type().0,
                icmp_code: icmp.get_icmp_code().0,
            };
            Ok((Some(TransportHeader::Icmp(header)), 4))
        }
        _ => Ok((None, 0)),
    }
}

/// Decode an ARP packet from the Ethernet payload.
pub fn decode_arp(data: &[u8]) -> Result<ArpPacket<'_>, PacketError> {
    ArpPacket::new(data).ok_or(PacketError::Truncated {
        expected: 28,
        actual: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet + IPv4 + TCP packet for testing.
    fn build_test_packet() -> Vec<u8> {
        let mut buf = Vec::with_capacity(54);

        // Ethernet header (14 bytes)
        buf.extend_from_slice(&[0x00; 6]); // dst MAC
        buf.extend_from_slice(&[0x00; 6]); // src MAC
        buf.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header (20 bytes)
        buf.push(0x45); // version + IHL (5 => 20 bytes)
        buf.push(0x00); // DSCP
        buf.extend_from_slice(&[0x00, 0x34]); // total length (52)
        buf.extend_from_slice(&[0x00, 0x00]); // ID
        buf.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
        buf.push(0x40); // TTL
        buf.push(0x06); // protocol TCP
        buf.extend_from_slice(&[0x00, 0x00]); // checksum (not checked)
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]); // src 192.168.1.1
        buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]); // dst 192.168.1.2

        // TCP header (20 bytes)
        buf.extend_from_slice(&[0x1f, 0x90]); // src port 8080
        buf.extend_from_slice(&[0x00, 0x50]); // dst port 80
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        buf.push(0x50); // data offset (5 => 20 bytes)
        buf.push(0x00); // flags
        buf.extend_from_slice(&[0xff, 0xff]); // window
        buf.extend_from_slice(&[0x00, 0x00]); // checksum
        buf.extend_from_slice(&[0x00, 0x00]); // urgent

        buf
    }

    #[test]
    fn test_decode_ethernet_ipv4_tcp() {
        let data = build_test_packet();
        let buf = PacketBuf::new(data, 14);
        let decoded = decode_packet(&buf).unwrap();

        assert_eq!(decoded.ethernet.ethertype, 0x0800);
        assert!(decoded.ipv4.is_some());

        let ip = decoded.ipv4.as_ref().unwrap();
        assert_eq!(ip.source, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ip.destination, "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(ip.protocol, 6); // TCP

        let transport = decoded.transport.as_ref().unwrap();
        match transport {
            TransportHeader::Tcp(tcp) => {
                assert_eq!(tcp.source_port, 8080);
                assert_eq!(tcp.destination_port, 80);
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn test_decode_ethernet_only() {
        // Build a non-IP packet (EtherType 0x0806 = ARP)
        let mut buf = Vec::with_capacity(14);
        buf.extend_from_slice(&[0x00; 6]); // dst MAC
        buf.extend_from_slice(&[0x00; 6]); // src MAC
        buf.extend_from_slice(&[0x08, 0x06]); // EtherType ARP

        let packet_buf = PacketBuf::new(buf, 14);
        let decoded = decode_packet(&packet_buf).unwrap();

        assert_eq!(decoded.ethernet.ethertype, 0x0806);
        assert!(decoded.ipv4.is_none());
        assert!(decoded.transport.is_none());
    }

    #[test]
    fn test_decode_truncated_packet() {
        let buf = PacketBuf::new(vec![0x00, 0x01, 0x02], 14);
        let result = decode_packet(&buf);
        assert!(result.is_err());
    }
}
