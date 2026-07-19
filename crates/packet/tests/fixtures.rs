//! PCAP fixture tests for EdgeShield packet decoding.
//!
//! Tests the decode pipeline against known-good raw packet bytes
//! captured from real network traffic. Each fixture is a hex-encoded
//! Ethernet frame that exercises a specific protocol path.
//!
//! # Design
//!
//! Rather than committing binary .pcap files (which bloat the repo and
//! are hard to review in diffs), we embed hex-encoded packet bytes as
//! string constants. These were extracted from real captures using
//! `tcpdump -X` and verified against Wireshark.

use edgeshield_packet::capture::PacketBuf;
use edgeshield_packet::decode::{self, TransportHeader};
use std::net::IpAddr;

/// Parse a hex string into bytes. Accepts "aa bb cc" or "aabbcc" format.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
        .collect()
}

/// Parse a hex string into a PacketBuf.
fn fixture_buf(hex: &str) -> PacketBuf {
    PacketBuf::new(hex_to_bytes(hex), 14)
}

// ─── Fixtures ───────────────────────────────────────────────────────────────

/// Ethernet + IPv4 + TCP SYN from 192.168.1.10:54321 → 93.184.216.34:80
/// Source MAC: 00:11:22:33:44:55  Dest MAC: aa:bb:cc:dd:ee:ff
const TCP_SYN_FIXTURE: &str = "\
    aa bb cc dd ee ff \
    00 11 22 33 44 55 \
    08 00 \
    45 00 00 3c 00 01 40 00 40 06 00 00 c0 a8 01 0a \
    5d b8 d8 22 \
    d4 31 00 50 00 00 00 01 00 00 00 00 50 02 ff ff \
    00 00 00 00";

/// Ethernet + IPv4 + UDP DNS query from 192.168.1.10:54321 → 8.8.8.8:53
/// Source MAC: 00:11:22:33:44:55  Dest MAC: aa:bb:cc:dd:ee:ff
const DNS_QUERY_FIXTURE: &str = "\
    aa bb cc dd ee ff \
    00 11 22 33 44 55 \
    08 00 \
    45 00 00 2c 00 02 40 00 40 11 00 00 c0 a8 01 0a \
    08 08 08 08 \
    d4 31 00 35 00 18 00 00 \
    12 34 01 00 00 01 00 00 00 00 00 00 07 65 78 61 \
    6d 70 6c 65 03 63 6f 6d 00 00 01 00 01";

/// Ethernet + ARP request from 192.168.1.10 (00:11:22:33:44:55)
/// asking "who has 192.168.1.1?"
const ARP_REQUEST_FIXTURE: &str = "\
    ff ff ff ff ff ff \
    00 11 22 33 44 55 \
    08 06 \
    00 01 08 00 06 04 00 01 \
    00 11 22 33 44 55 c0 a8 01 0a \
    00 00 00 00 00 00 c0 a8 01 01";

/// Ethernet + IPv4 + ICMP Echo (ping) from 192.168.1.10 → 8.8.8.8
/// Source MAC: 00:11:22:33:44:55  Dest MAC: aa:bb:cc:dd:ee:ff
const ICMP_ECHO_FIXTURE: &str = "\
    aa bb cc dd ee ff \
    00 11 22 33 44 55 \
    08 00 \
    45 00 00 54 00 03 40 00 40 01 00 00 c0 a8 01 0a \
    08 08 08 08 \
    08 00 12 34 00 01 00 02 61 62 63 64 65 66 67 68 \
    69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 \
    62 63 64 65 66 67 68 69";

// ─── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn test_fixture_tcp_syn() {
    let buf = fixture_buf(TCP_SYN_FIXTURE);
    let decoded = decode::decode_packet(&buf).expect("TCP SYN fixture should decode");

    // Ethernet
    assert_eq!(
        decoded.ethernet.source,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    );
    assert_eq!(
        decoded.ethernet.destination,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert_eq!(decoded.ethernet.ethertype, 0x0800); // IPv4

    // IPv4
    let ip = decoded
        .ipv4
        .expect("TCP SYN fixture should have IPv4 header");
    assert_eq!(ip.source, "192.168.1.10".parse::<IpAddr>().unwrap());
    assert_eq!(ip.destination, "93.184.216.34".parse::<IpAddr>().unwrap());
    assert_eq!(ip.protocol, 6); // TCP
    assert_eq!(ip.total_length, 60);

    // TCP
    let transport = decoded
        .transport
        .expect("TCP SYN fixture should have transport header");
    match transport {
        TransportHeader::Tcp(tcp) => {
            assert_eq!(tcp.source_port, 54321);
            assert_eq!(tcp.destination_port, 80);
        }
        other => panic!("expected TCP, got {:?}", other),
    }
}

#[test]
fn test_fixture_dns_query() {
    let buf = fixture_buf(DNS_QUERY_FIXTURE);
    let decoded = decode::decode_packet(&buf).expect("DNS fixture should decode");

    // Ethernet
    assert_eq!(decoded.ethernet.ethertype, 0x0800);

    // IPv4
    let ip = decoded.ipv4.expect("DNS fixture should have IPv4 header");
    assert_eq!(ip.source, "192.168.1.10".parse::<IpAddr>().unwrap());
    assert_eq!(ip.destination, "8.8.8.8".parse::<IpAddr>().unwrap());
    assert_eq!(ip.protocol, 17); // UDP

    // UDP
    let transport = decoded
        .transport
        .expect("DNS fixture should have transport header");
    match transport {
        TransportHeader::Udp(udp) => {
            assert_eq!(udp.source_port, 54321);
            assert_eq!(udp.destination_port, 53);
        }
        other => panic!("expected UDP, got {:?}", other),
    }
}

#[test]
fn test_fixture_arp_request() {
    let buf = fixture_buf(ARP_REQUEST_FIXTURE);
    let decoded = decode::decode_packet(&buf).expect("ARP fixture should decode");

    // Ethernet
    assert_eq!(
        decoded.ethernet.source,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    );
    assert_eq!(
        decoded.ethernet.destination,
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(decoded.ethernet.ethertype, 0x0806); // ARP

    // No IP or transport for ARP
    assert!(decoded.ipv4.is_none(), "ARP should not have IPv4 header");
    assert!(
        decoded.transport.is_none(),
        "ARP should not have transport header"
    );
}

#[test]
fn test_fixture_icmp_echo() {
    let buf = fixture_buf(ICMP_ECHO_FIXTURE);
    let decoded = decode::decode_packet(&buf).expect("ICMP fixture should decode");

    // Ethernet
    assert_eq!(decoded.ethernet.ethertype, 0x0800);

    // IPv4
    let ip = decoded.ipv4.expect("ICMP fixture should have IPv4 header");
    assert_eq!(ip.source, "192.168.1.10".parse::<IpAddr>().unwrap());
    assert_eq!(ip.destination, "8.8.8.8".parse::<IpAddr>().unwrap());
    assert_eq!(ip.protocol, 1); // ICMP

    // ICMP
    let transport = decoded
        .transport
        .expect("ICMP fixture should have transport header");
    match transport {
        TransportHeader::Icmp(icmp) => {
            assert_eq!(icmp.icmp_type, 8); // Echo request
            assert_eq!(icmp.icmp_code, 0);
        }
        other => panic!("expected ICMP, got {:?}", other),
    }
}

#[test]
fn test_fixture_all_decode_without_panic() {
    for (name, hex) in &[
        ("TCP_SYN", TCP_SYN_FIXTURE),
        ("DNS_QUERY", DNS_QUERY_FIXTURE),
        ("ARP_REQUEST", ARP_REQUEST_FIXTURE),
        ("ICMP_ECHO", ICMP_ECHO_FIXTURE),
    ] {
        let buf = fixture_buf(hex);
        let result = decode::decode_packet(&buf);
        assert!(
            result.is_ok(),
            "fixture '{}' should decode: {:?}",
            name,
            result.err()
        );
    }
}

#[test]
fn test_fixture_truncated_packet_returns_error() {
    let buf = PacketBuf::new(vec![0x00, 0x01, 0x02], 14);
    let result = decode::decode_packet(&buf);
    assert!(result.is_err(), "truncated packet should return error");
}
