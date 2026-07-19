//! Integration test for the full EdgeShield pipeline.
//!
//! Exercises the complete flow: synthetic packet → decode → classify →
//! device update → store query. No real network interface needed.

use std::sync::Arc;

use mac_address::MacAddress;
use tokio::sync::mpsc;

use edgeshield_common::Protocol;
use edgeshield_discovery::discovery::{DiscoveryEngine, DiscoveryEvent};
use edgeshield_packet::capture::PacketBuf;
use edgeshield_storage::memory::MemoryStore;
use edgeshield_storage::store::DeviceStore;

/// Build a synthetic Ethernet + IPv4 + TCP packet.
///
/// Returns raw bytes suitable for wrapping in a PacketBuf.
fn build_tcp_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(54);

    // Ethernet header (14 bytes)
    buf.extend_from_slice(dst_mac);
    buf.extend_from_slice(src_mac);
    buf.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

    // IPv4 header (20 bytes)
    buf.push(0x45); // version 4, IHL 5 (20 bytes)
    buf.push(0x00); // DSCP + ECN
    buf.extend_from_slice(&0u16.to_be_bytes()); // total length — placeholder
    buf.extend_from_slice(&[0x00, 0x01]); // identification
    buf.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
    buf.push(0x40); // TTL 64
    buf.push(0x06); // protocol TCP
    buf.extend_from_slice(&[0x00, 0x00]); // header checksum (ignored)
    buf.extend_from_slice(src_ip);
    buf.extend_from_slice(dst_ip);

    // TCP header (20 bytes)
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sequence number
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack number
    buf.push(0x50); // data offset 5 (20 bytes)
    buf.push(0x02); // flags: SYN
    buf.extend_from_slice(&[0xff, 0xff]); // window size
    buf.extend_from_slice(&[0x00, 0x00]); // checksum (ignored)
    buf.extend_from_slice(&[0x00, 0x00]); // urgent pointer

    // Fix total length in IP header
    let total_len = buf.len() as u16;
    buf[16] = (total_len >> 8) as u8;
    buf[17] = (total_len & 0xff) as u8;

    buf
}

/// Build a synthetic ARP packet.
fn build_arp_packet(src_mac: &[u8; 6], src_ip: &[u8; 4]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(42);

    // Ethernet header (14 bytes)
    buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // broadcast dst
    buf.extend_from_slice(src_mac);
    buf.extend_from_slice(&[0x08, 0x06]); // EtherType ARP

    // ARP header (28 bytes)
    buf.extend_from_slice(&[0x00, 0x01]); // hardware type: Ethernet
    buf.extend_from_slice(&[0x08, 0x00]); // protocol type: IPv4
    buf.push(0x06); // hardware size
    buf.push(0x04); // protocol size
    buf.extend_from_slice(&[0x00, 0x01]); // opcode: request
    buf.extend_from_slice(src_mac); // sender MAC
    buf.extend_from_slice(src_ip); // sender IP
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // target MAC (unknown)
    buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]); // target IP 192.168.1.1

    buf
}

/// Build a synthetic UDP DNS query packet.
fn build_dns_packet(src_mac: &[u8; 6], dst_mac: &[u8; 6]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Ethernet header (14 bytes)
    buf.extend_from_slice(dst_mac);
    buf.extend_from_slice(src_mac);
    buf.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    buf.push(0x45);
    buf.push(0x00);
    buf.extend_from_slice(&0u16.to_be_bytes()); // placeholder
    buf.extend_from_slice(&[0x00, 0x02]);
    buf.extend_from_slice(&[0x40, 0x00]);
    buf.push(0x40);
    buf.push(0x11); // UDP
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x0a]); // src 192.168.1.10
    buf.extend_from_slice(&[0x08, 0x08, 0x08, 0x08]); // dst 8.8.8.8

    // UDP header (8 bytes)
    buf.extend_from_slice(&[0x00, 0x35]); // src port 53
    buf.extend_from_slice(&[0x00, 0x35]); // dst port 53
    buf.extend_from_slice(&[0x00, 0x10]); // length
    buf.extend_from_slice(&[0x00, 0x00]); // checksum

    // Fix total length
    let total_len = buf.len() as u16;
    buf[16] = (total_len >> 8) as u8;
    buf[17] = (total_len & 0xff) as u8;

    buf
}

#[tokio::test]
async fn test_pipeline_tcp_packet() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
    let (event_tx, _event_rx) = mpsc::channel::<DiscoveryEvent>(100);
    let engine = DiscoveryEngine::new(store.clone(), event_tx);

    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let src_ip = [192, 168, 1, 10];
    let dst_ip = [10, 0, 0, 1];

    let raw = build_tcp_packet(&src_mac, &dst_mac, &src_ip, &dst_ip, 12345, 23456);
    let buf = PacketBuf::new(raw, 14);
    engine.process_packet(buf).await;

    // Verify source device
    let src_mac_addr = MacAddress::new(src_mac);
    let src_device = store.get(&src_mac_addr).unwrap().expect("source device should exist");
    assert_eq!(src_device.packet_count, 1, "source should have 1 packet");
    assert!(src_device.bytes_sent > 0, "source should have bytes sent");
    assert!(src_device.protocols.contains(&Protocol::Tcp), "source should have TCP protocol");
    assert!(src_device.ips.contains(&"192.168.1.10".parse().unwrap()), "source should have its IP");

    // Verify destination device
    let dst_mac_addr = MacAddress::new(dst_mac);
    let dst_device = store.get(&dst_mac_addr).unwrap().expect("destination device should exist");
    assert_eq!(dst_device.packet_count, 1, "destination should have 1 packet");
    assert!(dst_device.bytes_received > 0, "destination should have bytes received");
    assert!(dst_device.protocols.contains(&Protocol::Tcp), "destination should have TCP protocol");
}

#[tokio::test]
async fn test_pipeline_arp_packet() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
    let (event_tx, _event_rx) = mpsc::channel::<DiscoveryEvent>(100);
    let engine = DiscoveryEngine::new(store.clone(), event_tx);

    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let src_ip = [192, 168, 1, 10];

    let raw = build_arp_packet(&src_mac, &src_ip);
    let buf = PacketBuf::new(raw, 14);
    engine.process_packet(buf).await;

    let mac_addr = MacAddress::new(src_mac);
    let device = store.get(&mac_addr).unwrap().expect("ARP sender should be discovered");
    assert!(device.protocols.contains(&Protocol::Arp), "ARP sender should have ARP protocol");
    assert_eq!(device.packet_count, 1);
}

#[tokio::test]
async fn test_pipeline_dns_packet() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
    let (event_tx, _event_rx) = mpsc::channel::<DiscoveryEvent>(100);
    let engine = DiscoveryEngine::new(store.clone(), event_tx);

    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    let raw = build_dns_packet(&src_mac, &dst_mac);
    let buf = PacketBuf::new(raw, 14);
    engine.process_packet(buf).await;

    let mac_addr = MacAddress::new(src_mac);
    let device = store.get(&mac_addr).unwrap().expect("DNS sender should be discovered");
    assert!(device.protocols.contains(&Protocol::Dns), "DNS sender should have DNS protocol");
}

#[tokio::test]
async fn test_pipeline_multiple_packets_same_device() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
    let (event_tx, _event_rx) = mpsc::channel::<DiscoveryEvent>(100);
    let engine = DiscoveryEngine::new(store.clone(), event_tx);

    let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let src_ip = [192, 168, 1, 10];
    let dst_ip = [10, 0, 0, 1];

    // Send 3 TCP packets from same source
    for _ in 0..3 {
        let raw = build_tcp_packet(&src_mac, &dst_mac, &src_ip, &dst_ip, 12345, 23456);
        engine.process_packet(PacketBuf::new(raw, 14)).await;
    }

    let mac_addr = MacAddress::new(src_mac);
    let device = store.get(&mac_addr).unwrap().expect("device should exist");
    assert_eq!(device.packet_count, 3, "device should have 3 packets after 3 sends");
}

#[tokio::test]
async fn test_pipeline_multiple_devices() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
    let (event_tx, _event_rx) = mpsc::channel::<DiscoveryEvent>(100);
    let engine = DiscoveryEngine::new(store.clone(), event_tx);

    let _dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    // Three different source MACs
    let devices = [
        ([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], [192, 168, 1, 10]),
        ([0x00, 0x11, 0x22, 0x33, 0x44, 0x66], [192, 168, 1, 11]),
        ([0x00, 0x11, 0x22, 0x33, 0x44, 0x77], [192, 168, 1, 12]),
    ];

    for (mac, ip) in &devices {
        let raw = build_arp_packet(mac, ip);
        engine.process_packet(PacketBuf::new(raw, 14)).await;
    }

    let all = store.list().unwrap();
    // 3 devices + 1 broadcast MAC (ff:ff:ff:ff:ff:ff) from ARP destination
    assert_eq!(all.len(), 4, "should have 3 devices + broadcast MAC");

    // Verify all 3 source MACs are present
    for (mac, _) in &devices {
        let addr = MacAddress::new(*mac);
        assert!(store.get(&addr).unwrap().is_some(), "device {} should exist", addr);
    }
}
