//! Packet capture for EdgeShield.
//!
//! This module handles raw packet capture from a network interface
//! using the `pcap` library. It owns the packet buffer lifecycle.
//!
//! # Why pcap instead of pnet::datalink
//!
//! `pnet::datalink::channel()` puts the interface into promiscuous mode
//! by default, which on WiFi interfaces disrupts the kernel's normal
//! network stack — it steals packets from the kernel, starving the
//! regular network path and causing connectivity loss.
//!
//! The `pcap` crate gives us precise control over capture parameters:
//! - `promisc(false)`: read-only capture, no promiscuous mode
//! - `immediate_mode(true)`: deliver packets immediately, no kernel buffering
//! - `timeout`: non-blocking read so the capture thread can check stop signals
//!
//! # Ownership
//!
//! `PacketBuf` wraps `bytes::Bytes`, a refcounted `'static` slice.
//! This allows the packet to be sent across tokio task boundaries without
//! lifetime gymnastics. The buffer is allocated by pcap and converted to
//! `Bytes` once, then shared by reference (via clone = atomic refcount bump)
//! through the pipeline stages.

use pcap::{Capture, Device};
use tokio::sync::mpsc;
use tracing::{Level, info, span, warn};

use edgeshield_common::PacketError;

/// Maximum consecutive capture errors before giving up.
const MAX_CAPTURE_ERRORS: u32 = 10;

/// Delay between reconnect attempts (milliseconds).
const RECONNECT_DELAY_MS: u64 = 2000;

/// A captured raw packet buffer.
///
/// # Ownership
///
/// `PacketBuf` wraps `bytes::Bytes`, which is a refcounted, `'static` slice.
/// This allows the packet to be sent across tokio task boundaries without
/// lifetime gymnastics.
#[derive(Debug, Clone)]
pub struct PacketBuf {
    /// The raw packet bytes, including the link-layer header.
    pub raw: bytes::Bytes,
    /// The length of the link-layer header in bytes.
    pub link_header_len: usize,
}

impl PacketBuf {
    /// Create a new packet buffer from raw bytes.
    pub fn new(data: Vec<u8>, link_header_len: usize) -> Self {
        Self {
            raw: bytes::Bytes::from(data),
            link_header_len,
        }
    }

    /// Get the network-layer payload (skipping the link header).
    ///
    /// Returns an empty slice for runt frames shorter than the link header
    /// rather than panicking. The decoder treats an empty payload as a
    /// `Truncated` error downstream, so this is defense in depth — the
    /// capture thread must never crash on a malformed frame.
    pub fn network_payload(&self) -> &[u8] {
        self.raw.get(self.link_header_len..).unwrap_or(&[])
    }
}

/// A running packet capture session.
///
/// Spawns a dedicated OS thread for packet capture (pcap's capture API
/// is blocking), then sends captured packets over an mpsc channel to
/// the async pipeline.
///
/// # Error recovery
///
/// If the capture interface goes down, the capture thread enters a
/// reconnect loop: it waits 2 seconds, then tries to re-open the
/// interface. After 10 consecutive failures it gives up.
///
/// # WiFi safety
///
/// Capture uses `promisc(false)` and `immediate_mode(true)` to avoid
/// disrupting normal network connectivity on wireless interfaces.
pub struct CaptureSession {
    /// Receiver for captured packets.
    pub rx: mpsc::Receiver<PacketBuf>,
    /// Handle to stop the capture thread.
    stop_tx: Option<std::sync::mpsc::Sender<()>>,
    /// The OS thread running the capture loop.
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl CaptureSession {
    /// Start capturing packets on the given interface.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - The network interface name (e.g., "eth0")
    /// * `channel_size` - The mpsc channel buffer size
    ///
    /// # Returns
    ///
    /// A `CaptureSession` with a receiver for captured packets.
    ///
    /// # Design
    ///
    /// We spawn a dedicated OS thread because pcap uses blocking I/O.
    /// The thread reads packets in a loop and sends them over a bounded
    /// mpsc channel. Backpressure is handled by the channel — if the
    /// pipeline is slow, packets are dropped at the capture level.
    pub fn start(interface_name: &str, channel_size: usize) -> Result<Self, PacketError> {
        let span = span!(Level::INFO, "capture", interface = %interface_name);
        let _guard = span.enter();

        let (tx, rx_channel) = mpsc::channel::<PacketBuf>(channel_size);
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

        let thread_interface = interface_name.to_string();
        let thread_handle = std::thread::Builder::new()
            .name(format!("pcap-{}", interface_name))
            .spawn(move || {
                let span = span!(Level::INFO, "capture-loop", interface = %thread_interface);
                let _guard = span.enter();

                Self::capture_loop(&thread_interface, &tx, &stop_rx);
            })
            .map_err(|e| PacketError::Capture(format!("failed to spawn capture thread: {e}")))?;

        info!("capture started on {}", interface_name);

        Ok(Self {
            rx: rx_channel,
            stop_tx: Some(stop_tx),
            thread_handle: Some(thread_handle),
        })
    }

    /// The main capture loop, running on a dedicated OS thread.
    fn capture_loop(
        interface_name: &str,
        tx: &mpsc::Sender<PacketBuf>,
        stop_rx: &std::sync::mpsc::Receiver<()>,
    ) {
        let mut consecutive_errors: u32 = 0;

        loop {
            // Check if we should stop
            if stop_rx.try_recv().is_ok() {
                info!("capture thread stopping");
                return;
            }

            // Try to open the interface
            let mut cap = match Self::open_capture(interface_name) {
                Ok(cap) => {
                    consecutive_errors = 0;
                    cap
                }
                Err(e) => {
                    consecutive_errors += 1;
                    warn!(
                        error = %e,
                        consecutive_errors = consecutive_errors,
                        max_errors = MAX_CAPTURE_ERRORS,
                        "failed to open capture interface"
                    );

                    if consecutive_errors >= MAX_CAPTURE_ERRORS {
                        warn!("too many consecutive errors, giving up");
                        return;
                    }

                    std::thread::sleep(std::time::Duration::from_millis(RECONNECT_DELAY_MS));
                    continue;
                }
            };

            // Compute the link-layer header length from the *actual* datalink
            // type reported by pcap. Hardcoding 14 (Ethernet) silently breaks
            // on Linux cooked captures (SLL, 16 bytes — common in containers
            // and the `any` interface), raw IP (0 bytes), and VLAN-tagged
            // frames. See `linktype_to_header_len` for the mapping.
            let link_header_len = linktype_to_header_len(cap.get_datalink());

            // Read packets from the interface
            loop {
                // Check if we should stop
                if stop_rx.try_recv().is_ok() {
                    info!("capture thread stopping");
                    return;
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        consecutive_errors = 0;
                        let buf = PacketBuf::new(packet.data.to_vec(), link_header_len);
                        if tx.try_send(buf).is_err() {
                            // Channel full — packet dropped. Intentional backpressure.
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // No packet available within the timeout — loop back and
                        // check stop signal. This is the non-blocking path.
                        continue;
                    }
                    Err(e) => {
                        warn!("capture error: {} — will attempt reconnect", e);
                        break; // break to outer loop for reconnect
                    }
                }
            }
        }
    }

    /// Open a capture handle on the given interface.
    ///
    /// Uses read-only mode (no promiscuous) and immediate delivery
    /// to avoid disrupting normal network traffic, especially on WiFi.
    fn open_capture(interface_name: &str) -> Result<Capture<pcap::Active>, PacketError> {
        // Construct a minimal Device struct — avoids calling Device::list()
        // which can fail under restricted capabilities.
        let device = Device {
            name: interface_name.to_string(),
            desc: None,
            addresses: vec![],
            flags: pcap::DeviceFlags::empty(),
        };

        // Open with read-only, non-promiscuous mode
        let cap = Capture::from_device(device)
            .map_err(|e| PacketError::CaptureOpen {
                interface: interface_name.to_string(),
                source: Box::new(e),
            })?
            .promisc(false) // CRITICAL: no promiscuous mode — avoids WiFi disruption
            .immediate_mode(true) // Deliver packets immediately, no kernel buffering
            .timeout(500) // 500ms read timeout — allows checking stop signal
            .open()
            .map_err(|e| PacketError::CaptureOpen {
                interface: interface_name.to_string(),
                source: Box::new(e),
            })?;

        Ok(cap)
    }

    /// Stop the capture session and wait for the thread to finish.
    pub fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Map a pcap datalink type to the length of its link-layer header in bytes.
///
/// This is the single source of truth for "where does the network-layer
/// payload start in a captured frame." Getting this wrong silently
/// corrupts every decoded packet — see the SLL/VLAN note in `capture_loop`.
///
/// # Known link types
///
/// | DLT | Name              | Header len |
/// |-----|-------------------|------------|
/// | 1   | EN10MB (Ethernet) | 14         |
/// | 12  | RAW (raw IP)      | 0          |
/// | 113 | LINUX_SLL         | 16         |
///
/// Unknown link types default to 14 (Ethernet) with a warning. This is a
/// pragmatic default for a homelab appliance; a stricter deployment should
/// treat unknown link types as a capture-open failure.
fn linktype_to_header_len(linktype: pcap::Linktype) -> usize {
    match linktype.0 {
        1 => 14,   // EN10MB — Ethernet II
        12 => 0,   // RAW — raw IP, no link-layer header
        113 => 16, // LINUX_SLL — Linux cooked capture (the `any` device)
        other => {
            warn!(
                link_type = other,
                "unknown pcap link type; assuming 14-byte Ethernet header. \
                 If packets decode incorrectly, the interface may use a \
                 different link-layer framing."
            );
            14
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop();
    }
}
