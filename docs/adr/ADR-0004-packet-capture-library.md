# ADR-0004: Packet Capture Library

## Status

Accepted

## Context

EdgeShield needs to capture raw Ethernet frames from a network interface. The capture library must:

- Open a raw socket on a specified interface
- Place the interface in promiscuous mode
- Read raw Ethernet frames (including link-layer headers)
- Support Linux (Raspberry Pi OS, Ubuntu, Debian, Fedora)
- Optionally support macOS for development
- Be callable from Rust with minimal `unsafe` code

### Considered options

1. **pnet**: Pure Rust wrapper around libpcap and raw sockets
2. **pcap**: Rust bindings to libpcap
3. **raw_socket**: Direct `AF_PACKET` socket usage via `std::net`
4. **etherparse**: Packet parsing only (no capture)
5. **libpcap via FFI**: Manual C bindings to libpcap

## Decision

Use the `pnet` crate for packet capture, with `etherparse` as a secondary dependency for packet parsing utilities.

## Rationale

### pnet

`pnet` provides a high-level API for packet capture that abstracts over the platform-specific details:

```rust
use pnet::datalink::{self, Channel};

let interface = datalink::interfaces()
    .into_iter()
    .find(|iface| iface.name == "eth0")
    .unwrap();

let channel = datalink::channel(&interface, Default::default()).unwrap();
let (_, mut rx) = match channel {
    Channel::Ethernet(_, rx) => rx,
    _ => panic!("unsupported channel type"),
};

match rx.next() {
    Ok(packet) => { /* process packet */ }
    Err(e) => { /* handle error */ }
}
```

Key advantages:

- **Cross-platform**: Works on Linux and macOS (via libpcap or raw sockets)
- **Promiscuous mode**: Automatically enabled when opening the channel
- **Buffer management**: Returns `Vec<u8>` buffers that we convert to `bytes::Bytes`
- **Mature**: Version 0.35, widely used in the Rust networking ecosystem
- **Safe API**: The `unsafe` code is contained within pnet, not in EdgeShield

### etherparse

`etherparse` is used as a secondary dependency for:

- Parsing individual protocol headers without the full pnet packet API
- Building synthetic test packets
- Future protocol support (IPv6, VLAN, MPLS)

### Why not alternatives

- **pcap crate**: Requires libpcap development headers at build time. pnet can use raw sockets directly on Linux, avoiding the libpcap dependency.
- **raw_socket**: Requires manual `AF_PACKET` socket management, which is error-prone and platform-specific.
- **libpcap via FFI**: Would require `unsafe` code in EdgeShield, which we want to avoid.
- **etherparse alone**: Provides parsing but not capture. We need both.

## Consequences

### Positive

- Cross-platform capture support (Linux, macOS)
- No libpcap dependency on Linux (uses raw sockets)
- Safe Rust API (unsafe code contained in pnet)
- Mature, well-tested library
- Automatic promiscuous mode management

### Negative

- pnet has a significant dependency tree (includes libpcap bindings for macOS)
- pnet's API is somewhat dated (uses `Vec<u8>` instead of `Bytes` directly)
- Some pnet features are Linux-specific (e.g., `Channel::Ethernet`)

### Neutral

- pnet's `DataLinkReceiver::next()` is blocking — this is why we use a dedicated OS thread
- We convert pnet's `Vec<u8>` to `bytes::Bytes` for zero-copy sharing

## Buffer Lifecycle

```text
pnet allocates Vec<u8> (per-packet allocation)
    │
    ▼
PacketBuf::new(data, 14) converts Vec<u8> → bytes::Bytes
    │  (zero-copy: Bytes takes ownership of the Vec's buffer)
    ▼
PacketBuf sent over mpsc channel (refcount bump, no data copy)
    │
    ▼
Pipeline receives PacketBuf, decodes headers in-place
    │
    ▼
PacketBuf dropped, buffer freed
```

## References

- [pnet crate documentation](https://docs.rs/pnet/)
- [etherparse crate documentation](https://docs.rs/etherparse/)
- [bytes crate documentation](https://docs.rs/bytes/)
