# Testing

## Testing Philosophy

EdgeShield follows a multi-layered testing strategy:

1. **Unit tests** verify individual functions and modules in isolation
2. **Integration tests** verify subsystem interactions through public APIs
3. **Benchmarks** measure performance and detect regressions
4. **Fuzz tests** discover edge cases in packet parsing

Tests are a first-class deliverable. Every pull request must include tests for new code and must not break existing tests.

## Unit Tests

### Location

Unit tests are defined in `#[cfg(test)] mod tests` blocks at the bottom of each source file. This keeps tests close to the code they test and allows testing private functions.

### Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;  // Import parent module items

    #[test]
    fn test_function_name_scenario() {
        // Arrange
        let input = ...;

        // Act
        let result = function_name(input);

        // Assert
        assert_eq!(result, expected);
    }
}
```

### Naming convention

Test function names follow the pattern `test_<function>_<scenario>`:

```rust
#[test]
fn test_decode_ethernet_ipv4_tcp() { ... }

#[test]
fn test_decode_truncated_packet() { ... }

#[test]
fn test_classify_arp() { ... }

#[test]
fn test_memory_store_upsert_and_get() { ... }
```

### What to test

- **Happy path**: Normal operation with valid input
- **Error paths**: Invalid input, truncated data, missing fields
- **Edge cases**: Empty data, boundary values, maximum values
- **Roundtrips**: Serialize → deserialize → compare
- **Invariants**: Properties that must always hold

### Async tests

Async functions use `#[tokio::test]`:

```rust
#[tokio::test]
async fn test_discovery_new_device() {
    let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
    let (event_tx, _) = mpsc::channel(100);
    let engine = DiscoveryEngine::new(store.clone(), event_tx);

    let buf = build_test_packet(&[0x00; 6], &[0x01; 6]);
    engine.process_packet(buf).await;

    let device = store.get(&MacAddress::new([0x00; 6])).unwrap().unwrap();
    assert_eq!(device.packet_count, 1);
}
```

## Integration Tests

### Location

Integration tests live in `tests/` at the crate level. They test the crate's public API by importing it as an external dependency.

### API integration tests

The `edgeshield-api` crate has integration tests that exercise the full HTTP stack:

```rust
// tests/api_integration.rs
use edgeshield_api::api::AppState;
use edgeshield_api::routes;
use axum::{Router, body::Body, http::Request};
use tower::ServiceExt;

#[tokio::test]
async fn test_health_endpoint() {
    let app = test_app();
    let response = app
        .oneshot(Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
```

### What integration tests cover

- **API endpoints**: Every endpoint with valid and invalid inputs
- **Pipeline integration**: Full capture → decode → classify → update flow
- **Store implementations**: All `DeviceStore` trait methods
- **Error propagation**: Errors at subsystem boundaries

## Packet Fixtures

### Synthetic packet builders

EdgeShield uses synthetic packet builders for testing. These construct valid Ethernet/IP/transport packets from raw bytes, avoiding the need for real network interfaces or pcap files.

```rust
/// Build a minimal Ethernet + IPv4 + TCP packet for testing.
fn build_test_packet() -> Vec<u8> {
    let mut buf = Vec::with_capacity(54);

    // Ethernet header (14 bytes)
    buf.extend_from_slice(&[0x00; 6]); // dst MAC
    buf.extend_from_slice(&[0x00; 6]); // src MAC
    buf.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

    // IPv4 header (20 bytes)
    buf.push(0x45); // version + IHL
    buf.push(0x00); // DSCP
    buf.extend_from_slice(&[0x00, 0x34]); // total length
    buf.extend_from_slice(&[0x00, 0x00]); // ID
    buf.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
    buf.push(0x40); // TTL
    buf.push(0x06); // protocol TCP
    buf.extend_from_slice(&[0x00, 0x00]); // checksum
    buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]); // src 192.168.1.1
    buf.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]); // dst 192.168.1.2

    // TCP header (20 bytes)
    buf.extend_from_slice(&[0x1f, 0x90]); // src port 8080
    buf.extend_from_slice(&[0x00, 0x50]); // dst port 80
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    buf.push(0x50); // data offset
    buf.push(0x00); // flags
    buf.extend_from_slice(&[0xff, 0xff]); // window
    buf.extend_from_slice(&[0x00, 0x00]); // checksum
    buf.extend_from_slice(&[0x00, 0x00]); // urgent

    buf
}
```

### Available fixtures

| Fixture | Protocols | Ports | IPs |
|---------|-----------|-------|-----|
| `build_test_packet()` | Ethernet + IPv4 + TCP | 8080 → 80 | 192.168.1.1 → 192.168.1.2 |
| `build_udp_packet(src, dst)` | Ethernet + IPv4 + UDP | Configurable | 192.168.1.1 → 192.168.1.2 |
| `build_arp_packet()` | Ethernet + ARP | N/A | N/A |
| `build_icmp_packet()` | Ethernet + IPv4 + ICMP | N/A | 192.168.1.1 → 192.168.1.2 |

### Adding new fixtures

When adding support for a new protocol, add a corresponding fixture builder:

1. Create a function `build_<protocol>_packet()` in the test module
2. Use it in tests for the new protocol
3. Add it to the shared test helpers if used across modules

## Benchmarks

### Criterion benchmarks

EdgeShield uses [Criterion](https://github.com/bheisler/criterion.rs) for benchmarks. Benchmarks are defined in `benches/` at the crate level.

```rust
// benches/packet_decode.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_decode_packet(c: &mut Criterion) {
    let data = build_test_packet();
    let buf = PacketBuf::new(data, 14);

    c.bench_function("decode_packet", |b| {
        b.iter(|| {
            let decoded = decode_packet(black_box(&buf)).unwrap();
            black_box(decoded);
        });
    });
}

criterion_group!(benches, bench_decode_packet);
criterion_main!(benches);
```

### Running benchmarks

```bash
# Run all benchmarks
cargo bench

# Run benchmarks for a specific crate
cargo bench -p edgeshield-packet

# Run a specific benchmark
cargo bench -- decode_packet
```

### Benchmark targets

| Benchmark | Target | Current | Measurement |
|-----------|--------|---------|-------------|
| `decode_packet` | < 500 ns | TBD | Per-packet latency |
| `classify` | < 100 ns | TBD | Per-packet latency |
| `store_upsert` | < 1 µs | TBD | Per-packet latency |
| `full_pipeline` | < 2 µs | TBD | End-to-end per-packet |
| `api_list_devices` | < 5 ms | TBD | 1000 devices |
| `api_get_device` | < 1 ms | TBD | Hash lookup |

## Performance Testing

### Throughput testing

Throughput testing measures how many packets per second EdgeShield can process on target hardware.

```bash
# Run the throughput test suite
cargo test --test throughput -- --nocapture
```

The throughput test generates synthetic packets at a configurable rate and measures:

- Packets per second processed
- Memory usage (RSS)
- Channel drop rate (backpressure behavior)
- API response time under load

### Memory profiling

```bash
# Build with debug symbols
cargo build

# Run under valgrind massif
valgrind --tool=massif target/debug/edgeshield run --config test_config.toml

# View the massif output
ms_print massif.out.*
```

### CPU profiling

```bash
# Build with frame pointers
RUSTFLAGS="-C force-frame-pointers=y" cargo build --release

# Run under perf
sudo perf record -g target/release/edgeshield run --config /etc/edgeshield/config.toml

# View the profile
sudo perf report
```

## Fuzz Testing

### Approach

Fuzz testing is planned for Phase 3 (protocol parsing). The fuzzer generates random byte sequences and feeds them to the packet decoder. The goal is to find:

- Panics in parsing code
- Infinite loops
- Excessive memory allocation
- Logic errors in protocol classification

### Tooling

EdgeShield will use `cargo-fuzz` (libFuzzer) for fuzz testing:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Initialize fuzz targets
cargo fuzz init

# Add a fuzz target for packet decoding
cargo fuzz add decode_packet
```

### Fuzz target

```rust
// fuzz/fuzz_targets/decode_packet.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use edgeshield_packet::capture::PacketBuf;
use edgeshield_packet::decode::decode_packet;

fuzz_target!(|data: &[u8]| {
    let buf = PacketBuf::new(data.to_vec(), 14);
    let _ = decode_packet(&buf);
});
```

### Running fuzz tests

```bash
# Run the fuzzer (indefinitely)
cargo fuzz run decode_packet

# Run with a specific number of iterations
cargo fuzz run decode_packet -- -runs=100000

# Run with a corpus directory
cargo fuzz run decode_packet -- corpus/
```

### Coverage

```bash
# Build with coverage instrumentation
cargo fuzz coverage decode_packet

# Generate coverage report
cargo fuzz coverage decode_packet -- corpus/
```

## CI Integration

### GitHub Actions

All tests run on every pull request and push to `main`/`develop`:

```yaml
# .github/workflows/ci.yml (abbreviated)
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo test --all-targets
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo fmt --check
      - run: cargo audit

  cross-compile:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - aarch64-unknown-linux-gnu
          - armv7-unknown-linux-gnueabihf
          - x86_64-unknown-linux-gnu
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo build --release --target ${{ matrix.target }}
```

### Test matrix

| Check | Command | Required |
|-------|---------|----------|
| Unit tests | `cargo test --all-targets` | ✅ |
| Clippy | `cargo clippy --all-targets -- -D warnings` | ✅ |
| Formatting | `cargo fmt --check` | ✅ |
| Audit | `cargo audit` | ✅ |
| Build (x86_64) | `cargo build --release` | ✅ |
| Build (aarch64) | `cross build --release --target aarch64-unknown-linux-gnu` | ✅ |
| Build (armv7) | `cross build --release --target armv7-unknown-linux-gnueabihf` | ✅ |
| Benchmarks | `cargo bench` (no regression check) | 📋 |
| Fuzz tests | `cargo fuzz run decode_packet -- -runs=10000` | 📋 |
