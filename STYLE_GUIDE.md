# Style Guide

This document defines the coding standards for all EdgeShield Rust code. These standards are enforced through `cargo clippy`, `cargo fmt`, and code review.

## Naming Conventions

EdgeShield follows the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) with the following specifics:

| Category | Convention | Example |
|----------|------------|---------|
| Types | `PascalCase` | `DiscoveryEngine`, `PacketBuf` |
| Enums | `PascalCase` | `Protocol::Tcp`, `TransportHeader::Udp` |
| Enum variants | `PascalCase` | `DiscoveryEvent::DeviceDiscovered` |
| Functions | `snake_case` | `decode_packet`, `classify` |
| Methods | `snake_case` | `device.record_sent()`, `store.upsert()` |
| Variables | `snake_case` | `src_mac`, `packet_count` |
| Constants | `SCREAMING_SNAKE_CASE` | `DEFAULT_API_PORT` |
| Type parameters | short `PascalCase` | `T`, `E`, `Store` |
| Lifetimes | short lowercase | `'a`, `'buf` |
| Modules | `snake_case` | `edgeshield_packet::capture` |
| Crates | `kebab-case` | `edgeshield-packet` |
| Feature flags | `snake_case` | `json-logging` |

### Abbreviations

- Abbreviations in type names are PascalCase with consistent casing: `IpAddr`, `TcpHeader`, `UdpHeader`, `DnsProtocol`.
- Abbreviations in variable names are snake_case: `ip_addr`, `tcp_port`, `dns_query`.
- Avoid abbreviations in public API names. Prefer `configuration` over `cfg`, `destination` over `dst` (except in hot path internal code where `dst` is acceptable).

## Module Organization

### File structure

```
crates/<name>/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Crate root: re-exports, module declarations
│   ├── <module>.rs     # One file per top-level module
│   └── <module>/
│       ├── mod.rs      # Submodule root
│       └── ...
```

### Module size

- A module should fit in a single screen (approximately 400 lines). If a module exceeds this, split it into submodules.
- A function should fit in a single screen (approximately 60 lines). If a function exceeds this, split it into helper functions.
- A file should not exceed 1000 lines. If it does, split the module.

### Module responsibilities

Each crate has a single responsibility:

```
edgeshield-common    → Shared types, errors, timestamps
edgeshield-config    → Configuration parsing
edgeshield-telemetry → Logging and observability
edgeshield-packet    → Packet capture and decoding
edgeshield-protocol  → Protocol classification
edgeshield-storage   → Device store abstraction
edgeshield-discovery → Device discovery engine
edgeshield-api       → REST API
edgeshield-daemon    → Application orchestrator
edgeshield-cli       → Binary entry point
```

## Traits

### When to use traits

- Use a trait when there are **two or more implementations** (e.g., `DeviceStore` for in-memory and SQLite).
- Do not introduce a trait for a single implementation. Use concrete types until a second implementation is needed.
- Prefer `impl Trait` in function arguments over `Box<dyn Trait>` when the function is not trait-object-safe.

### Trait design

- Traits should have a **single responsibility**. If a trait has more than 3-4 methods, consider splitting it.
- Traits should be **`Send + Sync`** if they will be shared across threads.
- Provide **blanket implementations** where useful (e.g., `impl<T: DeviceStore> DeviceStore for Arc<T>`).
- Use **associated types** for output types that are tied to the implementation.

```rust
// Good: single responsibility, Send + Sync
pub trait DeviceStore: Send + Sync {
    fn get(&self, mac: &MacAddress) -> Result<Option<Device>, StorageError>;
    fn upsert(&self, device: Device) -> Result<(), StorageError>;
    fn list(&self) -> Result<Vec<Device>, StorageError>;
    fn count(&self) -> Result<usize, StorageError>;
}
```

## Error Handling

### Error types

- Use `thiserror` for all error enums. Do not use `Box<dyn Error>` in public APIs.
- Each crate defines its own error type. Cross-crate errors are converted at boundaries.
- Error variants carry **structured context**, not formatted strings.

```rust
// Good: structured context
#[error("failed to open capture interface '{interface}': {source}")]
CaptureOpen {
    interface: String,
    source: Box<dyn std::error::Error + Send + Sync>,
}

// Bad: stringly-typed
#[error("{0}")]
CaptureOpen(String),
```

### Error propagation

- Use `anyhow::Error` for **application-level error handling** (CLI, daemon startup).
- Use typed errors for **library-level error handling** (crate boundaries).
- Use `Result<_, Box<dyn Error + Send + Sync>>` only in internal code where the error type is truly dynamic.

### Panics

- **No panics in application code**. Panics are reserved for unrecoverable programmer errors.
- Use `.expect()` only in tests and only with a descriptive message.
- Use `unwrap()` only when the success case is statically guaranteed (e.g., `[u8; 6]` from a `Vec<u8>` that was just checked for length).

## Logging

EdgeShield uses the `tracing` crate for all logging.

### Log levels

| Level | Usage |
|-------|-------|
| `ERROR` | Unrecoverable errors, subsystem failures |
| `WARN` | Recoverable errors, unexpected but handled conditions |
| `INFO` | Lifecycle events: startup, shutdown, new device discovered |
| `DEBUG` | Detailed subsystem state, configuration values |
| `TRACE` | Per-packet events, function entry/exit, individual operations |

### Structured fields

- Always use structured fields instead of string formatting in log macros.
- Use `%value` for `Display` formatting, `?value` for `Debug` formatting.

```rust
// Good: structured fields
info!(mac = %device.mac, protocol = %protocol, "new device discovered");

// Bad: string interpolation
info!("new device discovered: {}", device.mac);
```

### Spans

- Use spans for grouping related events (e.g., per-packet processing, API request handling).
- Spans should have meaningful names and include relevant context.

```rust
let span = span!(Level::TRACE, "process-packet");
let _guard = span.enter();
```

## Async Conventions

### Runtime

- Use `tokio` with the `full` features feature set.
- Use `#[tokio::test]` for async tests.

### Task boundaries

- Use `tokio::spawn` for long-running tasks (pipeline, API server).
- Use `mpsc::channel` for communication between tasks.
- All channels are **bounded**. No unbounded channels.

### Blocking code

- Blocking I/O (pnet capture) runs on a dedicated OS thread, not a tokio task.
- Use `std::thread::spawn` with a named thread for blocking work.
- Bridge blocking and async worlds via `mpsc::Sender`.

## Documentation Comments

### Crate-level docs

Every `lib.rs` must have a `//!` doc comment explaining:

- The crate's purpose
- Its key types and functions
- Design decisions and tradeoffs
- Dependencies on other workspace crates

### Public API docs

Every public function, type, trait, and method must have a `///` doc comment:

- **What** the item does
- **Arguments** (if non-obvious)
- **Return value** (if non-obvious)
- **Errors** (what can go wrong and under what conditions)
- **Panics** (if any — should be rare)
- **Performance characteristics** (if relevant to the hot path)

### Internal docs

Internal functions should have doc comments if their purpose is not obvious from the name and signature. Use `//` comments for inline explanations of non-obvious logic.

### Examples

Include `# Examples` sections in doc comments for non-trivial public APIs.

```rust
/// Decode a raw packet buffer into parsed headers.
///
/// # Arguments
///
/// * `buf` - The raw packet buffer, including the link-layer header.
///
/// # Returns
///
/// A `DecodedPacket` with owned header fields and a borrowed payload.
///
/// # Errors
///
/// Returns `PacketError::Truncated` if the packet is too short for
/// the expected headers.
///
/// # Examples
///
/// ```rust
/// let buf = PacketBuf::new(data, 14);
/// let decoded = decode_packet(&buf)?;
/// assert_eq!(decoded.ethernet.ethertype, 0x0800);
/// ```
pub fn decode_packet(buf: &PacketBuf) -> Result<DecodedPacket<'_>, PacketError> {
```

## Testing Expectations

### Unit tests

- Every module has a `#[cfg(test)] mod tests` block at the bottom of the file.
- Tests cover:
  - Happy path (normal operation)
  - Error cases (truncated packets, invalid input)
  - Edge cases (empty data, boundary values)
  - Serialization roundtrips (serde)
- Test functions are named `test_<function>_<scenario>`.

### Integration tests

- Integration tests live in `tests/` at the crate level.
- Integration tests exercise the public API of the crate.
- Integration tests use real types, not mocks (except for I/O boundaries).

### Test helpers

- Test helper functions are defined inside `#[cfg(test)]` blocks.
- Synthetic packet builders are preferred over real packet captures.
- Test helpers are shared across test files via `pub(crate)` visibility.

### Test attributes

```rust
#[test]
fn test_decode_ethernet_ipv4_tcp() {
    // ...
}

#[tokio::test]
async fn test_discovery_new_device() {
    // ...
}
```

## Unsafe Code Policy

EdgeShield has a **zero `unsafe` policy** for application code.

### Permitted unsafe

- `unsafe` is permitted only in dependencies that have been audited (e.g., `pnet`'s raw socket bindings).
- `unsafe` in EdgeShield code requires:
  1. An Architecture Decision Record (ADR) explaining why it is necessary
  2. A `// SAFETY:` comment on every `unsafe` block explaining the invariants
  3. Review by at least two maintainers
  4. MIRI test coverage

### Currently permitted

- None. EdgeShield has zero `unsafe` blocks in application code.

## Performance Guidelines

### Hot path

The per-packet hot path is:

1. `CaptureSession` → mpsc send
2. `decode_packet()` → header parsing
3. `classify()` → protocol classification
4. `DiscoveryEngine::process_packet()` → store update

Guidelines for hot path code:

- **No allocations** after the initial `PacketBuf` creation. Header fields are stack-allocated.
- **No dynamic dispatch**. Use concrete types or monomorphized generics.
- **No `Arc` clones** in the hot path. The `PacketBuf` is moved, not cloned.
- **No `Mutex` contention**. Use `DashMap` for concurrent access.
- **No `format!()` or string allocation**. Use structured tracing fields.

### Cold path

The API server is the cold path. Guidelines:

- **Allocations are acceptable** for JSON serialization and response construction.
- **Cloning device records** is acceptable (they are small and infrequently accessed).
- **Database queries** (future) should be paginated.

### Benchmark targets

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Packet decode | < 500 ns | Per-packet latency |
| Protocol classify | < 100 ns | Per-packet latency |
| Store upsert | < 1 µs | Per-packet latency |
| Full pipeline | < 2 µs | Per-packet latency (excluding capture) |
| API response | < 10 ms p99 | End-to-end latency |
| Memory per device | < 1 KB | RSS overhead |
