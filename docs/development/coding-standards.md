# Coding Standards

This document provides detailed engineering standards for contributors to EdgeShield. It supplements the [Style Guide](../../STYLE_GUIDE.md) with deeper technical guidance.

## Rust Version and Edition

EdgeShield targets Rust 1.85.0 as the minimum supported Rust version (MSRV), the first stable release of the 2024 edition. The crate uses the 2024 edition.

```toml
# Cargo.toml
edition = "2024"
```

The MSRV is enforced in CI. If a dependency requires a newer Rust version, the dependency must be pinned or replaced.

### Notable 2024 edition changes in this codebase

- `unsafe` attributes on extern blocks are required (`unsafe extern "C"`); we avoid `unsafe` in `common`.
- `gen` is a reserved keyword; not used here.
- Lifetime capture rules are stricter; the `DecodedPacket<'a>` borrow into `PacketBuf` relies on the 2024 capture rules.
- `#[must_use]` on constructors that return `Self` (e.g., `Device::new`) is now idiomatic and enforced by clippy.
- `rust_2024_compatibility` lint group is enabled by default; run `cargo fix --edition` when migrating further.

## Crate Organization

### Workspace structure

```
edgeshield/
├── Cargo.toml              # Workspace manifest
├── crates/
│   ├── common/             # Foundation: types, errors, timestamps
│   ├── config/             # Configuration parsing
│   ├── telemetry/          # Logging and observability
│   ├── packet/             # Packet capture and decoding
│   ├── protocol/           # Protocol classification
│   ├── storage/            # Device store abstraction
│   ├── discovery/          # Device discovery engine
│   ├── api/                # REST API
│   ├── daemon/             # Application orchestrator
│   └── cli/                # Binary entry point
```

### Crate naming

- Crate names use `edgeshield-` prefix followed by the subsystem name
- Directory names match crate names without the prefix: `crates/packet/` for `edgeshield-packet`
- Internal dependencies use path references: `edgeshield-packet = { path = "../packet" }`

### Dependency direction

Dependencies flow inward toward `edgeshield-common`. No crate at a lower layer depends on a crate at a higher layer.

```
cli → daemon → {config, telemetry, packet, protocol, discovery, api, storage} → common
```

## Type System

### Newtypes

Use newtypes for domain concepts rather than raw primitives:

```rust
// Good: explicit domain type
pub struct Timestamp(DateTime<Utc>);

// Bad: raw primitive
pub type Timestamp = DateTime<Utc>;
```

### Enums

Use enums for fixed sets of variants. The current `Protocol` enum reflects every protocol the classifier can produce today:

```rust
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
```

Do **not** pre-declare variants the classifier does not yet produce. Add a variant only when `classify()` actually returns it, so exhaustive `match` stays a reliable signal. If a public enum is part of a stable API contract, mark it `#[non_exhaustive]` to allow additions without a breaking semver bump; `Protocol` is internal to the workspace and is not marked `#[non_exhaustive]` for that reason.

### Error types

Use `thiserror` for all error enums. Each variant should carry structured context:

```rust
#[derive(Error, Debug)]
pub enum PacketError {
    #[error("failed to open capture interface '{interface}': {source}")]
    CaptureOpen {
        interface: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("packet too short: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
}
```

### Result types

Define type aliases for commonly used `Result` types:

```rust
pub type PacketResult<T> = Result<T, PacketError>;
```

## Traits

### Trait design

- Traits should have a single responsibility (ISP)
- Traits should be `Send + Sync` if shared across threads
- Provide blanket implementations for `Arc<T>` where useful
- Use associated types for output types tied to the implementation

```rust
pub trait DeviceStore: Send + Sync {
    fn get(&self, mac: &MacAddress) -> Result<Option<Device>, StorageError>;
    fn upsert(&self, device: Device) -> Result<(), StorageError>;
    fn list(&self) -> Result<Vec<Device>, StorageError>;
    fn count(&self) -> Result<usize, StorageError>;
}
```

### Trait objects vs generics

- Use `dyn Trait` when the implementation is selected at runtime (e.g., `Arc<dyn DeviceStore>`)
- Use generics when the implementation is known at compile time and performance matters
- Use `impl Trait` in function arguments for ergonomic single-implementation cases

## Error Handling

### Error propagation

Errors propagate upward through the call stack. Each layer converts errors to its own error type:

```rust
// In edgeshield-packet
fn decode_packet(buf: &PacketBuf) -> Result<DecodedPacket, PacketError> { ... }

// In edgeshield-discovery
fn process_packet(&self, buf: PacketBuf) {
    match decode_packet(&buf) {
        Ok(decoded) => { /* process */ }
        Err(e) => {
            trace!(error = %e, "failed to decode packet");
            // Packet is dropped — this is acceptable
        }
    }
}
```

### Error handling in the pipeline

The packet pipeline never returns errors to the caller. Errors are logged and the packet is dropped:

```rust
pub async fn process_packet(&self, buf: PacketBuf) {
    let decoded = match decode::decode_packet(&buf) {
        Ok(d) => d,
        Err(e) => {
            trace!(error = %e, "failed to decode packet");
            return;
        }
    };
    // ...
}
```

### Error handling in the API

API handlers return HTTP status codes with descriptive messages:

```rust
pub async fn get_device(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<Device>, (StatusCode, String)> {
    let mac = parse_mac(&mac).map_err(|e| {
        (StatusCode::BAD_REQUEST, e.to_string())
    })?;

    match state.store.get(&mac) {
        Ok(Some(device)) => Ok(Json(device)),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("device not found: {}", mac))),
        Err(e) => {
            tracing::error!(error = %e, "failed to get device");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()))
        }
    }
}
```

## Concurrency

### Shared state

- Use `Arc<dyn Trait>` for shared state that crosses task boundaries
- Use `DashMap` for concurrent hash maps (lock-free reads)
- Use `mpsc::channel` for task communication (bounded only)
- Use `Mutex` only when necessary (e.g., `mpsc::Receiver` is not `Sync`)

### Task boundaries

- Blocking I/O runs on OS threads, bridged to async via mpsc
- CPU-bound work runs on tokio tasks (no blocking)
- All channels are bounded — no unbounded growth

### Lock discipline

- Never hold a lock across an `.await` point
- Use `try_send` instead of `send` in the hot path (non-blocking)
- Use `DashMap`'s shard-level locking for fine-grained concurrency

## Performance

### Hot path rules

The per-packet hot path (capture → decode → classify → update) must follow these rules:

1. **No allocations** after the initial `PacketBuf` creation
2. **No dynamic dispatch** — use concrete types or monomorphized generics
3. **No `Arc` clones** — move the `PacketBuf`, don't clone it
4. **No `Mutex` contention** — use `DashMap` for concurrent access
5. **No `format!()`** — use structured tracing fields instead
6. **No `unwrap()` or `expect()`** — handle errors gracefully

### Allocation budget

| Operation | Allocations | Notes |
|-----------|-------------|-------|
| Packet capture | 1 (Vec<u8>) | Converted to Bytes (no copy) |
| Packet decode | 0 | Header fields on stack |
| Protocol classify | 0 | Pure function, no allocation |
| Store upsert | 0 (DashMap) | Internal shard management |
| Discovery event | 1 (DiscoveryEvent) | Per-packet, if store updated |
| API response | N (JSON) | Cold path, allocations acceptable |

### Inlining

Use `#[inline]` only when benchmarks show a measurable improvement. Prefer letting the compiler make inlining decisions.

```rust
// Only inline when benchmarks justify it
#[inline]
pub fn classify(packet: &DecodedPacket<'_>) -> Protocol { ... }
```

## Testing

### Test organization

- Unit tests: `#[cfg(test)] mod tests` at the bottom of each source file
- Integration tests: `tests/` directory at the crate level
- Benchmarks: `benches/` directory at the crate level

### Test patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Arrange-Act-Assert pattern
    #[test]
    fn test_function_scenario() {
        // Arrange
        let input = valid_input();

        // Act
        let result = function(input);

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value);
    }

    // Error path
    #[test]
    fn test_function_invalid_input() {
        let input = invalid_input();
        let result = function(input);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ErrorKind::SpecificVariant));
    }

    // Roundtrip
    #[test]
    fn test_serde_roundtrip() {
        let original = create_test_object();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: MyType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, original);
    }
}
```

### Test coverage expectations

| Code Type | Coverage Target | Notes |
|-----------|-----------------|-------|
| Public API functions | 100% of variants | Every error variant tested |
| Private helper functions | 100% of branches | Every if/else path tested |
| Error handling code | 100% of error paths | Every error return tested |
| Serialization types | 100% roundtrip | Every type tested |
| Hot path functions | 100% of happy path | Normal operation tested |

## Documentation

### Doc comment format

```rust
/// Short description (one line).
///
/// Longer description with details about behavior, design decisions,
/// and usage patterns.
///
/// # Arguments
///
/// * `arg1` - Description of arg1
/// * `arg2` - Description of arg2
///
/// # Returns
///
/// Description of the return value.
///
/// # Errors
///
/// * `ErrorVariant::Reason` - When this error occurs
///
/// # Panics
///
/// * When this condition is met (rare)
///
/// # Examples
///
/// ```rust
/// let result = function(args);
/// assert!(result.is_ok());
/// ```
pub fn function(arg1: Type1, arg2: Type2) -> Result<ReturnType, ErrorType> {
```

### Module-level docs

Every `lib.rs` must have a `//!` doc comment:

```rust
//! Packet capture and decoding for EdgeShield.
//!
//! This crate owns the packet buffer lifecycle — from raw capture
//! via pnet through zero-copy Ethernet/IP/transport header parsing.
//!
//! # Design decisions
//!
//! - We use `bytes::Bytes` for zero-copy buffer sharing
//! - Header fields are copied into owned structs for Send + Sync
//! - The capture thread is a dedicated OS thread (pnet is blocking)
```

### Inline comments

Use `//` comments for non-obvious code:

```rust
// The data offset field is in 32-bit words. Multiply by 4 to get bytes.
let data_offset = tcp.get_data_offset() as usize * 4;
```

## Dependency Management

### Adding dependencies

1. Add the dependency to the workspace `Cargo.toml` under `[workspace.dependencies]`
2. Reference it in the crate's `Cargo.toml` with `workspace = true`
3. Use minimal feature flags — never use `"full"` features
4. Justify the dependency in the pull request description

### Dependency versioning

- Use semantic versioning ranges: `"1"` for stable, `"0.7"` for pre-1.0
- Pin exact versions in `Cargo.lock` (committed to the repository)
- Update dependencies deliberately, not automatically

### Prohibited dependencies

- Dependencies with known vulnerabilities (blocked by `cargo audit`)
- GPL-licensed dependencies (incompatible with Apache 2.0 licensing)
- Dependencies with excessive transitive dependencies
- Dependencies that pull in `unsafe` code without justification

## CI/CD

### Required checks

Every pull request must pass:

1. `cargo test --all-targets` — All tests pass
2. `cargo clippy --all-targets -- -D warnings` — No clippy warnings
3. `cargo fmt --check` — Code is formatted
4. `cargo audit` — No known vulnerabilities
5. `cargo build --release` — Release build succeeds

### Optional checks

1. `cargo bench` — No performance regressions (compared to baseline)
2. `cargo fuzz` — Fuzz tests pass (limited iterations in CI)
3. Cross-compilation — All target architectures build successfully
