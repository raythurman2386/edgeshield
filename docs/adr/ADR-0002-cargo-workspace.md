# ADR-0002: Cargo Workspace

## Status

Accepted

## Context

EdgeShield has multiple distinct subsystems (packet capture, protocol classification, device discovery, storage, API, CLI). These subsystems have different dependency profiles and different rates of change. The project needs a build system that supports:

- **Independent compilation**: Changes to one subsystem should not require recompiling unrelated subsystems
- **Dependency isolation**: Subsystems should only depend on the libraries they need
- **Clear boundaries**: The public API of each subsystem should be explicit
- **Test isolation**: Tests for one subsystem should not depend on the internals of another
- **Binary and library separation**: The CLI binary should be separate from the library crates

### Considered options

1. **Single crate**: One `Cargo.toml` with all code in `src/`
2. **Cargo workspace**: Multiple crates in a `crates/` directory with a workspace root
3. **Separate repositories**: Each subsystem in its own git repository

## Decision

Use a Cargo workspace with one crate per subsystem, organized under `crates/`.

## Rationale

### Dependency isolation

Each crate declares only the dependencies it needs. For example:

- `edgeshield-common` depends only on `serde`, `thiserror`, `chrono`, and `mac_address`
- `edgeshield-packet` depends on `pnet`, `etherparse`, `bytes`, and `edgeshield-common`
- `edgeshield-api` depends on `axum`, `tower`, and `edgeshield-storage`

This means:

- A security vulnerability in `axum` does not affect the packet capture crate
- A change to `pnet` only requires recompiling `edgeshield-packet` and its dependents
- New contributors can understand a single crate without understanding the entire codebase

### Clear module boundaries

Each crate has an explicit `pub` API in `lib.rs`. Internal modules are private. This enforces encapsulation and makes the public API easy to audit.

### Build performance

Cargo's incremental compilation works at the crate level. Changing `edgeshield-discovery` only recompiles `edgeshield-discovery` and crates that depend on it (not `edgeshield-packet` or `edgeshield-common`).

### Shared dependency versions

The workspace `Cargo.toml` declares shared dependency versions under `[workspace.dependencies]`. All crates use the same version of `tokio`, `serde`, `tracing`, etc. This prevents version conflicts and ensures consistent behavior.

### Binary and library separation

The CLI binary is a thin wrapper in `edgeshield-cli` that calls into `edgeshield-daemon`. This allows:

- Other binaries (e.g., a future `edgeshieldctl` administration tool) to reuse the library crates
- Library crates to be published independently (future)
- Integration tests to import library crates without depending on the binary

## Consequences

### Positive

- Clear subsystem boundaries enforced by the build system
- Fast incremental compilation
- Dependency isolation (vulnerabilities in one crate don't affect others)
- Shared dependency versions across the workspace
- Library crates can be published and reused independently

### Negative

- More boilerplate (each crate needs its own `Cargo.toml`, `lib.rs`, module declarations)
- Cross-crate refactoring requires changing multiple files
- Slightly more complex build configuration

### Neutral

- The workspace structure mirrors the architectural layering
- New contributors need to understand the workspace structure

## Workspace Structure

```
edgeshield/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── common/             # Layer 0: Foundation
│   ├── config/             # Layer 1: Infrastructure
│   ├── telemetry/          # Layer 1: Infrastructure
│   ├── packet/             # Layer 2: Data plane
│   ├── protocol/           # Layer 2: Data plane
│   ├── storage/            # Layer 2: Data plane
│   ├── discovery/          # Layer 3: Logic
│   ├── api/                # Layer 4: Interface
│   ├── daemon/             # Layer 5: Application
│   └── cli/                # Layer 6: Entry point
```

## References

- [Cargo Workspaces Documentation](https://doc.rust-lang.org/cargo/reference/workspaces.html)
- [Rust API Guidelines: Crate Structure](https://rust-lang.github.io/api-guidelines/)
