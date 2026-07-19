# Design Principles

This document describes the engineering philosophy that guides every decision in EdgeShield. These principles are not aspirational — they are enforced through code review, CI checks, and architectural governance.

## Memory Safety

EdgeShield is written in Rust, which guarantees memory safety at compile time. We extend this guarantee with additional practices:

- **No `unsafe` code** in application logic. The only `unsafe` code permitted is in dependencies that have been audited (e.g., `pnet`'s raw socket bindings).
- **No raw pointers** in the public API. All cross-crate boundaries use safe Rust types.
- **No `transmute`** or other escape hatches. If the type system makes something difficult, that is a signal to reconsider the design, not to bypass the compiler.
- **Bounded allocations** in the hot path. Packet buffers are allocated once by pnet and shared via `bytes::Bytes` (refcounted). No per-packet allocations in the decode-classify-update pipeline.

## Performance First

EdgeShield targets resource-constrained hardware (Raspberry Pi Zero 2 W, Pi 3, Pi 4). Every microsecond and kilobyte matters.

- **Measure before optimizing**. All performance-sensitive code paths have benchmarks. We do not optimize without data.
- **Zero-cost abstractions** are preferred. If a trait or generic compiles down to the same machine code as a hand-written specialization, use it. If it adds overhead, don't.
- **The hot path is synchronous**. Packet decoding, classification, and store updates are synchronous functions. Async is used only at the channel boundaries (receive from capture, send to API).
- **No dynamic dispatch in the hot path**. The `DeviceStore` trait uses `dyn` because it is called from both the pipeline and API server, but the per-packet path is monomorphized.
- **Bounded queues everywhere**. All channels have fixed capacities. The system degrades by dropping packets under load, not by growing memory.

## Simplicity Over Abstraction

EdgeShield favors simple, direct code over abstract, generic code.

- **One level of abstraction per crate**. Each crate has a clear responsibility. If a crate needs more than one abstraction layer, it is probably two crates.
- **Concrete types by default**. Traits are introduced only when there are multiple implementations (e.g., `DeviceStore` for in-memory and future SQLite). A trait with one implementation is premature abstraction.
- **Flat module structure**. Modules are shallow. Deep nesting is a sign of over-engineering.
- **Obvious control flow**. The pipeline is a linear sequence of function calls. No callbacks, no visitors, no inversion of control in the hot path.

## Zero-Copy Where Practical

Packet data is never copied unnecessarily.

- **`bytes::Bytes`** for packet buffers. Cloning bumps a reference count instead of copying data.
- **Header fields are copied** (not zero-copy). This is intentional — header fields are small (MAC: 6 bytes, IP: 4-16 bytes, ports: 2 bytes), and owned structs avoid lifetime complexity across async boundaries.
- **Payload is referenced, not owned**. The `DecodedPacket` borrows from the `PacketBuf`. Payload extraction (e.g., DNS name parsing) allocates, but the raw payload bytes are never copied.
- **No intermediate buffers**. The pipeline reads from the capture channel, decodes in place, classifies, and updates the store. No temporary copies.

## Async-First

EdgeShield uses async I/O for all I/O operations, but not for CPU-bound work.

- **Tokio runtime** with multi-thread scheduler. One runtime, multiple tasks.
- **Blocking work on OS threads**. Packet capture (pnet) is blocking and runs on a dedicated OS thread. This is bridged to the async world via a bounded mpsc channel.
- **No `spawn_blocking` abuse**. Only the capture thread is blocking. Everything else is async.
- **Bounded channels** for all task communication. No `UnboundedChannel` anywhere.

## Strong Typing

EdgeShield uses Rust's type system to make illegal states unrepresentable.

- **Newtypes for domain concepts**. `Timestamp` is a newtype around `DateTime<Utc>`, not a raw string or integer. `Protocol` is an enum, not a `u8`.
- **No stringly-typed errors**. Every error variant is explicit with typed fields.
- **`Option` for optional fields**. Device fields like `hostname` and `vendor` are `Option<T>`, not empty strings.
- **`Result` for fallible operations**. No panics in application code. Panics are reserved for programmer errors (e.g., index out of bounds).
- **`#[non_exhaustive]` on public enums** to allow adding variants without breaking changes.

## Dependency Minimization

Every dependency is a liability. EdgeShield minimizes dependencies aggressively.

- **Audit every dependency**. New dependencies require justification in the pull request.
- **Prefer standard library**. If `std` provides what we need, we use it. No dependency for the sake of convenience.
- **Workspace-level dependencies**. Shared dependencies are declared in the workspace `Cargo.toml` with consistent versions. No crate pins its own version.
- **No proc-macro dependencies** in core crates. `serde` derive is acceptable because it is ubiquitous and well-audited.
- **Feature flag minimization**. Dependencies use minimal feature sets. No `"full"` features on libraries that offer granular selection.

## Testability

EdgeShield is designed to be tested at every level.

- **Pure functions for logic**. Protocol classification is a pure function — no I/O, no state, no side effects. It is tested with synthetic packet fixtures.
- **Trait-based storage**. The `DeviceStore` trait allows testing the discovery engine with a mock store.
- **Synthetic packet builders**. Test helpers construct valid Ethernet/IP/transport packets from raw bytes. No need for real network interfaces in unit tests.
- **Integration tests** exercise the full pipeline with synthetic packets and assert on store state and events.
- **Benchmarks** measure per-packet throughput, allocation counts, and memory usage.

## Security by Default

EdgeShield is designed to be secure without configuration.

- **No outbound connections**. EdgeShield never initiates network connections. It listens on a local port and captures from a local interface.
- **No telemetry**. Zero data leaves the device unless explicitly queried via the API.
- **Minimal API surface**. The REST API exposes four read-only endpoints. No mutation endpoints in the MVP.
- **Defensive parsing**. Packet parsing never panics. Malformed packets are logged and dropped.
- **Bounded resources**. All internal data structures have bounded size. The device store is bounded by the number of MAC addresses on the network (typically < 1000).

## API Stability

The REST API is a contract with users and integrators.

- **Versioned from day one**. The API version is embedded in the response (via the `version` field in `/health`).
- **Read-only in MVP**. The initial API is read-only. Mutation endpoints (configuration changes, device blocking) will be added with explicit version bumps.
- **Consistent error format**. All errors return a string message with an appropriate HTTP status code.
- **JSON only**. The API uses JSON for all request and response bodies. No XML, no protobuf, no custom formats.
- **Serde for serialization**. All response types derive `Serialize` and `Deserialize`. The serialization format is controlled by the type definition, not by ad-hoc formatting code.
