# ADR-0001: Why Rust

## Status

Accepted

## Context

EdgeShield is a network security monitoring tool that must run on resource-constrained hardware (Raspberry Pi Zero 2 W, Pi 3, Pi 4) while processing packets at line rate. The choice of programming language has significant implications for:

- **Memory safety**: Network security tools are historically written in C, which is prone to buffer overflows, use-after-free, and other memory corruption vulnerabilities. A security tool should not introduce security vulnerabilities.
- **Performance**: Packet capture and processing must happen at thousands of packets per second with minimal latency.
- **Deployment**: The binary must be self-contained and easy to deploy on ARM and x86_64 Linux.
- **Ecosystem**: The language must have mature libraries for packet capture, HTTP servers, and concurrency.

### Considered options

1. **Rust**: Systems language with memory safety guarantees, zero-cost abstractions, and a growing ecosystem.
2. **C**: Traditional choice for network tools (tcpdump, Wireshark, Suricata). Maximum performance but no memory safety.
3. **Go**: Garbage-collected language with good concurrency support and easy cross-compilation.
4. **Python**: High productivity but poor performance for packet processing.
5. **C++**: Memory safety only through discipline, complex build system, large attack surface.

## Decision

Use Rust as the implementation language for EdgeShield.

## Rationale

### Memory safety without GC

Rust's ownership model guarantees memory safety at compile time with zero runtime overhead. This eliminates entire classes of vulnerabilities (buffer overflows, use-after-free, double-free, null pointer dereferences) that have historically plagued network security tools written in C.

A garbage collector (Go, Java, Python) would introduce unpredictable latency spikes during GC pauses, which is unacceptable for a packet processing pipeline that must maintain consistent throughput.

### Zero-cost abstractions

Rust's traits, generics, and iterators compile down to the same machine code as hand-written C. There is no hidden allocation, no vtable dispatch where it isn't needed, and no runtime overhead for abstractions.

This allows us to write clean, maintainable code without sacrificing performance.

### Target audience alignment

The security community values memory-safe infrastructure. Rust is increasingly adopted in security tools (e.g., `ferret`, `sniffglue`, `redbpf`). Choosing Rust signals that EdgeShield takes security seriously.

### Cross-compilation

Rust's cross-compilation story is excellent. With a single toolchain, we can target:

- `x86_64-unknown-linux-gnu` (desktop/server Linux)
- `aarch64-unknown-linux-gnu` (Raspberry Pi 4, Pi Zero 2 W)
- `armv7-unknown-linux-gnueabihf` (Raspberry Pi 3, Pi Zero 2)

No runtime or VM is needed on the target system. The binary is statically linked and self-contained.

### Ecosystem maturity

Rust has mature libraries for all of EdgeShield's requirements:

| Requirement | Library | Maturity |
|-------------|---------|----------|
| Async runtime | tokio | Production-ready, widely used |
| HTTP server | axum | Production-ready, used by major projects |
| Packet capture | pnet | Mature, wraps libpcap |
| Packet parsing | etherparse | Active development |
| Serialization | serde | Industry standard |
| Concurrency | dashmap | Production-ready |
| Error handling | thiserror, anyhow | Industry standard |

### Community and longevity

Rust has a strong, growing community and is backed by major organizations (Mozilla, AWS, Google, Microsoft, Meta). The language is stable with a clear governance model and regular release cadence.

## Consequences

### Positive

- Memory safety guarantees without runtime overhead
- Excellent cross-compilation for ARM targets
- Growing ecosystem with mature libraries for all requirements
- Strong alignment with security-focused user base
- Single static binary deployment

### Negative

- Steeper learning curve for contributors unfamiliar with Rust
- Longer compile times compared to Go
- Smaller pool of potential contributors compared to Python or JavaScript
- Some packet capture libraries (pnet) require `unsafe` bindings to libpcap

### Neutral

- The borrow checker enforces correct concurrent code, which is beneficial for our pipeline architecture
- Rust's strictness catches bugs at compile time that would be caught at runtime in other languages

## References

- [Rust Memory Safety](https://doc.rust-lang.org/nomicon/meet-safe-and-unsafe.html)
- [pnet crate documentation](https://docs.rs/pnet/)
- [tokio runtime documentation](https://docs.rs/tokio/)
- [axum web framework](https://docs.rs/axum/)
