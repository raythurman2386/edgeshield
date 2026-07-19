# Changelog

All notable changes to EdgeShield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-18

### Added

- **Cargo workspace** with 10 crates: `common`, `config`, `telemetry`, `packet`, `protocol`, `storage`, `discovery`, `api`, `daemon`, `cli`.
- **Shared types** (`edgeshield-common`): `Device`, `Protocol`, `Timestamp`, and error enums for all subsystems.
- **Configuration parsing** (`edgeshield-config`): TOML-based configuration with validation and sensible defaults.
- **Structured logging** (`edgeshield-telemetry`): JSON logging via `tracing-subscriber` with configurable log levels.
- **Packet capture** (`edgeshield-packet`): Raw packet capture from network interfaces via `pnet`, zero-copy buffer abstraction with `bytes::Bytes`, bounded mpsc channel bridging blocking capture thread to async pipeline.
- **Header decoding** (`edgeshield-packet`): Ethernet, IPv4, TCP, UDP, ICMP, and ARP header parsing with owned structs.
- **Protocol classification** (`edgeshield-protocol`): Classification of ARP, IPv4, ICMP, TCP, UDP, and DNS protocols.
- **Device discovery** (`edgeshield-discovery`): Automatic device discovery from network traffic, per-device counters and protocol fingerprints, discovery event emission.
- **In-memory storage** (`edgeshield-storage`): `DeviceStore` trait with `DashMap`-backed in-memory implementation, lock-free concurrent access.
- **REST API** (`edgeshield-api`): Axum-based HTTP server with `/health`, `/devices`, `/devices/{mac}`, and `/metrics` endpoints.
- **Daemon orchestrator** (`edgeshield-daemon`): Wires together all subsystems, graceful shutdown on SIGINT/SIGTERM.
- **CLI** (`edgeshield-cli`): Binary entry point with `clap` argument parsing, `run` and `default-config` subcommands.
- **Comprehensive documentation**: README, ARCHITECTURE, DESIGN_PRINCIPLES, STYLE_GUIDE, ROADMAP, CHANGELOG, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, LICENSES, and full `docs/` directory.

[0.1.0]: https://github.com/edgeshield/edgeshield/releases/tag/v0.1.0
