# Changelog

All notable changes to EdgeShield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **ntfy.sh notification channel** (`edgeshield-notify`): HTTP POST-based new-device alerting as a broker-less alternative to MQTT. New `NtfyNotifier` reuses the MQTT `NewDevicePayload` JSON shape so consumers can switch transports without changing parsers. Supports `Bearer` token auth, `Priority`, and `Tags` headers. New `[ntfy]` config section with `base_url`, `topic`, `token`, `priority`, `tags`.
- **mDNS/Bonjour parsing** (`edgeshield-protocol`): New `mdns` module parses the DNS wire format on UDP 5353, extracting hostnames from SRV records and instance/service names from PTR records. Supports DNS name compression. Discovery populates `device.hostname` from mDNS when DHCP hasn't already.
- **HTTP banner sniffing** (`edgeshield-protocol`): TCP packets on non-standard ports are now classified as HTTP when the payload starts with an HTTP method (`GET`, `POST`, etc.) or an `HTTP/1.` status line. Catches HTTP on ports 8080, 8000, etc. without false-positiving on every TCP stream.
- **NTP header validation** (`edgeshield-protocol`): New `ntp` module validates the 48-byte NTP header (version 3 or 4, mode 1-6), reducing false positives where port 123 is used by something else.
- **DHCP vendor class storage** (`edgeshield-common`, `edgeshield-discovery`): The DHCP option 60 vendor class identifier is now extracted and stored on the device record as `dhcp_vendor_class`, distinct from the OUI vendor.
- **Per-protocol packet statistics** (`edgeshield-common`, `edgeshield-storage`): `Device` now tracks a `BTreeMap<Protocol, u64>` of per-protocol packet counts, persisted to SQLite as a JSON column and exposed via the REST API. Useful for fingerprinting (mDNS+DNS = IoT appliance; HTTPS+NTP = workstation).
- **SQLite schema migration** (`edgeshield-storage`): Additive `ALTER TABLE ADD COLUMN` migrations for `dhcp_vendor_class` and `protocol_stats`, idempotent against already-migrated databases.

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
