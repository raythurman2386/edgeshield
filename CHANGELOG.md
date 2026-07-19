# Changelog

All notable changes to EdgeShield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Device history snapshots** (`edgeshield-common`, `edgeshield-storage`): new `DeviceHistoryStore` trait and `DeviceHistorySnapshot` type in `edgeshield-common`. New `SqliteHistoryStore` in `edgeshield-storage` persists daily snapshots to a `device_history` table with `UNIQUE(mac, snapshot_date)` upsert. 8 new tests.
- **`/devices/:mac/history` API endpoint** (`edgeshield-api`): returns daily snapshots for a device, filtered by date range (`from`, `to`) and `limit`. Returns 501 if history is not enabled.
- **`[storage]` config section** (`edgeshield-config`): `history_snapshot_hours` (default 24) and `history_retention_days` (default 90). Set `history_snapshot_hours = 0` to disable. 3 new tests.
- **History snapshot + maintenance background task** (`edgeshield-daemon`): wakes every `history_snapshot_hours`, snapshots all devices, deletes snapshots older than `history_retention_days`, and runs `PRAGMA incremental_vacuum`.
- **Database vacuum** (`edgeshield-storage`): `PRAGMA incremental_vacuum` reclaim after retention deletion. Safe no-op if `auto_vacuum` is not enabled.
- **SQLite alert store** (`edgeshield-storage`): new `SqliteAlertStore` persists alert history to the same SQLite database as devices. Alert history now survives daemon restarts. Schema includes indexes on timestamp, mac, and acknowledged for fast queries.
- **`/alerts` API endpoints** (`edgeshield-api`): four new endpoints for alert management — `GET /alerts` (list with filters: severity, acknowledged, rule, limit), `GET /alerts/:id` (single alert), `POST /alerts/:id/acknowledge` (mark as acknowledged), `DELETE /alerts/:id` (delete alert).
- **Prometheus text metrics** (`edgeshield-api`): new `GET /metrics/prometheus` endpoint returning metrics in Prometheus text exposition format. Exposes `edgeshield_devices_total`, `edgeshield_packets_total`, `edgeshield_bytes_total`, `edgeshield_uptime_seconds`, and `edgeshield_alerts_total`. The existing JSON `/metrics` endpoint is preserved for programmatic consumption.
- **`AlertStore` trait moved to `edgeshield-common`** to break a circular dependency between `edgeshield-rules` and `edgeshield-storage`. Both crates now depend on `common` for the trait; `InMemoryAlertStore` remains in `rules`, `SqliteAlertStore` is in `storage`.

### Changed

- **Daemon wiring**: alert store now uses `SqliteAlertStore` when `database_path` is configured, falling back to `InMemoryAlertStore` only when in-memory. The API server receives the alert store alongside the device store.
- **API `AppState`**: now holds both `Arc<dyn DeviceStore>` and `Arc<dyn AlertStore>`. The `serve()` function takes both.

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
