# Changelog

All notable changes to EdgeShield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Terminal UI** (`edgeshield-tui`): new `edgeshield tui` subcommand — a ratatui-based read-only observability dashboard over the REST API. Views: devices table, device detail with history sparkline, alerts feed with acknowledge action, metrics, health. Feature-gated behind the `tui` feature (default-on); can be excluded for constrained targets. 34 new tests (13 client tests, 21 render tests).
- **Hot-path performance optimizations** (`edgeshield-common`, `edgeshield-discovery`, `edgeshield-storage`): three changes that together enable 10k+ pps with persistence on Raspberry Pi 4: (1) single timestamp per packet (halves clock_gettime syscalls), (2) event emission only on state changes (cuts event channel volume ~90%), (3) write-back cache for SqliteStore (DashMap front-end, 5s background flush, no per-packet SQL writes).
- **API key authentication** (`edgeshield-api`): Bearer token auth with SHA-256 hashed keys (never store plaintext in config) and constant-time comparison via `subtle`. Two permission levels: read-only (GET) and admin (POST/DELETE). Single-key mode when `admin_key_hash` is absent. `/health` is always exempt. 15 new tests in `auth.rs`.
- **Per-IP rate limiting** (`edgeshield-api`): tracks failed auth attempts per IP address in a `DashMap`. After `max_failures` (default 10) within `window_seconds` (default 60), the IP is blocked for `block_seconds` (default 300). Configurable via `[api.auth]`. Set `max_failures = 0` to disable.
- **TLS for API server** (`edgeshield-api`): HTTPS support via `axum-server` + `rustls`. Configure with `[api.tls]` (`cert_path`, `key_path` in PEM format). Pure Rust TLS — no OpenSSL dependency.
- **Configurable listen address** (`edgeshield-config`): new `api_bind_address` field (default `0.0.0.0`). Set to `127.0.0.1` to restrict to local processes only.
- **Audit logging** (`edgeshield-api`): JSON-lines audit log to a separate file. Logs method, path, status, key hash prefix (4 hex chars — identifies which key without revealing it), and duration. `/health` is exempt. Configure with `[api.audit] log_path`.
- **Startup security warnings** (`edgeshield-api`): warns when auth is disabled and binding to non-loopback, or when auth is enabled without TLS.
- **`[api]` config section** (`edgeshield-config`): `[api.auth]` (read_key_hash, admin_key_hash, max_failures, window_seconds, block_seconds), `[api.tls]` (cert_path, key_path), `[api.audit]` (log_path). Validation: hash format (64 hex chars), non-empty paths. 9 new tests.

### Changed

- **API `serve()` signature**: now takes `&Config` instead of individual args (port, store, alert_store, history_store). The config provides bind address, port, auth, TLS, and audit settings.
- **API `AppState`**: now holds `AuthState` and `Option<Arc<AuditLogger>>` alongside the stores.
- **Middleware via `from_fn_with_state`**: auth and audit middleware receive their state via `from_fn_with_state` (not extracted from the router's `AppState`) to avoid Axum extractor ordering constraints.

### Device history snapshots (Phase 3 completion)

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
