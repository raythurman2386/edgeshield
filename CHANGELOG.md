# Changelog

All notable changes to EdgeShield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Rule engine** (`edgeshield-rules` crate): evaluates user-configured rules against discovery events and emits `Alert`s. Five condition types: `new_device`, `new_device_by_vendor`, `new_device_by_mac_prefix`, `device_offline` (with `after_seconds` threshold), and `protocol_change`. Per-device per-rule cooldown tracking prevents alert floods. Alert acknowledgment suppresses future alerts for the same device/rule combination.
- **Inline TOML rules** (`edgeshield-config`): rules live in `config.toml` as `[[rules]]` tables. No separate rules file needed. Validated at parse time (name, severity, condition).
- **Multi-notifier fan-out** (`edgeshield-notify`): all configured notifiers (ntfy, MQTT, webhook, email) receive every alert simultaneously. New `Notifier` trait and `NotifierFanout` dispatcher. A slow notifier doesn't block others.
- **Webhook notification channel** (`edgeshield-notify`): POSTs alerts as JSON to any HTTP endpoint. Compatible with Slack, Discord, Microsoft Teams, and generic webhooks. Supports Bearer token auth and custom headers.
- **Email notification channel** (`edgeshield-notify`): sends alerts as plain-text emails via SMTP (lettre crate). Supports STARTTLS (port 587) and implicit TLS (port 465). No local MTA required.
- **Device offline scanner** (`edgeshield-daemon`): background task wakes every 60s (configurable via `[scanner] interval_seconds`), lists all devices, and emits `DeviceOffline` events for devices silent for more than 60 seconds. The rule engine evaluates these against `device_offline` rules.
- **Default new_device rule**: if no `[[rules]]` are configured, a default `new_device` rule runs (preserving pre-Phase-5 behavior — every new MAC triggers an alert).
- **Alert types** (`edgeshield-common`): new `Alert`, `Severity` (info/warning/critical), `AlertEventType` (new_device/device_offline/protocol_change/custom), and `AlertId` types.
- **AlertStore trait** (`edgeshield-rules`): storage abstraction for alerts with an in-memory implementation. `insert_alert`, `list_alerts` (with filter), `get_alert`, `acknowledge_alert`, `delete_alert`, `is_acknowledged`, `count_alerts`.
- **`DiscoveryEvent::DeviceOffline`** variant for the offline scanner.

### Changed

- **Notify crate refactored**: notifiers now consume `Alert`s (not `DiscoveryEvent`s) via the `Notifier` trait. The rule engine is the single consumer of `DiscoveryEvent`s. The `notify` crate no longer depends on `edgeshield-discovery`.
- **NtfyNotifier**: constructor takes `NtfyConfig` only (no `event_rx`); implements `Notifier` trait.
- **MqttNotifier**: constructor takes `MqttConfig` only; implements `Notifier` trait; connection polling moved to a background task.
- **Daemon wiring**: rule engine sits between discovery and notification; fanout dispatches alerts to all notifiers.

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
