# EdgeShield

**Lightweight, self-hosted network security monitoring for Raspberry Pi and Linux.**

EdgeShield is a passive network monitoring appliance written in Rust. It performs device discovery, protocol analysis, and traffic profiling on your local network — all while maintaining a minimal memory footprint and a privacy-first design. No cloud dependency. No data exfiltration. Everything runs on your hardware.

```text
┌─────────────────────────────────────────────────────┐
│                    EdgeShield                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │
│  │  Packet   │→│ Protocol │→│  Device Discovery │    │
│  │  Capture  │  │  Classify│  │  & Fingerprinting│   │
│  └──────────┘  └──────────┘  └────────┬─────────┘   │
│                                       │             │
│  ┌────────────────────────────────────▼──────────┐  │
│  │              Rule Engine                        │  │
│  │  (new_device, device_offline, protocol_change) │  │
│  └────────────────────┬───────────────────────────┘  │
│                       │                             │
│  ┌────────────────────▼──────────────────────────┐  │
│  │  Notifier Fan-out → [ntfy, MQTT, webhook, email]│ │
│  └───────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────┐  │
│  │  REST API + SQLite (devices, alerts, history)  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Features

- **Passive network monitoring** — listens only, never transmits. No active probing.
- **Device discovery** — automatically identifies every device on your LAN by MAC address, with OUI vendor lookup (39,762 IEEE entries embedded at build time).
- **Protocol classification** — detects ARP, IPv4, ICMP, TCP, UDP, DNS, DHCP, HTTP, HTTPS, mDNS, and NTP traffic. HTTP banner sniffing catches HTTP on non-standard ports.
- **Device fingerprinting** — hostnames from DHCP and mDNS/Bonjour, DHCP vendor class (option 60), per-protocol packet statistics.
- **Persistent storage** — SQLite backend so devices and alert history survive daemon restarts. Daily device history snapshots with configurable retention.
- **Rule engine** — user-configurable rules with five condition types: `new_device`, `new_device_by_vendor`, `new_device_by_mac_prefix`, `device_offline`, `protocol_change`. Per-device per-rule cooldown (debounce). Alert acknowledgment with suppression.
- **Multi-channel alerting** — ntfy.sh, MQTT, webhook (Slack/Discord/Teams-compatible), and SMTP email. All channels run simultaneously via the notifier fan-out.
- **REST API** — query device inventory, device history, alerts, metrics, and health. Prometheus text metrics endpoint for scraping.
- **API security** — Bearer token authentication with SHA-256 hashed keys, constant-time comparison, read-only vs admin permission levels, per-IP rate limiting, TLS support, and audit logging.
- **Structured JSON logging** — production-ready observability via `tracing`.
- **Low memory footprint** — designed for Raspberry Pi Zero 2 W and similar constrained hardware.
- **Privacy-first** — no telemetry, no external calls, no cloud dependency.
- **Self-contained binary** — single static binary with no runtime dependencies.

## Goals

- Provide a free, open-source network monitoring tool for homelab users and small businesses.
- Maintain a memory footprint under 50 MB RSS during normal operation.
- Process 10,000+ packets per second on a Raspberry Pi 4.
- Expose a clean, versioned REST API for integration with existing dashboards and alerting systems.
- Remain fully offline-capable — no internet connection required at any point.

## Non-Goals

- **Active network scanning** — EdgeShield does not send probes, pings, or ARP requests. It observes only.
- **Intrusion prevention** — EdgeShield is a monitoring tool, not a firewall or IPS. It cannot block traffic.
- **Deep packet inspection** — EdgeShield classifies protocols but does not reassemble streams or inspect payloads beyond header analysis.
- **Full packet capture** — EdgeShield does not store raw packets. It extracts metadata and discards payloads.
- **Real-time alerting** — EdgeShield focuses on passive monitoring. Alerting is handled by the rule engine and external notification channels (ntfy, MQTT, webhook, email), not by EdgeShield itself acting as a real-time IPS.

## Why Rust

EdgeShield is written in Rust for three reasons:

1. **Memory safety without GC** — Packet capture runs at line rate. A garbage collector would introduce unpredictable latency. Rust's ownership model guarantees memory safety at compile time with zero runtime overhead.
2. **Zero-cost abstractions** — Traits, generics, and iterators compile down to the same machine code as hand-written C. No hidden allocations, no vtable dispatch where it isn't needed.
3. **Target audience alignment** — The security community values memory-safe infrastructure. Rust eliminates entire classes of vulnerabilities (buffer overflows, use-after-free, double-free) that have historically plagued network security tools written in C.

## Architecture Overview

EdgeShield uses a pipeline architecture with concurrent stages:

```mermaid
graph LR
    A[Capture Thread] -->|mpsc channel| B[Pipeline Task]
    B -->|mpsc channel| C[Rule Engine]
    C -->|mpsc channel| D[Notifier Fan-out]
    D --> E[ntfy]
    D --> F[MQTT]
    D --> G[Webhook]
    D --> H[Email]
    B --> I[(Device Store)]
    C --> J[(Alert Store)]
    K[Offline Scanner] -->|DeviceOffline events| C
    L[History Snapshot Task] --> I
    M[API Server] --> I
    M --> J
```

| Stage | Runtime | Description |
|-------|---------|-------------|
| Capture | OS Thread (blocking) | Reads raw packets via `pcap` with `promisc(false)` — no WiFi disruption. |
| Pipeline | Tokio Task | Decodes packets, classifies protocols, extracts DHCP/mDNS hostnames, updates the device store. |
| Rule Engine | Tokio Task | Evaluates user-configured rules against discovery events, emits alerts with cooldown and acknowledgment suppression. |
| Notifier Fan-out | Tokio Task | Delivers alerts to all configured notifiers (ntfy, MQTT, webhook, email) simultaneously. |
| Offline Scanner | Tokio Task | Background task that detects silent devices and emits `DeviceOffline` events. |
| History Snapshot | Tokio Task | Takes daily device snapshots and deletes old history per retention policy. |
| API | Tokio Task | Serves the REST API via Axum with optional auth, TLS, and audit logging. |

The device store is either an in-memory `DashMap` or a persistent SQLite database, selected by configuration. Both implement the `DeviceStore` trait and are shared via `Arc<dyn DeviceStore>`.

## Repository Layout

```
edgeshield/
├── Cargo.toml              # Workspace manifest
├── Makefile                # Build, install, test targets
├── dist/
│   ├── edgeshield.service  # systemd unit file
│   └── edgeshield.8        # Man page
├── .gitea/workflows/
│   └── ci.yaml             # CI pipeline
├── crates/
│   ├── common/             # Shared types, errors, timestamps
│   ├── config/             # TOML configuration parsing
│   ├── telemetry/          # Structured JSON logging (tracing)
│   ├── packet/             # Packet capture (pcap) and header decoding
│   ├── protocol/           # Protocol classification (DHCP, mDNS, NTP, HTTP banners)
│   ├── storage/            # DeviceStore + AlertStore + HistoryStore (SQLite + in-memory)
│   ├── discovery/          # Device discovery engine
│   ├── rules/              # Rule engine + AlertStore trait
│   ├── notify/             # Notifier fan-out (ntfy, MQTT, webhook, email)
│   ├── api/                # REST API (Axum) + auth + audit
│   ├── daemon/             # Application orchestrator
│   └── cli/                # CLI binary entry point
├── docs/
│   ├── architecture/       # System architecture documentation
│   ├── development/        # Developer onboarding and standards
│   ├── api/                # REST API reference
│   ├── security/           # Threat model and cryptography
│   └── adr/                # Architecture Decision Records
├── README.md
├── ROADMAP.md
├── ARCHITECTURE.md
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
└── SUPPORT.md
```

## Installation

### Building from Source

**Prerequisites:**

- Rust toolchain (stable)
- `libpcap` runtime library (`libpcap.so.1` on Linux)

```bash
git clone https://github.com/edgeshield/edgeshield.git
cd edgeshield
cargo build --release
```

The binary is at `target/release/edgeshield`.

### systemd (Linux)

```bash
sudo make install
sudo systemctl enable edgeshield
sudo systemctl start edgeshield
```

## Running Locally

### 1. Create a configuration file

```toml
# /etc/edgeshield/config.toml
interface = "wlan0"
api_bind_address = "127.0.0.1"
api_port = 8080
log_level = "info"
database_path = "/var/lib/edgeshield/edgeshield.db"

# Alerting via ntfy (broker-less, HTTPS POST)
[ntfy]
base_url = "https://ntfy.sh"
topic = "edgeshield"

# API authentication (generate with: openssl rand -hex 32 | sha256sum)
[api.auth]
read_key_hash = "sha256-hex-of-your-read-key"

# Audit log
[api.audit]
log_path = "/var/log/edgeshield/audit.log"
```

### 2. Grant capture capabilities (no root required)

```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/edgeshield
```

### 3. Run the daemon

```bash
edgeshield run --config /etc/edgeshield/config.toml
```

### 4. Query the API

```bash
# Health check (no auth required)
curl http://localhost:8080/health

# List discovered devices (auth required)
curl -H "Authorization: Bearer $EDGESHIELD_KEY" http://localhost:8080/devices

# Get a specific device
curl -H "Authorization: Bearer $EDGESHIELD_KEY" http://localhost:8080/devices/00:11:22:33:44:55

# Device history (daily snapshots)
curl -H "Authorization: Bearer $EDGESHIELD_KEY" "http://localhost:8080/devices/00:11:22:33:44:55/history?limit=30"

# List alerts
curl -H "Authorization: Bearer $EDGESHIELD_KEY" http://localhost:8080/alerts

# Aggregate metrics (JSON)
curl -H "Authorization: Bearer $EDGESHIELD_KEY" http://localhost:8080/metrics

# Prometheus text metrics (for scrapers)
curl -H "Authorization: Bearer $EDGESHIELD_KEY" http://localhost:8080/metrics/prometheus
```

## Configuration

EdgeShield uses a single TOML configuration file. See [docs/configuration.md](docs/configuration.md) for the full reference.

```toml
# Minimal configuration
interface = "eth0"

# Full configuration with all options
interface         = "eth0"
api_bind_address  = "127.0.0.1"
api_port          = 8080
log_level         = "info"
capture_buffer    = 4096
database_path     = "/var/lib/edgeshield/edgeshield.db"

# Alerting rules (inline; if absent, a default new_device rule runs)
[[rules]]
name = "new-device-alert"
condition = "new_device"
severity = "info"
cooldown_seconds = 300

[[rules]]
name = "device-offline-30min"
condition = { device_offline = { after_seconds = 1800 } }
severity = "warning"

# Notification channels (all run simultaneously)
[ntfy]
base_url = "https://ntfy.sh"
topic = "edgeshield"

[webhook]
url = "https://hooks.slack.com/services/..."

[email]
host = "smtp.gmail.com"
port = 587
username = "you@gmail.com"
password = "app-password"
from = "edgeshield@home.lan"
to = "you@home.lan"

# API security
[api.auth]
read_key_hash = "sha256-hex-of-your-read-key"
admin_key_hash = "sha256-hex-of-your-admin-key"

[api.tls]
cert_path = "/etc/edgeshield/cert.pem"
key_path = "/etc/edgeshield/key.pem"

[api.audit]
log_path = "/var/log/edgeshield/audit.log"

# Device history snapshots
[storage]
history_snapshot_hours = 24
history_retention_days = 90

# Offline scanner
[scanner]
interval_seconds = 60
```

## Logging

EdgeShield uses structured JSON logging via the `tracing` framework. All log output goes to stderr.

```json
{"timestamp":"2026-07-18T12:00:00.000Z","level":"INFO","fields":{"message":"EdgeShield starting"},"target":"edgeshield_daemon::daemon","span":{"name":"daemon","interface":"eth0"}}
```

## API Overview

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/health` | Health check (status + version) | None |
| GET | `/devices` | List all discovered devices | Read |
| GET | `/devices/{mac}` | Get a single device by MAC address | Read |
| GET | `/devices/{mac}/history` | Daily snapshot history for a device | Read |
| GET | `/alerts` | List alerts (with filters) | Read |
| GET | `/alerts/{id}` | Get a single alert by ID | Read |
| POST | `/alerts/{id}/acknowledge` | Mark an alert as acknowledged | Admin |
| DELETE | `/alerts/{id}` | Delete an alert | Admin |
| GET | `/metrics` | Aggregate network metrics (JSON) | Read |
| GET | `/metrics/prometheus` | Prometheus text exposition format | Read |

See [docs/api/rest.md](docs/api/rest.md) for the complete API reference.

## Security Philosophy

EdgeShield is designed to be secure by default:

- **No network egress** — EdgeShield never initiates outbound connections. It listens on a local port and captures packets from a local interface.
- **No telemetry** — Zero data leaves the device unless explicitly queried via the API.
- **Minimal attack surface** — The REST API exposes only read-only endpoints.
- **Memory safety** — Written in Rust. No buffer overflows, use-after-free, or double-free vulnerabilities.

## Performance Goals

| Metric | Target | Hardware |
|--------|--------|----------|
| Memory (idle) | < 10 MB RSS | Raspberry Pi 4 |
| Memory (1000 devices) | < 50 MB RSS | Raspberry Pi 4 |
| Packet throughput | 10,000+ pps | Raspberry Pi 4 |
| API response time | < 10 ms p99 | Any |
| Startup time | < 1 second | Raspberry Pi 4 |

## Contributing

EdgeShield welcomes contributions. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Quick start:

```bash
git clone https://github.com/edgeshield/edgeshield.git
cd edgeshield
cargo test
cargo clippy
cargo fmt --check
```

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | MVP — Device Discovery & Monitoring | ✅ Complete |
| 2 | Production Hardening | ✅ Complete |
| 3 | Persistent Storage (SQLite) | ✅ Complete |
| 4 | Protocol Depth (DHCP, HTTP, mDNS) | 🔄 Next |
| 5 | Alerting & Rules | 📅 Planned |
| 6 | Security & Access Control | 📅 Planned |
| 7 | Packaging & Distribution | 📅 Planned |
| 8 | Web Dashboard | 📅 Planned |

See [ROADMAP.md](ROADMAP.md) for the full development roadmap.

## FAQ

**Q: Does EdgeShield require an internet connection?**

No. EdgeShield is fully offline-capable. It never makes outbound connections.

**Q: Does EdgeShield store packet payloads?**

No. EdgeShield extracts header metadata (MAC addresses, IP addresses, ports, protocol types) and discards the payload. No raw packets are stored.

**Q: Can EdgeShield detect intruders?**

The MVP focuses on device discovery and traffic profiling. Anomaly detection and signature-based intrusion detection are planned for Phase 5.

**Q: What hardware do I need?**

EdgeShield runs on any Linux system with a network interface. A Raspberry Pi 3 or 4 is sufficient for home networks. Raspberry Pi Zero 2 W works for smaller networks (< 20 devices).

**Q: Does EdgeShield support Wi-Fi interfaces?**

Yes. EdgeShield uses read-only capture mode (`promisc(false)`) that does not disrupt normal WiFi connectivity. No monitor mode or special drivers required.

**Q: How is EdgeShield different from Wireshark, Suricata, or Zeek?**

Wireshark is an interactive packet analyzer. Suricata and Zeek are full-featured IDS/IPS systems. EdgeShield is a lightweight, purpose-built device discovery and traffic profiling tool. It does not do deep packet inspection, stream reassembly, or signature matching. It is designed for continuous passive monitoring on resource-constrained hardware.

## License

EdgeShield is dual-licensed:

- **Community Edition**: [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE)
- **Commercial Edition**: Proprietary (see [LICENSES.md](LICENSES.md))

The Community Edition is free for all use — personal, educational, and commercial.
