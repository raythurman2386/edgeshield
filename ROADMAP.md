# EdgeShield ROADMAP

> **Status**: MVP Phase (Phase 1 complete)
> **Version**: 0.1.0
> **Last updated**: 2026-07-19

---

## Guiding Principles

1. **No cloud dependency** — everything runs self-hosted or not at all
2. **ARM64-first** — Raspberry Pi 4/5 is the primary target; x86_64 is secondary
3. **Idle at zero** — the daemon must consume <1% CPU when no traffic is flowing
4. **Ship when stable** — each phase must be production-quality before moving on
5. **No feature flags** — full transitions only; no dead code paths

---

## Phase 1: MVP — Device Discovery & Passive Monitoring ✅

**Goal**: Capture packets, identify devices, expose inventory via REST API.

### Delivered

| Feature | Status | Notes |
|---|---|---|
| Cargo workspace (10 crates) | ✅ | Clean architecture, modular crates |
| TOML configuration | ✅ | Interface, port, log level, buffer size |
| Packet capture (pnet) | ✅ | Dedicated OS thread, mpsc channel |
| Packet decode (Ethernet/IP/TCP/UDP/ICMP) | ✅ | Owned header structs, no lifetime complexity |
| Protocol classification (ARP/IPv4/ICMP/TCP/UDP/DNS) | ✅ | Pure functions, independently testable |
| Device discovery engine | ✅ | MAC→Device table, first/last seen, counters |
| In-memory device store (DashMap) | ✅ | Lock-free concurrent access |
| REST API (health/devices/metrics) | ✅ | Axum, 4 endpoints |
| Structured JSON logging (tracing) | ✅ | JSON output, span-based |
| Graceful shutdown (Ctrl+C) | ✅ | Capture thread → pipeline → API |
| CLI entry point (clap) | ✅ | `edgeshield run`, `edgeshield default-config` |
| Unit tests | ✅ | 33 tests, all passing |
| Integration tests (pipeline) | ✅ | 5 tests, synthetic TCP/ARP/DNS/multi-device |
| PCAP fixture tests | ✅ | 6 tests, real packet decode verification |
| Root check (warn if not root) | ✅ | CLI prints warning, suggests setcap |
| Config fallback paths | ✅ | Tries /etc, /usr/local/etc, cwd |
| Error recovery (interface flap) | ✅ | Auto-reconnect with backoff, 10-retry limit |

---

## Phase 2: Production Hardening ✅

**Goal**: Ship-ready daemon that survives reboots, interface flaps, and operator mistakes.

| Feature | Status | Notes |
|---|---|---|
| systemd service file + Makefile install target | ✅ | `dist/edgeshield.service`, `Makefile` with install/uninstall |
| PID file / single-instance guard | ✅ | `/run/edgeshield.pid`, detects running process via `libc::kill` |
| Interface health monitoring (reconnect on flap) | ✅ | Done in Phase 1 — auto-reconnect with 2s backoff, 10-retry limit |
| Clippy-clean codebase | ✅ | `cargo clippy --all-targets -- -D warnings` passes clean |
| CI pipeline (cargo test, clippy, fmt) | ✅ | `.gitea/workflows/ci.yaml` — push + PR on main |
| Man page (`edgeshield(8)`) | ✅ | `dist/edgeshield.8` — full man page with synopsis, options, endpoints |
| Bash/Zsh completions | ✅ | `edgeshield completions bash` / `edgeshield completions zsh` |
| Prometheus text metrics on /metrics | ⬜ | JSON endpoint exists; Prometheus text format deferred to Phase 3 |
| Config reload (SIGHUP) | ⬜ | Deferred to Phase 3 — requires config watch infrastructure |
| Log rotation support (file appender) | ⬜ | Deferred to Phase 3 — tracing subscriber file layer |

**Exit criteria**: `cargo clippy --all-targets -- -D warnings` passes. ✅

---

## Phase 3: Persistent Storage ✅

**Goal**: Devices survive daemon restart. Historical data for trend analysis.

| Feature | Status | Notes |
|---|---|---|
| SQLite `DeviceStore` implementation | ✅ | `SqliteStore` with WAL mode, UPSERT, JSON serde for IPs/protocols |
| Schema migration framework | ✅ | Auto-creates table on open; `CREATE TABLE IF NOT EXISTS` |
| Config option for database path | ✅ | `database_path` in TOML; empty = in-memory fallback |
| Device history table (per-day snapshots) | ⬜ | Deferred — requires separate history table + cron |
| `/devices/history` API endpoint | ⬜ | Deferred — depends on history table |
| Database vacuum / maintenance | ⬜ | Deferred — `PRAGMA auto_vacuum=INCREMENTAL` for later |

**Exit criteria**: Restart the daemon, all previously discovered devices reappear. ✅ (verified via `test_sqlite_store_persistence`)

---

## Phase 4: Protocol Depth ⬜

**Goal**: Detect application-layer protocols beyond port heuristics.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| DHCP detection (hostname extraction) | P0 | 2 days | — |
| HTTP request/response detection | P1 | 3 days | — |
| mDNS / Bonjour detection | P1 | 2 days | — |
| NTP detection | P2 | 0.5 day | — |
| DHCP fingerprint (vendor class) | P2 | 2 days | — |
| Protocol statistics per device | P1 | 1 day | — |

**Exit criteria**: A device doing DHCP gets its hostname populated. HTTP servers are identified by port + banner.

---

## Phase 5: Alerting & Rules ⬜

**Goal**: User-configurable rules that trigger on network events.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| Rule engine (TOML rules file) | P0 | 3 days | — |
| Built-in rules (new device, known device offline) | P0 | 1 day | rule engine |
| Webhook notification channel | P0 | 2 days | rule engine |
| Email notification channel (sendmail) | P1 | 2 days | rule engine |
| `/alerts` API endpoint + alert history | P1 | 1 day | rule engine |
| Rate-limited alerts (debounce) | P1 | 1 day | — |

**Exit criteria**: Configure a rule that emails you when a new MAC appears. Configure another that webhooks when a known device goes silent for 30 min.

---

## Phase 6: Security & Access Control ⬜

**Goal**: The API is not an open door.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| API key authentication (Bearer token) | P0 | 1 day | — |
| TLS for API server | P0 | 1 day | — |
| Configurable listen address (not just 0.0.0.0) | P0 | 0.5 day | — |
| Read-only API key vs admin key | P1 | 1 day | auth |
| Audit log (who accessed what, when) | P2 | 1 day | auth |

**Exit criteria**: Without a valid API key, all endpoints return 401. With TLS, curl works with `--cacert`.

---

## Phase 7: Packaging & Distribution ⬜

**Goal**: One-command install on supported platforms.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| `.deb` package (Debian/Ubuntu/Raspbian) | P0 | 1 day | Phase 2 |
| Docker image (multi-arch: amd64, arm64) | P0 | 1 day | — |
| `edgeshield setup` wizard (first-run config) | P1 | 2 days | — |
| Release script (tag, build, publish) | P1 | 1 day | — |
| Homebrew formula (macOS devs) | P2 | 0.5 day | — |

**Exit criteria**: `apt install edgeshield` on a Pi 4, then `systemctl start edgeshield` = running daemon.

---

## Phase 8: Web Dashboard ⬜

**Goal**: Visual device inventory and network topology.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| Static file server in API crate | P0 | 0.5 day | — |
| Device list view (table, sortable) | P0 | 2 days | — |
| Device detail view (timeline, protocols) | P0 | 2 days | — |
| Network topology graph (force-directed) | P1 | 3 days | — |
| Real-time device updates (SSE) | P1 | 2 days | event channel (done) |
| Alert history view | P1 | 1 day | Phase 5 |

**Exit criteria**: Open `http://edgeshield:8080` in a browser, see all devices, click one for details.

---

## Phase 9: Performance Tuning ⬜

**Goal**: Handle 100Mbps sustained on a Pi 4 without dropping packets.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| BPF filter support (capture only relevant traffic) | P0 | 1 day | — |
| Ring buffer capture (AF_PACKET v3 / TPACKET_V3) | P0 | 3 days | — |
| Perf benchmarks + regression harness | P1 | 2 days | — |
| NUMA-aware channel sizing | P2 | 1 day | — |
| Batch processing (process N packets per yield) | P2 | 2 days | — |

**Exit criteria**: `iperf3` at 100Mbps → zero dropped packets in `edgeshield /metrics`.

---

## Phase 10: Commercial Readiness ⬜

**Goal**: Sellable product with support infrastructure.

| Feature | Priority | Effort | Depends On |
|---|---|---|---|
| License key validation | P0 | 2 days | — |
| Support bundle script (logs + config + device DB) | P0 | 1 day | — |
| Telemetry opt-in (version, device count, uptime only) | P1 | 1 day | — |
| Documentation site (API reference, deployment guide) | P1 | 3 days | — |
| EULA / license file | P0 | 0.5 day | legal |

**Exit criteria**: Customer can install, license, and get support without emailing a human.

---

## Never Do

These are explicitly out of scope to prevent feature creep:

- ❌ Cloud dashboard / SaaS offering
- ❌ Deep packet inspection (DPI) / content filtering
- ❌ Intrusion prevention (IPS) — blocking traffic
- ❌ VPN / firewall functionality
- ❌ NetFlow / IPFIX export
- ❌ SNMP support
- ❌ Windows support
- ❌ Machine learning / anomaly detection
- ❌ Packet capture to PCAP files (use `tcpdump`)
- ❌ Active scanning / ARP spoof detection

---

## Current Focus

**Phase 4: Protocol Depth** — DHCP hostname extraction, HTTP detection, mDNS/Bonjour.
