# EdgeShield TUI

The `edgeshield tui` subcommand is a **read-only observability dashboard** that renders live state from a running EdgeShield daemon over its REST API. It is a thin client — it holds no authoritative state of its own.

## Quickstart

```bash
# Daemon running on localhost with default port
edgeshield tui

# Connect to a remote daemon with an admin key (required for ack)
edgeshield tui --url http://10.0.0.5:8080 --key $EDGESHIELD_KEY

# Faster refresh (1 second)
edgeshield tui --refresh-ms 1000
```

The TUI can also be built as a standalone binary:

```bash
cargo build -p edgeshield-tui --release
./target/release/edgeshield-tui
```

## Options

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--url` | `EDGESHIELD_URL` | `http://localhost:8080` | Base URL of the daemon's REST API |
| `--key` | `EDGESHIELD_KEY` | — | Bearer token (admin key required for ack) |
| `--refresh-ms` | — | `2000` | Poll interval in milliseconds |

## Keybindings

### Global

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| `Tab` / `Shift+Tab` | Cycle to next / previous view |
| `1`–`4` | Jump directly to a view |

### Devices view

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move selection |
| `Enter` | Open the device-detail overlay for the selected device |

### Alerts view

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move selection |
| `a` | Acknowledge the selected alert (requires admin key) |

### Device-detail overlay

| Key | Action |
|-----|--------|
| `Esc` / `Backspace` | Close the overlay and return to the Devices view |
| `q` / `Ctrl+C` | Quit (works from the overlay too) |

## Views

### Devices

The device inventory table. Columns: MAC, IPs, hostname, vendor, packet count, last seen. This is the default view. Press `Enter` on a row to open the device-detail overlay.

### Device detail (overlay)

A full-screen overlay showing a single device's complete record:

- MAC, IPs, hostname, vendor, DHCP vendor class
- Packet count, bytes sent/received
- First seen, last seen
- Detected protocols
- A **packet-count sparkline** rendered from the device's daily history snapshots (`GET /devices/:mac/history`)

If history is disabled on the daemon (HTTP 501), the sparkline area shows "no history data" and the rest of the detail view still renders from the current device record. If the history fetch fails for another reason, the error is shown inline.

### Alerts

The alert feed with severity coloring (`info` = blue, `warning` = yellow, `critical` = red). Each row shows the severity, alert ID, event type, and MAC. Press `a` to acknowledge the selected alert — this calls `POST /alerts/:id/acknowledge` and forces an immediate refresh.

### Metrics

Aggregate counters from `GET /metrics`: total devices, total packets, total bytes, daemon uptime.

### Health

Daemon reachability, version, and the last fetch error. Always visible as a compact status bar at the bottom of every view.

## Status bar

A one-line bar at the bottom of every screen shows:

- A reachability indicator (`●` reachable, `○` unreachable)
- The current view name
- Device and alert counts
- Any transient error (e.g. ack failure)

## Scope — what the TUI is and is not

The TUI is an **observability dashboard**. It can:

- Display the device inventory, a single device's detail and history, the alert feed, aggregate metrics, and daemon health.
- Acknowledge an alert via `POST /alerts/:id/acknowledge` — the **only** mutation it performs, and only on the Alerts view.

It deliberately **cannot**:

- Edit configuration. The daemon reads `/etc/edgeshield/config.toml`; the TUI never writes it.
- Author or modify rules. Rules are user-configured files; the TUI shows their status and cooldowns.
- Start, stop, or restart capture. That is a systemd / daemon lifecycle concern.
- Delete alerts or devices.

This boundary is intentional and is documented in [ADR-0006](adr/ADR-0006-tui-observability-dashboard.md).

## Architecture

```text
┌────────────┐   poll (1–2 s)   ┌──────────────────┐
│  REST API  │ ───────────────▶ │  poller task     │
│  (daemon)  │                  │  client → Snapshot│
└────────────┘                  └────────┬─────────┘
                                         │ Arc<RwLock<Snapshot>>
                                         ▼
                                ┌──────────────────┐
                                │  render loop      │
                                │  ratatui::init()  │
                                └──────────────────┘
```

- The poller is the **only** writer of the shared `Snapshot`. The render loop reads it each frame.
- All four read endpoints (`/health`, `/devices`, `/alerts`, `/metrics`) are fetched in parallel each tick via `tokio::join!`.
- The device-detail overlay fetches `GET /devices/:mac/history` on demand when opened; it is not part of the regular poll cycle.
- On any per-endpoint failure, the corresponding field is `None` and `last_error` is set — the view renders "API unreachable" rather than showing stale data as if it were current.
- The TUI holds no domain state beyond the cached `Snapshot` and the transient `DeviceDetailState`. Kill it, restart it, run two of them — nothing changes about the daemon's state.

## Crate layout

```
crates/tui/
  Cargo.toml
  src/
    lib.rs              # crate root, run() entry with ratatui::init()/restore()
    main.rs             # standalone edgeshield-tui binary entry
    app.rs              # App state, event loop, input dispatch, overlay handling
    client.rs           # thin HTTP client; one method per REST endpoint
    snapshot.rs         # Snapshot — the single shared state struct
    event.rs            # async crossterm event polling
    theme.rs            # color palette and border styles
    views/
      mod.rs            # View enum (tab-cycle, titles)
      devices.rs        # device inventory table
      device_detail.rs  # single-device overlay + history sparkline
      alerts.rs         # alert feed + ack selection
      metrics.rs        # aggregate counters
      health.rs         # daemon reachability + last error
  tests/
    client.rs           # mock-server tests (in-process axum)
    render.rs           # render tests with ratatui TestBackend
```

## Feature gating

The TUI is feature-gated in `edgeshield-cli` behind the `tui` feature (default-on). To build a daemon-only binary without ratatui:

```bash
cargo build -p edgeshield-cli --no-default-features --release
```

This keeps the daemon binary small for constrained targets (e.g. Raspberry Pi Zero 2 W).

## Dependencies

- [ratatui](https://crates.io/crates/ratatui) 0.30 — terminal UI (uses `ratatui::init()` / `ratatui::restore()` lifecycle)
- [crossterm](https://crates.io/crates/crossterm) 0.28 — terminal backend (with `event-stream` for async input)
- [reqwest](https://crates.io/crates/reqwest) — HTTP client (reuses the workspace's `rustls-tls`/`json` config)
- `edgeshield-common` — shared `Device`/`Alert`/`DeviceHistorySnapshot` types (already `Serialize`/`Deserialize` to the API JSON shapes)

## Testing

- `crates/tui/tests/client.rs` — mock-server tests for the HTTP client (in-process axum server). Covers every endpoint, the ack mutation, snapshot aggregation, network errors, the 501-history-disabled case, and bearer-token construction.
- `crates/tui/tests/render.rs` — render tests using ratatui's `TestBackend` (no terminal required, CI-safe). One per view for both the populated and "API unreachable" cases, plus the device-detail overlay and unit tests for selection state.

Run with:

```bash
cargo test -p edgeshield-tui
```

## Shell completion

The `edgeshield completions` subcommand generates bash and zsh completion scripts that include the `tui` subcommand and its flags (`--url`, `--key`, `--refresh-ms`):

```bash
# bash
eval "$(edgeshield completions bash)"

# zsh
source <(edgeshield completions zsh)
```