# ADR-0006: TUI as a Read-Only Observability Dashboard

## Status

Accepted — 2026-07-19.

## Context

EdgeShield exposes all observable state through a REST API (`/health`, `/devices`, `/alerts`, `/metrics`, plus `/devices/:mac/history`). Before this ADR, the only ways to consume that state were:

1. `curl` + `jq` from the command line.
2. A future web dashboard (not yet built, and out of scope for the near term).
3. External integrations (Prometheus scrape, ntfy/MQTT/webhook/email alerts).

For a homelab user SSH'd into a Raspberry Pi, none of these is a good "what's happening on my network right now" experience. A terminal UI is the natural fit for the project's audience and deployment target.

The question was: **what is the TUI's role, and where do we draw its boundary?**

### Considered options

1. **Full control surface.** The TUI can edit config, author rules, start/stop capture, ack/delete alerts, and view state.
2. **Observability dashboard only.** The TUI renders state from the REST API and performs exactly one mutation: alert acknowledgment (which already exists as `POST /alerts/:id/acknowledge`).
3. **No TUI.** Defer to a web dashboard built later.

## Decision

Adopt **option 2**: the TUI is a read-only observability dashboard that talks to the daemon over its existing REST API. The only mutation it performs is acknowledging an alert.

## Rationale

### Single source of truth

The daemon owns all state. Config lives in `/etc/edgeshield/config.toml`. Rules are user-configured files. Capture lifecycle is a systemd concern. If the TUI were allowed to mutate any of these, it would become a second writer alongside the daemon, and the system would need a coherence story (reload signals, conflict resolution, audit trails for TUI-initiated changes). That complexity is not justified for a v1 TUI.

By restricting the TUI to the existing REST API — and to the one mutation that already exists and is already audited (`acknowledge_alert` in `crates/api/src/routes.rs`) — the TUI cannot violate any existing invariant. The daemon remains the sole writer of config, rules, and capture state.

### Crash safety

A TUI that holds no authoritative state is crash-safe by construction. If it panics, the daemon is unaffected. If the daemon is down, the TUI shows "API unreachable" and keeps trying. This is the property you want for a dashboard that may run over a flaky SSH connection.

### Thin client over existing work

The REST API already has authentication (Bearer tokens, read vs admin), rate limiting, TLS, and audit logging. The TUI reuses all of it by being an HTTP client. No new auth, rate-limit, or audit code is needed in the TUI crate. The TUI can also run on a different host than the daemon — useful for monitoring a headless Pi from a laptop.

### Why not a web dashboard now

A web dashboard is a larger undertaking (frontend build tooling, asset serving, a second auth surface, browser compatibility) and does not fit the project's "self-contained binary, minimal footprint, terminal-friendly" ethos for v1. The TUI is a few thousand lines of Rust, links no frontend runtime, and ships in the same binary. A web dashboard remains a future option; the REST API it would consume is the same one the TUI consumes.

### Why ratatui

- Maintained fork of `tui-rs`, the de facto Rust TUI library.
- Pure Rust, no native deps, works over any SSH session.
- `TestBackend` enables CI-safe render tests without a terminal.
- Small dependency footprint; feature-gated so the daemon binary can be built without it.

## Consequences

### Positive

- The TUI is a low-risk addition: it cannot corrupt daemon state.
- All existing tests, auth, and audit logging apply unchanged.
- The TUI can be built and shipped independently (standalone `edgeshield-tui` binary) or as a subcommand (`edgeshield tui`).
- Feature-gating keeps the daemon binary small for constrained targets.

### Negative

- Users cannot edit config or rules from the TUI. They must edit files and reload the daemon. This is acceptable for v1 and matches the project's existing operational model.
- The TUI polls rather than streams. A 1–2 s refresh interval is fine for passive monitoring but would not suit a future real-time IPS feature. If streaming becomes needed, a websocket/SSE channel can be added to the API later; the TUI's poller is the only thing that changes.
- Acknowledging an alert requires an admin key. A user with only a read key will see a 403 on the ack action; the TUI surfaces this as a flash error.

## Implementation

- New crate `crates/tui/` (workspace member).
- Feature-gated in `edgeshield-cli` behind the `tui` feature (default-on).
- Shared state is `Arc<RwLock<Snapshot>>`; the poller is the only writer.
- The one mutation (`acknowledge_alert`) is dispatched from the Alerts view via the existing `POST /alerts/:id/acknowledge` endpoint.
- See `docs/tui.md` for usage and `crates/tui/` for source.