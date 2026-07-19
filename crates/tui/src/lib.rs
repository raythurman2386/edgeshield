//! EdgeShield TUI — a read-only observability dashboard for the
//! EdgeShield daemon.
//!
//! This crate implements the `edgeshield tui` subcommand: a terminal
//! user interface that renders live state from the running daemon's
//! REST API. It is a thin client — it holds no authoritative state of
//! its own. All domain state (devices, alerts, history, metrics) is
//! owned by the daemon and fetched on a fixed cadence into a
//! [`snapshot::Snapshot`] that the render loop reads.
//!
//! # Scope
//!
//! The TUI is an **observability dashboard**. It can:
//!
//! - Display the device inventory, alert feed, aggregate metrics, and
//!   daemon health.
//! - Acknowledge an alert via `POST /alerts/:id/acknowledge` (the only
//!   mutation it performs, and only on the Alerts view).
//!
//! It deliberately cannot:
//!
//! - Edit configuration (the daemon reads `/etc/edgeshield/config.toml`).
//! - Author or modify rules.
//! - Start, stop, or restart capture (a systemd / daemon lifecycle
//!   concern).
//! - Delete alerts or devices.
//!
//! See `docs/tui.md` for the full design rationale and the
//! "observability dashboard" invariant.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐   poll (1–2 s)   ┌──────────────────┐
//! │  REST API  │ ───────────────▶│  poller task     │
//! │  (daemon)  │                 │  client → Snapshot│
//! └────────────┘                 └────────┬─────────┘
//!                                         │ Arc<RwLock<Snapshot>>
//!                                         ▼
//!                                ┌──────────────────┐
//!                                │  render loop      │
//!                                │  ratatui::init()  │
//!                                └──────────────────┘
//! ```
//!
//! The poller is the only writer of the [`Snapshot`]. The render loop
//! reads it each frame. There is no other shared state.

pub mod app;
pub mod client;
pub mod event;
pub mod snapshot;
pub mod theme;
pub mod views;

pub use app::{App, Args};
pub use client::Client;
pub use snapshot::Snapshot;

use std::time::Duration;

/// Default base URL of the daemon's REST API.
pub const DEFAULT_URL: &str = "http://localhost:8080";

/// Default refresh interval in milliseconds.
pub const DEFAULT_REFRESH_MS: u64 = 2000;

/// Run the TUI against the daemon at `args.url`.
///
/// This is the entry point invoked by the `edgeshield tui` subcommand.
/// It owns the tokio runtime, initializes the terminal via
/// [`ratatui::init`], runs the event loop, and guarantees
/// [`ratatui::restore`] is called on exit — including on panic.
pub fn run(args: Args) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let terminal = ratatui::init();
        let result = app::run(terminal, args).await;
        // Always restore the terminal, even on error.
        ratatui::restore();
        result
    })
}

/// Convenience constructor for the default refresh interval.
#[must_use]
pub fn default_refresh() -> Duration {
    Duration::from_millis(DEFAULT_REFRESH_MS)
}
