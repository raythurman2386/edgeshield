//! The aggregated state fetched from the daemon each poll tick.
//!
//! [`Snapshot`] is the **only** shared state between the poller task
//! and the render loop. It is a plain data struct — no methods mutate
//! daemon state. The poller constructs a fresh `Snapshot` each tick
//! and replaces the previous one wholesale via `Arc<RwLock<Snapshot>>`.
//!
//! # Invariant
//!
//! The TUI holds no authoritative domain state. Every field here is a
//! cached copy of state the daemon owns. If a fetch fails, the
//! corresponding field is `None` and `last_error` is set — the view
//! renders "API unreachable" rather than showing stale data as if it
//! were current.

use std::time::Instant;

use edgeshield_common::{Alert, Device};

use crate::client::MetricsResponse;

/// A point-in-time copy of the daemon's observable state.
///
/// Constructed by [`crate::client::Client::snapshot`] on each poll and
/// stored in `Arc<RwLock<Snapshot>>` for the render loop to read.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// When this snapshot was fetched (local monotonic clock).
    pub fetched_at: Option<Instant>,
    /// `GET /health` result. `None` if the daemon was unreachable.
    pub health: Option<HealthSnapshot>,
    /// `GET /devices` result. `None` if the fetch failed.
    pub devices: Option<Vec<Device>>,
    /// `GET /alerts` result. `None` if the fetch failed.
    pub alerts: Option<Vec<Alert>>,
    /// `GET /metrics` result. `None` if the fetch failed.
    pub metrics: Option<MetricsResponse>,
    /// The most recent fetch error, if any. Cleared on the next
    /// successful full poll.
    pub last_error: Option<String>,
}

/// Subset of `GET /health` that the TUI renders.
#[derive(Debug, Clone)]
pub struct HealthSnapshot {
    pub status: String,
    pub version: String,
}

impl Snapshot {
    /// Construct an empty snapshot (used before the first poll).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if the daemon was reachable on the last poll.
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.health.is_some()
    }

    /// Number of devices in the current snapshot, or `0` if the fetch
    /// failed.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.as_ref().map_or(0, Vec::len)
    }

    /// Number of alerts in the current snapshot, or `0` if the fetch
    /// failed.
    #[must_use]
    pub fn alert_count(&self) -> usize {
        self.alerts.as_ref().map_or(0, Vec::len)
    }
}
