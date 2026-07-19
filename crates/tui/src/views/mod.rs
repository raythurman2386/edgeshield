//! View modules — one per top-level screen of the dashboard.
//!
//! Each view is a pure render function `fn render(frame, area, snapshot,
//! state)` plus any view-local state it needs (e.g. selection index).
//! Views never call the client directly; the only mutation (alert ack)
//! is dispatched through [`crate::app::App`].

pub mod alerts;
pub mod device_detail;
pub mod devices;
pub mod health;
pub mod metrics;

/// Which view is currently displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Devices,
    Alerts,
    Metrics,
    Health,
}

impl View {
    /// All views in tab-cycle order.
    pub const ALL: [Self; 4] = [Self::Devices, Self::Alerts, Self::Metrics, Self::Health];

    /// Cycle to the next view.
    #[must_use]
    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|v| *v == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    /// Cycle to the previous view.
    #[must_use]
    pub fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|v| *v == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    /// Human-readable title for headers and help.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Devices => "Devices",
            Self::Alerts => "Alerts",
            Self::Metrics => "Metrics",
            Self::Health => "Health",
        }
    }
}
