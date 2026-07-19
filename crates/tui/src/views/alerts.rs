//! Alerts view — the alert feed plus the one mutation (ack).
//!
//! Renders `GET /alerts` as a list. Pressing `a` on a selected alert
//! calls `POST /alerts/:id/acknowledge` via [`crate::client::Client`]
//! (dispatched from [`crate::app::App`], not here).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, List, ListItem, ListState};

use edgeshield_common::{Alert, Severity};

use crate::snapshot::Snapshot;
use crate::theme;

/// State held across frames for the alerts view.
#[derive(Debug, Default)]
pub struct AlertsState {
    /// Currently selected alert index.
    pub selected: usize,
}

impl AlertsState {
    /// Move the selection up by one, clamping at the top.
    pub fn up(&mut self, len: usize) {
        if len == 0 {
            self.selected = 0;
        } else {
            self.selected = self.selected.saturating_sub(1).min(len - 1);
        }
    }

    /// Move the selection down by one, clamping at the bottom.
    pub fn down(&mut self, len: usize) {
        if len == 0 {
            self.selected = 0;
        } else {
            self.selected = (self.selected + 1).min(len - 1);
        }
    }

    /// ID of the alert at the current selection, if any.
    ///
    /// Used by [`crate::app::App`] to dispatch the ack mutation.
    #[must_use]
    pub fn selected_alert_id(&self, alerts: &[Alert]) -> Option<u64> {
        alerts.get(self.selected).map(|a| a.id)
    }
}

/// Color for a given alert severity.
fn severity_color(s: Severity) -> ratatui::style::Color {
    match s {
        Severity::Info => theme::Theme::info(),
        Severity::Warning => theme::Theme::warning(),
        Severity::Critical => theme::Theme::critical(),
    }
}

/// Render the alerts view into `area`.
pub fn render(frame: &mut Frame, area: Rect, snap: &Snapshot, state: &mut AlertsState) {
    let block = theme::active_block("Alerts");

    let alerts: Vec<&Alert> = match snap.alerts.as_ref() {
        Some(a) => a.iter().collect(),
        None => {
            frame.render_widget(
                Block::default()
                    .borders(ratatui::widgets::Borders::NONE)
                    .title("Alerts — API unreachable"),
                area,
            );
            return;
        }
    };

    let items: Vec<ListItem> = alerts
        .iter()
        .map(|a| {
            let sev = a.severity;
            let color = severity_color(sev);
            let ack = if a.acknowledged { "✓ " } else { "  " };
            let line = format!(
                "{ack}{sev:>7}  #{id:<6}  {event}  {mac}",
                sev = sev,
                id = a.id,
                event = a.event_type,
                mac = a.mac,
            );
            ListItem::new(line).style(Style::default().fg(color))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().reversed());

    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(list, area, &mut list_state);
}
