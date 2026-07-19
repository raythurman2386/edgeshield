//! Devices view — the device inventory table.
//!
//! Renders `GET /devices` as a sortable table. This is the default view
//! and the highest-value screen for "what's on my network right now".

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Cell, Row, Table, TableState};

use edgeshield_common::Device;

use crate::snapshot::Snapshot;
use crate::theme;

/// State held across frames for the devices view.
#[derive(Debug, Default)]
pub struct DevicesState {
    /// Currently selected row index.
    pub selected: usize,
    /// Sort order (last-seen descending for now; future: toggleable).
    pub sort: SortOrder,
}

/// How the device table is sorted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    #[default]
    LastSeenDesc,
    PacketCountDesc,
}

impl DevicesState {
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
}

/// Render the devices view into `area`.
pub fn render(frame: &mut Frame, area: Rect, snap: &Snapshot, state: &mut DevicesState) {
    let block = theme::active_block("Devices");

    let devices: Vec<&Device> = match snap.devices.as_ref() {
        Some(d) => d.iter().collect(),
        None => {
            frame.render_widget(
                Block::default()
                    .borders(ratatui::widgets::Borders::NONE)
                    .title("Devices — API unreachable"),
                area,
            );
            return;
        }
    };

    let rows: Vec<Row> = devices
        .iter()
        .map(|d| {
            let ips = d
                .ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let hostname = d.hostname.clone().unwrap_or_else(|| "—".into());
            let vendor = d.vendor.clone().unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(d.mac.to_string()),
                Cell::from(ips),
                Cell::from(hostname),
                Cell::from(vendor),
                Cell::from(d.packet_count.to_string()),
                Cell::from(d.last_seen.to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(18),
        Constraint::Min(16),
        Constraint::Min(16),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(28),
    ];

    let table = Table::new(rows, widths)
        .block(block)
        .header(
            Row::new(vec![
                "MAC",
                "IPs",
                "Hostname",
                "Vendor",
                "Packets",
                "Last seen",
            ])
            .style(theme::heading_style())
            .bottom_margin(1),
        )
        .row_highlight_style(Style::default().reversed());

    let mut table_state = TableState::default();
    table_state.select(Some(state.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

// Re-export Constraint for the widths array above.
use ratatui::layout::Constraint;
