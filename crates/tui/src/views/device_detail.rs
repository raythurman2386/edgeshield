//! Device detail view — a single device's full record plus a
//! packet-count sparkline derived from its daily history snapshots.
//!
//! Reached by pressing `Enter` on a device row in the Devices view.
//! Press `Esc` or `Backspace` to return to the Devices list.
//!
//! This view fetches `GET /devices/:mac/history` on entry (via
//! [`crate::app::App`]) and stores the result in
//! [`DeviceDetailState`]. It does not call the client directly.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Clear, Paragraph, Sparkline};

use edgeshield_common::{Device, DeviceHistorySnapshot};

use crate::theme;

/// Format a byte count with a sensible unit (KB/MB/GB), keeping two
/// significant figures. Values under 1024 render as plain bytes.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", n, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

/// State held while the device-detail view is open.
#[derive(Debug, Default)]
pub struct DeviceDetailState {
    /// The MAC address being viewed (set on entry).
    pub mac: Option<String>,
    /// The device record (a cached copy from the main snapshot).
    pub device: Option<Device>,
    /// Daily history snapshots (fetched on entry).
    pub history: Vec<DeviceHistorySnapshot>,
    /// Set if the history fetch failed.
    pub history_error: Option<String>,
}

impl DeviceDetailState {
    /// Reset state when leaving the detail view.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Packet counts from history, oldest first, for the sparkline.
    #[must_use]
    pub fn packet_series(&self) -> Vec<u64> {
        // History may be returned newest-first or oldest-first depending
        // on the store; sort by snapshot_date ascending for a left-to-right
        // timeline.
        let mut sorted = self.history.clone();
        sorted.sort_by(|a, b| a.snapshot_date.cmp(&b.snapshot_date));
        sorted.iter().map(|s| s.packet_count).collect()
    }
}

/// Render the device-detail view into `area`.
///
/// This is an overlay: it draws on top of the previously-rendered
/// view. Ratatui only paints cells the new widgets touch, so an
/// overlay that doesn't clear its area first leaves the underlying
/// frame visible in any cell the overlay's widgets don't write to
/// (empty rows inside the bordered block, gaps between the info
/// block and the sparkline, etc.). We render a `Clear` widget over
/// the whole area first to blank it back to the default style.
pub fn render(frame: &mut Frame, area: Rect, state: &DeviceDetailState) {
    // Blank the underlying frame first — without this, the Devices
    // table bleeds through the empty rows of the overlay.
    frame.render_widget(Clear, area);

    let block = theme::active_block("Device Detail");

    let device = match state.device.as_ref() {
        Some(d) => d,
        None => {
            frame.render_widget(
                Paragraph::new("No device selected. Press Esc to return.")
                    .block(block)
                    .alignment(Alignment::Center),
                area,
            );
            return;
        }
    };

    let [info_area, spark_area] =
        Layout::vertical([Constraint::Min(8), Constraint::Length(5)]).areas(area);

    render_info(frame, info_area, device, state);
    render_sparkline(frame, spark_area, state);
}

fn render_info(frame: &mut Frame, area: Rect, device: &Device, state: &DeviceDetailState) {
    let block = theme::active_block("Device Detail");
    let ips = device
        .ips
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let protocols = device
        .protocols
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut lines: Vec<Line> = vec![
        Line::from(format!("MAC          : {}", device.mac)),
        Line::from(format!(
            "IPs          : {}",
            if ips.is_empty() { "—" } else { &ips }
        )),
        Line::from(format!(
            "Hostname     : {}",
            device.hostname.as_deref().unwrap_or("—")
        )),
        Line::from(format!(
            "Vendor       : {}",
            device.vendor.as_deref().unwrap_or("—")
        )),
        Line::from(format!(
            "DHCP class   : {}",
            device.dhcp_vendor_class.as_deref().unwrap_or("—")
        )),
        Line::from(format!("Packets      : {}", device.packet_count)),
        Line::from(format!(
            "Bytes sent   : {}   received: {}",
            human_bytes(device.bytes_sent),
            human_bytes(device.bytes_received),
        )),
        Line::from(format!("First seen   : {}", device.first_seen)),
        Line::from(format!("Last seen    : {}", device.last_seen)),
        Line::from(format!(
            "Protocols    : {}",
            if protocols.is_empty() {
                "—"
            } else {
                &protocols
            }
        )),
    ];

    if let Some(err) = state.history_error.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("History error: {err}")).style(Style::default().red()));
    } else if state.history.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("History      : no daily snapshots available"));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "History      : {} daily snapshot(s)",
            state.history.len()
        )));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_sparkline(frame: &mut Frame, area: Rect, state: &DeviceDetailState) {
    let block = theme::dim_block("Packet count over time (daily snapshots)");
    let data = state.packet_series();
    if data.is_empty() {
        frame.render_widget(
            Paragraph::new("no history data")
                .block(block)
                .alignment(Alignment::Center),
            area,
        );
        return;
    }
    let sparkline = Sparkline::default()
        .block(block)
        .data(&data)
        .style(Style::default().cyan());
    frame.render_widget(sparkline, area);
}
