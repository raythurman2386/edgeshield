//! Metrics view — aggregate counters from `GET /metrics`.
//!
//! A simple, mostly-static view: total devices, total packets, total
//! bytes, daemon uptime. Future versions can add per-protocol
//! sparklines derived from `/devices` `protocol_stats`.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;

use crate::snapshot::Snapshot;
use crate::theme;

/// Render the metrics view into `area`.
pub fn render(frame: &mut Frame, area: Rect, snap: &Snapshot) {
    let block = theme::active_block("Metrics");

    let body = match snap.metrics.as_ref() {
        Some(m) => format!(
            "Total devices : {}\n\
             Total packets : {}\n\
             Total bytes   : {}\n\
             Uptime         : {}s",
            m.total_devices, m.total_packets, m.total_bytes, m.uptime_seconds,
        ),
        None => "Metrics — API unreachable".to_string(),
    };

    frame.render_widget(Paragraph::new(body).block(block), area);
}
