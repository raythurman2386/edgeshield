//! Health view — daemon reachability, version, and last error.
//!
//! Also rendered as a compact status bar at the bottom of every view
//! (see [`crate::app::App::render_status_bar`]).

use ratatui::Frame;
use ratatui::widgets::Paragraph;

use ratatui::layout::Rect;

use crate::snapshot::Snapshot;
use crate::theme;

/// Render the health view into `area`.
pub fn render(frame: &mut Frame, area: Rect, snap: &Snapshot) {
    let block = theme::active_block("Health");

    let body = match snap.health.as_ref() {
        Some(h) => format!(
            "Status   : {}\n\
             Version  : {}\n\
             Reachable: yes",
            h.status, h.version,
        ),
        None => "Daemon unreachable".to_string(),
    };

    let mut body = body;
    if let Some(err) = snap.last_error.as_ref() {
        body.push_str(&format!("\n\nLast error: {err}"));
    }

    frame.render_widget(Paragraph::new(body).block(block), area);
}
