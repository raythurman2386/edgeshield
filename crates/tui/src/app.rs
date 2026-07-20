//! Application state and the main event loop.
//!
//! [`App`] owns the view-local state (selection indices, current view)
//! and a reference to the shared [`Snapshot`]. The event loop in
//! [`run`] drives rendering, input, and the poller task.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::RwLock;

use crate::client::Client;
use crate::event;
use crate::snapshot::Snapshot;
use crate::views::device_detail::DeviceDetailState;
use crate::views::{View, alerts::AlertsState, devices::DevicesState};
use crate::{DEFAULT_REFRESH_MS, DEFAULT_URL};

/// Command-line arguments for the TUI.
#[derive(Debug, Clone, Parser)]
#[command(name = "edgeshield-tui", about = "EdgeShield observability dashboard")]
pub struct Args {
    /// Base URL of the EdgeShield daemon's REST API.
    #[arg(long, env = "EDGESHIELD_URL", default_value = DEFAULT_URL)]
    pub url: String,

    /// Bearer token for the daemon's REST API (admin key required for ack).
    #[arg(long, env = "EDGESHIELD_KEY")]
    pub key: Option<String>,

    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = DEFAULT_REFRESH_MS)]
    pub refresh_ms: u64,
}

/// Top-level application state.
pub struct App {
    snapshot: Arc<RwLock<Snapshot>>,
    client: Client,
    view: View,
    devices: DevicesState,
    alerts: AlertsState,
    /// When set, the device-detail overlay is open and covers the
    /// current view. `None` means no overlay.
    detail: Option<DeviceDetailState>,
    /// Transient error message shown after a failed ack, cleared on
    /// the next redraw tick.
    flash: Option<String>,
    /// Set when the user requests a quit.
    quit: bool,
}

impl App {
    /// Construct app state from args. Also returns the shared snapshot
    /// handle so the caller can spawn the poller against it.
    pub fn new(client: Client) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Snapshot::empty())),
            client,
            view: View::Devices,
            devices: DevicesState::default(),
            alerts: AlertsState::default(),
            detail: None,
            flash: None,
            quit: false,
        }
    }

    /// Shared snapshot handle for the poller task.
    pub fn snapshot_handle(&self) -> Arc<RwLock<Snapshot>> {
        self.snapshot.clone()
    }

    /// Cycle to the next view.
    pub fn next_view(&mut self) {
        self.view = self.view.next();
    }

    /// Cycle to the previous view.
    pub fn prev_view(&mut self) {
        self.view = self.view.prev();
    }

    /// Move the current view's selection up.
    pub fn up(&mut self) {
        let len = self.current_list_len();
        match self.view {
            View::Devices => self.devices.up(len),
            View::Alerts => self.alerts.up(len),
            _ => {}
        }
    }

    /// Move the current view's selection down.
    pub fn down(&mut self) {
        let len = self.current_list_len();
        match self.view {
            View::Devices => self.devices.down(len),
            View::Alerts => self.alerts.down(len),
            _ => {}
        }
    }

    /// Acknowledge the currently-selected alert (Alerts view only).
    ///
    /// This is the **only** mutation the TUI performs. On success it
    /// forces an immediate snapshot refresh so the UI reflects the
    /// new ack state without waiting for the next tick.
    pub async fn ack_selected(&mut self) {
        let id = {
            let snap = self.snapshot.read().await;
            match snap.alerts.as_ref() {
                Some(alerts) => self.alerts.selected_alert_id(alerts),
                None => None,
            }
        };
        match id {
            Some(id) => match self.client.acknowledge_alert(id).await {
                Ok(()) => {
                    self.flash = None;
                    // Force an immediate refresh.
                    let s = self.client.snapshot().await;
                    *self.snapshot.write().await = s;
                }
                Err(e) => self.flash = Some(format!("ack failed: {e}")),
            },
            None => self.flash = Some("no alert selected".into()),
        }
    }

    /// Open the device-detail overlay for the currently-selected
    /// device in the Devices view. No-op if the devices list is empty
    /// or the fetch fails to find the device.
    pub async fn open_device_detail(&mut self) {
        let mac = {
            let snap = self.snapshot.read().await;
            match snap.devices.as_ref() {
                Some(devices) => devices
                    .get(self.devices.selected)
                    .map(|d| d.mac.to_string()),
                None => None,
            }
        };
        let Some(mac) = mac else {
            self.flash = Some("no device selected".into());
            return;
        };

        // Fetch history for the device. 501 (history disabled) is
        // treated as an empty history, not an error.
        let (history, history_error) = match self.client.device_history(&mac).await {
            Ok(h) => (h, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };

        // Cache the device record from the current snapshot.
        let device = {
            let snap = self.snapshot.read().await;
            snap.devices
                .as_ref()
                .and_then(|ds| ds.iter().find(|d| d.mac.to_string() == mac).cloned())
        };

        self.detail = Some(DeviceDetailState {
            mac: Some(mac),
            device,
            history,
            history_error,
        });
    }

    /// Close the device-detail overlay if open.
    pub fn close_device_detail(&mut self) {
        if let Some(mut d) = self.detail.take() {
            d.clear();
        }
    }

    /// Returns `true` if the device-detail overlay is currently open.
    #[must_use]
    pub fn is_detail_open(&self) -> bool {
        self.detail.is_some()
    }

    /// Number of rows in the currently-active list view (for clamping
    /// selection). Returns 0 for non-list views.
    fn current_list_len(&self) -> usize {
        // Snapshot is held behind a RwLock; for selection clamping we
        // use a best-effort read. If the lock is busy we return 0,
        // which is safe (selection stays put).
        match self.snapshot.try_read() {
            Ok(snap) => match self.view {
                View::Devices => snap.device_count(),
                View::Alerts => snap.alert_count(),
                _ => 0,
            },
            Err(_) => 0,
        }
    }

    /// Render the current frame.
    pub fn render(&mut self, frame: &mut Frame) {
        // try_read so a slow poller never blocks the render loop.
        let snap = match self.snapshot.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => return, // poller is mid-write; skip this frame
        };

        let area = frame.area();
        let [body, status] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(area);

        match self.view {
            View::Devices => crate::views::devices::render(frame, body, &snap, &mut self.devices),
            View::Alerts => crate::views::alerts::render(frame, body, &snap, &mut self.alerts),
            View::Metrics => crate::views::metrics::render(frame, body, &snap),
            View::Health => crate::views::health::render(frame, body, &snap),
        }

        // Device-detail overlay renders on top of the current view
        // when open. It covers the body area but leaves the status bar
        // visible.
        if let Some(detail) = self.detail.as_mut() {
            crate::views::device_detail::render(frame, body, detail);
        }

        self.render_status_bar(frame, status, &snap);
    }

    fn render_status_bar(&self, frame: &mut Frame, area: Rect, snap: &Snapshot) {
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::{Line, Span};

        // Left side: reachability dot (colored), current view, counts,
        // and any transient flash message.
        let reachable = snap.is_reachable();
        let dot_color = if reachable {
            crate::theme::Theme::ok()
        } else {
            crate::theme::Theme::error()
        };
        let view = self.view.title();
        let counts = format!("{} dev · {} alert", snap.device_count(), snap.alert_count());

        let mut left_spans: Vec<Span> = vec![
            Span::styled(" ●".to_string(), Style::default().fg(dot_color)),
            Span::raw(format!(" {view:<8} ")),
            Span::styled(counts, Style::default().add_modifier(Modifier::BOLD)),
        ];
        if let Some(flash) = self.flash.as_deref() {
            left_spans.push(Span::raw("  "));
            left_spans.push(Span::styled(
                flash.to_string(),
                Style::default().fg(crate::theme::Theme::error()),
            ));
        }

        // Right side: a compact keybinding hint. The hint changes per
        // view so the most relevant action is shown.
        let hint = match self.view {
            View::Devices => "↑↓ select · Enter detail · Tab switch · 1-4 views · q quit",
            View::Alerts => "↑↓ select · a ack · Tab switch · 1-4 views · q quit",
            View::Metrics => "Tab switch · 1-4 views · q quit",
            View::Health => "Tab switch · 1-4 views · q quit",
        };

        // Compose: left spans (variable width) + right-aligned hint.
        // We compute the remaining width and insert spaces to push the
        // hint to the right edge of the status bar.
        let total = area.width as usize;
        let left_len: usize = left_spans.iter().map(|s| s.content.chars().count()).sum();
        let hint_len: usize = hint.chars().count() + 1; // +1 for leading space
        let padding = total.saturating_sub(left_len + hint_len);

        let mut spans = left_spans;
        spans.push(Span::raw(" ".repeat(padding)));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(hint, Style::default().fg(Color::DarkGray)));

        let bar = Line::from(spans);
        frame.render_widget(Paragraph::new(bar).style(crate::theme::bar_style()), area);
    }

    /// Whether the user has requested to quit.
    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.quit
    }
}

/// Run the TUI event loop against the given terminal.
///
/// Spawns a poller task that refreshes the snapshot every
/// `args.refresh_ms` milliseconds, then drives the render loop with
/// `tokio::select!` between input and a redraw tick.
pub async fn run(mut terminal: DefaultTerminal, args: Args) -> anyhow::Result<()> {
    let key = args.key.as_deref();
    let client = Client::new(&args.url, key)?;
    let mut app = App::new(client);
    let snapshot = app.snapshot_handle();
    let client_clone = app.client_clone();

    // Poller task: the only writer of the shared Snapshot.
    let poller = tokio::spawn(poll_loop(
        client_clone,
        snapshot,
        Duration::from_millis(args.refresh_ms),
    ));

    let redraw = Duration::from_millis(250);
    loop {
        terminal.draw(|f| app.render(f))?;
        if app.should_quit() {
            break;
        }
        tokio::select! {
            ev = event::poll(redraw) => {
                if let Some(ev) = ev {
                    handle_event(&mut app, ev).await;
                }
            }
        }
    }

    poller.abort();
    Ok(())
}

impl App {
    /// Clone the client for the poller task. Internal helper.
    fn client_clone(&self) -> Client {
        // reqwest::Client is cheaply cloneable (Arc internally).
        self.client.clone()
    }
}

/// Background poll loop. Runs until the handle is aborted.
async fn poll_loop(client: Client, snapshot: Arc<RwLock<Snapshot>>, interval: Duration) {
    let mut t = tokio::time::interval(interval);
    loop {
        t.tick().await;
        let s = client.snapshot().await;
        *snapshot.write().await = s;
    }
}

/// Dispatch a terminal event to the app.
async fn handle_event(app: &mut App, ev: crossterm::event::Event) {
    use crossterm::event::{Event, KeyCode, KeyModifiers};
    let Event::Key(key) = ev else { return };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    // When the device-detail overlay is open, it captures navigation.
    if app.is_detail_open() {
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => app.close_device_detail(),
            // Allow quit from the overlay too.
            KeyCode::Char('q') if !ctrl => app.quit = true,
            KeyCode::Char('c') if ctrl => app.quit = true,
            _ => {}
        }
        return;
    }

    match (key.code, ctrl) {
        (KeyCode::Char('q'), false) | (KeyCode::Char('c'), true) => app.quit = true,
        (KeyCode::Tab, false) => app.next_view(),
        (KeyCode::BackTab, false) => app.prev_view(),
        (KeyCode::Char('1'), false) => app.view = View::Devices,
        (KeyCode::Char('2'), false) => app.view = View::Alerts,
        (KeyCode::Char('3'), false) => app.view = View::Metrics,
        (KeyCode::Char('4'), false) => app.view = View::Health,
        (KeyCode::Up, _) => app.up(),
        (KeyCode::Down, _) => app.down(),
        (KeyCode::Enter, _) => app.open_device_detail().await,
        (KeyCode::Char('a'), false) => app.ack_selected().await,
        _ => {}
    }
}
