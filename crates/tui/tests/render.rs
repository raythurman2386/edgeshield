//! Render tests using ratatui's `TestBackend`.
//!
//! Each test builds a `Snapshot`, renders a view into a `TestBackend`
//! buffer, and asserts that the expected strings appear. No terminal
//! is required — these run in CI.

use edgeshield_common::{Alert, AlertEventType, Device, DeviceHistorySnapshot, Severity};
use edgeshield_tui::client::MetricsResponse;
use edgeshield_tui::snapshot::{HealthSnapshot, Snapshot};
use edgeshield_tui::views::alerts::AlertsState;
use edgeshield_tui::views::device_detail::DeviceDetailState;
use edgeshield_tui::views::devices::DevicesState;
use mac_address::MacAddress;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use std::str::FromStr;

/// Render a view into a fresh buffer and return the buffer contents.
fn render<F>(width: u16, height: u16, render_fn: F) -> Buffer
where
    F: FnOnce(&mut Terminal<TestBackend>) -> Result<(), Box<dyn std::error::Error>>,
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    render_fn(&mut terminal).unwrap();
    terminal.backend().buffer().clone()
}

/// Assert that a buffer contains a given substring.
fn assert_contains(buf: &Buffer, needle: &str) {
    let text = buffer_text(buf);
    assert!(
        text.contains(needle),
        "expected buffer to contain {needle:?}; got:\n{text}"
    );
}

/// Flatten a buffer into a single string (rows joined by '\n').
fn buffer_text(buf: &Buffer) -> String {
    let area = buf.area;
    let mut rows = Vec::with_capacity(area.height as usize);
    for y in 0..area.height {
        let row: String = (0..area.width).map(|x| buf[(x, y)].symbol()).collect();
        rows.push(row.trim_end().to_string());
    }
    rows.join("\n")
}

fn sample_device() -> Device {
    let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
    Device::new(mac)
}

fn sample_alert() -> Alert {
    let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
    Alert::new(
        "rogue-device".into(),
        Severity::Critical,
        AlertEventType::NewDevice,
        Device::new(mac),
        "a new device appeared".into(),
    )
}

fn healthy_snapshot() -> Snapshot {
    Snapshot {
        fetched_at: Some(std::time::Instant::now()),
        health: Some(HealthSnapshot {
            status: "ok".into(),
            version: "0.1.0".into(),
        }),
        devices: Some(vec![sample_device()]),
        alerts: Some(vec![sample_alert()]),
        metrics: Some(MetricsResponse {
            total_devices: 1,
            total_packets: 100,
            total_bytes: 10_000,
            uptime_seconds: 42,
        }),
        last_error: None,
    }
}

#[test]
fn test_devices_view_renders_header_and_mac() {
    let snap = healthy_snapshot();
    let mut state = DevicesState::default();
    let buf = render(120, 20, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::devices::render(f, f.area(), &snap, &mut state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "Devices");
    assert_contains(&buf, "MAC");
    assert_contains(&buf, "00:11:22:33:44:55");
}

#[test]
fn test_devices_view_shows_unreachable_when_no_devices() {
    let snap = Snapshot::empty();
    let mut state = DevicesState::default();
    let buf = render(80, 10, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::devices::render(f, f.area(), &snap, &mut state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "API unreachable");
}

#[test]
fn test_alerts_view_renders_alert_fields() {
    let snap = healthy_snapshot();
    let mut state = AlertsState::default();
    let buf = render(120, 20, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::alerts::render(f, f.area(), &snap, &mut state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "Alerts");
    assert_contains(&buf, "critical");
    assert_contains(&buf, "new_device");
    assert_contains(&buf, "00:11:22:33:44:55");
}

#[test]
fn test_alerts_view_shows_unreachable_when_no_alerts() {
    let snap = Snapshot::empty();
    let mut state = AlertsState::default();
    let buf = render(80, 10, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::alerts::render(f, f.area(), &snap, &mut state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "API unreachable");
}

#[test]
fn test_metrics_view_renders_counters() {
    let snap = healthy_snapshot();
    let buf = render(80, 10, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::metrics::render(f, f.area(), &snap);
        })?;
        Ok(())
    });
    assert_contains(&buf, "Metrics");
    assert_contains(&buf, "Total devices : 1");
    assert_contains(&buf, "Total packets : 100");
    assert_contains(&buf, "Uptime         : 42s");
}

#[test]
fn test_metrics_view_unreachable() {
    let snap = Snapshot::empty();
    let buf = render(80, 10, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::metrics::render(f, f.area(), &snap);
        })?;
        Ok(())
    });
    assert_contains(&buf, "API unreachable");
}

#[test]
fn test_health_view_renders_status_and_version() {
    let snap = healthy_snapshot();
    let buf = render(80, 10, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::health::render(f, f.area(), &snap);
        })?;
        Ok(())
    });
    assert_contains(&buf, "Health");
    assert_contains(&buf, "ok");
    assert_contains(&buf, "0.1.0");
    assert_contains(&buf, "Reachable: yes");
}

#[test]
fn test_health_view_unreachable_shows_error() {
    let snap = Snapshot {
        fetched_at: Some(std::time::Instant::now()),
        health: None,
        last_error: Some("connection refused".into()),
        ..Snapshot::empty()
    };
    let buf = render(80, 10, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::health::render(f, f.area(), &snap);
        })?;
        Ok(())
    });
    assert_contains(&buf, "Daemon unreachable");
    assert_contains(&buf, "connection refused");
}

#[test]
fn test_snapshot_is_reachable_reflects_health() {
    let mut snap = Snapshot::empty();
    assert!(!snap.is_reachable());
    snap.health = Some(HealthSnapshot {
        status: "ok".into(),
        version: "0.1.0".into(),
    });
    assert!(snap.is_reachable());
}

#[test]
fn test_snapshot_counts_handle_none() {
    let snap = Snapshot::empty();
    assert_eq!(snap.device_count(), 0);
    assert_eq!(snap.alert_count(), 0);
}

#[test]
fn test_view_cycle_wraps_around() {
    use edgeshield_tui::views::View;
    let v = View::Devices;
    assert_eq!(v.next(), View::Alerts);
    assert_eq!(View::Health.next(), View::Devices);
    assert_eq!(View::Devices.prev(), View::Health);
}

#[test]
fn test_view_titles_are_stable() {
    use edgeshield_tui::views::View;
    assert_eq!(View::Devices.title(), "Devices");
    assert_eq!(View::Alerts.title(), "Alerts");
    assert_eq!(View::Metrics.title(), "Metrics");
    assert_eq!(View::Health.title(), "Health");
}

#[test]
fn test_alerts_state_selection_clamps() {
    let mut state = AlertsState::default();
    state.up(5); // no-op at top
    assert_eq!(state.selected, 0);
    state.down(5);
    assert_eq!(state.selected, 1);
    state.down(5);
    state.down(5);
    state.down(5);
    state.down(5);
    assert_eq!(state.selected, 4, "should clamp at last index");
    state.down(5); // already at bottom
    assert_eq!(state.selected, 4);
}

#[test]
fn test_alerts_state_selected_alert_id() {
    let alerts = vec![sample_alert(), sample_alert()];
    let mut state = AlertsState::default();
    assert_eq!(state.selected_alert_id(&alerts), Some(0));
    state.down(2);
    assert_eq!(state.selected_alert_id(&alerts), Some(0));
    state.selected = 1;
    assert_eq!(state.selected_alert_id(&alerts), Some(0));
}

#[test]
fn test_alerts_state_empty_list_returns_none() {
    let state = AlertsState::default();
    let alerts: Vec<Alert> = vec![];
    assert_eq!(state.selected_alert_id(&alerts), None);
}

// ---- Device detail view ----

fn sample_history(mac: MacAddress, count: usize) -> Vec<DeviceHistorySnapshot> {
    use edgeshield_common::Timestamp;
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;
    let now = Timestamp::now();
    (0..count)
        .map(|i| DeviceHistorySnapshot {
            mac,
            snapshot_date: format!("2026-07-{:02}", i + 1),
            snapshot_timestamp: now,
            ips: BTreeSet::<IpAddr>::new(),
            hostname: None,
            vendor: None,
            dhcp_vendor_class: None,
            packet_count: (i as u64 + 1) * 100,
            bytes_sent: 0,
            bytes_received: 0,
            protocols: BTreeSet::new(),
            protocol_stats: BTreeMap::new(),
            first_seen: now,
            last_seen: now,
        })
        .collect()
}

#[test]
fn test_device_detail_renders_device_fields() {
    let device = sample_device();
    let state = DeviceDetailState {
        mac: Some(device.mac.to_string()),
        device: Some(device.clone()),
        history: Vec::new(),
        history_error: None,
    };
    let buf = render(100, 24, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::device_detail::render(f, f.area(), &state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "Device Detail");
    assert_contains(&buf, "00:11:22:33:44:55");
    assert_contains(&buf, "no daily snapshots available");
}

#[test]
fn test_device_detail_renders_history_count() {
    let device = sample_device();
    let history = sample_history(device.mac, 5);
    let state = DeviceDetailState {
        mac: Some(device.mac.to_string()),
        device: Some(device),
        history,
        history_error: None,
    };
    let buf = render(100, 24, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::device_detail::render(f, f.area(), &state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "5 daily snapshot(s)");
}

#[test]
fn test_device_detail_renders_history_error() {
    let device = sample_device();
    let state = DeviceDetailState {
        mac: Some(device.mac.to_string()),
        device: Some(device),
        history: Vec::new(),
        history_error: Some("connection refused".into()),
    };
    let buf = render(100, 24, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::device_detail::render(f, f.area(), &state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "History error: connection refused");
}

#[test]
fn test_device_detail_no_device_shows_placeholder() {
    let state = DeviceDetailState::default();
    let buf = render(80, 20, |terminal| {
        terminal.draw(|f| {
            edgeshield_tui::views::device_detail::render(f, f.area(), &state);
        })?;
        Ok(())
    });
    assert_contains(&buf, "No device selected");
}

#[test]
fn test_device_detail_packet_series_sorted_ascending() {
    let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
    // Insert in reverse date order to verify sorting.
    let mut history = sample_history(mac, 3);
    history.reverse();
    let state = DeviceDetailState {
        mac: Some(mac.to_string()),
        device: Some(Device::new(mac)),
        history,
        history_error: None,
    };
    let series = state.packet_series();
    assert_eq!(series, vec![100, 200, 300], "should be ascending by date");
}

#[test]
fn test_device_detail_state_clear_resets() {
    let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
    let mut state = DeviceDetailState {
        mac: Some(mac.to_string()),
        device: Some(Device::new(mac)),
        history: sample_history(mac, 2),
        history_error: Some("err".into()),
    };
    state.clear();
    assert!(state.mac.is_none());
    assert!(state.device.is_none());
    assert!(state.history.is_empty());
    assert!(state.history_error.is_none());
}
