//! Tests for the API client.
//!
//! These tests run against an in-process axum server that mirrors the
//! daemon's REST endpoints. They verify the client's happy paths and
//! error handling without requiring a live daemon.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use edgeshield_common::{Alert, AlertEventType, Device, DeviceHistorySnapshot, Severity};
use edgeshield_tui::client::{Client, ClientError, MetricsResponse};
use mac_address::MacAddress;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpListener;

/// A minimal mock of the daemon's REST API.
async fn mock_app(ack_calls: std::sync::Arc<std::sync::atomic::AtomicU32>) -> Router {
    let ack_calls = std::sync::Arc::clone(&ack_calls);
    Router::new()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({
                    "status": "ok",
                    "version": "0.1.0",
                }))
            }),
        )
        .route(
            "/devices",
            get(|| async {
                let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
                let device = Device::new(mac);
                Json(vec![device])
            }),
        )
        .route(
            "/alerts",
            get(|| async {
                let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
                let alert = Alert::new(
                    "test-rule".into(),
                    Severity::Warning,
                    AlertEventType::NewDevice,
                    Device::new(mac),
                    "a new device appeared".into(),
                );
                Json(vec![alert])
            }),
        )
        .route(
            "/metrics",
            get(|| async {
                Json(MetricsResponse {
                    total_devices: 1,
                    total_packets: 100,
                    total_bytes: 10_000,
                    uptime_seconds: 42,
                })
            }),
        )
        .route(
            "/alerts/:id/acknowledge",
            post(move |Path(id): Path<u64>| async move {
                ack_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(id, 7);
                StatusCode::NO_CONTENT
            }),
        )
        .route(
            "/devices/:mac/history",
            get(|| async { Json(Vec::<DeviceHistorySnapshot>::new()) }),
        )
}

/// Bind a mock server to an ephemeral port and return its base URL.
async fn spawn_mock() -> (String, std::sync::Arc<std::sync::atomic::AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let ack_calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let app = mock_app(std::sync::Arc::clone(&ack_calls)).await;
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), ack_calls)
}

#[tokio::test]
async fn test_client_health_ok() {
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    let health = client.health().await.unwrap();
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, "0.1.0");
}

#[tokio::test]
async fn test_client_devices_ok() {
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    let devices = client.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        devices[0].mac,
        MacAddress::from_str("00:11:22:33:44:55").unwrap()
    );
}

#[tokio::test]
async fn test_client_alerts_ok() {
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    let alerts = client.alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_name, "test-rule");
    assert_eq!(alerts[0].severity, Severity::Warning);
}

#[tokio::test]
async fn test_client_metrics_ok() {
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    let metrics = client.metrics().await.unwrap();
    assert_eq!(metrics.total_devices, 1);
    assert_eq!(metrics.total_packets, 100);
    assert_eq!(metrics.uptime_seconds, 42);
}

#[tokio::test]
async fn test_client_acknowledge_ok() {
    let (url, ack_calls) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    client.acknowledge_alert(7).await.unwrap();
    assert_eq!(
        ack_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "ack endpoint should be called exactly once"
    );
}

#[tokio::test]
async fn test_client_snapshot_aggregates_all() {
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    let snap = client.snapshot().await;
    assert!(snap.is_reachable(), "health should be reachable");
    assert_eq!(snap.device_count(), 1);
    assert_eq!(snap.alert_count(), 1);
    assert!(snap.metrics.is_some());
    assert!(snap.last_error.is_none(), "no errors on a healthy mock");
}

#[tokio::test]
async fn test_client_network_error_unreachable() {
    // Bind and immediately drop to get a port nothing listens on.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{addr}");
    let client = Client::new(&url, None).unwrap();
    let err = client.health().await.unwrap_err();
    assert!(matches!(err, ClientError::Network(_)), "got {err:?}");
}

#[tokio::test]
async fn test_client_snapshot_records_error_on_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{addr}");
    let client = Client::new(&url, None).unwrap();
    let snap = client.snapshot().await;
    assert!(!snap.is_reachable());
    assert!(snap.last_error.is_some(), "error should be recorded");
    assert_eq!(snap.device_count(), 0);
}

#[tokio::test]
async fn test_client_strips_trailing_slash() {
    let (url, _) = spawn_mock().await;
    let url_with_slash = format!("{url}/");
    let client = Client::new(&url_with_slash, None).unwrap();
    // If the slash weren't stripped, /health would become //health and 404.
    let health = client.health().await.unwrap();
    assert_eq!(health.status, "ok");
}

#[tokio::test]
async fn test_client_with_bearer_token_header() {
    // The mock ignores auth, but this verifies the client builds with a
    // key and sends requests without error.
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, Some("secret-key")).unwrap();
    let health = client.health().await.unwrap();
    assert_eq!(health.status, "ok");
}

#[tokio::test]
async fn test_client_device_history_ok() {
    let (url, _) = spawn_mock().await;
    let client = Client::new(&url, None).unwrap();
    // The mock returns an empty Vec; we just verify it parses.
    let history = client.device_history("00:11:22:33:44:55").await.unwrap();
    assert!(history.is_empty());
}

#[tokio::test]
async fn test_client_device_history_501_treated_as_empty() {
    // A server that returns 501 (history disabled) should yield an
    // empty Vec, not an error.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/devices/:mac/history",
        get(|| async { StatusCode::NOT_IMPLEMENTED }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("http://{addr}");
    let client = Client::new(&url, None).unwrap();
    let history = client.device_history("00:11:22:33:44:55").await.unwrap();
    assert!(history.is_empty(), "501 should be treated as no history");
}

#[tokio::test]
async fn test_client_invalid_key_returns_build_error() {
    // A newline is invalid in an HTTP header value.
    let err = Client::new("http://localhost:8080", Some("bad\nkey")).unwrap_err();
    assert!(matches!(err, ClientError::Build(_)), "got {err:?}");
}
