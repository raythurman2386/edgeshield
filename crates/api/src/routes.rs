//! Route handlers for the EdgeShield REST API.
//!
//! Each handler is a separate function for testability. They receive
//! the shared `AppState` via Axum's state extraction.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{Level, span};

use edgeshield_common::{Alert, AlertFilter, Device};

use crate::api::AppState;

/// Response for the health check endpoint.
#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    status: String,
    version: String,
}

/// Response for the metrics endpoint.
#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    total_devices: usize,
    total_packets: u64,
    total_bytes: u64,
    uptime_seconds: u64,
}

/// Lazy initialization of the server start time for uptime calculation.
fn server_start() -> Instant {
    static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    *START
}

/// GET /health
///
/// Simple health check. Returns 200 OK with status and version.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// GET /devices
///
/// Returns the full device inventory.
pub async fn list_devices(
    State(state): State<AppState>,
) -> Result<Json<Vec<Device>>, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-list-devices");
    let _guard = span.enter();

    match state.store.list() {
        Ok(devices) => Ok(Json(devices)),
        Err(e) => {
            tracing::error!(error = %e, "failed to list devices");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to list devices".to_string(),
            ))
        }
    }
}

/// GET /devices/{mac}
///
/// Returns a single device by MAC address.
pub async fn get_device(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<Device>, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-get-device", mac = %mac);
    let _guard = span.enter();

    let mac_orig = mac.clone();
    let mac_clean = mac.replace(':', "");
    let bytes: [u8; 6] = hex::decode(&mac_clean)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid MAC address: {mac_orig}"),
            )
        })?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid MAC address length: {mac_orig}"),
            )
        })?;
    let mac = MacAddress::new(bytes);

    match state.store.get(&mac) {
        Ok(Some(device)) => Ok(Json(device)),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("device not found: {mac}"))),
        Err(e) => {
            tracing::error!(error = %e, "failed to get device");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to get device".to_string(),
            ))
        }
    }
}

/// GET /metrics
///
/// Returns aggregate metrics about the network in JSON format.
pub async fn metrics(
    State(state): State<AppState>,
) -> Result<Json<MetricsResponse>, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-metrics");
    let _guard = span.enter();

    let devices = state.store.list().map_err(|e| {
        tracing::error!(error = %e, "failed to list devices for metrics");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to compute metrics".to_string(),
        )
    })?;

    let total_devices = devices.len();
    let total_packets: u64 = devices.iter().map(|d| d.packet_count).sum();
    let total_bytes: u64 = devices
        .iter()
        .map(|d| d.bytes_sent + d.bytes_received)
        .sum();
    let uptime_seconds = server_start().elapsed().as_secs();

    Ok(Json(MetricsResponse {
        total_devices,
        total_packets,
        total_bytes,
        uptime_seconds,
    }))
}

/// GET /metrics/prometheus
///
/// Returns metrics in Prometheus text exposition format. This is the
/// format Prometheus scrapers expect (unlike the JSON `/metrics`
/// endpoint, which is for human/programmatic consumption).
///
/// Exposed metrics:
/// - `edgeshield_devices_total` — total number of discovered devices
/// - `edgeshield_packets_total` — total packets observed
/// - `edgeshield_bytes_total` — total bytes observed
/// - `edgeshield_uptime_seconds` — daemon uptime in seconds
/// - `edgeshield_alerts_total` — total alerts in the alert store
pub async fn metrics_prometheus(
    State(state): State<AppState>,
) -> Result<String, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-metrics-prometheus");
    let _guard = span.enter();

    let devices = state.store.list().map_err(|e| {
        tracing::error!(error = %e, "failed to list devices for prometheus metrics");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to compute metrics".to_string(),
        )
    })?;

    let total_devices = devices.len();
    let total_packets: u64 = devices.iter().map(|d| d.packet_count).sum();
    let total_bytes: u64 = devices
        .iter()
        .map(|d| d.bytes_sent + d.bytes_received)
        .sum();
    let uptime_seconds = server_start().elapsed().as_secs();
    let total_alerts = state.alert_store.count_alerts().unwrap_or(0);

    // Prometheus text exposition format (v0.0.4).
    // Each metric has a HELP line (description) and TYPE line (counter/gauge).
    let body = format!(
        "# HELP edgeshield_devices_total Total number of discovered devices.\n\
         # TYPE edgeshield_devices_total gauge\n\
         edgeshield_devices_total {total_devices}\n\
         # HELP edgeshield_packets_total Total packets observed across all devices.\n\
         # TYPE edgeshield_packets_total counter\n\
         edgeshield_packets_total {total_packets}\n\
         # HELP edgeshield_bytes_total Total bytes observed across all devices.\n\
         # TYPE edgeshield_bytes_total counter\n\
         edgeshield_bytes_total {total_bytes}\n\
         # HELP edgeshield_uptime_seconds Daemon uptime in seconds.\n\
         # TYPE edgeshield_uptime_seconds gauge\n\
         edgeshield_uptime_seconds {uptime_seconds}\n\
         # HELP edgeshield_alerts_total Total alerts in the alert store.\n\
         # TYPE edgeshield_alerts_total gauge\n\
         edgeshield_alerts_total {total_alerts}\n"
    );

    Ok(body)
}

/// GET /alerts
///
/// Returns the alert history, optionally filtered. Query params:
/// - `severity` — filter by severity (info, warning, critical)
/// - `acknowledged` — filter by acknowledged status (true, false)
/// - `rule` — filter by rule name
/// - `limit` — maximum number of alerts to return
pub async fn list_alerts(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<Alert>>, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-list-alerts");
    let _guard = span.enter();

    let mut filter = AlertFilter::default();
    if let Some(sev) = params.get("severity") {
        filter.severity = std::str::FromStr::from_str(sev).ok();
    }
    if let Some(ack) = params.get("acknowledged") {
        filter.acknowledged = match ack.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
    }
    if let Some(rule) = params.get("rule") {
        filter.rule_name = Some(rule.clone());
    }
    if let Some(limit) = params.get("limit") {
        filter.limit = limit.parse().ok();
    }

    match state.alert_store.list_alerts(filter) {
        Ok(alerts) => Ok(Json(alerts)),
        Err(e) => {
            tracing::error!(error = %e, "failed to list alerts");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to list alerts".to_string(),
            ))
        }
    }
}

/// GET /alerts/{id}
///
/// Returns a single alert by ID.
pub async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Alert>, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-get-alert", id = %id);
    let _guard = span.enter();

    let id: u64 = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid alert id: {id}")))?;

    match state.alert_store.get_alert(id) {
        Ok(Some(alert)) => Ok(Json(alert)),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("alert not found: {id}"))),
        Err(e) => {
            tracing::error!(error = %e, "failed to get alert");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to get alert".to_string(),
            ))
        }
    }
}

/// POST /alerts/{id}/acknowledge
///
/// Marks an alert as acknowledged. Acknowledged alerts suppress future
/// alerts for the same device/rule combination.
pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-ack-alert", id = %id);
    let _guard = span.enter();

    let id: u64 = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid alert id: {id}")))?;

    match state.alert_store.acknowledge_alert(id) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!(error = %e, "failed to acknowledge alert");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to acknowledge alert".to_string(),
            ))
        }
    }
}

/// DELETE /alerts/{id}
///
/// Deletes an alert by ID.
pub async fn delete_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let span = span!(Level::INFO, "api-delete-alert", id = %id);
    let _guard = span.enter();

    let id: u64 = id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid alert id: {id}")))?;

    match state.alert_store.delete_alert(id) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!(error = %e, "failed to delete alert");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to delete alert".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Method, Request},
        routing::get,
    };
    use edgeshield_common::AlertStore;
    use edgeshield_storage::memory::MemoryStore;
    use edgeshield_storage::store::DeviceStore;
    use std::str::FromStr;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let store = Arc::new(MemoryStore::new()) as Arc<dyn DeviceStore>;
        let alert_store =
            Arc::new(edgeshield_rules::store::InMemoryAlertStore::new()) as Arc<dyn AlertStore>;

        // Add a test device
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.record_sent(100, edgeshield_common::Protocol::Tcp);
        device.add_ip("192.168.1.10".parse().unwrap());
        store.upsert(device).unwrap();

        let state = AppState { store, alert_store };

        Router::new()
            .route("/health", get(health))
            .route("/devices", get(list_devices))
            .route("/devices/:mac", get(get_device))
            .route("/metrics", get(metrics))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body: HealthResponse = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body.status, "ok");
    }

    #[tokio::test]
    async fn test_list_devices_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let devices: Vec<Device> = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].mac,
            MacAddress::from_str("00:11:22:33:44:55").unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_device_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/devices/00:11:22:33:44:55")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let device: Device = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            device.mac,
            MacAddress::from_str("00:11:22:33:44:55").unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_device_not_found() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/devices/00:11:22:33:44:66")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_device_invalid_mac() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/devices/not-a-mac")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let metrics: MetricsResponse = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metrics.total_devices, 1);
        assert!(metrics.total_packets > 0);
    }
}
