//! REST API for EdgeShield.
//!
//! This module provides the Axum-based HTTP server that exposes
//! device inventory, health checks, metrics, and alert history.

use std::sync::Arc;

use axum::Router;
use tracing::info;

use edgeshield_common::{AlertStore, DeviceHistoryStore};
use edgeshield_storage::store::DeviceStore;

use crate::routes;

/// The shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    /// The device store (shared with the discovery engine).
    pub store: Arc<dyn DeviceStore>,
    /// The alert store (shared with the rule engine).
    pub alert_store: Arc<dyn AlertStore>,
    /// The device history store (shared with the snapshot task).
    /// `None` when history is disabled (in-memory mode or
    /// `history_snapshot_hours = 0`).
    pub history_store: Option<Arc<dyn DeviceHistoryStore>>,
}

/// Start the REST API server.
pub async fn serve(
    port: u16,
    store: Arc<dyn DeviceStore>,
    alert_store: Arc<dyn AlertStore>,
    history_store: Option<Arc<dyn DeviceHistoryStore>>,
) -> Result<(), anyhow::Error> {
    let state = AppState {
        store,
        alert_store,
        history_store,
    };

    let app = Router::new()
        .route("/health", axum::routing::get(routes::health))
        .route("/devices", axum::routing::get(routes::list_devices))
        .route("/devices/:mac", axum::routing::get(routes::get_device))
        .route(
            "/devices/:mac/history",
            axum::routing::get(routes::get_device_history),
        )
        .route("/metrics", axum::routing::get(routes::metrics))
        .route(
            "/metrics/prometheus",
            axum::routing::get(routes::metrics_prometheus),
        )
        .route("/alerts", axum::routing::get(routes::list_alerts))
        .route("/alerts/:id", axum::routing::get(routes::get_alert))
        .route(
            "/alerts/:id/acknowledge",
            axum::routing::post(routes::acknowledge_alert),
        )
        .route("/alerts/:id", axum::routing::delete(routes::delete_alert))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    info!(addr = %addr, "starting API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
