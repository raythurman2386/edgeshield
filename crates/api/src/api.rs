//! REST API for EdgeShield.
//!
//! This module provides the Axum-based HTTP server that exposes
//! device inventory, health checks, and metrics.

use std::sync::Arc;

use axum::Router;
use tokio::sync::mpsc;
use tracing::info;

use edgeshield_discovery::discovery::DiscoveryEvent;
use edgeshield_storage::store::DeviceStore;

use crate::routes;

/// The shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    /// The device store (shared with the discovery engine).
    pub store: Arc<dyn DeviceStore>,
    /// Receiver for discovery events (for future WebSocket push).
    pub event_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<DiscoveryEvent>>>,
}

/// Start the REST API server.
///
/// # Arguments
///
/// * `port` - The port to listen on
/// * `store` - The shared device store
/// * `event_rx` - Receiver for discovery events
///
/// # Design
///
/// The API server runs on a separate tokio task from the capture pipeline.
/// It shares the device store via `Arc<dyn DeviceStore>`, which is lock-free
/// for reads (DashMap). The event channel allows future WebSocket push
/// without changing the architecture.
pub async fn serve(
    port: u16,
    store: Arc<dyn DeviceStore>,
    event_rx: mpsc::Receiver<DiscoveryEvent>,
) -> Result<(), anyhow::Error> {
    let state = AppState {
        store,
        event_rx: Arc::new(tokio::sync::Mutex::new(event_rx)),
    };

    let app = Router::new()
        .route("/health", axum::routing::get(routes::health))
        .route("/devices", axum::routing::get(routes::list_devices))
        .route("/devices/:mac", axum::routing::get(routes::get_device))
        .route("/metrics", axum::routing::get(routes::metrics))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!(addr = %addr, "starting API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
