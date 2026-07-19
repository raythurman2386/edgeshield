//! REST API for EdgeShield.
//!
//! This module provides the Axum-based HTTP server that exposes
//! device inventory, health checks, metrics, and alert history. It
//! supports optional Bearer token authentication, TLS, and audit
//! logging.

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use tracing::{info, warn};

use edgeshield_common::{AlertStore, DeviceHistoryStore};
use edgeshield_config::config::{ApiTlsConfig, Config};
use edgeshield_storage::store::DeviceStore;

use crate::audit::AuditLogger;
use crate::auth::AuthState;
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
    /// Authentication state. When auth is disabled, all requests pass.
    pub auth: AuthState,
    /// Audit logger. `None` when audit logging is disabled.
    pub audit_logger: Option<Arc<AuditLogger>>,
}

/// Start the REST API server.
///
/// # Arguments
///
/// * `config` - The full daemon config (used for bind address, port,
///   auth, TLS, and audit settings).
/// * `store` - The shared device store.
/// * `alert_store` - The shared alert store.
/// * `history_store` - The shared history store (optional).
pub async fn serve(
    config: &Config,
    store: Arc<dyn DeviceStore>,
    alert_store: Arc<dyn AlertStore>,
    history_store: Option<Arc<dyn DeviceHistoryStore>>,
) -> Result<(), anyhow::Error> {
    // Build auth state from config.
    let auth = AuthState::new(config.api.auth.as_ref());

    // Build audit logger if configured.
    let audit_logger = if let Some(ref audit_cfg) = config.api.audit {
        match AuditLogger::new(&audit_cfg.log_path).await {
            Ok(logger) => Some(Arc::new(logger)),
            Err(e) => {
                warn!(error = %e, "failed to open audit log; audit logging disabled");
                None
            }
        }
    } else {
        None
    };

    // Security warnings at startup.
    emit_security_warnings(config, &auth);

    let state = AppState {
        store,
        alert_store,
        history_store,
        auth,
        audit_logger,
    };

    // Build the router. `/health` is always open (no auth, no audit).
    // All other routes go through the auth + audit middleware.
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
        .with_state(state.clone())
        .layer(from_fn_with_state(
            state.auth.clone(),
            crate::auth::auth_middleware,
        ))
        .layer(from_fn_with_state(
            state.audit_logger.clone(),
            crate::audit::audit_middleware,
        ));

    let addr = format!("{}:{}", config.api_bind_address, config.api_port);
    info!(addr = %addr, "starting API server");

    // Start with TLS if configured, otherwise plain HTTP.
    if let Some(ref tls) = config.api.tls {
        serve_tls(addr, tls, app).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}

/// Start the API server with TLS using `axum-server` + `rustls`.
async fn serve_tls(addr: String, tls: &ApiTlsConfig, app: Router) -> Result<(), anyhow::Error> {
    use axum_server::tls_rustls::RustlsConfig;

    // Load the certificate and key from PEM files.
    let cert = std::fs::read(&tls.cert_path).context("failed to read TLS certificate")?;
    let key = std::fs::read(&tls.key_path).context("failed to read TLS private key")?;

    let tls_config = RustlsConfig::from_pem(cert, key)
        .await
        .map_err(|e| anyhow::anyhow!("failed to build TLS config: {e}"))?;

    info!(addr = %addr, "API server starting with TLS");

    let bind_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{addr}': {e}"))?;

    axum_server::bind_rustls(bind_addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

/// Emit security warnings at startup for insecure configurations.
fn emit_security_warnings(config: &Config, auth: &AuthState) {
    let is_loopback =
        config.api_bind_address == "127.0.0.1" || config.api_bind_address == "localhost";

    if !auth.is_enabled() && !is_loopback {
        warn!(
            bind = %config.api_bind_address,
            "API is not authenticated and binds to a non-loopback address — \
             anyone on this network can access device inventory"
        );
    } else if !auth.is_enabled() && is_loopback {
        info!(
            "API is not authenticated but binds to 127.0.0.1 — \
             only local processes can access"
        );
    }

    if auth.is_enabled() && config.api.tls.is_none() {
        warn!(
            "API authentication is enabled but TLS is not — \
             API keys will be sent in cleartext over the network"
        );
    }
}

// Re-export anyhow's context for the TLS file reading.
use anyhow::Context;
