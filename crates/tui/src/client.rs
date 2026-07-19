//! Thin HTTP client over the EdgeShield REST API.
//!
//! The client is the **only** component that talks to the daemon. It
//! exposes one method per REST endpoint the TUI consumes, plus a
//! [`Client::snapshot`] convenience that fetches all of them in
//! parallel for a single poll tick.
//!
//! # Auth
//!
//! When an API key is configured (`--key` or `EDGESHIELD_KEY`), it is
//! sent as `Authorization: Bearer <key>` on every request, matching
//! `crates/api/src/auth.rs`. The daemon enforces read vs admin
//! permissions; the TUI only needs admin for the ack action.
//!
//! # Errors
//!
//! Network and parse errors are returned as [`ClientError`] and never
//! panic. The poller converts them into a `Snapshot` with `last_error`
//! set so the render loop can keep running.

use std::time::Duration;

use reqwest::{Client as HttpClient, StatusCode};
use serde::{Deserialize, Serialize};

use edgeshield_common::{Alert, Device, DeviceHistorySnapshot};

use crate::snapshot::{HealthSnapshot, Snapshot};

/// Errors produced by the API client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("client build error: {0}")]
    Build(String),
    #[error("unexpected status {status} from {url}: {body}")]
    Status {
        url: String,
        status: StatusCode,
        body: String,
    },
    #[error("invalid response body from {url}: {source}")]
    Decode {
        url: String,
        #[source]
        source: serde_json::Error,
    },
}

/// `GET /metrics` response shape (mirrors `crates/api/src/routes.rs`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsResponse {
    pub total_devices: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub uptime_seconds: u64,
}

/// `GET /health` response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// A read-only client for the EdgeShield REST API.
#[derive(Clone, Debug)]
pub struct Client {
    pub(crate) base: String,
    pub(crate) http: HttpClient,
}

impl Client {
    /// Create a new client.
    ///
    /// `base` is the daemon URL (e.g. `http://localhost:8080`). A
    /// trailing slash is stripped. `key`, if present, is sent as a
    /// Bearer token on every request.
    pub fn new(base: &str, key: Option<&str>) -> Result<Self, ClientError> {
        let base = base.trim_end_matches('/').to_string();
        let mut builder = HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2));
        if let Some(k) = key {
            let mut headers = reqwest::header::HeaderMap::new();
            let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {k}"))
                .map_err(|e| ClientError::Build(e.to_string()))?;
            headers.insert(reqwest::header::AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
        Ok(Self {
            base,
            http: builder.build()?,
        })
    }

    /// `GET /health`
    pub async fn health(&self) -> Result<HealthSnapshot, ClientError> {
        let url = format!("{}/health", self.base);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status { url, status, body });
        }
        let body = resp.text().await?;
        let parsed: HealthResponse =
            serde_json::from_str(&body).map_err(|e| ClientError::Decode { url, source: e })?;
        Ok(HealthSnapshot {
            status: parsed.status,
            version: parsed.version,
        })
    }

    /// `GET /devices`
    pub async fn devices(&self) -> Result<Vec<Device>, ClientError> {
        let url = format!("{}/devices", self.base);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status { url, status, body });
        }
        let body = resp.text().await?;
        serde_json::from_str(&body).map_err(|e| ClientError::Decode { url, source: e })
    }

    /// `GET /alerts`
    pub async fn alerts(&self) -> Result<Vec<Alert>, ClientError> {
        let url = format!("{}/alerts", self.base);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status { url, status, body });
        }
        let body = resp.text().await?;
        serde_json::from_str(&body).map_err(|e| ClientError::Decode { url, source: e })
    }

    /// `GET /metrics`
    pub async fn metrics(&self) -> Result<MetricsResponse, ClientError> {
        let url = format!("{}/metrics", self.base);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status { url, status, body });
        }
        let body = resp.text().await?;
        serde_json::from_str(&body).map_err(|e| ClientError::Decode { url, source: e })
    }

    /// `GET /devices/:mac/history`
    ///
    /// Returns daily snapshots for a device. Returns an empty `Vec` if
    /// history is disabled on the daemon (HTTP 501 is treated as
    /// "no history available" rather than an error, since the TUI
    /// should still render the detail view with current state only).
    pub async fn device_history(
        &self,
        mac: &str,
    ) -> Result<Vec<DeviceHistorySnapshot>, ClientError> {
        let url = format!("{}/devices/{mac}/history", self.base);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        // 501 = history disabled on the daemon — render empty, not an error.
        if status == StatusCode::NOT_IMPLEMENTED {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status { url, status, body });
        }
        let body = resp.text().await?;
        serde_json::from_str(&body).map_err(|e| ClientError::Decode { url, source: e })
    }

    /// `POST /alerts/{id}/acknowledge`
    ///
    /// This is the **only** mutation the TUI performs. Returns `Ok(())`
    /// on HTTP 204 (the daemon's success response).
    pub async fn acknowledge_alert(&self, id: u64) -> Result<(), ClientError> {
        let url = format!("{}/alerts/{id}/acknowledge", self.base);
        let resp = self.http.post(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status { url, status, body });
        }
        Ok(())
    }

    /// Fetch all read endpoints in parallel and assemble a [`Snapshot`].
    ///
    /// On any per-endpoint failure, the corresponding field is `None`
    /// and `last_error` records the first error encountered. The
    /// health fetch is attempted first so reachability is reported
    /// accurately even when the other endpoints fail.
    pub async fn snapshot(&self) -> Snapshot {
        let (health, devices, alerts, metrics) =
            tokio::join!(self.health(), self.devices(), self.alerts(), self.metrics(),);
        let mut last_error: Option<String> = None;
        let health = match health {
            Ok(h) => Some(h),
            Err(e) => {
                last_error = Some(e.to_string());
                None
            }
        };
        let devices = match devices {
            Ok(d) => Some(d),
            Err(e) => {
                if last_error.is_none() {
                    last_error = Some(e.to_string());
                }
                None
            }
        };
        let alerts = match alerts {
            Ok(a) => Some(a),
            Err(e) => {
                if last_error.is_none() {
                    last_error = Some(e.to_string());
                }
                None
            }
        };
        let metrics = match metrics {
            Ok(m) => Some(m),
            Err(e) => {
                if last_error.is_none() {
                    last_error = Some(e.to_string());
                }
                None
            }
        };
        Snapshot {
            fetched_at: Some(std::time::Instant::now()),
            health,
            devices,
            alerts,
            metrics,
            last_error,
        }
    }
}
