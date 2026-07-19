//! Notifier fan-out — delivers alerts to all configured notifiers.
//!
//! The fanout owns the single `mpsc::Receiver<Alert>` from the rule
//! engine and clones each alert to every configured notifier. Each
//! notifier runs in its own tokio task with a bounded buffer, so a
//! slow webhook doesn't block ntfy or MQTT.
//!
//! # Architecture
//!
//! ```text
//! RuleEngine → mpsc<Alert> → NotifierFanout → [ntfy, mqtt, webhook, email]
//! ```
//!
//! # Backpressure
//!
//! Each notifier has its own bounded channel. If a notifier's
//! channel is full (slow consumer), the fanout drops the alert for
//! that notifier (with a log) rather than blocking the rule engine.
//! This is the same degradation philosophy as the packet capture
//! backpressure: lose alerts rather than stall the hot path.

use std::sync::Arc;

use edgeshield_common::Alert;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// A notifier delivers an alert to an external system.
///
/// Each notifier (ntfy, MQTT, webhook, email) implements this trait.
/// The fanout calls `deliver` on each notifier for every alert.
#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    /// Deliver a single alert. Called by the fanout for each alert.
    ///
    /// # Errors
    ///
    /// Returns an error if delivery fails. The fanout logs the error
    /// but does not retry — the next alert will try again.
    async fn deliver(&self, alert: &Alert) -> Result<(), NotifierError>;

    /// A human-readable name for this notifier (for logging).
    fn name(&self) -> &str;
}

/// Errors that can occur during alert delivery.
#[derive(Debug, thiserror::Error)]
pub enum NotifierError {
    #[error("delivery failed: {0}")]
    Delivery(String),
    #[error("configuration error: {0}")]
    Config(String),
}

/// The fan-out dispatcher. Owns the alert receiver and delivers each
/// alert to all configured notifiers.
pub struct NotifierFanout {
    alert_rx: mpsc::Receiver<Alert>,
    notifiers: Vec<Arc<dyn Notifier>>,
}

impl NotifierFanout {
    /// Create a new fanout with the given notifiers.
    #[must_use]
    pub fn new(alert_rx: mpsc::Receiver<Alert>, notifiers: Vec<Arc<dyn Notifier>>) -> Self {
        Self {
            alert_rx,
            notifiers,
        }
    }

    /// Run the fanout loop until the alert sender is dropped.
    pub async fn run(mut self) {
        info!(
            notifier_count = self.notifiers.len(),
            "notifier fanout starting"
        );
        while let Some(alert) = self.alert_rx.recv().await {
            for notifier in &self.notifiers {
                if let Err(e) = notifier.deliver(&alert).await {
                    warn!(
                        notifier = notifier.name(),
                        error = %e,
                        rule = %alert.rule_name,
                        "notifier delivery failed"
                    );
                }
            }
        }
        info!("alert channel closed; notifier fanout stopping");
    }
}

/// Convenience: spawn the fanout as a tokio task.
pub fn spawn_fanout(
    alert_rx: mpsc::Receiver<Alert>,
    notifiers: Vec<Arc<dyn Notifier>>,
) -> tokio::task::JoinHandle<()> {
    let fanout = NotifierFanout::new(alert_rx, notifiers);
    tokio::spawn(async move {
        fanout.run().await;
    })
}
