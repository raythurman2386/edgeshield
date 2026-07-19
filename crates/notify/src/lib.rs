//! Notification delivery for EdgeShield.
//!
//! This crate consumes `DiscoveryEvent`s from the discovery pipeline
//! and delivers them to external systems. The first (and currently
//! only) delivery target is MQTT, chosen because it is the native
//! protocol of every homelab automation stack (Home Assistant,
//! Node-RED, n8n, etc.).
//!
//! # Design
//!
//! The notifier is a single async task that owns the `mpsc::Receiver`
//! for `DiscoveryEvent`s. It connects to the MQTT broker on startup
//! and publishes each event as a JSON message. If the broker is
//! unreachable, the notifier logs and drops events — it never blocks
//! the capture pipeline. This is the same degradation philosophy as
//! the packet capture backpressure: lose alerts rather than stall
//! the hot path.
//!
//! # Why a separate crate
//!
//! Notification is an *outbound* concern. Keeping it isolated from
//! the API (inbound) and the discovery engine (core logic) means we
//! can add webhook, email, or Slack delivery later without touching
//! the data plane. The dependency direction is:
//!
//! ```text
//! notify → common, config, discovery
//! ```
//!
//! `notify` never depends on `api`, `packet`, or `daemon`.

pub mod email;
pub mod fanout;
pub mod mqtt;
pub mod ntfy;
pub mod webhook;

pub use email::EmailNotifier;
pub use fanout::{Notifier, NotifierError, NotifierFanout};
pub use mqtt::MqttNotifier;
pub use ntfy::NtfyNotifier;
pub use webhook::WebhookNotifier;
