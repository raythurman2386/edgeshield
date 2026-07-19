//! EdgeShield daemon — the main application orchestrator.
//!
//! This module wires together all subsystems: packet capture, protocol
//! classification, device discovery, storage, and the REST API.
//!
//! # Pipeline
//!
//! ```text
//! Capture Thread (blocking)
//!   │
//!   ▼  mpsc channel
//! Pipeline Task (async)
//!   │  decode → classify → update device table
//!   │
//!   ▼  mpsc channel
//! API Server (async, separate task)
//! ```
//!
//! # Concurrency
//!
//! - Capture runs on a dedicated OS thread (pcap is blocking)
//! - Pipeline processing runs on a tokio task
//! - API server runs on a separate tokio task
//! - Device store is shared via `Arc<dyn DeviceStore>` (DashMap = lock-free)
//! - Events flow through mpsc channels
//!
//! # Shutdown
//!
//! Handles both SIGINT (Ctrl+C) and SIGTERM (systemd stop, kill).
//! On receiving either signal, the capture session is stopped, the
//! pipeline is drained, and the API server shuts down.

use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, span, Level};

use edgeshield_api::api;
use edgeshield_config::config::Config;
use edgeshield_discovery::discovery::{DiscoveryEngine, DiscoveryEvent};
use edgeshield_notify::{Notifier, EmailNotifier, MqttNotifier, NtfyNotifier, WebhookNotifier};
use edgeshield_packet::capture::CaptureSession;
use edgeshield_rules::store::InMemoryAlertStore;
use edgeshield_rules::{Rule, RuleCondition, RuleEngine};
use edgeshield_storage::memory::MemoryStore;
use edgeshield_storage::sqlite::SqliteStore;
use edgeshield_storage::store::DeviceStore;
use edgeshield_telemetry::telemetry;

/// Run the EdgeShield daemon.
pub async fn run(config: Config) -> Result<(), anyhow::Error> {
    let span = span!(Level::INFO, "daemon", interface = %config.interface);
    let _guard = span.enter();

    // 1. Initialize telemetry
    telemetry::init(&config.log_level)?;
    info!("EdgeShield starting");

    // 2. Create the device store
    let store: Arc<dyn DeviceStore> = if config.database_path.is_empty() {
        info!("using in-memory device store");
        Arc::new(MemoryStore::new())
    } else {
        match SqliteStore::open(&config.database_path)? {
            Some(sqlite) => {
                info!(path = %config.database_path, "using SQLite device store");
                Arc::new(sqlite)
            }
            None => {
                info!("using in-memory device store (no database path)");
                Arc::new(MemoryStore::new())
            }
        }
    };

    // 3. Create the event channel (discovery → rule engine)
    let (event_tx, event_rx) = mpsc::channel::<DiscoveryEvent>(1024);

    // 4. Create the discovery engine
    let engine = Arc::new(DiscoveryEngine::new(store.clone(), event_tx));

    // 5. Build the rule set from config. If no rules are configured,
    // use a default `new_device` rule (preserving pre-Phase-5
    // behavior: every new MAC triggers an alert).
    let mut rules: Vec<Rule> = config
        .rules
        .iter()
        .filter_map(|rc| {
            match Rule::try_from(rc.clone()) {
                Ok(r) => Some(r),
                Err(e) => {
                    error!(rule = %rc.name, error = %e, "skipping invalid rule");
                    None
                }
            }
        })
        .collect();
    if rules.is_empty() {
        info!("no rules configured; using default new_device rule");
        rules.push(Rule::new(
            "new_device".to_string(),
            true,
            RuleCondition::NewDevice,
            edgeshield_common::Severity::Info,
            0,
        ));
    }

    // 6. Create the alert store (in-memory for now; SQLite alert
    // persistence is a follow-up).
    let alert_store = Arc::new(InMemoryAlertStore::new());

    // 7. Create the alert channel (rule engine → notifier fanout)
    let (alert_tx, alert_rx) = mpsc::channel::<edgeshield_common::Alert>(256);

    // 8. Start the rule engine (owns the discovery event receiver)
    let rule_engine = RuleEngine::new(
        rules,
        event_rx,
        alert_tx,
        alert_store.clone(),
    );
    let rule_engine_handle = tokio::spawn(async move {
        rule_engine.run().await;
    });

    // 9. Build the notifier list from config. All configured
    // notifiers receive every alert via the fanout.
    let mut notifiers: Vec<Arc<dyn Notifier>> = Vec::new();
    if let Some(ntfy_config) = config.ntfy.clone() {
        match NtfyNotifier::new(ntfy_config) {
            Ok(n) => {
                info!("ntfy notifier enabled");
                notifiers.push(Arc::new(n));
            }
            Err(e) => error!(error = %e, "failed to create ntfy notifier"),
        }
    }
    if let Some(mqtt_config) = config.mqtt.clone() {
        info!("MQTT notifier enabled");
        notifiers.push(Arc::new(MqttNotifier::new(mqtt_config)));
    }
    if let Some(webhook_config) = config.webhook.clone() {
        match WebhookNotifier::new(webhook_config) {
            Ok(n) => {
                info!("webhook notifier enabled");
                notifiers.push(Arc::new(n));
            }
            Err(e) => error!(error = %e, "failed to create webhook notifier"),
        }
    }
    if let Some(email_config) = config.email.clone() {
        match EmailNotifier::new(email_config) {
            Ok(n) => {
                info!("email notifier enabled");
                notifiers.push(Arc::new(n));
            }
            Err(e) => error!(error = %e, "failed to create email notifier"),
        }
    }

    // 10. Start the notifier fanout (owns the alert receiver)
    let fanout_handle = if notifiers.is_empty() {
        info!("no notifiers configured; alerts will only be persisted");
        // Drop alert_rx to avoid the rule engine blocking on send.
        drop(alert_rx);
        None
    } else {
        Some(edgeshield_notify::fanout::spawn_fanout(
            alert_rx,
            notifiers,
        ))
    };

    // 11. Start the offline scanner (if configured)
    let scanner_handle = if config.scanner.interval_seconds > 0 {
        let scanner_store = store.clone();
        let scanner_tx = engine.clone();
        let interval = config.scanner.interval_seconds;
        Some(tokio::spawn(async move {
            offline_scanner(scanner_store, scanner_tx, interval).await;
        }))
    } else {
        None
    };

    // 6. Start the API server
    let api_store = store.clone();
    let api_handle = tokio::spawn(async move {
        if let Err(e) = api::serve(config.api_port, api_store).await {
            error!(error = %e, "API server error");
        }
    });

    // 7. Start packet capture
    let mut capture = CaptureSession::start(&config.interface, config.capture_buffer)?;
    info!("packet capture started");

    // 8. Process packets in the pipeline
    // Extract the receiver before spawning so we can still call capture.stop() later.
    let (_, closed_rx) = mpsc::channel::<edgeshield_packet::capture::PacketBuf>(1);
    let mut pipeline_rx = std::mem::replace(&mut capture.rx, closed_rx);
    let pipeline_engine = engine.clone();
    let pipeline_handle = tokio::spawn(async move {
        while let Some(buf) = pipeline_rx.recv().await {
            pipeline_engine.process_packet(buf).await;
        }
        info!("pipeline task finished");
    });

    // 9. Wait for shutdown signal (SIGINT or SIGTERM)
    info!("EdgeShield running. Press Ctrl+C to stop.");

    // Set up SIGTERM handler (Unix only)
    let mut term_signal = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("SIGINT received");
        }
        _ = term_signal.recv() => {
            info!("SIGTERM received");
        }
    }

    // 10. Graceful shutdown
    info!("shutting down");
    capture.stop();
    pipeline_handle.await?;
    api_handle.abort();
    rule_engine_handle.abort();
    if let Some(handle) = fanout_handle {
        handle.abort();
    }
    if let Some(handle) = scanner_handle {
        handle.abort();
    }

    info!("EdgeShield stopped");
    Ok(())
}

/// Background scanner for device-offline detection.
///
/// Wakes every `interval_seconds`, lists all devices, and emits
/// `DeviceOffline` events for devices that have been silent for
/// longer than any `device_offline` rule's threshold. The rule
/// engine then evaluates these events against its rules.
async fn offline_scanner(
    store: Arc<dyn DeviceStore>,
    engine: Arc<DiscoveryEngine>,
    interval_seconds: u64,
) {
    use std::time::Duration;

    info!(interval_seconds, "offline scanner starting");
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
    // Skip the first (immediate) tick — we don't want to scan before
    // any devices have been seen.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let devices = match store.list() {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "scanner: failed to list devices");
                continue;
            }
        };
        let now = chrono::Utc::now();
        for device in devices {
            let last_seen = device.last_seen.inner();
            let silent_for = now.signed_duration_since(*last_seen);
            // Emit an offline event for any device silent for more
            // than 60 seconds. The rule engine's `device_offline`
            // rules have their own thresholds; the scanner just
            // provides the raw signal.
            if silent_for.num_seconds() > 60 {
                let _ = engine.emit_offline_event(device).await;
            }
        }
    }
}
