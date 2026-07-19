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
use edgeshield_notify::MqttNotifier;
use edgeshield_packet::capture::CaptureSession;
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

    // 3. Create the event channel
    let (event_tx, event_rx) = mpsc::channel::<DiscoveryEvent>(1024);

    // 4. Create the discovery engine
    let engine = Arc::new(DiscoveryEngine::new(store.clone(), event_tx));

    // 5. Start the notifier (if MQTT is configured)
    //
    // The notifier owns the event receiver. When MQTT is disabled,
    // event_rx is dropped and the discovery engine's try_send calls
    // silently fail — the pipeline is unaffected.
    let notifier_handle = if let Some(mqtt_config) = config.mqtt.clone() {
        let notifier = MqttNotifier::new(mqtt_config, event_rx);
        Some(tokio::spawn(async move {
            notifier.run().await;
        }))
    } else {
        info!("MQTT notifications disabled (no [mqtt] config)");
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
    if let Some(handle) = notifier_handle {
        // The notifier exits when event_tx is dropped, which happens when
        // the discovery engine (and its event_tx) is dropped below. We
        // abort rather than await because the notifier may be mid-publish
        // to a slow broker and we don't want to block shutdown.
        handle.abort();
    }

    info!("EdgeShield stopped");
    Ok(())
}
