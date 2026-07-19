# Logging

## Philosophy

EdgeShield treats logging as structured data, not human-readable text. Every log event is a JSON object with typed fields that can be ingested, filtered, and analyzed by log management systems (ELK, Loki, Datadog, etc.).

We use the `tracing` framework because it provides:

- **Structured fields**: Log events carry typed key-value pairs, not formatted strings
- **Spans**: Hierarchical context that groups related events (e.g., all processing for a single packet)
- **Layers**: Composable processing pipelines for filtering, formatting, and exporting
- **Zero-cost spans**: Spans that are disabled at the log level have zero runtime overhead

## Log Levels

| Level | Usage | Example |
|-------|-------|---------|
| `ERROR` | Unrecoverable errors, subsystem failures | `failed to open capture interface` |
| `WARN` | Recoverable errors, unexpected conditions | `capture error: channel full` |
| `INFO` | Lifecycle events | `EdgeShield starting`, `new device discovered` |
| `DEBUG` | Detailed subsystem state | `configuration loaded`, `API request received` |
| `TRACE` | Per-packet events | `packet decoded`, `classified as TCP` |

### Level selection guidelines

- **ERROR**: Something is broken and requires operator intervention. The system may be degraded.
- **WARN**: Something unexpected happened but the system recovered. No operator action required.
- **INFO**: Normal lifecycle events that an operator would want to see during normal operation.
- **DEBUG**: Detailed information useful for diagnosing issues. Not emitted in production by default.
- **TRACE**: Per-packet or per-request events. Very high volume. Only enabled during active debugging.

## Structured Logging

### Field conventions

All structured fields use `snake_case` keys. Values are typed (strings, numbers, booleans, objects).

```rust
// Good: structured fields
info!(
    mac = %device.mac,
    protocol = %protocol,
    packet_count = device.packet_count,
    "device updated"
);

// Bad: string interpolation
info!("device updated: {} protocol={}", device.mac, protocol);
```

### Standard fields

Every log event includes:

| Field | Description | Always Present |
|-------|-------------|----------------|
| `timestamp` | ISO 8601 UTC timestamp | ✅ |
| `level` | Log level (uppercase) | ✅ |
| `message` | Human-readable event description | ✅ |
| `target` | Rust module path | ✅ |
| `file` | Source file path | ✅ |
| `line` | Source line number | ✅ |
| `span` | Active span name and fields | When inside a span |

### Domain-specific fields

| Event | Fields |
|-------|--------|
| Packet decoded | `ethertype`, `has_ip`, `has_transport` |
| Packet classified | `protocol`, `src_port`, `dst_port` |
| Device discovered | `mac`, `protocol` |
| Device updated | `mac`, `protocol`, `packet_count` |
| API request | `method`, `path`, `status`, `duration_ms` |
| Capture started | `interface` |
| Capture error | `error` |

## Log Format

### JSON format (default)

```json
{
    "timestamp": "2026-07-18T12:00:00.000Z",
    "level": "INFO",
    "fields": {
        "message": "new device discovered",
        "mac": "00:11:22:33:44:55",
        "protocol": "TCP"
    },
    "target": "edgeshield_discovery::discovery",
    "span": {
        "name": "process-packet"
    },
    "file": "crates/discovery/src/discovery.rs",
    "line": 126
}
```

### Pretty format (development)

For development, the pretty formatter provides human-readable output:

```
2026-07-18T12:00:00.000Z  INFO edgeshield_daemon::daemon: EdgeShield starting interface=eth0
2026-07-18T12:00:01.000Z  INFO edgeshield_discovery::discovery: new device discovered mac=00:11:22:33:44:55 protocol=TCP
2026-07-18T12:00:02.000Z  INFO edgeshield_api::routes: api-list-devices
```

Enable pretty format with the `EDGESHIELD_LOG_FORMAT` environment variable:

```bash
EDGESHIELD_LOG_FORMAT=pretty edgeshield run
```

## Correlation IDs

Correlation IDs trace a single unit of work (a packet, an API request) through the system. They are implemented using `tracing` spans.

### Packet processing

Every packet processed by the pipeline is wrapped in a `process-packet` span. All log events within that span share the span context:

```json
{
    "timestamp": "2026-07-18T12:00:00.000Z",
    "level": "TRACE",
    "fields": { "message": "packet decoded" },
    "target": "edgeshield_packet::decode",
    "span": { "name": "process-packet" }
}
```

### API requests

Every API request is wrapped in a span named after the handler:

```json
{
    "timestamp": "2026-07-18T12:00:00.000Z",
    "level": "INFO",
    "fields": { "message": "api-list-devices" },
    "target": "edgeshield_api::routes",
    "span": { "name": "api-list-devices" }
}
```

## Log Output

All log output goes to **stderr**. This is a deliberate choice:

- stdout is reserved for program output (e.g., `edgeshield default-config`)
- stderr can be redirected independently of stdout
- stderr is the standard location for diagnostic output
- Log management systems typically collect stderr from systemd services

### systemd integration

When running under systemd, stderr is captured by journald:

```bash
journalctl -u edgeshield -f
```

### File logging (future)

Future versions will support logging to a file with log rotation:

```toml
[logging]
format = "json"
path = "/var/log/edgeshield/edgeshield.log"
max_size_mb = 100
max_files = 5
```

## Log Configuration

### Via config file

```toml
log_level = "info"
```

### Via environment variable

```bash
RUST_LOG=debug edgeshield run
```

### Per-module filtering

```bash
# Only debug logging for the packet crate
RUST_LOG=edgeshield_packet=debug edgeshield run

# Multiple modules
RUST_LOG=edgeshield_packet=debug,edgeshield_discovery=trace edgeshield run

# All modules except one
RUST_LOG=info,edgeshield_packet=debug edgeshield run
```

## Logging Best Practices

### Do

```rust
// Use structured fields
info!(mac = %device.mac, "device discovered");

// Use Display formatting with %
warn!(error = %e, "capture error");

// Use Debug formatting with ?
debug!(?config, "configuration loaded");

// Use spans for grouping
let span = span!(Level::INFO, "api-get-device", mac = %mac);
let _guard = span.enter();
```

### Don't

```rust
// Don't use string interpolation
info!("device discovered: {}", device.mac);

// Don't log sensitive data
info!("api key: {}", api_key);

// Don't log in the hot path at INFO level
info!("packet decoded");  // Use TRACE for per-packet events

// Don't use eprintln! for logging
eprintln!("error: {}", e);  // Use tracing::error!
```

## Metrics

In addition to structured logging, EdgeShield exposes aggregate metrics via the `/metrics` endpoint. These are computed from the device store, not from log events.

| Metric | Source | Description |
|--------|--------|-------------|
| `total_devices` | Device store count | Number of unique MAC addresses |
| `total_packets` | Sum of device packet counts | Total packets observed |
| `total_bytes` | Sum of device byte counters | Total bytes transferred |
| `uptime_seconds` | Server start time | API server uptime |

Future versions will add:

- Per-protocol packet counts
- Per-device traffic rates (bytes/second)
- Channel drop rate (backpressure events)
- API request rate and latency
