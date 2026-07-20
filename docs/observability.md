# Observability

EdgeShield is privacy-first: the daemon makes **zero outbound connections** by default. It never phones home, embeds telemetry, or ships logs to a cloud service. This is a security guarantee documented in [SECURITY.md](../SECURITY.md), not an oversight.

This guide shows how to get OpenTelemetry-grade observability — metrics, logs, and crash capture — **without modifying the daemon or adding any egress to it**. The pattern is the homelab standard: a **sidecar collector** reads EdgeShield's existing structured output and forwards it to your backend of choice. The daemon stays private; observability happens outside the process.

## What EdgeShield already exposes

| Source | Format | Endpoint / Path | Direction |
|---|---|---|---|
| Metrics | Prometheus text | `GET /metrics/prometheus` | Pull (scraper fetches) |
| Logs | Structured JSON (`tracing`) | stdout / journald | Push (collector reads) |
| Crashes | Panic backtraces | journald (systemd unit) | Push (collector reads) |
| Device inventory | JSON | `GET /devices` | Pull (on demand) |
| Alerts | JSON | `GET /alerts` | Pull (on demand) |

Nothing above initiates an outbound connection. A collector scraping these sources is the only thing that talks to a backend — and you control where that backend lives.

## Metrics: Prometheus + Grafana

EdgeShield exposes a [Prometheus text exposition](https://prometheus.io/docs/instrumenting/exposition_formats/) endpoint at `/metrics/prometheus`. The metrics are:

| Metric | Type | Description |
|---|---|---|
| `edgeshield_devices_total` | gauge | Total number of discovered devices |
| `edgeshield_packets_total` | counter | Total packets observed across all devices |
| `edgeshield_bytes_total` | counter | Total bytes observed across all devices |
| `edgeshield_uptime_seconds` | gauge | Daemon uptime in seconds |
| `edgeshield_alerts_total` | gauge | Total alerts in the alert store |

### Prometheus scrape config

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: edgeshield
    scrape_interval: 15s
    metrics_path: /metrics/prometheus
    static_configs:
      - targets: ["localhost:8080"]  # EdgeShield API host:port
    # If you enabled API auth, pass the Bearer token:
    # bearer_token: "your-read-key-here"
```

### Grafana dashboard

A ready-to-import dashboard is at [`dist/grafana/edgeshield-dashboard.json`](../dist/grafana/edgeshield-dashboard.json). Import it via **Dashboards → New → Import → Upload JSON**. It assumes a Prometheus datasource named `Prometheus`.

Panels included:
- Device count (gauge)
- Packet rate (packets/sec, `rate()` over `edgeshield_packets_total`)
- Byte rate (bytes/sec)
- Uptime (stat)
- Alert count (stat)
- Packet throughput over time (time series)
- Byte throughput over time (time series)

See [`docs/deployment/grafana.md`](deployment/grafana.md) for a full walkthrough including the Prometheus datasource setup and a docker-compose that brings up Prometheus + Grafana alongside EdgeShield.

## Logs: structured JSON → Loki / Datadog / ELK

EdgeShield emits structured JSON logs to stdout (see [logging.md](logging.md)). Every event is a JSON object with `timestamp`, `level`, `message`, `target`, and typed fields. When run under systemd (the default install path), logs go to journald.

### Option A: Promtail → Loki (recommended for homelabs)

Promtail reads journald and ships to Loki. Add to `promtail.yml`:

```yaml
scrape_configs:
  - job_name: journald
    journal:
      labels:
        job: edgeshield
      # Optional: only ship edgeshield unit logs
      path: /var/log/journal
    relabel_configs:
      - source_labels: ["__journal__systemd_unit"]
        regex: "edgeshield.service"
        action: keep
    pipeline_stages:
      - json:
          expressions:
            level: level
            message: message
            target: target
      - labels:
          level:
          target:
```

Then query in Grafana with LogQL:

```logql
{job="edgeshield"} |= "new device" | json
```

### Option B: Vector / Fluent Bit → anywhere

Both can read journald or stdout and forward to Datadog, Elasticsearch, OpenSearch, S3, or an OpenTelemetry collector. Example Vector config:

```toml
[sources.edgeshield_journald]
type = "journald"
include_units = ["edgeshield.service"]

[sinks.otlp]
type = "opentelemetry"
inputs = ["edgeshield_journald"]
endpoint = "http://otel-collector:4318"
```

This gives you OTLP-formatted logs in any OTel-compatible backend — **without EdgeShield itself knowing OTel exists**.

## Traces

EdgeShield does not emit distributed traces (it's a single-process daemon with a linear pipeline; traces would add overhead for little insight). If you want span-level latency data, the structured logs already include `span` context via `tracing`. A log collector can reconstruct timing from the JSON `span` fields.

## Crash / error capture (Sentry-equivalent, self-hosted)

EdgeShield is a daemon — crashes go to journald, which gives you structured logs and panic backtraces via `journalctl -u edgeshield`. For Sentry-equivalent aggregation (stack traces, deduplication, release tracking), forward journald to a self-hosted backend:

| Backend | How |
|---|---|
| **GlitchTip** (open-source Sentry) | Vector/Fluent Bit → GlitchTip's Sentry-compatible ingest endpoint |
| **Loki + Grafana alerting** | Promtail → Loki, alert on `level=error` with dedup via `count_over_time` |
| **ELK / OpenSearch** | Vector → Elasticsearch, Kibana dashboards on `level` and `target` |

All of these keep data on your hardware. None require any change to EdgeShield.

## Why not OpenTelemetry SDK / Sentry SDK in the daemon?

Both would add **automatic outbound egress** — directly contradicting the security guarantee in [SECURITY.md](../SECURITY.md): *"EdgeShield never phones home, embeds telemetry, or makes automatic network calls."* They also add non-trivial dependency weight and a background exporter task, which matters on the Raspberry Pi Zero 2 W target (see [performance.md](performance.md)). The sidecar pattern gives you the same observability with zero daemon changes, zero new dependencies, and zero egress from the monitoring process itself.

## Quick start: EdgeShield + Prometheus + Grafana via Docker

See [`docs/deployment/grafana.md`](deployment/grafana.md) for a complete `docker-compose.yaml` that runs EdgeShield, Prometheus, and Grafana together with the dashboard pre-provisioned.