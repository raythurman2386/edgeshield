# Grafana Deployment

This guide brings up EdgeShield, Prometheus, and Grafana together via Docker Compose, with the EdgeShield dashboard pre-provisioned. The daemon stays fully private — only Prometheus (which you control) scrapes its `/metrics/prometheus` endpoint.

## Prerequisites

- Docker + Docker Compose
- The EdgeShield Docker image (build locally or pull from GHCR)

## Files

Create a directory with these three files:

### `docker-compose.yaml`

```yaml
services:
  edgeshield:
    image: ghcr.io/edgeshield/edgeshield:latest
    # build: .  # uncomment to build locally instead of pulling
    container_name: edgeshield
    network_mode: host
    cap_add:
      - NET_RAW
    volumes:
      - edgeshield-data:/var/lib/edgeshield
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    network_mode: host
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      # Pre-provision the Prometheus datasource
      - ./grafana/provisioning/datasources:/etc/grafana/provisioning/datasources:ro
      # Pre-provision the EdgeShield dashboard
      - ./grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./dist/grafana/edgeshield-dashboard.json:/var/lib/grafana/dashboards/edgeshield-dashboard.json:ro
    restart: unless-stopped

volumes:
  edgeshield-data:
  prometheus-data:
  grafana-data:
```

### `prometheus.yml`

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: edgeshield
    scrape_interval: 15s
    metrics_path: /metrics/prometheus
    static_configs:
      - targets: ["localhost:8080"]
    # If you enabled API auth, uncomment and set the read key:
    # bearer_token: "your-read-key-here"
```

### `grafana/provisioning/datasources/datasources.yml`

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: true
```

### `grafana/provisioning/dashboards/dashboards.yml`

```yaml
apiVersion: 1
providers:
  - name: EdgeShield
    orgId: 1
    folder: EdgeShield
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
```

## Bring it up

```bash
docker compose up -d
```

Then open Grafana at `http://localhost:3000` (admin / admin) and navigate to **Dashboards → EdgeShield**. The dashboard should already be there with live data.

## What you'll see

The dashboard (`dist/grafana/edgeshield-dashboard.json`) has nine panels:

| Panel | Metric | Type |
|---|---|---|
| Discovered Devices | `edgeshield_devices_total` | stat |
| Daemon Uptime | `edgeshield_uptime_seconds` | stat |
| Total Alerts | `edgeshield_alerts_total` | stat |
| Packet Rate | `rate(edgeshield_packets_total[1m])` | stat |
| Byte Rate | `rate(edgeshield_bytes_total[1m])` | stat |
| Packet Throughput | `rate(edgeshield_packets_total[1m])` | time series |
| Byte Throughput | `rate(edgeshield_bytes_total[1m])` | time series |
| Device Count Over Time | `edgeshield_devices_total` | time series |
| Alert Count Over Time | `edgeshield_alerts_total` | time series |

The dashboard uses a `${DS_PROMETHEUS}` datasource variable so it works regardless of what you name your Prometheus datasource.

## Importing the dashboard manually

If you already have Grafana running and just want the dashboard:

1. Copy `dist/grafana/edgeshield-dashboard.json` from this repo.
2. In Grafana: **Dashboards → New → Import → Upload JSON**.
3. Select your Prometheus datasource when prompted.

## Adding logs (optional)

To see EdgeShield's structured JSON logs in Grafana alongside the metrics, add Loki + Promtail. See [observability.md](../observability.md) for the Promtail journald config. A minimal addition to the compose file:

```yaml
  loki:
    image: grafana/loki:latest
    container_name: loki
    ports:
      - "3100:3100"
    volumes:
      - loki-data:/loki
    restart: unless-stopped

  promtail:
    image: grafana/promtail:latest
    container_name: promtail
    volumes:
      - /var/log/journal:/var/log/journal:ro
      - ./promtail.yml:/etc/promtail/promtail.yml:ro
    command: -config.file=/etc/promtail/promtail.yml
    restart: unless-stopped

volumes:
  loki-data:
```

Then add a Loki datasource in Grafana and query with LogQL:

```logql
{job="edgeshield"} | json | level =~ "error|warn"
```

## Security notes

- The compose above uses `network_mode: host` for EdgeShield and Prometheus so they can reach each other and the host's interfaces. On a macvlan setup, drop `network_mode` and attach them to the macvlan network instead.
- Grafana is exposed on `:3000` — put it behind a reverse proxy or restrict access. Change the default admin password immediately.
- EdgeShield's API auth (if enabled) requires a `bearer_token` in the Prometheus scrape config. Use a **read key** (not admin) — Prometheus only reads.