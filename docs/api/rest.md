# REST API Reference

## Overview

EdgeShield exposes a REST API for querying device inventory, device history, alerts, system health, and aggregate metrics. The API supports optional Bearer token authentication, TLS, and audit logging.

### Base URL

```
http://<edgeshield-host>:<api-port>/
```

The default port is `8080`. The default bind address is `0.0.0.0` (all interfaces). Set `api_bind_address = "127.0.0.1"` to restrict to local access only.

### Authentication

When `[api.auth]` is configured, all endpoints except `/health` require a Bearer token:

```bash
curl -H "Authorization: Bearer $EDGESHIELD_KEY" http://localhost:8080/devices
```

Two permission levels:
- **Read key**: GET endpoints only
- **Admin key**: GET + POST/DELETE endpoints
- **Single-key mode** (no `admin_key_hash`): read key grants admin access

`/health` is always exempt from authentication.

Failed auth attempts are rate-limited per IP (configurable via `[api.auth]`).

### Content Type

All responses use `application/json`, except `/metrics/prometheus` which uses `text/plain`.

### Error Format

Errors return an appropriate HTTP status code with a plain text error message in the response body:

```
Status: 404 Not Found
Content-Type: text/plain; charset=utf-8

device not found: 00:11:22:33:44:66
```

### HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful response |
| 204 | No Content | Successful acknowledge/delete |
| 400 | Bad Request | Invalid MAC address or alert ID format |
| 401 | Unauthorized | Missing or invalid API key |
| 403 | Forbidden | Read key used for admin endpoint |
| 404 | Not Found | Device or alert not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server error |
| 501 | Not Implemented | History endpoint when history is disabled |

---

## Endpoints

### GET /health

Health check endpoint. Returns the server status and version.

**Response `200 OK`**:

```json
{
    "status": "ok",
    "version": "0.1.0"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"ok"` when the server is running |
| `version` | string | Semantic version of the running binary |

**Errors**: None.

**Example**:

```bash
curl http://localhost:8080/health
```

---

### GET /devices

Returns all discovered devices, sorted by MAC address.

**Response `200 OK`**:

```json
[
    {
        "mac": "00:11:22:33:44:55",
        "ips": ["192.168.1.10"],
        "hostname": "living-room-plug",
        "first_seen": "2026-07-18T12:00:00.000Z",
        "last_seen": "2026-07-18T12:05:00.000Z",
        "packet_count": 1500,
        "bytes_sent": 250000,
        "bytes_received": 180000,
        "protocols": ["ARP", "TCP", "UDP", "DNS"],
        "vendor": "TP-Link Technologies",
        "dhcp_vendor_class": null,
        "protocol_stats": { "TCP": 800, "UDP": 400, "DNS": 200, "ARP": 100 }
    }
]
```

**Response fields**:

| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | MAC address in `XX:XX:XX:XX:XX:XX` format |
| `ips` | array of string | Observed IP addresses |
| `hostname` | string or null | Hostname from DHCP or mDNS |
| `first_seen` | string | ISO 8601 timestamp of first observation |
| `last_seen` | string | ISO 8601 timestamp of most recent observation |
| `packet_count` | integer | Total packets observed for this device |
| `bytes_sent` | integer | Total bytes transmitted by this device |
| `bytes_received` | integer | Total bytes received by this device |
| `protocols` | array of string | Detected protocols (uppercase names) |
| `vendor` | string or null | OUI vendor name from IEEE registry |
| `dhcp_vendor_class` | string or null | DHCP option 60 vendor class identifier |
| `protocol_stats` | object | Per-protocol packet counts (e.g., `{"TCP": 800, "DNS": 200}`) |

**Errors**:

| Status | Condition |
|--------|-----------|
| 500 | Internal store error |

**Example**:

```bash
curl http://localhost:8080/devices
```

---

### GET /devices/{mac}

Returns a single device by MAC address.

**Path Parameters**:

| Parameter | Type | Description | Format |
|-----------|------|-------------|--------|
| `mac` | string | MAC address | `XX:XX:XX:XX:XX:XX` or `XXXXXXXXXXXX` |

**Response `200 OK`**:

```json
{
    "mac": "00:11:22:33:44:55",
    "ips": ["192.168.1.10"],
    "hostname": null,
    "first_seen": "2026-07-18T12:00:00.000Z",
    "last_seen": "2026-07-18T12:05:00.000Z",
    "packet_count": 1500,
    "bytes_sent": 250000,
    "bytes_received": 180000,
    "protocols": ["ARP", "TCP", "UDP", "DNS"],
    "vendor": null
}
```

**Errors**:

| Status | Condition |
|--------|-----------|
| 400 | Invalid MAC address format |
| 404 | Device not found |
| 500 | Internal store error |

**Examples**:

```bash
# Colon-separated format
curl http://localhost:8080/devices/00:11:22:33:44:55

# Plain hex format
curl http://localhost:8080/devices/001122334455

# Error: invalid MAC
curl http://localhost:8080/devices/not-a-mac
# Response: 400 Bad Request
# Body: "invalid MAC address: not-a-mac"

# Error: not found
curl http://localhost:8080/devices/00:11:22:33:44:66
# Response: 404 Not Found
# Body: "device not found: 00:11:22:33:44:66"
```

---

### GET /metrics

Returns aggregate network metrics.

**Response `200 OK`**:

```json
{
    "total_devices": 12,
    "total_packets": 45200,
    "total_bytes": 12500000,
    "uptime_seconds": 3600
}
```

| Field | Type | Description |
|-------|------|-------------|
| `total_devices` | integer | Number of unique MAC addresses discovered |
| `total_packets` | integer | Sum of all packet counts across all devices |
| `total_bytes` | integer | Sum of all bytes sent and received across all devices |
| `uptime_seconds` | integer | Seconds since the API server started |

**Errors**:

| Status | Condition |
|--------|-----------|
| 500 | Internal store error |

**Example**:

```bash
curl http://localhost:8080/metrics
```

---

### GET /devices/{mac}/history

Returns daily snapshot history for a device. Each snapshot is a full copy of the device's state at the time of the last snapshot for that day.

**Path Parameters**:

| Parameter | Type | Description | Format |
|-----------|------|-------------|--------|
| `mac` | string | MAC address | `XX:XX:XX:XX:XX:XX` or `XXXXXXXXXXXX` |

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `from` | string | none | Start date (`YYYY-MM-DD`, inclusive) |
| `to` | string | none | End date (`YYYY-MM-DD`, inclusive) |
| `limit` | integer | `90` | Maximum number of snapshots to return |

**Response `200 OK`**:

```json
[
    {
        "mac": "00:11:22:33:44:55",
        "snapshot_date": "2026-07-18",
        "snapshot_timestamp": "2026-07-18T23:59:59.000Z",
        "ips": ["192.168.1.10"],
        "hostname": "living-room-plug",
        "vendor": "TP-Link Technologies",
        "dhcp_vendor_class": null,
        "packet_count": 1500,
        "bytes_sent": 250000,
        "bytes_received": 180000,
        "protocols": ["TCP", "DNS"],
        "protocol_stats": { "TCP": 800, "DNS": 200 },
        "first_seen": "2026-07-18T12:00:00.000Z",
        "last_seen": "2026-07-18T23:59:50.000Z"
    }
]
```

**Errors**:

| Status | Condition |
|--------|-----------|
| 400 | Invalid MAC address format |
| 501 | History not enabled (set `database_path` and `history_snapshot_hours > 0`) |

**Example**:

```bash
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/devices/00:11:22:33:44:55/history?from=2026-07-01&to=2026-07-19&limit=30"
```

---

### GET /alerts

Returns the alert history, optionally filtered. Ordered by most recent first.

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | none | Filter by severity: `info`, `warning`, `critical` |
| `acknowledged` | string | none | Filter by acknowledged status: `true` or `false` |
| `rule` | string | none | Filter by rule name (exact match) |
| `limit` | integer | none | Maximum number of alerts to return |

**Response `200 OK`**:

```json
[
    {
        "id": 42,
        "rule_name": "new-device-alert",
        "severity": "info",
        "event_type": "new_device",
        "mac": "00:11:22:33:44:55",
        "message": "New device discovered: living-room-plug (00:11:22:33:44:55)",
        "device_snapshot": { "mac": "00:11:22:33:44:55", "..." : "..." },
        "timestamp": "2026-07-19T15:00:00.000Z",
        "acknowledged": false
    }
]
```

**Example**:

```bash
# All unacknowledged warnings
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/alerts?severity=warning&acknowledged=false"

# Last 10 alerts
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8080/alerts?limit=10"
```

---

### GET /alerts/{id}

Returns a single alert by ID.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Alert ID |

**Response `200 OK`**: Same as the alert object in `GET /alerts`.

**Errors**:

| Status | Condition |
|--------|-----------|
| 400 | Invalid alert ID |
| 404 | Alert not found |

---

### POST /alerts/{id}/acknowledge

Marks an alert as acknowledged. Acknowledged alerts suppress future alerts for the same device/rule combination.

**Auth**: Requires admin key.

**Response `204 No Content`**: Success.

**Errors**:

| Status | Condition |
|--------|-----------|
| 400 | Invalid alert ID |
| 403 | Read key used (admin key required) |
| 500 | Alert not found or internal error |

**Example**:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_KEY" \
  http://localhost:8080/alerts/42/acknowledge
```

---

### DELETE /alerts/{id}

Deletes an alert by ID.

**Auth**: Requires admin key.

**Response `204 No Content`**: Success.

**Example**:

```bash
curl -X DELETE -H "Authorization: Bearer $ADMIN_KEY" \
  http://localhost:8080/alerts/42
```

---

### GET /metrics/prometheus

Returns metrics in Prometheus text exposition format. Suitable for scraping by Prometheus.

**Response `200 OK`** (Content-Type: `text/plain`):

```text
# HELP edgeshield_devices_total Total number of discovered devices.
# TYPE edgeshield_devices_total gauge
edgeshield_devices_total 15
# HELP edgeshield_packets_total Total packets observed across all devices.
# TYPE edgeshield_packets_total counter
edgeshield_packets_total 45200
# HELP edgeshield_bytes_total Total bytes observed across all devices.
# TYPE edgeshield_bytes_total counter
edgeshield_bytes_total 12500000
# HELP edgeshield_uptime_seconds Daemon uptime in seconds.
# TYPE edgeshield_uptime_seconds gauge
edgeshield_uptime_seconds 3600
# HELP edgeshield_alerts_total Total alerts in the alert store.
# TYPE edgeshield_alerts_total gauge
edgeshield_alerts_total 3
```

**Example**:

```bash
curl -H "Authorization: Bearer $KEY" http://localhost:8080/metrics/prometheus
```

---

## Rate Limiting

When `[api.auth]` is configured with `max_failures > 0`, failed authentication attempts are rate-limited per IP address. After `max_failures` (default 10) failed attempts within `window_seconds` (default 60), the IP is blocked for `block_seconds` (default 300). Blocked requests return `429 Too Many Requests`.

Set `max_failures = 0` to disable rate limiting.
- `X-Total-Count` header for total result count
