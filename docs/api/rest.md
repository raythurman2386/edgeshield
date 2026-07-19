# REST API Reference

## Overview

EdgeShield exposes a REST API for querying device inventory, system health, and aggregate metrics. The API is read-only in the MVP and uses JSON for all responses.

### Base URL

```
http://<edgeshield-host>:<api-port>/
```

The default port is `8080`. The API binds to `0.0.0.0` (all interfaces).

### Content Type

All responses use `application/json`. No request bodies are required in the MVP.

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
| 400 | Bad Request | Invalid MAC address format |
| 404 | Not Found | Device not found |
| 500 | Internal Server Error | Unexpected server error |

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
        "hostname": null,
        "first_seen": "2026-07-18T12:00:00.000Z",
        "last_seen": "2026-07-18T12:05:00.000Z",
        "packet_count": 1500,
        "bytes_sent": 250000,
        "bytes_received": 180000,
        "protocols": ["ARP", "TCP", "UDP", "DNS"],
        "vendor": null
    },
    {
        "mac": "66:77:88:99:AA:BB",
        "ips": ["192.168.1.20", "192.168.1.21"],
        "hostname": null,
        "first_seen": "2026-07-18T12:01:00.000Z",
        "last_seen": "2026-07-18T12:04:30.000Z",
        "packet_count": 850,
        "bytes_sent": 120000,
        "bytes_received": 95000,
        "protocols": ["TCP", "ICMP"],
        "vendor": null
    }
]
```

**Response fields**:

| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | MAC address in `XX:XX:XX:XX:XX:XX` format |
| `ips` | array of string | Observed IP addresses |
| `hostname` | string or null | Hostname (future: DHCP discovery) |
| `first_seen` | string | ISO 8601 timestamp of first observation |
| `last_seen` | string | ISO 8601 timestamp of most recent observation |
| `packet_count` | integer | Total packets observed for this device |
| `bytes_sent` | integer | Total bytes transmitted by this device |
| `bytes_received` | integer | Total bytes received by this device |
| `protocols` | array of string | Detected protocols (uppercase names) |
| `vendor` | string or null | OUI vendor name (future) |

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

## Future Endpoints

The following endpoints are planned for future releases:

### GET /events

Returns discovery events (new devices, device updates).

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `since` | string | ISO 8601 timestamp — return events after this time |
| `limit` | integer | Maximum number of events to return (default: 100) |

### GET /events/stream

WebSocket endpoint for real-time event streaming.

### GET /alerts

Returns detection engine alerts.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity: `low`, `medium`, `high`, `critical` |
| `since` | string | ISO 8601 timestamp |
| `limit` | integer | Maximum number of alerts to return |

### GET /alerts/{id}

Returns a single alert by ID.

### GET /api/v1/devices

Versioned device list endpoint (future API version).

### GET /api/v1/devices/{mac}

Versioned single device endpoint.

---

## Rate Limiting

Rate limiting is not implemented in the MVP. Future versions may add:

- Configurable rate limits per IP
- Burst allowance
- Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`)

## Authentication

Authentication is not implemented in the MVP. The API is open to any client that can reach the configured port.

Future authentication methods:

- **API key**: `X-API-Key` header
- **mTLS**: Client certificate authentication
- **OAuth2**: Bearer token authentication (commercial edition)

## CORS

CORS is not configured in the MVP. Future versions will add configurable CORS for web dashboard access.

## Pagination

Pagination is not implemented in the MVP. The device list returns all devices. Future versions will add:

- `page` and `per_page` query parameters
- `Link` header for pagination navigation
- `X-Total-Count` header for total result count
