# Configuration

EdgeShield uses a single TOML configuration file. The default path is `/etc/edgeshield/config.toml`, but a custom path can be specified with the `--config` flag.

## File Location

```bash
# Default
sudo edgeshield run

# Custom path
sudo edgeshield run --config /home/pi/edgeshield.toml
```

## Configuration Reference

### `interface` (required)

The network interface to capture packets on.

- **Type**: string
- **Required**: yes
- **Default**: none (must be specified)

```toml
interface = "eth0"
```

Common values:

| Value | Description |
|-------|-------------|
| `eth0` | Wired Ethernet (Raspberry Pi) |
| `wlan0` | Wi-Fi interface (requires monitor mode) |
| `enp3s0` | Wired Ethernet (desktop Linux) |
| `en0` | Wired Ethernet (macOS) |

The interface must exist and the process must have `CAP_NET_RAW` capability (or run as root) to open a raw socket on it.

### `api_port` (optional)

The port for the REST API HTTP server.

- **Type**: integer (u16)
- **Required**: no
- **Default**: `8080`

```toml
api_port = 8080
```

### `api_bind_address` (optional)

The address to bind the REST API server to.

- **Type**: string
- **Required**: no
- **Default**: `"0.0.0.0"` (all interfaces)

```toml
api_bind_address = "127.0.0.1"
```

Set to `127.0.0.1` to restrict API access to local processes only. This is recommended when using a reverse proxy or when no API authentication is configured. When binding to a non-loopback address without authentication, EdgeShield logs a warning at startup.

### `database_path` (optional)

Path to the SQLite database file. Used for device storage, alert history, and device history snapshots.

- **Type**: string
- **Required**: no
- **Default**: `""` (in-memory only — data lost on restart)

```toml
database_path = "/var/lib/edgeshield/edgeshield.db"
```

When empty, all data is in-memory and lost on restart. When set, devices, alerts, and daily history snapshots persist across restarts.

**Write-back cache**: When SQLite is enabled, the device store uses a write-back cache — the hot path (per-packet updates) hits an in-memory DashMap, and a background task flushes dirty devices to SQLite every 5 seconds (and on shutdown). On an unclean shutdown (`kill -9`, power loss), the last flush interval's counter updates may be lost. The device inventory and last-known state are recovered on the next start. This trade-off is necessary to sustain 10k+ pps on Raspberry Pi — a SQL write per packet cannot keep up.

### `log_level` (optional)

The log level filter for structured JSON logging.

- **Type**: string
- **Required**: no
- **Default**: `"info"`
- **Valid values**: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`

```toml
log_level = "info"
```

| Level | Use Case |
|-------|----------|
| `error` | Production — only log errors |
| `warn` | Production — log warnings and errors |
| `info` | Default — log lifecycle events |
| `debug` | Development — detailed subsystem state |
| `trace` | Debugging — per-packet events |

The log level can also be overridden at runtime via the `RUST_LOG` environment variable, which supports per-module filtering:

```bash
RUST_LOG=edgeshield_packet=debug,edgeshield_discovery=trace edgeshield run
```

### `capture_buffer` (optional)

The size of the bounded mpsc channel between the capture thread and the pipeline task. This controls the maximum number of packets that can be queued before backpressure drops packets.

- **Type**: integer (usize)
- **Required**: no
- **Default**: `4096`

```toml
capture_buffer = 4096
```

**Tuning guidance**:

| Network Size | Recommended Buffer | Notes |
|--------------|-------------------|-------|
| Home (< 20 devices) | 1024 | Low traffic, minimal buffering needed |
| Small office (< 50 devices) | 4096 | Default — good for most networks |
| Large office (< 200 devices) | 16384 | Higher traffic, more buffering |
| Enterprise (> 200 devices) | 65536 | High traffic, but consider hardware upgrade |

A larger buffer reduces packet drops during traffic bursts but uses more memory. Each buffer slot holds one `PacketBuf` (typically ~1514 bytes for a full Ethernet frame). A buffer of 4096 uses approximately 6 MB of memory for the channel.

### `[mqtt]` (optional)

MQTT notification settings. When present, EdgeShield publishes a JSON event to the configured broker every time a **new device** is discovered on the network. When absent, MQTT is disabled and EdgeShield behaves as before.

This is the feature that makes EdgeShield worth running on a homelab network: pair it with Home Assistant or Node-RED to get an alert the moment an unknown device joins your network.

- **Type**: table
- **Required**: no
- **Default**: absent (MQTT disabled)

```toml
[mqtt]
host = "homeassistant.local"
port = 1883
topic = "edgeshield/devices/new"
client_id = "edgeshield"
# username = "edgeshield"
# password = "secret"
qos = 1
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | (required) | Broker hostname or IP |
| `port` | integer | `1883` | Broker port (8883 for TLS — not yet supported) |
| `topic` | string | `"edgeshield/devices/new"` | Topic to publish new-device events to |
| `client_id` | string | `"edgeshield"` | MQTT client ID (unique per broker) |
| `username` | string | none | Optional broker username |
| `password` | string | none | Optional broker password |
| `qos` | integer | `1` | QoS level (0, 1, or 2) |

#### Published message format

Each new-device event is published as a JSON object:

```json
{
  "event": "new_device",
  "mac": "00:11:22:33:44:55",
  "ip": "192.168.1.10",
  "hostname": "living-room-plug",
  "vendor": "TP-Link Technologies",
  "protocol": "TCP",
  "first_seen": "2026-07-18T12:00:00.000Z"
}
```

Fields are additive only — never renamed or removed without a topic version bump. `ip`, `hostname`, and `vendor` are `null` if not yet observed. The `vendor` field comes from the IEEE OUI registry (39,000+ entries, embedded at build time for offline use).

#### Home Assistant example

Add an MQTT sensor in `configuration.yaml`:

```yaml
mqtt:
  sensor:
    - name: "EdgeShield New Device"
      state_topic: "edgeshield/devices/new"
      value_template: "{{ value_json.mac }}"
      json_attributes_topic: "edgeshield/devices/new"
```

#### Security

The password is read from the config file in plaintext. For production, prefer a broker that accepts anonymous clients on a trusted VLAN, or run EdgeShield under systemd with `LoadCredential=` and a config that reads the password from a protected path. Do not commit credentials to version control.

### `[ntfy]` (optional)

ntfy.sh notification settings. When present, EdgeShield POSTs a JSON event to the configured ntfy server every time a **new device** is discovered on the network. When absent, ntfy is disabled.

ntfy is an HTTP-based pub/sub service (https://ntfy.sh). Unlike MQTT, it requires no broker — you POST to a topic URL and any subscriber receives the message. This makes it a good fit for homelabs without an MQTT broker. If both `[mqtt]` and `[ntfy]` are configured, ntfy takes precedence and MQTT is ignored (with a log line).

- **Type**: table
- **Required**: no
- **Default**: absent (ntfy disabled)

```toml
[ntfy]
base_url = "https://ntfy.sh"
topic = "edgeshield"
# token = "tok_your_access_token"
# priority = 2
# tags = "warning,desktop"
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | (required) | Server URL without trailing slash (e.g., `https://ntfy.sh`) |
| `topic` | string | (required) | Topic name; publish URL becomes `{base_url}/{topic}` |
| `token` | string | none | Optional `Bearer` token for authenticated servers |
| `priority` | integer | none | ntfy priority header (1 = max, 5 = min) |
| `tags` | string | none | Comma-separated emoji shortcodes (e.g., `warning,desktop`) |

#### Published message format

The POST body is the same JSON object used by the MQTT notifier, so consumers can switch transports without changing their parsers:

```json
{
  "event": "new_device",
  "mac": "00:11:22:33:44:55",
  "ip": "192.168.1.10",
  "hostname": "living-room-plug",
  "vendor": "TP-Link Technologies",
  "protocol": "TCP",
  "first_seen": "2026-07-18T12:00:00.000Z"
}
```

The ntfy `Title` header is set to a human-readable summary (`New device: <hostname|vendor|mac> (<mac>)`) so the notification card is useful before the body is expanded.

#### Security

The token is read from the config file in plaintext. For production, prefer a public topic on a trusted ntfy instance, or run EdgeShield under systemd with `LoadCredential=` and a config that reads the token from a protected path. Do not commit credentials to version control.

### `[webhook]` (optional)

Webhook notification settings. When present, EdgeShield POSTs each alert as JSON to the configured URL. Compatible with Slack, Discord, Microsoft Teams, and any generic webhook that accepts a JSON POST body.

```toml
[webhook]
url = "https://hooks.slack.com/services/..."
# token = "bearer-token"           # optional Bearer auth
# headers = { "X-Custom" = "value" } # optional custom headers
# timeout_seconds = 10             # request timeout (default 10)
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | (required) | Webhook URL |
| `token` | string | none | Optional Bearer token (`Authorization: Bearer <token>`) |
| `headers` | map | none | Optional custom HTTP headers |
| `timeout_seconds` | integer | `10` | Request timeout |

### `[email]` (optional)

Email notification settings via SMTP. Sends each alert as a plain-text email. Uses the `lettre` crate — no local MTA required.

```toml
[email]
host = "smtp.gmail.com"
port = 587
username = "you@gmail.com"
password = "app-password"
from = "edgeshield@home.lan"
to = "you@home.lan"
# starttls = true              # default true (STARTTLS on port 587)
# subject_prefix = "[EdgeShield]" # default
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | (required) | SMTP server hostname |
| `port` | integer | `587` | SMTP port (587 for STARTTLS, 465 for implicit TLS) |
| `username` | string | (required) | SMTP username |
| `password` | string | (required) | SMTP password (use an app-specific password for Gmail) |
| `from` | string | (required) | From email address |
| `to` | string | (required) | To email address (recipient) |
| `starttls` | boolean | `true` | Use STARTTLS (port 587) vs implicit TLS (port 465) |
| `subject_prefix` | string | `"[EdgeShield]"` | Subject prefix for alert emails |

### `[[rules]]` (optional)

Alerting rules. Each rule defines a condition, severity, and cooldown. When the rule engine matches a condition against a discovery event, it produces an alert that is delivered to all configured notifiers.

If no rules are configured, a default `new_device` rule runs (preserving the pre-Phase-5 behavior — every new MAC triggers an alert).

```toml
[[rules]]
name = "new-device-alert"
condition = "new_device"
severity = "info"
cooldown_seconds = 300

[[rules]]
name = "new-iot-device"
condition = { new_device_by_vendor = "TP-Link" }
severity = "warning"

[[rules]]
name = "new-apple-device"
condition = { new_device_by_mac_prefix = "8C:85:90" }
severity = "info"

[[rules]]
name = "device-offline-30min"
condition = { device_offline = { after_seconds = 1800 } }
severity = "warning"
cooldown_seconds = 3600

[[rules]]
name = "protocol-change"
condition = "protocol_change"
severity = "info"
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | (required) | Human-readable rule name (shown in alerts) |
| `enabled` | boolean | `true` | Whether the rule is active |
| `condition` | string or table | (required) | The condition that triggers the rule (see below) |
| `severity` | string | `"info"` | `info`, `warning`, or `critical` |
| `cooldown_seconds` | integer | `0` | Min seconds between alerts for the same device (0 = no cooldown) |

#### Conditions

| Condition | Format | Description |
|-----------|--------|-------------|
| `new_device` | `"new_device"` | Fires for every new MAC address |
| `new_device_by_vendor` | `{ new_device_by_vendor = "TP-Link" }` | Fires for a new device whose OUI vendor matches (case-insensitive substring) |
| `new_device_by_mac_prefix` | `{ new_device_by_mac_prefix = "8C:85:90" }` | Fires for a new device whose MAC starts with the prefix (case-insensitive) |
| `device_offline` | `{ device_offline = { after_seconds = 1800 } }` | Fires when a known device has been silent for N seconds |
| `protocol_change` | `"protocol_change"` | Fires when a device starts using a new protocol |

### `[scanner]` (optional)

Background scanner settings for device-offline detection. The scanner wakes periodically, lists all devices, and emits `DeviceOffline` events for devices that have been silent longer than 60 seconds.

```toml
[scanner]
interval_seconds = 60  # default 60; set to 0 to disable
```

### `[storage]` (optional)

Device history snapshot and retention settings.

```toml
[storage]
history_snapshot_hours = 24   # default 24; set to 0 to disable
history_retention_days = 90   # default 90; set to 0 to keep forever
```

### `[api.auth]` (optional)

API key authentication. When present, all endpoints except `/health` require a valid Bearer token. Keys are stored as SHA-256 hashes — never store the plaintext key in the config.

```bash
# Generate a key
KEY=$(openssl rand -hex 32)
echo "Your API key: $KEY"

# Hash it for the config
echo -n "$KEY" | sha256sum
# → a1b2c3d4...  (64 hex chars)
```

```toml
[api.auth]
read_key_hash = "a1b2c3d4..."   # SHA-256 hex of the read key (required)
admin_key_hash = "d4e5f6..."    # SHA-256 hex of the admin key (optional)
max_failures = 10               # rate limit: max failed attempts per IP (default 10, 0 = disabled)
window_seconds = 60             # rate limit: window for counting failures (default 60)
block_seconds = 300             # rate limit: how long to block an IP (default 300)
```

#### Permission levels

| Key | GET endpoints | POST/DELETE endpoints |
|-----|---------------|----------------------|
| Read key | ✅ | ❌ (403 Forbidden) |
| Admin key | ✅ | ✅ |
| Single-key mode (no admin key) | ✅ | ✅ (read key grants admin) |

`/health` is always exempt from authentication.

### `[api.tls]` (optional)

TLS settings for the API server. When present, the API uses HTTPS via `rustls` (pure Rust, no OpenSSL).

```toml
[api.tls]
cert_path = "/etc/edgeshield/cert.pem"
key_path = "/etc/edgeshield/key.pem"
```

Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=edgeshield"
```

### `[api.audit]` (optional)

Audit logging. When present, all API requests (except `/health`) are logged to a file in JSON-lines format.

```toml
[api.audit]
log_path = "/var/log/edgeshield/audit.log"
```

Each audit entry is a JSON object:

```json
{"timestamp":"2026-07-19T15:00:00.123Z","method":"GET","path":"/devices","status":200,"key_prefix":"a1b2","duration_ms":3}
```

The `key_prefix` field is the first 4 hex characters of the SHA-256 hash of the key used — enough to identify which key was used without revealing it.

---

## Complete Example

### Minimal configuration

```toml
interface = "eth0"
```

### Full configuration with all options

```toml
interface         = "eth0"
api_bind_address  = "127.0.0.1"
api_port          = 8080
log_level         = "info"
capture_buffer    = 4096
database_path     = "/var/lib/edgeshield/edgeshield.db"
```

### Production configuration with alerting and security

```toml
interface         = "wlan0"
api_bind_address  = "0.0.0.0"
api_port          = 8080
log_level         = "warn"
capture_buffer    = 16384
database_path     = "/var/lib/edgeshield/edgeshield.db"

# Alerting rules
[[rules]]
name = "new-device-alert"
condition = "new_device"
severity = "info"
cooldown_seconds = 300

[[rules]]
name = "device-offline-30min"
condition = { device_offline = { after_seconds = 1800 } }
severity = "warning"
cooldown_seconds = 3600

# Notification channels (all run simultaneously)
[ntfy]
base_url = "https://ntfy.sh"
topic = "edgeshield"

[webhook]
url = "https://hooks.slack.com/services/..."

[email]
host = "smtp.gmail.com"
port = 587
username = "you@gmail.com"
password = "app-password"
from = "edgeshield@home.lan"
to = "you@home.lan"

# API security
[api.auth]
read_key_hash = "sha256-hex-of-your-read-key"
admin_key_hash = "sha256-hex-of-your-admin-key"

[api.tls]
cert_path = "/etc/edgeshield/cert.pem"
key_path = "/etc/edgeshield/key.pem"

[api.audit]
log_path = "/var/log/edgeshield/audit.log"

# Device history
[storage]
history_snapshot_hours = 24
history_retention_days = 90

# Offline scanner
[scanner]
interval_seconds = 60
```

---

## Environment Variables

The following environment variables override configuration file values:

| Variable | Overrides | Example |
|----------|-----------|---------|
| `RUST_LOG` | `log_level` (with per-module support) | `RUST_LOG=debug` |
| `EDGESHIELD_CONFIG` | Config file path | `EDGESHIELD_CONFIG=/custom/path/config.toml` |

---

## Configuration Validation

The configuration is validated at startup:

1. **File exists**: The specified path must exist and be readable
2. **Valid TOML**: The file must be valid TOML syntax
3. **Interface non-empty**: The interface name must not be empty
4. **Interface exists**: The interface must exist on the system (validated at capture start)
5. **Port in range**: The API port must be a valid u16 (0-65535)
6. **Log level valid**: The log level must be one of the valid values

If validation fails, EdgeShield prints an error message and exits with a non-zero status code:

```bash
$ edgeshield run --config /etc/edgeshield/config.toml
Error: failed to read config file '/etc/edgeshield/config.toml': No such file or directory
```

---

## Generating a Default Configuration

```bash
edgeshield default-config
```

This prints the default configuration to stdout:

```toml
# EdgeShield Configuration
interface = "eth0"
api_port = 8080
log_level = "info"
capture_buffer = 4096
```

Redirect to a file to create a starting configuration:

```bash
edgeshield default-config > /etc/edgeshield/config.toml
```
