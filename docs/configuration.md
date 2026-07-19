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

The API server binds to `0.0.0.0`. In production, consider:

- Binding to `127.0.0.1` and using a reverse proxy (future feature)
- Using a firewall to restrict access to the API port
- Changing the port to avoid conflicts with other services

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

---

## Complete Example

### Minimal configuration

```toml
interface = "eth0"
```

### Full configuration with defaults

```toml
interface       = "eth0"
api_port        = 8080
log_level       = "info"
capture_buffer  = 4096
```

### Configuration with MQTT alerting

```toml
interface       = "eth0"
api_port        = 8080
log_level       = "info"
capture_buffer  = 4096

[mqtt]
host = "homeassistant.local"
port = 1883
topic = "edgeshield/devices/new"
client_id = "edgeshield"
qos = 1
```

### Configuration with ntfy alerting

```toml
interface       = "wlan0"
api_port        = 0
log_level       = "info"
capture_buffer  = 4096
database_path   = "/var/lib/edgeshield/edgeshield.db"

[ntfy]
base_url = "https://ntfy.sh"
topic = "edgeshield"
```

### Development configuration

```toml
interface       = "eth0"
api_port        = 9090
log_level       = "debug"
capture_buffer  = 1024
```

### Production configuration

```toml
interface       = "eth0"
api_port        = 8080
log_level       = "warn"
capture_buffer  = 16384
```

---

## Environment Variables

The following environment variables override configuration file values:

| Variable | Overrides | Example |
|----------|-----------|---------|
| `RUST_LOG` | `log_level` (with per-module support) | `RUST_LOG=debug` |
| `EDGESHIELD_CONFIG` | Config file path | `EDGESHIELD_CONFIG=/custom/path/config.toml` |

---

## Future Configuration Options

The following options are planned for future releases:

```toml
[api]
bind_address = "127.0.0.1"
tls_certificate = "/etc/edgeshield/cert.pem"
tls_key = "/etc/edgeshield/key.pem"
cors_origins = ["https://dashboard.example.com"]

[api.auth]
mode = "api-key"
# api_key = "..."  # Stored as SHA-256 hash

[storage]
backend = "sqlite"
path = "/var/lib/edgeshield/edgeshield.db"

[storage.retention]
events_days = 7
metrics_days = 30
alerts_days = 90

[rules]
enabled = ["new-device", "protocol-change", "volume-spike"]

[rules.volume-spike]
threshold_multiplier = 10
window_minutes = 5
cooldown_minutes = 30

[logging]
format = "json"  # or "pretty" for development
correlation_id = true
```

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
