# Docker Deployment

EdgeShield ships as a multi-arch Docker image (`linux/amd64` + `linux/arm64`) published to GHCR. This is the fastest way to get a running daemon without installing anything on the host.

## Quick start

```bash
docker run -d \
  --name edgeshield \
  --net=host \
  --cap-add=NET_RAW \
  -v edgeshield-data:/var/lib/edgeshield \
  ghcr.io/edgeshield/edgeshield:latest
```

Then check it's up:

```bash
curl http://localhost:8080/health
```

## Why `--net=host` and `--cap-add=NET_RAW`

EdgeShield captures packets from a network interface using a raw socket. Inside a container, two things are required for this to work:

1. **`--net=host`** — share the host's network namespace so the container can see the host's interfaces (`eth0`, `wlan0`, …). Without this, the container only sees its own isolated namespace and there's nothing meaningful to capture.
2. **`--cap-add=NET_RAW`** — grant the `CAP_NET_RAW` capability so the container can open raw sockets without running as root.

If you'd rather not use host networking, attach the container to a [macvlan/ipvlan](https://docs.docker.com/network/network-tutorial-macvlan/) network that bridges to your physical interface. The daemon's `interface` config must then name the interface as seen *inside* that namespace.

## Volumes

| Volume | Purpose |
|---|---|
| `/etc/edgeshield` | Config file (`config.toml`). Mount read-only if you manage it on the host. |
| `/var/lib/edgeshield` | SQLite database (devices, alerts, history). Must be writable. |

If you don't mount `/etc/edgeshield/config.toml`, the entrypoint generates a first-run config non-interactively (see [First-run config](#first-run-config) below).

## First-run config

The image's entrypoint (`dist/docker/entrypoint.sh`) checks for `/etc/edgeshield/config.toml` on startup. If it's missing, it runs:

```bash
edgeshield setup --non-interactive --interface eth0 --api-port 8080 \
    --database-path /var/lib/edgeshield/edgeshield.db --force
```

…then starts the daemon. You can override the interface and other defaults with environment variables:

| Env var | Default | Meaning |
|---|---|---|
| `EDGESHIELD_CONFIG` | `/etc/edgeshield/config.toml` | Path to the config file |
| `EDGESHIELD_INTERFACE` | `eth0` | Interface to capture |
| `EDGESHIELD_API_PORT` | `8080` | REST API port |
| `EDGESHIELD_DATABASE_PATH` | `/var/lib/edgeshield/edgeshield.db` | SQLite path |

For anything more involved (API auth, MQTT/ntfy/webhook/email notifiers, TLS), mount your own `config.toml`. See the [Configuration reference](../configuration.md).

## docker-compose

A ready-to-use `docker-compose.yaml` is at the repo root:

```yaml
services:
  edgeshield:
    image: ghcr.io/edgeshield/edgeshield:latest
    container_name: edgeshield
    network_mode: host
    cap_add:
      - NET_RAW
    volumes:
      - ./edgeshield.toml:/etc/edgeshield/config.toml:ro
      - edgeshield-data:/var/lib/edgeshield
    restart: unless-stopped

volumes:
  edgeshield-data:
```

```bash
docker compose up -d
```

## Using the TUI against a containerized daemon

The image includes the `edgeshield tui` binary, but a TUI needs a TTY. The recommended pattern is to run the daemon in Docker and the TUI on your host machine, pointing at the container's API:

```bash
# On the host (where edgeshield is installed via apt or built locally):
edgeshield tui --url http://localhost:8080
```

If you want the TUI from inside the container:

```bash
docker run -it --rm --net=host ghcr.io/edgeshield/edgeshield:latest tui --url http://localhost:8080
```

## Building the image locally

```bash
# Host architecture only (fast):
make docker

# Multi-arch (amd64 + arm64) via buildx:
make docker-multiarch

# Smoke test:
make docker-run
```

The `Dockerfile` is a multi-stage build: `rust:1.85-bookworm` compiles the binary, then it's copied into a `debian:bookworm-slim` runtime image with only `libpcap0.8`, `ca-certificates`, and `tini`.

## ARM / Raspberry Pi

The image is built for `linux/arm64`, which covers Raspberry Pi 4/5 running a 64-bit kernel. For a Pi 3 or any 32-bit OS, use the `.deb` package or build from source — `armv7` Docker support is deferred (see ROADMAP).

## Troubleshooting

- **`error: interface 'eth0' not found`** — the container can't see the host interface. You forgot `--net=host`, or the interface name differs. Set `EDGESHIELD_INTERFACE` or mount a config with the right `interface`.
- **`permission denied` on capture** — missing `--cap-add=NET_RAW`.
- **API unreachable from another host** — with `--net=host`, the API binds to `0.0.0.0:8080` on the host. Check the host firewall. To restrict to localhost, set `api_bind_address = "127.0.0.1"` in your config.
- **Data lost on restart** — you didn't mount `/var/lib/edgeshield`. The SQLite DB lives there.