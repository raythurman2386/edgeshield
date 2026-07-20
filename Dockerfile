# EdgeShield — multi-arch Docker image (amd64, arm64)
#
# Multi-stage build:
#   1. builder  — Rust toolchain + libpcap-dev, builds the release binary
#   2. runtime  — slim Debian with only the runtime libpcap + the binary
#
# The image runs the daemon directly (no systemd inside the container).
# Packet capture requires `--net=host` (or a macvlan/ipvlan attachment)
# plus `--cap-add=NET_RAW`. See docs/deployment/docker.md.

# syntax=docker/dockerfile:1.7

############################################
# Stage 1: builder
############################################
FROM --platform=$BUILDPLATFORM rust:1.97-bookworm AS builder

# libpcap-dev + cmake + pkg-config are required to build the
# pcap/pnet crates. build-essential is already in the rust image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap-dev \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the workspace manifests first to leverage layer caching for
# dependency compilation. Cargo rebuilds deps only when these change.
COPY Cargo.toml rust-toolchain.toml ./
COPY crates/ ./crates/

# Map Docker's TARGETPLATFORM (set by buildx, e.g. linux/arm64) to a
# Rust target triple. When BUILDPLATFORM == TARGETPLATFORM we build
# natively; otherwise we cross-compile via rustup target add + cargo
# --target. This avoids QEMU for the common amd64-on-amd64 and
# arm64-on-arm64 cases (buildx picks a native node per platform).
#
# To force a specific target (e.g. for a local non-buildx build), pass
# `--build-arg RUST_TARGET=x86_64-unknown-linux-gnu`.
ARG RUST_TARGET=""
RUN set -e; \
    target="$RUST_TARGET"; \
    if [ -z "$target" ]; then \
        case "$TARGETPLATFORM" in \
            linux/amd64)  target="x86_64-unknown-linux-gnu" ;; \
            linux/arm64)  target="aarch64-unknown-linux-gnu" ;; \
            linux/arm/v7) target="armv7-unknown-linux-gnueabihf" ;; \
            *)            target="" ;; \
        esac; \
    fi; \
    if [ -n "$target" ] && [ "$target" != "$(rustc -vV | sed -n 's/host: //p')" ]; then \
        rustup target add "$target" && \
        cargo build --release --target "$target" -p edgeshield-cli && \
        cp "target/$target/release/edgeshield" /edgeshield; \
    else \
        cargo build --release -p edgeshield-cli && \
        cp target/release/edgeshield /edgeshield; \
    fi

############################################
# Stage 2: runtime
############################################
FROM debian:bookworm-slim AS runtime

# Runtime deps: libpcap0.8 (the shared lib the binary links against),
# ca-certificates (for HTTPS webhook/ntfy/email/MQTT-TLS calls), and
# tini as PID 1 for proper signal forwarding (SIGINT/SIGTERM).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Create the config + data directories. These are intended to be
# backed by volumes so config and the SQLite DB survive restarts.
RUN mkdir -p /etc/edgeshield /var/lib/edgeshield /run

# Copy the binary from the builder stage.
COPY --from=builder /edgeshield /usr/bin/edgeshield

# Copy the entrypoint shim that generates a first-run config if none
# is mounted, then execs the daemon.
COPY dist/docker/entrypoint.sh /usr/local/bin/edgeshield-entrypoint.sh
RUN chmod +x /usr/local/bin/edgeshield-entrypoint.sh

# Expose the REST API port. With --net=host this is informational.
EXPOSE 8080

# Persist config + SQLite data.
VOLUME ["/etc/edgeshield", "/var/lib/edgeshield"]

# tini forwards signals to the entrypoint shim so Ctrl+C / docker stop
# work. The shim execs `edgeshield run` once the config is in place.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/edgeshield-entrypoint.sh"]