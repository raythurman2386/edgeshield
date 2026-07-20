#!/bin/sh
# EdgeShield container entrypoint shim.
#
# Wraps `edgeshield run` so that if no config file is present at
# /etc/edgeshield/config.toml (e.g. the user mounted an empty volume),
# we generate a first-run config non-interactively before starting
# the daemon. This mirrors the `edgeshield setup --non-interactive`
# flow and makes `docker run` work with zero config.
#
# If a config already exists (mounted by the user, or baked into the
# image), it is left untouched.
#
# Signals (SIGINT/SIGTERM) are handled by tini (PID 1); this shim just
# execs the daemon so it becomes the foreground process.

set -eu

CONFIG="${EDGESHIELD_CONFIG:-/etc/edgeshield/config.toml}"
INTERFACE="${EDGESHIELD_INTERFACE:-eth0}"
API_PORT="${EDGESHIELD_API_PORT:-8080}"
DB_PATH="${EDGESHIELD_DATABASE_PATH:-/var/lib/edgeshield/edgeshield.db}"

if [ ! -f "$CONFIG" ]; then
    echo "edgeshield: no config at $CONFIG — generating first-run config"
    mkdir -p "$(dirname "$CONFIG")"
    /usr/bin/edgeshield setup \
        --non-interactive \
        --config "$CONFIG" \
        --interface "$INTERFACE" \
        --api-port "$API_PORT" \
        --database-path "$DB_PATH" \
        --force
fi

exec /usr/bin/edgeshield run --config "$CONFIG"