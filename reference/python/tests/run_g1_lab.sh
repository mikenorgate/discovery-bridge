#!/usr/bin/env bash
set -euo pipefail
: "${MDNS_AVAHI_IMAGE:?Set existing Python 3.13/Avahi/dbus-daemon/nft lab image ID}"
: "${MDNS_LAB_DEPS:?Set the directory containing verified Python dependencies}"
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deps_dir=$(realpath -- "$MDNS_LAB_DEPS")
name="discovery-bridge-g1-$(cat /proc/sys/kernel/random/uuid)"
cleanup() { podman rm --force "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=5s 170s podman run --rm --name "$name" \
 --pull=never --network=none --read-only --tmpfs /run --tmpfs /tmp \
 --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN --memory 256m --pids-limit 96 \
 --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/app:/deps \
 --env MDNS_ISOLATED_LAB=1 \
 --mount "type=bind,src=$source_dir,target=/app,ro" \
 --mount "type=bind,src=$deps_dir,target=/deps,ro" \
 --entrypoint /usr/bin/python3 "$MDNS_AVAHI_IMAGE" /app/tests/g1_lab.py
