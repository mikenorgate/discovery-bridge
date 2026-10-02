#!/usr/bin/env bash
set -euo pipefail
: "${MDNS_LAB_IMAGE:?Set an existing Python 3.13/iproute2/openssl lab image ID}"
: "${MDNS_LAB_DEPS:?Set the directory containing hash-verified Python dependencies including zeroconf}"
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deps_dir=$(realpath -- "$MDNS_LAB_DEPS")
name="discovery-bridge-broker-$(cat /proc/sys/kernel/random/uuid)"
cleanup() { podman rm --force "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=5s 60s podman run --rm --name "$name" \
  --pull=never --network=none --read-only --tmpfs /run --tmpfs /tmp \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-drop NET_RAW --memory 256m --pids-limit 64 \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/app:/deps \
  --env MDNS_ISOLATED_LAB=1 \
  --mount "type=bind,src=$source_dir,target=/app,ro" \
  --mount "type=bind,src=$deps_dir,target=/deps,ro" \
  --entrypoint /usr/bin/python3 "$MDNS_LAB_IMAGE" /app/tests/broker_lab.py
