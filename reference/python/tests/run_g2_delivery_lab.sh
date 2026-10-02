#!/usr/bin/env bash
set -euo pipefail
: "${MDNS_AVAHI_IMAGE:?Set the existing Avahi lab image ID}"
: "${MDNS_LAB_DEPS:?Set the verified dependency directory}"
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deps_dir=$(realpath -- "$MDNS_LAB_DEPS")
name="discovery-bridge-g2-$(cat /proc/sys/kernel/random/uuid)"
cleanup() { podman rm --force "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=5s 180s podman run --rm --name "$name" \
  --pull=never --network=none --read-only --tmpfs /run --tmpfs /tmp --tmpfs /lab \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW --memory 384m --pids-limit 96 \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/app:/deps \
  --env MDNS_ISOLATED_LAB=1 --env MDNS_BOUNDARY_LAB=1 \
  --mount "type=bind,src=$source_dir,target=/app,ro" \
  --mount "type=bind,src=$deps_dir,target=/deps,ro" \
  --entrypoint /usr/bin/python3 "$MDNS_AVAHI_IMAGE" /app/tests/application_lab.py
