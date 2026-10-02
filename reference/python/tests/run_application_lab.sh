#!/usr/bin/env bash
set -euo pipefail
: "${MDNS_AVAHI_IMAGE:?Set the existing Avahi lab image ID}"
: "${MDNS_LAB_DEPS:?Set the verified dependency directory}"
: "${MDNS_ESPHOME_IMAGE:?Set the released ESPHome image ID}"
: "${MDNS_HA_IMAGE:?Set the released Home Assistant image ID}"
: "${MDNS_APP_RESULTS:?Set a new empty results directory}"
case "${MDNS_APP_NETWORK:=ipv6}" in ipv6|dual) ;; *) exit 2 ;; esac
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deps_dir=$(realpath -- "$MDNS_LAB_DEPS")
mkdir -p -- "$MDNS_APP_RESULTS"
results_dir=$(realpath -- "$MDNS_APP_RESULTS")
test -z "$(ls -A -- "$results_dir")"
name="discovery-bridge-app-$(cat /proc/sys/kernel/random/uuid)"
cleanup() {
  touch "$results_dir/stop"
  podman rm --force "$name-esphome" "$name-ha" "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
podman run --detach --name "$name" --pull=never --network=none --read-only \
  --tmpfs /run --tmpfs /tmp --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW \
  --memory 384m --pids-limit 96 \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/app:/deps --env MDNS_ISOLATED_LAB=1 \
  --env "MDNS_APP_NETWORK=$MDNS_APP_NETWORK" \
  --mount "type=bind,src=$source_dir,target=/app,ro" \
  --mount "type=bind,src=$deps_dir,target=/deps,ro" \
  --mount "type=bind,src=$results_dir,target=/lab" \
  --entrypoint /usr/bin/python3 "$MDNS_AVAHI_IMAGE" /app/tests/application_lab.py >/dev/null
for _ in {1..60}; do
  test ! -f "$results_dir/ready.json" || break
  if test "$(podman inspect --format '{{.State.Running}}' "$name")" != true; then
    podman logs "$name" >&2
    exit 1
  fi
  sleep 1
done
test -f "$results_dir/ready.json"
lab_pid=$(podman inspect --format '{{.State.Pid}}' "$name")
pod_namespace="/proc/$lab_pid/root/run/netns/discovery-pod"
for application in esphome ha; do
  app_image=$MDNS_ESPHOME_IMAGE
  if test "$application" = ha; then app_image=$MDNS_HA_IMAGE; fi
  timeout --signal=TERM --kill-after=5s 120s podman run --rm --name "$name-$application" \
    --pull=never --network "ns:$pod_namespace" --read-only --tmpfs /tmp --tmpfs /config \
    --cap-drop ALL --memory 1536m --pids-limit 128 --env PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$source_dir/tests/application_client.py,target=/client.py,ro" \
    --mount "type=bind,src=$results_dir,target=/lab" \
    --entrypoint python "$app_image" /client.py "$application" \
    >"$results_dir/$application.jsonl" 2>"$results_dir/$application.stderr"
done
touch "$results_dir/stop"
podman wait "$name" >"$results_dir/lab.exit"
podman logs "$name" >"$results_dir/lab.log" 2>&1
cat "$results_dir/esphome.jsonl" "$results_dir/ha.jsonl"
python3 - "$results_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
rows = [json.loads(line) for name in ('esphome', 'ha') for line in (root / (name + '.jsonl')).read_text().splitlines()]
assert len(rows) == 10 and all(row['status'] == 'pass' for row in rows), 'application acceptance has failures; preserve evidence'
assert (root / 'lab.exit').read_text().strip() == '0', 'lab process failed'
PY
