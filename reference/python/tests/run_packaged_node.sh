#!/usr/bin/env bash
# Test the baked image source, then export that same image. No registry writes.
set -euo pipefail
arch=${1:?Usage: run_packaged_node.sh amd64|arm64}
case "$arch:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) echo 'Native architecture required' >&2; exit 64;; esac
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output_dir="$source_dir/build-inputs/$arch"
image_id=$(cat "$output_dir/node.iid")
deps_dir=$(mktemp -d)
name="discovery-bridge-packaged-$(cat /proc/sys/kernel/random/uuid)"
cleanup() { podman rm --force "$name" >/dev/null 2>&1 || true; rm -rf -- "$deps_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Ephemeral test dependencies, installed only from verified wheels.
podman run --rm --name "$name" --timeout 90 --pull=never --network=none \
  --read-only --tmpfs /tmp --env PYTHONDONTWRITEBYTECODE=1 \
  --mount "type=bind,src=$source_dir,target=/inputs,ro" \
  --mount "type=bind,src=$deps_dir,target=/test-deps" \
  --entrypoint /usr/bin/python3 "$image_id" -m pip install --no-compile \
  --no-index --no-cache-dir --require-hashes --target=/test-deps \
  --find-links="/inputs/build-inputs/$arch/lab-wheels" \
  -r /inputs/requirements-test.txt -r /inputs/requirements-pod-lab.txt
common=(--rm --name "$name" --timeout 150 --pull=never --network=none
  --read-only --tmpfs /tmp --tmpfs /run --env PYTHONDONTWRITEBYTECODE=1
  --env PYTHONPATH=/app:/opt/discovery-deps:/deps
  --mount "type=bind,src=$source_dir/tests,target=/app/tests,ro"
  --mount "type=bind,src=$deps_dir,target=/deps,ro"
  --entrypoint /usr/bin/python3)
podman run "${common[@]}" \
  --mount "type=bind,src=$source_dir/registry,target=/app/registry,ro" \
  --mount "type=bind,src=$source_dir/node_candidate/config.disabled.json,target=/app/node_candidate/config.disabled.json,ro" \
  --mount "type=bind,src=$source_dir/../router_factory/scripts,target=/router_factory/scripts,ro" \
  --mount "type=bind,src=$source_dir/../filter_plugins,target=/filter_plugins,ro" \
  --mount "type=bind,src=$source_dir/discovery/router_candidate.py,target=/service_discovery/discovery/router_candidate.py,ro" \
  "$image_id" -m unittest discover -s /app/tests -v > "$output_dir/unit-tests.log" 2>&1
# This lab creates/mounts disposable netns; Ubuntu's container AppArmor profile
# denies those mounts. Relax AppArmor only for this isolated test container.
# The deployed broker has its separately approved container-only AppArmor exception.
podman run "${common[@]}" --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-drop NET_RAW \
  --security-opt apparmor=unconfined \
  --memory 256m --pids-limit 64 --env MDNS_ISOLATED_LAB=1 \
  "$image_id" /app/tests/node_lab.py > "$output_dir/runtime.jsonl" 2> "$output_dir/runtime.stderr"
python3 - "$output_dir/runtime.jsonl" <<'PY'
import json,sys
from pathlib import Path
cases=[json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
assert len(cases)==9 and all(case['status']=='pass' for case in cases), 'Runtime acceptance incomplete'
print('Packaged runtime: 9 checks passed')
PY
podman save --format oci-archive --output "$output_dir/node.oci.tar" "$image_id"
(cd -- "$output_dir" && sha256sum node.oci.tar > node.oci.tar.sha256)
