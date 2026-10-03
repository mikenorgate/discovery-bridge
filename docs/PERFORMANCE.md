# Go and Python comparison

Measured on 3 October 2026, Linux AMD64. The Go executable is the downloaded
`v0.1.0` release, built with Go 1.27.1 at `170fd20`. Python 3.13.5 runs the
unchanged reference tagged `python-reference-20261003`.

## Worker workload

`tests/compare_runtime.py` runs both workers against the same HTTP gateway and
isolated IPv6 pod namespace. A catalog contains 16 synthetic services, with
81 PTR/SRV/TXT/A/AAAA records. Each worker answers 48 questions in six seconds:
16 AAAA, 16 SRV and 16 TXT. Every reply must retain the expected record data.
Unexpected questions fail the run. Both workers refresh every five seconds,
retain the existing response delay and run with UID/GID 65532, no effective
capabilities and no-new-privileges. Go uses `GOMAXPROCS=2`.

Ten pairs alternate execution order, starting a fresh worker each time.
Samples exclude startup and warmup. CPU is worker process time from `/proc`;
RSS and thread counts are sampled after each reply. The fixture, gateway and
client are outside those measurements. Image assembly finished before these
measurements started.

| Metric | Go median (range) | Python median (range) |
| --- | --- | --- |
| CPU seconds per 48 questions | 0.235 (0.20–0.25) | 1.565 (1.18–1.64) |
| Highest sampled RSS, MiB | 21.28 (18.44–23.20) | 31.03 (30.85–31.13) |
| Highest sampled threads | 8–9 | 1 |
| Mean query response, ms | 85.55 (77.38–90.97) | 100.66 (92.06–103.73) |
| Per-run 95th percentile response, ms | 127.64 (120.35–133.27) | 145.25 (135.33–150.41) |

On this workload, paired mean CPU use fell by roughly 85% and sampled RSS by
roughly 33%. A paired bootstrap with 10,000 resamples gives 95% intervals of
84.2–85.1% and 29.2–36.0%, respectively. Response times include mDNS's intentional
delay, and neither implementation exceeds its existing resource limits.
These results cover one worker and this catalog size; they do not measure the
router, Avahi, total broker memory, ARM64 performance or sustained LAN traffic.

## Container sizes

Both AMD64 images use the same pinned Debian 13 slim base and signed
`20260918T000000Z` snapshots, kubectl 1.36.3, crictl 1.36.0, iproute2 and CA
certificates. Go uses the published OCI archive. Python uses the frozen
reference Containerfiles with those common base and CLI inputs.

| Size | Go | Python reference |
| --- | --- | --- |
| Uncompressed layers reported by Podman | 205,955,635 bytes | 341,225,074 bytes |
| Exported OCI archive | 80,788,480 bytes | 130,612,736 bytes |

The image comparison includes packaging changes: the reference retains pip
and copies CLI tools through an intermediate image layer. This is not a
measurement of language overhead alone. Neither comparison image contains
deployment configuration or accesses a cluster.

## Reproduce the worker run

On native Linux AMD64 with Podman and runc, download the release tarball and
verify it against the release's `SHA256SUMS`. Extract its executable into
`dist/measurement/discovery-bridge`. Download the reference's two hash-verified
wheels into the same ignored directory:

```sh
mkdir -p dist/measurement
python3 -m pip download --require-hashes --only-binary=:all: \
  -r reference/python/requirements-gateway.txt --dest dist/measurement
podman build --file tests/Containerfile.integration \
  --tag discovery-bridge-integration tests
podman run --runtime=runc --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,exec --tmpfs /deps --memory 384m --pids-limit 96 \
  --cap-drop ALL --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add SETUID \
  --cap-add SETGID --cap-add NET_ADMIN --cap-add KILL \
  --security-opt apparmor=unconfined --security-opt no-new-privileges \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/source/reference/python:/deps \
  --volume "$PWD:/source:ro" --volume "$PWD/dist/measurement:/results" \
  --entrypoint /bin/sh discovery-bridge-integration -ec '
    python3 -m zipfile -e /results/dnspython-2.8.0-py3-none-any.whl /deps
    python3 -m zipfile -e /results/h11-0.16.0-py3-none-any.whl /deps
    python3 /source/tests/compare_runtime.py --go-binary /results/discovery-bridge \
      --repeat 10 --queries 48 --output /results/worker.json
  '
```

The container privileges belong to the namespace fixture. Each measured worker
has no capabilities. Keep generated inputs and results outside tracked source.
Run the comparison separately from image builds and other tests.
