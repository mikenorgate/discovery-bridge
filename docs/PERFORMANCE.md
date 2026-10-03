# Worker measurements

Measured on 3 October 2026, Linux AMD64, using the downloaded `v0.1.0`
executable built with Go 1.27.1 at `170fd20`.

The workload used an isolated IPv6 pod namespace and 16 synthetic services,
with 81 PTR/SRV/TXT/A/AAAA records. Each worker answered 48 questions over six
seconds: 16 AAAA, 16 SRV and 16 TXT. Every reply retained the expected data.
The worker refreshed every five seconds and ran with UID/GID 65532, no effective
capabilities, no-new-privileges and `GOMAXPROCS=2`.

Ten runs started a fresh worker each time. Samples excluded startup and warmup.
CPU came from worker process time in `/proc`; RSS and thread counts were sampled
after replies. The gateway and client were outside these measurements.

| Metric | Median (range) |
| --- | --- |
| CPU seconds per 48 questions | 0.235 (0.20–0.25) |
| Highest sampled RSS, MiB | 21.28 (18.44–23.20) |
| Highest sampled threads | 8–9 |
| Mean query response, ms | 85.55 (77.38–90.97) |
| Per-run 95th percentile response, ms | 127.64 (120.35–133.27) |

Response times include mDNS's intentional delay. These historical measurements
cover one worker and this catalog size. They do not measure the router, Avahi,
total broker memory, ARM64 performance or sustained LAN traffic.

The published AMD64 image occupied 205,955,635 bytes of uncompressed layers;
its OCI archive was 80,788,480 bytes. It includes kubectl, crictl, iproute2 and CA
certificates on the pinned Debian 13 slim base.

Current CI checks worker permissions, resource limits and replies using the
actual installed binary and imported OCI image on both native architectures.
The disposable systemd fixture also checks router limits and watchdog recovery.
These qualification checks verify behavior and limits; they are not benchmarks
of the workload above.
