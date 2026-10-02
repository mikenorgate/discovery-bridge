# Discovery Bridge

Discovery Bridge connects LAN mDNS/DNS-SD discovery with Kubernetes clients and
explicitly published Services. Avahi owns LAN browsing, probing and publication.
The adapters retain record expiry, apply address policy and answer opted-in pods
without forwarding LAN questions into them or advertising individual pods.

The Go port is in progress. The CLI currently provides registry descriptions;
the tested Go libraries implement source policy, translation eligibility,
namespace socket creation and descriptor passing. Runtime daemons and release
packages are still being implemented. The Python snapshot is a behavioral
reference, with synthetic fixtures; it is not the new deployment runtime.

## Build

Use Go **1.27.1**. It is pinned in `go.mod`, `.go-version` and CI.

```sh
make test
make check
make build
dist/discovery-bridge registry describe --locale de _http._tcp
```

The build embeds the pinned Avahi and IANA service type data. Unknown observed
types retain their raw description. Generated service names follow RFC6335.

Run the reference tests with Python 3.14 and hash-verified dependencies:

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary=:all: -r reference/python/requirements-test.txt
cd reference/python
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python -m unittest discover -s tests -v
```

Linux namespace integration tests require root and an isolated test environment
with `iproute2` and `util-linux`. CI runs them on disposable native AMD64 and
ARM64 runners. `go test -tags integration ./internal/linuxnet` creates disposable
network namespaces and verifies IPv4/IPv6 mDNS sockets and namespace restoration.

## Configuration and deployment

Network ranges, interfaces, admission rules, translator settings and endpoint
addresses belong to deployment configuration. Examples use synthetic devices
and isolated test networks. The public repository contains application source,
registry data and tests; deployment inventories and captured traffic stay with
the operator's infrastructure repository.

The [compatibility contract](docs/CONTRACT.md) records the behavior the port must
preserve. Binaries, Debian packages and multi-architecture containers will share
one versioned source build. Router deployment and Kubernetes reconciliation
remain the infrastructure owner's responsibility.

The [MIT license](LICENSE) covers project source. Pinned third-party registry
data retain their [upstream notices](registry/COPYING.avahi).
