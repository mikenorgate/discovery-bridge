# Discovery Bridge

Discovery Bridge connects LAN mDNS/DNS-SD discovery with Kubernetes clients and
explicitly published Services. Avahi owns LAN browsing, probing and publication.
The adapters retain record expiry, apply address policy and answer opted-in pods
without forwarding LAN questions into them or advertising individual pods.

The Go port is in progress. The binary provides the router collector and
independent publisher, node broker, unprivileged responder and registry descriptions.
Tested libraries cover
leased catalogs, DNS-SD responses, address policy, HTTP feeds, SQLite state and
interface-scoped Avahi observations with independent wire expiry.
Router tests use a real Avahi daemon and separate unprivileged processes.
Translator readiness, Kubernetes Service publication and release packages are
still being implemented. The Python
snapshot provides a behavioral reference with synthetic fixtures.

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
with `iproute2`, `util-linux`, `dbus`, `avahi-daemon` and `ethtool`. CI runs them on disposable native AMD64
and ARM64 runners. `go test -tags integration ./internal/linuxnet ./internal/node
./internal/avahi ./internal/observation ./internal/router` checks pod replies,
namespace restoration, worker cleanup, D-Bus ownership loss, fragmented IPv4/IPv6
LAN responses, collector restart and independent publication expiry.
Raw receive copies leave Avahi's UDP port ownership intact. CI also runs these
checks in a restricted Debian 13 container.

With the reference dependencies installed, run
`go test -tags reference ./internal/gateway` to check the Go client against the
Python router's catalog and lookup endpoints.

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

Router roles share one explicit configuration:

```sh
discovery-bridge publisher --config /etc/discovery-bridge/router.json
discovery-bridge collector --config /etc/discovery-bridge/router.json
```

Configure LAN interfaces and families, admitted source ranges, an alias prefix,
the local D-Bus socket, identity database, publisher socket and collector account.
An optional gateway listener requires a numeric bind address and explicit client
ranges. Provision the identity database and its WAL files with group write access
for both accounts. Packaging will provide the account and file setup.

The [MIT license](LICENSE) covers project source. Pinned third-party registry
data retain their [upstream notices](registry/COPYING.avahi).
