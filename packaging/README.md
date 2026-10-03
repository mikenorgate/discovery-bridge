# Packages and router support

Build native artifacts with Go 1.27.1 and `dpkg-deb`:

```sh
make artifacts VERSION=0.1.1
```

The builder compiles once with CGo disabled and trimmed source paths, then puts
those same executable bytes in a binary archive and Debian package under
`dist/releases/<architecture>`. It records the actual compiler, source commit,
source cleanliness, compatibility schemas and SHA256 checksums. Artifacts
include registry data and licenses for the linked Go modules. Local builds may
record an uncommitted source tree; published candidates require clean source.

Debian packages target Debian 13. Install them with `apt install ./<package>.deb`.
Installation creates locked accounts and shared-state files, retaining existing
contents. It leaves the units disabled and installs the example under
`/usr/share/doc/discovery-bridge/examples`, with no active configuration.
Package upgrades leave service restart scheduling to the infrastructure owner.
Stop the previous publisher before replacing a running installation.

`cmd/release-tools` builds the packages and runs disposable qualification checks.
It uses the same pinned Go SDK as the application and is excluded from release
packages and runtime images. Deployment hosts need the released executable.

Build a native container and OCI archive from that executable with Podman:

```sh
make container
```

`packaging/container-inputs.json` pins the Debian 13 base, signed Debian
snapshots, CLI versions and download checksums. The generated context contains
only the three binaries, licenses and build metadata. The image includes `ip`
and CA certificates, defaults to UID/GID 65532 and runs `version` until a role
is selected. Select `broker --config <path>` or
`kubernetes-publisher --config <path>` for deployment. The broker requires root
and its existing namespace capabilities; the Service producer needs none.
Supply configuration and API/runtime access through the infrastructure owner.

The builder exports under `dist/releases/<architecture>` and loads that OCI
archive as `localhost/discovery-bridge-qualified:<architecture>`. Checks verify
every referenced blob, architecture, imported executable bytes, CLI versions
and image defaults. CI runs the actual broker and Service producer from this
imported image using runc, with isolated API/CRI JSON fixtures. It tests pod admission and
withdrawal, native replies, Service readiness withdrawal, independent expiry
and recovery.

## Candidate releases

Start a candidate from a clean source commit with:

```sh
gh workflow run release.yml --repo mikenorgate/discovery-bridge --ref main -f version=0.1.1
```

A pushed `vMAJOR.MINOR.PATCH` tag also starts the workflow. Both paths run the
same native AMD64 and ARM64 qualification used by CI. The publishing job takes
only the resulting artifacts; it does not rebuild them. It joins their OCI
manifests into one index and uses Skopeo to preserve each qualified digest.
Registry checks verify the index and both platform manifests after publication.

The GitHub prerelease contains both Debian packages, binary tarballs, offline
OCI archives, `SHA256SUMS` and `release.json`. Metadata records the source commit,
Go compiler, compatibility schemas, native qualification run, package checksums,
platform image digests and combined image digest. Deploy by those recorded
checksums and digests. Do not reuse a version for changed source or artifacts.

Keep the release marked as a prerelease until the infrastructure owner's live
acceptance passes. Promote that existing release with:

```sh
gh release edit <tag> --prerelease=false
```

Promotion does not change its artifacts or image digest.
Local reproduction uses the two `make` commands above on native Linux runners
with the pinned Go compiler, `dpkg-deb` and Podman. Qualification uses the
commands in `.github/workflows/ci.yml` and needs isolated network namespaces.

This directory provides units, account definitions, shared-state permissions
and D-Bus policy for the Debian package. Package installation must leave
discovery disabled and supply no active router configuration. The example is an operator
template; replace its documentation networks and interface before enabling it.

The collector and publisher have separate locked accounts. Their shared group
can write the identity database and SQLite WAL files. The publisher owns
`/run/discovery-bridge`; the collector connects to its admitted Unix socket.
Both roles retain only `CAP_NET_RAW`, a 128 MiB memory limit and 32 tasks.
`GOMAXPROCS=2` bounds runtime concurrency on hosts with many CPUs. The Avahi
D-Bus policy limits each account to its required methods.

The infrastructure owner supplies `/etc/discovery-bridge/router.json`, Avahi
settings, firewall rules and interface readiness dependencies. Add those
dependencies through systemd drop-ins. If configuration selects other state or
socket directories, also adjust the unit writable paths, runtime directory and
tmpfiles setup. Unit installation and package assembly must preserve the
operator's existing database. Stop the old publisher before starting a new one.

CI checks the artifact file allowlist, ownership, architecture and checksums.
Debian 13 fixtures install, reinstall, remove and restore the package while
retaining database contents and leaving discovery inactive. Restricted network
fixtures select the installed executable for worker replies and real Avahi
collector, publisher and Service-producer behavior. A disposable systemd
container checks unit startup, credentials, resource limits and watchdog
recovery. Live deployment qualification remains with the infrastructure owner.
