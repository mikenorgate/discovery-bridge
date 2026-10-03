# Packages and router support

Build native artifacts with Go 1.27.1, Python 3 and `dpkg-deb`:

```sh
make artifacts VERSION=0.1.0-rc.1
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
recovery. Container releases and deployment qualification remain in progress.
