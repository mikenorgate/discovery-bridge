# Router support files

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

CI verifies the units and account/file setup in Debian 13, including repeat
provisioning with retained database contents. The real Avahi fixture verifies
the account-specific D-Bus methods. Package assembly and installed-service
qualification are still in progress.
