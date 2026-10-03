# Compatibility contract

The Go port preserves DNS-SD behavior, the HTTP feed and the SQLite schema.
Installation configuration supplies network ranges, interface names, opt-in
labels, translation settings and filesystem locations.

## Discovery

Records have a source link and an independent expiry. Withdraw records when
their source lease expires or a goodbye arrives. Keep PTR/SRV/TXT/address chains
within one source. Withhold ambiguous original hostnames and incomplete service
instances. Unknown observed types and subtypes remain discoverable.

Avahi browser events are hints with no renewable TTL. Export requires matching
wire evidence on the same interface generation and transport family. A cached
hint cannot renew an expired packet observation. Lose all hints when Avahi's
D-Bus owner changes, its running state ends or a bounded event queue overflows.
Observe kernel-reassembled raw UDP copies without competing for Avahi's unicast
port. Require receive metadata, hop 255, UDP port 5353 and valid checksums.
Queued observations retain their receive timestamps. A delayed packet cannot
renew an expired observation or undo a newer cache flush on another family.

Retain known-answer suppression, cache-flush ownership, QU questions, legacy
unicast replies, family-specific multicast history and bounded packet sizes.
Questions and answers sent by pods never become LAN advertisements or catalog
observations. Pod access requires its configured opt-in label and an independent
operator rule matching namespace, service account and workload labels.

NAT64 synthesis requires a ready translator. NAT46 A records require an existing
ready mapping with matching installed and acknowledged generations. Discovery
never allocates mappings or changes application access policy. Native records
remain available when translation is unavailable.

## Feed and publication

HTTP catalog envelopes use schema 1 with `generation`, `policy_revision`,
`nonce`, `unique_rrsets` and `snapshot`. Snapshots carry `epoch`, `revision`,
`issued_at`, `valid_until` and `records`; snapshot schema 2 supports translated
records with `native_id`. Preserve source policy, byte/record bounds, replay
rejection and both wall-clock and monotonic expiry. A renewal must not extend an
already observed record beyond its actual source lifetime.

Keep catalog, lookup and Service publication as separate admitted operations.
Service publication requires explicit selection, ready endpoints, an admitted
LoadBalancer address and the external Service port. Ownership and lease loss
withdraw advertisements. The LAN publisher expires producer leases independently
of collector progress.

LAN publication IPC remains newline-delimited JSON with `boot`, `sequence`,
`issued` and complete `groups`. The Unix peer UID admits one local producer.
Each group carries an approved interface/family, an absolute monotonic deadline
and coherent records with persistent name ownership. Receiver cache TTL is one
second. Disconnect, invalid replacement or an expired lease withdraws ownership.
Run groups concurrently within the twelve-group bound; retain each group's
ordered D-Bus calls. A stalled D-Bus writer cannot extend a publication lease.
The collector and publisher capture their own topology generations. A link or
address notification closes captured sockets and withdraws the old epoch before
reopening. Reconnecting a collector requires fresh wire evidence even while
Avahi retains its cache. The pod feed preserves original names as shared answers;
LAN publication probes stable aliases and original hosts on their other links.

Broker IPC remains bounded JSON over Unix `SOCK_SEQPACKET`, with at most two
socket descriptors per message. The broker owns namespace admission; the
unprivileged worker receives sockets and leases. Worker requests cannot choose
host PIDs, network namespaces or commands. Broker death terminates the worker,
including while that worker is stopped.

## Persistent state

Keep these SQLite tables and canonical DNS wire encodings:

- `identities(identity, source, original, alias, collision)`
- `reservations(name, identity)`
- `gateway_generation(id, generation)`

Alias identity hashes combine the source, a zero byte and the canonical original
DNS name. Existing reservations and aliases remain stable. WAL, synchronous
transactions and producer locks retain their current behavior. Test the Python
reference reopening a database written by Go before relying on rollback.
