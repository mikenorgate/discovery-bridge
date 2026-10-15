# Discovery DNS

The optional `dns-proxy` role answers ordinary DNS questions using native mDNS
observations from a selected link. Applications can use names such as
`sensor.alpha.devices.example.test` without implementing mDNS themselves.
This feature is not enabled by package installation.

Each link has its own DNS zone. Identical `.local` names on different links do
not collide, and there is no flat alias spanning links. DNS answers do not grant
application access: routing, translation and firewall policy remain independent.

## Resolver path

```text
client → recursive resolver / DNS64 → dns-proxy → local native-query socket
                                                   ↓
                                       collector → selected LAN
```

The collector owns Avahi and packet observation. The DNS frontend has no raw
sockets, publication permission or access to the identity database. Its local
query protocol authenticates both Unix peer UIDs and carries source-qualified
DNS wire messages. It cannot create mappings or advertise records.

Use a recursive resolver such as Unbound for caching, DNS64 and synthetic reverse
lookups. The frontend never synthesizes addresses. Configure exact forward or
stub zones with fallback disabled, allow eight seconds for a direct native
authority query and thirty seconds across chained DNS64 resolvers, and disable
minimum-TTL inflation and stale answers on this path.
Allow a 30-second UDP reply lifetime (`discard-timeout: 30000` in Unbound):
chained DNS64 absence checks can repeat six-second AAAA and A misses. Declare
specific discovery/reverse zones `transparent` so inherited private empty zones
cannot answer first; a nonexistent `nodefault` child does not override its parent.
Keep private discovery zones outside public DNSSEC validation. Preserve any
existing static reverse answers with more-specific resolver overrides.

On a dedicated private resolver, disable QNAME minimisation for this path
(`qname-minimisation: no` in Unbound). Otherwise a service lookup such as
`_http._tcp.alpha.devices.example.test` can first trigger an address query for
`_tcp.alpha.devices.example.test`, adding a six-second multicast miss before
the requested service lookup. Keep QNAME minimisation enabled on the public
recursive resolver; forward private zones to the dedicated instance.

TCP queries on one connection run concurrently and replies may arrive out of
order, matched by DNS message ID. A cold lookup does not delay a cached answer
on that connection. The frontend accepts at most 64 TCP connections across all
listeners and 16 in-flight requests per connection, closing each connection
after 64 requests have completed. Excess requests receive SERVFAIL without
entering a work queue. Disconnect and shutdown cancel pending lookups.

## Configuration

Start with [dns.json](../packaging/examples/dns.json). Replace its documentation
addresses and domains before use. Add a `native` object to `router.json`:

```json
{
  "socket": "/run/discovery-bridge-native/query.sock",
  "user": "discovery-bridge-dns",
  "sources": ["alpha", "beta"]
}
```

The listed sources must already be configured physical collector interfaces.
Use the same socket in `dns.json`, and select the collector's account through
`collector_user`. Supply explicit DNS client prefixes; an unrestricted `/0`
is rejected. Do not expose the listener to the Internet.

Each `links` entry declares a source, a rich-text `service_domain`, an LDH
`host_domain`, and its native address prefixes. The two domains may be identical
when the deployment does not require separate rich-text and hostname namespaces.
Zones must be distinct and non-overlapping. Reverse delegations require octet-
aligned IPv4 or nibble-aligned IPv6 prefixes. Exclude translated, reserved,
backend and unrelated networks from these prefixes.

Set `nameservers` to the complete authoritative NS set, with names outside every
proxied child zone. Publish those names and child delegations in the parent
authority. Publish DNS-SD `b`, `db` and `lb` enumeration PTRs in the deployment's
search domains; `default_source` must identify a listed browse source.

Before starting the optional unit:

```sh
discovery-bridge collector --config /etc/discovery-bridge/router.json --check
discovery-bridge dns-proxy --config /etc/discovery-bridge/dns.json --check
```

The package supplies locked accounts, a separate native-query socket directory
and `discovery-bridge-dns.service`. The DNS account is not in the shared database
group. The unit has only `CAP_NET_BIND_SERVICE`, not `NET_RAW` or `NET_ADMIN`.
It installs no active configuration and is not enabled automatically.

## RFC 8766 behaviour

This is an unsigned, ordinary-query discovery proxy as described by
[RFC 8766](https://www.rfc-editor.org/rfc/rfc8766.html). DNS Push, LLQ, dynamic
updates, zone transfers and online DNSSEC signing are not implemented.

| Requirement | Implementation and checks |
| --- | --- |
| Link-qualified forward and reverse lookup | Explicit source zones; reverse questions retain their original wire name; source and collision tests |
| Native mDNS ownership | Existing Avahi connection for typed interests; existing packet sender for genuine ANY; provenance and epoch checks |
| Fresh cache and cold lookup | Wire TTLs only; fresh answers cause no multicast; coalesced cold interests end after six seconds with NOERROR/NODATA |
| Name translation | DNS-label suffix mapping for owners and structured RDATA; external names and TXT bytes unchanged; no IDNA conversion |
| Usable results | Reject unsafe or foreign addresses; suppress incomplete local SRV/PTR chains by default; dependency lifetime tests |
| TTL and negative answers | Maximum ten seconds, no longer than supporting evidence; SOA minimum ten, serial zero and standard proxy timers |
| Authority metadata | Complete apex NS/SOA; no multicast for administration or unsupported update/Push/LLQ discovery |
| Type introspection | Native ANY for NSEC/NSEC3 requests; narrow generated intervals, never copied mDNS denial records |
| DNS transports | UDP 512, EDNS up to 1232, TC truncation and concurrent TCP replies; pipeline, disconnect and real socket integration tests |
| Resource bounds | 64 active queries, 64 TCP connections, 16 in-flight requests per connection, 16 native interests per source, bounded messages and dependency traversal; cancellation and race tests |

Apply a shared per-link multicast query limiter at the host firewall, including
both address families while excluding responses. The deployment recommendation
is 20 queries per second per link. The frontend's concurrency bounds alone are
not a packet-rate limiter.

## Security boundaries

mDNS devices and DNS clients are untrusted inputs. The authenticated native
socket is the boundary between observation and DNS presentation. Neither a DNS
answer nor an mDNS announcement is proof of device identity.

- A device may spoof another device's name or native address on its admitted
  link. Source-prefix and packet-provenance checks limit scope but cannot
  authenticate mDNS. Use application authentication and firewall rules.
- A client may try to query another zone, update records or request a transfer.
  The authority refuses these operations; the frontend has no write protocol.
- A client may flood cold names or hold connections open. Deadlines, query
  coalescing, message bounds, descriptor limits and the link limiter bound work.
- A stale Avahi hint may outlive the device. Only fresh wire evidence can renew
  DNS records; epoch loss withdraws authority and returns SERVFAIL, not absence.
- A name may contain escaped bytes or resemble another zone. Mapping operates
  on DNS labels with ASCII case folding; TXT and unknown RDATA stay opaque.
- A compromised DNS frontend may query selected links but cannot write the
  publisher database, join unselected sources or acquire raw network access.

Names and DNS queries can reveal device information to admitted resolver clients.
Choose client ACLs accordingly. This is not a confidential or authenticated
discovery protocol.

## Qualification

Run unit/race tests, then the real transport and IPC tests:

```sh
go test -race ./...
go test -race -tags integration ./internal/native ./internal/discoverydns
```

The native socket test runs as a non-root account. The real resolver-chain test
requires `unbound` in PATH or `UNBOUND_TEST_BINARY`. Set `COREDNS_TEST_BINARY` to
qualify an existing CoreDNS release too. It checks private DNS64, native IPv6,
synthetic PTR conversion and six-second cold answers. Missing external binaries
are reported as skipped checks, not evidence of qualification.

`COREDNS_TEST_FORWARD_OPTIONS` supplies test-only forward options. CoreDNS 1.14.2
fails the cold-query gate with its fixed timeout, including the retry-only
`prefer_udp`/`max_fails 0` workaround. A resolver with a configurable upstream
read timeout is needed; do not hide that failure by warming the cache first.

Before deploying, verify the actual resolver chain, native query ownership,
parent delegations, existing DNS records and authenticated application access.
Retain any application-specific resolver workaround until that application's
replacement path passes. Removing DNS forwarding and stopping only the optional
frontend leaves the legacy pod discovery path unchanged.
