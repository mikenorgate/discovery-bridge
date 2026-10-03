# Kubernetes Service publication

Run one `kubernetes-publisher` process with read-only Kubernetes credentials.
It selects configured Service ports, sends leased intents to the router and
withdraws them when readiness is lost. Avahi probes and publishes the resulting
DNS-SD records on the configured LANs. Pod catalogs retain the UID-based names.

Publication is disabled when the router omits `publication`. To enable it, add
an explicit VIP source to `sources` and a separate listener:

```json
"sources": {
  "lan-a": ["192.0.2.0/24", "2001:db8:1::/64"],
  "kubernetes": ["2001:db8:ff00::/60"]
},
"publication": {
  "host": "2001:db8:1::1",
  "port": 9444,
  "clients": ["2001:db8:ffff::22/128"],
  "source": "kubernetes"
}
```

Replace documentation addresses with operator-owned settings. The publication
source must be separate from LAN observation sources, and its VIP ranges must
not overlap their native ranges. Catalog clients have no publication authority.
Apply firewall rules to the separate listener in the infrastructure repository.

The producer uses its own configuration:

```json
{
  "enabled": true,
  "kubectl": ["/usr/bin/kubectl"],
  "kubeconfig": "/etc/discovery-bridge/kubeconfig",
  "gateway": {"host": "2001:db8:1::1", "port": 9444},
  "vip_networks": ["2001:db8:ff00::/60"],
  "forbidden": ["2001:db8:f000::/56"],
  "services": [{
    "namespace": "services",
    "name": "example",
    "port": "http",
    "type": "_http._tcp",
    "instance": "Example web",
    "txt": {"path": "/"},
    "subtypes": ["test"]
  }]
}
```

```sh
discovery-bridge kubernetes-publisher --config /etc/discovery-bridge/services.json
```

Grant `get` on the selected Services and `list` on EndpointSlices in their
namespaces. Use a verified HTTPS API endpoint and mounted read-only kubeconfig;
the process needs no Linux capabilities. The existing `kubectl` adapter bounds
command duration and output. No Kubernetes client library is required.

## Admission and names

A selection identifies one namespace, Service and named external port. Require
a LoadBalancer Service, an admitted numeric VIP and a matching EndpointSlice
owned by that Service UID. Endpoints must be explicitly ready, serving when that
condition is present, and not terminating. Services with
`publishNotReadyAddresses` are withheld. Paginated, racing or failed API reads
produce an empty replacement. ClusterIPs and known endpoint addresses are
excluded from the VIP list.

The published SRV port is the Service port. Backend addresses and `targetPort`
remain in the Kubernetes API. Service recreation changes the UID-based names:
`kube-<12 hex digits>.local` and `<instance>-<8 hex digits>._service._tcp.local`.
LAN aliases use the existing SQLite ownership rules. Records include type
enumeration, PTR, SRV, TXT, A/AAAA and configured subtype PTRs. TXT values are
literal UTF-8 strings. Unknown valid service types are accepted; generated types
must meet RFC6335 naming rules.

The producer supports at most 16 selections and four VIPs per selection. Each
full replacement has a 15-second absolute lease and is sent again after five
seconds. Retransmissions cannot renew the same lease. The receiver independently
expires a stopped or unreachable producer using wall and monotonic clocks.
Optional Service records are withheld when they would exceed the existing
catalog or LAN publication budgets; native device discovery retains capacity.

When translation is enabled, VIP records use the same readiness sampler as
device records. An IPv4 answer for an IPv6 VIP requires an existing ready NAT46
mapping. Discovery never creates one. Mapping expiry removes the derived
address; Service expiry removes the complete Service graph.

CI checks both producer/receiver directions against the Python reference,
including DNS wire names and opaque TXT data. The real Avahi fixture exercises
the compiled producer with synthetic API responses, cross-LAN IPv4/IPv6
publication, readiness goodbyes, stopped-producer expiry and recovery. It does
not require access to an operator's cluster.
