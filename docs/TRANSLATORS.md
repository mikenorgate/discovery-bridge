# Translator readiness

Translation is disabled when the router configuration omits `translators`.
Discovery Bridge reads existing TAYGA state. It never starts a translator,
changes a route, creates a mapping or sends a readiness probe.

Add an object like this to the router configuration, replacing the documentation
networks and paths with operator-owned settings:

```json
"translators": {
  "nat64_prefix": "2001:db8:64::/96",
  "nat46_pool": "198.51.100.0/24",
  "reserved": ["198.51.100.1"],
  "ip": ["/usr/sbin/ip"],
  "systemctl": ["/usr/bin/systemctl"],
  "nat46": {
    "interface": "xlate46",
    "unit": "translator46.service",
    "config": "/etc/translator46.conf",
    "binary": "/usr/sbin/tayga",
    "ipv4": "198.51.100.1",
    "ipv6": "2001:db8:46:ffff::1",
    "prefix": "2001:db8:46::/96",
    "data_directory": "/var/lib/translator46"
  },
  "nat64": {
    "interface": "xlate64",
    "unit": "translator64.service",
    "config": "/etc/translator64.conf",
    "binary": "/usr/sbin/tayga",
    "ipv4": "203.0.113.1",
    "ipv6": "2001:db8:64:ffff::1",
    "prefix": "2001:db8:64::/96",
    "data_directory": "/var/lib/translator64",
    "dynamic_pool": "203.0.113.0/24"
  }
}
```

Either profile can be omitted. The translation ranges remain explicit so pod
agents can validate derived records with the same policy. Translation prefixes,
alias pools and the NAT64 dynamic pool are excluded from native observations.

The configuration must be a root-owned regular file on a read-only filesystem,
without group or world write permission. Its directives must match the profile
exactly. NAT46 accepts unique inline `map IPv4 IPv6` entries; external map files
and reloadable directives are rejected. NAT64 requires a TAYGA build supporting
`udp-cksum-mode calc`. The running process must use the configured binary,
`--nodetach` and one `--config` argument. Optional `--pidfile`, `--user` and
`--group` arguments are accepted.

One sampler inside the collector checks service identity before and after
reading the configuration, process arguments, TUN addresses and main-table
routes. NAT46 targets need a specific usable route through an admitted LAN;
default routes, blackholes and tied routes through other interfaces do not
confirm readiness. A sample lasts at most ten seconds and is polled again two
seconds after the preceding sample completes. Reads and heartbeats cannot
extend it. Clock discontinuities withhold translation.

LAN aliases and the pod catalog use the same sampled readiness. Native address
families take precedence. NAT46 A answers require an existing loaded static map;
an unmapped IPv6 device keeps its native discovery records. Loss of one
translator withdraws its derived addresses while preserving native discovery
and the other translator's readiness. Pod agents also expire derived addresses
without a new gateway response.
