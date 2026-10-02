"""Read-only readiness for the router's existing immutable TAYGA services.

No allocation, route changes, service control, DNS lookups or network probes.
The local system manager and read-only, root-owned configuration are authority.
"""
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from discovery.policy import MappingReadiness
from discovery.translation import NAT64, POOL, RESERVED, translated_records

LEASE = 10
NAT46_PREFIX = IPv6Network('2001:db8:1000:fd46::/96')
NAT64_PREFIX = IPv6Network((NAT64, 96))
PATHS = {'nat46': '/etc/tayga-nat46.conf', 'nat64-internal': '/etc/tayga-nat64-internal.conf'}


def immutable_config(path):
    """Mutable configuration cannot attest what a running process loaded."""
    with open(path, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not os.fstatvfs(stream.fileno()).f_flag & os.ST_RDONLY):
            raise ValueError('translator configuration must be root-owned and read-only')
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('translator configuration exceeds budget')
    return data


def parse_config(data, kind):
    """Accept the installed static-map profile, not external/reloadable map files."""
    values, maps = {}, {}
    for line in data.decode('ascii').splitlines():
        fields = line.split('#', 1)[0].split()
        if not fields:
            continue
        if fields[0] == 'map' and kind == 'nat46' and len(fields) == 3:
            alias, target = IPv4Address(fields[1]), IPv6Address(fields[2])
            if (alias not in POOL or alias in RESERVED or alias in (POOL.network_address, POOL.broadcast_address)
                    or target.is_unspecified or target.is_loopback or target.is_link_local or target.is_multicast
                    or target.ipv4_mapped or target.scope_id or target in NAT46_PREFIX or target in NAT64_PREFIX
                    or target in maps or alias in maps.values()):
                raise ValueError('invalid or duplicate static map')
            maps[target] = alias
        elif len(fields) == 2 and fields[0] in {'tun-device', 'ipv4-addr', 'ipv6-addr', 'prefix', 'data-dir', 'dynamic-pool', 'udp-cksum-mode'} and fields[0] not in values:
            values[fields[0]] = fields[1]
        else:
            raise ValueError('unsupported or duplicate translator directive')
    required = {'tun-device', 'ipv4-addr', 'ipv6-addr', 'prefix', 'data-dir'}
    if kind == 'nat64-internal':
        required |= {'dynamic-pool', 'udp-cksum-mode'}
    if set(values) != required or values['tun-device'] != kind:
        raise ValueError('incomplete translator profile')
    if IPv6Network(values['prefix']) != (NAT46_PREFIX if kind == 'nat46' else NAT64_PREFIX):
        raise ValueError('unexpected translator prefix')
    IPv4Address(values['ipv4-addr']); IPv6Address(values['ipv6-addr'])
    if kind == 'nat46':
        if not maps or IPv4Address(values['ipv4-addr']) != IPv4Address('198.19.200.1'):
            raise ValueError('static translator requires reviewed maps')
    elif IPv4Network(values['dynamic-pool']) not in (IPv4Network('198.18.0.0/20'), IPv4Network('198.18.16.0/20')) or values['udp-cksum-mode'] != 'calc':
        raise ValueError('unapproved internal translator pool or UDP mode')
    return values, maps


def command(*argv):
    result = subprocess.run(argv, check=True, capture_output=True, timeout=1, text=True)
    if len(result.stdout) > 1_048_576:
        raise ValueError('readiness observation exceeds budget')
    return result.stdout


def service(kind, run):
    text = run('systemctl', 'show', 'example-router-' + kind + '.service',
               '--property=ActiveState,SubState,MainPID,InvocationID')
    value = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    if (value.get('ActiveState') != 'active' or value.get('SubState') != 'running'
            or not value.get('MainPID', '').isdigit() or int(value['MainPID']) <= 1
            or len(value.get('InvocationID', '')) != 32):
        raise ValueError('translator service is not running')
    return value


def installed(kind, config, links, routes):
    link = next((item for item in links if item['ifname'] == kind), {})
    if ('UP' not in link.get('flags', []) or link.get('linkinfo', {}).get('info_kind') != 'tun'
            or link.get('linkinfo', {}).get('info_data', {}).get('type') != 'tun'):
        return False
    addresses = {a['local'] for a in link.get('addr_info', []) if not a.get('tentative')}
    if not {config['ipv4-addr'], config['ipv6-addr']} <= addresses:
        return False
    expected = {config['prefix'], str(POOL) if kind == 'nat46' else config['dynamic-pool']}
    found = {r.get('dst') for r in routes if r.get('dev') == kind and r.get('type', 'unicast') == 'unicast'
             and not r.get('gateway') and not r.get('multipath') and 'linkdown' not in r.get('flags', [])}
    return expected <= found


def target_routed(target, routes):
    """Require a specific main-table LAN route, excluding a WAN default fallback."""
    matches = []
    for route in routes:
        try:
            prefix = IPv6Network(route.get('dst', '::/0'))
        except ValueError:
            continue
        if target in prefix:
            matches.append((prefix.prefixlen, route))
    if not matches:
        return False
    longest = max(length for length, _ in matches)
    return longest > 0 and all(
        route.get('dev') in {f'lan-vlan{v}' for v in (1, 11, 22, 23, 55, 98)}
        and route.get('type', 'unicast') == 'unicast' and not route.get('multipath')
        and 'linkdown' not in route.get('flags', [])
        for length, route in matches if length == longest)


@dataclass(frozen=True)
class Readiness:
    observed_at: datetime
    monotonic: float
    nat64: bool = False
    maps: dict = field(default_factory=dict)
    generation: int = 1
    unavailable: tuple = ()

    def render(self, records, *, now, monotonic):
        elapsed = monotonic - self.monotonic
        wall_elapsed = (now - self.observed_at).total_seconds()
        if not 0 <= elapsed < LEASE or abs(wall_elapsed - elapsed) > 2:
            return tuple(records)
        until = min(self.observed_at + timedelta(seconds=LEASE), now + timedelta(seconds=LEASE - elapsed))
        mappings = {r.id: MappingReadiness(r.id, IPv6Address(r.data), self.maps[IPv6Address(r.data)],
                                         self.generation, self.generation, self.generation, 'ready', until)
                    for r in records if r.type == 28 and IPv6Address(r.data) in self.maps}
        return translated_records(records, now=now, catalog_until=until, mappings=mappings,
                                  nat64=self.nat64, nat46=True)


def observe(*, run=command, read=immutable_config):
    """Sample running process identity on both sides of config/TUN/route checks."""
    wall, mono = datetime.now(timezone.utc), time.monotonic()
    links = json.loads(run('ip', '-j', '-d', 'address', 'show'))
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show')) + json.loads(run('ip', '-j', '-6', 'route', 'show'))
    nat64, maps, generation = False, {}, 1
    unavailable = []
    for kind, path in PATHS.items():
        try:
            before = service(kind, run)
            data = read(path)
            config, current = parse_config(data, kind)
            # cmdline is read-only procfs state, never a shell command.
            argv = Path('/proc', before['MainPID'], 'cmdline').read_bytes().split(b'\0')
            binary = b'/usr/sbin/tayga' if kind == 'nat46' else b'/usr/lib/example-router/tayga-internal'
            if not argv or argv[0] != binary or b'--nodetach' not in argv:
                raise ValueError('unexpected translator process')
            index = argv.index(b'--config')
            if argv[index + 1] != path.encode() or not installed(kind, config, links, routes):
                raise ValueError('translator config/TUN/routes do not match')
            if service(kind, run) != before or read(path) != data:
                raise ValueError('translator changed during observation')
            if kind == 'nat46':
                maps = {target: alias for target, alias in current.items() if target_routed(target, routes)}
                generation = int.from_bytes(hashlib.sha256(data + before['InvocationID'].encode()).digest()[:7], 'big') + 1
            else:
                nat64 = True
        except (OSError, ValueError, IndexError, subprocess.SubprocessError) as exc:
            unavailable.append((kind, str(exc)[:256]))
            continue  # Failure of one translator does not withdraw native records.
    return Readiness(wall, mono, nat64, maps, generation, tuple(unavailable))


class RouterTranslation:
    """One bounded sampler inside the collector; requests only read its state."""
    def __init__(self):
        self.state = None

    def render(self, records, *, now, monotonic):
        return self.state.render(records, now=now, monotonic=monotonic) if self.state else tuple(records)

    async def poll(self):
        previous = None
        while True:
            try:
                self.state = await asyncio.to_thread(observe)
            except (OSError, ValueError, subprocess.SubprocessError):
                self.state = None
            status = ((self.state.nat64, len(self.state.maps), self.state.unavailable)
                      if self.state else (False, 0, (('observer', 'unavailable'),)))
            if status != previous:
                print(json.dumps({'event': 'translation_readiness', 'nat64': status[0],
                                  'nat46_maps': status[1], 'unavailable': status[2]}), flush=True)
                previous = status
            await asyncio.sleep(2)
