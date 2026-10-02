"""Bounded Kubernetes service intent; no Pod addresses, DNS writes or NAT allocation."""
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
import re
import time

import dns.name
import dns.rdata
import dns.rdatatype as rt

from discovery.catalog import Record, _fields, _object, _time
from discovery.feed import encode
from discovery.lookup import Bucket, MAX_LOOKUP_BYTES
from discovery.registry import generated_type, observed_type

SOURCE = 'kubernetes'
VIP_POOL = '2001:db8:1000:ff00::/60'
LEASE = 15
MAX_SERVICES = 16


def resource_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', value):
        raise ValueError('invalid Kubernetes resource name')
    return value


def metadata(value):
    """Explicit protocol metadata, validated independently by producer and gateway."""
    _fields(value, {'namespace', 'name', 'port', 'type', 'instance', 'txt', 'subtypes'})
    for key in ('namespace', 'name', 'port'):
        resource_name(value[key])
    kind = observed_type(value['type'])
    identifier, transport = kind.split('._')
    if generated_type(identifier[1:], transport) != kind:
        raise ValueError('invalid generated service type')
    label = value['instance']
    if not isinstance(label, str) or not 1 <= len(label.encode()) <= 32 or any(ord(c) < 32 for c in label):
        raise ValueError('bounded service instance label required')
    txt = value['txt']
    if not isinstance(txt, dict) or len(txt) > 16:
        raise ValueError('public TXT limit')
    strings = []
    for key, text in sorted(txt.items()):
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', key) or not isinstance(text, str):
            raise ValueError('invalid public TXT field')
        field = (key + '=' + text).encode()
        if len(field) > 255:
            raise ValueError('TXT field limit')
        strings.append(field)
    if sum(len(v) + 1 for v in strings) > 1024:
        raise ValueError('TXT byte limit')
    subtypes = value['subtypes']
    if not isinstance(subtypes, list) or len(subtypes) > 8 or len(set(subtypes)) != len(subtypes):
        raise ValueError('subtype limit')
    for subtype in subtypes:
        if not isinstance(subtype, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}', subtype):
            raise ValueError('invalid subtype label')
    return kind, strings


def service_intent(service, slices, selected):
    """Select a ready numeric VIP and external Service port from complete API reads."""
    kind, _ = metadata(selected)
    meta, spec = service['metadata'], service['spec']
    if (meta['namespace'] != selected['namespace'] or meta['name'] != selected['name']
            or meta.get('deletionTimestamp') or spec.get('type') != 'LoadBalancer'
            or spec.get('publishNotReadyAddresses', False)):
        return None
    ports = [p for p in spec['ports'] if p.get('name') == selected['port']
             and p.get('protocol', 'TCP').lower() == kind.rsplit('._', 1)[1]]
    if len(ports) != 1:
        return None
    addresses = sorted({str(ip_address(a['ip'])) for a in service.get('status', {}).get('loadBalancer', {}).get('ingress', [])
                        if 'ip' in a and a.get('ipMode', 'VIP') == 'VIP' and ip_address(a['ip']) in ip_network(VIP_POOL)})
    if not addresses:
        return None
    ready = False
    for item in slices:
        sm = item['metadata']
        if (sm.get('namespace') != meta['namespace'] or sm.get('deletionTimestamp')
                or sm.get('labels', {}).get('kubernetes.io/service-name') != meta['name']
                or not any(o.get('kind') == 'Service' and o.get('uid') == meta['uid'] and o.get('controller') is True
                           for o in sm.get('ownerReferences', [])) or item.get('addressType') != 'IPv6'):
            continue
        if not any(p.get('name') == selected['port'] and p.get('protocol', 'TCP') == ports[0].get('protocol', 'TCP')
                   and type(p.get('port')) is int and 1 <= p['port'] <= 65535 for p in item.get('ports', [])):
            continue
        for endpoint in item.get('endpoints', []):
            conditions = endpoint.get('conditions', {})
            if (conditions.get('ready') is True and conditions.get('serving') is not False
                    and conditions.get('terminating') is not True and endpoint.get('addresses')):
                ready = True
    if not ready:
        return None
    return {**selected, 'uid': meta['uid'], 'addresses': addresses, 'service_port': ports[0]['port']}


def records(intents, until):
    """Build complete DNS-SD chains with UID-based names; addresses are VIPs only."""
    result, seen = [], set()
    if not isinstance(intents, list) or len(intents) > MAX_SERVICES:
        raise ValueError('service intent limit')
    for intent in intents:
        _fields(intent, {'namespace', 'name', 'port', 'type', 'instance', 'txt', 'subtypes', 'uid', 'addresses', 'service_port'})
        kind, strings = metadata({k: intent[k] for k in ('namespace', 'name', 'port', 'type', 'instance', 'txt', 'subtypes')})
        uid = intent['uid']
        if not isinstance(uid, str) or not re.fullmatch('[a-zA-Z0-9-]{1,64}', uid):
            raise ValueError('invalid Service UID')
        key = (intent['namespace'], intent['name'], intent['port'])
        if key in seen:
            raise ValueError('duplicate Service port intent')
        seen.add(key)
        port = intent['service_port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('invalid exposed Service port')
        addresses = intent['addresses']
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= 4 or len(set(addresses)) != len(addresses):
            raise ValueError('numeric VIP list required')
        for address in addresses:
            if ip_address(address) not in ip_network(VIP_POOL):
                raise ValueError('publication address is not a LoadBalancer VIP')
        identity = hashlib.sha256(encode([*key, uid])).hexdigest()[:12]
        host = 'kube-' + identity + '.local.'
        service_type = kind + '.local.'
        instance = dns.name.Name(((intent['instance'] + '-' + identity[:8]).encode(),) + dns.name.from_text(service_type).labels).to_text()
        entries = [('_services._dns-sd._udp.local.', rt.PTR, service_type),
                   (service_type, rt.PTR, instance),
                   (instance, rt.SRV, f'0 0 {port} {host}')]
        wire = b''.join(bytes((len(v),)) + v for v in strings) or b'\0'
        entries.append((instance, rt.TXT, dns.rdata.from_wire(1, rt.TXT, wire, 0, len(wire)).to_text()))
        entries += [(host, rt.AAAA, str(ip_address(a))) for a in addresses]
        entries += [('_' + sub + '._sub.' + service_type, rt.PTR, instance) for sub in intent['subtypes']]
        for name, kind, data in entries:
            identifier = hashlib.sha256(encode([SOURCE, name, int(kind), data])).hexdigest()
            result.append(Record(identifier, name, int(kind), data, SOURCE, until))
    # Shared type enumeration records occur once, even for several instances.
    return tuple({r.id: r for r in result}.values())


class ServiceIntent:
    """One network-admitted producer; absolute lease with no replay renewal."""
    def __init__(self):
        self.current = ()
        self.issued = self.until = None
        self.signature = None
        self.deadline = 0
        self.received_wall = self.received_mono = None

    def install(self, payload, *, now, monotonic):
        if not 1 <= len(payload) <= MAX_LOOKUP_BYTES:
            raise ValueError('publication byte limit')
        value = json.loads(payload.decode(), object_pairs_hook=_object)
        _fields(value, {'schema', 'issued_at', 'valid_until', 'services'})
        if type(value['schema']) is not int or value['schema'] != 1:
            raise ValueError('unsupported publication schema')
        issued, until = _time(value['issued_at']), _time(value['valid_until'])
        if not 0 < (until - issued).total_seconds() <= LEASE or issued > now + timedelta(seconds=2) or until <= now:
            raise ValueError('invalid publication lease')
        candidate = records(value['services'], until)
        signature = hashlib.sha256(encode(value)).digest()
        if self.issued is not None:
            if issued < self.issued or (issued == self.issued and signature != self.signature):
                raise ValueError('stale or conflicting publication')
            if issued == self.issued:
                return  # Retransmission cannot renew the monotonic lease.
        self.current, self.issued, self.until, self.signature = candidate, issued, until, signature
        self.deadline = monotonic + min(LEASE, (until - now).total_seconds())
        self.received_wall, self.received_mono = now, monotonic

    def records(self, *, now, monotonic):
        if (self.received_mono is None or monotonic < self.received_mono or monotonic >= self.deadline
                or abs((now - self.received_wall).total_seconds() - (monotonic - self.received_mono)) > 2):
            return ()
        until = min(self.until, now + timedelta(seconds=self.deadline - monotonic))
        return tuple(Record(r.id, r.name, r.type, r.data, r.source_link, until) for r in self.current)


class PublicationAPI:
    """Separate listener; the node catalog/lookup API cannot publish."""
    def __init__(self, intent, *, now=lambda: datetime.now(timezone.utc), clock=time.monotonic):
        self.intent, self.now, self.clock = intent, now, clock
        self.rate = Bucket(2, 4)

    async def handle(self, method, target, payload):
        if method != b'POST' or target != b'/v1/publications':
            return 404, encode({'error': 'route'})
        if not self.rate.take(self.clock()):
            return 429, encode({'error': 'capacity'})
        try:
            self.intent.install(payload, now=self.now(), monotonic=self.clock())
            return 200, encode({'accepted': True})
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, dns.exception.DNSException):
            return 400, encode({'error': 'publication'})
