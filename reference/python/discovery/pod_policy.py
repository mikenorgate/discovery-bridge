"""Explicit operator selectors and trusted Kubernetes/CRI admission data.

Inputs come from the broker's API/runtime adapters, never from a responder IPC
request. Labels select workloads; Kubernetes RBAC controls who can create them.
"""
from dataclasses import dataclass
from ipaddress import ip_address
import re

OPT_IN = 'discovery-bridge-client'


def addresses(values):
    result = frozenset(ip_address(value) for value in values)
    if not result or any(a.is_unspecified or a.is_multicast or a.is_loopback or a.is_link_local for a in result):
        raise ValueError('routable pod addresses required')
    if len(result) > 2 or not any(a.version == 6 for a in result):
        raise ValueError('IPv6 required; at most one address per family')
    if len({a.version for a in result}) != len(result):
        raise ValueError('duplicate pod address family')
    return result


@dataclass(frozen=True)
class Rule:
    namespace: str
    service_account: str
    match_labels: tuple[tuple[str, str], ...]

    def __post_init__(self):
        if (not self.namespace or not self.service_account or not self.match_labels
                or len(dict(self.match_labels)) != len(self.match_labels)
                or any(not k or not v or k == OPT_IN for k, v in self.match_labels)):
            raise ValueError('explicit namespace, service account and workload labels required')


@dataclass(frozen=True)
class Pod:
    uid: str
    name: str
    namespace: str
    addresses: frozenset


class PodPolicy:
    def __init__(self, node, rules):
        if not node:
            raise ValueError('node name required')
        self.node, self.rules = node, tuple(rules)

    def select(self, item):
        """Return an eligible identity, or None; malformed API objects fail closed."""
        try:
            meta, spec, status = item['metadata'], item['spec'], item['status']
            labels = meta.get('labels') or {}
            if (spec.get('nodeName') != self.node or spec.get('hostNetwork', False) is not False
                    or meta.get('deletionTimestamp') is not None or status.get('phase') != 'Running'
                    or labels.get(OPT_IN) != 'true'):
                return None
            if not any(meta['namespace'] == r.namespace
                       and spec.get('serviceAccountName') == r.service_account
                       and all(labels.get(k) == v for k, v in r.match_labels) for r in self.rules):
                return None
            if any(not isinstance(meta[k], str) or not meta[k] for k in ('uid', 'name', 'namespace')):
                return None
            return Pod(meta['uid'], meta['name'], meta['namespace'],
                       addresses(a['ip'] for a in status['podIPs']))
        except (KeyError, TypeError, ValueError, AttributeError):
            return None


@dataclass(frozen=True)
class Sandbox:
    id: str
    pid: int
    pod: Pod

    @classmethod
    def from_status(cls, data, pod):
        """Decode crictl inspectp JSON for containerd; reject other/unknown shapes."""
        try:
            status, info = data['status'], data['info']
            meta = status['metadata']
            actual = addresses([status['network']['ip']] +
                               [a['ip'] for a in status['network'].get('additionalIps', [])])
            if (status['state'] != 'SANDBOX_READY'
                    or (meta['uid'], meta['name'], meta['namespace']) != (pod.uid, pod.name, pod.namespace)
                    or actual != pod.addresses
                    or status['linux']['namespaces']['options']['network'] != 'POD'
                    or info['processStatus'] != 'running' or info['netNamespaceClosed'] is not False
                    or type(info['pid']) is not int or info['pid'] <= 1
                    or not re.fullmatch('[a-f0-9]{64}', status['id'])):
                raise ValueError('sandbox identity/state rejected')
            return cls(status['id'], info['pid'], pod)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('unsupported containerd inspectp response') from exc
