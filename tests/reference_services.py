"""Compare Service intents and DNS wire data across the maintained runtimes."""
import asyncio
from datetime import datetime, timezone
import json
import sys

import dns.name
import dns.rdata

from discovery.feed import encode
from discovery.kubernetes import PublicationAPI, ServiceIntent, records
from discovery.kubernetes_publisher import KubernetesServices


def signature(record):
    return [dns.name.from_text(record.name).to_wire().hex(), record.type,
            dns.rdata.from_text(1, record.type, record.data).to_wire().hex(),
            record.source_link]


async def main():
    request = json.load(sys.stdin)
    value = request['snapshot']
    now = datetime.fromisoformat(value['issued_at']).astimezone(timezone.utc)
    receiver = ServiceIntent()
    api = PublicationAPI(receiver, now=lambda: now, clock=lambda: 100)
    status, _ = await api.handle(b'POST', b'/v1/publications', encode(value))
    assert status == 200
    received = receiver.records(now=now, monotonic=100)
    assert not receiver.records(now=now, monotonic=115)

    def read(argv):
        if 'config' in argv:
            return {'clusters': [{'cluster': {'server': 'https://fixture'}}]}
        if 'endpointslices?' in argv[-1]:
            return request['slices']
        return request['service']

    producer = KubernetesServices({'services': request['selected'],
                                  'kubectl': ['/usr/bin/kubectl'],
                                  'kubeconfig': '/etc/fixture-kubeconfig'}, run=read)
    produced = producer.snapshot()
    produced_records = records(produced['services'], now)
    print(json.dumps({'accepted': status, 'received': sorted(map(signature, received)),
                      'snapshot': produced,
                      'produced': sorted(map(signature, produced_records))}))


asyncio.run(main())
