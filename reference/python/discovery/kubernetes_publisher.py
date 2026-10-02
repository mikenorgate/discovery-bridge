"""Single opt-in Service publisher using existing kubectl and gateway HTTP framing."""
import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import signal

from discovery.feed import encode
from discovery.gateway import GatewayClient
from discovery.kubernetes import LEASE, MAX_SERVICES, metadata, service_intent
from discovery.node_inputs import command, read_json


class KubernetesServices:
    def __init__(self, config, *, run=read_json):
        self.selected = config['services']
        if not isinstance(self.selected, list) or len(self.selected) > MAX_SERVICES:
            raise ValueError('explicit bounded Service opt-ins required')
        seen = set()
        for value in self.selected:
            metadata(value)
            key = (value['namespace'], value['name'], value['port'])
            if key in seen:
                raise ValueError('duplicate Service port opt-in')
            seen.add(key)
        if not Path(config['kubeconfig']).is_absolute():
            raise ValueError('absolute kubeconfig path required')
        self.argv = command(config['kubectl']) + ('--kubeconfig', config['kubeconfig'],
                    '--request-timeout=2s', '--insecure-skip-tls-verify=false')
        self.run, self.checked = run, False

    def snapshot(self):
        if not self.checked:
            config = self.run((*self.argv, 'config', 'view', '--minify', '--output=json'))
            clusters = config['clusters']
            if (len(clusters) != 1 or not clusters[0]['cluster']['server'].startswith('https://')
                    or clusters[0]['cluster'].get('insecure-skip-tls-verify', False)):
                raise ValueError('verified HTTPS Kubernetes endpoint required')
            self.checked = True
        issued = datetime.now(timezone.utc)
        intents = []
        for selected in self.selected:
            namespace, name = selected['namespace'], selected['name']
            path = f'/api/v1/namespaces/{namespace}/services/{name}'
            before = self.run((*self.argv, 'get', '--raw=' + path))
            slices = self.run((*self.argv, 'get', '--raw=' +
                f'/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D{name}'))
            after = self.run((*self.argv, 'get', '--raw=' + path))
            if (slices.get('kind') != 'EndpointSliceList' or slices.get('apiVersion') != 'discovery.k8s.io/v1'
                    or slices.get('metadata', {}).get('continue') or not isinstance(slices.get('items'), list)
                    or len(slices['items']) > 256):
                raise ValueError('complete bounded EndpointSlice list required')
            if before['metadata']['resourceVersion'] != after['metadata']['resourceVersion'] or before['metadata']['uid'] != after['metadata']['uid']:
                raise ValueError('Service changed during observation')
            intent = service_intent(after, slices['items'], selected)
            if intent:
                intents.append(intent)
        return {'schema': 1, 'issued_at': issued.isoformat(),
                'valid_until': (issued + timedelta(seconds=LEASE)).isoformat(), 'services': intents}


async def run(config):
    source = KubernetesServices(config)
    endpoint = config['gateway']
    client = GatewayClient(endpoint['host'], endpoint['port'])
    while True:
        try:
            value = await asyncio.to_thread(source.snapshot)
        except (OSError, ValueError, KeyError, TypeError):
            # API failure withdraws immediately when reachable; otherwise the
            # gateway independently expires the previous absolute lease.
            now = datetime.now(timezone.utc)
            value = {'schema': 1, 'issued_at': now.isoformat(),
                     'valid_until': (now + timedelta(seconds=LEASE)).isoformat(), 'services': []}
            print(json.dumps({'event': 'publication_source_unavailable'}), flush=True)
        try:
            await client.post(b'/v1/publications', encode(value), expected=200)
        except (OSError, ValueError, TimeoutError):
            print(json.dumps({'event': 'publication_gateway_unavailable'}), flush=True)
        await asyncio.sleep(5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    async def start():
        task = asyncio.current_task()
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
        await run(json.loads(Path(args.config).read_text()))
    try:
        asyncio.run(start())
    except asyncio.CancelledError:
        pass


if __name__ == '__main__':
    main()
