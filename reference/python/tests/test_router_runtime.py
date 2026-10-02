"""Exercise the router HTTP listener across immediate process-style restarts."""
import socket
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from discovery.catalog import SourcePolicy
from discovery.feed import NodeFeed
from discovery.gateway import GatewayClient
from discovery.identity import Identities
from discovery.runtime import run_collector


class RouterRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_listener_rebinds_after_serving_a_client(self):
        with socket.socket(socket.AF_INET6) as reserve:
            reserve.bind(('::1', 0))
            port = reserve.getsockname()[1]
        config = {'interfaces': ['lan-vlan1'], 'prefixes': {'lan-vlan1': ['192.0.2.0/24']},
                  'gateway': {'enabled': True, 'listen_address': '::1', 'port': port,
                              'clients': ['::1/128']}}
        async def request(*args, **kwargs):
            node = NodeFeed(SourcePolicy(config['prefixes'], ()))
            await GatewayClient('::1', port).refresh(node)
            self.assertIsNotNone(node.generation)
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(state=str(Path(directory) / 'identities.db'), socket='/unused')
            identities = Identities(args.state)
            try:
                with patch('discovery.runtime.supervise', side_effect=request):
                    for _ in range(3):
                        await run_collector(config, identities, args)
            finally:
                identities.close()
