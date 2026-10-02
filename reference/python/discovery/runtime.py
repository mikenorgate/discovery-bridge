"""Router-only component entry points; source packaging and rollout are G5."""
import argparse
import asyncio
from contextlib import AsyncExitStack
from ipaddress import ip_address
import json
import os
import pwd
import signal
from pathlib import Path
import socket

from discovery.collector import CollectorFeed, supervise, topology
from discovery.catalog import Catalog, SourcePolicy
from discovery.feed import GatewayFeed
from discovery.identity import Identities
from discovery.publication import LeaseServer, Publisher
from discovery.records import PublicationPolicy
from discovery.transport import LinkMonitor


def notify():
    path = os.environ.get('NOTIFY_SOCKET')
    if path:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect('\0' + path[1:] if path.startswith('@') else path)
            sock.sendall(b'READY=1\nWATCHDOG=1')


async def run_collector(config, identities, args):
    """Optional internal HTTP endpoint in the collector; no extra service or IPC path."""
    async with AsyncExitStack() as stack:
        from discovery.gateway import GatewayServer
        from discovery.kubernetes import PublicationAPI, ServiceIntent, SOURCE, VIP_POOL
        async def listen(api, settings):
            address = ip_address(settings['listen_address'])
            port = settings['port']
            if address.is_unspecified or address.is_multicast or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('explicit unicast bind address and port required')
            server = GatewayServer(api, settings['clients'])
            listener = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
            stack.callback(listener.close)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((str(address), port))
            listener.listen(32)
            await server.start(listener)
            stack.push_async_callback(server.close)

        publications = None
        publication_settings = config.get('publication', {})
        if publication_settings.get('enabled') is True:
            publications = ServiceIntent()
            await listen(PublicationAPI(publications), publication_settings)
        translation = None
        if config.get('translation') is True:
            from discovery.router_translation import RouterTranslation
            translation = RouterTranslation()
            sampler = asyncio.create_task(translation.poll())
            async def stop_sampler():
                sampler.cancel()
                await asyncio.gather(sampler, return_exceptions=True)
            stack.push_async_callback(stop_sampler)
        bridge = None
        settings = config.get('gateway', {})
        if settings.get('enabled') is True:
            from discovery.gateway import GatewayAPI
            from discovery.lookup import LookupCoordinator
            address = ip_address(settings['listen_address'])
            port = settings['port']
            if address.is_unspecified or address.is_multicast or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('gateway requires an explicit unicast bind address and port')
            sources = config['interfaces']
            if not sources or set(sources) - {f'lan-vlan{v}' for v in (1, 11, 22, 23, 55, 98)}:
                raise ValueError('invalid gateway source links')
            scopes = {name: tuple(config['prefixes'][name]) for name in sources}
            forbidden = tuple(config.get('forbidden', ()))
            if publications is not None:
                scopes[SOURCE] = (VIP_POOL,)
                forbidden = tuple(n for n in forbidden if n != VIP_POOL)
            policy = SourcePolicy(scopes, forbidden)
            feed = GatewayFeed(Catalog(policy), PublicationPolicy(frozenset()), args.state + '.feed', translation=translation)
            stack.callback(feed.close)
            bridge = CollectorFeed(feed, identities)
            lookups = LookupCoordinator(sources, bridge.demand)
            stack.push_async_callback(lookups.close)
            await listen(GatewayAPI(feed, lookups), settings)
        await supervise(config, identities, args.socket, watchdog=notify, gateway=bridge,
                        translation=translation, publications=publications)


async def run(args):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    config = json.loads(Path(args.config).read_text())
    if config.get('enabled') is not True:
        raise ValueError('router discovery profile is disabled')
    identities = Identities(args.state)
    try:
        if args.component == 'collector':
            await run_collector(config, identities, args)
        else:
            monitor = LinkMonitor()
            publisher = None
            try:
                links, addresses, receivers, _ = topology(config, receive=False)
                for receiver in receivers:
                    receiver.close()
                from discovery.kubernetes import SOURCE
                sources = (SOURCE,) if config.get('publication', {}).get('enabled') is True else ()
                publisher = await Publisher(links, addresses=addresses, sources=sources).connect()
                def health():
                    if monitor.changed():
                        raise RuntimeError('publisher link generation changed')
                    notify()
                server = LeaseServer(publisher, producer_uid=pwd.getpwnam(args.producer_user).pw_uid if args.producer_user else args.producer_uid, owns=identities.owns, owns_host=identities.owns_host, watchdog=health)
                await server.serve(args.socket)
            finally:
                if publisher:
                    await publisher.close()
                monitor.close()
    finally:
        identities.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('component', choices=('collector', 'publisher'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--state', required=True)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--producer-uid', type=int, default=os.getuid())
    parser.add_argument('--producer-user')
    try:
        asyncio.run(run(parser.parse_args()))
    except asyncio.CancelledError:
        pass


if __name__ == '__main__':
    main()
