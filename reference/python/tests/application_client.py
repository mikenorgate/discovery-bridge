"""Exercise discovery consumers inside the unmodified released app images.

Fresh application state only. No production config, device credentials or API
connection is supplied. Results distinguish application discovery from access.
"""
import asyncio
import json
import logging
from pathlib import Path
import sys
import time

ROOT = Path('/lab')
SERVICE = '_esphomelib._tcp.local.'


def report(case, passed, **details):
    network = json.loads((ROOT / 'ready.json').read_text())['network']
    print(json.dumps({'case': case, 'status': 'pass' if passed else 'fail', 'network': network, **details}), flush=True)


async def until(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        await asyncio.sleep(.1)
    return bool(predicate())


async def esphome():
    from esphome.const import __version__
    from esphome.zeroconf import AsyncEsphomeZeroconf, DashboardBrowser, DashboardStatus
    from zeroconf import IPVersion
    from zeroconf.asyncio import AsyncServiceInfo
    expected = json.loads((ROOT / 'ready.json').read_text())
    status = {}
    tracker = DashboardStatus(status.update)
    zc = AsyncEsphomeZeroconf(interfaces=['fd00:5353::2'], ip_version=IPVersion.V6Only)
    browser = DashboardBrowser(zc.zeroconf, SERVICE, handlers=[tracker.browser_callback])
    try:
        await until(lambda: any(status.values()))
        report('esphome_dashboard_native_device_online', status.get('mdns-canary') is True,
               version=__version__, observed=status)
        info = AsyncServiceInfo(SERVICE, expected['instance'])
        found = await info.async_request(zc.zeroconf, 5000)
        report('esphome_resolves_exported_service', found and info.port == 6053,
               name=info.name, server=info.server, addresses=info.parsed_addresses())
        addresses = await zc.async_resolve_host(expected['host'], timeout=4)
        report('esphome_native_hostname_resolves', bool(addresses), addresses=addresses)
        report('esphome_has_one_native_dashboard_entry', status == {'mdns-canary': True}, observed=status)
        (ROOT / 'phase').write_text('down')
        removed = await until(lambda: not any(status.values()), seconds=20)
        report('esphome_device_withdrawal_leaves_no_online_entry', removed, observed=status,
               cache=[str(r) for r in zc.zeroconf.cache.entries_with_name(SERVICE)])
        (ROOT / 'phase').write_text('up')
        restored = removed and await until(lambda: status.get('mdns-canary') is True, seconds=25)
        report('esphome_device_reannouncement_recovers', restored, observed=status)
    finally:
        (ROOT / 'phase').write_text('up')
        await browser.async_cancel()
        await zc.async_close()


async def homeassistant():
    from homeassistant.const import __version__
    from homeassistant.core import HomeAssistant
    from homeassistant import bootstrap, loader
    from homeassistant.setup import async_setup_component
    from homeassistant.components.zeroconf.const import DATA_DISCOVERY
    from homeassistant.components import zeroconf
    from zeroconf import AddressResolver
    hass = HomeAssistant('/config')
    loader.async_setup(hass)
    hass.config.skip_pip = True
    hass.config.internal_url = 'http://[fd00:5353::2]:8123'
    events = []
    config = {'homeassistant': {'name': 'Discovery Lab', 'latitude': 0, 'longitude': 0,
                               'elevation': 0, 'unit_system': 'metric', 'time_zone': 'UTC'},
              'zeroconf': {}}
    assert await bootstrap.async_from_config_dict(config, hass) is hass
    original = hass.config_entries.flow.async_init
    async def record_flow(domain, *, context=None, data=None):
        if domain == 'esphome' and context and context.get('source') == 'zeroconf':
            events.append({'name': data.name, 'hostname': data.hostname, 'host': data.host,
                           'port': data.port, 'properties': data.properties})
        return await original(domain, context=context, data=data)
    hass.config_entries.flow.async_init = record_flow
    try:
        if not await async_setup_component(hass, 'zeroconf', config):
            report('ha_zeroconf_setup', False, version=__version__, reason='inspect application stderr')
            return
        removed = []
        discovery = hass.data[DATA_DISCOVERY]
        assert SERVICE in discovery.zeroconf_types, 'HA did not load the ESPHome discovery matcher'
        discovery.async_register_service_removed_listener(removed.append)
        await hass.async_start()
        found = await until(lambda: bool(events), seconds=30)
        report('ha_zeroconf_dispatches_esphome_config_flow', found and any(
            e['hostname'] == 'mdns-canary.local.' and e['port'] == 6053 for e in events),
            version=__version__, discoveries=events)
        aiozc = await zeroconf.async_get_async_instance(hass)
        resolver = AddressResolver('mdns-canary.local.')
        resolved = await resolver.async_request(aiozc.zeroconf, 4000)
        report('ha_native_hostname_resolves', resolved, addresses=resolver.parsed_addresses())
        (ROOT / 'phase').write_text('down')
        gone = await until(lambda: any(name.endswith(SERVICE) for name in removed), seconds=20)
        report('ha_device_withdrawal_removes_browse_entry', gone, removed=removed)
        updated = []
        discovery.async_register_service_update_listener(lambda info: updated.append(info.name))
        (ROOT / 'phase').write_text('up')
        restored = await until(lambda: any(name.endswith(SERVICE) for name in updated), seconds=25)
        report('ha_device_reannouncement_recovers', restored, observed=updated)
    finally:
        (ROOT / 'phase').write_text('up')
        await hass.async_stop()


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(esphome() if sys.argv[1] == 'esphome' else homeassistant())
