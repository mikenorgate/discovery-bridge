"""Exercise Avahi permissions using separate Linux identities in an isolated lab."""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from dbus_next import Message, MessageType
from dbus_next.aio import MessageBus


async def client(role):
    bus = await MessageBus(bus_address='unix:path=/run/dbus/system_bus_socket').connect()
    owner = await bus.call(Message(destination='org.freedesktop.DBus', path='/org/freedesktop/DBus',
        interface='org.freedesktop.DBus', member='GetNameOwner', signature='s', body=['org.freedesktop.Avahi']))
    assert owner.message_type == MessageType.METHOD_RETURN
    async def call(interface, member, *, path='/', signature='', body=None):
        return await bus.call(Message(destination=owner.body[0], path=path,
            interface='org.freedesktop.Avahi.' + interface, member=member, signature=signature, body=body or []))
    try:
        assert (await call('Server', 'GetState')).message_type == MessageType.METHOD_RETURN
        group = await call('Server', 'EntryGroupNew')
        if role == 'collector':
            assert group.message_type == MessageType.ERROR and group.error_name == 'org.freedesktop.DBus.Error.AccessDenied'
            browser = await call('Server2', 'RecordBrowserPrepare', signature='iisqqu',
                                 body=[2, 0, '_esphomelib._tcp.local.', 1, 12, 0])
            assert browser.message_type == MessageType.METHOD_RETURN, browser.error_name
            for member in ('Start', 'Free'):
                assert (await call('RecordBrowser', member, path=browser.body[0])).message_type == MessageType.METHOD_RETURN
        else:
            assert group.message_type == MessageType.METHOD_RETURN, group.error_name
            assert (await call('EntryGroup', 'Free', path=group.body[0])).message_type == MessageType.METHOD_RETURN
            denied = await call('Server', 'SetHostName', signature='s', body=['forbidden'])
            assert denied.message_type == MessageType.ERROR and denied.error_name == 'org.freedesktop.DBus.Error.AccessDenied'
        print(json.dumps({'case': role + '_avahi_method_policy', 'status': 'pass'}), flush=True)
    finally:
        bus.disconnect()


def run():
    assert os.environ.get('MDNS_ISOLATED_LAB') == '1' and socket.if_nameindex() == [(1, 'lo')]
    for command in (['ip', 'link', 'add', 'eth0', 'type', 'dummy'], ['ip', 'address', 'add', '10.22.0.1/24', 'dev', 'eth0'],
                    ['ip', 'link', 'set', 'eth0', 'up']):
        subprocess.run(command, check=True)
    policy = Path('/app/router_candidate/zz-discovery-bridge.conf').read_text()
    # Existing test-image identities; the candidate's sysusers creates separate
    # collector/publisher identities in the real image. No host accounts change.
    Path('/tmp/discovery-policy.conf').write_text(policy.replace('discovery-bridge-collector', 'nobody').replace('discovery-bridge-publisher', 'daemon'))
    Path('/tmp/dbus.conf').write_text('<busconfig><include>/usr/share/dbus-1/system.conf</include><include>/tmp/discovery-policy.conf</include></busconfig>')
    Path('/run/dbus').mkdir(exist_ok=True)
    processes = []
    try:
        processes.append(subprocess.Popen(['dbus-daemon', '--nofork', '--nopidfile', '--config-file=/tmp/dbus.conf']))
        time.sleep(.4)
        Path('/tmp/avahi.conf').write_text('[server]\nallow-interfaces=eth0\nuse-ipv4=yes\nuse-ipv6=no\nenable-dbus=yes\n[publish]\npublish-addresses=no\npublish-workstation=no\n[reflector]\nenable-reflector=no\n')
        processes.append(subprocess.Popen(['avahi-daemon', '--no-chroot', '--no-drop-root', '-f', '/tmp/avahi.conf'],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1)
        for role, uid in (('collector', 65534), ('publisher', 1)):
            subprocess.run([sys.executable, __file__, role], check=True, user=uid, group=uid, extra_groups=[])
    finally:
        for process in reversed(processes):
            process.terminate(); process.wait(timeout=3)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        asyncio.run(client(sys.argv[1]))
    else:
        run()
