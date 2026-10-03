"""Qualify installed units under systemd in a disposable network-isolated container."""
import http.client
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import subprocess
import time

ROLES = ['discovery-bridge-publisher', 'discovery-bridge-collector']


def call(*args):
    return subprocess.check_output(args, text=True, timeout=15).strip()


def properties(role):
    return dict(line.split('=', 1) for line in call('systemctl', 'show', role,
                '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'NRestarts',
                '-p', 'WatchdogTimestampMonotonic', '-p', 'MemoryMax', '-p', 'TasksMax').splitlines())


def healthy(role):
    info = properties(role)
    assert info['ActiveState'] == 'active' and info['SubState'] == 'running', info
    assert int(info['MemoryMax']) == 128 * 1024 * 1024 and int(info['TasksMax']) == 32, info
    status = dict(line.split(':', 1) for line in Path('/proc/' + info['MainPID'] + '/status').read_text().splitlines())
    assert int(status['Uid'].split()[0]) == pwd.getpwnam(role).pw_uid
    assert int(status['CapEff'].strip(), 16) == 1 << 13  # CAP_NET_RAW only.
    assert int(status['NoNewPrivs']) == 1 and int(status['Seccomp']) == 2
    assert int(status['Threads']) <= 32 and int(status['VmRSS'].split()[0]) < 128 * 1024
    return info


def catalog():
    connection = http.client.HTTPConnection('127.0.0.1', 19443, timeout=3)
    try:
        nonce = os.urandom(32).hex()
        connection.request('POST', '/v1/catalog', body=json.dumps({'schema': 1, 'nonce': nonce}),
                           headers={'Content-Type': 'application/json', 'Connection': 'close'})
        response = connection.getresponse()
        assert response.status == 200
        value = json.loads(response.read())
        assert value['schema'] == 1 and value['nonce'] == nonce
        return value
    finally:
        connection.close()


def main():
    if os.geteuid() != 0 or Path('/proc/1/comm').read_text().strip() != 'systemd' or not any(
            Path(path).exists() for path in ('/.dockerenv', '/run/.containerenv')):
        raise SystemExit('Run this test inside a disposable systemd container.')
    try:
        assert not Path('/etc/discovery-bridge/router.json').exists()
        call('systemctl', 'start', ROLES[0])
        assert properties(ROLES[0])['ActiveState'] == 'inactive', 'Missing config must skip startup'
        call('ip', 'link', 'add', 'lan0', 'type', 'dummy')
        call('ip', 'link', 'set', 'lan0', 'up', 'multicast', 'on')
        call('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'lan0')
        call('ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'lan0', 'nodad')
        config = json.loads(Path('/source/packaging/examples/router.disabled.json').read_text())
        config['enabled'] = True
        config['gateway'] = {'host': '127.0.0.1', 'port': 19443, 'clients': ['127.0.0.1/32']}
        directory = Path('/etc/discovery-bridge')
        directory.mkdir()
        (directory / 'router.json').write_text(json.dumps(config))
        call('systemctl', 'start', ROLES[1])
        initial = {role: healthy(role) for role in ROLES}
        assert all(info['NRestarts'] == '0' for info in initial.values()), initial
        first = catalog()['generation']
        time.sleep(1)
        assert all(int(healthy(role)['WatchdogTimestampMonotonic']) > int(initial[role]['WatchdogTimestampMonotonic']) for role in ROLES)
        call('systemctl', 'restart', ROLES[1])
        assert catalog()['generation'] == first + 1
        previous = healthy(ROLES[1])
        call('systemctl', 'kill', '--signal=SIGSTOP', ROLES[1])
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            info = properties(ROLES[1])
            if info['ActiveState'] == 'active' and info['MainPID'] not in ('0', previous['MainPID']):
                break
            time.sleep(0.1)
        else:
            raise AssertionError('Systemd did not recover the stopped collector within its watchdog bound')
        assert healthy(ROLES[1])['NRestarts'] == '1'
        assert healthy(ROLES[0])['MainPID'] == initial[ROLES[0]]['MainPID']
        assert catalog()['generation'] == first + 2
        call('systemctl', 'stop', ROLES[1], ROLES[0])
        assert all(properties(role)['ActiveState'] == 'inactive' for role in ROLES)
        state = Path('/var/lib/discovery-bridge/identities.db')
        assert stat.S_IMODE(state.stat().st_mode) == 0o660
        with sqlite3.connect(state) as connection:
            assert {'identities', 'reservations'}.issubset({row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")})
        print('Installed units passed startup, credentials, limits, watchdog recovery and persistent-state checks.')
    except BaseException:
        subprocess.run(['journalctl', '--no-pager', '-n', '80', '-u', ROLES[0], '-u', ROLES[1]], timeout=10)
        raise


if __name__ == '__main__':
    main()
