"""Install, reinstall and remove a package in a disposable Debian 13 container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess


def call(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not any(Path(path).exists() for path in ('/.dockerenv', '/run/.containerenv')):
        raise SystemExit('This test requires root in a disposable container.')
    if 'VERSION_ID="13"' not in Path('/etc/os-release').read_text():
        raise SystemExit('This test targets Debian 13.')
    arch = call('dpkg-deb', '--field', str(args.package), 'Architecture')
    # Slim images may intentionally exclude /usr/share/doc during unpacking.
    # Compare installed executable bytes with the independently checked build.
    metadata = json.loads((Path(__file__).resolve().parents[1] / 'dist/native' / arch / 'build.json').read_text())
    state = Path('/var/lib/discovery-bridge')
    state.mkdir(parents=True, exist_ok=True)
    database = state / 'identities.db'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE retained (value TEXT)')
        connection.execute('INSERT INTO retained VALUES (?)', ('existing identity state',))
    original = hashlib.sha256(database.read_bytes()).hexdigest()
    for _ in range(2):
        subprocess.run(['dpkg', '--install', str(args.package.resolve())], check=True)
        binary = Path('/usr/bin/discovery-bridge')
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == metadata['binary_sha256']
        assert call(str(binary), 'version') == f'discovery-bridge {metadata["version"]} ({metadata["go_version"]})'
        assert json.loads(call(str(binary), 'registry', 'describe', '_http._tcp'))['description']
        assert not Path('/etc/discovery-bridge/router.json').exists()
        assert not Path('/run/discovery-bridge/publisher.sock').exists()
        assert not any(path.name.startswith('discovery-bridge-') for path in Path('/etc/systemd/system').rglob('*.wants/*'))
        assert stat.S_IMODE(state.stat().st_mode) == 0o770
        assert stat.S_IMODE(database.stat().st_mode) == 0o660
        assert hashlib.sha256(database.read_bytes()).hexdigest() == original
        users = {line.split(':')[0]: line.split(':') for line in Path('/etc/passwd').read_text().splitlines()}
        names = ['discovery-bridge-collector', 'discovery-bridge-publisher']
        assert users[names[0]][2] != users[names[1]][2]
        assert database.stat().st_uid == int(users[names[1]][2])
        assert all(users[name][5:] == ['/nonexistent', '/usr/sbin/nologin'] for name in names)
    subprocess.run(['dpkg', '--remove', 'discovery-bridge'], check=True)
    assert not Path('/usr/bin/discovery-bridge').exists()
    assert hashlib.sha256(database.read_bytes()).hexdigest() == original
    subprocess.run(['dpkg', '--install', str(args.package.resolve())], check=True)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == original
    print('Debian install, reinstall, removal and recovery passed; state retained, discovery inactive.')


if __name__ == '__main__':
    main()
