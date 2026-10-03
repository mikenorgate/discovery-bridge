"""Qualify account and SQLite file setup in a disposable system root."""
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='bridge-support-') as directory:
        root = Path(directory)
        for component in ('sysusers', 'tmpfiles'):
            path = root / 'usr/lib' / (component + '.d') / 'discovery-bridge.conf'
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'packaging' / component / 'discovery-bridge.conf', path)
        state = root / 'var/lib/discovery-bridge'
        state.mkdir(parents=True)
        original = b'Existing identity state must remain unchanged.\n'
        for name in ('identities.db', 'identities.db-wal', 'identities.db-shm'):
            (state / name).write_bytes(original)
        for _ in range(2):
            subprocess.run(['systemd-sysusers', '--root=' + directory], check=True)
            subprocess.run(['systemd-tmpfiles', '--root=' + directory, '--create'], check=True)
        users = {v[0]: v for line in (root / 'etc/passwd').read_text().splitlines()
                 if (v := line.split(':'))}
        groups = {v[0]: v for line in (root / 'etc/group').read_text().splitlines()
                  if (v := line.split(':'))}
        shadow = {v[0]: v[1] for line in (root / 'etc/shadow').read_text().splitlines()
                  if (v := line.split(':'))}
        names = ['discovery-bridge-collector', 'discovery-bridge-publisher']
        assert users[names[0]][2] != users[names[1]][2]
        assert set(names).issubset(set(groups['discovery-bridge'][3].split(',')))
        for name in names:
            assert users[name][5:] == ['/nonexistent', '/usr/sbin/nologin']
            assert shadow[name].startswith('!')
        group = int(groups['discovery-bridge'][2])
        assert stat.S_IMODE(state.stat().st_mode) == 0o770
        assert state.stat().st_gid == group
        for path in state.iterdir():
            assert stat.S_IMODE(path.stat().st_mode) == 0o660
            assert path.stat().st_gid == group
            if path.name != 'identities.db.feed':
                assert path.read_bytes() == original
        assert (state / 'identities.db').stat().st_uid == int(users[names[1]][2])
        assert (state / 'identities.db.feed').stat().st_uid == int(users[names[0]][2])
        binary = root / 'usr/bin/discovery-bridge'
        binary.parent.mkdir(parents=True)
        shutil.copy2(ROOT / 'dist/discovery-bridge', binary)
        units = root / 'usr/lib/systemd/system'
        units.mkdir(parents=True)
        for source in (ROOT / 'packaging/systemd').glob('*.service'):
            shutil.copy2(source, units / source.name)
        # Minimal dependencies let the verifier resolve the staged units. Real
        # Avahi process/method behavior is tested in the separate network lab.
        for name in ('basic', 'sysinit', 'shutdown', 'multi-user', 'network-online'):
            (units / (name + '.target')).write_text('[Unit]\nDescription=Fixture target\n')
        (units / 'avahi-daemon.service').write_text(
            '[Unit]\nDescription=Fixture dependency\n[Service]\n'
            'ExecStart=/usr/bin/discovery-bridge version\n')
        subprocess.run(['systemd-analyze', '--root=' + directory, 'verify',
                        'discovery-bridge-collector.service',
                        'discovery-bridge-publisher.service'], check=True)
    example = json.loads((ROOT / 'packaging/examples/router.disabled.json').read_text())
    assert example['enabled'] is False
    assert example['producer_user'] == names[0]
    print('Router units, accounts and shared-state setup passed; existing contents retained.')


if __name__ == '__main__':
    main()
