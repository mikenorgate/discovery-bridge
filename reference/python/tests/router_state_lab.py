"""Check shared SQLite state with the packaged users and tmpfiles policy."""
import grp
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import sys

ROOT = Path('/var/lib/discovery-bridge')
DATABASE = ROOT / 'identities.db'
POLICY = '/app/router_candidate/tmpfiles.conf'


def child(role, code, *, check=True):
    user = pwd.getpwnam('discovery-bridge-' + role)
    group = grp.getgrnam('discovery-bridge')
    return subprocess.run([sys.executable, '-c', code], user=user.pw_uid,
                          group=group.gr_gid, extra_groups=[], umask=0o007,
                          text=True, capture_output=True, check=check)


def configure():
    subprocess.run(['systemd-tmpfiles', '--create', POLICY], check=True)


def write_and_read(label):
    code = f'''from discovery.identity import Identities
import dns.name
s = Identities({str(DATABASE)!r})
_, alias = s.alias('lan-vlan22', dns.name.from_text({label!r}))
print(alias.to_text(), flush=True)
s.close()
'''
    alias = child('collector', code).stdout.strip()
    result = child('publisher', f'''from discovery.identity import Identities
import dns.name
s = Identities({str(DATABASE)!r})
assert s.owns(dns.name.from_text({alias!r}))
assert s.original({alias!r}) == ('lan-vlan22', {label!r})
s.close()
''')
    assert not result.stderr
    assert DATABASE.stat().st_mode & 0o777 == 0o660


def main():
    assert os.environ.get('MDNS_ISOLATED_LAB') == '1', 'disposable container only'
    subprocess.run(['systemd-sysusers', '/app/router_candidate/sysusers.conf'], check=True)
    configure()
    write_and_read('fresh.local.')
    print(json.dumps({'case': 'fresh_shared_database', 'status': 'pass'}), flush=True)

    # Reproduce .178: publisher owns a 0640 database; collector owns old sidecars.
    os.chown(ROOT, pwd.getpwnam('discovery-bridge-publisher').pw_uid, -1)
    DATABASE.chmod(0o640)
    failed = child('collector', f'''from discovery.identity import Identities
import dns.name
s = Identities({str(DATABASE)!r})
s.alias('lan-vlan22', dns.name.from_text('rejected.local.'))
''', check=False)
    assert failed.returncode != 0 and 'readonly database' in failed.stderr
    uid = pwd.getpwnam('discovery-bridge-collector').pw_uid
    gid = grp.getgrnam('discovery-bridge').gr_gid
    # Empty sidecars represent a clean checkpoint; tmpfiles must preserve owners.
    for suffix in ('-wal', '-shm'):
        path = Path(str(DATABASE) + suffix)
        path.touch()
        path.chmod(0o640)
        os.chown(path, uid, gid)
    configure()
    for suffix in ('-wal', '-shm'):
        info = Path(str(DATABASE) + suffix).stat()
        assert info.st_mode & 0o777 == 0o660 and info.st_uid == uid
    write_and_read('recovered.local.')
    with sqlite3.connect(DATABASE) as db:
        assert db.execute('SELECT count(*) FROM identities').fetchone()[0] == 2
    print(json.dumps({'case': 'existing_state_permission_repair', 'status': 'pass'}), flush=True)


if __name__ == '__main__':
    main()
