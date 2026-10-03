"""Verify release payloads before any package is installed or archive extracted."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def inspect(tar, metadata):
    expected = dict(metadata['payload_sha256'])
    expected['usr/share/doc/discovery-bridge/build.json'] = hashlib.sha256(
        (ROOT / 'dist/native' / metadata['architecture'] / 'build.json').read_bytes()).hexdigest()
    found = {}
    for entry in tar:
        name = entry.name.removeprefix('./').removesuffix('/')
        if name in ('', '.') and entry.isdir():
            continue
        assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts, name
        assert entry.uid == entry.gid == 0 and entry.uname in ('', 'root') and entry.gname in ('', 'root'), name
        if entry.isdir():
            assert any(file.startswith(name + '/') for file in expected), name
            continue
        assert entry.isfile() and not entry.issparse() and name in expected and name not in found, name
        assert entry.mtime == metadata['source_date_epoch'], name
        assert entry.mode == (0o755 if name == 'usr/bin/discovery-bridge' else 0o644), name
        content = tar.extractfile(entry).read()
        found[name] = hashlib.sha256(content).hexdigest()
        assert found[name] == expected[name], name
        if name == 'usr/bin/discovery-bridge':
            assert content[:6] == b'\x7fELF\x02\x01', 'Expected a little-endian 64-bit ELF binary'
            assert struct.unpack_from('<H', content, 18)[0] == {'amd64': 62, 'arm64': 183}[metadata['architecture']]
            # The linker must not retain local source paths. Registry contents
            # include public upstream names and are checked against pinned data.
            assert b'/home/' not in content and b'/Users/' not in content, 'Untrimmed local build path'
    assert found == expected, 'Incomplete release payload'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    args = parser.parse_args()
    directory = ROOT / 'dist/releases' / args.arch
    metadata = json.loads((directory / 'build.json').read_text())
    assert metadata['architecture'] == args.arch
    assert metadata['go_version'] == 'go' + (ROOT / '.go-version').read_text().strip()
    assert metadata['cgo_enabled'] is False
    for name, expected in metadata['artifacts'].items():
        path = directory / name
        assert path.parent == directory
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name
        if name.endswith('.deb'):
            contents = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(path)])
            with tarfile.open(fileobj=io.BytesIO(contents)) as tar:
                inspect(tar, metadata)
            control = subprocess.check_output(['dpkg-deb', '--field', str(path)], text=True)
            assert 'Architecture: ' + args.arch + '\n' in control
            assert 'Version: ' + metadata['version'].replace('-', '~', 1) + '\n' in control
            controls = subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(path)])
            with tarfile.open(fileobj=io.BytesIO(controls)) as tar:
                found = set()
                for entry in tar:
                    member = entry.name.removeprefix('./')
                    if member in ('', '.') and entry.isdir():
                        continue
                    assert entry.isfile() and member in ('control', 'postinst') and member not in found, member
                    assert entry.uid == entry.gid == 0
                    assert entry.mode == (0o755 if member == 'postinst' else 0o644)
                    if member == 'postinst':
                        assert tar.extractfile(entry).read() == (ROOT / 'packaging/debian/postinst').read_bytes()
                    found.add(member)
                assert found == {'control', 'postinst'}
        else:
            with tarfile.open(path, 'r:gz') as tar:
                inspect(tar, metadata)
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=directory, check=True)
    print('Release allowlist, ownership, modes, architecture, compiler and checksums passed.')


if __name__ == '__main__':
    main()
