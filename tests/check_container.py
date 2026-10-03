"""Verify a complete OCI graph and the executable bytes of the imported image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    args = parser.parse_args()
    directory = ROOT / 'dist/releases' / args.arch
    metadata = json.loads((directory / 'container.json').read_text())
    image = metadata['image']
    archive = directory / image['archive']
    with archive.open('rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == image['sha256']
    with tarfile.open(archive) as tar:
        names = set()
        for entry in tar:
            assert entry.isfile() or entry.isdir()
            name = entry.name.removeprefix('./').removesuffix('/')
            if entry.isdir():
                assert name in ('', '.', 'blobs', 'blobs/sha256'), name
                continue
            assert name not in names and (name in ('index.json', 'oci-layout') or name.startswith('blobs/sha256/')), name
            names.add(name)
            if name.startswith('blobs/sha256/'):
                assert len(name.removeprefix('blobs/sha256/')) == 64
                assert hashlib.file_digest(tar.extractfile(entry), 'sha256').hexdigest() == name.removeprefix('blobs/sha256/'), name
        assert json.load(tar.extractfile('oci-layout'))['imageLayoutVersion'] == '1.0.0'
        index = json.load(tar.extractfile('index.json'))
        assert index['schemaVersion'] == 2 and len(index['manifests']) == 1
        descriptor = index['manifests'][0]
        assert descriptor['digest'] == image['platform_digest']

        def blob(value):
            assert value['digest'].startswith('sha256:')
            member = tar.getmember('blobs/sha256/' + value['digest'].removeprefix('sha256:'))
            assert member.size == value['size']
            return tar.extractfile(member)

        manifest = json.load(blob(descriptor))
        assert manifest['schemaVersion'] == 2
        assert manifest['config']['digest'] == image['config_digest']
        config = json.load(blob(manifest['config']))
        assert config['architecture'] == args.arch and config['os'] == 'linux'
        for layer in manifest['layers']:
            assert layer['digest'].startswith('sha256:')
            assert tar.getmember('blobs/sha256/' + layer['digest'].removeprefix('sha256:')).size == layer['size']
        assert names == {'index.json', 'oci-layout'} | {
            'blobs/sha256/' + value['digest'].removeprefix('sha256:')
            for value in [descriptor, manifest['config'], *manifest['layers']]}
        assert len(config['rootfs']['diff_ids']) == len(manifest['layers'])
        runtime = config['config']
        assert runtime['Entrypoint'] == ['/usr/bin/discovery-bridge'] and runtime['Cmd'] == ['version']
        assert runtime['User'] == '65532:65532' and 'GOMAXPROCS=2' in runtime['Env']
        assert runtime['Labels']['org.opencontainers.image.revision'] == metadata['source_commit']
        assert runtime['Labels']['org.opencontainers.image.version'] == metadata['version']
        assert runtime['Labels']['org.opencontainers.image.source'] == 'https://github.com/mikenorgate/discovery-bridge'
    base = ['podman', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--memory=192m', '--pids-limit=64']

    def execute(program, *args):
        return subprocess.check_output(base + ['--entrypoint=' + program, image['qualified_reference'], *args], text=True, timeout=20).strip()

    assert execute('/usr/bin/discovery-bridge', 'version') == f'discovery-bridge {metadata["version"]} ({metadata["go_version"]})'
    kubectl = json.loads(execute('/usr/bin/kubectl', 'version', '--client=true', '--output=json'))
    assert kubectl['clientVersion']['gitVersion'] == metadata['container_inputs']['kubectl_version']
    assert execute('/usr/bin/crictl', '--version') == 'crictl version ' + metadata['container_inputs']['crictl_version']
    assert 'iproute2' in execute('/usr/sbin/ip', '-Version')
    for name, expected in metadata['container_binary_sha256'].items():
        assert execute('/usr/bin/sha256sum', '/usr/bin/' + name).split()[0] == expected
    forbidden = ['/usr/bin/python3', '/usr/local/go', '/app', '/root/.kube', '/etc/discovery-bridge/router.json']
    subprocess.run(base + ['--entrypoint=/bin/sh', image['qualified_reference'], '-ec',
                          'test -s /etc/ssl/certs/ca-certificates.crt; ' +
                          '; '.join('test ! -e ' + path for path in forbidden)], check=True, timeout=20)
    print('OCI graph, native architecture, imported runtime, CLI versions, hashes and defaults passed.')


if __name__ == '__main__':
    main()
