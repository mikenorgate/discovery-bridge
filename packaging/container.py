"""Prepare verified container inputs, build natively and export the same image as OCI."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
INPUTS = json.loads((ROOT / 'packaging/container-inputs.json').read_text())


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def download(url, path, expected):
    if path.exists() and digest(path) == expected:
        return
    temporary = path.with_suffix('.partial')
    try:
        with urllib.request.urlopen(url, timeout=30) as response, temporary.open('wb') as output:
            if not response.url.startswith('https://'):
                raise ValueError('Release input redirected away from HTTPS')
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise ValueError('Release input exceeds size limit')
                output.write(chunk)
        if digest(temporary) != expected:
            raise ValueError('Release input checksum mismatch: ' + path.name)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare(arch):
    native = ROOT / 'dist/native' / arch
    metadata = json.loads((native / 'build.json').read_text())
    if metadata['architecture'] != arch or digest(native / 'discovery-bridge') != metadata['binary_sha256']:
        raise ValueError('Container input differs from the qualified native binary')
    context = ROOT / 'dist/container' / arch
    context.mkdir(parents=True, exist_ok=True)
    binaries = context / 'bin'
    binaries.mkdir(exist_ok=True)
    for name in ('discovery-bridge', 'crictl'):
        if (binaries / name).exists():
            (binaries / name).chmod(0o644)
    shutil.copyfile(native / 'discovery-bridge', binaries / 'discovery-bridge')
    checksums = INPUTS['architectures'][arch]
    download(f'https://dl.k8s.io/release/{INPUTS["kubectl_version"]}/bin/linux/{arch}/kubectl',
             binaries / 'kubectl', checksums['kubectl'])
    archive = ROOT / 'dist' / f'crictl-{arch}.tar.gz'
    download(f'https://github.com/kubernetes-sigs/cri-tools/releases/download/{INPUTS["crictl_version"]}/crictl-{INPUTS["crictl_version"]}-linux-{arch}.tar.gz',
             archive, checksums['crictl_archive'])
    with tarfile.open(archive) as tar:
        member = tar.getmember('crictl')
        if not member.isfile() or member.size > 128 * 1024 * 1024:
            raise ValueError('Invalid crictl archive member')
        (binaries / 'crictl').write_bytes(tar.extractfile(member).read())
    for binary in binaries.iterdir():
        binary.chmod(0o555)
    licenses = context / 'licenses'
    if licenses.exists():
        shutil.rmtree(licenses)
    shutil.copytree(native / 'licenses', licenses)
    shutil.copyfile(ROOT / 'registry/COPYING.avahi', licenses / 'Avahi-registry.txt')
    download(f'https://raw.githubusercontent.com/kubernetes/kubernetes/{INPUTS["kubectl_version"]}/LICENSE',
             licenses / 'kubectl.txt', INPUTS['licenses']['kubectl'])
    download(f'https://raw.githubusercontent.com/kubernetes-sigs/cri-tools/{INPUTS["crictl_version"]}/LICENSE',
             licenses / 'crictl.txt', INPUTS['licenses']['crictl'])
    for name in ('Containerfile', '.dockerignore'):
        shutil.copyfile(ROOT / name, context / name)
    metadata['container_inputs'] = INPUTS
    metadata['container_binary_sha256'] = {name: digest(binaries / name) for name in ('discovery-bridge', 'kubectl', 'crictl')}
    (context / 'metadata.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
    (context / 'SHA256SUMS').write_text(''.join(value + '  ' + name + '\n'
                                             for name, value in sorted(metadata['container_binary_sha256'].items())))
    expected = {'Containerfile', '.dockerignore', 'metadata.json', 'SHA256SUMS'} | {
        'bin/' + name for name in metadata['container_binary_sha256']} | {
        'licenses/' + path.name for path in licenses.iterdir()}
    actual = {str(path.relative_to(context)) for path in context.rglob('*') if not path.is_dir()}
    if actual != expected or any(path.is_symlink() for path in context.rglob('*')):
        raise ValueError('Container context contains an unexpected file')
    print('Prepared verified, explicit container context for ' + arch)


def build(arch):
    if {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine()) != arch:
        raise ValueError('Build and qualify on a native runner of the selected architecture')
    context = ROOT / 'dist/container' / arch
    metadata = json.loads((context / 'metadata.json').read_text())
    image = 'ghcr.io/mikenorgate/discovery-bridge:v' + metadata['version']
    subprocess.run(['podman', 'build', '--format=oci', '--layers', '--timestamp=' + str(metadata['source_date_epoch']),
                    '--build-arg', 'BASE_IMAGE=' + INPUTS['base'],
                    '--build-arg', 'DEBIAN_SNAPSHOT=' + INPUTS['debian_snapshot'],
                    '--build-arg', 'SECURITY_SNAPSHOT=' + INPUTS['security_snapshot'],
                    '--label', 'org.opencontainers.image.source=https://github.com/mikenorgate/discovery-bridge',
                    '--label', 'org.opencontainers.image.revision=' + metadata['source_commit'],
                    '--label', 'org.opencontainers.image.version=' + metadata['version'],
                    '--tag', image, str(context)], check=True)
    directory = ROOT / 'dist/releases' / arch
    archive = directory / f'discovery-bridge_{metadata["version"]}_linux_{arch}.oci.tar'
    subprocess.run(['podman', 'save', '--format=oci-archive', '--output', str(archive), image], check=True)
    # Import the exported artifact under a fresh name. Qualification uses this
    # name, so a later offline consumer receives the bytes that passed testing.
    with tarfile.open(archive) as tar:
        index = json.load(tar.extractfile('index.json'))
        descriptor = index['manifests'][0]
        manifest = json.load(tar.extractfile('blobs/sha256/' + descriptor['digest'].removeprefix('sha256:')))
    image_id = subprocess.check_output(['podman', 'image', 'inspect', image, '--format', '{{.Id}}'], text=True).strip().removeprefix('sha256:')
    if manifest['config']['digest'] != 'sha256:' + image_id:
        raise ValueError('Exported OCI configuration differs from the built image')
    subprocess.run(['podman', 'load', '--input', str(archive)], check=True)
    qualified = 'localhost/discovery-bridge-qualified:' + arch
    subprocess.run(['podman', 'tag', manifest['config']['digest'], qualified], check=True)
    metadata['image'] = {'platform_digest': descriptor['digest'], 'config_digest': manifest['config']['digest'],
                         'qualified_reference': qualified, 'archive': archive.name, 'sha256': digest(archive)}
    (directory / 'container.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
    print('Exported and reloaded ' + archive.name + ': ' + descriptor['digest'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'build'))
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    arguments = parser.parse_args()
    (prepare if arguments.command == 'prepare' else build)(arguments.arch)
