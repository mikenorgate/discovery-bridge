"""Prepare verified public inputs or build locally; never push or deploy."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'node_candidate/build-inputs.json').read_text())


def download(url, path, digest):
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        temporary = path.with_suffix(path.suffix + '.partial')
        try:
            with urllib.request.urlopen(url, timeout=30) as response, temporary.open('wb') as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 128 * 1024 * 1024:
                        raise ValueError('release input exceeds size limit')
                    output.write(chunk)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != digest:
                raise ValueError('release checksum mismatch')
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def prepare(arch):
    output = ROOT / 'build-inputs' / arch
    binaries = output / 'bin'; binaries.mkdir(parents=True, exist_ok=True)
    hashes = LOCK['architectures'][arch]
    download(f'https://dl.k8s.io/release/{LOCK["kubectl_version"]}/bin/linux/{arch}/kubectl',
             binaries / 'kubectl', hashes['kubectl'])
    archive = output / 'crictl.tar.gz'
    download(f'https://github.com/kubernetes-sigs/cri-tools/releases/download/{LOCK["crictl_version"]}/crictl-{LOCK["crictl_version"]}-linux-{arch}.tar.gz',
             archive, hashes['crictl_archive'])
    with tarfile.open(archive) as bundle:
        member = bundle.getmember('crictl')
        if not member.isfile() or member.size > 128 * 1024 * 1024:
            raise ValueError('invalid crictl archive member')
        (binaries / 'crictl').write_bytes(bundle.extractfile(member).read())
    (binaries / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256((binaries / name).read_bytes()).hexdigest() + '  ' + name + '\n'
        for name in ('kubectl', 'crictl')))
    subprocess.run([sys.executable, '-m', 'pip', 'download', '--require-hashes', '--only-binary=:all:',
        '--no-deps', '--dest', str(ROOT / 'build-inputs/wheels'), '-r', str(ROOT / 'requirements-test.txt')], check=True)
    # Keep native test clients outside the shipped image. Both builders use
    # Debian's Python 3.13, regardless of the controller's Python version.
    subprocess.run([sys.executable, '-m', 'pip', 'download', '--require-hashes', '--only-binary=:all:',
        '--platform', 'manylinux2014_' + {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch],
        '--python-version', '3.13', '--implementation', 'cp', '--abi', 'cp313',
        '--dest', str(output / 'lab-wheels'), '-r', str(ROOT / 'requirements-test.txt'),
        '-r', str(ROOT / 'requirements-pod-lab.txt')], check=True)


def build(arch):
    if {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine()) != arch:
        raise ValueError('build on a native worker of the selected architecture')
    output = ROOT / 'build-inputs' / arch
    output.mkdir(parents=True, exist_ok=True)
    base_file = output / 'base.iid'
    subprocess.run(['podman', 'build', '--pull=never', '--arch', arch, '--iidfile', str(base_file),
        '--build-arg', 'BASE_IMAGE=' + LOCK['base'],
        '--build-arg', 'DEBIAN_SNAPSHOT=' + LOCK['debian_snapshot'],
        '--build-arg', 'SECURITY_SNAPSHOT=' + LOCK['security_snapshot'],
        '-f', 'node_candidate/Containerfile.base', '.'], cwd=ROOT, check=True)
    subprocess.run(['podman', 'build', '--pull=never', '--network=none', '--arch', arch,
        '--build-arg', 'BASE_IMAGE=' + base_file.read_text().strip(), '--build-arg', 'TARGETARCH=' + arch,
        '--iidfile', str(output / 'node.iid'), '-f', 'node_candidate/Containerfile', '.'], cwd=ROOT, check=True)
    print((output / 'node.iid').read_text().strip())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'build'))
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    args = parser.parse_args()
    (prepare if args.action == 'prepare' else build)(args.arch)
