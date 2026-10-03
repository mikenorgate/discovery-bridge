"""Assemble a release from two qualified platforms without rebuilding either."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from check_container import inspect_archive

REPOSITORY = 'https://github.com/mikenorgate/discovery-bridge'
IMAGE = 'ghcr.io/mikenorgate/discovery-bridge'
INDEX_TYPE = 'application/vnd.oci.image.index.v1+json'
ARCHITECTURES = ('amd64', 'arm64')


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def validate_version(version):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?', version):
        raise ValueError('Version must be MAJOR.MINOR.PATCH with an optional prerelease suffix')
    return version


def prepare_version(version):
    validate_version(version)
    if os.environ.get('GITHUB_REF_TYPE') == 'tag' and os.environ.get('GITHUB_REF_NAME') != 'v' + version:
        raise ValueError('Requested version differs from the checked-out tag')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
        raise ValueError('Candidates require a clean source tree')
    tag = subprocess.run(['git', 'rev-parse', '--verify', 'refs/tags/v' + version + '^{commit}'],
                         cwd=ROOT, text=True, capture_output=True)
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if tag.returncode == 0 and tag.stdout.strip() != source:
        raise ValueError('The version tag already belongs to another source commit')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('version=' + version + '\n')


def assemble(args):
    validate_version(args.version)
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_commit):
        raise ValueError('Expected a full source commit')
    if not re.fullmatch(REPOSITORY + r'/actions/runs/[0-9]+', args.qualification_run):
        raise ValueError('Expected the native qualification workflow URL')
    if args.output.exists() or args.layout.exists():
        raise ValueError('Use new output and OCI layout directories')
    platforms, descriptors, common = {}, [], None
    # Validate both complete platform inputs before writing any release output.
    for arch in ARCHITECTURES:
        directory = args.input / ('qualified-' + arch)
        build = json.loads((directory / 'build.json').read_text())
        container = json.loads((directory / 'container.json').read_text())
        expected = {'build.json', 'container.json', 'SHA256SUMS',
                    f'discovery-bridge_{args.version}_linux_{arch}.tar.gz',
                    f'discovery-bridge_{args.version}_{arch}.deb',
                    f'discovery-bridge_{args.version}_linux_{arch}.oci.tar'}
        if {path.name for path in directory.iterdir()} != expected or any(not path.is_file() or path.is_symlink() for path in directory.iterdir()):
            raise ValueError('Unexpected qualified platform files: ' + arch)
        for metadata in (build, container):
            if metadata['architecture'] != arch or metadata['version'] != args.version or metadata['source_commit'] != args.source_commit or metadata['source_dirty'] is not False:
                raise ValueError('Qualified platform provenance differs: ' + arch)
            if metadata['go_version'] != 'go' + (ROOT / '.go-version').read_text().strip() or metadata['cgo_enabled'] is not False:
                raise ValueError('Qualified platform compiler differs: ' + arch)
        shared_keys = ('source_date_epoch', 'go_version', 'cgo_enabled', 'compatibility', 'modules')
        shared = {key: build[key] for key in shared_keys}
        if any(build[key] != container[key] for key in (*shared_keys, 'binary_sha256', 'payload_sha256')):
            raise ValueError('Package and image did not use the same native build')
        shared['container_inputs'] = container['container_inputs']
        if shared['container_inputs'] != json.loads((ROOT / 'packaging/container-inputs.json').read_text()):
            raise ValueError('Qualified container inputs differ from source pins')
        if common is not None and shared != common:
            raise ValueError('Architecture builds differ in source or shared inputs')
        common = shared
        package_names = expected - {'build.json', 'container.json', 'SHA256SUMS', container['image']['archive']}
        if set(build['artifacts']) != package_names:
            raise ValueError('Unexpected package checksum inputs')
        for name, checksum in build['artifacts'].items():
            if digest(directory / name) != checksum:
                raise ValueError('Qualified package checksum mismatch: ' + name)
        sums = ''.join(digest(directory / name) + '  ' + name + '\n'
                       for name in (*sorted(package_names), 'build.json'))
        # Native packaging records archive, Debian package, then metadata.
        recorded = dict(line.split('  ', 1)[::-1] for line in (directory / 'SHA256SUMS').read_text().splitlines())
        calculated = dict(line.split('  ', 1)[::-1] for line in sums.splitlines())
        if recorded != calculated or len(recorded) != 3:
            raise ValueError('Qualified package checksum file differs')
        image = container['image']
        descriptor = inspect_archive(directory / image['archive'], container)
        if container['container_binary_sha256']['discovery-bridge'] != build['binary_sha256']:
            raise ValueError('Container executable differs from the native package')
        descriptors.append({key: descriptor[key] for key in ('mediaType', 'digest', 'size')} |
                           {'platform': {'os': 'linux', 'architecture': arch}})
        platforms[arch] = {
            'binary_sha256': build['binary_sha256'],
            'artifacts': build['artifacts'] | {image['archive']: image['sha256']},
            'image_digest': image['platform_digest'], 'image_config_digest': image['config_digest'],
        }
    args.output.mkdir(parents=True)
    (args.layout / 'blobs/sha256').mkdir(parents=True)
    for arch, platform in platforms.items():
        directory = args.input / ('qualified-' + arch)
        for name in platform['artifacts']:
            shutil.copyfile(directory / name, args.output / name)
        archive = next(name for name in platform['artifacts'] if name.endswith('.oci.tar'))
        with tarfile.open(directory / archive) as tar:
            for member in tar:
                if member.isfile() and member.name.startswith('blobs/sha256/'):
                    target = args.layout / member.name
                    if not target.exists():
                        with tar.extractfile(member) as source, target.open('wb') as output:
                            shutil.copyfileobj(source, output)
    index = {'schemaVersion': 2, 'mediaType': INDEX_TYPE, 'manifests': descriptors}
    wire = encoded(index)
    index_digest = hashlib.sha256(wire).hexdigest()
    (args.layout / 'blobs/sha256' / index_digest).write_bytes(wire)
    write_json(args.layout / 'oci-layout', {'imageLayoutVersion': '1.0.0'})
    write_json(args.layout / 'index.json', {'schemaVersion': 2, 'manifests': [{
        'mediaType': INDEX_TYPE, 'digest': 'sha256:' + index_digest, 'size': len(wire),
        'annotations': {'org.opencontainers.image.ref.name': 'release'},
    }]})
    release = {'schema': 1, 'version': args.version, 'tag': 'v' + args.version,
               'source_repository': REPOSITORY, 'source_commit': args.source_commit,
               'qualification_run': args.qualification_run,
               'qualified_roles': ['broker', 'kubernetes-publisher'],
               **common, 'platforms': platforms,
               'image': {'reference': IMAGE + ':v' + args.version, 'digest': 'sha256:' + index_digest}}
    write_json(args.output / 'release.json', release)
    (args.output / 'SHA256SUMS').write_text(''.join(
        digest(path) + '  ' + path.name + '\n' for path in sorted(args.output.iterdir())))
    print('Assembled two qualified platforms and OCI index sha256:' + index_digest)


def verify_registry(directory):
    release = json.loads((directory / 'release.json').read_text())
    reference = release['image']['reference']
    for name, expected in [('index', release['image']['digest'])] + [
            (arch, platform['image_digest']) for arch, platform in release['platforms'].items()]:
        target = reference if name == 'index' else IMAGE + '@' + expected
        raw = subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + target], timeout=60)
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Registry changed the qualified manifest: ' + name)
    print('Registry index and both platform manifests retain the qualified digests.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--version', required=True)
    assembly = commands.add_parser('assemble')
    assembly.add_argument('--version', required=True)
    assembly.add_argument('--source-commit', required=True)
    assembly.add_argument('--qualification-run', required=True)
    assembly.add_argument('--input', type=Path, required=True)
    assembly.add_argument('--output', type=Path, required=True)
    assembly.add_argument('--layout', type=Path, required=True)
    verify = commands.add_parser('verify-registry')
    verify.add_argument('--release', type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == 'prepare':
        prepare_version(arguments.version)
    elif arguments.command == 'assemble':
        assemble(arguments)
    else:
        verify_registry(arguments.release)
