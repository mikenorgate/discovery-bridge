"""Build one native binary, then package those bytes using explicit file lists."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = {
    'systemd/discovery-bridge-collector.service': 'usr/lib/systemd/system/discovery-bridge-collector.service',
    'systemd/discovery-bridge-publisher.service': 'usr/lib/systemd/system/discovery-bridge-publisher.service',
    'sysusers/discovery-bridge.conf': 'usr/lib/sysusers.d/discovery-bridge.conf',
    'tmpfiles/discovery-bridge.conf': 'usr/lib/tmpfiles.d/discovery-bridge.conf',
    'dbus/org.discovery-bridge.conf': 'usr/share/dbus-1/system.d/org.discovery-bridge.conf',
    'examples/router.disabled.json': 'usr/share/doc/discovery-bridge/examples/router.disabled.json',
    'README.md': 'usr/share/doc/discovery-bridge/INSTALL.md',
}


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def json_objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        yield value
        text = text.lstrip()[end:]


def compile_binary(version):
    env = dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='local', GOFLAGS='')
    settings = json.loads(run('go', 'env', '-json', 'GOVERSION', 'GOOS', 'GOARCH', 'GOROOT', env=env))
    required = 'go' + (ROOT / '.go-version').read_text().strip()
    if settings['GOVERSION'] != required or settings['GOOS'] != 'linux' or settings['GOARCH'] not in ('amd64', 'arm64'):
        raise ValueError('Use the pinned Go compiler on a native Linux AMD64 or ARM64 runner.')
    arch = settings['GOARCH']
    output = ROOT / 'dist/native' / arch
    output.mkdir(parents=True, exist_ok=True)
    binary = output / 'discovery-bridge'
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=true', '-ldflags',
                    '-s -w -X main.version=' + version, '-o', str(binary),
                    './cmd/discovery-bridge'], cwd=ROOT, env=env, check=True)
    if run(str(binary), 'version') != f'discovery-bridge {version} ({required})':
        raise ValueError('The compiled binary has unexpected version metadata.')
    modules = {}
    for package in json_objects(run('go', 'list', '-deps', '-json', './cmd/discovery-bridge', env=env)):
        module = package.get('Module')
        if module and not module.get('Main'):
            if module.get('Replace'):
                raise ValueError('Release modules must not contain local replacements.')
            modules[module['Path']] = module
    licenses = output / 'licenses'
    if licenses.exists():
        shutil.rmtree(licenses)
    licenses.mkdir()
    shutil.copyfile(ROOT / 'LICENSE', licenses / 'discovery-bridge.txt')
    shutil.copyfile(Path(settings['GOROOT']) / 'LICENSE', licenses / 'go.txt')
    for path, module in sorted(modules.items()):
        files = sorted({file for pattern in ('LICENSE*', 'COPYING*', 'NOTICE*', 'PATENTS*')
                        for file in Path(module['Dir']).glob(pattern) if file.is_file()})
        if not files:
            raise ValueError('Missing license for linked module: ' + path)
        for file in files:
            shutil.copyfile(file, licenses / (path.replace('/', '_') + '-' + file.name))
    metadata = {
        'schema': 1, 'version': version, 'architecture': arch,
        'source_commit': run('git', 'rev-parse', 'HEAD'),
        'source_dirty': bool(run('git', 'status', '--porcelain', '--untracked-files=normal')),
        'source_date_epoch': int(run('git', 'show', '-s', '--format=%ct', 'HEAD')),
        'go_version': settings['GOVERSION'], 'cgo_enabled': False,
        'binary_sha256': digest(binary),
        'compatibility': {'catalog_schema': 1, 'snapshot_schemas': [1, 2],
                          'sqlite_schema': 'identities-reservations-gateway_generation'},
        'modules': [{key: module[key] for key in ('Path', 'Version', 'Sum')}
                    for _, module in sorted(modules.items())],
    }
    build_info = run('go', 'version', '-m', str(binary), env=env)
    for field in ('-trimpath=true', 'CGO_ENABLED=0', 'GOOS=linux', 'GOARCH=' + arch,
                  'vcs.revision=' + metadata['source_commit'],
                  'vcs.modified=' + str(metadata['source_dirty']).lower()):
        if '\tbuild\t' + field + '\n' not in build_info + '\n':
            raise ValueError('Compiled build information differs from metadata: ' + field)
    write_json(output / 'build.json', metadata)
    metadata['payload_sha256'] = {name: digest(source) for name, source in payload(arch).items()
                                  if name != 'usr/share/doc/discovery-bridge/build.json'}
    write_json(output / 'build.json', metadata)
    print(f'Built {arch} {version} using {required}: {metadata["binary_sha256"]}')


def payload(arch):
    native = ROOT / 'dist/native' / arch
    files = {'usr/bin/discovery-bridge': native / 'discovery-bridge',
             'usr/share/doc/discovery-bridge/build.json': native / 'build.json',
             'usr/share/doc/discovery-bridge/CONTRACT.md': ROOT / 'docs/CONTRACT.md'}
    files.update({target: ROOT / 'packaging' / source for source, target in SUPPORT.items()})
    for name in ('manifest.json', 'service-types', 'iana.csv', 'COPYING.avahi'):
        files['usr/share/discovery-bridge/registry/' + name] = ROOT / 'registry' / name
    files.update({'usr/share/doc/discovery-bridge/licenses/' + file.name: file
                  for file in sorted((native / 'licenses').iterdir())})
    return files


def assemble(arch, version):
    native = ROOT / 'dist/native' / arch
    metadata = json.loads((native / 'build.json').read_text())
    if metadata['version'] != version or metadata['architecture'] != arch or metadata['binary_sha256'] != digest(native / 'discovery-bridge'):
        raise ValueError('Package inputs differ from the recorded native build.')
    files = payload(arch)
    if metadata['payload_sha256'] != {name: digest(source) for name, source in files.items()
                                     if name != 'usr/share/doc/discovery-bridge/build.json'}:
        raise ValueError('Support files or licenses changed after compilation.')
    directory = ROOT / 'dist/releases' / arch
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f'discovery-bridge_{version}_linux_{arch}.tar.gz'
    epoch = metadata['source_date_epoch']
    with archive.open('wb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(mode='w', fileobj=compressed, format=tarfile.USTAR_FORMAT) as tar:
                for name, source in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size = source.stat().st_size
                    info.mode = 0o755 if name == 'usr/bin/discovery-bridge' else 0o644
                    info.mtime = epoch
                    with source.open('rb') as content:
                        tar.addfile(info, content)
    deb_version = version.replace('-', '~', 1)
    deb = directory / f'discovery-bridge_{version}_{arch}.deb'
    with tempfile.TemporaryDirectory(prefix='bridge-package-') as temporary:
        staging = Path(temporary)
        staging.chmod(0o755)
        for name, source in files.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755 if name == 'usr/bin/discovery-bridge' else 0o644)
        control = staging / 'DEBIAN'
        control.mkdir()
        (control / 'control').write_text(
            'Package: discovery-bridge\nVersion: ' + deb_version + '\nArchitecture: ' + arch + '\n'
            'Maintainer: Discovery Bridge contributors <maintainers@discovery-bridge.example>\n'
            'Section: net\nPriority: optional\n'
            'Depends: avahi-daemon, dbus, iproute2, systemd (>= 257)\n'
            'Homepage: https://github.com/mikenorgate/discovery-bridge\n'
            'Description: Linux mDNS and DNS-SD adapters for Kubernetes\n'
            ' Leased discovery catalogs, pod responses and explicit Service publication.\n')
        for name in ('postinst',):
            source = ROOT / 'packaging/debian' / name
            shutil.copyfile(source, control / source.name)
            (control / source.name).chmod(0o755)
        for path in staging.rglob('*'):
            os.utime(path, (epoch, epoch))
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', '--uniform-compression',
                        '-Zxz', str(staging), str(deb)], env=env, check=True)
    metadata['artifacts'] = {file.name: digest(file) for file in (archive, deb)}
    write_json(directory / 'build.json', metadata)
    (directory / 'SHA256SUMS').write_text(''.join(
        digest(file) + '  ' + file.name + '\n' for file in (archive, deb, directory / 'build.json')))
    print(f'Packaged {arch} {version}: {archive.name}, {deb.name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('compile', 'package'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--arch', choices=('amd64', 'arm64'))
    args = parser.parse_args()
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?', args.version):
        parser.error('Version must be MAJOR.MINOR.PATCH with an optional prerelease suffix.')
    if args.command == 'compile':
        compile_binary(args.version)
    elif not args.arch:
        parser.error('Packaging requires --arch.')
    else:
        assemble(args.arch, args.version)


if __name__ == '__main__':
    main()
