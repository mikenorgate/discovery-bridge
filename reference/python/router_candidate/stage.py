"""Copy public discovery artifacts into an Ansible overlay, before build approval."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]


def stage(overlay):
    root = overlay / 'mkosi.extra'
    target = root / 'usr/lib/discovery-bridge'
    if target.exists():
        raise ValueError('discovery staging requires a fresh overlay')
    target.mkdir(parents=True)
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-compile',
        '--find-links', str(SOURCE / 'build-inputs/wheels'), '--require-hashes',
        '--target', str(target), '-r', str(SOURCE / 'requirements-test.txt')], check=True)
    shutil.copytree(SOURCE / 'discovery', target / 'discovery', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    files = {'sysusers.conf': 'usr/lib/sysusers.d/78-discovery-bridge.conf',
             'tmpfiles.conf': 'usr/lib/tmpfiles.d/78-discovery-bridge.conf',
             'zz-discovery-bridge.conf': 'etc/dbus-1/system.d/zz-discovery-bridge.conf',
             'discovery-bridge-collector.service': 'usr/lib/systemd/system/discovery-bridge-collector.service',
             'discovery-bridge-publisher.service': 'usr/lib/systemd/system/discovery-bridge-publisher.service'}
    for source, destination in files.items():
        path = root / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / 'router_candidate' / source, path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('overlay', type=Path)
    stage(parser.parse_args().overlay)
