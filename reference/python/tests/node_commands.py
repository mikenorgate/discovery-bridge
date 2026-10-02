#!/usr/bin/python3
"""Fixture executables for the isolated node integration lab, never production."""
import json
from pathlib import Path
import sys
import time

if __name__ == '__main__':
    value = json.loads(Path('/tmp/node-state.json').read_text())
    args = sys.argv[1:]
    if 'config' in args:
        print(json.dumps({'clusters': [{'cluster': {'server': 'https://fixture.invalid'}}]}))
    elif 'get' in args:
        if value.get('api_failure'): raise SystemExit(1)
        print(json.dumps({'apiVersion': 'v1', 'kind': 'PodList', 'items': value['pods']}))
    elif 'inspectp' in args:
        print(json.dumps(value['runtime']))
    elif 'pods' in args:
        if value.get('runtime_hang'): time.sleep(10)
        print(json.dumps({'items': [value['runtime']['status']]}))
    else:
        raise SystemExit('fixture command rejected')
