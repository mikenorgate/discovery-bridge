"""Bounded read-only kubectl/crictl adapters; no custom API or watch cache."""
import json
import os
import re
import selectors
import signal
import subprocess
import time

from discovery.pod_policy import Sandbox


class CommandError(ValueError):
    """Command failure without exposing stdout, stderr or credentials."""


def read_json(argv, *, tick=lambda: None, timeout=3, limit=4_194_304):
    """Run a fixed operator command, servicing broker expiry while it runs.

    Bound wall time and output, discard stderr, kill the process group on every
    failure. No shell, stdin, inherited descriptors or responder-supplied argv.
    """
    start = time.monotonic()
    data = bytearray()
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as process:
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                eof = False
                while not eof or process.poll() is None:
                    tick()
                    if time.monotonic() - start >= timeout:
                        raise CommandError('command deadline exceeded')
                    for key, _ in selector.select(.05):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            eof = True
                        data.extend(chunk)
                        if len(data) > limit:
                            raise CommandError('command output limit exceeded')
                if process.returncode:
                    raise CommandError('command failed')
            return json.loads(data)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise


def command(value):
    if (not isinstance(value, (list, tuple)) or not value or len(value) > 2
            or not all(isinstance(part, str) and part for part in value)
            or not os.path.isabs(value[0])):
        raise ValueError('absolute operator command path required')
    # Supports standalone tools or the existing k3s kubectl/crictl wrapper.
    return tuple(value)


class KubernetesPods:
    def __init__(self, node, executable, kubeconfig, *, run=read_json):
        if not re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', node) or not os.path.isabs(kubeconfig):
            raise ValueError('node name and absolute kubeconfig path required')
        self.node, self.run = node, run
        self.argv = command(executable) + ('--kubeconfig', kubeconfig, '--request-timeout=2s',
                                           '--insecure-skip-tls-verify=false')
        self.checked = False

    def snapshot(self):
        if not self.checked:
            config = self.run((*self.argv, 'config', 'view', '--minify', '--output=json'))
            try:
                clusters = config['clusters']
                if (len(clusters) != 1 or not clusters[0]['cluster']['server'].startswith('https://')
                        or clusters[0]['cluster'].get('insecure-skip-tls-verify', False)):
                    raise ValueError('verified HTTPS Kubernetes endpoint required')
            except (KeyError, TypeError, AttributeError) as exc:
                raise ValueError('invalid Kubernetes connection configuration') from exc
            self.checked = True
        observed_at = time.monotonic()
        value = self.run((*self.argv, 'get',
                          '--raw=/api/v1/pods?fieldSelector=spec.nodeName%3D' + self.node))
        try:
            if (value['kind'] not in ('PodList', 'List') or value['apiVersion'] != 'v1'
                    or value.get('metadata', {}).get('continue')
                    or not isinstance(value['items'], list) or len(value['items']) > 4096):
                raise ValueError('complete bounded Pod list required')
            if any(p['spec']['nodeName'] != self.node for p in value['items']):
                raise ValueError('API returned a foreign node Pod')
            return value['items'], observed_at
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('invalid Kubernetes Pod list') from exc


class Containerd:
    def __init__(self, executable, endpoint, *, run=read_json):
        if not isinstance(endpoint, str) or not endpoint.startswith('unix:///'):
            raise ValueError('explicit local runtime socket required')
        self.argv = command(executable) + ('--runtime-endpoint', endpoint, '--timeout=2s')
        self.run = run

    def inspect(self, pod):
        # Read-only commands only. Runtime metadata, never name regexes, select
        # the sandbox; multiple ready sandboxes are ambiguous and rejected.
        value = self.run((*self.argv, 'pods', '--state=ready', '--output=json'))
        try:
            if not isinstance(value['items'], list) or len(value['items']) > 4096:
                raise ValueError('bounded runtime list required')
            matches = [s for s in value['items'] if s.get('metadata', {}).get('uid') == pod.uid]
            if len(matches) != 1 or not re.fullmatch('[a-f0-9]{64}', matches[0]['id']):
                raise ValueError('unique ready sandbox required')
            identifier = matches[0]['id']
            data = self.run((*self.argv, 'inspectp', '--output=json', identifier))
            result = Sandbox.from_status(data, pod)
            if result.id != identifier:
                raise ValueError('runtime returned a different sandbox')
            return result
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('invalid runtime sandbox list') from exc
