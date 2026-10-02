"""Actual installed kubectl, disposable TLS API fixture; no cluster connection."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

from discovery.node_inputs import CommandError, KubernetesPods
from test_broker import pod_item
from kubectl_pki import make_test_pki


def main():
    binary = shutil.which('kubectl')
    if not binary: raise SystemExit('an existing kubectl binary is required')
    calls = []
    mode = {'deny': False}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            parsed = urlsplit(self.path)
            assert parsed.path == '/api/v1/pods'
            assert parse_qs(parsed.query).get('fieldSelector') == ['spec.nodeName=node-1'], parsed.query
            assert set(parse_qs(parsed.query)) <= {'fieldSelector', 'timeout'}, parsed.query
            calls.append(self.path)
            value = {'kind': 'PodList', 'apiVersion': 'v1', 'metadata': {'resourceVersion': '123'}, 'items': [pod_item()]}
            status = 403 if mode['deny'] else 200
            if status == 403: value = {'kind': 'Status', 'apiVersion': 'v1', 'status': 'Failure', 'reason': 'Forbidden', 'code': 403}
            wire = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(wire)))
            self.end_headers(); self.wfile.write(wire)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary); make_test_pki(root)
        server = HTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / 'server.crt', root / 'server.key')
        context.load_verify_locations(root / 'ca.crt'); context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        config = {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'lab',
            'clusters': [{'name': 'lab', 'cluster': {'server': f'https://127.0.0.1:{server.server_port}',
                         'tls-server-name': 'gateway.test', 'certificate-authority': str(root / 'ca.crt')}}],
            'users': [{'name': 'lab', 'user': {'client-certificate': str(root / 'node.crt'), 'client-key': str(root / 'node.key')}}],
            'contexts': [{'name': 'lab', 'context': {'cluster': 'lab', 'user': 'lab'}}]}
        file = root / 'kubeconfig'; file.write_text(json.dumps(config)); file.chmod(0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            client = KubernetesPods('node-1', [binary], str(file))
            items, observed = client.snapshot()
            assert items == [pod_item()] and observed > 0 and len(calls) == 1
            version = subprocess.check_output([binary, 'version', '--client', '--output=json'])
            print(json.dumps({'case': 'actual_kubectl_verified_tls_node_scoped_list', 'status': 'pass',
                              'version': json.loads(version)['clientVersion']['gitVersion']}), flush=True)
            mode['deny'] = True
            try:
                client.snapshot()
                raise AssertionError('forbidden response admitted')
            except CommandError: pass
            print(json.dumps({'case': 'actual_kubectl_api_denial_rejected', 'status': 'pass'}), flush=True)
        finally:
            server.shutdown(); thread.join(); server.server_close()


if __name__ == '__main__': main()
