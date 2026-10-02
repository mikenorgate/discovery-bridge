"""Disposable certificates only for the Kubernetes API TLS test."""
import subprocess

def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def make_test_pki(root):
    """Disposable server/client certificates for the kubectl test only."""
    for ca in ('ca',):
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', root / f'{ca}.key', '-out', root / f'{ca}.crt', '-days', '2',
                '-subj', f'/CN={ca}', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    for serial, name in enumerate(('server', 'node'), 10):
        openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', root / f'{name}.key', '-out', root / f'{name}.csr', '-subj', f'/CN={name}')
        extension = root / f'{name}.ext'
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                             'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'
                             f'extendedKeyUsage={"serverAuth" if name == "server" else "clientAuth"}\n'
                             'subjectAltName=DNS:gateway.test\n')
        issuer = 'ca'
        openssl('x509', '-req', '-in', root / f'{name}.csr', '-CA', root / f'{issuer}.crt',
                '-CAkey', root / f'{issuer}.key', '-set_serial', serial, '-days', '2',
                '-extfile', extension, '-out', root / f'{name}.crt')
