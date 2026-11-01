"""Sign measured OTA metadata offline; never publishes or changes a manifest.

Production key material must be supplied from the operator's private store.
Passwords use hidden input or stdin, never arguments/logs. Public verification
key must match the key provisioned into the protected controllers.
"""
import argparse
import getpass
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def openssl_path():
    result = shutil.which('openssl')
    fallback = Path('C:/Program Files/Git/usr/bin/openssl.exe')
    if not result and fallback.exists():
        result = str(fallback)
    if not result:
        raise RuntimeError('OpenSSL is required.')
    return result


def canonical(version, security_version, size, digest):
    if (not re.fullmatch(r'(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})', version) or
            any(int(n) > 0xffffffff for n in version.split('.')) or
            type(security_version) is not int or not 1 <= security_version <= 0xffffffff or
            type(size) is not int or not 1 <= size <= 4 * 1024 * 1024 or
            not re.fullmatch(r'[0-9a-f]{64}', digest)):
        raise ValueError('Invalid signed firmware metadata.')
    return f'GGFW1\nesp32-gopher\n{version}\n{security_version}\n{size}\n{digest}\n'.encode('ascii')


def sign(binary, version, security_version, private_key, public_key, password):
    binary = Path(binary)
    size = binary.stat().st_size
    if not 1 <= size <= 4 * 1024 * 1024:
        raise ValueError('Invalid firmware file size.')
    data = binary.read_bytes()
    if data[0] != 0xe9:
        raise ValueError('Expected an ESP image, not another artifact.')
    digest = hashlib.sha256(data).hexdigest()
    message = canonical(version, security_version, size, digest)
    openssl = openssl_path()
    public_info = subprocess.run([openssl, 'pkey', '-pubin', '-in', str(public_key),
                                  '-text_pub', '-noout'], capture_output=True, check=True).stdout
    if b'ASN1 OID: prime256v1' not in public_info:
        raise ValueError('Expected the provisioned ECDSA P-256 public key.')
    # The signing password is stdin only. OpenSSL errors are intentionally not
    # reflected; paths/credentials must not enter CI/support output.
    with tempfile.TemporaryDirectory(prefix='gg-ota-sign-') as temp:
        root = Path(temp)
        (root / 'message').write_bytes(message)
        result = subprocess.run([openssl, 'dgst', '-sha256', '-sign', str(private_key),
                                 '-passin', 'stdin', '-out', str(root / 'signature'),
                                 str(root / 'message')], input=password.encode() + b'\n', capture_output=True)
        if result.returncode:
            raise ValueError('Could not sign with the supplied private key.')
        verified = subprocess.run([openssl, 'dgst', '-sha256', '-verify', str(public_key),
                                   '-signature', str(root / 'signature'), str(root / 'message')],
                                  capture_output=True)
        if verified.returncode:
            raise ValueError('Signing key does not match the provisioned verification key.')
        signature = (root / 'signature').read_bytes()
    return dict(version=version, security_version=security_version, size=size,
                sha256=digest, signature=signature.hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--security-version', type=int, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('Refusing to overwrite existing metadata.')
    password = sys.stdin.readline().rstrip('\r\n') if args.password_stdin else getpass.getpass('Signing-key password (hidden): ')
    try:
        result = sign(args.binary, args.version, args.security_version,
                      args.private_key, args.public_key, password)
        with args.output.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('Signing failed. Verify the private input, password and provisioned public key.') from None
    finally:
        password = ''
    print('Signed measured metadata prepared; no release was published.')


if __name__ == '__main__':
    main()
