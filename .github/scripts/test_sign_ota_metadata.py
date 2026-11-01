import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('sign_ota_metadata', Path(__file__).with_name('sign_ota_metadata.py'))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)


class SignedMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key, self.pub = self.root / 'key.pem', self.root / 'pub.pem'
        self.openssl = signer.openssl_path()
        self.run_openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(self.key))
        self.run_openssl('pkey', '-in', str(self.key), '-pubout', '-out', str(self.pub))
        self.binary = self.root / 'fixture.bin'
        self.binary.write_bytes(b'\xe9' + b'isolated-signature-fixture' * 128)

    def run_openssl(self, *args):
        return subprocess.run([self.openssl, *args], check=True, capture_output=True)

    def test_real_signature_matches_canonical_firmware_message(self):
        meta = signer.sign(self.binary, '1.0.18', 1, self.key, self.pub, '')
        message = signer.canonical(meta['version'], meta['security_version'], meta['size'], meta['sha256'])
        (self.root / 'message').write_bytes(message)
        (self.root / 'signature').write_bytes(bytes.fromhex(meta['signature']))
        self.run_openssl('dgst', '-sha256', '-verify', str(self.pub), '-signature',
                         str(self.root / 'signature'), str(self.root / 'message'))
        (self.root / 'message').write_bytes(message.replace(b'1.0.18', b'1.0.17'))
        result = subprocess.run([self.openssl, 'dgst', '-sha256', '-verify', str(self.pub),
                                 '-signature', str(self.root / 'signature'), str(self.root / 'message')], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_refuses_wrong_key_malformed_version_and_unsigned_security_level(self):
        other = self.root / 'other.pem'
        self.run_openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(other))
        with self.assertRaises(ValueError):
            signer.sign(self.binary, '1.0.18', 1, other, self.pub, '')
        for version, level in [('01.0.18', 1), ('1.0.18-dev', 1), ('1.0.18', 0)]:
            with self.assertRaises(ValueError):
                signer.sign(self.binary, version, level, self.key, self.pub, '')

    def test_changed_bytes_get_a_different_signed_digest(self):
        before = signer.sign(self.binary, '1.0.18', 1, self.key, self.pub, '')
        with self.binary.open('ab') as output:
            output.write(b'changed')
        after = signer.sign(self.binary, '1.0.18', 1, self.key, self.pub, '')
        self.assertNotEqual(before['sha256'], after['sha256'])
        self.assertNotEqual(before['size'], after['size'])


if __name__ == '__main__':
    unittest.main()
