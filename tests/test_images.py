# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test local image format, signature, and immutable cache validation.

"""P05: small local format and signature fixtures; no real guest images."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from vm_dev_lab.errors import LabError
from vm_dev_lab.process import run
from vm_dev_lab.storage.images import ImageCache, ImageSpec, TrustPolicy, signature_status
from vm_dev_lab.provisioning.arch import cloud_image_spec

FPR = 'A' * 40


def fixture():
    data = bytearray(512)
    struct.pack_into('>4sI', data, 0, b'QFI\xfb', 3)
    struct.pack_into('>I', data, 20, 9)
    struct.pack_into('>Q', data, 24, 1024 * 1024)
    struct.pack_into('>I', data, 100, 104)
    return data


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / 'source.fixture'; self.image.write_bytes(fixture())
        self.signature = self.root / 'signature.fixture'; self.signature.write_bytes(b'local-signature-fixture')
        self.keyring = self.root / 'public.fixture'; self.keyring.write_bytes(b'local-public-keyring-fixture')
        self.spec = cloud_image_spec('20261015.611680', 'https://example.invalid/Arch-Linux-x86_64-cloudimg-20261015.611680.qcow2', hashlib.sha256(self.image.read_bytes()).hexdigest(), 512, 2 * 1024 * 1024)
        self.policy = TrustPolicy('archlinux', (FPR,), hashlib.sha256(self.keyring.read_bytes()).hexdigest(), 'OFFLINE FIXTURE, not a publisher approval')
        self.commands = []
        self.sig_returncode = 0
        self.sig_output = f'[GNUPG:] GOODSIG fixture local\n[GNUPG:] VALIDSIG {FPR} 2026-10-26 1 0 4 0 22 8 00 {FPR}\n'.encode()
        self.info = {'format': 'qcow2', 'virtual-size': 1024 * 1024, 'format-specific': {'data': {}}}
        self.cache = ImageCache(self.root / 'cache', self.runner)

    def runner(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[0] == 'gpg': return self.sig_returncode, self.sig_output
        if argv[0] == 'qemu-img': return 0, json.dumps(self.info).encode()
        raise AssertionError(argv)

    def publish(self):
        return self.cache.import_local(self.spec, self.image, self.signature, self.keyring, self.policy)

    def fails(self, action, code):
        with self.assertRaises(LabError) as caught: action()
        self.assertEqual(caught.exception.detail['code'], code)
        return caught.exception

    def test_atomic_cache_and_reverification_do_not_trust_a_boolean(self):
        result = self.publish()
        path = self.root / 'cache' / self.spec.sha256
        self.assertEqual(result, self.cache.verify_entry(self.spec.sha256, self.policy))
        self.assertEqual(result, self.publish())
        self.assertEqual((path / 'image.qcow2').stat().st_mode & 0o777, 0o400)
        self.assertEqual(path.stat().st_mode & 0o777, 0o500)
        self.assertTrue(any('/proc/self/fd/' in ' '.join(c) for c in self.commands))
        os.chmod(path / 'manifest.json', 0o600)
        manifest = json.loads((path / 'manifest.json').read_text()); manifest['signature']['primary_fingerprint'] = 'B' * 40
        (path / 'manifest.json').write_text(json.dumps(manifest))
        self.fails(lambda: self.cache.verify_entry(self.spec.sha256, self.policy), 'CACHE_INVALID')

    def test_unknown_unsigned_expired_and_wrong_signer_are_rejected(self):
        for status in (b'', self.sig_output + b'[GNUPG:] BADSIG forged\n', self.sig_output + b'[GNUPG:] EXPKEYSIG expired\n', self.sig_output + self.sig_output):
            with self.subTest(status=status):
                self.fails(lambda: signature_status(0, status, self.policy), 'SIGNATURE_INVALID')
        self.fails(lambda: signature_status(1, self.sig_output, self.policy), 'SIGNATURE_INVALID')
        self.fails(lambda: signature_status(0, self.sig_output.replace(b' 8 00', b' 2 00'), self.policy), 'SIGNATURE_INVALID')
        self.fails(lambda: signature_status(0, self.sig_output.replace(FPR.encode(), b'B' * 40), self.policy), 'SIGNER_NOT_APPROVED')
        self.sig_returncode = 1
        self.fails(self.publish, 'SIGNATURE_INVALID')
        self.assertFalse((self.root / 'cache' / self.spec.sha256).exists())
        self.assertFalse(any(c[0] == 'qemu-img' for c in self.commands))

    def test_mirror_hash_alone_wrong_keyring_and_wrong_publisher_never_suffice(self):
        self.policy = replace(self.policy, keyring_sha256='0' * 64)
        self.fails(self.publish, 'TRUST_ANCHOR_MISMATCH')
        self.assertEqual(self.commands, [])
        self.policy = replace(self.policy, publisher='another')
        self.fails(self.publish, 'SIGNER_NOT_APPROVED')
        self.fails(lambda: TrustPolicy('archlinux', (), '0' * 64, ''), 'TRUST_ANCHOR_MISSING')
        self.fails(lambda: TrustPolicy('archlinux', (FPR,), '0' * 64, True), 'TRUST_ANCHOR_MISSING')

    def test_hash_and_size_limits_fail_before_image_tools(self):
        self.image.write_bytes(b'changed')
        self.fails(self.publish, 'IMAGE_HASH_MISMATCH')
        self.assertEqual(self.commands, [])
        self.image.write_bytes(b'x' * 513)
        self.fails(self.publish, 'IMAGE_SIZE_LIMIT')

    def test_backing_external_data_encryption_and_virtual_size_are_checked_before_qemu(self):
        for offset, value, fmt in ((8, 128, '>Q'), (16, 10, '>I'), (72, 4, '>Q'), (32, 1, '>I'), (24, 10**12, '>Q')):
            with self.subTest(offset=offset):
                data = fixture(); struct.pack_into(fmt, data, offset, value); self.image.write_bytes(data)
                self.spec = replace(self.spec, sha256=hashlib.sha256(data).hexdigest())
                self.commands.clear()
                self.fails(self.publish, 'IMAGE_FORMAT_UNSAFE')
                self.assertFalse(any(c[0] == 'qemu-img' for c in self.commands))
                self.assertFalse((self.root / 'cache' / self.spec.sha256).exists())

    def test_image_tool_metadata_cannot_override_header_or_allow_external_files(self):
        for info in ({'format': 'raw', 'virtual-size': 1048576}, {'format': 'qcow2', 'virtual-size': True},
                     {'format': 'qcow2', 'virtual-size': 1048576, 'backing-filename': '/etc/passwd'},
                     {'format': 'qcow2', 'virtual-size': 1048576, 'format-specific': {'data': {'data-file': '/etc/passwd'}}}):
            self.info = info
            self.fails(self.publish, 'IMAGE_FORMAT_UNSAFE')

    def test_symlinks_fifo_traversal_and_existing_cache_paths_are_not_followed(self):
        self.image.unlink(); self.image.symlink_to(self.keyring)
        self.fails(self.publish, 'IMAGE_PATH_UNSAFE')
        self.image.unlink(); os.mkfifo(self.image)
        self.fails(self.publish, 'IMAGE_PATH_UNSAFE')
        self.fails(lambda: ImageCache(self.root / '../escape'), 'IMAGE_PATH_UNSAFE')
        target = self.root / 'cache' / self.spec.sha256
        target.symlink_to(self.root, target_is_directory=True)
        self.fails(self.publish, 'IMAGE_PATH_UNSAFE')
        self.assertEqual(self.keyring.read_bytes(), b'local-public-keyring-fixture')

    def test_failed_publication_never_exposes_partial_entry(self):
        with patch('vm_dev_lab.storage.images.os.rename', side_effect=OSError('ENOSPC')):
            with self.assertRaises(LabError): self.publish()
        self.assertFalse((self.root / 'cache' / self.spec.sha256).exists())
        self.assertTrue(list((self.root / 'cache').glob('.staging-*')))

    def test_arch_adapter_rejects_mutable_version_basic_image_and_urls(self):
        self.fails(lambda: cloud_image_spec('latest', self.spec.source_url, self.spec.sha256, 512, 1024), 'IMAGE_SPEC_INVALID')
        for url in ('http://example.invalid/image', self.spec.source_url.replace('cloudimg', 'basic'), self.spec.source_url + '?token=secret'):
            self.fails(lambda: replace(self.spec, source_url=url), 'IMAGE_SPEC_INVALID')

    def test_tool_status_stdout_is_separate_and_bounded(self):
        status, output = run([sys.executable, '-c', 'import sys; print("machine"); print("untrusted diagnostic", file=sys.stderr)'])
        self.assertEqual((status, output.strip()), (0, b'machine'))
        with self.assertRaises(LabError) as caught:
            run([sys.executable, '-c', 'import sys; sys.stderr.write("x" * 4096)'], limit=128)
        self.assertEqual(caught.exception.detail['code'], 'TOOL_OUTPUT_LIMIT')
        with self.assertRaises(LabError) as caught:
            run([sys.executable, '-c', 'import time; time.sleep(3)'], timeout=.1)
        self.assertEqual(caught.exception.exit_code, 7)

    @unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgconf'), 'GnuPG tools are missing; no installation')
    def test_actual_detached_signature_with_isolated_ephemeral_test_key(self):
        home = self.root / 'gnupg'; home.mkdir(mode=0o700)
        self.addCleanup(lambda: subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'], stdin=subprocess.DEVNULL, capture_output=True, timeout=10))
        def gpg(*args):
            result = subprocess.run(['gpg', '--homedir', str(home), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, 'Local GnuPG fixture tool failed')
            return result.stdout
        gpg('--quick-generate-key', 'vm-dev-lab offline fixture', 'ed25519', 'sign', '1d')
        listing = gpg('--with-colons', '--list-keys').decode()
        fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        self.keyring.write_bytes(gpg('--export', fingerprint))
        self.signature.unlink()
        gpg('--output', str(self.signature), '--detach-sign', str(self.image))
        self.policy = TrustPolicy('archlinux', (fingerprint,), hashlib.sha256(self.keyring.read_bytes()).hexdigest(), 'Ephemeral LOCAL TEST key, not an Arch publisher key')
        def runner(argv, **kwargs):
            return run(argv, **kwargs) if argv[0] == 'gpg' else self.runner(argv, **kwargs)
        self.cache = ImageCache(self.root / 'real-signature-cache', runner)
        self.assertEqual(self.publish()['signature']['primary_fingerprint'], fingerprint)
        self.assertEqual(self.cache.verify_entry(self.spec.sha256, self.policy)['image']['sha256'], self.spec.sha256)
        original_runner = self.cache.run
        def expired(argv, **kwargs):
            if argv[0] == 'gpg':
                return run([argv[0], '--faked-system-time', str(int(time.time()) + 172800), *argv[1:]], **kwargs)
            return self.runner(argv, **kwargs)
        self.cache.run = expired
        self.fails(lambda: self.cache.verify_entry(self.spec.sha256, self.policy), 'SIGNATURE_INVALID')
        self.cache.run = original_runner
        self.sig_returncode = 0
        # The real verifier must reject the test image after modification without new approval.
        self.image.write_bytes(b'bad' + bytes(fixture())[3:])
        self.spec = replace(self.spec, sha256=hashlib.sha256(self.image.read_bytes()).hexdigest())
        self.fails(self.publish, 'SIGNATURE_INVALID')
