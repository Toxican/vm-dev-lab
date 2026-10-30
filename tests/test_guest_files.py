# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test guest file manifests, SFTP batches, and host staging safety.

"""P11-B: path, manifest, SFTP batch, and host-staging contract, offline only."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.errors import LabError
from vm_dev_lab.guest.files import (ADAPTER_VERSION, PROTOCOL_VERSION, RESPONSE_LIMIT,
    ADAPTER_SOURCE, HostDestination, download_batch, endpoint, endpoints, manifest_digest,
    remote_command, response, scan_host_source, upload_batch)
from vm_dev_lab.guest.exec import encode_frame


class GuestFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_endpoints_accept_unicode_spaces_quotes_and_exactly_one_vm(self):
        spec = endpoints(str(self.root / "source file'ä"), 'arch-test:/Projekt ä/quote"')
        self.assertEqual(spec['direction'], 'host-to-guest')
        self.assertEqual(spec['guest_path'], 'Projekt ä/quote"')
        reverse = endpoints('arch-test:/Result/result.bin', str(self.root/'result'))
        self.assertEqual(reverse['direction'], 'guest-to-host')
        for source, destination in (
                ('a', 'b'), ('a:/x', 'b:/y'), ('arch-test:/../x', 'host'),
                ('arch-test:/a\0b', 'host'), ('arch-test:/' + 'a/' * 20, 'host')):
            with self.subTest(source=source), self.assertRaises(LabError):
                endpoints(source, destination)

    def test_host_scan_manifest_fds_and_batch_never_embed_user_paths(self):
        source = self.root / "tree quote'ä"; source.mkdir()
        (source/'sub dir').mkdir(); (source/'sub dir'/'a ä.txt').write_bytes(b'hello')
        (source/'empty').write_bytes(b'')
        scanned = scan_host_source(source); self.addCleanup(scanned.close)
        self.assertEqual(scanned.kind, 'directory')
        self.assertEqual([item['path'] for item in scanned.public_manifest()],
                         ['empty', 'sub dir/a ä.txt'])
        batch = upload_batch(str(uuid4()), scanned)
        self.assertNotIn(str(source).encode(), batch)
        self.assertIn(b'/tmp/vm-dev-lab-copy-', batch)
        self.assertRegex(manifest_digest(scanned.kind, scanned.public_manifest()), r'^[0-9a-f]{64}$')

    def test_scan_rejects_secret_symlink_hardlink_fifo_and_limits(self):
        cases = []
        secret = self.root/'secret'; secret.mkdir(); (secret/'.env').write_text('TOKEN=x'); cases.append(secret)
        symlink = self.root/'symlink'; symlink.mkdir(); (symlink/'x').symlink_to('/etc/passwd'); cases.append(symlink)
        hard = self.root/'hard'; hard.mkdir(); (hard/'a').write_text('x'); os.link(hard/'a', hard/'b'); cases.append(hard)
        fifo = self.root/'fifo'; fifo.mkdir(); os.mkfifo(fifo/'pipe'); cases.append(fifo)
        image = self.root/'disk.qcow2'; image.write_bytes(b'x'); cases.append(image)
        disguised = self.root/'innocent.txt'
        disguised.write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n')
        cases.append(disguised)
        cases.append(Path('/dev/null'))
        for path in cases:
            with self.subTest(path=path), self.assertRaises((LabError, OSError)):
                scan_host_source(path)
        large = self.root/'large'; large.write_bytes(b'1234')
        with patch('vm_dev_lab.guest.files.MAX_FILE_SIZE', 3), self.assertRaises(LabError):
            scan_host_source(large)
        socket_info=SimpleNamespace(st_mode=0o140600,st_nlink=1,st_dev=1,st_ino=1)
        with patch('vm_dev_lab.guest.files.os.lstat',return_value=socket_info), self.assertRaises(LabError):
            scan_host_source(self.root/'socket-fixture')

    def test_source_inode_exchange_is_detected_while_open_fd_remains_bound(self):
        path = self.root/'source'; path.write_bytes(b'old')
        scanned = scan_host_source(path); self.addCleanup(scanned.close)
        path.unlink(); path.write_bytes(b'new')
        with self.assertRaises(LabError) as caught: scanned.verify()
        self.assertEqual(caught.exception.detail['code'], 'COPY_SOURCE_CHANGED')

    def test_download_batch_uses_only_fixed_staging_names(self):
        transfer = str(uuid4()); staging = '/tmp/vm-dev-lab-test-staging'
        files = [{'path':"evil ' ä",'size':0,'sha256':'0'*64}]
        batch = download_batch(transfer, files, staging)
        self.assertNotIn(b'evil', batch)
        self.assertIn(f'{staging}/00000000'.encode(), batch)

    def test_host_destination_verifies_hash_publishes_and_controls_overwrite(self):
        target = self.root/'result.bin'; transfer = str(uuid4())
        destination = HostDestination(target, transfer, False)
        staged = Path(destination.staging)/'00000000'; staged.write_bytes(b'result')
        manifest = [{'path':'result.bin','size':6,
                     'sha256':hashlib.sha256(b'result').hexdigest()}]
        destination.finalize('file', manifest); destination.close()
        self.assertEqual(target.read_bytes(), b'result')
        with self.assertRaises(LabError): HostDestination(target, str(uuid4()), False)
        transfer2 = str(uuid4()); replacement = HostDestination(target, transfer2, True)
        (Path(replacement.staging)/'00000000').write_bytes(b'new')
        replacement.finalize('file', [{'path':'x','size':3,
            'sha256':hashlib.sha256(b'new').hexdigest()}]); replacement.close()
        self.assertEqual(target.read_bytes(), b'new')

    def test_host_destination_rejects_hash_mismatch_and_protected_target(self):
        transfer = str(uuid4()); destination = HostDestination(self.root/'result', transfer, False)
        (Path(destination.staging)/'00000000').write_bytes(b'bad')
        with self.assertRaises(LabError) as caught:
            destination.finalize('file', [{'path':'x','size':3,'sha256':'0'*64}])
        self.assertEqual(caught.exception.detail['code'], 'COPY_INTEGRITY_MISMATCH')
        destination.close()
        protected = self.root/'.ssh'; protected.mkdir()
        with self.assertRaises(LabError): HostDestination(protected/'x', str(uuid4()), False)
        real_parent=self.root/'real-parent'; real_parent.mkdir()
        linked_parent=self.root/'linked-parent'; linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(LabError): HostDestination(linked_parent/'x', str(uuid4()), False)

    def test_protocol_rejects_wrong_job_version_and_unbound_response(self):
        transfer = str(uuid4())
        valid = {'protocol_version':PROTOCOL_VERSION,'adapter_version':ADAPTER_VERSION,
                 'action':'prepare-download','transfer_id':transfer,'ok':True,'code':None,
                 'kind':'file','files':[{'path':'x','size':0,'sha256':'0'*64}]}
        self.assertTrue(response(encode_frame(valid, RESPONSE_LIMIT), transfer,
                                 'prepare-download')['ok'])
        for change in ({'protocol_version':2}, {'transfer_id':str(uuid4())},
                       {'adapter_version':'other'}, {'files':[]}):
            with self.subTest(change=change), self.assertRaises(LabError):
                response(encode_frame({**valid, **change}, RESPONSE_LIMIT), transfer,
                         'prepare-download')
        self.assertNotIn('PRIVATE_USER_PATH', remote_command())
        compile(ADAPTER_SOURCE, '<vm-dev-lab-files-v1>', 'exec')

    def test_git_metadata_is_recorded_while_dot_git_is_not_transferred(self):
        repository=self.root/'repository'; repository.mkdir()
        subprocess.run(['git','init','-q',str(repository)],check=True)
        subprocess.run(['git','-C',str(repository),'config','user.email','fixture@example.invalid'],check=True)
        subprocess.run(['git','-C',str(repository),'config','user.name','Fixture'],check=True)
        (repository/'tracked').write_text('one')
        subprocess.run(['git','-C',str(repository),'add','tracked'],check=True)
        subprocess.run(['git','-C',str(repository),'commit','-qm','fixture'],check=True)
        (repository/'tracked').write_text('two')
        scanned=scan_host_source(repository); self.addCleanup(scanned.close)
        self.assertRegex(scanned.git['commit'],r'^[0-9a-f]{40}$')
        self.assertTrue(scanned.git['dirty'])
        self.assertEqual([item['path'] for item in scanned.public_manifest()],['tracked'])


if __name__ == '__main__':
    unittest.main()
