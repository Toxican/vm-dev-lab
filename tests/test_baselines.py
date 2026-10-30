# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test baseline bundle integrity, ownership, and atomic publication.

"""P08-A: Offline bundles, integrity, and atomic visibility."""
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.baselines import BaselineManager
from vm_dev_lab.errors import LabError
try:
    import test_lifecycle as lifecycle_fixtures
except ModuleNotFoundError:
    import tests.test_lifecycle as lifecycle_fixtures


class BaselineTests(unittest.TestCase):
    _write = lifecycle_fixtures.LifecycleTests._write
    _id = staticmethod(lifecycle_fixtures.LifecycleTests._id)
    _resources = lifecycle_fixtures.LifecycleTests._resources

    def setUp(self):
        lifecycle_fixtures.LifecycleTests.setUp(self)
        self.firmware = self.root / 'OVMF_CODE.fd'
        self.firmware.write_bytes(b'qualified firmware')
        self.firmware_hash = hashlib.sha256(self.firmware.read_bytes()).hexdigest()
        root = ET.fromstring(self.domain._xml)
        root.find('./os/loader').text = str(self.firmware)
        self.domain._xml = ET.tostring(root, encoding='unicode')
        private_xml = self.paths.data / 'instances' / self.record['instance_id'] / 'domain.xml'
        private_xml.write_text(self.domain._xml)
        # Adjust the P07 fixture to the actually required SSH policy value.
        guest_path = self.paths.data / 'instances' / self.record['instance_id'] / 'guest-manifest.json'
        guest = json.loads(guest_path.read_text())
        guest['provisioning']['ssh']['password_authentication'] = False
        guest_path.write_text(json.dumps(guest))
        # project-ready may be frozen only after a verified graceful shutdown.
        current = self.store.inspect(self.record['instance_id'])
        operation = self.store.begin(current, 'shutdown')
        self.store.advance(current['instance_id'], operation, 'defined', complete=True)
        self.deadline = time.monotonic() + 30
        self.manager = self._manager()

    def _tool(self, argv, deadline):
        if argv[1] == 'convert':
            Path(argv[-1]).write_bytes(b'standalone qcow2\n')
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        payload = {'format': 'qcow2', 'virtual-size': 4096}
        if '--backing-chain' in argv:
            output = json.dumps([payload]).encode()
        else:
            output = json.dumps(payload).encode()
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def _manager(self, *, tool=None, disk_usage=None):
        kwargs = {}
        if disk_usage is not None:
            kwargs['disk_usage'] = disk_usage
        manager = BaselineManager(self.lifecycle, clock=time.monotonic,
                                  tool=tool or self._tool, **kwargs)
        return manager

    def _create(self, name='project-base'):
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}):
            return self.manager.create('arch-test', name, 'project-ready', self.deadline)

    def _remove_lock_runtime(self):
        self.assertEqual(self.paths.runtime.parent, self.root)
        for entry in self.paths.runtime.iterdir():
            self.assertTrue(entry.is_file() and not entry.is_symlink())
            entry.unlink()
        self.paths.runtime.rmdir()

    def _lifecycle_verify(self, target, baseline_id):
        with patch.object(
                self.lifecycle, '_run',
                side_effect=lambda argv, deadline, timeout: self._tool(argv, deadline)):
            return self.lifecycle.verify_snapshot(target, baseline_id, self.deadline)

    def _lifecycle_list(self, target):
        with patch.object(
                self.lifecycle, '_run',
                side_effect=lambda argv, deadline, timeout: self._tool(argv, deadline)):
            return self.lifecycle.list_snapshots(target, self.deadline)

    def test_complete_bundle_creation_and_independent_verification(self):
        result = self._create()
        self.assertTrue(result['verified'])
        path = Path(result['path'])
        self.assertEqual(set(p.name for p in path.iterdir()), {
            'disk.qcow2','nvram.fd','domain.xml','instance.json','guest-manifest.json','manifest.json'})
        manifest = json.loads((path / 'manifest.json').read_text())
        self.assertEqual(path.name, manifest['baseline_id'])
        self.assertTrue(manifest['disk']['standalone'])
        self.assertEqual(manifest['instance']['domain_uuid'], self.record['domain_uuid'])
        self.assertEqual(manifest['guest_identity']['seed_instance_id'], self.data['seed']['seed_instance_id'])
        verified = self.manager.verify('arch-test', result['baseline_id'])
        self.assertEqual(verified['baseline_id'], result['baseline_id'])
        self.assertEqual(self.manager.list('arch-test')['baselines'], [
            {'name':'project-base','baseline_id':result['baseline_id'],
             'verified':True,'readiness':'project-ready'}])

    def test_disk_nvram_and_identity_are_bound(self):
        result = self._create(); path = Path(result['path'])
        manifest = json.loads((path / 'manifest.json').read_text())
        self.assertEqual(manifest['files']['nvram.fd']['sha256'],
                         hashlib.sha256((path/'nvram.fd').read_bytes()).hexdigest())
        instance = json.loads((path/'instance.json').read_text())
        self.assertEqual(instance['domain_uuid'], manifest['instance']['domain_uuid'])

    def test_missing_tampered_and_foreign_components_are_rejected(self):
        for index, (action, code) in enumerate((
                (lambda p: (p/'nvram.fd').unlink(), 'BASELINE_INCOMPLETE'),
                (lambda p: (p/'disk.qcow2').write_bytes(b'tampered'), 'BASELINE_HASH_MISMATCH'),
                (lambda p: (p/'foreign').write_bytes(b'x'), 'BASELINE_INCOMPLETE'))):
            with self.subTest(code=code):
                result = self._create('base-' + str(index))
                path = Path(result['path']); action(path)
                with self.assertRaises(LabError) as caught:
                    self.manager.verify('arch-test', result['baseline_id'])
                self.assertEqual(caught.exception.detail['code'], code)

    def test_bad_hash_and_corrupt_manifest_are_rejected(self):
        result = self._create(); path = Path(result['path'])
        manifest = json.loads((path/'manifest.json').read_text())
        manifest['files']['disk.qcow2']['sha256'] = '0' * 64
        (path/'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(LabError) as caught:
            self.manager.verify('arch-test', result['baseline_id'])
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_MANIFEST_INVALID')
        (path/'manifest.json').write_bytes(b'{')
        with self.assertRaises(LabError) as caught:
            self.manager.verify('arch-test', result['baseline_id'])
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_MANIFEST_INVALID')

    def test_existing_name_and_content_id_are_never_overwritten(self):
        first = self._create(); before = (Path(first['path'])/'manifest.json').read_bytes()
        with self.assertRaises(LabError) as caught:
            self._create()
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_NAME_EXISTS')
        self.assertEqual((Path(first['path'])/'manifest.json').read_bytes(), before)

    def test_interruption_during_staging_is_not_visible(self):
        def interrupted(argv, deadline):
            if argv[1] == 'convert':
                Path(argv[-1]).write_bytes(b'partial')
                raise KeyboardInterrupt
            return self._tool(argv, deadline)
        manager = self._manager(tool=interrupted)
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                self.assertRaises(KeyboardInterrupt):
            manager.create('arch-test','interrupted','project-ready',self.deadline)
        self.assertEqual(manager.list('arch-test')['baselines'], [])
        stages = list((Path(self.data['storage']).parent/'.baseline-staging').iterdir())
        self.assertEqual(len(stages), 1)
        self.assertTrue((stages[0]/'disk.qcow2').exists())

    def test_enospc_preflight_and_runtime_leave_no_published_pointer(self):
        low = self._manager(disk_usage=lambda _: SimpleNamespace(free=1))
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                self.assertRaises(LabError) as caught:
            low.create('arch-test','no-space','project-ready',self.deadline)
        self.assertEqual(caught.exception.detail['code'],'BASELINE_NO_SPACE')

        def enospc(argv, deadline):
            if argv[1] == 'convert':
                raise OSError(errno.ENOSPC, 'injected')
            return self._tool(argv, deadline)
        manager = self._manager(tool=enospc)
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                self.assertRaises(LabError) as caught:
            manager.create('arch-test','runtime-full','project-ready',self.deadline)
        self.assertEqual(caught.exception.detail['code'],'BASELINE_NO_SPACE')
        self.assertEqual(manager.list('arch-test')['baselines'], [])

    def test_rename_and_index_failures_never_publish_incomplete_bundle(self):
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                patch('vm_dev_lab.baselines.os.rename', side_effect=OSError(errno.ENOSPC,'injected')), \
                self.assertRaises(LabError) as caught:
            self.manager.create('arch-test','rename-full','project-ready',self.deadline)
        self.assertEqual(caught.exception.detail['code'],'BASELINE_NO_SPACE')
        self.assertEqual(self.manager.list('arch-test')['baselines'], [])

        real_replace = os.replace
        def fail_baseline_index(source, target, *args, **kwargs):
            if target == 'baselines.json':
                raise OSError(errno.ENOSPC, 'injected')
            return real_replace(source, target, *args, **kwargs)
        with patch('vm_dev_lab.baselines.os.replace', side_effect=fail_baseline_index):
            with self.assertRaises(LabError) as caught: self._create('index-failed')
        self.assertEqual(caught.exception.detail['code'],'BASELINE_NO_SPACE')
        self.assertEqual(self.manager.list('arch-test')['baselines'], [])
        # The complete but unindexed bundle remains diagnostic material.
        sealed = list((Path(self.data['storage']).parent/'baselines'/self.record['instance_id']).iterdir())
        self.assertEqual(len(sealed), 1)

    def test_symlink_path_traversal_and_unknown_source_file_are_blocked(self):
        result = self._create(); path = Path(result['path'])
        disk = path/'disk.qcow2'; disk.unlink(); disk.symlink_to('/etc/passwd')
        with self.assertRaises(LabError) as caught:
            self.manager.verify('arch-test', result['baseline_id'])
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_HASH_MISMATCH')

        runtime = Path(self.data['storage']); (runtime/'foreign').write_bytes(b'x')
        with self.assertRaises(LabError) as caught:
            self._create('foreign-source')
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')
        runtime.joinpath('foreign').unlink()
        with self.assertRaises(LabError) as caught:
            self.manager.verify('arch-test', '../escape')
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_ID_INVALID')

    def test_active_foreign_and_managed_save_domains_are_rejected(self):
        cases = []
        self.domain.running = True
        cases.append(('DOMAIN_RUNNING', lambda: None))
        for expected, _ in cases:
            with self.assertRaises(LabError) as caught: self._create('active')
            self.assertEqual(caught.exception.detail['code'], expected)
        self.domain.running = False
        self.domain._uuid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        with self.assertRaises(LabError) as caught: self._create('foreign')
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')
        self.domain._uuid = self.record['domain_uuid']
        with patch.object(self.domain, 'hasManagedSaveImage', return_value=1), self.assertRaises(LabError) as caught:
            self._create('managed')
        self.assertEqual(caught.exception.detail['code'], 'MANAGED_SAVE_UNSUPPORTED')

    def test_invalid_or_unproven_readiness_is_rejected(self):
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}):
            with self.assertRaises(LabError) as caught:
                self.manager.create('arch-test','bad-label','unknown',self.deadline)
            self.assertEqual(caught.exception.detail['code'],'BASELINE_READINESS_INVALID')
            with self.assertRaises(LabError) as caught:
                self.manager.create('arch-test','wrong-proof','ssh-ready',self.deadline)
            self.assertEqual(caught.exception.detail['code'],'BASELINE_READINESS_UNPROVEN')

    def test_clean_has_positive_no_start_evidence(self):
        private = self.paths.data/'instances'/self.record['instance_id']
        guest_path = private/'guest-manifest.json'
        with self.store.lock('global'):
            state=self.store._read(); record=state['instances'][self.record['instance_id']]
            record['journal'].pop()
            self.store._write(state)
        guest=json.loads(guest_path.read_text())
        guest.update(cloud_init='pending',ssh_ready=False,project_ready=False)
        guest['provisioning'].update(status='provisioning',installed_packages={},error=None)
        guest['provisioning']['user']={'name':'developer','valid':False}
        guest['provisioning']['ssh']['password_authentication']=None
        guest['provisioning']['transaction']['exit_code']=None
        guest_path.write_text(json.dumps(guest))
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}):
            clean=self.manager.create('arch-test','clean-base','clean',self.deadline)
        self.assertEqual(clean['readiness']['label'],'clean')

    def test_ssh_ready_has_positive_guest_and_shutdown_evidence(self):
        guest_path=self.paths.data/'instances'/self.record['instance_id']/'guest-manifest.json'
        guest=json.loads(guest_path.read_text())
        guest.update(cloud_init='completed',ssh_ready=True,project_ready=False)
        guest['provisioning'].update(status='provisioning',installed_packages={},error=None)
        guest['provisioning']['transaction']['exit_code']=None
        guest_path.write_text(json.dumps(guest))
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}):
            ssh=self.manager.create('arch-test','ssh-base','ssh-ready',self.deadline)
        self.assertEqual(ssh['readiness']['label'],'ssh-ready')

    def test_preexisting_baseline_id_path_is_never_replaced(self):
        real_manifest=self.manager._manifest
        collision={}
        def manifest(**kwargs):
            value=real_manifest(**kwargs)
            target=Path(self.data['storage']).parent/'baselines'/self.record['instance_id']/value['baseline_id']
            target.mkdir()
            (target/'foreign').write_bytes(b'preserve')
            collision['target']=target
            return value
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                patch.object(self.manager, '_manifest', side_effect=manifest), \
                self.assertRaises(LabError) as caught:
            self.manager.create('arch-test','id-collision','project-ready',self.deadline)
        self.assertEqual(caught.exception.detail['code'],'BASELINE_ID_EXISTS')
        self.assertEqual((collision['target']/'foreign').read_bytes(),b'preserve')
        self.assertEqual(self.manager.list('arch-test')['baselines'], [])

    def test_verification_hashing_obeys_the_global_deadline(self):
        result=self._create()
        with self.assertRaises(LabError) as caught:
            self.manager.verify('arch-test',result['baseline_id'],deadline=0)
        self.assertEqual(caught.exception.detail['code'],'DEADLINE_EXCEEDED')

    def test_published_baseline_remains_listable_and_verifiable_after_vm_destroy(self):
        result=self._create()
        instance_id=result['instance_id']
        self.lifecycle.destroy('arch-test',time.monotonic()+30)
        self.assertFalse(Path(self.data['storage']).exists())
        verified=self.manager.verify(instance_id,result['baseline_id'],self.deadline)
        self.assertTrue(verified['verified'])
        self.assertEqual(self.manager.list(instance_id,self.deadline)['baselines'],[{
            'name':'project-base','baseline_id':result['baseline_id'],
            'verified':True,'readiness':'project-ready'}])

    def test_destroyed_baseline_verifies_without_preexisting_lock_runtime(self):
        result = self._create()
        instance_id = result['instance_id']
        self.lifecycle.destroy('arch-test', time.monotonic()+30)
        self._remove_lock_runtime()
        verified = self._lifecycle_verify(instance_id, result['baseline_id'])
        self.assertTrue(verified['verified'])
        self.assertEqual(self._lifecycle_list(instance_id)['baselines'], [{
            'name':'project-base','baseline_id':result['baseline_id'],
            'verified':True,'readiness':'project-ready'}])
        info = self.paths.runtime.stat()
        self.assertEqual((info.st_uid, info.st_mode & 0o777), (os.geteuid(), 0o700))

    def test_existing_instance_baseline_verification_keeps_runtime_identity(self):
        result = self._create()
        before = self._id(self.paths.runtime)
        verified = self._lifecycle_verify(
            self.record['instance_id'], result['baseline_id'])
        self.assertTrue(verified['verified'])
        self.assertEqual(self._id(self.paths.runtime), before)

    def test_destroyed_baseline_still_rejects_tampering_and_foreign_target(self):
        result = self._create()
        instance_id = result['instance_id']
        self.lifecycle.destroy('arch-test', time.monotonic()+30)
        self._remove_lock_runtime()
        (Path(result['path'])/'disk.qcow2').write_bytes(b'tampered')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.verify_snapshot(instance_id, result['baseline_id'], self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_HASH_MISMATCH')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.verify_snapshot(
                'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', result['baseline_id'], self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'REGISTRY_CONFLICT')

    def test_destroyed_baseline_requires_registry_and_index_evidence(self):
        result = self._create()
        instance_id = result['instance_id']
        self.lifecycle.destroy('arch-test', time.monotonic()+30)
        self._remove_lock_runtime()
        (self.paths.state/'baselines.json').unlink()
        with self.assertRaises(LabError) as caught:
            self.lifecycle.verify_snapshot(instance_id, result['baseline_id'], self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_NOT_PUBLISHED')
        (self.paths.state/'registry.json').unlink()
        with self.assertRaises(LabError) as caught:
            self.lifecycle.verify_snapshot(instance_id, result['baseline_id'], self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'PATH_UNSAFE')

    def test_destroyed_baseline_rejects_symlink_runtime_replacement(self):
        result = self._create()
        instance_id = result['instance_id']
        self.lifecycle.destroy('arch-test', time.monotonic()+30)
        self._remove_lock_runtime()
        replacement = self.root/'replacement'; replacement.mkdir(mode=0o700)
        self.paths.runtime.symlink_to(replacement, target_is_directory=True)
        with self.assertRaises(LabError) as caught:
            self.lifecycle.verify_snapshot(instance_id, result['baseline_id'], self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'PATH_UNSAFE')

    def test_external_start_during_conversion_blocks_publication(self):
        def starts_domain(argv, deadline):
            result = self._tool(argv, deadline)
            if argv[1] == 'convert': self.domain.running = True
            return result
        manager = self._manager(tool=starts_domain)
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                self.assertRaises(LabError) as caught:
            manager.create('arch-test','raced','project-ready',self.deadline)
        self.assertEqual(caught.exception.detail['code'],'DOMAIN_STARTED_DURING_BASELINE')
        self.assertEqual(manager.list('arch-test')['baselines'], [])

    def test_instance_lock_blocks_concurrent_creation(self):
        with self.store.lock(self.record['instance_id']), self.assertRaises(LabError) as caught:
            self._create('concurrent')
        self.assertEqual(caught.exception.detail['code'], 'LOCK_CONFLICT')

    def test_hard_stop_journal_can_never_prove_clean_shutdown(self):
        # Direct valid forced-shutdown sequence as an offline fixture.
        with self.store.lock('global'):
            state = self.store._read(); record = state['instances'][self.record['instance_id']]
            record['journal'][-1]['events'] = ['planned','forcing','defined']
            record['journal'][-1]['phase'] = 'defined'
            self.store._write(state)
        with patch('vm_dev_lab.baselines.FIRMWARE_CODE', self.firmware), \
                patch.dict('vm_dev_lab.baselines.FIRMWARE_HASHES', {'code': self.firmware_hash}), \
                self.assertRaises(LabError) as caught:
            self.manager.create('arch-test','unclean','project-ready',self.deadline)
        self.assertEqual(caught.exception.detail['code'],'BASELINE_READINESS_UNPROVEN')


if __name__ == '__main__':
    unittest.main()
