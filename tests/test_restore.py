# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test restore preparation, activation, recovery, and access checks.

"""P08-B1: Restore validation and protected staging without switching."""
from contextlib import ExitStack
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
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
from vm_dev_lab.restore import (ACTIVE_FILES, RestoreActivationManager,
                                RestorePreparationManager, RestoreRecoveryManager,
                                RestoreStartRecoveryManager)
try:
    import test_lifecycle as lifecycle_fixtures
except ModuleNotFoundError:
    import tests.test_lifecycle as lifecycle_fixtures


class RestorePreparationTests(unittest.TestCase):
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
        private = self.paths.data / 'instances' / self.record['instance_id']
        (private / 'domain.xml').write_text(self.domain._xml)
        guest_path = private / 'guest-manifest.json'
        guest = json.loads(guest_path.read_text())
        guest['provisioning']['ssh']['password_authentication'] = False
        guest_path.write_text(json.dumps(guest))
        current = self.store.inspect(self.record['instance_id'])
        operation = self.store.begin(current, 'shutdown')
        self.store.advance(current['instance_id'], operation, 'defined', complete=True)
        self.deadline = time.monotonic() + 30
        self.backings = {}
        self.acls = {}
        self.disk_usage = lambda _path: SimpleNamespace(free=100 * 1024 ** 3)
        self.baselines = BaselineManager(self.lifecycle, clock=time.monotonic,
                                         tool=self._tool, disk_usage=self.disk_usage)
        with self._firmware():
            self.baseline = self.baselines.create(
                'arch-test', 'project-base', 'project-ready', self.deadline)
        self.manager = RestorePreparationManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool,
            disk_usage=self.disk_usage)
        self.operation = '66666666-6666-4666-8666-666666666666'

    def _firmware(self):
        return _Firmware(self.firmware, self.firmware_hash)

    def _tool(self, argv, deadline):
        if argv[0] == 'setfacl':
            if '--remove-default' in argv:
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            path = Path(argv[-1]); acl = argv[argv.index('--set') + 1]
            self.acls[str(path)] = acl
            if path.is_dir():
                path.chmod(0o710)
            elif path.name in {'disk.qcow2', 'nvram.fd'}:
                path.chmod(0o660)
            else:
                path.chmod(0o600)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        if argv[0] == 'getfacl':
            acl = self.acls.get(str(Path(argv[-1])))
            if acl is None:
                info = Path(argv[-1]).stat()
                bits = stat.S_IMODE(info.st_mode)
                def permissions(value):
                    return ''.join((letter if value & bit else '-')
                                   for letter, bit in (('r', 4), ('w', 2), ('x', 1)))
                acl = '\n'.join((
                    f'user::{permissions((bits >> 6) & 7)}',
                    f'group::{permissions((bits >> 3) & 7)}',
                    f'other::{permissions(bits & 7)}',
                ))
            if '\n' in acl:
                return subprocess.CompletedProcess(argv, 0, (acl + '\n').encode(), b'')
            names = {'u': 'user', 'g': 'group', 'm': 'mask', 'o': 'other'}
            output = '\n'.join(
                names[item.split(':', 1)[0]] + ':' + item.split(':', 1)[1]
                for item in acl.split(',')) + '\n'
            return subprocess.CompletedProcess(argv, 0, output.encode(), b'')
        if argv[1] == 'convert':
            Path(argv[-1]).write_bytes(b'standalone qcow2\n')
            Path(argv[-1]).chmod(0o600)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        if argv[1] == 'create':
            target = Path(argv[-2])
            target.write_bytes(b'restore overlay\n')
            target.chmod(0o600)
            self.backings[str(target)] = argv[argv.index('-b') + 1]
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        payload = {'format': 'qcow2', 'virtual-size': 4096,
                   'filename': str(Path(argv[-1]))}
        backing = self.backings.get(argv[-1])
        if backing:
            payload['full-backing-filename'] = backing
        if '--backing-chain' in argv:
            chain = [payload]
            if backing:
                chain.append({'format':'qcow2', 'virtual-size':4096,
                              'filename':backing})
            output = json.dumps(chain).encode()
        else:
            output = json.dumps(payload).encode()
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def _prepare(self, operation=None, manager=None):
        with self._firmware():
            return (manager or self.manager).prepare(
                'arch-test', self.baseline['baseline_id'], operation or self.operation,
                self.deadline)

    def _snapshot(self):
        runtime = Path(self.data['storage'])
        bundle = Path(self.baseline['path'])
        registry = json.loads((self.paths.state / 'registry.json').read_text())
        registry.pop('resources', None)
        return {
            'registry': registry,
            'xml': self.domain._xml,
            'disk': (runtime / 'work.qcow2').read_bytes(),
            'nvram': (runtime / 'nvram.fd').read_bytes(),
            'bundle': {path.name: path.read_bytes() for path in bundle.iterdir()},
            'backend': list(self.backend.domains),
        }

    def test_valid_baseline_prepares_complete_bound_generation_without_switch(self):
        before = self._snapshot()
        with ExitStack() as stack:
            for method in ('define','undefine','start','request_shutdown','force_stop'):
                stack.enter_context(patch.object(
                    self.backend, method, side_effect=AssertionError('B1 backend mutation')))
            result = self._prepare()
        self.assertTrue(result['prepared'])
        self.assertFalse(result['activation_permitted'])
        self.assertTrue(result['requires_reverification'])
        path = Path(result['path'])
        self.assertEqual(set(item.name for item in path.iterdir()),
                         {'disk.qcow2','nvram.fd','domain.xml','preparation.json'})
        manifest = json.loads((path / 'preparation.json').read_text())
        self.assertEqual(manifest['schema_version'], 1)
        self.assertEqual(manifest['operation_id'], self.operation)
        self.assertEqual(manifest['baseline_id'], self.baseline['baseline_id'])
        self.assertEqual(manifest['status'], 'prepared')
        self.assertEqual(set(manifest['artifacts']), {'disk.qcow2','nvram.fd','domain.xml'})
        root = ET.fromstring((path/'domain.xml').read_bytes())
        disk = next(entry for entry in root.findall('./devices/disk')
                    if entry.get('device') == 'disk')
        backing = disk.find('backingStore')
        self.assertEqual(backing.attrib, {'type': 'file'})
        self.assertEqual(backing.find('format').attrib, {'type': 'qcow2'})
        source = backing.find('source')
        self.assertEqual(source.get('file'), str(Path(self.baseline['path'])/'disk.qcow2'))
        self.assertEqual(source.find('seclabel').attrib,
                         {'model': 'dac', 'relabel': 'no'})
        self.assertEqual(list(backing.find('backingStore')), [])
        validator = shutil.which('virt-xml-validate')
        if validator is None:
            self.skipTest('installed libvirt schema tool is missing')
        validated = subprocess.run(
            [validator, str(path/'domain.xml'), 'domain'], capture_output=True, check=False)
        self.assertEqual(validated.returncode, 0, validated.stderr.decode())
        self.assertEqual(self._snapshot(), before)

    def test_restore_requires_backing_store_input_capability_before_staging(self):
        unsupported = ('<domainCapabilities><features>'
                       '<backingStoreInput supported="no"/>'
                       '</features></domainCapabilities>')
        with patch.object(self.backend, 'getDomainCapabilities', return_value=unsupported), \
                self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'],
                         'RESTORE_BACKING_STORE_UNSUPPORTED')
        self.assertFalse((Path(self.data['storage']).parent/'.restore-staging').exists())

    def test_wrong_baseline_id_and_destroyed_target_are_rejected(self):
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', '0' * 64, self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'BASELINE_NOT_PUBLISHED')
        self.lifecycle.destroy('arch-test', self.deadline)
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare(self.record['instance_id'], self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_TARGET_DESTROYED')

    def test_missing_or_tampered_baseline_disk_and_nvram_are_rejected(self):
        for name, action, code in (
                ('disk.qcow2', lambda p: p.unlink(), 'BASELINE_INCOMPLETE'),
                ('nvram.fd', lambda p: p.write_bytes(b'tampered'), 'BASELINE_HASH_MISMATCH')):
            with self.subTest(name=name):
                original = Path(self.baseline['path']) / name
                saved = original.read_bytes()
                action(original)
                with self._firmware(), self.assertRaises(LabError) as caught:
                    self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                         self.operation, self.deadline)
                self.assertEqual(caught.exception.detail['code'], code)
                original.write_bytes(saved)

    def test_firmware_and_domain_xml_incompatibility_are_rejected(self):
        self.firmware.write_bytes(b'changed')
        with self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_FIRMWARE_INCOMPATIBLE')
        self.firmware.write_bytes(b'qualified firmware')
        root = ET.fromstring(self.domain._xml)
        root.find('memory').text = '1024'
        self.domain._xml = ET.tostring(root, encoding='unicode')
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_XML_INCOMPATIBLE')

    def test_active_and_managed_save_domains_are_rejected(self):
        domain = self.backend.domain(self.record['domain_uuid'])
        domain.running = True
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'DOMAIN_RUNNING')
        domain.running = False
        domain.hasManagedSaveImage = lambda _flags: 1
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'MANAGED_SAVE_UNSUPPORTED')

    def test_unknown_disk_tpm_and_metadata_changes_are_rejected(self):
        variants = ('disk', 'tpm', 'metadata')
        for variant in variants:
            with self.subTest(variant=variant):
                original = self.domain._xml
                root = ET.fromstring(original)
                if variant == 'disk':
                    disk = ET.SubElement(root.find('devices'), 'disk', type='file', device='disk')
                    ET.SubElement(disk, 'source', file='/foreign.qcow2')
                elif variant == 'tpm':
                    ET.SubElement(root.find('devices'), 'tpm')
                else:
                    next(iter(root.find('metadata'))).set('lab_id',
                        '77777777-7777-4777-8777-777777777777')
                self.domain._xml = ET.tostring(root, encoding='unicode')
                with self._firmware(), self.assertRaises(LabError) as caught:
                    self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                         self.operation, self.deadline)
                self.assertIn(caught.exception.detail['code'],
                              {'PERSISTENT_DEVICE_UNSUPPORTED','OWNERSHIP_MISMATCH'})
                self.domain._xml = original

    def test_registry_path_and_inode_replacement_block_before_staging(self):
        runtime = Path(self.data['storage'])
        current = runtime / 'work.qcow2'
        saved = current.read_bytes()
        current.unlink(); current.write_bytes(saved)
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')
        self.assertFalse((runtime.parent / '.restore-staging').exists())

    def test_space_preflight_and_runtime_enospc_never_report_prepared(self):
        low = RestorePreparationManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool,
            disk_usage=lambda _path: SimpleNamespace(free=1))
        with self._firmware(), self.assertRaises(LabError) as caught:
            low.prepare('arch-test', self.baseline['baseline_id'], self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_NO_SPACE')

        def enospc(argv, deadline):
            if argv[1] == 'create':
                raise OSError(errno.ENOSPC, 'injected')
            return self._tool(argv, deadline)
        manager = RestorePreparationManager(
            self.lifecycle, clock=time.monotonic, tool=enospc,
            disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(LabError) as caught:
            manager.prepare('arch-test', self.baseline['baseline_id'], self.operation,
                            self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_NO_SPACE')
        state = json.loads((Path(self.data['storage']).parent / '.restore-staging' /
                            self.record['instance_id'] / self.operation /
                            'preparation.json').read_text())
        self.assertEqual(state['status'], 'failed')

    def test_interruptions_during_disk_and_nvram_staging_are_diagnostic(self):
        before = self._snapshot()
        def interrupt_disk(argv, deadline):
            if argv[1] == 'create':
                Path(argv[-2]).write_bytes(b'partial disk')
                raise KeyboardInterrupt
            return self._tool(argv, deadline)
        disk_manager = RestorePreparationManager(
            self.lifecycle, clock=time.monotonic, tool=interrupt_disk,
            disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(KeyboardInterrupt):
            disk_manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        path = Path(self.data['storage']).parent / '.restore-staging' / self.record['instance_id'] / self.operation
        status = json.loads((path / 'preparation.json').read_text())
        self.assertEqual(status['status'], 'interrupted')
        with self._firmware():
            diagnostic = self.manager.inspect(
                'arch-test', self.baseline['baseline_id'], self.operation, self.deadline)
        self.assertEqual((diagnostic['status'], diagnostic['prepared']), ('interrupted', False))
        self.assertEqual(self._snapshot(), before)

        operation = '77777777-7777-4777-8777-777777777777'
        def interrupt_copy(source, target, deadline, clock):
            Path(target).write_bytes(b'partial')
            raise KeyboardInterrupt
        with patch('vm_dev_lab.restore._copy_file', side_effect=interrupt_copy), \
                self._firmware(), self.assertRaises(KeyboardInterrupt):
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 operation, self.deadline)
        path = Path(self.data['storage']).parent / '.restore-staging' / self.record['instance_id'] / operation
        status = json.loads((path / 'preparation.json').read_text())
        self.assertEqual(status['status'], 'interrupted')
        self.assertNotEqual(set(path.iterdir()), set())
        self.assertEqual(self._snapshot(), before)

    def test_existing_operation_and_instance_lock_block_concurrency(self):
        self._prepare()
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_OPERATION_EXISTS')
        with self.store.lock(self.record['instance_id']), self._firmware(), \
                self.assertRaises(LabError) as caught:
            self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                 '77777777-7777-4777-8777-777777777777', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'LOCK_CONFLICT')

    def test_external_start_during_staging_never_reports_prepared(self):
        def starts_domain(argv, deadline):
            result = self._tool(argv, deadline)
            if argv[1] == 'create':
                self.domain.running = True
            return result
        manager = RestorePreparationManager(
            self.lifecycle, clock=time.monotonic, tool=starts_domain,
            disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(LabError) as caught:
            manager.prepare('arch-test', self.baseline['baseline_id'],
                            self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'DOMAIN_RUNNING')
        state = json.loads((Path(self.data['storage']).parent / '.restore-staging' /
                            self.record['instance_id'] / self.operation /
                            'preparation.json').read_text())
        self.assertEqual(state['status'], 'failed')

    def test_prepared_artifact_exchange_and_source_change_are_detected(self):
        result = self._prepare()
        path = Path(result['path'])
        disk = path / 'disk.qcow2'
        disk.unlink(); disk.write_bytes(b'replaced')
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.inspect('arch-test', self.baseline['baseline_id'],
                                 self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_HASH_MISMATCH')

        operation = '77777777-7777-4777-8777-777777777777'
        second = self._prepare(operation)
        runtime_disk = Path(self.data['storage']) / 'work.qcow2'
        runtime_disk.write_bytes(b'changed without inode replacement')
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.manager.inspect('arch-test', self.baseline['baseline_id'],
                                 operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_SOURCE_CHANGED')
        self.assertTrue(Path(second['path']).exists())

    def test_symlink_and_hardlink_staging_artifacts_are_rejected(self):
        real_tool = self._tool
        for kind in ('symlink','hardlink'):
            with self.subTest(kind=kind):
                operation = ('77777777-7777-4777-8777-' +
                             ('777777777777' if kind == 'symlink' else '888888888888'))
                def unsafe(argv, deadline, kind=kind):
                    if argv[1] == 'create':
                        target = Path(argv[-2])
                        if kind == 'symlink':
                            target.symlink_to(Path(self.baseline['path']) / 'disk.qcow2')
                        else:
                            os.link(Path(self.baseline['path']) / 'disk.qcow2', target)
                        self.backings[str(target)] = argv[argv.index('-b') + 1]
                        return subprocess.CompletedProcess(argv, 0, b'', b'')
                    return real_tool(argv, deadline)
                manager = RestorePreparationManager(
                    self.lifecycle, clock=time.monotonic, tool=unsafe,
                    disk_usage=self.disk_usage)
                with self._firmware(), self.assertRaises(LabError) as caught:
                    manager.prepare('arch-test', self.baseline['baseline_id'], operation,
                                    self.deadline)
                self.assertEqual(caught.exception.detail['code'], 'RESTORE_PATH_UNSAFE')


class RestoreActivationTests(unittest.TestCase):
    _write = lifecycle_fixtures.LifecycleTests._write
    _id = staticmethod(lifecycle_fixtures.LifecycleTests._id)
    _resources = lifecycle_fixtures.LifecycleTests._resources
    _firmware = RestorePreparationTests._firmware
    _tool = RestorePreparationTests._tool
    _prepare = RestorePreparationTests._prepare
    _snapshot = RestorePreparationTests._snapshot

    def setUp(self):
        RestorePreparationTests.setUp(self)
        self.activation = RestoreActivationManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool,
            disk_usage=self.disk_usage)

    def _activate(self, operation=None):
        with self._firmware():
            return self.activation.activate(
                'arch-test', self.baseline['baseline_id'], operation or self.operation,
                self.deadline)

    def _failed_operation(self):
        operation = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual(operation['kind'], 'restore_activation')
        self.assertEqual(operation['status'], 'review_required')
        self.assertEqual(operation['phase'], 'failed')
        return operation

    def _assert_start_blocked(self):
        with self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'REVIEW_REQUIRED')

    def test_prepared_pair_is_activated_and_old_generation_is_retained(self):
        private_guest = (self.paths.data/'instances'/self.record['instance_id'] /
                         'guest-manifest.json')
        baseline_guest = (Path(self.baseline['path'])/'guest-manifest.json').read_bytes()
        changed_guest = json.loads(private_guest.read_text())
        changed_guest['provisioning']['installed_packages']['git'] = '9.9-current'
        private_guest.write_text(json.dumps(changed_guest))
        prepared = self._prepare()
        runtime = Path(self.data['storage'])
        old = {name: (self._id(runtime/name), (runtime/name).read_bytes())
               for name in ('work.qcow2','nvram.fd')}
        result = self._activate()
        self.assertTrue(result['restored']); self.assertFalse(result['started'])
        self.assertTrue(result['old_generation_retained'])
        self.assertEqual(result['active_disk'], str(Path(prepared['path'])/'disk.qcow2'))
        root = ET.fromstring(self.backend.domain(self.record['domain_uuid'])._xml)
        self.assertEqual(root.findtext('./os/nvram'), result['active_nvram'])
        self.assertIn(result['active_disk'],
                      [item.find('source').get('file') for item in root.findall('./devices/disk')])
        for name, expected in old.items():
            self.assertEqual((self._id(runtime/name), (runtime/name).read_bytes()), expected)
        current = self.store.inspect('arch-test')
        self.assertFalse(current['requires_review'])
        self.assertEqual(current['journal'][-1]['events'],
                         ['planned','binding_generation','generation_bound','redefining',
                          'redefined','updating_registry','activated'])
        status = self.lifecycle.status('arch-test')
        self.assertEqual((status['power_state'], status['requires_review']), ('shutoff', False))
        self.assertEqual(private_guest.read_bytes(), baseline_guest)
        self.assertEqual((Path(prepared['path'])/'previous-guest-manifest.json').read_text(),
                         json.dumps(changed_guest))
        destroyed = self.lifecycle.destroy('arch-test', self.deadline)
        self.assertTrue(destroyed['removed'])
        self.assertFalse(Path(prepared['path']).exists())

    def test_activation_reverifies_preparation_and_rejects_active_domain(self):
        prepared = self._prepare()
        (Path(prepared['path'])/'nvram.fd').write_bytes(b'tampered')
        with self.assertRaises(LabError) as caught:
            self._activate()
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_HASH_MISMATCH')
        self.assertNotEqual(self.store.inspect('arch-test')['journal'][-1]['kind'],
                            'restore_activation')

        operation = '77777777-7777-4777-8777-777777777777'
        self._prepare(operation); self.domain.running = True
        with self.assertRaises(LabError) as caught:
            self._activate(operation)
        self.assertEqual(caught.exception.detail['code'], 'DOMAIN_RUNNING')

    def test_failure_while_binding_generation_blocks_start_with_old_domain(self):
        self._prepare()
        old_xml = self.domain._xml
        with patch('vm_dev_lab.restore._atomic_manifest',
                   side_effect=LabError(6, 'INJECTED', 'activation', 'injected', 'test')), \
                self.assertRaises(LabError):
            self._activate()
        self._failed_operation()
        self.assertEqual(self.backend.domain(self.record['domain_uuid'])._xml, old_xml)
        self._assert_start_blocked()

    def test_libvirt_redefine_failure_retains_old_domain_and_blocks_start(self):
        self._prepare(); old_xml = self.domain._xml
        with patch.object(self.backend, 'define', side_effect=RuntimeError('injected')), \
                self.assertRaises(RuntimeError):
            self._activate()
        operation = self._failed_operation()
        self.assertEqual(operation['last_safe'], 'generation_bound')
        self.assertEqual(self.backend.domain(self.record['domain_uuid'])._xml, old_xml)
        self._assert_start_blocked()

    def test_failure_after_redefine_leaves_new_pair_but_blocks_start(self):
        prepared = self._prepare()
        with patch.object(self.activation, '_replace_private',
                          side_effect=OSError(errno.EIO, 'injected')), \
                self.assertRaises(LabError) as caught:
            self._activate()
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        operation = self._failed_operation()
        self.assertEqual(operation['last_safe'], 'redefined')
        root = ET.fromstring(self.backend.domain(self.record['domain_uuid'])._xml)
        self.assertEqual(root.findtext('./os/nvram'), str(Path(prepared['path'])/'nvram.fd'))
        self._assert_start_blocked()

    def test_registry_update_failure_never_reports_success_and_blocks_start(self):
        self._prepare()
        with patch.object(self.activation.store, 'replace_instance_bindings',
                          side_effect=LabError(6, 'INJECTED', 'state', 'injected', 'test')), \
                self.assertRaises(LabError):
            self._activate()
        self._failed_operation()
        self._assert_start_blocked()

    def test_final_journal_failure_keeps_new_complete_state_blocked(self):
        self._prepare()
        real_advance = self.activation.store.advance
        def fail_final(instance, operation, phase, **kwargs):
            if phase == 'activated':
                raise LabError(6, 'INJECTED', 'state', 'injected', 'test')
            return real_advance(instance, operation, phase, **kwargs)
        with patch.object(self.activation.store, 'advance', side_effect=fail_final), \
                self.assertRaises(LabError):
            self._activate()
        self._failed_operation()
        self._assert_start_blocked()

    def test_successful_restore_can_be_started_only_by_separate_command(self):
        self._prepare(); result = self._activate()
        self.assertFalse(result['started']); self.assertFalse(self.domain.running)
        Path(result['active_disk']).write_bytes(b'guest-mutated overlay')
        Path(result['active_nvram']).write_bytes(b'guest-mutated nvram')
        self.lifecycle.status('arch-test')
        with patch.object(self.lifecycle, '_host', return_value=self.plan), \
                patch.object(self.lifecycle, '_run',
                             side_effect=lambda argv, deadline, **_kwargs:
                             self._tool(argv, deadline)), \
                patch.object(self.lifecycle, '_readiness', return_value='192.0.2.10'), \
                patch.object(self.lifecycle, '_project_readiness', return_value={}):
            started = self.lifecycle.start('arch-test', self.deadline)
        self.assertEqual(started['power_state'], 'running')

    def test_second_restore_keeps_both_prior_generations_and_switches_pair(self):
        first = self._prepare(); self._activate()
        baseline_acls = {key:value for key, value in self.acls.items()
                         if str(self.baseline['path']) in key}
        second_id = '77777777-7777-4777-8777-777777777777'
        second = self._prepare(second_id); result = self._activate(second_id)
        self.assertTrue(Path(first['path']).is_dir())
        self.assertTrue(Path(second['path']).is_dir())
        self.assertEqual(result['active_disk'], str(Path(second['path'])/'disk.qcow2'))
        self.assertNotEqual(first['generation_id'], second['generation_id'])
        self.assertEqual({key:value for key, value in self.acls.items()
                          if str(self.baseline['path']) in key}, baseline_acls)

    def test_foreign_or_writable_backing_xml_is_rejected_without_baseline_change(self):
        self._prepare(); self._activate()
        bundle = Path(self.baseline['path'])
        baseline_before = (bundle/'disk.qcow2').read_bytes()
        domain = self.backend.domain(self.record['domain_uuid'])
        original = domain._xml
        for variant in ('foreign', 'relabel'):
            with self.subTest(variant=variant):
                root = ET.fromstring(original)
                disk = next(entry for entry in root.findall('./devices/disk')
                            if entry.get('device') == 'disk')
                if variant == 'foreign':
                    disk.find('./backingStore/source').set('file', '/foreign/baseline.qcow2')
                else:
                    disk.find('./backingStore/source/seclabel').set('relabel', 'yes')
                domain._xml = ET.tostring(root, encoding='unicode')
                with self.assertRaises(LabError) as caught:
                    self.lifecycle.status('arch-test')
                self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')
                self.assertEqual((bundle/'disk.qcow2').read_bytes(), baseline_before)
        domain._xml = original

    def test_activation_grants_only_traversal_and_pair_write_access(self):
        prepared = self._prepare(); before = self._snapshot()['bundle']
        self._activate(); path = Path(prepared['path'])
        bundle = Path(self.baseline['path'])
        uid = self.plan['qemu']['uid']
        directory_acl = f'u::rwx,u:{uid}:--x,g::---,m::--x,o::---'
        data_acl = f'u::rw-,u:{uid}:rw-,g::---,m::rw-,o::---'
        baseline_disk_acl = f'u::rw-,u:{uid}:r--,g::---,m::r--,o::---'
        private_acl = 'u::rw-,g::---,m::---,o::---'
        for directory in (path.parent.parent, path.parent, path):
            self.assertEqual(self.acls[str(directory)], directory_acl)
        for name in ('disk.qcow2', 'nvram.fd'):
            self.assertEqual(self.acls[str(path/name)], data_acl)
        for name in ('domain.xml', 'preparation.json', 'activation.json',
                     'guest-manifest.json', 'previous-guest-manifest.json'):
            self.assertEqual(self.acls[str(path/name)], private_acl)
        for directory in (bundle.parent.parent, bundle.parent, bundle):
            self.assertEqual(self.acls[str(directory)], directory_acl)
        self.assertEqual(self.acls[str(bundle/'disk.qcow2')], baseline_disk_acl)
        for name in ('nvram.fd', 'domain.xml', 'instance.json',
                     'guest-manifest.json', 'manifest.json'):
            self.assertEqual(self.acls[str(bundle/name)], private_acl)
        self.assertEqual(self._snapshot()['bundle'], before)

    def test_start_rechecks_baseline_traversal_and_exact_backing_before_journal(self):
        prepared = self._prepare(); self._activate()
        path = Path(prepared['path']); bundle = Path(self.baseline['path'])
        worker = self.plan['qemu']['uid']
        before = len(self.store.inspect('arch-test')['journal'])
        self.acls[str(bundle)] = f'u::rwx,u:{worker}:rwx,g::---,m::---,o::---'
        with patch.object(self.lifecycle, '_host', return_value=self.plan), \
                patch.object(self.lifecycle, '_run',
                             side_effect=lambda argv, deadline, **_kwargs:
                             self._tool(argv, deadline)), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_ACCESS_INVALID')
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)
        self.acls[str(bundle)] = f'u::rwx,u:{worker}:--x,g::---,m::--x,o::---'
        self.backings[str(path/'disk.qcow2')] = '/foreign/backing.qcow2'
        with patch.object(self.lifecycle, '_host', return_value=self.plan), \
                patch.object(self.lifecycle, '_run',
                             side_effect=lambda argv, deadline, **_kwargs:
                             self._tool(argv, deadline)), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_BACKING_INVALID')
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)
        self.assertFalse(self.domain.running)

    def test_baseline_inode_exchange_during_acl_binding_blocks_activation(self):
        self._prepare(); bundle = Path(self.baseline['path'])
        disk = bundle/'disk.qcow2'; original = disk.read_bytes()
        exchanged = False
        def exchange(argv, deadline):
            nonlocal exchanged
            result = self._tool(argv, deadline)
            if (not exchanged and argv[0] == 'setfacl' and '--set' in argv
                    and Path(argv[-1]) == disk):
                disk.rename(bundle/'old-disk.qcow2')
                disk.write_bytes(original); disk.chmod(0o640)
                exchanged = True
            return result
        manager = RestoreActivationManager(
            self.lifecycle, clock=time.monotonic, tool=exchange,
            disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(LabError) as caught:
            manager.activate('arch-test', self.baseline['baseline_id'],
                             self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_PATH_UNSAFE')
        self.assertTrue(self.store.inspect('arch-test')['requires_review'])

    def test_baseline_acl_write_failure_blocks_before_generation_binding(self):
        self._prepare(); bundle = Path(self.baseline['path'])
        def fail_baseline(argv, deadline):
            if (argv[0] == 'setfacl' and '--set' in argv
                    and Path(argv[-1]) == bundle):
                return subprocess.CompletedProcess(argv, 1, b'', b'injected')
            return self._tool(argv, deadline)
        manager = RestoreActivationManager(
            self.lifecycle, clock=time.monotonic, tool=fail_baseline,
            disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(LabError) as caught:
            manager.activate('arch-test', self.baseline['baseline_id'],
                             self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_ACCESS_FAILED')
        operation = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((operation['phase'], operation['last_safe']),
                         ('failed', 'planned'))

    def test_effective_acl_mask_is_rechecked_before_start_without_start_journal(self):
        prepared = self._prepare(); self._activate(); path = Path(prepared['path'])
        uid = self.plan['qemu']['uid']
        self.acls[str(path/'disk.qcow2')] = (
            f'u::rw-,u:{uid}:rw-,g::---,m::r--,o::---')
        before = len(self.store.inspect('arch-test')['journal'])
        with patch.object(self.lifecycle, '_host', return_value=self.plan), \
                patch.object(self.lifecycle, '_run',
                             side_effect=lambda argv, deadline, **_kwargs:
                             self._tool(argv, deadline)), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_ACCESS_INVALID')
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)
        self.assertFalse(self.domain.running)

    def test_different_qualified_worker_uid_is_bound_without_fixed_uid_assumption(self):
        prepared = self._prepare(); worker = {'name': 'qemu-test', 'uid': 23456, 'gid': 23457}
        self.plan['qemu'] = worker
        account = SimpleNamespace(pw_name=worker['name'], pw_uid=worker['uid'],
                                  pw_gid=worker['gid'])
        owner = self.accounts[self.plan['owner']['name']]
        self.activation.access.lookup = lambda name: (
            account if name == worker['name'] else owner)
        self.activation.access.lookup_uid = lambda uid: (
            account if uid == worker['uid'] else owner)
        self.activation.access.lookup_gid = lambda gid: SimpleNamespace(gr_gid=gid)
        self._activate()
        self.assertIn(f'u:{worker["uid"]}:rw-',
                      self.acls[str(Path(prepared['path'])/'disk.qcow2')])

    def test_conflicting_worker_identity_blocks_before_generation_binding(self):
        self._prepare(); self.plan['qemu']['uid'] += 1
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.activation.activate('arch-test', self.baseline['baseline_id'],
                                     self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_WORKER_INVALID')
        failed = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((failed['phase'], failed['last_safe']),
                         ('failed', 'planned'))

    def test_missing_worker_binding_blocks_before_generation_binding(self):
        self._prepare(); del self.plan['qemu']
        with self._firmware(), self.assertRaises(LabError) as caught:
            self.activation.activate('arch-test', self.baseline['baseline_id'],
                                     self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_WORKER_INVALID')
        failed = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((failed['phase'], failed['last_safe']),
                         ('failed', 'planned'))

    def test_acl_write_failure_blocks_before_generation_binding(self):
        self._prepare(); real_tool = self._tool
        manager = RestoreActivationManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool,
            disk_usage=self.disk_usage)
        manager.access.tool = lambda argv, deadline: (
            subprocess.CompletedProcess(argv, 1, b'', b'injected')
            if argv[0] == 'setfacl' else real_tool(argv, deadline))
        with self._firmware(), self.assertRaises(LabError) as caught:
            manager.activate('arch-test', self.baseline['baseline_id'],
                             self.operation, self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_ACCESS_FAILED')
        failed = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((failed['phase'], failed['last_safe']),
                         ('failed', 'planned'))

    def test_unknown_file_added_at_activation_boundary_is_rejected_without_deletion(self):
        prepared = self._prepare()
        path = Path(prepared['path'])
        real_manifest = __import__('vm_dev_lab.restore', fromlist=['_atomic_manifest'])._atomic_manifest
        def add_foreign(target, value, **kwargs):
            result = real_manifest(target, value, **kwargs)
            if target.name == 'activation.json':
                (target.parent/'foreign').write_bytes(b'keep')
            return result
        with patch('vm_dev_lab.restore._atomic_manifest', side_effect=add_foreign), \
                self.assertRaises(LabError) as caught:
            self._activate()
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_PREPARATION_INCOMPLETE')
        self.assertTrue((path/'foreign').exists())
        self._assert_start_blocked()


class RestoreRecoveryTests(unittest.TestCase):
    """P08-B3 recovery after a simulated process restart."""

    _write = lifecycle_fixtures.LifecycleTests._write
    _id = staticmethod(lifecycle_fixtures.LifecycleTests._id)
    _resources = lifecycle_fixtures.LifecycleTests._resources
    _firmware = RestorePreparationTests._firmware
    _tool = RestorePreparationTests._tool
    _prepare = RestorePreparationTests._prepare
    _snapshot = RestorePreparationTests._snapshot
    _activate = RestoreActivationTests._activate
    _assert_start_blocked = RestoreActivationTests._assert_start_blocked

    def setUp(self):
        RestoreActivationTests.setUp(self)
        self.recovery = RestoreRecoveryManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool)

    def _recover_restore(self, source):
        with self._firmware():
            return self.recovery.recover('arch-test', source, self.deadline)

    def _source_id(self):
        for operation in reversed(self.store.inspect('arch-test')['journal']):
            if operation['kind'] == 'restore_activation':
                return operation['id']
        self.fail('restore source missing')

    def test_old_complete_state_is_resolved_without_replaying_activation(self):
        self._prepare(); old_xml = self.domain._xml
        with patch('vm_dev_lab.restore._atomic_manifest',
                   side_effect=LabError(6, 'INJECTED', 'activation', 'injected', 'test')), \
                self.assertRaises(LabError):
            self._activate()
        source = self._source_id()
        with patch.object(self.backend, 'define',
                          side_effect=AssertionError('must not redefine')):
            result = self._recover_restore(source)
        self.assertEqual(result['classification'], 'old-complete')
        self.assertFalse(result['requires_review'])
        self.assertEqual(self.backend.domain(self.record['domain_uuid'])._xml, old_xml)
        journal = len(self.store.inspect('arch-test')['journal'])
        repeated = self._recover_restore(source)
        self.assertTrue(repeated['idempotent'])
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), journal)

    def test_new_complete_state_is_confirmed_without_repeating_file_or_libvirt_mutation(self):
        self._prepare()
        real_advance = self.activation.store.advance
        def fail_final(instance, operation, phase, **kwargs):
            if phase == 'activated':
                raise LabError(6, 'INJECTED', 'state', 'injected', 'test')
            return real_advance(instance, operation, phase, **kwargs)
        with patch.object(self.activation.store, 'advance', side_effect=fail_final), \
                self.assertRaises(LabError):
            self._activate()
        source = self._source_id()
        with patch.object(self.backend, 'define',
                          side_effect=AssertionError('must not redefine')), \
                patch.object(self.recovery.activation, '_replace_private',
                             side_effect=AssertionError('must not replace')):
            result = self._recover_restore(source)
        self.assertEqual(result['classification'], 'new-complete')
        self.assertFalse(result['requires_review'])

    def test_recovery_resumes_only_missing_manifest_and_registry_switch(self):
        self._prepare()
        with patch.object(self.activation, '_replace_private',
                          side_effect=OSError(errno.EIO, 'injected')), \
                self.assertRaises(LabError):
            self._activate()
        source = self._source_id()
        with patch.object(self.backend, 'define',
                          side_effect=AssertionError('must not redefine')):
            result = self._recover_restore(source)
        self.assertEqual(result['classification'], 'resume-new')
        self.assertFalse(result['requires_review'])
        self.lifecycle.status('arch-test')

    def test_recovery_resumes_after_private_files_changed_but_registry_not_switched(self):
        self._prepare()
        with patch.object(self.activation.store, 'replace_instance_bindings',
                          side_effect=LabError(6, 'INJECTED', 'state', 'injected', 'test')), \
                self.assertRaises(LabError):
            self._activate()
        result = self._recover_restore(self._source_id())
        self.assertEqual(result['classification'], 'resume-new')
        self.lifecycle.status('arch-test')

    def test_interrupted_recovery_is_repeatable_after_process_restart(self):
        self._prepare()
        with patch.object(self.activation, '_replace_private',
                          side_effect=OSError(errno.EIO, 'activation')), \
                self.assertRaises(LabError):
            self._activate()
        source = self._source_id()
        with patch.object(self.recovery.activation, '_replace_private',
                          side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self._recover_restore(source)
        self._assert_start_blocked()
        restarted = RestoreRecoveryManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool)
        with self._firmware():
            result = restarted.recover('arch-test', source, self.deadline)
        self.assertEqual(result['classification'], 'resume-new')
        self.assertFalse(result['requires_review'])

    def test_enospc_during_recovery_keeps_start_block_and_can_be_retried(self):
        self._unclear_after_redefine()
        source = self._source_id()
        with patch.object(self.recovery.activation, '_replace_private',
                          side_effect=LabError(6, 'RESTORE_NO_SPACE', 'activation',
                                               'injected', 'test')), \
                self.assertRaises(LabError) as caught:
            self._recover_restore(source)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_NO_SPACE')
        self._assert_start_blocked()
        result = self._recover_restore(source)
        self.assertIn(result['classification'], {'resume-new','new-complete'})
        self.assertFalse(result['requires_review'])

    def test_failure_before_recovery_journal_completion_is_reclassified_as_new(self):
        self._unclear_after_redefine()
        source = self._source_id()
        with patch.object(self.recovery.store, 'resolve_restore_recovery',
                          side_effect=LabError(6, 'INJECTED', 'state', 'injected', 'test')), \
                self.assertRaises(LabError):
            self._recover_restore(source)
        self._assert_start_blocked()
        result = self._recover_restore(source)
        self.assertEqual(result['classification'], 'new-complete')
        self.assertFalse(result['requires_review'])

    def _unclear_after_redefine(self):
        prepared = self._prepare()
        with patch.object(self.activation, '_replace_private',
                          side_effect=OSError(errno.EIO, 'activation')), \
                self.assertRaises(LabError):
            self._activate()
        return prepared

    def test_tampered_generation_remains_unclear(self):
        prepared = self._unclear_after_redefine()
        (Path(prepared['path'])/'nvram.fd').write_bytes(b'tampered')
        with self.assertRaises(LabError) as caught:
            self._recover_restore(self._source_id())
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_RECOVERY_UNCLEAR')
        self._assert_start_blocked()

    def test_active_domain_remains_unclear(self):
        self._unclear_after_redefine()
        self.backend.domain(self.record['domain_uuid']).running = True
        with self.assertRaises(LabError) as caught:
            self._recover_restore(self._source_id())
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_RECOVERY_UNCLEAR')

    def test_mixed_old_domain_and_new_private_xml_remains_unclear(self):
        prepared = self._unclear_after_redefine()
        self.backend.domain(self.record['domain_uuid'])._xml = self.domain._xml
        private = self.paths.data/'instances'/self.record['instance_id']
        (private/'domain.xml').write_bytes((Path(prepared['path'])/'domain.xml').read_bytes())
        with self.assertRaises(LabError) as caught:
            self._recover_restore(self._source_id())
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_RECOVERY_UNCLEAR')
        self._assert_start_blocked()

    def test_changed_domain_uuid_remains_unclear_without_new_journal(self):
        self._unclear_after_redefine()
        source = self._source_id()
        before = len(self.store.inspect('arch-test')['journal'])
        domain = self.backend.domain(self.record['domain_uuid'])
        root = ET.fromstring(domain._xml)
        root.find('uuid').text = '99999999-9999-4999-8999-999999999999'
        domain._xml = ET.tostring(root, encoding='unicode')
        with self.assertRaises(LabError) as caught:
            self._recover_restore(source)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_RECOVERY_UNCLEAR')
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)

    def test_changed_registry_inode_remains_unclear(self):
        self._unclear_after_redefine()
        source = self._source_id()
        with self.store.lock('global'):
            state = self.store._read()
            record = state['instances'][self.record['instance_id']]
            item = next(entry for entry in record['manifest'] if entry['path'] == 'domain.xml')
            item['inode'] += 1
            self.store._write(state)
        with self.assertRaises(LabError) as caught:
            self._recover_restore(source)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_RECOVERY_UNCLEAR')

    def test_instance_lock_blocks_concurrent_restore_recovery(self):
        self._prepare()
        with patch('vm_dev_lab.restore._atomic_manifest',
                   side_effect=LabError(6, 'INJECTED', 'activation', 'injected', 'test')), \
                self.assertRaises(LabError):
            self._activate()
        with self.store.lock(self.record['instance_id']), self.assertRaises(LabError) as caught:
            self._recover_restore(self._source_id())
        self.assertEqual(caught.exception.detail['code'], 'LOCK_CONFLICT')

    def test_destroy_removes_all_bound_generations_after_repeated_restore(self):
        first = self._prepare(); self._activate()
        (Path(first['path'])/'disk.qcow2').write_bytes(b'mutated former disk')
        (Path(first['path'])/'nvram.fd').write_bytes(b'mutated former nvram')
        second_id = '77777777-7777-4777-8777-777777777777'
        second = self._prepare(second_id); self._activate(second_id)
        bundle = Path(self.baseline['path'])
        baseline_before = {item.name:item.read_bytes() for item in bundle.iterdir()}
        baseline_acls = {key:value for key, value in self.acls.items()
                         if str(bundle) in key}
        result = self.lifecycle.destroy('arch-test', self.deadline)
        self.assertTrue(result['removed'])
        self.assertFalse(Path(first['path']).exists())
        self.assertFalse(Path(second['path']).exists())
        self.assertEqual({item.name:item.read_bytes() for item in bundle.iterdir()},
                         baseline_before)
        self.assertEqual({key:value for key, value in self.acls.items()
                          if str(bundle) in key}, baseline_acls)

    def test_destroy_preserves_unknown_and_unbound_staging(self):
        active = self._prepare(); self._activate()
        foreign = Path(active['path'])/'foreign'
        foreign.write_bytes(b'keep')
        with patch.object(self.backend, 'undefine',
                          side_effect=AssertionError('must not undefine')), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.destroy('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')
        self.assertTrue(foreign.exists())

    def test_destroy_blocks_unactivated_b1_generation_without_deleting_it(self):
        self._prepare(); self._activate()
        pending_id = '77777777-7777-4777-8777-777777777777'
        pending = self._prepare(pending_id)
        with patch.object(self.backend, 'undefine',
                          side_effect=AssertionError('must not undefine')), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.destroy('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'],
                         'RESTORE_GENERATION_CLEANUP_UNSUPPORTED')
        self.assertTrue(Path(pending['path']).exists())

    def test_destroy_preserves_generation_with_tampered_activation_manifest(self):
        active = self._prepare(); self._activate()
        manifest = Path(active['path'])/'activation.json'
        value = json.loads(manifest.read_bytes())
        value['generation_id'] = '77777777-7777-4777-8777-777777777777'
        manifest.write_bytes(json.dumps(
            value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        with patch.object(self.backend, 'undefine',
                          side_effect=AssertionError('must not undefine')), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.destroy('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')
        self.assertTrue(Path(active['path']).exists())

    def test_interrupted_generation_cleanup_never_reports_destroy_success(self):
        active = self._prepare(); self._activate()
        real_unlink = os.unlink; calls = 0
        def interrupt(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, 'injected')
            return real_unlink(path, *args, **kwargs)
        with patch('vm_dev_lab.restore.os.unlink', side_effect=interrupt), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.destroy('arch-test', self.deadline)
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        state = self.store.inspect(self.record['instance_id'])
        self.assertTrue(state['requires_review'])
        self.assertEqual(state['journal'][-1]['kind'], 'destroy')
        self.assertEqual(state['journal'][-1]['status'], 'review_required')
        self.assertTrue(Path(active['path']).exists())


class LegacyRestoreDestroyRejectionTests(unittest.TestCase):
    """Unknown implicit backing contracts remain fail-closed."""

    _write = lifecycle_fixtures.LifecycleTests._write
    _id = staticmethod(lifecycle_fixtures.LifecycleTests._id)
    _resources = lifecycle_fixtures.LifecycleTests._resources
    _firmware = RestorePreparationTests._firmware
    _tool = RestorePreparationTests._tool
    _prepare = RestorePreparationTests._prepare
    _activate = RestoreActivationTests._activate

    def setUp(self):
        RestoreActivationTests.setUp(self)
        self.prepared = self._prepare()
        self._activate()
        domain = self.backend.domain(self.record["domain_uuid"])
        root = ET.fromstring(domain._xml)
        disk = next(item for item in root.findall("./devices/disk")
                    if item.get("device") == "disk")
        disk.remove(disk.find("backingStore"))
        domain._xml = ET.tostring(root, encoding="unicode")
        private = self.paths.data/"instances"/self.record["instance_id"]/"domain.xml"
        private.write_text(domain._xml)

    def test_implicit_legacy_backing_contract_is_not_destroyable(self):
        bundle = Path(self.baseline["path"])
        bundle_before = {path.name: path.read_bytes() for path in bundle.iterdir()}
        with patch.object(self.backend, "undefine",
                          side_effect=AssertionError("must not undefine")), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.destroy("arch-test", self.deadline)
        self.assertEqual(caught.exception.detail["code"], "OWNERSHIP_MISMATCH")
        self.assertTrue(Path(self.prepared["path"]).exists())
        self.assertEqual(
            {path.name: path.read_bytes() for path in bundle.iterdir()},
            bundle_before)

    def test_historical_migration_journal_is_readable_but_not_advanceable(self):
        record = self.store.inspect('arch-test')
        generation = json.loads((
            self.paths.data/'instances'/record['instance_id']/'instance.json'
        ).read_text())['restore_generation']
        activation = next(
            item for item in record['journal']
            if item['id'] == generation['activation_operation_id'])
        disk = Path(generation['baseline_disk']['path'])
        info = disk.lstat()
        operation = self.store._operation('legacy_dac_migration')
        operation['recovery'] = {
            'source_operation': activation['id'],
            'baseline_id': generation['baseline_id'],
            'generation_id': generation['generation_id'],
            'lifecycle_state': activation['restore']['old_state'],
            'baseline_disk': {
                **generation['baseline_disk'], 'uid': info.st_uid,
                'gid': info.st_gid},
            'old_domain_sha256': '1' * 64,
            'new_domain_sha256': '2' * 64,
            'request_sha256': '3' * 64,
        }
        with self.store.lock('global'):
            state = self.store._read()
            state['instances'][record['instance_id']]['journal'].append(operation)
            self.store._write(state)

        historical = self.store.inspect('arch-test')
        self.assertEqual(historical['journal'][-1]['kind'],
                         'legacy_dac_migration')
        self.assertTrue(historical['requires_review'])
        with self.assertRaises(LabError) as caught:
            self.store.advance(record['instance_id'], operation['id'],
                               'awaiting_helper')
        self.assertEqual(caught.exception.detail['code'], 'STATE_CONFLICT')
        self.assertFalse(hasattr(self.store, 'begin_legacy_dac_migration'))
        self.assertFalse(hasattr(self.store, 'resolve_legacy_dac_migration'))
        self.assertFalse(hasattr(self.lifecycle, 'migrate_legacy_dac'))


class RestoreStartRecoveryTests(unittest.TestCase):
    """Recovery of a powered-off restore start that failed because of ACLs."""

    _write = lifecycle_fixtures.LifecycleTests._write
    _id = staticmethod(lifecycle_fixtures.LifecycleTests._id)
    _resources = lifecycle_fixtures.LifecycleTests._resources
    _firmware = RestorePreparationTests._firmware
    _tool = RestorePreparationTests._tool
    _prepare = RestorePreparationTests._prepare
    _activate = RestoreActivationTests._activate

    def setUp(self):
        RestoreActivationTests.setUp(self)
        self.start_recovery = RestoreStartRecoveryManager(
            self.lifecycle, clock=time.monotonic, tool=self._tool)

    def _legacy_access(self, path):
        path = Path(path)
        owner = self.plan['owner']['uid']; worker = self.plan['qemu']['uid']
        def inherited(owner_permissions, mask, *, defaults=False):
            access = [
                f'user::{owner_permissions}', f'user:{owner}:rwx',
                f'user:{worker}:rwx', 'group::---', f'mask::{mask}', 'other::---',
            ]
            default = [
                'default:user::rwx', f'default:user:{owner}:rwx',
                f'default:user:{worker}:rwx', 'default:group::---',
                'default:mask::rwx', 'default:other::---',
            ] if defaults else []
            return '\n'.join(access + default)
        for directory in (path.parent.parent, path.parent, path):
            directory.chmod(0o700)
            self.acls[str(directory)] = inherited('rwx', '---', defaults=True)
        for name in ('disk.qcow2', 'nvram.fd'):
            target = path/name
            target.chmod(0o640 if name == 'disk.qcow2' else 0o600)
            mask = 'r--' if name == 'disk.qcow2' else '---'
            self.acls[str(target)] = inherited('rw-', mask)
        for name in ('domain.xml', 'preparation.json', 'activation.json',
                     'guest-manifest.json', 'previous-guest-manifest.json'):
            target = path/name; target.chmod(0o600)
            self.acls[str(target)] = inherited('rw-', '---')

    def _legacy_baseline_access(self):
        bundle = Path(self.baseline['path'])
        owner = self.plan['owner']['uid']; worker = self.plan['qemu']['uid']
        directory_acl = '\n'.join((
            'user::rwx', f'user:{owner}:rwx', f'user:{worker}:rwx',
            'group::---', 'mask::---', 'other::---',
            'default:user::rwx', f'default:user:{owner}:rwx',
            f'default:user:{worker}:rwx', 'default:group::---',
            'default:mask::rwx', 'default:other::---'))
        for directory in (bundle.parent.parent, bundle.parent, bundle):
            directory.chmod(0o700)
            self.acls[str(directory)] = directory_acl
        for name in ('disk.qcow2','nvram.fd','domain.xml','instance.json',
                     'guest-manifest.json','manifest.json'):
            target = bundle/name
            target.chmod(0o640 if name == 'disk.qcow2' else 0o600)
            mask = 'r--' if name == 'disk.qcow2' else '---'
            self.acls[str(target)] = '\n'.join((
                'user::rw-', f'user:{owner}:rwx', f'user:{worker}:rwx',
                'group::---', f'mask::{mask}', 'other::---'))

    def _failed_restore_start(self):
        prepared = self._prepare(); activated = self._activate()
        private = self.paths.data/'instances'/self.record['instance_id']/'instance.json'
        instance = json.loads(private.read_text())
        instance['restore_generation'].pop('baseline_disk')
        private.write_text(json.dumps(instance, sort_keys=True, separators=(',', ':')))
        with self.store.lock('global'):
            state = self.store._read()
            activation = next(item for item in
                              state['instances'][self.record['instance_id']]['journal']
                              if item['id'] == activated['activation_operation_id'])
            activation['restore']['new_generation'].pop('baseline_disk')
            self.store._write(state)
        self._legacy_access(prepared['path'])
        self._legacy_baseline_access()
        current = self.store.inspect('arch-test')
        source = self.store.begin(current, 'start')
        self.store.advance(current['instance_id'], source, 'booting')
        self.store.advance(current['instance_id'], source, 'failed', failed=True)
        return prepared, activated, source

    def test_real_legacy_baseline_acls_normalize_read_only_without_content_change(self):
        _prepared, _activated, source = self._failed_restore_start()
        bundle = Path(self.baseline['path']); worker = self.plan['qemu']['uid']
        before = {item.name:item.read_bytes() for item in bundle.iterdir()}
        result = self._recover(source)
        self.assertTrue(result['resolved'])
        for directory in (bundle.parent.parent, bundle.parent, bundle):
            self.assertEqual(self.acls[str(directory)],
                             f'u::rwx,u:{worker}:--x,g::---,m::--x,o::---')
        self.assertEqual(self.acls[str(bundle/'disk.qcow2')],
                         f'u::rw-,u:{worker}:r--,g::---,m::r--,o::---')
        for name in ('nvram.fd','domain.xml','instance.json',
                     'guest-manifest.json','manifest.json'):
            self.assertEqual(self.acls[str(bundle/name)],
                             'u::rw-,g::---,m::---,o::---')
        self.assertEqual({item.name:item.read_bytes() for item in bundle.iterdir()}, before)

    def test_recovery_persists_legacy_baseline_inode_and_start_rejects_exchange(self):
        _prepared, activated, source = self._failed_restore_start()
        result = self._recover(source)
        record = self.store.inspect('arch-test')
        recovery = record['journal'][-1]['recovery']
        self.assertEqual(recovery['restore_activation'],
                         activated['activation_operation_id'])
        disk = Path(self.baseline['path'])/'disk.qcow2'
        self.assertEqual(recovery['baseline_disk']['inode'], disk.stat().st_ino)
        content = disk.read_bytes(); disk.rename(disk.parent.parent/'old-disk.qcow2')
        disk.write_bytes(content); disk.chmod(0o640)
        before = len(record['journal'])
        with patch.object(self.lifecycle, '_host', return_value=self.plan), \
                patch.object(self.lifecycle, '_run',
                             side_effect=lambda argv, deadline, **_kwargs:
                             self._tool(argv, deadline)), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test', self.deadline)
        self.assertIn(caught.exception.detail['code'],
                      {'OWNERSHIP_MISMATCH','RESTORE_PATH_UNSAFE'})
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)
        self.assertFalse(result['started'])

    def test_foreign_baseline_acl_principal_is_rejected_before_intent(self):
        _prepared, _activated, source = self._failed_restore_start()
        disk = Path(self.baseline['path'])/'disk.qcow2'
        self.acls[str(disk)] += '\nuser:54321:r--'
        before = deepcopy(self.store.inspect('arch-test')['journal'])
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'],
                         'RESTORE_ACCESS_NOT_REPAIRABLE')
        self.assertEqual(self.store.inspect('arch-test')['journal'], before)

    def _recover(self, source, manager=None):
        with self._firmware():
            return (manager or self.start_recovery).recover(
                'arch-test', source, self.deadline)

    def _assert_acl_rejected(self, source, code='RESTORE_ACCESS_NOT_REPAIRABLE'):
        before = deepcopy(self.store.inspect('arch-test')['journal'])
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], code)
        current = self.store.inspect('arch-test')
        self.assertEqual(current['journal'], before)
        self.assertTrue(current['requires_review'])

    def test_exact_hostsetup_legacy_acls_normalize_to_minimal_contract(self):
        prepared, _activated, source = self._failed_restore_start()
        path = Path(prepared['path']); worker = self.plan['qemu']['uid']
        directories = (path.parent.parent, path.parent, path)
        self.assertTrue(all('default:user:' in self.acls[str(item)]
                            for item in directories))
        result = self._recover(source)
        self.assertTrue(result['resolved'])
        for item in directories:
            self.assertEqual(
                self.acls[str(item)],
                f'u::rwx,u:{worker}:--x,g::---,m::--x,o::---')
        for name in ('disk.qcow2', 'nvram.fd'):
            self.assertEqual(
                self.acls[str(path/name)],
                f'u::rw-,u:{worker}:rw-,g::---,m::rw-,o::---')
        for name in ('domain.xml', 'preparation.json', 'activation.json',
                     'guest-manifest.json', 'previous-guest-manifest.json'):
            self.assertEqual(self.acls[str(path/name)],
                             'u::rw-,g::---,m::---,o::---')

    def test_previous_restrictive_legacy_form_remains_repairable(self):
        prepared, _activated, source = self._failed_restore_start()
        path = Path(prepared['path']); worker = self.plan['qemu']['uid']
        for directory in (path.parent.parent, path.parent, path):
            self.acls[str(directory)] = (
                f'user::rwx\nuser:{worker}:rwx\ngroup::---\nmask::---\nother::---')
        for name in ACTIVE_FILES:
            mask = 'r--' if name == 'disk.qcow2' else '---'
            self.acls[str(path/name)] = (
                f'user::rw-\nuser:{worker}:rwx\ngroup::---\nmask::{mask}\nother::---')
        self.assertTrue(self._recover(source)['resolved'])

    def test_success_preserves_failed_start_and_only_enables_new_regular_start(self):
        prepared, _activated, source = self._failed_restore_start()
        bundle = Path(self.baseline['path'])
        baseline_before = {item.name:item.read_bytes() for item in bundle.iterdir()}
        failed = deepcopy(self.store.inspect('arch-test')['journal'][-1])
        result = self._recover(source)
        self.assertTrue(result['resolved']); self.assertFalse(result['started'])
        self.assertFalse(result['requires_review']); self.assertFalse(self.domain.running)
        record = self.store.inspect('arch-test')
        self.assertEqual(record['journal'][-2], failed)
        self.assertEqual(record['journal'][-1]['events'],
                         ['planned','repairing_access','access_ready','resolved'])
        with patch.object(self.lifecycle, '_host', return_value=self.plan), \
                patch.object(self.lifecycle, '_run',
                             side_effect=lambda argv, deadline, **_kwargs:
                             self._tool(argv, deadline)), \
                patch.object(self.lifecycle, '_readiness', return_value='192.0.2.10'), \
                patch.object(self.lifecycle, '_project_readiness', return_value={}):
            started = self.lifecycle.start('arch-test', self.deadline)
        self.assertEqual(started['power_state'], 'running')
        self.assertEqual(self.store.inspect('arch-test')['journal'][-1]['kind'], 'start')
        self.assertTrue((Path(prepared['path'])/'disk.qcow2').is_file())
        self.assertEqual({item.name:item.read_bytes() for item in bundle.iterdir()},
                         baseline_before)
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], 'RECOVERY_SOURCE_MISMATCH')

    def test_completed_recovery_is_idempotent_without_reapplying_acl(self):
        _prepared, _activated, source = self._failed_restore_start()
        first = self._recover(source)
        before = dict(self.acls); journal = deepcopy(self.store.inspect('arch-test')['journal'])
        second = self._recover(source)
        self.assertTrue(second['idempotent'])
        self.assertEqual(second['recovery_operation_id'], first['recovery_operation_id'])
        self.assertEqual(self.acls, before)
        self.assertEqual(self.store.inspect('arch-test')['journal'], journal)

    def test_wrong_source_active_domain_and_managed_save_are_rejected_without_journal(self):
        _prepared, _activated, source = self._failed_restore_start()
        before = deepcopy(self.store.inspect('arch-test')['journal'])
        with self.assertRaises(LabError) as caught:
            self._recover('99999999-9999-4999-8999-999999999999')
        self.assertEqual(caught.exception.detail['code'], 'RECOVERY_SOURCE_MISMATCH')
        domain = self.backend.domain(self.record['domain_uuid'])
        domain.running = True
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], 'RECOVERY_STATE_CONFLICT')
        domain.running = False
        domain.hasManagedSaveImage = lambda _flags: 1
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], 'RECOVERY_STATE_CONFLICT')
        self.assertEqual(self.store.inspect('arch-test')['journal'], before)

    def test_tampered_generation_is_rejected_before_intent(self):
        prepared, _activated, source = self._failed_restore_start()
        before = len(self.store.inspect('arch-test')['journal'])
        (Path(prepared['path'])/'foreign').write_bytes(b'foreign')
        with self.assertRaises(LabError):
            self._recover(source)
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)

    def test_changed_domain_is_rejected_before_intent(self):
        _prepared, _activated, source = self._failed_restore_start()
        before = len(self.store.inspect('arch-test')['journal'])
        domain = self.backend.domain(self.record['domain_uuid'])
        root = ET.fromstring(domain._xml); root.find('name').text = 'foreign'
        domain._xml = ET.tostring(root, encoding='unicode')
        with self.assertRaises(LabError):
            self._recover(source)
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)

    def test_changed_worker_is_rejected_before_intent(self):
        _prepared, _activated, source = self._failed_restore_start()
        before = len(self.store.inspect('arch-test')['journal'])
        self.plan['qemu']['uid'] += 1
        with self.assertRaises(LabError):
            self._recover(source)
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)

    def test_changed_registry_inode_is_rejected_before_intent(self):
        _prepared, _activated, source = self._failed_restore_start()
        before = len(self.store.inspect('arch-test')['journal'])
        with self.store.lock('global'):
            state = self.store._read()
            record = state['instances'][self.record['instance_id']]
            item = next(entry for entry in record['manifest']
                        if entry['path'] == 'domain.xml')
            item['inode'] += 1
            self.store._write(state)
        with self.assertRaises(LabError):
            self._recover(source)
        self.assertEqual(len(self.store.inspect('arch-test')['journal']), before)

    def test_interrupt_before_recovery_intent_preserves_original_start_block(self):
        _prepared, _activated, source = self._failed_restore_start()
        before = deepcopy(self.store.inspect('arch-test')['journal'])
        with patch.object(self.start_recovery.store, 'begin_restore_start_recovery',
                          side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self._recover(source)
        current = self.store.inspect('arch-test')
        self.assertEqual(current['journal'], before)
        self.assertTrue(current['requires_review'])

    def test_replaced_pair_inode_is_rejected(self):
        prepared, _activated, source = self._failed_restore_start()
        path = Path(prepared['path']); disk = path/'disk.qcow2'
        disk.rename(path/'replaced.qcow2'); disk.write_bytes(b'replacement')
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')

    def test_replaced_nvram_inode_is_rejected(self):
        prepared, _activated, source = self._failed_restore_start()
        path = Path(prepared['path']); nvram = path/'nvram.fd'
        nvram.rename(path/'replaced-nvram.fd'); nvram.write_bytes(b'replacement')
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], 'OWNERSHIP_MISMATCH')

    def test_unknown_acl_principal_is_rejected(self):
        prepared, _activated, source = self._failed_restore_start()
        disk = Path(prepared['path'])/'disk.qcow2'
        self.acls[str(disk)] += '\nuser:54321:r--'
        self._assert_acl_rejected(source)

    def test_undefined_numeric_acl_qualifier_is_never_worker(self):
        prepared, _activated, source = self._failed_restore_start()
        disk = Path(prepared['path'])/'disk.qcow2'
        worker = str(self.plan['qemu']['uid'])
        self.acls[str(disk)] = self.acls[str(disk)].replace(worker, '4294967295')
        self._assert_acl_rejected(source)

    def test_different_legacy_owner_or_worker_principal_is_rejected(self):
        prepared, _activated, source = self._failed_restore_start()
        disk = Path(prepared['path'])/'disk.qcow2'
        owner = str(self.plan['owner']['uid'])
        worker = str(self.plan['qemu']['uid'])
        self.acls[str(disk)] = self.acls[str(disk)].replace(
            f'user:{owner}:rwx', 'user:54320:rwx')
        self._assert_acl_rejected(source)
        self._legacy_access(prepared['path'])
        self.acls[str(disk)] = self.acls[str(disk)].replace(
            f'user:{worker}:rwx', 'user:54321:rwx')
        self._assert_acl_rejected(source)

    def test_owner_and_worker_must_resolve_by_name_and_uid(self):
        _prepared, _activated, source = self._failed_restore_start()
        owner_uid = self.plan['owner']['uid']; worker_uid = self.plan['qemu']['uid']
        owner_account = self.accounts_by_uid[owner_uid]
        del self.accounts_by_uid[worker_uid]
        self._assert_acl_rejected(source, 'RESTORE_WORKER_INVALID')
        self.accounts_by_uid[worker_uid] = owner_account
        self._assert_acl_rejected(source, 'RESTORE_WORKER_INVALID')
        self.accounts_by_uid[worker_uid] = self.accounts['qemu-worker']
        worker_gid = self.plan['qemu']['gid']
        del self.groups_by_gid[worker_gid]
        self._assert_acl_rejected(source, 'RESTORE_WORKER_INVALID')
        self.groups_by_gid[worker_gid] = SimpleNamespace(gr_gid=worker_gid + 1)
        self._assert_acl_rejected(source, 'RESTORE_WORKER_INVALID')
        self.groups_by_gid[worker_gid] = SimpleNamespace(gr_gid=worker_gid)
        self.plan['owner']['uid'] += 1
        self._assert_acl_rejected(source, 'RESTORE_OWNER_INVALID')

    def test_extra_group_and_changed_legacy_mask_are_rejected(self):
        prepared, _activated, source = self._failed_restore_start()
        path = Path(prepared['path']); disk = path/'disk.qcow2'
        self.acls[str(disk)] += '\ngroup:54321:r--'
        self._assert_acl_rejected(source)
        self.acls[str(disk)] = self.acls[str(disk)].replace('\ngroup:54321:r--', '')
        root = path.parent.parent
        self.acls[str(root)] = self.acls[str(root)].replace(
            'mask::---', 'mask::--x', 1)
        self._assert_acl_rejected(source)

    def test_file_defaults_and_partial_directory_defaults_are_rejected(self):
        prepared, _activated, source = self._failed_restore_start()
        path = Path(prepared['path']); disk = path/'disk.qcow2'
        self.acls[str(disk)] += '\ndefault:user::rwx'
        self._assert_acl_rejected(source)
        self.acls[str(disk)] = self.acls[str(disk)].replace(
            '\ndefault:user::rwx', '')
        root = path.parent.parent
        worker_default = f'\ndefault:user:{self.plan["qemu"]["uid"]}:rwx'
        self.acls[str(root)] = self.acls[str(root)].replace(worker_default, '')
        self._assert_acl_rejected(source)

    def test_inactive_domain_with_live_runtime_id_is_rejected(self):
        _prepared, _activated, source = self._failed_restore_start()
        domain = self.backend.domain(self.record['domain_uuid'])
        domain.ID = lambda: 42
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'], 'RECOVERY_STATE_CONFLICT')

    def test_acl_failure_keeps_block_and_retry_can_resolve(self):
        _prepared, _activated, source = self._failed_restore_start()
        real_tool = self._tool
        calls = {'set': 0}
        def fail_partially(argv, deadline):
            if argv[0] == 'setfacl' and '--set' in argv:
                calls['set'] += 1
                if calls['set'] == 2:
                    return subprocess.CompletedProcess(argv, 1, b'', b'injected')
            return real_tool(argv, deadline)
        failing = RestoreStartRecoveryManager(
            self.lifecycle, clock=time.monotonic, tool=fail_partially)
        with self.assertRaises(LabError) as caught:
            self._recover(source, failing)
        self.assertEqual(caught.exception.detail['code'], 'RESTORE_ACCESS_FAILED')
        blocked = self.store.inspect('arch-test')
        self.assertTrue(blocked['requires_review'])
        self.assertEqual(blocked['journal'][-1]['kind'], 'restore_start_recovery')
        result = self._recover(source)
        self.assertTrue(result['resolved']); self.assertFalse(result['requires_review'])

    def test_interrupt_after_intent_keeps_block_and_retry_can_resolve(self):
        _prepared, _activated, source = self._failed_restore_start()
        with patch.object(self.start_recovery.access, 'apply',
                          side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self._recover(source)
        blocked = self.store.inspect('arch-test')
        self.assertTrue(blocked['requires_review'])
        self.assertEqual(blocked['journal'][-1]['kind'], 'restore_start_recovery')
        self.assertEqual(blocked['journal'][-1]['status'], 'review_required')
        result = self._recover(source)
        self.assertTrue(result['resolved']); self.assertFalse(result['requires_review'])

    def test_crash_after_acl_application_resumes_without_reapplying(self):
        _prepared, _activated, source = self._failed_restore_start()
        with patch.object(self.start_recovery.store, 'resolve_restore_start_recovery',
                          side_effect=KeyboardInterrupt), \
                patch.object(self.start_recovery, '_mark_failed'), \
                self.assertRaises(KeyboardInterrupt):
            self._recover(source)
        state = self.store.inspect('arch-test')
        self.assertTrue(state['requires_review'])
        self.assertEqual(state['journal'][-1]['phase'], 'access_ready')
        before = dict(self.acls)
        result = self._recover(source)
        self.assertTrue(result['resolved'])
        self.assertEqual(self.acls, before)


class _Firmware:
    def __init__(self, path, digest):
        self.path, self.digest = path, digest

    def __enter__(self):
        self.stack = patch.multiple('vm_dev_lab.baselines', FIRMWARE_CODE=self.path,
                                    FIRMWARE_HASHES={'code': self.digest})
        return self.stack.__enter__()

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


if __name__ == '__main__':
    unittest.main()
