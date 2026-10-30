# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test ownership-bound cleanup of failed baseline and restore staging.

"""P09-C: gezieltes, journalgebundenes Cleanup fehlgeschlagener Stagings."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.baselines import BaselineManager
from vm_dev_lab.errors import LabError
from vm_dev_lab.restore import RestorePreparationManager
from vm_dev_lab.staging_cleanup import StagingCleanupManager

try:
    import test_restore as restore_tests
except ModuleNotFoundError:
    from tests import test_restore as restore_tests


class StagingCleanupTests(unittest.TestCase):
    """Use only isolated P08 fixtures, never host resources."""

    _write = restore_tests.RestorePreparationTests._write
    _id = staticmethod(restore_tests.RestorePreparationTests._id)
    _resources = restore_tests.RestorePreparationTests._resources
    _tool = restore_tests.RestorePreparationTests._tool
    _firmware = restore_tests.RestorePreparationTests._firmware
    _prepare = restore_tests.RestorePreparationTests._prepare

    def setUp(self):
        restore_tests.RestorePreparationTests.setUp(self)

    def _new_review_reservation(self, before, kind):
        reservations = self.lifecycle.resources.inventory()['reservations']
        candidates = [value for operation, value in reservations.items()
                      if operation not in before and value['kind'] == kind
                      and value['state'] == 'review_required']
        self.assertEqual(len(candidates), 1)
        return candidates[0]

    def _failed_baseline(self):
        before = set(self.lifecycle.resources.inventory()['reservations'])

        def interrupted(argv, deadline):
            if argv[:2] == ['qemu-img', 'convert']:
                Path(argv[-1]).write_bytes(b'partial baseline')
                raise KeyboardInterrupt
            return self._tool(argv, deadline)

        manager = BaselineManager(self.lifecycle, clock=time.monotonic,
                                  tool=interrupted, disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(KeyboardInterrupt):
            manager.create('arch-test', 'failed-base', 'project-ready', self.deadline)
        reservation = self._new_review_reservation(before, 'snapshot')
        operation = reservation['operation_id']
        path = (Path(self.data['storage']).parent / '.baseline-staging'
                / ('.stage-' + operation))
        self.assertTrue(path.is_dir())
        return operation, path, reservation

    def _failed_restore(self):
        operation = '77777777-7777-4777-8777-777777777777'

        def interrupted(argv, deadline):
            if argv[:2] == ['qemu-img', 'create']:
                Path(argv[-2]).write_bytes(b'partial restore')
                raise KeyboardInterrupt
            return self._tool(argv, deadline)

        manager = RestorePreparationManager(
            self.lifecycle, clock=time.monotonic, tool=interrupted,
            disk_usage=self.disk_usage)
        with self._firmware(), self.assertRaises(KeyboardInterrupt):
            manager.prepare('arch-test', self.baseline['baseline_id'], operation,
                            self.deadline)
        reservation = self.lifecycle.resources.inventory()['reservations'][operation]
        self.assertEqual(reservation['state'], 'review_required')
        path = (Path(self.data['storage']).parent / '.restore-staging'
                / self.record['instance_id'] / operation)
        self.assertTrue(path.is_dir())
        return operation, path, reservation

    def _cleanup(self, kind, operation):
        return self.lifecycle.cleanup_staging(
            'arch-test', kind, operation, self.deadline)

    def test_failed_baseline_cleanup_releases_exact_reservation_and_is_idempotent(self):
        operation, path, reservation = self._failed_baseline()
        result = self._cleanup('baseline', operation)
        self.assertFalse(path.exists())
        self.assertEqual(result['removed_files'], ['disk.qcow2'])
        self.assertEqual(result['released_resources'], reservation['requested'])
        self.assertFalse(result['idempotent'])
        released = self.lifecycle.resources.inventory()['reservations'][operation]
        self.assertEqual(released['state'], 'released')
        self.assertFalse(any(released['committed'].values()))
        repeated = self._cleanup('baseline', operation)
        self.assertTrue(repeated['idempotent'])
        self.assertEqual(repeated['cleanup_operation'], result['cleanup_operation'])

    def test_interrupted_restore_cleanup_uses_complete_owned_inventory(self):
        operation, path, reservation = self._failed_restore()
        expected = sorted(item.name for item in path.iterdir())
        result = self._cleanup('restore', operation)
        self.assertEqual(result['removed_files'], expected)
        self.assertEqual(result['released_resources'], reservation['requested'])
        self.assertFalse(path.exists())
        journal = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((journal['kind'], journal['phase'], journal['status']),
                         ('staging_cleanup', 'complete', 'complete'))

    def test_valid_preparation_published_baseline_and_wrong_operation_are_rejected(self):
        prepared = self._prepare()
        for kind, operation in (
                ('restore', self.operation),
                ('baseline', next(value['operation_id'] for value in
                                  self.lifecycle.resources.inventory()['reservations'].values()
                                  if value['kind'] == 'snapshot')),
                ('restore', '99999999-9999-4999-8999-999999999999')):
            with self.subTest(kind=kind, operation=operation), \
                    self.assertRaises(LabError) as caught:
                self._cleanup(kind, operation)
            self.assertIn(caught.exception.detail['code'],
                          {'RESOURCE_RESERVATION_CONFLICT', 'STAGING_NOT_FOUND'})
        self.assertTrue(Path(prepared['path']).is_dir())
        self.assertTrue(Path(self.baseline['path']).is_dir())

    def test_unknown_entry_symlink_and_hardlink_fail_closed(self):
        mutations = ('unknown', 'symlink', 'hardlink')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                operation, path, _ = self._failed_restore()
                disk = path / 'disk.qcow2'
                if mutation == 'unknown':
                    (path / 'foreign').write_bytes(b'foreign')
                elif mutation == 'symlink':
                    disk.unlink(); disk.symlink_to(path / 'preparation.json')
                else:
                    os.link(disk, path.parent / ('outside-link-' + operation))
                with self.assertRaises(LabError) as caught:
                    self._cleanup('restore', operation)
                self.assertIn(caught.exception.detail['code'],
                              {'STAGING_INVENTORY_MISMATCH',
                               'STAGING_OWNERSHIP_MISMATCH'})
                self.assertTrue(path.exists())
                # Every subiteration needs a fresh fixture and source UUID.
                self.setUp()

    def test_inode_exchange_after_persistent_intent_blocks_retry(self):
        operation, path, _ = self._failed_restore()
        with patch('vm_dev_lab.staging_cleanup.os.unlink',
                   side_effect=OSError(errno.EIO, 'injected')), \
                self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        disk = path / 'disk.qcow2'
        replacement = path / 'replacement'
        replacement.write_bytes(b'replacement')
        os.replace(replacement, disk)
        with self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'],
                         'STAGING_OWNERSHIP_MISMATCH')
        self.assertTrue(path.exists())

    def test_tampered_manifest_instance_domain_and_reservation_block_without_intent(self):
        operation, path, _ = self._failed_restore()
        self.domain.running = True
        with self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'DOMAIN_RUNNING')
        self.domain.running = False
        manifest = path / 'preparation.json'
        value = json.loads(manifest.read_text())
        value['target']['domain_uuid'] = '99999999-9999-4999-8999-999999999999'
        manifest.write_text(json.dumps(value))
        with self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'STAGING_OWNERSHIP_MISMATCH')
        self.assertNotEqual(self.store.inspect('arch-test')['journal'][-1]['kind'],
                            'staging_cleanup')
        self.assertTrue(path.exists())

        with self.store.lock('global'):
            state = self.store._read()
            state['resources']['reservations'][operation]['state'] = 'active'
            self.store._write(state)
        with self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'],
                         'RESOURCE_RESERVATION_CONFLICT')

    def test_abort_before_intent_preserves_everything(self):
        operation, path, _ = self._failed_restore()
        before = {item.name: item.read_bytes() for item in path.iterdir()}
        with patch.object(self.lifecycle.store, 'begin_staging_cleanup',
                          side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self._cleanup('restore', operation)
        self.assertEqual({item.name: item.read_bytes() for item in path.iterdir()}, before)
        self.assertNotEqual(self.store.inspect('arch-test')['journal'][-1]['kind'],
                            'staging_cleanup')

    def test_unlink_failure_keeps_review_state_and_explicit_retry_resumes(self):
        operation, path, _ = self._failed_restore()
        with patch('vm_dev_lab.staging_cleanup.os.unlink',
                   side_effect=OSError(errno.EIO, 'injected')), \
                self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        journal = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((journal['phase'], journal['status']), ('removing', 'pending'))
        self.assertTrue(self.store.inspect('arch-test')['requires_review'])
        self.assertEqual(self.lifecycle.resources.inventory()['reservations'][operation]['state'],
                         'review_required')
        self.assertTrue(path.exists())
        with patch('vm_dev_lab.staging_cleanup.os.fsync',
                   side_effect=OSError(errno.EIO, 'injected')), \
                self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        self.assertTrue(path.exists())
        self.assertEqual(self.lifecycle.resources.inventory()['reservations'][operation]['state'],
                         'review_required')
        self.assertTrue(self._cleanup('restore', operation)['removed'])

    def test_rmdir_failure_and_inode_exchange_after_intent_block_retry(self):
        operation, path, _ = self._failed_restore()
        with patch('vm_dev_lab.staging_cleanup.os.rmdir',
                   side_effect=OSError(errno.EIO, 'injected')), \
                self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        self.assertTrue(path.exists())
        self.assertEqual(list(path.iterdir()), [])
        # The empty, still identical directory can be resumed safely.
        self.assertTrue(self._cleanup('restore', operation)['removed'])
        self.assertFalse(path.exists())

    def test_failure_before_atomic_ledger_release_resumes_without_redelete(self):
        operation, path, _ = self._failed_restore()
        with patch.object(self.lifecycle.store, 'complete_staging_cleanup',
                          side_effect=LabError(6, 'STATE_IO', 'registry',
                                               'injected', 'retry')), \
                self.assertRaises(LabError):
            self._cleanup('restore', operation)
        self.assertFalse(path.exists())
        journal = self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((journal['phase'], journal['status']), ('removed', 'pending'))
        self.assertEqual(self.lifecycle.resources.inventory()['reservations'][operation]['state'],
                         'review_required')
        self.assertTrue(self._cleanup('restore', operation)['removed'])
        self.assertEqual(self.lifecycle.resources.inventory()['reservations'][operation]['state'],
                         'released')

    def test_registry_write_failure_and_cas_conflict_never_delete_before_intent(self):
        operation, path, _ = self._failed_restore()
        with patch.object(self.lifecycle.store, '_write',
                          side_effect=OSError(errno.ENOSPC, 'injected')), \
                self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        self.assertTrue(path.exists())
        self.assertNotEqual(self.store.inspect('arch-test')['journal'][-1]['kind'],
                            'staging_cleanup')

        original = self.lifecycle.store.begin_staging_cleanup

        def conflict(record, evidence):
            changed = self.store.inspect(record['instance_id'])
            operation_id = self.store.begin(changed, 'shutdown')
            self.store.advance(changed['instance_id'], operation_id, 'defined', complete=True)
            return original(record, evidence)

        with patch.object(self.lifecycle.store, 'begin_staging_cleanup', side_effect=conflict), \
                self.assertRaises(LabError) as caught:
            self._cleanup('restore', operation)
        self.assertEqual(caught.exception.detail['code'], 'REGISTRY_CONFLICT')
        self.assertTrue(path.exists())

    def test_instance_lock_blocks_cleanup_restore_and_destroy(self):
        operation, path, _ = self._failed_restore()
        with self.store.lock(self.record['instance_id']):
            for action in (
                    lambda: self._cleanup('restore', operation),
                    lambda: self.manager.prepare('arch-test', self.baseline['baseline_id'],
                                                 '88888888-8888-4888-8888-888888888888',
                                                 self.deadline),
                    lambda: self.lifecycle.destroy('arch-test', self.deadline)):
                with self.assertRaises(LabError) as caught:
                    action()
                self.assertEqual(caught.exception.detail['code'], 'LOCK_CONFLICT')
        self.assertTrue(path.exists())


class ActiveRestoreCleanupRejectionTests(unittest.TestCase):
    _write = restore_tests.RestoreActivationTests._write
    _id = staticmethod(restore_tests.RestoreActivationTests._id)
    _resources = restore_tests.RestoreActivationTests._resources
    _tool = restore_tests.RestoreActivationTests._tool
    _firmware = restore_tests.RestoreActivationTests._firmware
    _prepare = restore_tests.RestoreActivationTests._prepare
    _activate = restore_tests.RestoreActivationTests._activate

    def setUp(self):
        restore_tests.RestoreActivationTests.setUp(self)

    def test_active_restore_generation_and_referencing_operation_are_rejected(self):
        prepared = self._prepare()
        self._activate()
        with self.assertRaises(LabError) as caught:
            self.lifecycle.cleanup_staging(
                'arch-test', 'restore', prepared['restore_operation_id'], self.deadline)
        self.assertEqual(caught.exception.detail['code'],
                         'RESOURCE_RESERVATION_CONFLICT')
        self.assertTrue(Path(prepared['path']).is_dir())


if __name__ == '__main__':
    unittest.main()
