# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test atomic resource admission, reservation, and release.

"""P09-B: Aggregated budgets, atomic reservation, and conservative release."""
from pathlib import Path
import json
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.errors import LabError
from vm_dev_lab.resources import (
    MAX_RESOURCE_INTEGER, ResourceLedger, available_host_cpus, request,
)
from vm_dev_lab.state import DEFAULT_RESOURCE_LIMITS, StatePaths, StateStore


class ResourceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = StateStore(StatePaths(root/'data', root/'state', root/'run'))
        self.store.initialize()
        self.host_cpus = 64
        self.ledger = ResourceLedger(
            self.store, host_cpu_provider=lambda: self.host_cpus)

    def _record(self, name):
        record = self.store.reserve(name)
        return record, record['journal'][-1]['id']

    def _limits(self, **values):
        with self.store.lock('global'):
            state = self.store._read()
            state['resources']['limits'].update(values)
            self.store._write(state)

    def _registry(self):
        return self.store.paths.state.joinpath('registry.json')

    def _concurrent_creates(self, requests):
        barrier = threading.Barrier(len(requests))
        results, errors = [], []

        def create(name, wanted):
            barrier.wait()
            for _attempt in range(100):
                try:
                    results.append(ResourceLedger(
                        StateStore(self.store.paths),
                        host_cpu_provider=lambda: self.host_cpus,
                    ).reserve_create(name, wanted))
                    return
                except LabError as error:
                    if error.detail['code'] != 'LOCK_CONFLICT':
                        errors.append(error)
                        return
                    time.sleep(0.001)
            errors.append(RuntimeError('global lock did not become available'))

        threads = [threading.Thread(target=create, args=item) for item in requests]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        return results, errors

    def test_create_record_journal_and_reservation_commit_atomically(self):
        wanted = request(instances=1, vcpus=2, memory_mib=1024,
                         virtual_disk_bytes=10, staging_bytes=10)
        with patch.object(self.store, '_write', wraps=self.store._write) as write:
            record = self.ledger.reserve_create('atomic', wanted)
        self.assertEqual(write.call_count, 1)
        state = self.store._read(); operation = record['journal'][-1]
        self.assertEqual(state['instances'][record['instance_id']], record)
        self.assertEqual((operation['kind'], operation['phase'], operation['status']),
                         ('create', 'planned', 'pending'))
        reservation = state['resources']['reservations'][operation['id']]
        self.assertEqual((reservation['instance_id'], reservation['kind'],
                          reservation['state'], reservation['requested']),
                         (record['instance_id'], 'create', 'active', wanted))

    def test_create_budget_rejections_leave_registry_byte_identical(self):
        generous = dict(DEFAULT_RESOURCE_LIMITS)
        cases = [
            ({**generous, 'vcpus': 1}, request(vcpus=2), 'RESOURCE_VCPU_BUDGET'),
            ({**generous, 'memory_mib': 1}, request(memory_mib=2),
             'RESOURCE_MEMORY_BUDGET'),
            ({**generous, 'storage_bytes': 10}, request(staging_bytes=11),
             'RESOURCE_STORAGE_BUDGET'),
            ({**generous, 'operations': 1}, request(operations=2),
             'RESOURCE_OPERATION_BUDGET'),
        ]
        for index, (limits, wanted, code) in enumerate(cases):
            with self.subTest(code=code):
                self._limits(**limits); before = self._registry().read_bytes()
                with self.assertRaises(LabError) as caught:
                    self.ledger.reserve_create(f'rejected-{index}', wanted)
                self.assertEqual(caught.exception.detail['code'], code)
                self.assertEqual(self._registry().read_bytes(), before)

    def test_host_budget_rejection_leaves_no_create_or_reservation(self):
        cases = [
            ('host-storage-rejected', 1, 10, 'HOST_STORAGE_BUDGET'),
            ('host-memory-rejected', 10, 1, 'HOST_MEMORY_BUDGET'),
        ]
        for name, storage, memory, code in cases:
            with self.subTest(code=code):
                before = self._registry().read_bytes()
                with self.assertRaises(LabError) as caught:
                    self.ledger.reserve_create(
                        name, request(memory_mib=2, staging_bytes=2),
                        host_memory_mib=memory, host_storage_bytes=storage)
                self.assertEqual(caught.exception.detail['code'], code)
                self.assertEqual(self._registry().read_bytes(), before)

    def test_concurrent_creates_use_latest_ledger_generation(self):
        self._limits(instances=2, vcpus=4, memory_mib=2048, operations=2)
        wanted = request(instances=1, vcpus=2, memory_mib=1024)
        results, errors = self._concurrent_creates([
            ('concurrent-one', wanted), ('concurrent-two', wanted)])
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        state = self.store._read()
        self.assertEqual(len(state['instances']), 2)
        self.assertEqual(len(state['resources']['reservations']), 2)

    def test_concurrent_aggregate_overbooking_commits_only_one_create(self):
        self._limits(instances=2, vcpus=2, memory_mib=2048, operations=2)
        wanted = request(instances=1, vcpus=2, memory_mib=1024)
        results, errors = self._concurrent_creates([
            ('racing-one', wanted), ('racing-two', wanted)])
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].detail['code'], 'RESOURCE_VCPU_BUDGET')
        state = self.store._read()
        self.assertEqual(len(state['instances']), 1)
        self.assertEqual(len(state['resources']['reservations']), 1)

    def test_cpu_overcommit_allows_15_of_20_host_vcpus(self):
        self.host_cpus = 10
        self._limits(instances=2, vcpus=20, memory_mib=4096, operations=2)
        wanted = request(instances=1, vcpus=15, memory_mib=1024)
        record = self.ledger.reserve_create('cpu-fifteen', wanted)
        operation = record['journal'][-1]['id']
        self.assertEqual(
            self.store._read()['resources']['reservations'][operation]['requested'],
            wanted)

    def test_cpu_overcommit_accepts_20_and_rejects_21_without_mutation(self):
        self.host_cpus = 10
        self._limits(instances=3, vcpus=30, memory_mib=4096, operations=3)
        self.ledger.reserve_create('cpu-ten-a', request(instances=1, vcpus=10))
        self.ledger.reserve_create('cpu-ten-b', request(instances=1, vcpus=10))
        before = self._registry().read_bytes()
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve_create('cpu-twenty-one', request(instances=1, vcpus=1))
        self.assertEqual(caught.exception.detail['code'], 'RESOURCE_VCPU_BUDGET')
        self.assertEqual(self._registry().read_bytes(), before)

    def test_lower_explicit_cpu_limit_remains_effective(self):
        self.host_cpus = 10
        self._limits(vcpus=12)
        before = self._registry().read_bytes()
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve_create('lab-limit', request(vcpus=13))
        self.assertEqual(caught.exception.detail['code'], 'RESOURCE_VCPU_BUDGET')
        self.assertEqual(self._registry().read_bytes(), before)

    def test_concurrent_creates_cannot_cross_cpu_overcommit_limit(self):
        self.host_cpus = 10
        self._limits(instances=2, vcpus=30, memory_mib=4096, operations=2)
        results, errors = self._concurrent_creates([
            ('cpu-race-ten', request(instances=1, vcpus=10)),
            ('cpu-race-eleven', request(instances=1, vcpus=11)),
        ])
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].detail['code'], 'RESOURCE_VCPU_BUDGET')
        state = self.store._read()
        self.assertEqual(len(state['instances']), 1)
        self.assertEqual(len(state['resources']['reservations']), 1)

    def test_invalid_and_overflowing_host_cpu_counts_fail_before_commit(self):
        invalid = (None, True, 0, -1, MAX_RESOURCE_INTEGER // 2 + 1)
        for index, value in enumerate(invalid):
            with self.subTest(value=value):
                self.host_cpus = value
                before = self._registry().read_bytes()
                with self.assertRaises(LabError) as caught:
                    self.ledger.reserve_create(f'cpu-invalid-{index}', request(vcpus=1))
                self.assertEqual(caught.exception.detail['code'], 'HOST_CPU_INVALID')
                self.assertEqual(self._registry().read_bytes(), before)

    def test_host_cpu_detection_prefers_affinity_and_has_safe_fallback(self):
        with patch('vm_dev_lab.resources.os.sched_getaffinity',
                   return_value=set(range(10))), \
                patch('vm_dev_lab.resources.os.cpu_count', return_value=99):
            self.assertEqual(available_host_cpus(), 10)
        with patch('vm_dev_lab.resources.os.sched_getaffinity',
                   side_effect=OSError('unavailable')), \
                patch('vm_dev_lab.resources.os.cpu_count', return_value=6):
            self.assertEqual(available_host_cpus(), 6)

    def test_lock_conflict_and_duplicate_operation_do_not_partially_commit(self):
        before = self._registry().read_bytes()
        with self.store.lock('global'):
            with self.assertRaises(LabError) as caught:
                self.ledger.reserve_create('locked', request())
        self.assertEqual(caught.exception.detail['code'], 'LOCK_CONFLICT')
        self.assertEqual(self._registry().read_bytes(), before)

        self.ledger.reserve_create('registry-conflict', request())
        committed = self._registry().read_bytes()
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve_create('registry-conflict', request())
        self.assertEqual(caught.exception.detail['code'], 'REGISTRY_CONFLICT')
        self.assertEqual(self._registry().read_bytes(), committed)

        operation = dict(id='11111111-1111-4111-8111-111111111111',
                         kind='create', phase='planned', last_safe='planned',
                         status='pending', events=['planned'])
        with patch.object(StateStore, '_operation', side_effect=lambda _kind: dict(operation)):
            first = self.ledger.reserve_create('first-fixed-operation', request())
            committed = self._registry().read_bytes()
            with self.assertRaises(LabError) as caught:
                self.ledger.reserve_create('second-fixed-operation', request())
        self.assertEqual(caught.exception.detail['code'],
                         'RESOURCE_RESERVATION_CONFLICT')
        self.assertEqual(self._registry().read_bytes(), committed)
        self.assertEqual(len(self.store._read()['instances']), 2)
        self.assertEqual(first['journal'][-1]['id'], operation['id'])

    def test_failures_before_and_during_registry_replace_publish_nothing(self):
        before = self._registry().read_bytes()
        with patch.object(self.store, '_write', side_effect=SystemExit('before commit')):
            with self.assertRaises(SystemExit):
                self.ledger.reserve_create('before-commit', request())
        self.assertEqual(self._registry().read_bytes(), before)

        with patch('vm_dev_lab.state.os.replace', side_effect=OSError('replace failed')):
            with self.assertRaises(LabError) as caught:
                self.ledger.reserve_create('replace-failed', request())
        self.assertEqual(caught.exception.detail['code'], 'STATE_IO')
        self.assertEqual(self._registry().read_bytes(), before)

    def test_interruption_after_replace_exposes_complete_combined_generation(self):
        calls = 0

        def fsync(_fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SystemExit('after replace')

        with patch('vm_dev_lab.state.os.fsync', side_effect=fsync):
            with self.assertRaises(SystemExit):
                self.ledger.reserve_create('after-commit', request(instances=1))
        state = self.store._read()
        self.assertEqual(len(state['instances']), 1)
        record = next(iter(state['instances'].values()))
        operation = record['journal'][-1]
        self.assertEqual(state['resources']['reservations'][operation['id']]['instance_id'],
                         record['instance_id'])
        self.assertEqual(operation['status'], 'pending')

    def test_v1_rejection_does_not_migrate_or_add_create(self):
        with self.store.lock('global'):
            state = self.store._read()
            legacy = {key: state[key] for key in ('schema_version', 'lab_id', 'instances')}
            legacy['schema_version'] = 1
            self.store._write(legacy)
        before = self._registry().read_bytes()
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve_create('legacy-blocked', request())
        self.assertEqual(caught.exception.detail['code'], 'RESOURCE_MIGRATION_REQUIRED')
        self.assertEqual(self._registry().read_bytes(), before)

    def test_two_creates_fit_and_third_aggregate_request_is_rejected(self):
        self._limits(instances=2, vcpus=4, memory_mib=2048, operations=2)
        first, first_op = self._record('first')
        second, second_op = self._record('second')
        wanted = request(instances=1, vcpus=2, memory_mib=1024,
                         virtual_disk_bytes=10, staging_bytes=10)
        self.ledger.reserve(first['instance_id'], first_op, 'create', wanted)
        self.ledger.reserve(second['instance_id'], second_op, 'create', wanted)
        third, third_op = self._record('third')
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve(third['instance_id'], third_op, 'create', wanted)
        self.assertEqual(caught.exception.detail['code'], 'RESOURCE_INSTANCE_BUDGET')

    def test_requested_before_reservation_consumes_nothing_but_mixed_operations_do(self):
        self._limits(operations=2)
        requested, _requested_op = self._record('requested-only')
        self.assertNotIn(_requested_op, self.ledger.inventory()['reservations'])
        snapshot, snapshot_op = self._record('snapshot-owner')
        restore, restore_op = self._record('restore-owner')
        self.ledger.reserve(snapshot['instance_id'], snapshot_op, 'snapshot',
                            request(staging_bytes=10))
        self.ledger.reserve(restore['instance_id'], restore_op, 'restore',
                            request(staging_bytes=10))
        third, third_op = self._record('mixed-blocked')
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve(third['instance_id'], third_op, 'create', request())
        self.assertEqual(caught.exception.detail['code'], 'RESOURCE_OPERATION_BUDGET')
        self.assertEqual(requested['state'], 'planned')

    def test_each_limit_and_shared_storage_staging_limit_fail_closed(self):
        cases = [
            ({'vcpus': 1}, request(vcpus=2), 'RESOURCE_VCPU_BUDGET'),
            ({'memory_mib': 1}, request(memory_mib=2), 'RESOURCE_MEMORY_BUDGET'),
            ({'virtual_disk_bytes': 1}, request(virtual_disk_bytes=2),
             'RESOURCE_VIRTUAL_DISK_BUDGET'),
            ({'storage_bytes': 10}, request(storage_bytes=6, staging_bytes=5),
             'RESOURCE_STORAGE_BUDGET'),
            ({'operations': 1}, request(operations=2), 'RESOURCE_OPERATION_BUDGET'),
        ]
        for index, (limits, wanted, code) in enumerate(cases):
            with self.subTest(code=code):
                record, operation = self._record(f'limit-{index}')
                self._limits(**limits)
                with self.assertRaises(LabError) as caught:
                    self.ledger.reserve(record['instance_id'], operation, 'create', wanted)
                self.assertEqual(caught.exception.detail['code'], code)

    def test_operation_uuid_is_idempotent_but_cannot_be_rebound(self):
        record, operation = self._record('retry')
        wanted = request(instances=1, vcpus=1, memory_mib=512)
        first = self.ledger.reserve(record['instance_id'], operation, 'create', wanted)
        self.assertEqual(self.ledger.reserve(
            record['instance_id'], operation, 'create', wanted), first)
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve(record['instance_id'], operation, 'create',
                                request(instances=1, vcpus=2, memory_mib=512))
        self.assertEqual(caught.exception.detail['code'],
                         'RESOURCE_RESERVATION_CONFLICT')

    def test_concurrent_host_headroom_counts_open_staging_and_memory(self):
        first, first_op = self._record('host-first')
        self.ledger.reserve(
            first['instance_id'], first_op, 'create',
            request(memory_mib=1024, staging_bytes=60),
            host_memory_mib=2048, host_storage_bytes=100)
        second, second_op = self._record('host-second')
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve(
                second['instance_id'], second_op, 'create',
                request(memory_mib=1024, staging_bytes=50),
                host_memory_mib=2048, host_storage_bytes=100)
        self.assertEqual(caught.exception.detail['code'], 'HOST_STORAGE_BUDGET')
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve(
                second['instance_id'], second_op, 'create',
                request(memory_mib=1025, staging_bytes=1),
                host_memory_mib=2048, host_storage_bytes=100)
        self.assertEqual(caught.exception.detail['code'], 'HOST_MEMORY_BUDGET')

    def test_crash_review_remains_reserved_and_bind_separates_sparse_usage(self):
        self._limits(operations=1)
        record, operation = self._record('unclear')
        wanted = request(instances=1, virtual_disk_bytes=30 * 1024**3,
                         staging_bytes=30 * 1024**3)
        self.ledger.reserve(record['instance_id'], operation, 'create', wanted)
        self.ledger.review(record['instance_id'], operation)
        other, other_op = self._record('blocked')
        with self.assertRaises(LabError) as caught:
            self.ledger.reserve(other['instance_id'], other_op, 'create', request())
        self.assertEqual(caught.exception.detail['code'], 'RESOURCE_OPERATION_BUDGET')

        fresh, fresh_op = self._record('sparse')
        self._limits(operations=2)
        sparse = request(instances=1, virtual_disk_bytes=40 * 1024**3,
                         staging_bytes=40 * 1024**3)
        self.ledger.reserve(fresh['instance_id'], fresh_op, 'create', sparse)
        bound = self.ledger.bind(
            fresh['instance_id'], fresh_op,
            request(instances=1, virtual_disk_bytes=40 * 1024**3,
                    storage_bytes=2 * 1024**3, operations=0))
        self.assertEqual(bound['committed']['virtual_disk_bytes'], 40 * 1024**3)
        self.assertEqual(bound['committed']['storage_bytes'], 2 * 1024**3)

    def test_destroy_releases_runtime_and_restore_but_preserves_baseline(self):
        record, create_op = self._record('destroyed')
        self.ledger.reserve(record['instance_id'], create_op, 'create', request(instances=1))
        self.ledger.bind(record['instance_id'], create_op,
                         request(instances=1, storage_bytes=10, operations=0))
        snapshot_op = '11111111-1111-4111-8111-111111111111'
        self.ledger.reserve(record['instance_id'], snapshot_op, 'snapshot',
                            request(staging_bytes=20))
        self.ledger.bind(record['instance_id'], snapshot_op,
                         request(storage_bytes=20, operations=0))
        self.store.advance(record['instance_id'], create_op, 'allocating')
        self.store.advance(record['instance_id'], create_op, 'defined', complete=True)
        current = self.store.inspect(record['instance_id'])
        destroy_op = self.store.begin(current, 'destroy')
        self.store.advance(record['instance_id'], destroy_op, 'undefined')
        self.store.complete_destroy(record['instance_id'], destroy_op)
        with self.assertRaises(LabError) as caught:
            self.store.complete_destroy(record['instance_id'], destroy_op)
        self.assertEqual(caught.exception.detail['code'], 'STATE_CONFLICT')
        reservations = self.ledger.inventory()['reservations']
        self.assertEqual(reservations[create_op]['state'], 'released')
        self.assertEqual(reservations[snapshot_op]['state'], 'bound')

    def test_tampered_negative_and_unknown_registry_data_are_rejected(self):
        record, operation = self._record('tamper')
        self.ledger.reserve(record['instance_id'], operation, 'create', request())
        path = self.store.paths.state / 'registry.json'
        value = json.loads(path.read_text())
        value['resources']['reservations'][operation]['requested']['staging_bytes'] = -1
        path.write_text(json.dumps(value)); path.chmod(0o600)
        with self.assertRaises(LabError) as caught:
            self.ledger.inventory()
        self.assertEqual(caught.exception.detail['code'], 'STATE_INVALID')


if __name__ == '__main__':
    unittest.main()
