# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test private state, locking, ownership, and crash recovery.

"""P03: ownership, concurrency, and crashes exclusively under TemporaryDirectory."""
from copy import deepcopy
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.config import ConfigLoader
from vm_dev_lab.errors import LabError
from vm_dev_lab.fake_backend import FakeBackend
from vm_dev_lab.operations import OfflineLab
from vm_dev_lab.state import StatePaths, StateStore
from test_config import public_key


def hold_lock(paths, name, ready, release):
    with StateStore(paths).lock(name):
        ready.set()
        release.wait(5)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = StatePaths(self.root / 'data', self.root / 'state', self.root / 'run')
        self.store = StateStore(self.paths)
        self.store.initialize()
        self.backend = FakeBackend()
        self.lab = OfflineLab(self.store, self.backend)
        self.profile_root = self.root / 'config'
        (self.profile_root / 'profiles').mkdir(parents=True)
        data = {'schema_version': 1, 'ready': True, 'vm': {'name': 'test', 'guest_os': 'arch',
                'base_image': {'path': '../base.fixture', 'sha256': 'a' * 64},
                'network': {'name': 'lab'}, 'ssh': {'public_keys': [public_key()]}}}
        (self.profile_root / 'profiles/test.yaml').write_text(json.dumps(data))
        self.config = ConfigLoader(self.profile_root).load('test')

    def create(self, name='test'):
        return self.lab.create(self.config, name)

    def registry(self):
        return self.paths.state / 'registry.json'

    def edit(self, change):
        value = json.loads(self.registry().read_text())
        change(value)
        self.registry().write_text(json.dumps(value))

    def failure(self, action, code=None):
        with self.assertRaises(LabError) as caught:
            action()
        if code:
            self.assertEqual(caught.exception.detail['code'], code)
        return caught.exception

    def test_xdg_resolution_is_pure_and_has_no_unsafe_runtime_fallback(self):
        env = {'HOME': str(self.root / 'home'), 'XDG_RUNTIME_DIR': str(self.root / 'runtime')}
        before = list(self.root.iterdir())
        paths = StatePaths.from_environment(env)
        self.assertEqual(paths.data, self.root / 'home/.local/share/vm-dev-lab')
        self.assertEqual(paths.state, self.root / 'home/.local/state/vm-dev-lab')
        self.assertEqual(before, list(self.root.iterdir()))
        self.failure(lambda: StatePaths.from_environment({'HOME': str(self.root)}), 'RUNTIME_MISSING')
        for env in ({'XDG_DATA_HOME': 'relative'}, {'XDG_RUNTIME_DIR': '../escape'}):
            self.failure(lambda: StatePaths.from_environment({'HOME': str(self.root), 'XDG_RUNTIME_DIR': str(self.root / 'runtime'), **env}))
        self.failure(lambda: StatePaths(self.root / 'same', self.root / 'same', self.root / 'run'))
        self.failure(lambda: StatePaths(self.root / '../escape', self.root / 'state', self.root / 'run'))

    def test_fake_lifecycle_identity_manifest_journal_and_only_owned_cleanup(self):
        foreign = {'name': 'foreign', 'uuid': 'foreign', 'running': True}
        self.backend.domains['foreign'] = deepcopy(foreign)
        record = self.create()
        self.assertEqual(record['state'], 'ready')
        self.assertFalse(record['requires_review'])
        self.assertNotEqual(record['instance_id'], record['domain_uuid'])
        self.assertNotEqual(record['lab_id'], record['domain_uuid'])
        self.assertEqual(record['journal'][0]['events'], ['planned', 'allocating', 'defined', 'booting', 'provisioning', 'ready'])
        self.assertTrue(self.backend.capabilities()['simulated'])
        self.store.verify(record, self.backend.inspect(record['domain_uuid']))
        folder = self.paths.data / 'instances' / record['instance_id']
        sentinel = folder / 'not-in-manifest'
        sentinel.write_bytes(b'not ours')
        self.lab.shutdown('test')
        result = self.lab.destroy('test')
        self.assertEqual(result['state'], 'destroyed')
        self.assertEqual(sentinel.read_bytes(), b'not ours')
        self.assertEqual(self.backend.domains['foreign'], foreign)
        self.assertFalse((folder / 'disk.fixture').exists())
        self.assertTrue(folder.exists())  # No recursive cleanup.
        again = self.create()
        self.assertNotEqual(again['instance_id'], record['instance_id'])

    def test_registry_conflicts_foreign_uuid_and_cas_do_not_mutate_backend(self):
        record = self.create()
        before = deepcopy(self.backend.domains)
        self.failure(lambda: self.create(), 'REGISTRY_CONFLICT')
        self.failure(lambda: self.lab.destroy('00000000-0000-4000-8000-000000000000'), 'REGISTRY_CONFLICT')
        self.failure(lambda: self.store.update(record['instance_id'], '00000000-0000-4000-8000-000000000000', lambda r: r.update(state='failed')), 'REGISTRY_CONFLICT')
        self.assertEqual(self.backend.domains, before)
        self.failure(lambda: self.lab.destroy('test'), 'STATE_CONFLICT')

    def test_domain_metadata_uri_uuid_paths_and_autostart_must_all_match(self):
        record = self.create(); self.lab.shutdown('test')
        domain_uuid = record['domain_uuid']
        original = deepcopy(self.backend.domains[domain_uuid])
        changes = [lambda d: d.update(uuid='00000000-0000-4000-8000-000000000000'),
                   lambda d: d['metadata'].update(lab_id='00000000-0000-4000-8000-000000000000'),
                   lambda d: d.update(uri='qemu:///session'), lambda d: d.update(paths=['/etc/passwd']),
                   lambda d: d.update(autostart=True), lambda d: d.update(name='foreign')]
        for change in changes:
            with self.subTest(change=change):
                self.backend.domains[domain_uuid] = deepcopy(original)
                change(self.backend.domains[domain_uuid])
                calls = list(self.backend.calls)
                self.failure(lambda: self.lab.destroy('test'), 'OWNERSHIP_MISMATCH')
                self.assertEqual(self.backend.calls, calls)
        self.backend.domains[domain_uuid] = original
        other_store = StateStore(self.paths, 'qemu:///session')
        self.failure(lambda: OfflineLab(other_store, FakeBackend('qemu:///session')).shutdown('test'), 'OWNERSHIP_MISMATCH')

    def test_manifest_symlink_hardlink_replacement_and_missing_file_abort_all_cleanup(self):
        record = self.create(); self.lab.shutdown('test')
        folder = self.paths.data / 'instances' / record['instance_id']
        owned = folder / 'disk.fixture'; backup = folder / 'backup'
        owned.rename(backup)
        foreign = self.root / 'foreign.fixture'; foreign.write_bytes(b'foreign')
        os.chmod(foreign, 0o600)
        for replacement in ('symlink', 'hardlink', 'missing', 'new'):
            with self.subTest(replacement=replacement):
                if replacement == 'symlink': owned.symlink_to(foreign)
                if replacement == 'hardlink': os.link(foreign, owned)
                if replacement == 'new': owned.write_bytes(b'different'); os.chmod(owned, 0o600)
                calls = list(self.backend.calls)
                self.failure(lambda: self.lab.destroy('test'))
                self.assertEqual(self.backend.calls, calls)
                self.assertEqual(foreign.read_bytes(), b'foreign')
                self.assertTrue((folder / 'nvram.fixture').exists())
                if owned.exists() or owned.is_symlink(): owned.unlink()
        backup.rename(owned)
        self.lab.destroy('test')

    def test_instance_directory_replacement_and_symlink_parent_are_rejected(self):
        record = self.create(); self.lab.shutdown('test')
        folder = self.paths.data / 'instances' / record['instance_id']
        backup = folder.with_name('backup')
        folder.rename(backup)
        folder.symlink_to(backup, target_is_directory=True)
        self.failure(lambda: self.lab.destroy('test'))
        folder.unlink(); folder.mkdir(mode=0o700)
        self.failure(lambda: self.lab.destroy('test'), 'OWNERSHIP_MISMATCH')
        self.assertTrue((backup / 'disk.fixture').exists())

    def test_corrupt_unknown_or_conflicting_registry_is_not_overwritten(self):
        self.create()
        original = self.registry().read_bytes()
        corruptions = [lambda s: s.update(schema_version=3), lambda s: s.update(extra=True),
                       lambda s: next(iter(s['instances'].values())).update(instance_id='bad'),
                       lambda s: next(iter(s['instances'].values()))['manifest'][0].update(path='../../foreign'),
                       lambda s: next(iter(s['instances'].values())).update(state='planned'),
                       lambda s: next(iter(s['instances'].values())).update(journal=[]),
                       lambda s: next(iter(s['instances'].values()))['journal'].append(deepcopy(next(iter(s['instances'].values()))['journal'][0]))]
        for corrupt in corruptions:
            self.registry().write_bytes(original); self.edit(corrupt)
            before = self.registry().read_bytes()
            self.failure(self.store.initialize)
            self.assertEqual(before, self.registry().read_bytes())
        for raw in (b'{broken', b'{"schema_version":1,"schema_version":2}', b'x' * (1024 * 1024 + 1)):
            self.registry().write_bytes(raw)
            self.failure(lambda: self.create('other'))
            self.assertEqual(raw, self.registry().read_bytes())

    def test_state_and_lock_files_cannot_be_symlinks_or_shared_permissions(self):
        foreign = self.root / 'foreign'; foreign.write_bytes(b'unchanged')
        self.registry().unlink(); self.registry().symlink_to(foreign)
        self.failure(self.store.initialize)
        self.assertEqual(foreign.read_bytes(), b'unchanged')
        lock = self.paths.runtime / 'global.lock'
        lock.unlink(); lock.symlink_to(foreign)
        self.failure(lambda: self.create())
        self.assertEqual(foreign.read_bytes(), b'unchanged')
        os.chmod(self.paths.data, 0o755)
        self.failure(self.store.initialize)
        self.assertEqual(self.paths.data.stat().st_mode & 0o777, 0o755)

    def test_locks_conflict_across_processes_and_are_released_on_exit(self):
        record = self.create()
        for name in ('global', record['instance_id']):
            ctx = multiprocessing.get_context('fork')
            ready, release = ctx.Event(), ctx.Event()
            child = ctx.Process(target=hold_lock, args=(self.paths, name, ready, release))
            child.start()
            try:
                self.assertTrue(ready.wait(5))
                with self.assertRaises(LabError) as caught:
                    with self.store.lock(name): pass
                self.assertEqual(caught.exception.detail['code'], 'LOCK_CONFLICT')
            finally:
                release.set(); child.join(5)
                if child.is_alive(): child.terminate(); child.join()
            self.assertEqual(child.exitcode, 0)
            with self.store.lock(name): pass

    def test_concurrent_create_and_destroy_cannot_cross_reservations(self):
        ready, release = threading.Event(), threading.Event()
        def hook(method, point):
            if (method, point) == ('define', 'before'):
                ready.set()
                if not release.wait(5): raise RuntimeError('Test deadline')
        self.backend.hook = hook
        result, errors = [], []
        def create():
            try: result.append(self.create())
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=create)
        thread.start()
        try:
            self.assertTrue(ready.wait(5))
            self.failure(lambda: self.create(), 'REGISTRY_CONFLICT')
            self.failure(lambda: self.lab.destroy('test'), 'LOCK_CONFLICT')
        finally:
            release.set(); thread.join(5)
        self.assertFalse(thread.is_alive()); self.assertFalse(errors)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(self.backend.domains), 1)

    def test_crash_after_define_blocks_retry_shutdown_and_cleanup(self):
        def crash(method, point):
            if (method, point) == ('define', 'after'): raise SystemExit('simulated crash')
        self.backend.hook = crash
        with self.assertRaises(SystemExit): self.create()
        self.backend.hook = None
        record = self.store.inspect('test')
        self.assertTrue(record['requires_review'])
        self.assertEqual(record['journal'][-1]['status'], 'pending')
        self.assertIsNotNone(self.backend.inspect(record['domain_uuid']))
        calls = list(self.backend.calls)
        restarted = OfflineLab(StateStore(self.paths), self.backend)
        self.failure(lambda: restarted.create(self.config), 'REGISTRY_CONFLICT')
        self.failure(lambda: restarted.shutdown('test'), 'REVIEW_REQUIRED')
        self.failure(lambda: restarted.destroy('test'), 'REVIEW_REQUIRED')
        self.assertEqual(calls, self.backend.calls)

    def test_backend_errors_before_after_mutation_never_publish_ready(self):
        for point in ('before', 'after'):
            name = 'fail-' + point
            def hook(method, when):
                if (method, when) == ('start', point): raise RuntimeError('injected')
            self.backend.hook = hook
            with self.assertRaises(RuntimeError): self.create(name)
            self.backend.hook = None
            record = self.store.inspect(name)
            self.assertEqual(record['state'], 'failed')
            self.assertEqual(record['journal'][-1]['status'], 'review_required')
            self.assertTrue(record['requires_review'])
            self.assertEqual(record['journal'][-1]['last_safe'], 'defined')
            self.failure(lambda: self.lab.destroy(name), 'REVIEW_REQUIRED')

    def test_forged_record_cannot_allocate_or_select_paths(self):
        record = self.create()
        for key, value in (('instance_id', '../../escape'), ('lab_id', '00000000-0000-4000-8000-000000000000'),
                           ('domain_uuid', '00000000-0000-4000-8000-000000000000')):
            changed = deepcopy(record); changed[key] = value
            with self.subTest(key=key):
                self.failure(lambda: self.store.allocate_fixtures(changed, record['journal'][-1]['id']))
                with self.assertRaises(LabError):
                    with self.store.selection(changed): pass
        self.assertFalse((self.root / 'escape').exists())
        self.assertEqual(len(list((self.paths.data / 'instances').iterdir())), 1)

    def test_atomic_journal_publication_survives_failed_replace(self):
        record = self.create(); before = self.registry().read_bytes()
        with patch('vm_dev_lab.state.os.replace', side_effect=OSError('ENOSPC')):
            self.failure(lambda: self.lab.shutdown('test'))
        self.assertEqual(before, self.registry().read_bytes())
        self.assertTrue(self.backend.inspect(record['domain_uuid'])['running'])
        self.assertTrue(list(self.paths.state.glob('.registry-*.tmp')))
        # The old complete registry remains valid; no implicit retry.
        self.assertFalse(self.store.inspect('test')['requires_review'])

    def test_crash_during_destroy_preserves_journal_and_remaining_files(self):
        record = self.create(); self.lab.shutdown('test')
        def crash(method, point):
            if (method, point) == ('undefine', 'after'): raise SystemExit('crash')
        self.backend.hook = crash
        with self.assertRaises(SystemExit): self.lab.destroy('test')
        self.backend.hook = None
        folder = self.paths.data / 'instances' / record['instance_id']
        self.assertTrue((folder / 'disk.fixture').exists())
        self.assertTrue(self.store.inspect('test')['requires_review'])
        self.assertIsNone(self.backend.inspect(record['domain_uuid']))
        self.failure(lambda: self.lab.destroy('test'), 'REVIEW_REQUIRED')

    def test_partial_cleanup_blocks_retries_and_preserves_remaining_resources(self):
        record = self.create(); self.lab.shutdown('test')
        folder = self.paths.data / 'instances' / record['instance_id']
        original_unlink = os.unlink
        def interrupt(path, **kwargs):
            if path == 'nvram.fixture': raise OSError('injected I/O error')
            return original_unlink(path, **kwargs)
        with patch('vm_dev_lab.operations.os.unlink', side_effect=interrupt):
            self.failure(lambda: self.lab.destroy('test'))
        self.assertFalse((folder / 'disk.fixture').exists())
        self.assertTrue((folder / 'nvram.fixture').exists())
        self.assertTrue(self.store.inspect('test')['requires_review'])
        self.failure(lambda: self.lab.destroy('test'), 'REVIEW_REQUIRED')

    def test_offline_harness_refuses_real_backends_and_has_no_external_calls(self):
        self.failure(lambda: OfflineLab(self.store, object()), 'FAKE_REQUIRED')
        with patch('subprocess.Popen', side_effect=AssertionError('No process')), patch('socket.socket', side_effect=AssertionError('No socket')):
            self.create(); self.lab.shutdown('test'); self.lab.destroy('test')
