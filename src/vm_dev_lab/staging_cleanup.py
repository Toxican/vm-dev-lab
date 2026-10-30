# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Remove ownership-bound failed staging resources safely.

"""P09-C: Explicit cleanup of unambiguously bound, unusable staging data."""
from copy import deepcopy
import json
import os
from pathlib import Path
import stat

from .baselines import BaselineIndex, BaselineManager
from .errors import LabError
from .lifecycle import RealOwnership
from .restore import RestorePreparationManager, _read_json


BASELINE_FILES = {
    'disk.qcow2', 'nvram.fd', 'domain.xml', 'instance.json',
    'guest-manifest.json', 'manifest.json',
}
RESTORE_FILES = {'disk.qcow2', 'nvram.fd', 'domain.xml', 'preparation.json'}


def fail(code, message, status=5):
    raise LabError(status, code, 'staging-cleanup', message,
                   'Inspect staging, operation, registry, and resource ledger; do not delete anything indiscriminately.')


class StagingCleanupManager:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.store = lifecycle.store
        self.backend = lifecycle.backend
        self.resources = lifecycle.resources

    @staticmethod
    def _file_identity(path):
        info = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_nlink != 1):
            fail('STAGING_OWNERSHIP_MISMATCH',
                 'Staging file is not regular, unambiguous, or associated with the user.')
        return {'device': info.st_dev, 'inode': info.st_ino,
                'size': info.st_size, 'blocks': info.st_blocks * 512}

    @staticmethod
    def _directory_identity(path):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            fail('STAGING_OWNERSHIP_MISMATCH',
                 'Staging directory is not private and unambiguously associated.')
        return {'device': info.st_dev, 'inode': info.st_ino}

    def _inventory(self, path, kind):
        allowed = BASELINE_FILES if kind == 'baseline' else RESTORE_FILES
        try:
            directory = self._directory_identity(path)
            names = {entry.name for entry in os.scandir(path)}
        except FileNotFoundError:
            fail('STAGING_NOT_FOUND', 'The bound staging does not exist.', 4)
        if not names <= allowed:
            fail('STAGING_INVENTORY_MISMATCH',
                 'Unknown file or subdirectory blocks cleanup.')
        return directory, {name: self._file_identity(path / name) for name in names}

    @staticmethod
    def _path(data, kind, source_operation):
        pool = Path(data['storage']).parent
        if kind == 'baseline':
            return pool / '.baseline-staging' / ('.stage-' + source_operation)
        return pool / '.restore-staging' / data['instance_id'] / source_operation

    def _reservation(self, record, kind, source_operation, *, state, requested=None):
        reservation = self.resources.inventory()['reservations'].get(source_operation)
        expected_kind = 'snapshot' if kind == 'baseline' else 'restore'
        if (reservation is None or reservation['instance_id'] != record['instance_id']
                or reservation['kind'] != expected_kind
                or reservation['state'] != state
                or (requested is not None and reservation['requested'] != requested)):
            fail('RESOURCE_RESERVATION_CONFLICT',
                 'No exactly matching staging reservation found.', 4)
        return reservation

    def _safe_domain(self, record, operation_id=None):
        domain = self.backend.domain(record['domain_uuid'])
        owner = RealOwnership(
            self.store, self.backend, operation_id,
            read_only_diagnostic=operation_id is not None)
        data = owner.verify(record, domain)
        if domain.isActive():
            fail('DOMAIN_RUNNING', 'Active domain blocks staging cleanup.', 4)
        managed = getattr(domain, 'hasManagedSaveImage', None)
        if managed is None or managed(0):
            fail('MANAGED_SAVE_UNSUPPORTED',
                 'Managed-save evidence is missing or a managed save exists.', 4)
        return data

    def _references(self, record, data, kind, source_operation, path, deadline):
        if kind == 'restore':
            generation = data.get('restore_generation')
            if generation and generation['preparation_operation_id'] == source_operation:
                fail('STAGING_REFERENCED', 'Restore generation is active and cannot be cleaned up.', 4)
            if any(item.get('kind') == 'restore_activation'
                   and item.get('restore', {}).get('preparation_operation_id') == source_operation
                   for item in record['journal']):
                fail('STAGING_REFERENCED',
                     'Restore preparation is referenced by the journal.', 4)
            try:
                value = _read_json(path / 'preparation.json')
                checker = RestorePreparationManager(
                    self.lifecycle, clock=self.lifecycle.clock,
                    tool=lambda argv, limit: self.lifecycle._run(
                        argv, limit, timeout=max(0.1, limit-self.lifecycle.clock())))
                checker._validate_manifest(value, path)
            except (OSError, LabError, ValueError, TypeError, json.JSONDecodeError):
                fail('STAGING_EVIDENCE_INVALID',
                     'Restore-preparation evidence is missing or inconsistent.')
            if (value['operation_id'] != source_operation
                    or value['target']['instance_id'] != record['instance_id']
                    or value['target']['domain_uuid'] != record['domain_uuid']):
                fail('STAGING_OWNERSHIP_MISMATCH',
                     'Restore preparation does not belong to the instance and operation.')
            if value['status'] == 'prepared':
                fail('STAGING_STILL_VALID',
                     'A valid prepared restore generation is not a cleanup target.', 4)
        else:
            manifest = path / 'manifest.json'
            if manifest.exists():
                try:
                    checker = BaselineManager(
                        self.lifecycle, clock=self.lifecycle.clock,
                        tool=lambda argv, limit: self.lifecycle._run(
                            argv, limit,
                            timeout=max(0.1, limit-self.lifecycle.clock())))
                    verified = checker.verify_path(
                        path, expected_instance=record['instance_id'],
                        indexed=False, deadline=deadline)
                    baseline_id = verified['baseline_id']
                    entries = BaselineIndex(self.store).read()['instances'].get(
                        record['instance_id'], {})
                except (LabError, OSError, ValueError, TypeError, json.JSONDecodeError):
                    fail('STAGING_EVIDENCE_INVALID',
                         'Baseline staging manifest is inconsistent.')
                if baseline_id in entries.values():
                    fail('STAGING_REFERENCED',
                         'A published immutable baseline is not a cleanup target.', 4)

    @staticmethod
    def _matches(path, expected):
        try:
            actual = StagingCleanupManager._file_identity(path)
        except FileNotFoundError:
            return False
        return actual == expected

    def _verify_resume(self, evidence, *, allow_missing):
        path = Path(evidence['path'])
        try:
            directory = self._directory_identity(path)
        except FileNotFoundError:
            if allow_missing:
                return set()
            fail('STAGING_NOT_FOUND', 'Staging is missing before the deletion intent.', 4)
        if directory != evidence['directory']:
            fail('STAGING_OWNERSHIP_MISMATCH', 'Staging directory was replaced.')
        names = {entry.name for entry in os.scandir(path)}
        expected = set(evidence['files'])
        if not names <= expected or (not allow_missing and names != expected):
            fail('STAGING_INVENTORY_MISMATCH',
                 'Staging inventory differs from the cleanup intent.')
        for name in names:
            if not self._matches(path / name, evidence['files'][name]):
                fail('STAGING_OWNERSHIP_MISMATCH', 'Staging file was replaced.')
        return names

    def cleanup(self, target, kind, source_operation, deadline):
        if kind not in {'baseline', 'restore'}:
            fail('STAGING_KIND_INVALID', 'Unknown staging kind.', 2)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record = self.store.inspect(initial['instance_id'])
            latest = record['journal'][-1]
            if latest.get('kind') == 'staging_cleanup':
                evidence = latest['cleanup']
                if (evidence['source_operation'] != source_operation
                        or evidence['staging_kind'] != kind):
                    fail('CLEANUP_SOURCE_MISMATCH',
                         'Open or latest cleanup belongs to a different source.', 4)
                if latest['status'] == 'complete':
                    if os.path.lexists(evidence['path']):
                        fail('CLEANUP_STATE_CONFLICT',
                             'Completed cleanup has a staging path again.', 4)
                    self._reservation(
                        record, kind, source_operation, state='released',
                        requested=evidence['reservation_requested'])
                    return self._result(record, latest, evidence, idempotent=True)
                if latest['status'] != 'pending':
                    fail('CLEANUP_STATE_CONFLICT', 'Cleanup cannot be continued safely.', 4)
                operation_id = latest['id']
                data = self._safe_domain(record, operation_id)
                if Path(evidence['path']) != self._path(data, kind, source_operation):
                    fail('CLEANUP_STATE_CONFLICT',
                         'Persisted cleanup path does not match the instance binding.', 4)
                self._reservation(
                    record, kind, source_operation, state='review_required',
                    requested=evidence['reservation_requested'])
            else:
                if record['requires_review']:
                    fail('REVIEW_REQUIRED',
                         'Another incomplete operation blocks staging cleanup.', 4)
                data = self._safe_domain(record)
                path = self._path(data, kind, source_operation)
                reservation = self._reservation(
                    record, kind, source_operation, state='review_required')
                self._references(record, data, kind, source_operation, path, deadline)
                directory, files = self._inventory(path, kind)
                evidence = {
                    'source_operation': source_operation, 'staging_kind': kind,
                    'path': str(path), 'directory': directory, 'files': files,
                    'reservation_requested': deepcopy(reservation['requested']),
                }
                operation_id = self.store.begin_staging_cleanup(record, evidence)
                record = self.store.inspect(record['instance_id'])

            phase = record['journal'][-1]['phase']
            path = Path(evidence['path'])
            if phase == 'planned':
                # A process interruption immediately after the intent must not
                # reinterpret reference validation as later deletion approval.
                self._references(
                    record, data, kind, source_operation, path, deadline)
                self._verify_resume(evidence, allow_missing=False)
                self.store.advance(record['instance_id'], operation_id, 'removing')
                phase = 'removing'
            if phase == 'removing':
                names = self._verify_resume(evidence, allow_missing=True)
                if path.exists():
                    parent = os.open(
                        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        fd = os.open(
                            path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
                        try:
                            for name in sorted(names):
                                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                                expected = evidence['files'][name]
                                if {'device': info.st_dev, 'inode': info.st_ino,
                                    'size': info.st_size,
                                    'blocks': info.st_blocks * 512} != expected:
                                    fail('STAGING_OWNERSHIP_MISMATCH',
                                         'File was replaced immediately before unlink.')
                                os.unlink(name, dir_fd=fd)
                                os.fsync(fd)
                        finally:
                            os.close(fd)
                        os.rmdir(path.name, dir_fd=parent)
                        os.fsync(parent)
                    finally:
                        os.close(parent)
                self.store.advance(record['instance_id'], operation_id, 'removed')
                phase = 'removed'
            if phase == 'removed':
                if os.path.lexists(path):
                    fail('CLEANUP_STATE_CONFLICT',
                         'Staging path still exists after removal.', 4)
                self.store.complete_staging_cleanup(record['instance_id'], operation_id)
            final = self.store.inspect(record['instance_id'])
            return self._result(final, final['journal'][-1], evidence, idempotent=False)

    @staticmethod
    def _result(record, operation, evidence, *, idempotent):
        return {
            'name': record['name'], 'instance_id': record['instance_id'],
            'domain_uuid': record['domain_uuid'],
            'staging_kind': evidence['staging_kind'],
            'source_operation': evidence['source_operation'],
            'cleanup_operation': operation['id'], 'removed': True,
            'removed_files': sorted(evidence['files']),
            'released_resources': deepcopy(evidence['reservation_requested']),
            'idempotent': idempotent,
        }
