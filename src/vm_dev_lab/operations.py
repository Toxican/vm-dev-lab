# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Orchestrate isolated offline lifecycle tests with the fake backend.

"""P03 offline test orchestration; intentionally no real lifecycle backend."""
import os

from .fake_backend import FakeBackend
from .state import fail


class OfflineLab:
    """Explicit StateStore fixtures and FakeBackend only; no CLI entry point."""

    def __init__(self, store, backend):
        if type(backend) is not FakeBackend:
            fail('FAKE_REQUIRED', 'OfflineLab accepts only FakeBackend.', 3)
        if backend.uri != store.uri:
            fail('OWNERSHIP_MISMATCH', 'Store and backend URIs do not match.')
        self.store, self.backend = store, backend

    def _advance(self, record, op, phase, **kwargs):
        self.store.advance(record['instance_id'], op, phase, **kwargs)

    def _failure(self, record, op):
        # No cleanup after an error. Failed journal publication
        # must not hide the original error: pending also blocks.
        try:
            self._advance(record, op, 'failed', failed=True)
        except Exception:
            pass

    def _owned(self, target, op=None):
        record = self.store.inspect(target)
        domain = self.backend.inspect(record['domain_uuid'])
        self.store.verify(record, domain, op)
        return record, domain

    def create(self, resolved, name=None):
        if not resolved.complete:
            fail('CONFIG_INCOMPLETE', 'Fake run requires complete P01 configuration.', 3)
        record = self.store.reserve(name or resolved.config['vm']['name'])
        op = record['journal'][-1]['id']
        with self.store.lock(record['instance_id']):
            try:
                self._advance(record, op, 'allocating')
                self.store.allocate_fixtures(self.store.inspect(record['instance_id']), op)
                current = self.store.inspect(record['instance_id'])
                if self.backend.inspect(record['domain_uuid']) is not None:
                    fail('BACKEND_CONFLICT', 'Domain UUID already exists.', 4)
                self.backend.define(self.store.specification(current))
                _, domain = self._owned(record['instance_id'], op)
                if domain['running']:
                    fail('BACKEND_STATE', 'Defined fake domain is unexpectedly active.', 6)
                self._advance(record, op, 'defined')
                self._advance(record, op, 'booting')
                self._owned(record['instance_id'], op)
                self.backend.start(record['domain_uuid'])
                _, domain = self._owned(record['instance_id'], op)
                if not domain['running']:
                    fail('BACKEND_STATE', 'Fake start was not confirmed.', 6)
                self._advance(record, op, 'provisioning')
                # No SSH or cloud-init evidence: ready is simulated only.
                self._advance(record, op, 'ready', complete=True)
            except Exception:
                self._failure(record, op)
                raise
        return self.store.inspect(record['instance_id'])

    def shutdown(self, target):
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record, domain = self._owned(initial['instance_id'])
            if not domain['running']:
                return record
            op = self.store.begin(record, 'shutdown')
            try:
                self._owned(record['instance_id'], op)
                self.backend.shutdown(record['domain_uuid'])
                if self.backend.inspect(record['domain_uuid'])['running']:
                    fail('BACKEND_STATE', 'Fake shutdown was not confirmed.', 6)
                self._owned(record['instance_id'], op)
                self._advance(record, op, 'defined', complete=True)
            except Exception:
                self._failure(record, op)
                raise
        return self.store.inspect(record['instance_id'])

    def destroy(self, target):
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record, domain = self._owned(initial['instance_id'])
            if domain['running']:
                fail('STATE_CONFLICT', 'Shut down cleanly before fake destroy.', 4)
            op = self.store.begin(record, 'destroy')
            try:
                record, _ = self._owned(record['instance_id'], op)
                # Verify all files before the first mutation, not just names.
                with self.store.selection(record, op):
                    self.backend.undefine(record['domain_uuid'])
                if self.backend.inspect(record['domain_uuid']) is not None:
                    fail('BACKEND_STATE', 'Fake undefine was not confirmed.', 6)
                self._advance(record, op, 'undefined')
                record = self.store.inspect(record['instance_id'])
                with self.store.selection(record, op) as parent:
                    for item in record['manifest']:
                        # Private instance directories and cooperating locks;
                        # no recursive deletion or cleanup of remnants.
                        info = os.stat(item['path'], dir_fd=parent, follow_symlinks=False)
                        if (info.st_dev, info.st_ino) != (item['device'], item['inode']):
                            fail('OWNERSHIP_MISMATCH', 'File replaced before cleanup.')
                        os.unlink(item['path'], dir_fd=parent)
                    os.fsync(parent)
                self._advance(record, op, 'destroyed', complete=True)
            except Exception:
                self._failure(record, op)
                raise
        return self.store.inspect(record['instance_id'])
