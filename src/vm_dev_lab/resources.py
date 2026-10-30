# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Enforce atomic CPU, memory, and storage resource accounting.

"""P09-B: durable resource ledger maintained atomically under the registry lock."""
from copy import deepcopy
import os
from pathlib import Path

from .state import RESOURCE_FIELDS, fail, uuid


MAX_RESOURCE_INTEGER = (1 << 63) - 1


def available_host_cpus():
    """Return logical CPUs available to the process without changing host state."""
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count()


def cpu_overcommit_limit(host_cpus):
    """Calculate the 2:1 vCPU limit with an explicit 64-bit overflow check."""
    if (type(host_cpus) is not int or host_cpus <= 0
            or host_cpus > MAX_RESOURCE_INTEGER // 2):
        fail('HOST_CPU_INVALID',
             'Available logical host CPUs are invalid or cannot be doubled safely.',
             3)
    return host_cpus * 2


def request(*, instances=0, vcpus=0, memory_mib=0, virtual_disk_bytes=0,
            storage_bytes=0, staging_bytes=0, operations=1):
    values = dict(instances=instances, vcpus=vcpus, memory_mib=memory_mib,
                  virtual_disk_bytes=virtual_disk_bytes,
                  storage_bytes=storage_bytes, staging_bytes=staging_bytes,
                  operations=operations)
    if (set(values) != RESOURCE_FIELDS
            or any(type(value) is not int or value < 0 for value in values.values())):
        fail('RESOURCE_REQUEST_INVALID', 'Resource request is invalid.', 2)
    return values


def allocated_bytes(path):
    """Count allocated bytes, not logical or sparse file size; reject symlinks."""
    total = 0
    candidates = [Path(path)]
    while candidates:
        current = candidates.pop()
        info = current.lstat()
        if current.is_symlink():
            fail('RESOURCE_EVIDENCE_INVALID', 'Symlink in Ressourcenbelegung.', 5)
        if current.is_dir():
            candidates.extend(current.iterdir())
        elif current.is_file():
            total += info.st_blocks * 512
        else:
            fail('RESOURCE_EVIDENCE_INVALID', 'Unknown artifact type.', 5)
    return total


class ResourceLedger:
    def __init__(self, store, *, host_cpu_provider=None):
        self.store = store
        self.host_cpu_provider = host_cpu_provider or available_host_cpus

    @staticmethod
    def _values(values):
        return request(**values)

    @staticmethod
    def _totals(resources):
        totals = request(operations=0)
        for reservation in resources['reservations'].values():
            if reservation['state'] == 'released':
                continue
            values = (reservation['committed'] if reservation['state'] == 'bound'
                      else reservation['requested'])
            for key in totals:
                totals[key] += values[key]
        return totals

    def _admit(self, resources, wanted, exclude=None, *, host_vcpu_limit=None):
        totals = self._totals(resources)
        old = resources['reservations'].get(exclude) if exclude else None
        if old and old['state'] != 'released':
            values = old['committed'] if old['state'] == 'bound' else old['requested']
            for key in totals:
                totals[key] -= values[key]
        combined = {key: totals[key] + wanted[key] for key in totals}
        limits = resources['limits']
        codes = {
            'instances': 'RESOURCE_INSTANCE_BUDGET',
            'vcpus': 'RESOURCE_VCPU_BUDGET',
            'memory_mib': 'RESOURCE_MEMORY_BUDGET',
            'virtual_disk_bytes': 'RESOURCE_VIRTUAL_DISK_BUDGET',
            'operations': 'RESOURCE_OPERATION_BUDGET',
        }
        for field, code in codes.items():
            limit = limits[field]
            if field == 'vcpus' and host_vcpu_limit is not None:
                limit = min(limit, host_vcpu_limit)
            if combined[field] > limit:
                fail(code, f'Aggregate lab budget for {field} is exhausted.', 3)
        if combined['storage_bytes'] + combined['staging_bytes'] > limits['storage_bytes']:
            fail('RESOURCE_STORAGE_BUDGET',
                 'Aggregate storage and staging budget is exhausted.', 3)

    @staticmethod
    def _resources(state):
        if state['schema_version'] != 2:
            fail('RESOURCE_MIGRATION_REQUIRED',
                 'Historical registry has no reliable resource bindings.', 4)
        return state['resources']

    def _reserve_in_state(self, state, instance_id, operation_id, kind, wanted,
                          *, host_storage_bytes=None, host_memory_mib=None):
        resources = self._resources(state)
        if instance_id not in state['instances']:
            fail('REGISTRY_CONFLICT', 'Resource instance is missing.', 4)
        existing = resources['reservations'].get(operation_id)
        if existing:
            if (existing['instance_id'] != instance_id or existing['kind'] != kind
                    or existing['requested'] != wanted):
                fail('RESOURCE_RESERVATION_CONFLICT',
                     'Operation UUID is already bound differently.', 4)
            return deepcopy(existing), False
        host_vcpu_limit = (cpu_overcommit_limit(self.host_cpu_provider())
                           if kind == 'create' else None)
        self._admit(resources, wanted, host_vcpu_limit=host_vcpu_limit)
        pending = [item['requested'] for item in resources['reservations'].values()
                   if item['state'] in {'active','review_required'}]
        if host_storage_bytes is not None:
            if (type(host_storage_bytes) is not int or host_storage_bytes < 0
                    or sum(item['staging_bytes'] for item in pending)
                       + wanted['staging_bytes'] > host_storage_bytes):
                fail('HOST_STORAGE_BUDGET',
                     'Free host storage, host reserve, and open staging commitments are insufficient.', 3)
        if host_memory_mib is not None:
            if (type(host_memory_mib) is not int or host_memory_mib < 0
                    or sum(item['memory_mib'] for item in pending)
                       + wanted['memory_mib'] > host_memory_mib):
                fail('HOST_MEMORY_BUDGET',
                     'Available host RAM and open Create commitments are insufficient.', 3)
        value = dict(operation_id=operation_id, instance_id=instance_id,
                     kind=kind, state='active', requested=wanted,
                     committed=request(operations=0))
        resources['reservations'][operation_id] = value
        return deepcopy(value), True

    def reserve_create(self, name, wanted, *, host_storage_bytes=None,
                       host_memory_mib=None):
        """Persist the planned Create and admission as one registry generation."""
        wanted = self._values(wanted)

        def prepare(state, record):
            operation_id = record['journal'][-1]['id']
            self._reserve_in_state(
                state, record['instance_id'], operation_id, 'create', wanted,
                host_storage_bytes=host_storage_bytes,
                host_memory_mib=host_memory_mib)

        return self.store.reserve(name, prepare=prepare)

    def reserve(self, instance_id, operation_id, kind, wanted, *,
                host_storage_bytes=None, host_memory_mib=None):
        uuid(instance_id); uuid(operation_id); wanted = self._values(wanted)
        if kind not in {'create','snapshot','restore'}:
            fail('RESOURCE_REQUEST_INVALID', 'Unbekannte Ressourcenoperation.', 2)
        with self.store.lock('global'):
            state = self.store._read()
            value, created = self._reserve_in_state(
                state, instance_id, operation_id, kind, wanted,
                host_storage_bytes=host_storage_bytes,
                host_memory_mib=host_memory_mib)
            if not created:
                return value
            self.store._write(state)
            return value

    def bind(self, instance_id, operation_id, committed):
        committed = self._values(committed)
        committed['operations'] = 0; committed['staging_bytes'] = 0
        with self.store.lock('global'):
            state = self.store._read(); resources = self._resources(state)
            value = resources['reservations'].get(operation_id)
            if value is None or value['instance_id'] != instance_id:
                fail('RESOURCE_RESERVATION_CONFLICT', 'Matching reservation is missing.', 4)
            if value['state'] == 'bound':
                if value['committed'] != committed:
                    fail('RESOURCE_RESERVATION_CONFLICT', 'Bound resources differ.', 4)
                return deepcopy(value)
            if value['state'] != 'active':
                fail('RESOURCE_RESERVATION_CONFLICT', 'Reservation cannot be transitioned.', 4)
            self._admit(resources, committed, exclude=operation_id)
            value['committed'] = committed; value['state'] = 'bound'
            self.store._write(state)
            return deepcopy(value)

    def review(self, instance_id, operation_id):
        with self.store.lock('global'):
            state = self.store._read(); resources = self._resources(state)
            value = resources['reservations'].get(operation_id)
            if value is None or value['instance_id'] != instance_id:
                fail('RESOURCE_RESERVATION_CONFLICT', 'Matching reservation is missing.', 4)
            if value['state'] in {'active','review_required'}:
                value['state'] = 'review_required'; self.store._write(state)
            return deepcopy(value)

    def inventory(self):
        with self.store.lock('global'):
            state = self.store._read()
            return deepcopy(self._resources(state))
