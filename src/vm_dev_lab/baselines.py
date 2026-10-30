# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Create and verify immutable offline VM baseline bundles.

"""P08-A: Immutable, complete offline baseline bundles."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import xml.etree.ElementTree as ET
from uuid import UUID, uuid4

from .errors import LabError
from .lifecycle import (FIRMWARE_CODE, FIRMWARE_HASHES, RealOwnership,
                        firmware_binding, load_host_record)
from .provisioning.arch import VERSION, validate_guest_manifest
from .resources import allocated_bytes, request as resource_request
from .state import directory


SCHEMA_VERSION = 1
PAYLOADS = ('disk.qcow2', 'nvram.fd', 'domain.xml', 'instance.json',
            'guest-manifest.json')
ALL_FILES = frozenset((*PAYLOADS, 'manifest.json'))
READINESS = frozenset({'clean', 'ssh-ready', 'project-ready'})
NAME = re.compile(r'[a-z][a-z0-9-]{0,62}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
MAX_JSON = 1024 * 1024
SPACE_RESERVE = 64 * 1024 * 1024


def fail(code, phase, message, status=6, hint=None, retryable=False):
    raise LabError(status, code, phase, message, hint or
                   'Inspect baseline, ownership, and staging state; do not delete anything automatically.',
                   retryable)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def sha256(path, *, deadline=None, clock=None):
    digest = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                fail('BASELINE_PATH_UNSAFE', 'verification',
                     'Bundle component is not an unambiguous regular file.', 5)
            while chunk := stream.read(1024 * 1024):
                if deadline is not None and clock is not None and clock() >= deadline:
                    fail('DEADLINE_EXCEEDED', 'verification',
                         'Deadline exceeded during integrity validation.', 7,
                         retryable=True)
                digest.update(chunk)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOENT, errno.ENOTDIR}:
            fail('BASELINE_INCOMPLETE', 'verification',
                 'Bundle component is missing or is an unsafe path.', 5)
        fail('BASELINE_IO', 'verification', 'Bundle component could not be read.')
    return digest.hexdigest()


def _write_new(path, data, mode=0o600):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        if error.errno == errno.ENOSPC:
            fail('BASELINE_NO_SPACE', 'staging', 'Storage space was exhausted during staging.', 6)
        if error.errno == errno.EEXIST:
            fail('BASELINE_CONFLICT', 'staging', 'Staging target already exists.', 4)
        raise


def _read_json(path, limit=MAX_JSON):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value
    def reject_constant(_value):
        raise ValueError
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            raw = stream.read(limit + 1)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or len(raw) > limit):
            raise ValueError
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        fail('BASELINE_MANIFEST_INVALID', 'verification',
             'Manifest is missing, corrupted, or exceeds the limit.', 5)


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


@contextmanager
def _safe_directory(path, *, create=False):
    """Open owned baseline paths without symlinks, privately or traversal-only."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        fail('BASELINE_PATH_UNSAFE', 'verification',
             'Baseline directory is not bound absolutely.', 5)
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=current)
            os.close(current); current = child
        info = os.fstat(current)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in {0o700, 0o710}:
            fail('BASELINE_PATH_UNSAFE', 'verification',
                 'Baseline directory is neither private nor traversable in a controlled manner.', 5)
        yield current
    except LabError:
        raise
    except OSError:
        fail('BASELINE_PATH_UNSAFE', 'verification',
             'Baseline directory is missing, replaced, or not safely accessible.', 5)
    finally:
        os.close(current)


def _copy_file(source, target, deadline, clock):
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(source_fd, 'rb') as src, os.fdopen(target_fd, 'wb') as dst:
            info = os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail('BASELINE_PATH_UNSAFE', 'staging', 'Source component is ambiguous.', 5)
            while chunk := src.read(1024 * 1024):
                if clock() >= deadline:
                    fail('DEADLINE_EXCEEDED', 'staging', 'Deadline exceeded during staging.', 7, retryable=True)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
    except OSError as error:
        if error.errno == errno.ENOSPC:
            fail('BASELINE_NO_SPACE', 'staging', 'Storage space was exhausted during staging.', 6)
        raise


def _readiness(record, guest, label):
    if label not in READINESS:
        fail('BASELINE_READINESS_INVALID', 'readiness',
             'Readiness must be clean, ssh-ready, or project-ready.', 2)
    last = record['journal'][-1]
    no_start = (last['kind'] == 'create' and last['status'] == 'complete'
                and last['events'] == ['planned', 'allocating', 'defined'])
    graceful = (last['kind'] == 'shutdown' and last['status'] == 'complete'
                and last['events'] == ['planned', 'defined'])
    if label == 'clean':
        valid = (no_start and guest['cloud_init'] == 'pending'
                 and not guest['ssh_ready'] and not guest['project_ready']
                 and guest['provisioning']['status'] == 'provisioning')
    elif label == 'ssh-ready':
        provision = guest['provisioning']
        valid = (graceful and guest['cloud_init'] == 'completed'
                 and guest['ssh_ready'] and not guest['project_ready']
                 and provision['status'] == 'provisioning'
                 and provision['user']['valid']
                 and provision['ssh']['public_key_login'] is True
                 and provision['ssh']['password_authentication'] is False)
    else:
        provision = guest['provisioning']
        valid = (graceful and guest['cloud_init'] == 'completed'
                 and guest['ssh_ready'] and guest['project_ready']
                 and provision['status'] == 'project-ready'
                 and provision['error'] is None
                 and provision['transaction']['exit_code'] in {0, None}
                 and set(provision['installed_packages'])
                     == set(provision['requested_packages']))
    if not valid:
        fail('BASELINE_READINESS_UNPROVEN', 'readiness',
             'Name or label does not prove the requested guest state.', 4,
             'Inspect the guest manifest and last graceful shutdown; a hard stop is not a clean source.')
    return {'label': label, 'evidence': {
        'last_operation_id': last['id'], 'last_operation_kind': last['kind'],
        'last_operation_events': deepcopy(last['events']),
        'cloud_init': guest['cloud_init'], 'ssh_ready': guest['ssh_ready'],
        'project_ready': guest['project_ready'],
        'provisioning_status': guest['provisioning']['status'],
    }}


def _parse_qemu_info(raw, *, standalone=False):
    try:
        value = json.loads(raw)
        if isinstance(value, list):
            if not value:
                raise ValueError
            value = value[0]
        if (not isinstance(value, dict) or value.get('format') != 'qcow2'
                or type(value.get('virtual-size')) is not int
                or value['virtual-size'] <= 0):
            raise ValueError
        if standalone and any(key in value for key in ('backing-filename', 'full-backing-filename')):
            fail('BASELINE_DISK_DEPENDENT', 'verification',
                 'Baseline disk still has a backing dependency.', 5)
        return value
    except (ValueError, TypeError, json.JSONDecodeError):
        fail('BASELINE_DISK_INVALID', 'verification',
             'qemu-img did not provide valid qcow2 evidence.', 6)


def _domain_storage_valid(root, storage, work_path=None, nvram_path=None):
    work_path = work_path or storage / 'work.qcow2'
    nvram_path = nvram_path or storage / 'nvram.fd'
    disks = root.findall('./devices/disk')
    if len(disks) != 2:
        return False
    by_source = {}
    for disk in disks:
        source = disk.find('source')
        if source is None or set(source.attrib) != {'file'}:
            return False
        by_source[source.get('file')] = disk
    work = by_source.get(str(work_path))
    seed = by_source.get(str(storage / 'seed.iso'))
    return (set(by_source) == {str(work_path), str(storage / 'seed.iso')}
            and work is not None and work.get('device') == 'disk'
            and work.find('readonly') is None
            and work.find('driver') is not None
            and work.find('driver').get('type') == 'qcow2'
            and seed is not None and seed.get('device') == 'cdrom'
            and seed.find('readonly') is not None
            and root.findtext('./os/nvram') == str(nvram_path)
            and root.find('./devices/tpm') is None
            and root.find('./devices/filesystem') is None
            and root.find('./devices/hostdev') is None)


def _bundle_readiness_valid(label, evidence, guest):
    provision = guest['provisioning']
    if label == 'clean':
        return (evidence['last_operation_kind'] == 'create'
                and evidence['last_operation_events'] == ['planned','allocating','defined']
                and guest['cloud_init'] == 'pending' and not guest['ssh_ready']
                and not guest['project_ready'] and provision['status'] == 'provisioning')
    graceful = (evidence['last_operation_kind'] == 'shutdown'
                and evidence['last_operation_events'] == ['planned','defined'])
    if label == 'ssh-ready':
        return (graceful and guest['cloud_init'] == 'completed' and guest['ssh_ready']
                and not guest['project_ready'] and provision['status'] == 'provisioning'
                and provision['user']['valid']
                and provision['ssh']['public_key_login'] is True
                and provision['ssh']['password_authentication'] is False)
    return (graceful and guest['cloud_init'] == 'completed' and guest['ssh_ready']
            and guest['project_ready'] and provision['status'] == 'project-ready'
            and provision['error'] is None and provision['transaction']['exit_code'] in {0, None}
            and set(provision['installed_packages']) == set(provision['requested_packages']))


class BaselineIndex:
    """Separate atomic name-to-ID index; lifecycle registry remains unchanged."""

    def __init__(self, store):
        self.store = store
        self.path = store.paths.state / 'baselines.json'

    def _empty(self):
        return {'schema_version': 1, 'lab_id': self.store._read()['lab_id'], 'instances': {}}

    def _validate(self, value):
        if (not isinstance(value, dict) or set(value) != {'schema_version', 'lab_id', 'instances'}
                or value['schema_version'] != 1 or not _uuid(value['lab_id'])
                or not isinstance(value['instances'], dict)):
            fail('BASELINE_INDEX_INVALID', 'index', 'Baseline index is invalid.', 5)
        current = self.store._read()
        if value['lab_id'] != current['lab_id']:
            fail('BASELINE_INDEX_INVALID', 'index', 'Baseline index belongs to a different lab.', 5)
        for instance, entries in value['instances'].items():
            if not _uuid(instance) or not isinstance(entries, dict):
                fail('BASELINE_INDEX_INVALID', 'index', 'Baseline index contains invalid identities.', 5)
            for name, baseline_id in entries.items():
                if (not isinstance(name, str) or not NAME.fullmatch(name)
                        or not isinstance(baseline_id, str) or not SHA256.fullmatch(baseline_id)):
                    fail('BASELINE_INDEX_INVALID', 'index', 'Baseline index contains invalid pointers.', 5)
        return value

    def read(self):
        try:
            if not os.path.lexists(self.path):
                return self._empty()
            return self._validate(_read_json(self.path))
        except LabError:
            raise

    def publish(self, instance_id, name, baseline_id):
        with self.store.lock('global'):
            value = self.read()
            entries = value['instances'].setdefault(instance_id, {})
            if name in entries:
                fail('BASELINE_NAME_EXISTS', 'publication',
                     'Baseline name is already assigned immutably.', 4)
            if baseline_id in entries.values():
                fail('BASELINE_ID_EXISTS', 'publication', 'Baseline ID is already published.', 4)
            entries[name] = baseline_id
            raw = canonical(value)
            with _safe_directory(self.store.paths.state) as parent:
                try:
                    stage = '.baselines-' + str(uuid4()) + '.tmp'
                    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                    os.replace(stage, 'baselines.json', src_dir_fd=parent, dst_dir_fd=parent)
                    os.fsync(parent)
                except OSError as error:
                    if error.errno == errno.ENOSPC:
                        fail('BASELINE_NO_SPACE', 'publication',
                             'Storage space exhausted during index publication.', 6)
                    fail('BASELINE_INDEX_IO', 'publication',
                         'Baseline index could not be published atomically.', 6)


class BaselineManager:
    """Create and verify P08-A bundles without restore or libvirt mutation."""

    def __init__(self, lifecycle, *, clock, tool, now=None, disk_usage=shutil.disk_usage):
        self.lifecycle = lifecycle
        self.store = lifecycle.store
        self.backend = lifecycle.backend
        self.clock = clock
        self.tool = tool
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.disk_usage = disk_usage
        self.index = BaselineIndex(self.store)
        self.resources = lifecycle.resources

    def _roots(self, data):
        root = Path(data['storage']).parent
        return root / '.baseline-staging', root / 'baselines', root / 'baselines' / data['instance_id']

    def _published_root(self, record):
        """Published bundles outlive the instance runtime they were created from."""
        if record['state'] != 'destroyed':
            data = RealOwnership(self.store, self.backend).files(record)
            return self._roots(data)[2]
        plan = deepcopy(self.lifecycle.host_record) if self.lifecycle.host_record is not None else load_host_record()
        try:
            storage = Path(plan['storage'])
            info = os.lstat(storage)
            if (not storage.is_absolute() or '..' in storage.parts
                    or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid()):
                raise ValueError
        except (KeyError, OSError, TypeError, ValueError):
            fail('BASELINE_STORAGE_UNAVAILABLE', 'verification',
                 'Qualified baseline storage is not bound safely after VM cleanup.', 5)
        return storage / 'baselines' / record['instance_id']

    def _ensure_roots(self, data):
        staging, published, instance = self._roots(data)
        for path in (staging, published, instance):
            with _safe_directory(path, create=True):
                pass
        return staging, published, instance

    def _tool(self, args, deadline, phase='staging'):
        if deadline is not None and self.clock() >= deadline:
            fail('DEADLINE_EXCEEDED', phase, 'Overall deadline exceeded.', 7, retryable=True)
        result = self.tool(args, deadline if deadline is not None else self.clock() + 600)
        if result.returncode:
            fail('BASELINE_DISK_TOOL_FAILED', phase,
                 'qemu-img could not create or verify the baseline disk.', 6)
        return result.stdout

    def _manifest(self, *, data, guest, name, readiness,
                  files, firmware, disk_info):
        value = {
            'schema_version': SCHEMA_VERSION,
            'baseline_id': None,
            'generation': str(uuid4()),
            'created_at': self.now().isoformat().replace('+00:00', 'Z'),
            'name': name,
            'readiness': readiness,
            'instance': {key: data[key] for key in
                         ('lab_id', 'instance_id', 'domain_uuid', 'name', 'uri', 'mac')},
            'guest_identity': {'seed_instance_id': data['seed']['seed_instance_id']},
            'firmware': firmware,
            'disk': {'format': 'qcow2', 'standalone': True,
                     'virtual_size': disk_info['virtual-size']},
            'files': files,
            'source': {'image_sha256': data['image_sha256'],
                       'arch_cloud_image_mutable': True,
                       'package_versions_frozen_by_bundle':
                           deepcopy(guest['provisioning']['installed_packages'])},
        }
        baseline_id = hashlib.sha256(canonical(value)).hexdigest()
        value['baseline_id'] = baseline_id
        return value

    def create(self, target, name, readiness_label, deadline):
        if not isinstance(name, str) or not NAME.fullmatch(name):
            fail('BASELINE_NAME_INVALID', 'validation', 'Invalid baseline name.', 2)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record = self.store.inspect(initial['instance_id'])
            if record['requires_review']:
                fail('REVIEW_REQUIRED', 'state', 'Incomplete lifecycle operation blocks the baseline.', 4)
            domain = self.backend.domain(record['domain_uuid'])
            owner = RealOwnership(self.store, self.backend)
            data = owner.verify(record, domain)
            guest = owner.guest_manifest(record)
            if domain.isActive():
                fail('DOMAIN_RUNNING', 'preflight', 'Baseline source must be powered off.', 4)
            managed = getattr(domain, 'hasManagedSaveImage', None)
            if managed is None or managed(0):
                fail('MANAGED_SAVE_UNSUPPORTED', 'preflight',
                     'Managed-save evidence is missing or a managed save exists.', 4)
            readiness = _readiness(record, guest, readiness_label)
            root = ET.fromstring(domain.XMLDesc(0))
            active = data.get('restore_generation')
            source_disk = (Path(active['path'])/'disk.qcow2' if active
                           else Path(data['storage'])/'work.qcow2')
            source_nvram = (Path(active['path'])/'nvram.fd' if active
                            else Path(data['storage'])/'nvram.fd')
            if not _domain_storage_valid(root, Path(data['storage']), source_disk, source_nvram):
                fail('PERSISTENT_DEVICE_UNSUPPORTED', 'preflight',
                     'Disk model, TPM, or other persistent state is not captured completely.', 4)
            plan = (deepcopy(self.lifecycle.host_record)
                    if self.lifecycle.host_record is not None else load_host_record())
            firmware = (firmware_binding(plan) if plan.get('firmware') else
                        {'code': FIRMWARE_CODE,
                         'code_sha256': FIRMWARE_HASHES['code']})
            loader = root.findtext('./os/loader')
            if loader != str(firmware['code']) or not firmware['code'].is_file():
                fail('FIRMWARE_CHANGED', 'preflight', 'Firmware path is not qualified.', 3)
            firmware_hash = sha256(firmware['code'], deadline=deadline, clock=self.clock)
            if firmware_hash != firmware['code_sha256']:
                fail('FIRMWARE_CHANGED', 'preflight', 'Firmware content differs from the qualified state.', 3)
            index = self.index.read()
            if name in index['instances'].get(record['instance_id'], {}):
                fail('BASELINE_NAME_EXISTS', 'publication',
                     'Baseline name is already assigned immutably.', 4)
            staging_root, _, published_root = self._roots(data)
            source_disk_hash = sha256(source_disk, deadline=deadline, clock=self.clock)
            source_nvram_hash = sha256(source_nvram, deadline=deadline, clock=self.clock)
            source_info = _parse_qemu_info(self._tool(
                ['qemu-img', 'info', '--output=json', '--backing-chain', str(source_disk)], deadline))
            needed = source_info['virtual-size'] + source_nvram.stat().st_size + SPACE_RESERVE
            resource_operation = str(uuid4())
            free_bytes = self.disk_usage(Path(data['storage']).parent).free
            if free_bytes < needed + plan['reserve_gib'] * 1024 ** 3:
                fail('BASELINE_NO_SPACE', 'preflight',
                     'Free space is insufficient for the bundle and host reserve.', 6)
            self.resources.reserve(
                record['instance_id'], resource_operation, 'snapshot',
                resource_request(virtual_disk_bytes=source_info['virtual-size'],
                                 staging_bytes=needed),
                host_storage_bytes=max(
                    0, free_bytes - plan['reserve_gib'] * 1024 ** 3))
            staging_root, _, published_root = self._ensure_roots(data)
            if self.disk_usage(staging_root).free < needed:
                fail('BASELINE_NO_SPACE', 'preflight',
                     'Free space is insufficient for the virtual disk, NVRAM, and reserve.', 6)
            # P09-C binds a failed remainder exactly to the same
            # Operation UUID like the resource reservation.
            stage_name = '.stage-' + resource_operation
            with _safe_directory(staging_root) as parent:
                os.mkdir(stage_name, 0o700, dir_fd=parent)
                os.fsync(parent)
            stage = staging_root / stage_name
            try:
                self._tool(['qemu-img', 'convert', '-O', 'qcow2', str(source_disk),
                            str(stage / 'disk.qcow2')], deadline)
                _copy_file(source_nvram, stage / 'nvram.fd', deadline, self.clock)
                domain_raw = domain.XMLDesc(0).encode()
                private = self.store.paths.data / 'instances' / record['instance_id']
                _write_new(stage / 'domain.xml', domain_raw)
                _copy_file(private / 'instance.json', stage / 'instance.json', deadline, self.clock)
                _copy_file(private / 'guest-manifest.json', stage / 'guest-manifest.json', deadline, self.clock)
                if domain.isActive():
                    fail('DOMAIN_STARTED_DURING_BASELINE', 'staging',
                         'Domain was started during baseline creation.', 4)
                owner.verify(self.store.inspect(record['instance_id']), domain)
                if (sha256(source_disk, deadline=deadline, clock=self.clock) != source_disk_hash
                        or sha256(source_nvram, deadline=deadline, clock=self.clock) != source_nvram_hash):
                    fail('SOURCE_CHANGED', 'staging', 'Disk or NVRAM changed during staging.', 4)
                disk_info = _parse_qemu_info(self._tool(
                    ['qemu-img', 'info', '--output=json', str(stage / 'disk.qcow2')], deadline),
                    standalone=True)
                files = {item: {'sha256': sha256(stage / item, deadline=deadline, clock=self.clock),
                                'size': os.lstat(stage / item).st_size}
                         for item in PAYLOADS}
                manifest = self._manifest(
                    data=data, guest=guest,
                    name=name, readiness=readiness, files=files,
                    firmware={'code_path': loader, 'code_sha256': firmware_hash,
                              'nvram_model': 'per-instance-copy'}, disk_info=disk_info)
                _write_new(stage / 'manifest.json', canonical(manifest))
                with _safe_directory(stage) as stage_fd:
                    os.fsync(stage_fd)
                verified = self.verify_path(stage, expected_instance=record['instance_id'], indexed=False,
                                            deadline=deadline)
                if domain.isActive():
                    fail('DOMAIN_STARTED_DURING_BASELINE', 'publication',
                         'Domain was started before atomic publication.', 4)
                owner.verify(self.store.inspect(record['instance_id']), domain)
                if (sha256(source_disk, deadline=deadline, clock=self.clock) != source_disk_hash
                        or sha256(source_nvram, deadline=deadline, clock=self.clock) != source_nvram_hash):
                    fail('SOURCE_CHANGED', 'publication',
                         'Disk or NVRAM changed before publication.', 4)
                baseline_id = manifest['baseline_id']
                destination = published_root / baseline_id
                with _safe_directory(staging_root) as staging_parent, \
                        _safe_directory(published_root) as published_parent:
                    try:
                        os.stat(baseline_id, dir_fd=published_parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        fail('BASELINE_ID_EXISTS', 'publication', 'Baseline ID already exists.', 4)
                    try:
                        os.rename(stage_name, baseline_id, src_dir_fd=staging_parent,
                                  dst_dir_fd=published_parent)
                        os.fsync(staging_parent)
                        os.fsync(published_parent)
                    except OSError as error:
                        if error.errno == errno.ENOSPC:
                            fail('BASELINE_NO_SPACE', 'publication',
                                 'Storage space exhausted during bundle publication.', 6)
                        fail('BASELINE_PUBLICATION_IO', 'publication',
                             'Bundle could not be published atomically.', 6)
                self.index.publish(record['instance_id'], name, baseline_id)
                self.resources.bind(
                    record['instance_id'], resource_operation,
                    resource_request(
                        virtual_disk_bytes=manifest['disk']['virtual_size'],
                        storage_bytes=allocated_bytes(destination), operations=0))
                verified['path'] = str(destination)
                verified['vm_name'] = record['name']
                return verified
            except OSError as error:
                try: self.resources.review(record['instance_id'], resource_operation)
                except Exception: pass
                if error.errno == errno.ENOSPC:
                    fail('BASELINE_NO_SPACE', 'staging', 'Storage space exhausted during staging.', 6)
                raise
            except BaseException:
                try: self.resources.review(record['instance_id'], resource_operation)
                except Exception: pass
                raise

    def _validate_manifest(self, value, path, *, require_id_path=True):
        expected = {'schema_version', 'baseline_id', 'generation', 'created_at', 'name',
                    'readiness', 'instance', 'guest_identity', 'firmware', 'disk', 'files', 'source'}
        if not isinstance(value, dict) or set(value) != expected or value['schema_version'] != 1:
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Unknown or incomplete manifest.', 5)
        candidate = deepcopy(value); claimed = candidate['baseline_id']; candidate['baseline_id'] = None
        try:
            timestamp = datetime.fromisoformat(value['created_at'].replace('Z', '+00:00'))
        except (ValueError, TypeError, AttributeError):
            timestamp = None
        if (not isinstance(claimed, str) or not SHA256.fullmatch(claimed)
                or hashlib.sha256(canonical(candidate)).hexdigest() != claimed
                or (require_id_path and path.name != claimed) or not _uuid(value['generation'])
                or not NAME.fullmatch(value['name'] or '') or timestamp is None
                or not isinstance(value['created_at'], str)
                or not re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[^Z]+Z', value['created_at'])
                or timestamp.tzinfo is None):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Manifest ID or identity is invalid.', 5)
        if (not isinstance(value['readiness'], dict)
                or set(value['readiness']) != {'label', 'evidence'}
                or not isinstance(value['readiness']['label'], str)
                or value['readiness']['label'] not in READINESS):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Readiness evidence is invalid.', 5)
        evidence = value['readiness']['evidence']
        if (not isinstance(evidence, dict) or set(evidence) != {
                'last_operation_id','last_operation_kind','last_operation_events',
                'cloud_init','ssh_ready','project_ready','provisioning_status'}
                or not _uuid(evidence['last_operation_id'])
                or not isinstance(evidence['last_operation_kind'], str)
                or evidence['last_operation_kind'] not in {'create','shutdown'}
                or not isinstance(evidence['last_operation_events'], list)
                or not isinstance(evidence['cloud_init'], str)
                or evidence['cloud_init'] not in {'pending','completed','failed'}
                or type(evidence['ssh_ready']) is not bool
                or type(evidence['project_ready']) is not bool
                or not isinstance(evidence['provisioning_status'], str)
                or evidence['provisioning_status'] not in {'provisioning','project-ready','failed'}):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Readiness evidence is incomplete.', 5)
        instance = value['instance']
        if (not isinstance(instance, dict)
                or set(instance) != {'lab_id','instance_id','domain_uuid','name','uri','mac'}
                or not all(_uuid(instance[key]) for key in ('lab_id','instance_id','domain_uuid'))
                or not isinstance(instance['name'], str) or not NAME.fullmatch(instance['name'])
                or instance['uri'] != 'qemu:///system' or not isinstance(instance['mac'], str)
                or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', instance['mac'])):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Instance identity is invalid.', 5)
        if (not isinstance(value['guest_identity'], dict)
                or set(value['guest_identity']) != {'seed_instance_id'}
                or not _uuid(value['guest_identity']['seed_instance_id'])):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Guest identity is invalid.', 5)
        firmware = value['firmware']
        if (not isinstance(firmware, dict)
                or set(firmware) != {'code_path','code_sha256','nvram_model'}
                or not isinstance(firmware['code_path'], str)
                or not Path(firmware['code_path']).is_absolute()
                or '..' in Path(firmware['code_path']).parts
                or not isinstance(firmware['code_sha256'], str)
                or not SHA256.fullmatch(firmware['code_sha256'])
                or firmware['nvram_model'] != 'per-instance-copy'):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Firmware binding is invalid.', 5)
        disk = value['disk']
        if (not isinstance(disk, dict)
                or set(disk) != {'format','standalone','virtual_size'} or disk['format'] != 'qcow2'
                or disk['standalone'] is not True or type(disk['virtual_size']) is not int
                or disk['virtual_size'] <= 0):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Disk evidence is invalid.', 5)
        if not isinstance(value['files'], dict) or set(value['files']) != set(PAYLOADS):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'File list is incomplete.', 5)
        for name, item in value['files'].items():
            if (name != Path(name).name or not isinstance(item, dict)
                    or set(item) != {'sha256','size'} or not isinstance(item['sha256'], str)
                    or not SHA256.fullmatch(item['sha256'])
                    or type(item['size']) is not int or item['size'] < 0):
                fail('BASELINE_MANIFEST_INVALID', 'verification', 'File entry is invalid.', 5)
        size_limits = {'nvram.fd': 64 * 1024 * 1024, 'domain.xml': 1024 * 1024,
                       'instance.json': 65536, 'guest-manifest.json': 65536}
        if (value['files']['disk.qcow2']['size'] <= 0
                or any(not 0 < value['files'][name]['size'] <= limit
                       for name, limit in size_limits.items())):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'File sizes violate the bundle contract.', 5)
        source = value['source']
        if (not isinstance(source, dict)
                or set(source) != {'image_sha256','arch_cloud_image_mutable','package_versions_frozen_by_bundle'}
                or not isinstance(source['image_sha256'], str)
                or not SHA256.fullmatch(source['image_sha256'])
                or source['arch_cloud_image_mutable'] is not True
                or not isinstance(source['package_versions_frozen_by_bundle'], dict)
                or any(not isinstance(name, str) or not isinstance(version, str)
                       or not VERSION.fullmatch(version)
                       for name, version in source['package_versions_frozen_by_bundle'].items())):
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Source evidence is invalid.', 5)
        return value

    def verify_path(self, path, *, expected_instance=None, indexed=False, deadline=None):
        path = Path(path)
        with _safe_directory(path) as parent:
            names = set(os.listdir(parent))
            if names != ALL_FILES:
                fail('BASELINE_INCOMPLETE', 'verification',
                     'Bundle contains missing or foreign files.', 5)
        manifest = self._validate_manifest(_read_json(path / 'manifest.json'), path,
                                           require_id_path=indexed)
        if expected_instance and manifest['instance']['instance_id'] != expected_instance:
            fail('BASELINE_IDENTITY_MISMATCH', 'verification', 'Bundle belongs to a different instance.', 5)
        try:
            for name, item in manifest['files'].items():
                info = os.lstat(path / name)
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_nlink != 1 or info.st_size != item['size']
                        or sha256(path / name, deadline=deadline, clock=self.clock) != item['sha256']):
                    fail('BASELINE_HASH_MISMATCH', 'verification',
                         'Bundle component is missing or does not match its SHA256.', 5)
        except OSError:
            fail('BASELINE_INCOMPLETE', 'verification', 'Bundle component is missing during validation.', 5)
        disk_info = _parse_qemu_info(self._tool(
            ['qemu-img','info','--output=json',str(path/'disk.qcow2')], deadline,
            phase='verification'), standalone=True)
        if disk_info['virtual-size'] != manifest['disk']['virtual_size']:
            fail('BASELINE_DISK_INVALID', 'verification', 'Virtual disk size differs from the manifest.', 5)
        try:
            instance = _read_json(path / 'instance.json')
            guest = _read_json(path / 'guest-manifest.json')
            xml_raw = (path / 'domain.xml').read_bytes()
            if b'<!DOCTYPE' in xml_raw.upper() or b'<!ENTITY' in xml_raw.upper():
                raise ET.ParseError
            root = ET.fromstring(xml_raw)
        except ET.ParseError:
            fail('BASELINE_MANIFEST_INVALID', 'verification', 'Domain XML is corrupted.', 5)
        identity = manifest['instance']
        try:
            validate_guest_manifest(guest['provisioning'], instance['requested_packages'],
                                    instance['ssh_user'])
        except (KeyError, TypeError, AttributeError):
            fail('BASELINE_IDENTITY_MISMATCH', 'verification', 'Guest manifest is invalid.', 5)
        evidence = manifest['readiness']['evidence']
        if (evidence['cloud_init'] != guest.get('cloud_init')
                or evidence['ssh_ready'] != guest.get('ssh_ready')
                or evidence['project_ready'] != guest.get('project_ready')
                or evidence['provisioning_status'] != guest['provisioning']['status']):
            fail('BASELINE_IDENTITY_MISMATCH', 'verification',
                 'Readiness evidence and guest manifest conflict.', 5)
        if (not _bundle_readiness_valid(manifest['readiness']['label'], evidence, guest)
                or manifest['source']['package_versions_frozen_by_bundle']
                    != guest['provisioning']['installed_packages']):
            fail('BASELINE_IDENTITY_MISMATCH', 'verification',
                 'Readiness or package evidence is semantically invalid.', 5)
        storage = Path(instance.get('storage', '.'))
        if (any(instance.get(key) != identity[key]
                for key in ('lab_id','instance_id','domain_uuid','name','uri','mac'))
                or instance.get('seed', {}).get('seed_instance_id')
                    != manifest['guest_identity']['seed_instance_id']
                or root.findtext('uuid') != identity['domain_uuid']
                or root.findtext('name') != identity['name']
                or root.find('./devices/interface/mac') is None
                or root.find('./devices/interface/mac').get('address') != identity['mac']
                or root.findtext('./os/loader') != manifest['firmware']['code_path']
                or not _domain_storage_valid(root, storage)
                or not isinstance(guest, dict)):
            fail('BASELINE_IDENTITY_MISMATCH', 'verification',
                 'Domain, instance, guest, or firmware is not bound consistently.', 5)
        return {'baseline_id': manifest['baseline_id'], 'name': manifest['name'],
                'vm_name': identity['name'],
                'instance_id': identity['instance_id'],
                'domain_uuid': identity['domain_uuid'],
                'readiness': manifest['readiness'], 'verified': True,
                'path': str(path), 'manifest_schema_version': SCHEMA_VERSION}

    def verify(self, target, baseline_id, deadline=None):
        if not isinstance(baseline_id, str) or not SHA256.fullmatch(baseline_id):
            fail('BASELINE_ID_INVALID', 'validation', 'Baseline ID must have SHA256 format.', 2)
        self.store.ensure_runtime()
        record = self.store.inspect(target)
        index = self.index.read()
        entries = index['instances'].get(record['instance_id'], {})
        if baseline_id not in entries.values():
            fail('BASELINE_NOT_PUBLISHED', 'verification',
                 'Baseline ID is not published for this instance.', 4)
        path = self._published_root(record) / baseline_id
        result = self.verify_path(path, expected_instance=record['instance_id'], indexed=True,
                                  deadline=deadline)
        if entries.get(result['name']) != baseline_id:
            fail('BASELINE_INDEX_INVALID', 'verification', 'Name and ID conflict with the index.', 5)
        return result

    def list(self, target, deadline=None):
        self.store.ensure_runtime()
        record = self.store.inspect(target)
        index = self.index.read()
        entries = index['instances'].get(record['instance_id'], {})
        bundles = []
        root = self._published_root(record)
        for name, baseline_id in sorted(entries.items()):
            verified = self.verify_path(root / baseline_id,
                                        expected_instance=record['instance_id'], indexed=True,
                                        deadline=deadline)
            if verified['name'] != name:
                fail('BASELINE_INDEX_INVALID', 'verification',
                     'Name and ID conflict with the index.', 5)
            bundles.append({'name': name, 'baseline_id': baseline_id, 'verified': True,
                            'readiness': verified['readiness']['label']})
        return {'vm_name': record['name'], 'instance_id': record['instance_id'],
                'domain_uuid': record['domain_uuid'],
                'baselines': bundles}
