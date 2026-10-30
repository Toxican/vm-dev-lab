# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Manage private registry state, locks, journals, and ownership data.

"""Private registry, locks, and ownership for local offline operations.

No initialization during import or construction; no host or libvirt calls.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid4

from .errors import LabError

MAX_STATE_BYTES = 1024 * 1024
STATES = {'planned', 'allocating', 'defined', 'booting', 'provisioning', 'ready', 'failed', 'destroyed'}
CLEANUP_SEQUENCE = ['planned', 'undefining', 'undefined', 'removing_runtime', 'runtime_removed',
                    'removing_client', 'client_removed', 'removing_private', 'private_removed',
                    'clearing_manifest', 'destroyed']
CLEANUP_PHASES = set(CLEANUP_SEQUENCE)
SHUTDOWN_PHASES = {'forcing'}
RESTORE_SEQUENCE = ['planned', 'binding_generation', 'generation_bound', 'redefining',
                    'redefined', 'updating_registry', 'activated']
RESTORE_PHASES = set(RESTORE_SEQUENCE)
RESTORE_RECOVERY_SEQUENCE = ['planned', 'resolving', 'resolved']
RESTORE_RECOVERY_PHASES = set(RESTORE_RECOVERY_SEQUENCE)
RESTORE_START_RECOVERY_SEQUENCE = ['planned', 'repairing_access', 'access_ready', 'resolved']
RESTORE_START_RECOVERY_PHASES = set(RESTORE_START_RECOVERY_SEQUENCE)
STAGING_CLEANUP_SEQUENCE = ['planned', 'removing', 'removed', 'complete']
STAGING_CLEANUP_PHASES = set(STAGING_CLEANUP_SEQUENCE)
EXEC_TERMINALS = {'completed', 'guest_failed', 'timed_out', 'transport_failed',
                  'protocol_failed'}
EXEC_PHASES = {'dispatched', *EXEC_TERMINALS}
TRANSFER_TERMINALS = {'completed', 'timed_out', 'transport_failed',
                      'integrity_failed', 'file_failed'}
TRANSFER_PHASES = {'dispatched', *TRANSFER_TERMINALS}
# Schema compatibility for previously persisted journals only. There is
# deliberately no remaining public or internal mutation path for this type.
LEGACY_DAC_MIGRATION_SEQUENCE = [
    'planned', 'awaiting_helper', 'owner_restored', 'normalizing_access',
    'access_ready', 'redefining', 'redefined', 'updating_registry', 'resolved',
]
LEGACY_DAC_MIGRATION_PHASES = set(LEGACY_DAC_MIGRATION_SEQUENCE)
MANIFEST_NAMES = {
    'disk.fixture', 'nvram.fixture',
    'domain.xml', 'instance.json', 'guest-manifest.json', 'user-data', 'meta-data', 'network-config', 'seed.iso',
}

RESOURCE_FIELDS = {
    'instances', 'vcpus', 'memory_mib', 'virtual_disk_bytes',
    'storage_bytes', 'staging_bytes', 'operations',
}
RESOURCE_STATES = {'active', 'bound', 'released', 'review_required'}
DEFAULT_RESOURCE_LIMITS = {
    'instances': 4,
    'vcpus': 8,
    'memory_mib': 16384,
    'virtual_disk_bytes': 240 * 1024 ** 3,
    'storage_bytes': 500 * 1024 ** 3,
    'operations': 2,
}


def fail(code, message, exit_code=5):
    raise LabError(exit_code, code, 'state', message,
                   'Inspect ownership, registry, and journal explicitly; do not clean up automatically.')


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value):
        fail('STATE_INVALID', 'Invalid instance name.', 2)


def uuid(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        fail('STATE_INVALID', 'Invalid UUID.')


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected.split()):
        fail('STATE_INVALID', 'Unknown or missing state fields.')


@dataclass(frozen=True)
class StatePaths:
    data: Path
    state: Path
    runtime: Path

    def __post_init__(self):
        paths = [Path(p) for p in (self.data, self.state, self.runtime)]
        if any(not p.is_absolute() or '..' in p.parts or '\0' in str(p) for p in paths):
            fail('PATH_INVALID', 'XDG paths must be absolute and normalized.', 3)
        if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(paths) for b in paths[i + 1:]):
            fail('PATH_INVALID', 'Data, state, and runtime roots must be separate.', 3)
        for name, path in zip(('data', 'state', 'runtime'), paths):
            object.__setattr__(self, name, path)

    @classmethod
    def from_environment(cls, environ=None):
        env = os.environ if environ is None else environ
        home = Path(env.get('HOME') or Path.home())
        runtime = env.get('XDG_RUNTIME_DIR')
        if not runtime:
            fail('RUNTIME_MISSING', 'XDG_RUNTIME_DIR is missing; no unsafe /tmp fallback.', 3)
        return cls(Path(env.get('XDG_DATA_HOME') or home / '.local/share') / 'vm-dev-lab',
                   Path(env.get('XDG_STATE_HOME') or home / '.local/state') / 'vm-dev-lab',
                   Path(runtime) / 'vm-dev-lab')


@contextmanager
def directory(path, create=False):
    """Resolve every path component fd-relatively without symlinks; keep the final root private."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            fail('PATH_UNSAFE', 'Application or instance directory is not private (0700, owned by the current user).')
        yield fd
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM, errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
            fail('PATH_UNSAFE', 'Directory is missing, unsafe, or inaccessible.')
        fail('STATE_IO', 'File-system operation failed; inspect the state before intervening again.', 6)
    finally:
        os.close(fd)


def private_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        fail('PATH_UNSAFE', 'File is not regular, private, or uniquely associated.')
    return info


class StateStore:
    def __init__(self, paths, uri='qemu:///system'):
        if uri not in {'qemu:///system', 'qemu:///session'}:
            fail('URI_UNSUPPORTED', 'Only explicit local libvirt URIs are supported.', 3)
        self.paths, self.uri = paths, uri

    def initialize(self):
        """Explicit creation of owned state directories; never chmod or repair."""
        for path in (self.paths.data, self.paths.state, self.paths.runtime):
            with directory(path, create=True):
                pass
        with directory(self.paths.data / 'instances', create=True):
            pass
        with self.lock('global'):
            with directory(self.paths.state) as fd:
                try:
                    os.stat('registry.json', dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    self._write(dict(schema_version=2, lab_id=str(uuid4()), instances={},
                                     resources={'schema_version': 1,
                                                'limits': deepcopy(DEFAULT_RESOURCE_LIMITS),
                                                'reservations': {}}))
                else:
                    self._read()  # Never overwrite an unknown version or a symlink.

    def ensure_runtime(self):
        """Ensure only the ephemeral private lock root, never persistent state."""
        parent = self.paths.runtime.parent
        name = self.paths.runtime.name
        if not name or name in {'.', '..'}:
            fail('PATH_INVALID', 'Invalid runtime lock root.', 3)
        with directory(parent) as parent_fd:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
        with directory(self.paths.runtime):
            pass

    @contextmanager
    def lock(self, name):
        if name != 'global':
            uuid(name)
        fd = None
        with directory(self.paths.runtime) as parent:
            try:
                fd = os.open(name + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
                private_file(fd)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    fail('LOCK_CONFLICT', 'Instance or global reservation is locked.', 4)
                yield
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EPERM, errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
                    fail('LOCK_UNSAFE', 'Lock file is missing or unsafe.')
                fail('STATE_IO', 'File-system operation failed; no automatic retry.', 6)
            finally:
                if fd is not None:
                    os.close(fd)  # Never unlink the lock file: no second lock inode.

    def _validate(self, state):
        if not isinstance(state, dict):
            fail('STATE_INVALID', 'Registry is not an object.')
        version = state.get('schema_version')
        keys(state, ('schema_version lab_id instances resources'
                     if version == 2 else 'schema_version lab_id instances'))
        if type(version) is not int or version not in {1, 2}:
            fail('STATE_VERSION_UNSUPPORTED', 'Unknown registry version; do not overwrite it.')
        uuid(state['lab_id'])
        if version == 2:
            self._validate_resources(state['resources'], state['instances'])
        if not isinstance(state['instances'], dict) or len(state['instances']) > 128:
            fail('STATE_INVALID', 'Invalid or oversized instance inventory.')
        names, domains = set(), set()
        for instance_id, record in state['instances'].items():
            keys(record, 'lab_id instance_id domain_uuid uri name state directory manifest journal')
            uuid(instance_id); uuid(record['domain_uuid'])
            if record['instance_id'] != instance_id or record['lab_id'] != state['lab_id']:
                fail('OWNERSHIP_MISMATCH', 'Registry identities conflict.')
            if record['uri'] not in {'qemu:///system', 'qemu:///session'} or record['state'] not in STATES:
                fail('STATE_INVALID', 'Unknown backend or lifecycle state.')
            identifier(record['name'])
            if record['domain_uuid'] in domains or (record['state'] != 'destroyed' and record['name'] in names):
                fail('REGISTRY_CONFLICT', 'Ambiguous domain UUID or instance names.', 4)
            domains.add(record['domain_uuid'])
            if record['state'] != 'destroyed':
                names.add(record['name'])
            if record['directory'] is not None:
                self._inode(record['directory'])
            if not isinstance(record['manifest'], list) or len(record['manifest']) > 16:
                fail('STATE_INVALID', 'Invalid resource manifest.')
            paths = set()
            for item in record['manifest']:
                keys(item, 'path device inode')
                self._inode({k: item[k] for k in ('device', 'inode')})
                if item['path'] not in MANIFEST_NAMES or item['path'] in paths:
                    fail('PATH_INVALID', 'Only unambiguous known instance-owned files are allowed.')
                paths.add(item['path'])
            journal = record['journal']
            if not isinstance(journal, list) or not journal or len(journal) > 128:
                fail('STATE_INVALID', 'Missing or oversized operation journal.')
            operation_ids = set()
            for operation in journal:
                if not isinstance(operation, dict):
                    fail('STATE_INVALID', 'Invalid journal contract.')
                kind = operation.get('kind')
                expected = ('id kind phase last_safe status events exec'
                            if kind == 'exec'
                            else 'id kind phase last_safe status events transfer'
                            if kind == 'copy'
                            else 'id kind phase last_safe status events cleanup'
                            if kind == 'staging_cleanup'
                            else 'id kind phase last_safe status events recovery'
                            if kind in {'failed_create_cleanup', 'restore_recovery',
                                        'restore_start_recovery', 'legacy_dac_migration'}
                            else 'id kind phase last_safe status events restore'
                            if kind == 'restore_activation'
                            else 'id kind phase last_safe status events')
                keys(operation, expected)
                uuid(operation['id'])
                if operation['id'] in operation_ids:
                    fail('REGISTRY_CONFLICT', 'Duplicate operation generation.', 4)
                operation_ids.add(operation['id'])
                if (operation['kind'] not in {'create', 'start', 'start_recovery', 'shutdown',
                                              'destroy', 'failed_create_cleanup',
                                              'restore_activation', 'restore_recovery',
                                              'restore_start_recovery', 'legacy_dac_migration',
                                              'staging_cleanup', 'exec', 'copy'}
                        or operation['status'] not in {'pending', 'complete',
                                                       'review_required'}):
                    fail('STATE_INVALID', 'Unknown journal contract.')
                if operation['kind'] == 'restore_activation':
                    self._validate_restore(operation['restore'], record)
                if operation['kind'] == 'restore_recovery':
                    self._validate_restore_recovery(operation['recovery'], record)
                if operation['kind'] == 'restore_start_recovery':
                    self._validate_restore_start_recovery(operation['recovery'], record)
                if operation['kind'] == 'legacy_dac_migration':
                    self._validate_legacy_dac_migration(operation['recovery'], record)
                if operation['kind'] == 'staging_cleanup':
                    self._validate_staging_cleanup(operation['cleanup'], record)
                if operation['kind'] == 'exec':
                    self._validate_exec(operation['exec'], operation['phase'])
                if operation['kind'] == 'copy':
                    self._validate_transfer(operation['transfer'], operation['phase'])
                if operation['kind'] == 'failed_create_cleanup':
                    recovery = operation['recovery']
                    expected_cleanup = set(
                        'source_operation domain_xml_sha256 instance_manifest_sha256 '
                        'guest_manifest_sha256 source_failure registry runtime client_directory '
                        'client_files'.split())
                    if (not isinstance(recovery, dict)
                            or set(recovery) not in (expected_cleanup,
                                                    expected_cleanup | {'hostkey_pinned'})):
                        fail('STATE_INVALID', 'Unknown or missing cleanup evidence fields.')
                    uuid(recovery['source_operation'])
                    for field in ('domain_xml_sha256', 'instance_manifest_sha256',
                                  'guest_manifest_sha256'):
                        if not isinstance(recovery[field], str) or not re.fullmatch(r'[0-9a-f]{64}', recovery[field]):
                            fail('STATE_INVALID', 'Invalid cleanup evidence.')
                    source_failure = recovery['source_failure']
                    keys(source_failure, 'cloud_init provisioning_status error')
                    if (source_failure['cloud_init'] not in {'pending', 'completed', 'failed'}
                            or source_failure['provisioning_status']
                            not in {'provisioning', 'failed'}
                            or (source_failure['error'] is not None
                                and (not isinstance(source_failure['error'], str)
                                     or len(source_failure['error']) > 128))):
                        fail('STATE_INVALID', 'Invalid provisioning failure evidence.')
                    registry = recovery['registry']
                    keys(registry, 'lab_id instance_id domain_uuid uri name')
                    if registry != {key: record[key]
                                    for key in ('lab_id', 'instance_id', 'domain_uuid', 'uri', 'name')}:
                        fail('OWNERSHIP_MISMATCH', 'Cleanup is bound to a different registry identity.')
                    runtime = recovery['runtime']
                    keys(runtime, 'storage directory files')
                    storage = Path(runtime['storage']) if isinstance(runtime['storage'], str) else Path('.')
                    if (not storage.is_absolute() or '..' in storage.parts
                            or storage.name != record['instance_id']):
                        fail('PATH_INVALID', 'Invalid bound cleanup run path.')
                    self._inode(runtime['directory'])
                    if (not isinstance(runtime['files'], dict)
                            or set(runtime['files'])
                            != {'base.qcow2', 'work.qcow2', 'nvram.fd', 'seed.iso', 'serial.log'}):
                        fail('STATE_INVALID', 'Invalid cleanup run manifest.')
                    for identity in runtime['files'].values():
                        self._inode(identity)
                    self._inode(recovery['client_directory'])
                    client_names = (set(recovery['client_files'])
                                    if isinstance(recovery['client_files'], dict) else set())
                    pinned = recovery.get('hostkey_pinned', True)
                    if (type(pinned) is not bool
                            or client_names != ({'id_ed25519', 'id_ed25519.pub', 'known_hosts'}
                                                if pinned else {'id_ed25519', 'id_ed25519.pub'})):
                        fail('STATE_INVALID', 'Invalid SSH cleanup manifest.')
                    source = next((item for item in record['journal']
                                   if item.get('id') == recovery['source_operation']), None)
                    if (not pinned
                            and (not self._recoverable_failed_create(source)
                                 or source_failure != {
                                     'cloud_init': 'pending',
                                     'provisioning_status': 'provisioning',
                                     'error': None,
                                 })):
                        fail('STATE_INVALID',
                             'Missing known_hosts is not bound to a pre-pinning Create.')
                    for identity in recovery['client_files'].values():
                        self._inode(identity)
                if (not isinstance(operation['events'], list) or not operation['events']
                        or len(operation['events']) > 32 or operation['phase'] != operation['events'][-1]
                        or any(p not in STATES | CLEANUP_PHASES | SHUTDOWN_PHASES | RESTORE_PHASES
                               | RESTORE_RECOVERY_PHASES | RESTORE_START_RECOVERY_PHASES
                               | LEGACY_DAC_MIGRATION_PHASES | STAGING_CLEANUP_PHASES | EXEC_PHASES
                               | TRANSFER_PHASES
                               for p in operation['events'])
                        or operation['last_safe'] not in STATES | CLEANUP_PHASES | SHUTDOWN_PHASES
                           | RESTORE_PHASES | RESTORE_RECOVERY_PHASES
                           | RESTORE_START_RECOVERY_PHASES | LEGACY_DAC_MIGRATION_PHASES
                           | STAGING_CLEANUP_PHASES | EXEC_PHASES | TRANSFER_PHASES):
                    fail('STATE_INVALID', 'Inkonsistenter Journalverlauf.')
                sequences = {
                    'create': (['planned', 'allocating', 'defined'],
                               ['planned', 'allocating', 'defined', 'booting', 'provisioning', 'ready']),
                    'start': (['planned', 'booting', 'ready'],),
                    'start_recovery': (['planned', 'ready'],),
                    'shutdown': (['planned', 'defined'], ['planned', 'forcing', 'defined']),
                    'destroy': (['planned', 'undefined', 'destroyed'],),
                    'failed_create_cleanup': (CLEANUP_SEQUENCE,),
                    'restore_activation': (RESTORE_SEQUENCE,),
                    'restore_recovery': (['planned', 'resolved'], RESTORE_RECOVERY_SEQUENCE),
                    'restore_start_recovery': (RESTORE_START_RECOVERY_SEQUENCE,),
                    'legacy_dac_migration': (LEGACY_DAC_MIGRATION_SEQUENCE,),
                    'staging_cleanup': (STAGING_CLEANUP_SEQUENCE,),
                    'exec': (['planned', 'dispatched'],
                             *(['planned', 'dispatched', terminal]
                               for terminal in sorted(EXEC_TERMINALS))),
                    'copy': (['planned', 'dispatched'],
                             *(['planned', 'dispatched', terminal]
                               for terminal in sorted(TRANSFER_TERMINALS))),
                }[operation['kind']]
                events = operation['events']
                prefix = events[:-1] if events[-1] == 'failed' else events
                valid_prefix = any(prefix == sequence[:len(prefix)] for sequence in sequences)
                completed = any(events == sequence for sequence in sequences)
                pending = any(events == sequence[:len(events)] and len(events) < len(sequence) for sequence in sequences)
                valid_status = ((operation['status'] == 'complete' and completed)
                                or (operation['status'] == 'pending' and pending)
                                or (operation['status'] == 'review_required' and events[-1] == 'failed'))
                if not valid_prefix or not prefix or not valid_status:
                    fail('STATE_INVALID', 'Journal status and transitions conflict.')
            if journal[0]['kind'] != 'create':
                fail('STATE_INVALID', 'Incomplete operation was bypassed.')
            for index, operation in enumerate(journal):
                if operation['kind'] == 'start_recovery':
                    previous = journal[index - 1] if index else None
                    if not self._recoverable_start(previous):
                        fail('STATE_INVALID', 'Start recovery has no matching failed start.')
                if operation['kind'] == 'failed_create_cleanup':
                    previous = journal[index - 1] if index else None
                    if (not self._recoverable_failed_create(previous)
                            or operation['recovery']['source_operation'] != previous['id']):
                        fail('STATE_INVALID', 'Failed-create cleanup has no matching source failure.')
                if operation['kind'] == 'restore_recovery':
                    source = next((candidate for candidate in journal[:index]
                                   if candidate['id'] == operation['recovery']['source_operation']), None)
                    if source is None or source['kind'] != 'restore_activation':
                        fail('STATE_INVALID', 'Restore recovery has no matching source operation.')
                    recovery = operation['recovery']; restore = source['restore']
                    if (recovery['baseline_id'] != restore['baseline_id']
                            or recovery['generation_id'] != restore['generation_id']
                            or recovery['lifecycle_state'] != restore['old_state']):
                        fail('STATE_INVALID', 'Restore recovery contradicts its source operation.')
                if operation['kind'] == 'restore_start_recovery':
                    recovery = operation['recovery']
                    source = next((candidate for candidate in journal[:index]
                                   if candidate['id'] == recovery['source_operation']), None)
                    activation = next((candidate for candidate in journal[:index]
                                       if candidate['id'] == recovery['restore_activation']), None)
                    if (not self._recoverable_start(source) or activation is None
                            or activation['kind'] != 'restore_activation'
                            or activation['status'] != 'complete'
                            or recovery['baseline_id'] != activation['restore']['baseline_id']
                            or recovery['generation_id'] != activation['restore']['generation_id']
                            or recovery['lifecycle_state'] != activation['restore']['old_state']):
                        fail('STATE_INVALID', 'Restore-start recovery contradicts its sources.')
                if operation['kind'] == 'legacy_dac_migration':
                    recovery = operation['recovery']
                    activation = next((candidate for candidate in journal[:index]
                                       if candidate['id'] == recovery['source_operation']), None)
                    if (activation is None or activation['kind'] != 'restore_activation'
                            or activation['status'] != 'complete'
                            or recovery['baseline_id'] != activation['restore']['baseline_id']
                            or recovery['generation_id'] != activation['restore']['generation_id']
                            or recovery['lifecycle_state'] != activation['restore']['old_state']):
                        fail('STATE_INVALID', 'Legacy DAC migration contradicts its restore source.')
                if operation['status'] != 'complete' and index < len(journal) - 1:
                    following = journal[index + 1]
                    allowed_recovery = (
                        (self._recoverable_start(operation)
                         and following['kind'] == 'start_recovery')
                        or (self._recoverable_failed_create(operation)
                            and following['kind'] == 'failed_create_cleanup'
                            and following['recovery']['source_operation'] == operation['id'])
                        or (operation['kind'] in {'restore_activation','restore_recovery'}
                            and following['kind'] == 'restore_recovery'
                            and following['recovery']['source_operation']
                            == (operation['id'] if operation['kind'] == 'restore_activation'
                                else operation['recovery']['source_operation']))
                        or (operation['kind'] in {'start','restore_start_recovery'}
                            and following['kind'] == 'restore_start_recovery'
                            and following['recovery']['source_operation']
                            == (operation['id'] if operation['kind'] == 'start'
                                else operation['recovery']['source_operation']))
                        or (operation['kind'] == 'legacy_dac_migration'
                            and following['kind'] == 'legacy_dac_migration'
                            and following['recovery']['source_operation']
                            == operation['recovery']['source_operation']))
                    if not allowed_recovery:
                        fail('STATE_INVALID', 'Incomplete operation was bypassed.')
            last = journal[-1]
            if last['phase'] in STATES and (last['phase'] != 'planned' or last['kind'] == 'create') and record['state'] != last['phase']:
                fail('STATE_INVALID', 'Registry state and journal phase conflict.')

    @staticmethod
    def _inode(value):
        keys(value, 'device inode')
        if any(type(n) is not int or n < 0 for n in value.values()):
            fail('STATE_INVALID', 'Invalid file-ownership evidence.')

    @staticmethod
    def _validate_exec(value, phase):
        keys(value, 'protocol_version adapter_version job_id argv_sha256 argv_count outcome '
                    'started pid pgid guest_exit_code ssh_exit_code stdout stderr')
        uuid(value['job_id'])
        if (value['protocol_version'] != 1
                or value['adapter_version'] != 'vm-dev-lab-exec-v1'
                or not isinstance(value['argv_sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['argv_sha256'])
                or type(value['argv_count']) is not int
                or not 1 <= value['argv_count'] <= 256
                or value['outcome'] != phase
                or (value['started'] is not None and type(value['started']) is not bool)
                or (value['pid'] is not None
                    and (type(value['pid']) is not int or value['pid'] <= 0))
                or value['pgid'] != value['pid']
                or (value['guest_exit_code'] is not None
                    and (type(value['guest_exit_code']) is not int
                         or not 0 <= value['guest_exit_code'] <= 255))
                or (value['ssh_exit_code'] is not None
                    and type(value['ssh_exit_code']) is not int)):
            fail('STATE_INVALID', 'Invalid exec evidence.')
        if ((value['started'] is True and value['pid'] is None)
                or (value['started'] in {None, False} and value['pid'] is not None)):
            fail('STATE_INVALID', 'Exec process group conflicts with the start state.')
        if phase == 'dispatched':
            if any(value[field] is not None for field in (
                    'started', 'pid', 'guest_exit_code', 'ssh_exit_code', 'stdout', 'stderr')):
                fail('STATE_INVALID', 'Dispatched exec already claims a result.')
            return
        if phase in {'completed', 'guest_failed'}:
            if (value['ssh_exit_code'] != 0 or type(value['started']) is not bool
                    or value['guest_exit_code'] is None
                    or (phase == 'completed') != (value['guest_exit_code'] == 0)):
                fail('STATE_INVALID', 'Guest execution result contradicts its outcome.')
        elif phase == 'timed_out':
            if value['guest_exit_code'] is not None or value['started'] not in {None, True}:
                fail('STATE_INVALID', 'Exec timeout claims guest completion.')
        elif phase == 'transport_failed':
            if (value['ssh_exit_code'] is None or value['guest_exit_code'] is not None
                    or value['started'] is not None):
                fail('STATE_INVALID', 'Execution transport error claims guest state.')
        elif phase == 'protocol_failed':
            if (value['ssh_exit_code'] != 0 or value['guest_exit_code'] is not None
                    or value['started'] is not None):
                fail('STATE_INVALID', 'Execution protocol error claims guest state.')
        for name in ('stdout', 'stderr'):
            stream = value[name]
            if phase in {'transport_failed', 'protocol_failed'} or (phase == 'timed_out' and value['started'] is None):
                if stream is not None:
                    fail('STATE_INVALID', 'Unknown guest execution state has output metadata.')
                continue
            keys(stream, 'bytes_total bytes_captured bytes_returned truncated redacted')
            if (type(stream['bytes_total']) is not int
                    or type(stream['bytes_captured']) is not int
                    or type(stream['bytes_returned']) is not int
                    or type(stream['truncated']) is not bool
                    or type(stream['redacted']) is not bool
                    or not 0 <= stream['bytes_captured'] <= stream['bytes_total']
                    or stream['bytes_returned'] < 0
                    or stream['truncated'] != (stream['bytes_total'] > stream['bytes_captured'])
                    or (not stream['redacted']
                        and stream['bytes_returned'] != stream['bytes_captured'])):
                fail('STATE_INVALID', 'Invalid exec output binding.')

    @staticmethod
    def _validate_transfer(value, phase):
        keys(value, 'protocol_version adapter_version transfer_id direction guest_path '
                    'host_path_sha256 outcome kind file_count total_bytes manifest_sha256 '
                    'ssh_exit_code overwrite source_commit source_dirty')
        uuid(value['transfer_id'])
        if (value['protocol_version'] != 1
                or value['adapter_version'] != 'vm-dev-lab-files-v1'
                or value['direction'] not in {'host-to-guest', 'guest-to-host'}
                or not isinstance(value['guest_path'], str)
                or not 1 <= len(value['guest_path'].encode('utf-8')) <= 512
                or not isinstance(value['host_path_sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['host_path_sha256'])
                or value['outcome'] != phase or type(value['overwrite']) is not bool
                or value['kind'] not in {None, 'file', 'directory'}
                or (value['file_count'] is not None
                    and (type(value['file_count']) is not int
                         or not 1 <= value['file_count'] <= 256))
                or (value['total_bytes'] is not None
                    and (type(value['total_bytes']) is not int
                         or not 0 <= value['total_bytes'] <= 64 * 1024 * 1024))
                or (value['manifest_sha256'] is not None
                    and (not isinstance(value['manifest_sha256'], str)
                         or not re.fullmatch(r'[0-9a-f]{64}', value['manifest_sha256'])))
                or (value['ssh_exit_code'] is not None
                    and type(value['ssh_exit_code']) is not int)
                or (value['source_commit'] is not None
                    and (not isinstance(value['source_commit'], str)
                         or not re.fullmatch(r'[0-9a-f]{40}', value['source_commit'])))
                or (value['source_dirty'] is not None
                    and type(value['source_dirty']) is not bool)):
            fail('STATE_INVALID', 'Invalid transfer evidence.')
        fields = (value['kind'], value['file_count'], value['total_bytes'],
                  value['manifest_sha256'])
        if (any(field is None for field in fields)
                and any(field is not None for field in fields)):
            fail('STATE_INVALID', 'Transfer manifest is only partially bound.')
        if (value['source_commit'] is None) != (value['source_dirty'] is None):
            fail('STATE_INVALID', 'Git source state is only partially bound.')
        if phase == 'completed' and (None in fields or value['ssh_exit_code'] != 0):
            fail('STATE_INVALID', 'Completed transfer has no integrity evidence.')
        if phase == 'dispatched' and value['ssh_exit_code'] is not None:
            fail('STATE_INVALID', 'Dispatched transfer already claims transport completion.')

    def _validate_restore(self, value, record):
        keys(value, 'target baseline_id preparation_operation_id generation_id old_state old_generation new_generation')
        keys(value['target'], 'lab_id instance_id domain_uuid')
        if value['target'] != {key: record[key] for key in ('lab_id', 'instance_id', 'domain_uuid')}:
            fail('OWNERSHIP_MISMATCH', 'Restore journal is bound to a different instance.')
        uuid(value['preparation_operation_id']); uuid(value['generation_id'])
        if value['old_state'] not in STATES - {'failed', 'destroyed'}:
            fail('STATE_INVALID', 'Invalid initial state in restore journal.')
        if (not isinstance(value['baseline_id'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['baseline_id'])):
            fail('STATE_INVALID', 'Invalid baseline binding in restore journal.')
        old = value['old_generation']
        keys(old, 'registry_sha256 last_operation_id domain_xml_sha256 disk nvram '
             'guest_manifest instance_manifest domain_manifest')
        uuid(old['last_operation_id'])
        for field in ('registry_sha256', 'domain_xml_sha256'):
            if not isinstance(old[field], str) or not re.fullmatch(r'[0-9a-f]{64}', old[field]):
                fail('STATE_INVALID', 'Invalid initial evidence in restore journal.')
        new = value['new_generation']
        if (not isinstance(new, dict)
                or set(new) not in ({'directory','artifacts','guest_manifest'},
                                    {'directory','artifacts','guest_manifest','baseline_disk'})):
            fail('STATE_INVALID', 'Incomplete new generation in restore journal.')
        path = Path(new['directory']) if isinstance(new['directory'], str) else Path('.')
        if (not path.is_absolute() or '..' in path.parts or '\0' in str(path)
                or path.name != value['preparation_operation_id']
                or path.parent.name != record['instance_id']
                or path.parent.parent.name != '.restore-staging'):
            fail('PATH_INVALID', 'Invalid generation path in restore journal.')
        if not isinstance(new['artifacts'], dict) or set(new['artifacts']) != {'disk.qcow2', 'nvram.fd', 'domain.xml'}:
            fail('STATE_INVALID', 'Incomplete new generation in restore journal.')
        artifacts = [old['disk'], old['nvram'], old['guest_manifest'],
                         old['instance_manifest'], old['domain_manifest'],
                         new['guest_manifest'], *new['artifacts'].values()]
        if 'baseline_disk' in new:
            artifacts.append(new['baseline_disk'])
        for artifact in artifacts:
            keys(artifact, 'path device inode size sha256')
            artifact_path = Path(artifact['path']) if isinstance(artifact['path'], str) else Path('.')
            if (not artifact_path.is_absolute() or '..' in artifact_path.parts
                    or any(type(artifact[field]) is not int or artifact[field] < 0
                           for field in ('device', 'inode', 'size'))
                    or not isinstance(artifact['sha256'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256'])):
                fail('STATE_INVALID', 'Invalid artifact binding in restore journal.')
        if any(Path(new['artifacts'][name]['path']) != path/name
               for name in ('disk.qcow2', 'nvram.fd', 'domain.xml')):
            fail('PATH_INVALID', 'New restore artifacts are outside their generation.')
        if 'baseline_disk' in new:
            baseline_path = Path(new['baseline_disk']['path'])
            expected = (path.parent.parent.parent/'baselines'/record['instance_id'] /
                        value['baseline_id']/'disk.qcow2')
            if baseline_path != expected:
                fail('PATH_INVALID', 'Baseline disk binding is outside its own bundle.')

    def _validate_restore_recovery(self, value, record):
        keys(value, 'source_operation classification baseline_id generation_id lifecycle_state')
        uuid(value['source_operation']); uuid(value['generation_id'])
        if (value['classification'] not in {'old-complete','new-complete','resume-new'}
                or value['lifecycle_state'] not in STATES - {'failed','destroyed'}
                or not isinstance(value['baseline_id'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['baseline_id'])):
            fail('STATE_INVALID', 'Invalid restore-recovery evidence.')

    def _validate_restore_start_recovery(self, value, record):
        expected = {'source_operation','restore_activation','baseline_id',
                    'generation_id','lifecycle_state'}
        if not isinstance(value, dict) or set(value) not in (expected, expected | {'baseline_disk'}):
            fail('STATE_INVALID', 'Invalid restore-start-recovery evidence.')
        uuid(value['source_operation']); uuid(value['restore_activation']); uuid(value['generation_id'])
        if (value['lifecycle_state'] not in STATES - {'failed','destroyed'}
                or not isinstance(value['baseline_id'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['baseline_id'])):
            fail('STATE_INVALID', 'Invalid restore-start-recovery evidence.')
        if 'baseline_disk' in value:
            artifact = value['baseline_disk']
            keys(artifact, 'path device inode size sha256')
            path = Path(artifact['path']) if isinstance(artifact['path'], str) else Path('.')
            if (not path.is_absolute() or '..' in path.parts
                    or any(type(artifact[field]) is not int or artifact[field] < 0
                           for field in ('device','inode','size'))
                    or not isinstance(artifact['sha256'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256'])):
                fail('STATE_INVALID', 'Invalid baseline-disk binding in recovery evidence.')
            if (path.name != 'disk.qcow2' or path.parent.name != value['baseline_id']
                    or path.parent.parent.name != record['instance_id']
                    or path.parent.parent.parent.name != 'baselines'):
                fail('PATH_INVALID', 'Recovery does not bind an owned baseline disk.')

    def _validate_legacy_dac_migration(self, value, record):
        expected = {'source_operation','baseline_id','generation_id','lifecycle_state',
                    'baseline_disk','old_domain_sha256','new_domain_sha256',
                    'request_sha256'}
        if not isinstance(value, dict) or set(value) != expected:
            fail('STATE_INVALID', 'Invalid legacy DAC migration evidence.')
        uuid(value['source_operation']); uuid(value['generation_id'])
        if (value['lifecycle_state'] not in STATES - {'failed','destroyed'}
                or not isinstance(value['baseline_id'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['baseline_id'])
                or any(not isinstance(value[field], str)
                       or not re.fullmatch(r'[0-9a-f]{64}', value[field])
                       for field in ('old_domain_sha256','new_domain_sha256','request_sha256'))):
            fail('STATE_INVALID', 'Invalid legacy DAC migration binding.')
        artifact = value['baseline_disk']
        keys(artifact, 'path device inode size sha256 uid gid')
        path = Path(artifact['path']) if isinstance(artifact['path'], str) else Path('.')
        if (not path.is_absolute() or '..' in path.parts
                or any(type(artifact[field]) is not int or artifact[field] < 0
                       for field in ('device','inode','size','uid','gid'))
                or not isinstance(artifact['sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256'])
                or path.name != 'disk.qcow2' or path.parent.name != value['baseline_id']
                or path.parent.parent.name != record['instance_id']
                or path.parent.parent.parent.name != 'baselines'):
            fail('PATH_INVALID', 'Migration does not bind an owned baseline disk.')

    def _validate_staging_cleanup(self, value, record):
        keys(value, 'source_operation staging_kind path directory files reservation_requested')
        uuid(value['source_operation'])
        if value['staging_kind'] not in {'baseline', 'restore'}:
            fail('STATE_INVALID', 'Unknown staging type in cleanup.')
        path = Path(value['path']) if isinstance(value['path'], str) else Path('.')
        if (not path.is_absolute() or '..' in path.parts
                or (value['staging_kind'] == 'baseline'
                    and (path.name != '.stage-' + value['source_operation']
                         or path.parent.name != '.baseline-staging'))
                or (value['staging_kind'] == 'restore'
                    and (path.name != value['source_operation']
                         or path.parent.name != record['instance_id']
                         or path.parent.parent.name != '.restore-staging'))):
            fail('PATH_INVALID', 'Cleanup is not bound to an owned staging path.')
        self._inode(value['directory'])
        files = value['files']
        allowed = ({'disk.qcow2','nvram.fd','domain.xml','instance.json',
                    'guest-manifest.json','manifest.json'}
                   if value['staging_kind'] == 'baseline'
                   else {'disk.qcow2','nvram.fd','domain.xml','preparation.json'})
        if not isinstance(files, dict) or not set(files) <= allowed:
            fail('STATE_INVALID', 'Cleanup file inventory is unknown.')
        for name, identity in files.items():
            keys(identity, 'device inode size blocks')
            if any(type(identity[field]) is not int or identity[field] < 0
                   for field in ('device','inode','size','blocks')):
                fail('STATE_INVALID', 'Invalid cleanup file binding.')
        requested = value['reservation_requested']
        if (not isinstance(requested, dict) or set(requested) != RESOURCE_FIELDS
                or any(type(item) is not int or item < 0 for item in requested.values())):
            fail('STATE_INVALID', 'Invalid cleanup resource binding.')

    def _validate_resources(self, resources, instances):
        keys(resources, 'schema_version limits reservations')
        if resources['schema_version'] != 1:
            fail('STATE_VERSION_UNSUPPORTED', 'Unknown resource-ledger version.')
        limits = resources['limits']
        if (not isinstance(limits, dict)
                or set(limits) != {'instances','vcpus','memory_mib',
                                   'virtual_disk_bytes','storage_bytes','operations'}
                or any(type(value) is not int or value <= 0
                       for value in limits.values())):
            fail('STATE_INVALID', 'Invalid resource limits.')
        reservations = resources['reservations']
        if not isinstance(reservations, dict) or len(reservations) > 512:
            fail('STATE_INVALID', 'Invalid reservation inventory.')
        zero = {key: 0 for key in RESOURCE_FIELDS}
        for operation_id, reservation in reservations.items():
            uuid(operation_id)
            keys(reservation, 'operation_id instance_id kind state requested committed')
            uuid(reservation['operation_id']); uuid(reservation['instance_id'])
            if (reservation['operation_id'] != operation_id
                    or reservation['instance_id'] not in instances
                    or reservation['kind'] not in {'create','snapshot','restore'}
                    or reservation['state'] not in RESOURCE_STATES):
                fail('STATE_INVALID', 'Invalid reservation identity.')
            for field in ('requested', 'committed'):
                values = reservation[field]
                if (not isinstance(values, dict) or set(values) != RESOURCE_FIELDS
                        or any(type(value) is not int or value < 0
                               for value in values.values())):
                    fail('STATE_INVALID', 'Invalid resource values or units.')
            if reservation['state'] == 'active' and reservation['committed'] != zero:
                fail('STATE_INVALID', 'Active reservation already contains bindings.')
            if (reservation['state'] in {'bound','released'}
                    and reservation['committed']['operations']):
                fail('STATE_INVALID', 'Completed reservation occupies an operation.')

    def _read(self):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    fail('STATE_INVALID', 'Doppelte Registryfelder.')
                result[key] = value
            return result
        try:
            with directory(self.paths.state) as parent:
                fd = os.open('registry.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                with os.fdopen(fd, 'rb') as stream:
                    private_file(stream.fileno())
                    raw = stream.read(MAX_STATE_BYTES + 1)
            if len(raw) > MAX_STATE_BYTES:
                fail('STATE_INVALID', 'Registry exceeds 1 MiB.')
            state = json.loads(raw, object_pairs_hook=unique)
            self._validate(state)
            return state
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            fail('STATE_INVALID', 'Registry is missing, unsafe, or corrupted.')

    def _write(self, state):
        self._validate(state)
        raw = json.dumps(state, allow_nan=False, sort_keys=True).encode()
        if len(raw) > MAX_STATE_BYTES:
            fail('STATE_LIMIT', 'Registrylimit erreicht.', 4)
        with directory(self.paths.state) as parent:
            name = '.registry-' + str(uuid4()) + '.tmp'
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            # Aborted staging remains diagnostic material; no automatic cleanup.
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, 'registry.json', src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)

    def inspect(self, target):
        with self.lock('global'):
            state = self._read()
            matches = [r for r in state['instances'].values()
                       if r['instance_id'] == target or r['domain_uuid'] == target
                       or (r['name'] == target and r['state'] != 'destroyed')]
            if len(matches) != 1:
                fail('REGISTRY_CONFLICT', 'Instance is missing or ambiguous.', 4)
            result = deepcopy(matches[0])
            result['requires_review'] = result['journal'][-1]['status'] != 'complete'
            return result

    def inventory(self):
        """Validated registry view including historical tombstones."""
        with self.lock('global'):
            state = self._read()
            result = []
            for record in state['instances'].values():
                item = deepcopy(record)
                item['requires_review'] = item['journal'][-1]['status'] != 'complete'
                result.append(item)
            return sorted(result, key=lambda item: (
                item['state'] == 'destroyed', item['name'], item['instance_id']))

    def reserve(self, name, *, prepare=None):
        """Reserve name and IDs, and optionally additional registry state, in one write.

        ``prepare`` runs under the same global lock after the planned Create
        has been added only to the local state copy. If preparation fails,
        neither the Create nor its additional mutation
        persistiert.
        """
        identifier(name)
        with self.lock('global'):
            state = self._read()
            if any(r['name'] == name and r['state'] != 'destroyed' for r in state['instances'].values()):
                fail('REGISTRY_CONFLICT', 'Instance name is already reserved.', 4)
            record = dict(lab_id=state['lab_id'], instance_id=str(uuid4()), domain_uuid=str(uuid4()),
                          uri=self.uri, name=name, state='planned', directory=None, manifest=[],
                          journal=[self._operation('create')])
            state['instances'][record['instance_id']] = record
            if prepare is not None:
                prepare(state, record)
            self._write(state)
            return deepcopy(record)

    @staticmethod
    def _operation(kind, operation_id=None):
        if operation_id is not None:
            uuid(operation_id)
        return dict(id=operation_id or str(uuid4()), kind=kind, phase='planned',
                    last_safe='planned', status='pending', events=['planned'])

    @staticmethod
    def _recoverable_start(operation):
        return (isinstance(operation, dict) and operation.get('kind') == 'start'
                and operation.get('status') == 'review_required' and operation.get('phase') == 'failed'
                and operation.get('events') == ['planned', 'booting', 'failed']
                and operation.get('last_safe') == 'planned')

    @staticmethod
    def _recoverable_failed_create(operation):
        return (isinstance(operation, dict) and operation.get('kind') == 'create'
                and operation.get('status') == 'review_required' and operation.get('phase') == 'failed'
                and operation.get('events') == ['planned', 'allocating', 'defined', 'booting',
                                                 'provisioning', 'failed']
                and operation.get('last_safe') == 'booting')

    def update(self, instance_id, operation_id, change):
        """CAS by operation ID; the caller must hold the instance lock."""
        with self.lock('global'):
            state = self._read()
            record = state['instances'].get(instance_id)
            if record is None or record['journal'][-1]['id'] != operation_id:
                fail('REGISTRY_CONFLICT', 'Operation generation does not match.', 4)
            change(record)
            self._write(state)

    def begin(self, record, kind):
        if record['requires_review']:
            fail('REVIEW_REQUIRED', 'Incomplete operation; inspect manually before further mutation.', 4)
        operation = self._operation(kind)
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed in the meantime.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], record['journal'][-1]['id'], change)
        return operation['id']

    def begin_exec(self, record, operation_id, evidence):
        """Publish a non-blocking guest job whose outcome is still unknown."""
        if record['requires_review']:
            fail('REVIEW_REQUIRED', 'Incomplete operation blocks exec.', 4)
        operation = self._operation('exec', operation_id)
        operation.update(phase='dispatched', last_safe='dispatched', status='complete',
                         events=['planned', 'dispatched'], exec=deepcopy(evidence))
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before exec.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], record['journal'][-1]['id'], change)
        return operation['id']

    def complete_exec(self, instance_id, operation_id, phase, evidence):
        """Replace unknown only with a bound terminal transport result."""
        if phase not in EXEC_TERMINALS:
            fail('STATE_CONFLICT', 'Invalid exec completion.', 4)
        def change(record):
            operation = record['journal'][-1]
            if (operation['id'] != operation_id or operation['kind'] != 'exec'
                    or operation['phase'] != 'dispatched' or operation['status'] != 'complete'):
                fail('REGISTRY_CONFLICT', 'Exec operation is no longer current.', 4)
            operation['phase'] = phase
            operation['last_safe'] = phase
            operation['events'].append(phase)
            operation['exec'] = deepcopy(evidence)
        self.update(instance_id, operation_id, change)

    def begin_transfer(self, record, operation_id, evidence):
        """Persist the transfer ID before the first guest or SFTP call."""
        if record['requires_review']:
            fail('REVIEW_REQUIRED', 'Incomplete operation blocks copy.', 4)
        operation = self._operation('copy', operation_id)
        operation.update(phase='dispatched', last_safe='dispatched', status='complete',
                         events=['planned', 'dispatched'], transfer=deepcopy(evidence))
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before copy.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], record['journal'][-1]['id'], change)

    def complete_transfer(self, instance_id, operation_id, phase, evidence):
        if phase not in TRANSFER_TERMINALS:
            fail('STATE_CONFLICT', 'Invalid transfer completion.', 4)
        def change(record):
            operation = record['journal'][-1]
            if (operation['id'] != operation_id or operation['kind'] != 'copy'
                    or operation['phase'] != 'dispatched' or operation['status'] != 'complete'):
                fail('REGISTRY_CONFLICT', 'Copy operation is no longer current.', 4)
            operation.update(phase=phase, last_safe=phase, transfer=deepcopy(evidence))
            operation['events'].append(phase)
        self.update(instance_id, operation_id, change)

    def begin_start_recovery(self, record):
        """Append only to an exactly matching failed start; never reinterpret it."""
        if not record.get('requires_review') or not self._recoverable_start(record['journal'][-1]):
            fail('REVIEW_REQUIRED', 'Only an unambiguously failed start can be recovered.', 4)
        operation = self._operation('start_recovery')
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before recovery.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], record['journal'][-1]['id'], change)
        return operation['id']

    def begin_restore_start_recovery(self, record, source_operation, evidence):
        """Bind ACL recovery to the current failed restore start."""
        latest = record['journal'][-1]
        initial = self._recoverable_start(latest) and latest['id'] == source_operation
        retry = (latest.get('kind') == 'restore_start_recovery'
                 and latest.get('status') == 'review_required'
                 and latest.get('phase') == 'failed'
                 and latest.get('recovery', {}).get('source_operation') == source_operation)
        if not record.get('requires_review') or not (initial or retry):
            fail('RECOVERY_SOURCE_MISMATCH',
                 'Only the current exactly bound failed restore start can be recovered.', 4)
        operation = self._operation('restore_start_recovery')
        operation['recovery'] = deepcopy(evidence)
        operation['recovery']['source_operation'] = source_operation
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before restore-start recovery.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], latest['id'], change)
        return operation['id']

    def begin_failed_create_cleanup(self, record, source_operation, evidence):
        """Bind cleanup to exactly the unchanged failed Create."""
        failed = record['journal'][-1]
        if (not record.get('requires_review') or not self._recoverable_failed_create(failed)
                or failed['id'] != source_operation):
            fail('RECOVERY_SOURCE_MISMATCH', 'Only an exactly matching failed provisioning Create can be cleaned up.', 4)
        operation = self._operation('failed_create_cleanup')
        operation['recovery'] = deepcopy(evidence)
        operation['recovery']['source_operation'] = source_operation
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before cleanup recovery.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], failed['id'], change)
        return operation['id']

    def begin_staging_cleanup(self, record, evidence):
        """Atomically bind staging cleanup and its review-required source reservation."""
        if record.get('requires_review'):
            fail('REVIEW_REQUIRED', 'Another incomplete operation blocks staging cleanup.', 4)
        operation = self._operation('staging_cleanup')
        operation['cleanup'] = deepcopy(evidence)
        source = evidence['source_operation']
        with self.lock('global'):
            state = self._read()
            current = state['instances'].get(record['instance_id'])
            expected = {key: value for key, value in record.items() if key != 'requires_review'}
            if current != expected or current['journal'][-1]['id'] != record['journal'][-1]['id']:
                fail('REGISTRY_CONFLICT', 'Registry changed before staging cleanup.', 4)
            reservation = state.get('resources', {}).get('reservations', {}).get(source)
            kind = {'baseline': 'snapshot', 'restore': 'restore'}[evidence['staging_kind']]
            if (reservation is None or reservation['instance_id'] != record['instance_id']
                    or reservation['kind'] != kind
                    or reservation['state'] != 'review_required'
                    or reservation['requested'] != evidence['reservation_requested']):
                fail('RESOURCE_RESERVATION_CONFLICT',
                     'Cleanup has no unambiguous review-required source reservation.', 4)
            current['journal'].append(operation)
            self._write(state)
        return operation['id']

    def begin_restore_activation(self, record, evidence):
        """Persist the complete switch plan before the first mutation."""
        if record['requires_review']:
            fail('REVIEW_REQUIRED', 'Incomplete operation; do not begin restore.', 4)
        operation = self._operation('restore_activation')
        operation['restore'] = deepcopy(evidence)
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before restore.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], record['journal'][-1]['id'], change)
        return operation['id']

    def begin_restore_recovery(self, record, source_operation, evidence):
        """Bind a recovery attempt to exactly one historical restore source."""
        source = next((item for item in record['journal'] if item['id'] == source_operation), None)
        if (source is None or source['kind'] != 'restore_activation'
                or not record.get('requires_review')):
            fail('RECOVERY_SOURCE_MISMATCH', 'No open matching restore source.', 4)
        for item in record['journal'][record['journal'].index(source) + 1:]:
            if (item['kind'] != 'restore_recovery'
                    or item['recovery']['source_operation'] != source_operation):
                fail('RECOVERY_SOURCE_MISMATCH', 'Restore source was superseded by other operations.', 4)
        operation = self._operation('restore_recovery')
        operation['recovery'] = deepcopy(evidence)
        operation['recovery']['source_operation'] = source_operation
        def change(current):
            if current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'Registry changed before restore recovery.', 4)
            current['journal'].append(operation)
        self.update(record['instance_id'], record['journal'][-1]['id'], change)
        return operation['id']

    def advance(self, instance_id, operation_id, phase, complete=False, failed=False):
        def change(record):
            operation = record['journal'][-1]
            if operation['status'] != 'pending':
                fail('REVIEW_REQUIRED', 'Do not continue a completed or ambiguous operation.', 4)
            if operation['kind'] == 'legacy_dac_migration':
                fail('STATE_CONFLICT',
                     'Historical legacy DAC journals are now read-only.', 4)
            transitions = {'create': {'planned': 'allocating', 'allocating': 'defined', 'defined': 'booting', 'booting': 'provisioning', 'provisioning': 'ready'},
                           'start': {'planned': 'booting', 'booting': 'ready'},
                           'start_recovery': {'planned': 'ready'},
                           'shutdown': {'planned': 'defined', 'forcing': 'defined'}, 'destroy': {'planned': 'undefined', 'undefined': 'destroyed'},
                           'failed_create_cleanup': {left: right for left, right in zip(CLEANUP_SEQUENCE, CLEANUP_SEQUENCE[1:])},
                           'restore_activation': {left: right for left, right in zip(RESTORE_SEQUENCE, RESTORE_SEQUENCE[1:])}}
            if operation['kind'] == 'restore_recovery':
                transitions['restore_recovery'] = {'planned': 'resolving', 'resolving': 'resolved'}
            if operation['kind'] == 'restore_start_recovery':
                transitions['restore_start_recovery'] = {
                    'planned': 'repairing_access', 'repairing_access': 'access_ready',
                    'access_ready': 'resolved'}
            if operation['kind'] == 'staging_cleanup':
                transitions['staging_cleanup'] = {
                    'planned': 'removing', 'removing': 'removed', 'removed': 'complete'}
            if not failed and transitions[operation['kind']].get(operation['phase']) != phase:
                fail('STATE_CONFLICT', 'Disallowed journal transition.', 4)
            if not failed:
                operation['last_safe'] = phase if complete else operation['phase']
            operation['phase'] = phase
            operation['events'].append(phase)
            operation['status'] = 'review_required' if failed else ('complete' if complete else 'pending')
            record['state'] = phase if phase in STATES else record['state']
        self.update(instance_id, operation_id, change)

    def complete_staging_cleanup(self, instance_id, operation_id):
        """Complete cleanup and ledger release in the same registry commit."""
        with self.lock('global'):
            state = self._read()
            record = state['instances'].get(instance_id)
            operation = record['journal'][-1] if record else None
            if (operation is None or operation['id'] != operation_id
                    or operation['kind'] != 'staging_cleanup'
                    or operation['status'] != 'pending'
                    or operation['phase'] != 'removed'):
                fail('STATE_CONFLICT', 'Staging-cleanup completion does not match the intent.', 4)
            source = operation['cleanup']['source_operation']
            reservation = state.get('resources', {}).get('reservations', {}).get(source)
            if (reservation is None or reservation['instance_id'] != instance_id
                    or reservation['kind'] != {
                        'baseline': 'snapshot', 'restore': 'restore'
                    }[operation['cleanup']['staging_kind']]
                    or reservation['state'] != 'review_required'
                    or reservation['requested']
                    != operation['cleanup']['reservation_requested']):
                fail('RESOURCE_RESERVATION_CONFLICT',
                     'Source reservation cannot be released safely.', 4)
            operation['last_safe'] = 'complete'
            operation['phase'] = 'complete'
            operation['events'].append('complete')
            operation['status'] = 'complete'
            reservation['state'] = 'released'
            reservation['committed'] = {key: 0 for key in RESOURCE_FIELDS}
            self._write(state)

    def complete_destroy(self, instance_id, operation_id):
        """Commit destroy completion and safe resource release in one CAS update."""
        def change(record):
            operation = record['journal'][-1]
            expected = {'destroy': 'undefined',
                        'failed_create_cleanup': 'clearing_manifest'}
            if (operation['id'] != operation_id or operation['status'] != 'pending'
                    or operation['kind'] not in expected
                    or operation['phase'] != expected[operation['kind']]):
                fail('STATE_CONFLICT', 'Destroy completion does not match the cleanup intent.', 4)
            operation['last_safe'] = 'destroyed'
            operation['phase'] = 'destroyed'
            operation['events'].append('destroyed')
            operation['status'] = 'complete'
            record['state'] = 'destroyed'

        with self.lock('global'):
            state = self._read()
            record = state['instances'].get(instance_id)
            if record is None or record['journal'][-1]['id'] != operation_id:
                fail('REGISTRY_CONFLICT', 'Operation generation does not match.', 4)
            change(record)
            if state['schema_version'] == 2:
                zero = {key: 0 for key in RESOURCE_FIELDS}
                for reservation in state['resources']['reservations'].values():
                    if (reservation['instance_id'] == instance_id
                            and reservation['kind'] in {'create','restore'}
                            and reservation['state'] != 'released'):
                        reservation['state'] = 'released'
                        reservation['committed'] = deepcopy(zero)
            self._write(state)

    def resolve_restore_recovery(self, instance_id, operation_id, *, from_resolving):
        """Complete recovery and lifecycle state in the same registry commit."""
        def change(record):
            operation = record['journal'][-1]
            expected = 'resolving' if from_resolving else 'planned'
            if (operation['id'] != operation_id or operation['kind'] != 'restore_recovery'
                    or operation['status'] != 'pending' or operation['phase'] != expected):
                fail('STATE_CONFLICT', 'Restore-recovery completion does not match the intent.', 4)
            operation['last_safe'] = 'resolved'
            operation['phase'] = 'resolved'
            operation['events'].append('resolved')
            operation['status'] = 'complete'
            record['state'] = operation['recovery']['lifecycle_state']
        self.update(instance_id, operation_id, change)

    def resolve_restore_start_recovery(self, instance_id, operation_id):
        """Atomically lift the start block only after the ACL state is confirmed."""
        def change(record):
            operation = record['journal'][-1]
            if (operation['id'] != operation_id
                    or operation['kind'] != 'restore_start_recovery'
                    or operation['status'] != 'pending'
                    or operation['phase'] != 'access_ready'):
                fail('STATE_CONFLICT', 'Restore-start-recovery completion does not match the intent.', 4)
            operation['last_safe'] = 'resolved'
            operation['phase'] = 'resolved'
            operation['events'].append('resolved')
            operation['status'] = 'complete'
            record['state'] = operation['recovery']['lifecycle_state']
        self.update(instance_id, operation_id, change)

    def replace_instance_bindings(self, record, operation_id, identities):
        """CAS update for private control files already replaced atomically."""
        if (not isinstance(identities, dict)
                or set(identities) != {'instance.json', 'domain.xml', 'guest-manifest.json'}):
            fail('STATE_INVALID', 'Invalid restore registry update.', 2)
        for value in identities.values():
            self._inode(value)
        def change(current):
            operation = current['journal'][-1]
            allowed = ((operation['kind'] == 'restore_activation'
                        and operation['phase'] == 'updating_registry')
                       or (operation['kind'] == 'restore_recovery'
                           and operation['phase'] == 'resolving'))
            if (operation['id'] != operation_id or operation['status'] != 'pending' or not allowed):
                fail('STATE_CONFLICT', 'Registry update does not match the restore intent.', 4)
            found = {item['path']: item for item in current['manifest']}
            if not set(identities).issubset(found):
                fail('OWNERSHIP_MISMATCH', 'Private restore control files are not registered.')
            for name, identity in identities.items():
                found[name].update(identity)
        self.update(record['instance_id'], operation_id, change)

    def mark_force_stop(self, instance_id, operation_id):
        """Persist the hard-stop intent before backend mutation."""
        def change(record):
            operation = record['journal'][-1]
            if (operation['id'] != operation_id or operation['kind'] != 'shutdown'
                    or operation['status'] != 'pending' or operation['phase'] != 'planned'):
                fail('STATE_CONFLICT', 'Hard-stop intent does not match the active shutdown operation.', 4)
            operation['phase'] = 'forcing'
            operation['events'].append('forcing')
        self.update(instance_id, operation_id, change)

    def allocate_fixtures(self, record, operation_id):
        """Create only two tiny test files; do not create qcow2 or NVRAM data."""
        self._registered(record, operation_id)
        path = self.paths.data / 'instances' / record['instance_id']
        with directory(self.paths.data / 'instances') as parent:
            os.mkdir(record['instance_id'], 0o700, dir_fd=parent)  # Do not reuse unknown directories.
            os.fsync(parent)
        with directory(path) as parent:
            info = os.fstat(parent)
            manifest = []
            for name in ('disk.fixture', 'nvram.fixture'):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(b'vm-dev-lab OFFLINE fixture\n')
                    stream.flush(); os.fsync(stream.fileno())
                    file_info = private_file(stream.fileno())
                    manifest.append(dict(path=name, device=file_info.st_dev, inode=file_info.st_ino))
            os.fsync(parent)
            def change(current):
                current['directory'] = dict(device=info.st_dev, inode=info.st_ino)
                current['manifest'] = manifest
            self.update(record['instance_id'], record['journal'][-1]['id'], change)

    def register_instance_files(self, record, operation_id, names):
        """Bind already-created private P06 control files to the registry."""
        self._registered(record, operation_id)
        if (not isinstance(names, (tuple, list)) or not names or len(set(names)) != len(names)
                or any(name not in MANIFEST_NAMES or name.endswith('.fixture') for name in names)):
            fail('PATH_INVALID', 'Invalid P06 manifest files.', 2)
        path = self.paths.data / 'instances' / record['instance_id']
        with directory(path) as parent:
            folder = os.fstat(parent)
            manifest = []
            for name in names:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    info = private_file(fd)
                    manifest.append(dict(path=name, device=info.st_dev, inode=info.st_ino))
                finally:
                    os.close(fd)
            def change(current):
                current['directory'] = dict(device=folder.st_dev, inode=folder.st_ino)
                current['manifest'] = manifest
            self.update(record['instance_id'], operation_id, change)

    def clear_instance_files(self, record, operation_id):
        """Remove the registry binding only after verified P06 cleanup."""
        self._registered(record, operation_id)
        def change(current):
            current['directory'] = None
            current['manifest'] = []
        self.update(record['instance_id'], operation_id, change)

    def specification(self, record):
        return dict(name=record['name'], uuid=record['domain_uuid'], uri=record['uri'],
                    metadata={k: record[k] for k in ('lab_id', 'instance_id', 'domain_uuid')}, autostart=False,
                    paths=[str(self.paths.data / 'instances' / record['instance_id'] / item['path']) for item in record['manifest']])

    @contextmanager
    def selection(self, record, operation_id=None, recover_failed_start=False,
                  recover_failed_create=False, recover_restore=False,
                  read_only_diagnostic=False):
        """Require positive fd-relative selection before cleanup; no recursion or pool cleanup."""
        self._registered(record, operation_id, recover_failed_start, recover_failed_create,
                         recover_restore, read_only_diagnostic)
        if record['uri'] != self.uri or record['directory'] is None or not record['manifest']:
            fail('OWNERSHIP_MISMATCH', 'URI or complete resource evidence is missing.')
        with directory(self.paths.data / 'instances' / record['instance_id']) as parent:
            info = os.fstat(parent)
            if record['directory'] != dict(device=info.st_dev, inode=info.st_ino):
                fail('OWNERSHIP_MISMATCH', 'Instance directory was replaced.')
            for item in record['manifest']:
                try:
                    fd = os.open(item['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        info = private_file(fd)
                        if (info.st_dev, info.st_ino) != (item['device'], item['inode']):
                            fail('OWNERSHIP_MISMATCH', 'Resource file was replaced.')
                    finally:
                        os.close(fd)
                except OSError:
                    fail('OWNERSHIP_MISMATCH', 'Manifest file is missing or unsafe.')
            yield parent

    def _registered(self, record, operation_id=None, recover_failed_start=False,
                    recover_failed_create=False, recover_restore=False,
                    read_only_diagnostic=False):
        uuid(record.get('instance_id'))
        with self.lock('global'):
            state = self._read()
            current = state['instances'].get(record['instance_id'])
            if current is None or current != {k: v for k, v in record.items() if k != 'requires_review'}:
                fail('REGISTRY_CONFLICT', 'No current registry ownership evidence.', 4)
            if record['lab_id'] != state['lab_id'] or record['uri'] != self.uri:
                fail('OWNERSHIP_MISMATCH', 'Lab or connection URI does not match.')
            operation = current['journal'][-1]
            reviewed_start = (recover_failed_start and operation['id'] == operation_id
                              and self._recoverable_start(operation))
            reviewed_create = (recover_failed_create and operation['id'] == operation_id
                               and self._recoverable_failed_create(operation))
            reviewed_restore = (recover_restore and operation['id'] == operation_id
                                and operation['kind'] in {'restore_activation','restore_recovery',
                                                          'restore_start_recovery'})
            diagnostic = (read_only_diagnostic and operation['id'] == operation_id)
            if ((operation['status'] == 'review_required'
                 and not (reviewed_start or reviewed_create or reviewed_restore or diagnostic))
                    or (operation['status'] == 'pending'
                        and operation['id'] != operation_id and not diagnostic)):
                fail('REVIEW_REQUIRED', 'Pending or failed operation requires review.', 4)

    def verify(self, record, domain, operation_id=None):
        self._registered(record, operation_id)
        expected = self.specification(record)
        if (not isinstance(domain, dict) or set(domain) != set(expected) | {'running'}
                or type(domain['running']) is not bool or domain.get('autostart') is not False
                or any(domain.get(k) != v for k, v in expected.items())):
            fail('OWNERSHIP_MISMATCH', 'Domain UUID, URI, metadata, or resource paths conflict with the registry.')
        with self.selection(record, operation_id):
            pass
