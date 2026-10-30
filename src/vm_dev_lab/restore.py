# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Prepare, activate, and recover verified restore generations.

"""P08-B1: validate a restore and prepare an inactive generation."""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import xml.etree.ElementTree as ET
from uuid import UUID, uuid4

from .baselines import (ALL_FILES as BASELINE_FILES, BaselineManager, SPACE_RESERVE, _copy_file,
                        _parse_qemu_info, _read_json, canonical, sha256)
from .errors import LabError
from .libvirt_backend import (OWNER_NS, backing_store_input, immutable_backing_store,
                              set_immutable_backing_store)
from .lifecycle import RealOwnership, load_host_record
from .resources import allocated_bytes, request as resource_request
from .state import directory, private_file


SCHEMA_VERSION = 1
ARTIFACTS = ('disk.qcow2', 'nvram.fd', 'domain.xml')
READY_FILES = frozenset((*ARTIFACTS, 'preparation.json'))
ACTIVE_FILES = frozenset((*READY_FILES, 'activation.json', 'guest-manifest.json',
                          'previous-guest-manifest.json'))
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def fail(code, phase, message, status=6, hint=None, retryable=False):
    raise LabError(status, code, phase, message, hint or
                   'Inspect restore preparation, ownership, and staging; do not delete anything automatically.',
                   retryable)


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _identity(path):
    try:
        info = os.lstat(path)
    except OSError:
        fail('RESTORE_PATH_UNSAFE', 'staging', 'Restore artifact is missing or cannot be accessed safely.', 5)
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1 or info.st_uid != os.geteuid()):
        fail('RESTORE_PATH_UNSAFE', 'staging',
             'Restore artifact is not an unambiguous owned regular file.', 5)
    return {'device': info.st_dev, 'inode': info.st_ino}


@contextmanager
def _restore_directory(path, *, create=False):
    """Open owned restore directories, including with an ACL traversal mask."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        fail('RESTORE_PATH_UNSAFE', 'access', 'Restore directory is not bound absolutely.', 5)
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=current)
            os.close(current); current = child
        info = os.fstat(current); mode = stat.S_IMODE(info.st_mode)
        if (info.st_uid != os.geteuid() or mode & 0o007 or mode & 0o060
                or mode not in {0o700, 0o710}):
            fail('RESTORE_PATH_UNSAFE', 'access',
                 'Restore directory has unexpected ownership or mode permissions.', 5)
        yield current
    except LabError:
        raise
    except OSError:
        fail('RESTORE_PATH_UNSAFE', 'access',
             'Restore directory is missing, replaced, or not safely accessible.', 5)
    finally:
        os.close(current)


class RestoreRuntimeAccess:
    """Bind minimal effective POSIX ACLs to the qualified QEMU worker."""

    def __init__(self, *, clock, tool, lookup=pwd.getpwnam,
                 lookup_uid=pwd.getpwuid, lookup_gid=grp.getgrgid):
        self.clock, self.tool = clock, tool
        self.lookup, self.lookup_uid, self.lookup_gid = lookup, lookup_uid, lookup_gid

    def _account(self, value, *, owner=False):
        try:
            if (set(value) != {'name', 'uid', 'gid'}
                    or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', value['name'])
                    or type(value['uid']) is not int or type(value['gid']) is not int
                    or not 0 < value['uid'] < 4294967295
                    or not 0 < value['gid'] < 4294967295
                    or (owner and value['uid'] != os.geteuid())):
                raise ValueError
            by_name = self.lookup(value['name'])
            by_uid = self.lookup_uid(value['uid'])
            by_gid = self.lookup_gid(value['gid'])
            expected = (value['name'], value['uid'], value['gid'])
            if ((by_name.pw_name, by_name.pw_uid, by_name.pw_gid) != expected
                    or (by_uid.pw_name, by_uid.pw_uid, by_uid.pw_gid) != expected
                    or by_gid.gr_gid != value['gid']):
                raise ValueError
            return value
        except (KeyError, OverflowError, TypeError, ValueError):
            fail('RESTORE_OWNER_INVALID' if owner else 'RESTORE_WORKER_INVALID', 'access',
                 ('Storage owner' if owner else 'QEMU worker')
                 + ' is not bound unambiguously in qualified host evidence.', 5)

    def owner(self, plan):
        try:
            return self._account(plan['owner'], owner=True)
        except KeyError:
            fail('RESTORE_OWNER_INVALID', 'access',
                 'Storage owner is missing from qualified host evidence.', 5)

    def worker(self, plan):
        try:
            value = self._account(plan['qemu'])
            if value['uid'] == os.geteuid():
                raise ValueError
            return value
        except (KeyError, ValueError):
            fail('RESTORE_WORKER_INVALID', 'access',
                 'QEMU worker is not bound unambiguously in qualified host evidence.', 5)

    def _run(self, argv, deadline, code):
        if self.clock() >= deadline:
            fail('DEADLINE_EXCEEDED', 'access', 'Overall access-validation deadline exceeded.', 7,
                 retryable=True)
        result = self.tool(argv, deadline)
        if result.returncode:
            fail(code, 'access', 'Restore access permissions could not be set or verified safely.', 6)
        try:
            return result.stdout.decode('ascii')
        except (AttributeError, UnicodeDecodeError):
            fail('RESTORE_ACCESS_INVALID', 'access', 'POSIX ACL output is invalid.', 5)

    @staticmethod
    def _paths(operation):
        operation = Path(operation)
        return (operation.parent.parent, operation.parent, operation)

    @staticmethod
    def _baseline_paths(bundle):
        bundle = Path(bundle)
        return (bundle.parent.parent, bundle.parent, bundle)

    @staticmethod
    def _safe(path, directory=False):
        try:
            info = os.lstat(path)
        except OSError:
            fail('RESTORE_PATH_UNSAFE', 'access', 'Restore access path is missing.', 5)
        valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not valid_type or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
                or (not directory and info.st_nlink != 1)):
            fail('RESTORE_PATH_UNSAFE', 'access',
                 'Restore access path is replaced, linked, or foreign.', 5)
        return (info.st_dev, info.st_ino)

    @staticmethod
    def _acl(raw):
        entries = {}
        try:
            for line in raw.splitlines():
                if not line or line.startswith('#'):
                    continue
                if line.startswith('default:'):
                    raise ValueError
                parts = line.split('\t', 1)[0].split(':')
                if len(parts) != 3 or parts[0] not in {'user', 'group', 'mask', 'other'}:
                    raise ValueError
                key = (parts[0], parts[1])
                if key in entries or not re.fullmatch(r'[r-][w-][x-]', parts[2]):
                    raise ValueError
                entries[key] = parts[2]
            return entries
        except (TypeError, ValueError):
            fail('RESTORE_ACCESS_INVALID', 'access',
                 'POSIX ACL output is incomplete or ambiguous.', 5)

    @staticmethod
    def _permission_subset(actual, allowed):
        return all(value == '-' or allowed[index] != '-'
                   for index, value in enumerate(actual))

    @staticmethod
    def _effective(value, mask):
        return ''.join(item if mask[index] != '-' else '-'
                       for index, item in enumerate(value))

    def _restricted_acl(self, access, defaults, worker, expected):
        required = {('user',''), ('group',''), ('other','')}
        optional = {('mask',''), ('user', str(worker['uid']))}
        if (not required <= set(access) or not set(access) <= required | optional
                or defaults or access[('user','')] != expected['owner']
                or access[('group','')] != '---' or access[('other','')] != '---'):
            return False
        named = access.get(('user', str(worker['uid'])), '---')
        mask = access.get(('mask',''), access[('group','')])
        return self._permission_subset(
            self._effective(named, mask), expected['effective'])

    @staticmethod
    def _legacy_acl(access, defaults, owner, worker, expected, directory):
        if owner['uid'] == worker['uid'] or 4294967295 in {owner['uid'], worker['uid']}:
            return False
        base = {('user',''), ('group',''), ('mask',''), ('other','')}
        named = {('user', str(owner['uid'])), ('user', str(worker['uid']))}
        expected_access = {
            ('user',''): expected['owner'],
            ('user',str(owner['uid'])): 'rwx',
            ('user',str(worker['uid'])): 'rwx',
            ('group',''): '---',
            ('mask',''): expected['legacy_mask'],
            ('other',''): '---',
        }
        expected_default = {
            ('user',''): 'rwx',
            ('user',str(owner['uid'])): 'rwx',
            ('user',str(worker['uid'])): 'rwx',
            ('group',''): '---',
            ('mask',''): 'rwx',
            ('other',''): '---',
        }
        return (set(access) == base | named and access == expected_access
                and ((directory and defaults == expected_default)
                     or (not directory and not defaults)))

    def _repairable_acl(self, path, owner, worker, expected, deadline, *, directory=False):
        raw = self._run(['getfacl', '--numeric', '--omit-header', '--absolute-names',
                         '--', str(path)], deadline, 'RESTORE_ACCESS_INVALID')
        access, defaults = {}, {}
        try:
            for line in raw.splitlines():
                if not line or line.startswith('#'):
                    continue
                target = defaults if line.startswith('default:') else access
                value = line[8:] if line.startswith('default:') else line
                parts = value.split('\t', 1)[0].split(':')
                if len(parts) != 3 or parts[0] not in {'user','group','mask','other'}:
                    raise ValueError
                key = (parts[0], parts[1])
                if key in target or not re.fullmatch(r'[r-][w-][x-]', parts[2]):
                    raise ValueError
                if parts[1] == '4294967295':
                    raise ValueError
                target[key] = parts[2]
            if (not self._restricted_acl(access, defaults, worker, expected)
                    and not self._legacy_acl(
                        access, defaults, owner, worker, expected, directory)):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            fail('RESTORE_ACCESS_NOT_REPAIRABLE', 'access',
                 'Existing ACLs cannot be limited unambiguously to the narrow restore contract.', 5)

    def repairable(self, operation, plan, deadline):
        """Accept only restrictive legacy or partial ACLs without foreign principals."""
        owner, worker = self.owner(plan), self.worker(plan)
        for path in self._paths(operation):
            self._safe(path, True)
            self._repairable_acl(
                path, owner, worker,
                {'owner':'rwx', 'effective':'--x', 'legacy_mask':'---'}, deadline,
                directory=True)
        for name in ACTIVE_FILES:
            path = Path(operation)/name; self._safe(path)
            expected = {
                'owner':'rw-',
                'effective':'rw-' if name in {'disk.qcow2','nvram.fd'} else '---',
                'legacy_mask':'r--' if name == 'disk.qcow2' else '---',
            }
            self._repairable_acl(path, owner, worker, expected, deadline)

    def repairable_baseline(self, bundle, plan, deadline):
        """Accept only private or qualified inherited baseline ACLs."""
        owner, worker = self.owner(plan), self.worker(plan)
        for path in self._baseline_paths(bundle):
            self._safe(path, True)
            self._repairable_acl(
                path, owner, worker,
                {'owner':'rwx', 'effective':'--x', 'legacy_mask':'---'}, deadline,
                directory=True)
        for name in BASELINE_FILES:
            path = Path(bundle)/name; self._safe(path)
            expected = {
                'owner':'rw-',
                'effective':'r--' if name == 'disk.qcow2' else '---',
                'legacy_mask':'r--' if name == 'disk.qcow2' else '---',
            }
            self._repairable_acl(path, owner, worker, expected, deadline)

    def _verify_acl(self, path, worker, expected, deadline):
        raw = self._run(['getfacl', '--numeric', '--omit-header', '--absolute-names',
                         '--', str(path)], deadline, 'RESTORE_ACCESS_INVALID')
        entries = self._acl(raw)
        allowed = {('user', ''), ('group', ''), ('mask', ''), ('other', '')}
        if expected['worker'] is not None:
            allowed.add(('user', str(worker['uid'])))
        if (set(entries) != allowed or entries[('user', '')] != expected['owner']
                or (expected['worker'] is not None
                    and entries[('user', str(worker['uid']))] != expected['worker'])
                or entries[('group', '')] != '---'
                or entries[('mask', '')] != expected['mask']
                or entries[('other', '')] != '---'):
            fail('RESTORE_ACCESS_INVALID', 'access',
                 'Effective restore ACL does not match the minimal worker contract.', 5)

    def _verify_chain(self, operation, bundle, deadline, baseline_binding=None):
        overlay = Path(operation)/'disk.qcow2'
        baseline = Path(bundle)/'disk.qcow2'
        identities = {overlay: self._safe(overlay), baseline: self._safe(baseline)}
        if baseline_binding is not None:
            try:
                manifest_disk = _read_json(Path(bundle)/'manifest.json')['files']['disk.qcow2']
                info = os.lstat(baseline)
                if (set(baseline_binding) != {'path','device','inode','size','sha256'}
                        or baseline_binding['path'] != str(baseline)
                        or {key:baseline_binding[key] for key in ('device','inode')}
                           != {'device':info.st_dev, 'inode':info.st_ino}
                        or baseline_binding['size'] != info.st_size
                        or baseline_binding['size'] != manifest_disk['size']
                        or baseline_binding['sha256'] != manifest_disk['sha256']):
                    raise ValueError
            except (KeyError, OSError, TypeError, ValueError):
                fail('RESTORE_PATH_UNSAFE', 'access',
                     'Baseline disk does not match its persisted inode binding.', 5)
        raw = self._run(
            ['qemu-img','info','--output=json','--backing-chain',str(overlay)],
            deadline, 'RESTORE_BACKING_INVALID')
        try:
            chain = json.loads(raw)
            first, second = chain
            backing = first.get('full-backing-filename', first.get('backing-filename'))
            stored_backing = first.get('backing-filename')
            if (len(chain) != 2 or first.get('format') != 'qcow2'
                    or second.get('format') != 'qcow2'
                    or first.get('filename') != str(overlay)
                    or backing != str(baseline)
                    or (stored_backing is not None and stored_backing != str(baseline))
                    or first.get('backing-filename-format', 'qcow2') != 'qcow2'
                    or second.get('filename') != str(baseline)
                    or any(key in second for key in
                           ('backing-filename','full-backing-filename','data-file','encrypted'))
                    or any(key in first for key in ('data-file','encrypted'))):
                raise ValueError
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            fail('RESTORE_BACKING_INVALID', 'access',
                 'qcow2 backing chain is not bound exactly to the verified baseline.', 5)
        if any(self._safe(path) != identity for path, identity in identities.items()):
            fail('RESTORE_PATH_UNSAFE', 'access',
                 'Backing chain was replaced during validation.', 5)

    def apply(self, operation, plan, deadline, *, baseline=None, baseline_binding=None):
        worker = self.worker(plan); directories = self._paths(operation)
        files = [Path(operation)/name for name in ACTIVE_FILES]
        identities = {path: self._safe(path, True) for path in directories}
        identities.update({path: self._safe(path) for path in files})
        baseline_directories = self._baseline_paths(baseline) if baseline else ()
        baseline_files = ([Path(baseline)/name for name in BASELINE_FILES]
                          if baseline else [])
        if baseline:
            self._verify_chain(operation, baseline, deadline, baseline_binding)
            self.repairable_baseline(baseline, plan, deadline)
            identities.update({path: self._safe(path, True)
                               for path in baseline_directories})
            identities.update({path: self._safe(path) for path in baseline_files})
        directory_acl = f'u::rwx,u:{worker["uid"]}:--x,g::---,m::--x,o::---'
        data_acl = f'u::rw-,u:{worker["uid"]}:rw-,g::---,m::rw-,o::---'
        baseline_disk_acl = f'u::rw-,u:{worker["uid"]}:r--,g::---,m::r--,o::---'
        private_acl = 'u::rw-,g::---,m::---,o::---'
        for path in directories:
            self._run(['setfacl', '--remove-default', '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
            self._run(['setfacl', '--set', directory_acl, '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
        for path in files:
            acl = data_acl if path.name in {'disk.qcow2', 'nvram.fd'} else private_acl
            self._run(['setfacl', '--set', acl, '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
        for path in baseline_directories:
            self._run(['setfacl', '--remove-default', '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
            self._run(['setfacl', '--set', directory_acl, '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
        for path in baseline_files:
            acl = baseline_disk_acl if path.name == 'disk.qcow2' else private_acl
            self._run(['setfacl', '--set', acl, '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
        all_directories = set(directories) | set(baseline_directories)
        if any(self._safe(path, path in all_directories) != identity
               for path, identity in identities.items()):
            fail('RESTORE_PATH_UNSAFE', 'access',
                 'Restore path was replaced during ACL binding.', 5)
        self.verify(operation, plan, deadline, baseline=baseline,
                    baseline_binding=baseline_binding)

    def apply_baseline(self, bundle, plan, deadline, baseline_binding):
        """Normalize only the already bound immutable baseline."""
        worker = self.worker(plan)
        directories = self._baseline_paths(bundle)
        files = [Path(bundle)/name for name in BASELINE_FILES]
        self._verify_chain(Path(baseline_binding['overlay']).parent, bundle, deadline,
                           {key: baseline_binding[key] for key in
                            ('path','device','inode','size','sha256')})
        self.repairable_baseline(bundle, plan, deadline)
        identities = {path: self._safe(path, True) for path in directories}
        identities.update({path: self._safe(path) for path in files})
        directory_acl = f'u::rwx,u:{worker["uid"]}:--x,g::---,m::--x,o::---'
        baseline_disk_acl = f'u::rw-,u:{worker["uid"]}:r--,g::---,m::r--,o::---'
        private_acl = 'u::rw-,g::---,m::---,o::---'
        for path in directories:
            self._run(['setfacl', '--remove-default', '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
            self._run(['setfacl', '--set', directory_acl, '--', str(path)], deadline,
                      'RESTORE_ACCESS_FAILED')
        for path in files:
            self._run(['setfacl', '--set',
                       baseline_disk_acl if path.name == 'disk.qcow2' else private_acl,
                       '--', str(path)], deadline, 'RESTORE_ACCESS_FAILED')
        if any(self._safe(path, path in directories) != identity
               for path, identity in identities.items()):
            fail('RESTORE_PATH_UNSAFE', 'access',
                 'Baseline path was replaced during ACL normalization.', 5)
        self.verify_baseline(bundle, plan, deadline,
                             {key: baseline_binding[key] for key in
                              ('path','device','inode','size','sha256')},
                             Path(baseline_binding['overlay']).parent)

    def verify_baseline(self, bundle, plan, deadline, baseline_binding, operation):
        worker = self.worker(plan)
        self._verify_chain(operation, bundle, deadline, baseline_binding)
        for path in self._baseline_paths(bundle):
            self._safe(path, True)
            self._verify_acl(path, worker,
                             {'owner':'rwx', 'worker':'--x', 'mask':'--x'}, deadline)
        for name in BASELINE_FILES:
            path = Path(bundle)/name; self._safe(path)
            expected = ({'owner':'rw-', 'worker':'r--', 'mask':'r--'}
                        if name == 'disk.qcow2' else
                        {'owner':'rw-', 'worker':None, 'mask':'---'})
            self._verify_acl(path, worker, expected, deadline)

    def verify(self, operation, plan, deadline, *, baseline=None, baseline_binding=None):
        worker = self.worker(plan)
        for path in self._paths(operation):
            self._safe(path, True)
            self._verify_acl(path, worker,
                             {'owner': 'rwx', 'worker': '--x', 'mask': '--x'}, deadline)
        for name in ACTIVE_FILES:
            path = Path(operation)/name; self._safe(path)
            expected = ({'owner': 'rw-', 'worker': 'rw-', 'mask': 'rw-'}
                        if name in {'disk.qcow2', 'nvram.fd'} else
                        {'owner': 'rw-', 'worker': None, 'mask': '---'})
            self._verify_acl(path, worker, expected, deadline)
        if baseline:
            self._verify_chain(operation, baseline, deadline, baseline_binding)
            for path in self._baseline_paths(baseline):
                self._safe(path, True)
                self._verify_acl(path, worker,
                                 {'owner':'rwx', 'worker':'--x', 'mask':'--x'}, deadline)
            for name in BASELINE_FILES:
                path = Path(baseline)/name; self._safe(path)
                expected = ({'owner':'rw-', 'worker':'r--', 'mask':'r--'}
                            if name == 'disk.qcow2' else
                            {'owner':'rw-', 'worker':None, 'mask':'---'})
                self._verify_acl(path, worker, expected, deadline)


def _atomic_manifest(path, value, *, create=False):
    raw = canonical(value)
    if len(raw) > 1024 * 1024:
        fail('RESTORE_PREPARATION_INVALID', 'staging', 'Preparation manifest exceeds the limit.', 5)
    with directory(path.parent) as parent:
        name = path.name if create else '.preparation-' + str(uuid4()) + '.tmp'
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if not create:
                os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        except OSError as error:
            if error.errno == errno.ENOSPC:
                fail('RESTORE_NO_SPACE', 'staging',
                     'Storage space exhausted while writing the preparation manifest.', 6)
            if error.errno == errno.EEXIST:
                fail('RESTORE_OPERATION_EXISTS', 'staging',
                     'Restore operation or manifest already exists.', 4)
            fail('RESTORE_STAGING_IO', 'staging',
                 'Preparation manifest could not be written safely.', 6)


def _parse_xml(raw):
    if len(raw) > 1024 * 1024 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        fail('RESTORE_XML_INCOMPATIBLE', 'compatibility', 'Domain XML is unsafe or too large.', 5)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        fail('RESTORE_XML_INCOMPATIBLE', 'compatibility', 'Domain XML is corrupted.', 5)
    if root.tag != 'domain':
        fail('RESTORE_XML_INCOMPATIBLE', 'compatibility', 'Unerwartetes Domain-XML-Format.', 5)
    return root


def _compatible_xml(root):
    """Compare machine model and identity, not generation paths."""
    value = deepcopy(root)
    writable = [disk for disk in value.findall('./devices/disk')
                if disk.get('device') == 'disk' and disk.find('readonly') is None]
    if len(writable) != 1 or writable[0].find('source') is None:
        fail('RESTORE_XML_INCOMPATIBLE', 'compatibility',
             'Domain does not have exactly one supported working disk.', 5)
    writable[0].find('source').set('file', '@RESTORE-DISK@')
    for store in writable[0].findall('backingStore'):
        writable[0].remove(store)
    nvram = value.find('./os/nvram')
    if nvram is None:
        fail('RESTORE_XML_INCOMPATIBLE', 'compatibility', 'Domain has no NVRAM.', 5)
    nvram.text = '@RESTORE-NVRAM@'
    return ET.tostring(value)


class RestorePreparationManager:
    """Prepare B1 artifacts without mutating the domain or active registry."""

    def __init__(self, lifecycle, *, clock, tool, now=None, disk_usage=shutil.disk_usage):
        self.lifecycle = lifecycle
        self.store = lifecycle.store
        self.backend = lifecycle.backend
        self.clock = clock
        self.tool = tool
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.disk_usage = disk_usage
        self.baselines = BaselineManager(lifecycle, clock=clock, tool=tool,
                                         now=now, disk_usage=disk_usage)
        self.resources = lifecycle.resources

    def _tool(self, args, deadline, phase='staging'):
        if self.clock() >= deadline:
            fail('DEADLINE_EXCEEDED', phase, 'Overall deadline exceeded.', 7,
                 retryable=True)
        result = self.tool(args, deadline)
        if result.returncode:
            fail('RESTORE_DISK_TOOL_FAILED', phase,
                 'qemu-img could not create or verify the restore disk.', 6)
        return result.stdout

    def _plan(self):
        plan = (deepcopy(self.lifecycle.host_record) if self.lifecycle.host_record is not None
                else load_host_record())
        try:
            storage = Path(plan['storage'])
            reserve = plan['reserve_gib']
            info = os.lstat(storage)
            if (not storage.is_absolute() or '..' in storage.parts
                    or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid() or type(reserve) is not int
                    or not 0 <= reserve <= 16384):
                raise ValueError
        except (KeyError, OSError, TypeError, ValueError):
            fail('RESTORE_STORAGE_UNAVAILABLE', 'preflight',
                 'Qualified storage is not bound safely for restore staging.', 5)
        return plan

    def _roots(self, data, operation_id):
        pool = Path(data['storage']).parent
        root = pool / '.restore-staging'
        instance = root / data['instance_id']
        operation = instance / operation_id
        return root, instance, operation

    def _current(self, target, deadline):
        record = self.store.inspect(target)
        if record['state'] == 'destroyed':
            fail('RESTORE_TARGET_DESTROYED', 'preflight',
                 'P08-B1 prepares restore only for an existing instance.', 4)
        if record['requires_review']:
            fail('REVIEW_REQUIRED', 'state',
                 'Incomplete lifecycle operation blocks restore preparation.', 4)
        domain = self.backend.domain(record['domain_uuid'])
        owner = RealOwnership(self.store, self.backend)
        data = owner.verify(record, domain)
        if domain.isActive():
            fail('DOMAIN_RUNNING', 'preflight', 'Restore preparation requires a powered-off VM.', 4)
        managed = getattr(domain, 'hasManagedSaveImage', None)
        if managed is None or managed(0):
            fail('MANAGED_SAVE_UNSUPPORTED', 'preflight',
                 'Managed-save evidence is missing or a managed save exists.', 4)
        xml_raw = domain.XMLDesc(0).encode()
        root = _parse_xml(xml_raw)
        disk, nvram = self._active_paths(data)
        generation = data.get('restore_generation')
        baseline_path = (Path(data['storage']).parent/'baselines'/record['instance_id'] /
                         generation['baseline_id']/'disk.qcow2') if generation else None
        if not self._domain_storage_valid(
                root, Path(data['storage']), disk, nvram, baseline_path):
            fail('PERSISTENT_DEVICE_UNSUPPORTED', 'preflight',
                 'Unknown disk, TPM, or other persistent state is rejected.', 4)
        plan = self._plan()
        if Path(data['storage']).parent != Path(plan['storage']):
            fail('RESTORE_STORAGE_UNAVAILABLE', 'preflight',
                 'Instance is not in qualified restore storage.', 5)
        try:
            capabilities = self.backend.connect().getDomainCapabilities(
                None, 'x86_64', 'q35', 'kvm', 0)
            supported = backing_store_input(capabilities)
        except Exception:
            fail('RESTORE_BACKING_STORE_UNSUPPORTED', 'preflight',
                 'Domain capabilities for the safe backing chain are unreadable.', 3)
        if not supported:
            fail('RESTORE_BACKING_STORE_UNSUPPORTED', 'preflight',
                 'libvirt does not confirm backingStoreInput for the restore domain.', 3)
        registry = {key: value for key, value in record.items() if key != 'requires_review'}
        binding = {
            'registry_sha256': hashlib.sha256(canonical(registry)).hexdigest(),
            'last_operation_id': record['journal'][-1]['id'],
            'domain_xml_sha256': hashlib.sha256(xml_raw).hexdigest(),
            'disk': self._file_binding(disk, deadline),
            'nvram': self._file_binding(nvram, deadline),
        }
        return record, domain, owner, data, xml_raw, root, plan, binding

    @staticmethod
    def _active_paths(data):
        generation = data.get('restore_generation')
        if generation:
            root = Path(generation['path'])
            return root / 'disk.qcow2', root / 'nvram.fd'
        storage = Path(data['storage'])
        return storage / 'work.qcow2', storage / 'nvram.fd'

    @staticmethod
    def _domain_storage_valid(root, storage, work_path, nvram_path, baseline_path=None):
        disks = root.findall('./devices/disk')
        if len(disks) != 2:
            return False
        by_source = {}
        for disk in disks:
            source = disk.find('source')
            if source is None or set(source.attrib) != {'file'}:
                return False
            by_source[source.get('file')] = disk
        work = by_source.get(str(work_path)); seed = by_source.get(str(storage/'seed.iso'))
        backing_valid = (immutable_backing_store(work, baseline_path)
                         if baseline_path is not None and work is not None
                         else work is not None and work.find('backingStore') is None)
        return (set(by_source) == {str(work_path), str(storage/'seed.iso')}
                and work is not None and work.get('device') == 'disk'
                and work.find('readonly') is None and work.find('driver') is not None
                and work.find('driver').get('type') == 'qcow2'
                and backing_valid
                and seed is not None and seed.get('device') == 'cdrom'
                and seed.find('readonly') is not None
                and root.findtext('./os/nvram') == str(nvram_path)
                and root.find('./devices/tpm') is None
                and root.find('./devices/filesystem') is None
                and root.find('./devices/hostdev') is None)

    def _file_binding(self, path, deadline):
        identity = _identity(path)
        info = os.lstat(path)
        return {'path': str(path), **identity, 'size': info.st_size,
                'sha256': sha256(path, deadline=deadline, clock=self.clock)}

    @staticmethod
    def _target(record, data):
        return {key: data[key] for key in
                ('lab_id', 'instance_id', 'domain_uuid', 'name', 'uri', 'mac')}

    def _compatibility(self, record, data, xml_raw, root, manifest, bundle, deadline):
        target = self._target(record, data)
        if (manifest['instance'] != target
                or manifest['source']['image_sha256'] != data['image_sha256']
                or manifest['guest_identity']['seed_instance_id']
                    != data['seed']['seed_instance_id']):
            fail('RESTORE_IDENTITY_MISMATCH', 'compatibility',
                 'Baseline and target instance do not have the same complete identity.', 5)
        baseline_xml = (bundle / 'domain.xml').read_bytes()
        if _compatible_xml(_parse_xml(baseline_xml)) != _compatible_xml(root):
            fail('RESTORE_XML_INCOMPATIBLE', 'compatibility',
                 'Current domain XML differs from the baseline contract.', 4)
        loader = root.findtext('./os/loader')
        firmware = Path(manifest['firmware']['code_path'])
        if (loader != str(firmware) or not firmware.is_file()
                or sha256(firmware, deadline=deadline, clock=self.clock)
                    != manifest['firmware']['code_sha256']):
            fail('RESTORE_FIRMWARE_INCOMPATIBLE', 'compatibility',
                 'Firmware path or firmware hash is incompatible with the baseline.', 3)
        current_info = _parse_qemu_info(self._tool(
            ['qemu-img', 'info', '--output=json', str(self._active_paths(data)[0])],
            deadline, 'compatibility'))
        if current_info['virtual-size'] != manifest['disk']['virtual_size']:
            fail('RESTORE_DISK_INCOMPATIBLE', 'compatibility',
                 'Virtual target disk size differs from the baseline.', 4)
        return target

    def _prepared_xml(self, xml_raw, data, operation, baseline_disk):
        root = _parse_xml(xml_raw)
        storage = Path(data['storage'])
        active_disk, active_nvram = self._active_paths(data)
        work = None
        for disk in root.findall('./devices/disk'):
            source = disk.find('source')
            if source is not None and source.get('file') == str(active_disk):
                work = disk
        nvram = root.find('./os/nvram')
        if work is None or nvram is None or nvram.text != str(active_nvram):
            fail('RESTORE_XML_INCOMPATIBLE', 'compatibility',
                 'Disk or NVRAM path is missing from domain XML.', 5)
        work.find('source').set('file', str(operation / 'disk.qcow2'))
        set_immutable_backing_store(work, baseline_disk)
        nvram.text = str(operation / 'nvram.fd')
        return ET.tostring(root, encoding='utf-8')

    def _artifact(self, path, deadline):
        info = os.lstat(path)
        return {'path': str(path), **_identity(path), 'size': info.st_size,
                'sha256': sha256(path, deadline=deadline, clock=self.clock)}

    def _manifest(self, operation_id, generation_id, target, baseline_id, binding):
        return {
            'schema_version': SCHEMA_VERSION,
            'operation_id': operation_id,
            'generation_id': generation_id,
            'created_at': self.now().isoformat().replace('+00:00', 'Z'),
            'status': 'preparing',
            'events': ['planned'],
            'target': target,
            'baseline_id': baseline_id,
            'current_generation': binding,
            'artifacts': {},
            'error': None,
            'activation': {'permitted': False, 'requires_reverification': True},
        }

    def _validate_manifest(self, value, operation, *, require_prepared=False):
        expected = {'schema_version','operation_id','generation_id','created_at','status','events',
                    'target','baseline_id','current_generation','artifacts','error','activation'}
        if (not isinstance(value, dict) or set(value) != expected
                or value['schema_version'] != SCHEMA_VERSION
                or not _uuid(value['operation_id']) or operation.name != value['operation_id']
                or not _uuid(value['generation_id'])
                or value['status'] not in {'preparing','prepared','failed','interrupted'}
                or not isinstance(value['events'], list) or not value['events']
                or value['events'][0] != 'planned'
                or any(event not in {'planned','disk-staged','nvram-staged','verified',
                                     'failed','interrupted'} for event in value['events'])
                or not isinstance(value['baseline_id'], str)
                or not SHA256.fullmatch(value['baseline_id'])
                or value['activation'] != {'permitted': False, 'requires_reverification': True}):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Preparation manifest is unknown or incomplete.', 5)
        target = value['target']
        if (not isinstance(target, dict)
                or set(target) != {'lab_id','instance_id','domain_uuid','name','uri','mac'}
                or not all(_uuid(target[key]) for key in ('lab_id','instance_id','domain_uuid'))
                or not isinstance(target['name'], str)
                or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', target['name'])
                or target['uri'] != 'qemu:///system'
                or not isinstance(target['mac'], str)
                or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', target['mac'])):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Preparation target identity is invalid.', 5)
        try:
            timestamp = datetime.fromisoformat(value['created_at'].replace('Z', '+00:00'))
        except (ValueError, TypeError, AttributeError):
            timestamp = None
        if (timestamp is None or timestamp.tzinfo is None
                or not isinstance(value['created_at'], str)
                or not re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[^Z]+Z',
                                    value['created_at'])):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Preparation timestamp is invalid.', 5)
        binding = value['current_generation']
        if (not isinstance(binding, dict)
                or set(binding) != {'registry_sha256','last_operation_id','domain_xml_sha256','disk','nvram'}
                or not SHA256.fullmatch(binding['registry_sha256'] or '')
                or not SHA256.fullmatch(binding['domain_xml_sha256'] or '')
                or not _uuid(binding['last_operation_id'])):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Source generation is not bound completely.', 5)
        for name in ('disk', 'nvram'):
            self._validate_artifact(binding[name], None)
        artifacts = value['artifacts']
        if (not isinstance(artifacts, dict) or not set(artifacts).issubset(ARTIFACTS)):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Preparation artifact list is invalid.', 5)
        for name, artifact in artifacts.items():
            self._validate_artifact(artifact, operation / name)
        terminal = value['status'] in {'failed','interrupted'}
        if (terminal != (value['events'][-1] in {'failed','interrupted'})
                or (terminal and (not isinstance(value['error'], dict)
                    or set(value['error']) != {'code','phase'}
                    or not all(isinstance(item, str) and item for item in value['error'].values())))
                or (not terminal and value['error'] is not None)):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Status, events, and failure evidence conflict.', 5)
        if require_prepared and (value['status'] != 'prepared'
                                 or value['events'] != ['planned','disk-staged','nvram-staged','verified']
                                 or set(value['artifacts']) != set(ARTIFACTS)
                                 or value['error'] is not None):
            fail('RESTORE_PREPARATION_INCOMPLETE', 'verification',
                 'Restore generation is not prepared completely.', 4)
        return value

    @staticmethod
    def _validate_artifact(value, expected_path):
        if (not isinstance(value, dict)
                or set(value) != {'path','device','inode','size','sha256'}
                or not isinstance(value['path'], str)
                or not Path(value['path']).is_absolute() or '..' in Path(value['path']).parts
                or any(type(value[key]) is not int or value[key] < 0
                       for key in ('device','inode','size'))
                or not isinstance(value['sha256'], str)
                or not SHA256.fullmatch(value['sha256'])
                or (expected_path is not None and Path(value['path']) != expected_path)):
            fail('RESTORE_PREPARATION_INVALID', 'verification',
                 'Preparation path, inode, or hash binding is invalid.', 5)

    def _mark_failed(self, path, manifest, error):
        try:
            current = deepcopy(manifest)
            interrupted = isinstance(error, (KeyboardInterrupt, SystemExit))
            current['status'] = 'interrupted' if interrupted else 'failed'
            current['events'] = [*current['events'], current['status']]
            current['error'] = {
                'code': (error.detail['code'] if isinstance(error, LabError)
                         else 'INTERRUPTED' if interrupted else 'RESTORE_STAGING_IO'),
                'phase': (error.detail['phase'] if isinstance(error, LabError) else 'staging'),
            }
            _atomic_manifest(path, current)
        except BaseException:
            # The already persisted "preparing" state remains conservative interruption evidence.
            pass

    def prepare(self, target, baseline_id, operation_id, deadline):
        if not _uuid(operation_id):
            fail('RESTORE_OPERATION_INVALID', 'validation', 'Restore operation ID is invalid.', 2)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record, domain, owner, data, xml_raw, root, plan, binding = self._current(
                initial['instance_id'], deadline)
            verified = self.baselines.verify(record['instance_id'], baseline_id, deadline)
            bundle = Path(verified['path'])
            manifest = _read_json(bundle / 'manifest.json')
            target_identity = self._compatibility(
                record, data, xml_raw, root, manifest, bundle, deadline)
            needed = (manifest['disk']['virtual_size']
                      + manifest['files']['nvram.fd']['size']
                      + plan['reserve_gib'] * 1024 ** 3 + SPACE_RESERVE)
            staging_root, instance_root, operation = self._roots(data, operation_id)
            free_bytes = self.disk_usage(Path(data['storage']).parent).free
            if free_bytes < needed:
                fail('RESTORE_NO_SPACE', 'preflight',
                     'Free space is insufficient for the generation, host reserve, and staging reserve.', 6)
            self.resources.reserve(
                record['instance_id'], operation_id, 'restore',
                resource_request(virtual_disk_bytes=manifest['disk']['virtual_size'],
                                 staging_bytes=(manifest['disk']['virtual_size']
                                                + manifest['files']['nvram.fd']['size']
                                                + SPACE_RESERVE)),
                host_storage_bytes=max(
                    0, free_bytes - plan['reserve_gib'] * 1024 ** 3))
            for path in (staging_root, instance_root):
                with _restore_directory(path, create=True):
                    pass
            if self.disk_usage(staging_root).free < needed:
                fail('RESTORE_NO_SPACE', 'preflight',
                     'Free space is insufficient for the generation, host reserve, and staging reserve.', 6)
            generation_id = str(uuid4())
            with _restore_directory(instance_root) as parent:
                try:
                    os.mkdir(operation_id, 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    fail('RESTORE_OPERATION_EXISTS', 'staging',
                         'Restore operation already exists and will not be overwritten.', 4)
            state = self._manifest(operation_id, generation_id, target_identity,
                                   baseline_id, binding)
            preparation = operation / 'preparation.json'
            _atomic_manifest(preparation, state, create=True)
            try:
                self._tool(['qemu-img','create','-f','qcow2','-F','qcow2','-b',
                            str(bundle/'disk.qcow2'),str(operation/'disk.qcow2'),
                            str(manifest['disk']['virtual_size'])], deadline)
                state['events'].append('disk-staged')
                _copy_file(bundle/'nvram.fd', operation/'nvram.fd', deadline, self.clock)
                state['events'].append('nvram-staged')
                prepared_xml = self._prepared_xml(
                    xml_raw, data, operation, bundle/'disk.qcow2')
                fd = os.open(operation/'domain.xml', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(prepared_xml); stream.flush(); os.fsync(stream.fileno())
                disk_info = _parse_qemu_info(self._tool(
                    ['qemu-img','info','--output=json',str(operation/'disk.qcow2')], deadline,
                    'verification'))
                backing = disk_info.get('full-backing-filename', disk_info.get('backing-filename'))
                if (disk_info['virtual-size'] != manifest['disk']['virtual_size']
                        or backing != str(bundle/'disk.qcow2')
                        or disk_info.get('backing-filename-format', 'qcow2') != 'qcow2'
                        or any(key in disk_info for key in ('data-file','encrypted'))):
                    fail('RESTORE_DISK_INCOMPATIBLE', 'verification',
                         'Prepared disk is not bound unambiguously to the baseline.', 5)
                artifacts = {name: self._artifact(operation/name, deadline) for name in ARTIFACTS}
                if artifacts['nvram.fd']['sha256'] != manifest['files']['nvram.fd']['sha256']:
                    fail('RESTORE_HASH_MISMATCH', 'verification',
                         'Prepared NVRAM does not match the baseline.', 5)
                prepared_root = _parse_xml((operation/'domain.xml').read_bytes())
                prepared_disk = next((entry for entry in prepared_root.findall('./devices/disk')
                                      if entry.find('source') is not None
                                      and entry.find('source').get('file')
                                      == str(operation/'disk.qcow2')), None)
                if (prepared_root.findtext('./os/nvram') != str(operation/'nvram.fd')
                        or prepared_disk is None
                        or not immutable_backing_store(prepared_disk, bundle/'disk.qcow2')):
                    fail('RESTORE_XML_INCOMPATIBLE', 'verification',
                         'Prepared XML does not bind disk and NVRAM together.', 5)
                self.baselines.verify(record['instance_id'], baseline_id, deadline)
                current = self._current(record['instance_id'], deadline)
                if current[-1] != binding:
                    fail('RESTORE_SOURCE_CHANGED', 'verification',
                         'Current VM generation changed during staging.', 4)
                state['artifacts'] = artifacts
                state['status'] = 'prepared'
                state['events'].append('verified')
                _atomic_manifest(preparation, state)
                with directory(operation) as parent:
                    os.fsync(parent)
                self.resources.bind(
                    record['instance_id'], operation_id,
                    resource_request(
                        virtual_disk_bytes=manifest['disk']['virtual_size'],
                        storage_bytes=allocated_bytes(operation), operations=0))
                return self.inspect(record['instance_id'], baseline_id, operation_id, deadline,
                                    locked=True)
            except OSError as error:
                self._mark_failed(preparation, state, error)
                try: self.resources.review(record['instance_id'], operation_id)
                except Exception: pass
                if error.errno == errno.ENOSPC:
                    fail('RESTORE_NO_SPACE', 'staging',
                         'Storage space exhausted during restore preparation.', 6)
                fail('RESTORE_STAGING_IO', 'staging',
                     'File-system error during restore preparation.', 6)
            except BaseException as error:
                self._mark_failed(preparation, state, error)
                try: self.resources.review(record['instance_id'], operation_id)
                except Exception: pass
                raise

    def inspect(self, target, baseline_id, operation_id, deadline, *, locked=False):
        if not _uuid(operation_id):
            fail('RESTORE_OPERATION_INVALID', 'validation', 'Restore operation ID is invalid.', 2)
        initial = self.store.inspect(target)
        context = nullcontext() if locked else self.store.lock(initial['instance_id'])
        with context:
            record, _domain, _owner, data, _xml, _root, _plan, binding = self._current(
                initial['instance_id'], deadline)
            _, _, operation = self._roots(data, operation_id)
            try:
                value = self._validate_manifest(_read_json(operation/'preparation.json'), operation)
            except LabError as error:
                if error.detail['code'] == 'BASELINE_MANIFEST_INVALID':
                    fail('RESTORE_PREPARATION_INVALID', 'verification',
                         'Preparation manifest is missing or corrupted.', 5)
                raise
            if (value['target'] != self._target(record, data)
                    or value['baseline_id'] != baseline_id):
                fail('RESTORE_IDENTITY_MISMATCH', 'verification',
                     'Preparation does not belong to the target instance or baseline.', 5)
            if value['status'] == 'prepared':
                self._validate_manifest(value, operation, require_prepared=True)
                with directory(operation) as parent:
                    if set(os.listdir(parent)) != READY_FILES:
                        fail('RESTORE_PREPARATION_INCOMPLETE', 'verification',
                             'Preparation directory contains missing or foreign files.', 5)
                for name, expected in value['artifacts'].items():
                    actual = self._artifact(operation/name, deadline)
                    if actual != expected:
                        fail('RESTORE_HASH_MISMATCH', 'verification',
                             'Prepared artifact was replaced or changed.', 5)
                self.baselines.verify(record['instance_id'], baseline_id, deadline)
                if binding != value['current_generation']:
                    fail('RESTORE_SOURCE_CHANGED', 'verification',
                         'Current VM generation no longer matches the preparation.', 4)
            return {
                'vm_name': record['name'], 'instance_id': record['instance_id'],
                'domain_uuid': record['domain_uuid'], 'baseline_id': baseline_id,
                'restore_operation_id': operation_id,
                'generation_id': value['generation_id'], 'status': value['status'],
                'prepared': value['status'] == 'prepared',
                'activation_permitted': False, 'requires_reverification': True,
                'path': str(operation), 'events': deepcopy(value['events']),
                'error': deepcopy(value['error']), 'artifacts': deepcopy(value['artifacts']),
            }


class RestoreActivationManager:
    """P08-B2: bind a prepared generation without an implicit start."""

    def __init__(self, lifecycle, *, clock, tool, now=None, disk_usage=shutil.disk_usage):
        self.lifecycle = lifecycle
        self.store = lifecycle.store
        self.backend = lifecycle.backend
        self.clock = clock
        self.preparations = RestorePreparationManager(
            lifecycle, clock=clock, tool=tool, now=now, disk_usage=disk_usage)
        self.access = RestoreRuntimeAccess(
            clock=clock, tool=tool,
            lookup=getattr(lifecycle, 'qemu_lookup', pwd.getpwnam),
            lookup_uid=getattr(lifecycle, 'uid_lookup', pwd.getpwuid),
            lookup_gid=getattr(lifecycle, 'gid_lookup', grp.getgrgid))

    def _replace_private(self, record, name, raw):
        path = self.store.paths.data / 'instances' / record['instance_id']
        with directory(path) as parent:
            temporary = '.restore-' + str(uuid4()) + '.tmp'
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            except OSError as error:
                if error.errno == errno.ENOSPC:
                    fail('RESTORE_NO_SPACE', 'activation',
                         'Storage space exhausted while switching control files.', 6)
                fail('RESTORE_ACTIVATION_IO', 'activation',
                     'Private restore control file could not be replaced atomically.', 6)

    def _bindings(self, path, deadline):
        return {name: self.preparations._artifact(path/name, deadline)
                for name in ACTIVE_FILES}

    def _mark_failed(self, instance_id, operation_id):
        try:
            self.store.advance(instance_id, operation_id, 'failed', failed=True)
        except BaseException:
            # A persisted pending intent also blocks starts conservatively.
            pass

    def activate(self, target, baseline_id, preparation_id, deadline):
        if not _uuid(preparation_id):
            fail('RESTORE_OPERATION_INVALID', 'validation',
                 'Restore preparation ID is invalid.', 2)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            inspected = self.preparations.inspect(
                initial['instance_id'], baseline_id, preparation_id, deadline, locked=True)
            if not inspected['prepared']:
                fail('RESTORE_PREPARATION_INCOMPLETE', 'verification',
                     'Only a completely prepared generation may be activated.', 4)
            (record, _domain, _owner, data, _xml_raw, _root, _plan,
             current_binding) = self.preparations._current(initial['instance_id'], deadline)
            operation_path = Path(inspected['path'])
            preparation = self.preparations._validate_manifest(
                _read_json(operation_path/'preparation.json'), operation_path,
                require_prepared=True)
            private = self.store.paths.data/'instances'/record['instance_id']
            baseline = self.preparations.baselines.verify(
                record['instance_id'], baseline_id, deadline)
            baseline_disk = self.preparations._file_binding(
                Path(baseline['path'])/'disk.qcow2', deadline)
            baseline_guest = Path(baseline['path'])/'guest-manifest.json'
            old_guest = self.preparations._file_binding(private/'guest-manifest.json', deadline)
            old_instance = self.preparations._file_binding(private/'instance.json', deadline)
            old_domain = self.preparations._file_binding(private/'domain.xml', deadline)
            new_guest_source = self.preparations._file_binding(baseline_guest, deadline)
            old_generation = deepcopy(current_binding)
            old_generation['guest_manifest'] = old_guest
            old_generation['instance_manifest'] = old_instance
            old_generation['domain_manifest'] = old_domain
            evidence = {
                'target': {key: record[key] for key in ('lab_id','instance_id','domain_uuid')},
                'baseline_id': baseline_id,
                'preparation_operation_id': preparation_id,
                'generation_id': preparation['generation_id'],
                'old_state': record['state'],
                'old_generation': old_generation,
                'new_generation': {
                    'directory': str(operation_path),
                    'artifacts': deepcopy(preparation['artifacts']),
                    'guest_manifest': new_guest_source,
                    'baseline_disk': baseline_disk,
                },
            }
            activation_id = self.store.begin_restore_activation(record, evidence)
            try:
                self.store.advance(record['instance_id'], activation_id, 'binding_generation')
                activation = {
                    'schema_version': 1,
                    'activation_operation_id': activation_id,
                    'preparation_operation_id': preparation_id,
                    'generation_id': preparation['generation_id'],
                    'baseline_id': baseline_id,
                    'target': deepcopy(preparation['target']),
                    'artifacts': deepcopy(preparation['artifacts']),
                    'previous_guest_manifest': old_guest,
                    'guest_manifest_source': new_guest_source,
                }
                _atomic_manifest(operation_path/'activation.json', activation, create=True)
                _copy_file(private/'guest-manifest.json',
                           operation_path/'previous-guest-manifest.json', deadline, self.clock)
                _copy_file(baseline_guest, operation_path/'guest-manifest.json', deadline, self.clock)
                with directory(operation_path) as parent:
                    if set(os.listdir(parent)) != ACTIVE_FILES:
                        fail('RESTORE_PREPARATION_INCOMPLETE', 'activation',
                             'Activation generation contains missing or foreign files.', 5)
                for name, expected in preparation['artifacts'].items():
                    if self.preparations._artifact(operation_path/name, deadline) != expected:
                        fail('RESTORE_HASH_MISMATCH', 'activation',
                             'Prepared artifact changed before activation.', 5)
                previous_guest = self.preparations._artifact(
                    operation_path/'previous-guest-manifest.json', deadline)
                active_guest = self.preparations._artifact(
                    operation_path/'guest-manifest.json', deadline)
                if (previous_guest['sha256'] != old_guest['sha256']
                        or active_guest['sha256'] != new_guest_source['sha256']):
                    fail('RESTORE_HASH_MISMATCH', 'activation',
                         'Guest-manifest generation does not match the old state or baseline.', 5)
                bundle = Path(baseline['path'])
                self.access.apply(operation_path, _plan, deadline, baseline=bundle,
                                  baseline_binding=baseline_disk)
                self.preparations.baselines.verify_path(
                    bundle, expected_instance=record['instance_id'], indexed=True,
                    deadline=deadline)
                self.store.advance(record['instance_id'], activation_id, 'generation_bound')

                domain = self.backend.domain(record['domain_uuid'])
                if domain.isActive():
                    fail('DOMAIN_RUNNING', 'activation',
                         'External domain start blocks restore activation.', 4)
                if hashlib.sha256(domain.XMLDesc(0).encode()).hexdigest() != current_binding['domain_xml_sha256']:
                    fail('RESTORE_SOURCE_CHANGED', 'activation',
                         'Domain definition changed before switching.', 4)
                new_xml = (operation_path/'domain.xml').read_bytes()
                self.store.advance(record['instance_id'], activation_id, 'redefining')
                self.backend.define(new_xml.decode())
                domain = self.backend.domain(record['domain_uuid'])
                new_root = _parse_xml(domain.XMLDesc(0).encode())
                if (domain.isActive()
                        or not self.preparations._domain_storage_valid(
                            new_root, Path(data['storage']), operation_path/'disk.qcow2',
                            operation_path/'nvram.fd', bundle/'disk.qcow2')):
                    fail('RESTORE_REDEFINE_UNCONFIRMED', 'activation',
                         'Read-back domain definition does not bind the new complete generation.', 6)
                self.access.verify(operation_path, _plan, deadline, baseline=bundle,
                                   baseline_binding=baseline_disk)
                self.store.advance(record['instance_id'], activation_id, 'redefined')

                self.store.advance(record['instance_id'], activation_id, 'updating_registry')
                artifacts = deepcopy(preparation['artifacts'])
                artifacts['guest-manifest.json'] = active_guest
                generation = {
                    'schema_version': 1,
                    'baseline_id': baseline_id,
                    'preparation_operation_id': preparation_id,
                    'activation_operation_id': activation_id,
                    'generation_id': preparation['generation_id'],
                    'path': str(operation_path),
                    'files': self._bindings(operation_path, deadline),
                    'artifacts': artifacts,
                    'previous_guest_manifest': previous_guest,
                    'baseline_disk': baseline_disk,
                }
                new_data = deepcopy(data); new_data['restore_generation'] = generation
                self._replace_private(record, 'domain.xml', new_xml)
                self._replace_private(record, 'guest-manifest.json',
                                      (operation_path/'guest-manifest.json').read_bytes())
                self._replace_private(record, 'instance.json', canonical(new_data))
                identities = {name: _identity(private/name)
                              for name in ('instance.json','domain.xml','guest-manifest.json')}
                self.store.replace_instance_bindings(record, activation_id, identities)
                current = self.store.inspect(record['instance_id'])
                RealOwnership(self.store, self.backend, activation_id).verify(current, domain)
                result = {
                    'vm_name': record['name'], 'instance_id': record['instance_id'],
                    'domain_uuid': record['domain_uuid'], 'baseline_id': baseline_id,
                    'restore_operation_id': preparation_id,
                    'activation_operation_id': activation_id,
                    'generation_id': preparation['generation_id'],
                    'restored': True, 'started': False,
                    'old_generation_retained': True,
                    'active_disk': str(operation_path/'disk.qcow2'),
                    'active_nvram': str(operation_path/'nvram.fd'),
                }
                self.store.advance(record['instance_id'], activation_id, 'activated', complete=True)
                return result
            except BaseException:
                self._mark_failed(record['instance_id'], activation_id)
                raise


class RestoreRecoveryManager:
    """P08-B3: classify and resolve only bound partial restore states."""

    def __init__(self, lifecycle, *, clock, tool):
        self.lifecycle = lifecycle
        self.store = lifecycle.store
        self.backend = lifecycle.backend
        self.clock = clock
        self.preparations = RestorePreparationManager(lifecycle, clock=clock, tool=tool)
        self.activation = RestoreActivationManager(lifecycle, clock=clock, tool=tool)

    @staticmethod
    def _source(record, source_id):
        source = next((item for item in record['journal'] if item['id'] == source_id), None)
        if source is None or source['kind'] != 'restore_activation':
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Operation is not a bound restore activation.', 4)
        index = record['journal'].index(source)
        tail = record['journal'][index + 1:]
        if any(item['kind'] != 'restore_recovery'
               or item['recovery']['source_operation'] != source_id for item in tail):
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Restore source was superseded by another operation.', 4)
        return source, tail

    def _private(self, record):
        root = self.store.paths.data/'instances'/record['instance_id']
        expected = {item['path']: item for item in record['manifest']}
        values, identities = {}, {}
        with directory(root) as parent:
            info = os.fstat(parent)
            if record['directory'] != {'device': info.st_dev, 'inode': info.st_ino}:
                fail('OWNERSHIP_MISMATCH', 'recovery',
                     'Private instance directory was replaced.', 5)
            if set(os.listdir(parent)) != set(expected):
                fail('OWNERSHIP_MISMATCH', 'recovery',
                     'Private instance files are missing or contain unknown resources.', 5)
            for name, item in expected.items():
                try:
                    fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                                 dir_fd=parent)
                except OSError:
                    fail('OWNERSHIP_MISMATCH', 'recovery',
                         'Private instance file changed during validation.', 5)
                with os.fdopen(fd, 'rb') as stream:
                    file_info = private_file(stream.fileno())
                    identity = {'device': file_info.st_dev, 'inode': file_info.st_ino}
                    if name not in {'instance.json','domain.xml','guest-manifest.json'}:
                        if identity != {key: item[key] for key in ('device','inode')}:
                            fail('OWNERSHIP_MISMATCH', 'recovery',
                                 'Unrelated private instance file was replaced.', 5)
                    raw = stream.read(1024 * 1024 + 1)
                    if len(raw) > 1024 * 1024:
                        fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                             'Private control file exceeds the limit.', 5)
                    values[name] = raw; identities[name] = identity
        return values, identities

    @staticmethod
    def _binding_matches(path, binding, *, mutable=False):
        try:
            info = os.lstat(path)
            return (stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                    and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and {'device': info.st_dev, 'inode': info.st_ino}
                        == {key: binding[key] for key in ('device','inode')}
                    and (mutable or (info.st_size == binding['size']
                                     and sha256(path) == binding['sha256'])))
        except (OSError, KeyError, TypeError):
            return False

    @staticmethod
    def _content_matches(path, binding):
        try:
            info = os.lstat(path)
            return (stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                    and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and info.st_size == binding['size']
                    and sha256(path) == binding['sha256'])
        except (OSError, KeyError, TypeError):
            return False

    def _generation(self, source, deadline):
        evidence = source['restore']; path = Path(evidence['new_generation']['directory'])
        with _restore_directory(path) as parent:
            if set(os.listdir(parent)) != ACTIVE_FILES:
                fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                     'Restore generation is incomplete or contains unknown files.', 5)
        preparation = self.preparations._validate_manifest(
            _read_json(path/'preparation.json'), path, require_prepared=True)
        old = evidence['old_generation']
        old_binding = {key: old[key] for key in (
            'registry_sha256', 'last_operation_id', 'domain_xml_sha256',
            'disk', 'nvram')}
        if (preparation['baseline_id'] != evidence['baseline_id']
                or preparation['generation_id'] != evidence['generation_id']
                or preparation['operation_id'] != evidence['preparation_operation_id']
                or preparation['current_generation'] != old_binding
                or preparation['artifacts'] != evidence['new_generation']['artifacts']
                or any(preparation['target'][key] != evidence['target'][key]
                       for key in ('lab_id', 'instance_id', 'domain_uuid'))):
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Preparation and restore journal conflict.', 5)
        for name, binding in evidence['new_generation']['artifacts'].items():
            if not self._binding_matches(path/name, binding):
                fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                     'Restore artifact was changed or replaced.', 5)
        new_guest = evidence['new_generation']['guest_manifest']
        if (not self._content_matches(path/'guest-manifest.json', new_guest)
                or not self._content_matches(path/'previous-guest-manifest.json',
                                             old['guest_manifest'])):
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Guest-manifest generation is not bound completely.', 5)
        try:
            activation = _read_json(path/'activation.json')
        except LabError:
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Activation manifest is missing or corrupted.', 5)
        expected_fields = {'schema_version','activation_operation_id','preparation_operation_id',
                           'generation_id','baseline_id','target','artifacts',
                           'previous_guest_manifest','guest_manifest_source'}
        if (not isinstance(activation, dict) or set(activation) != expected_fields
                or activation['schema_version'] != 1
                or activation['activation_operation_id'] != source['id']
                or activation['preparation_operation_id'] != evidence['preparation_operation_id']
                or activation['generation_id'] != evidence['generation_id']
                or activation['baseline_id'] != evidence['baseline_id']
                or activation['target'] != preparation['target']
                or activation['artifacts'] != evidence['new_generation']['artifacts']
                or activation['previous_guest_manifest'] != old['guest_manifest']
                or activation['guest_manifest_source'] != new_guest):
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Activation manifest conflicts with the journal.', 5)
        plan = self.preparations._plan()
        entries = self.preparations.baselines.index.read()['instances'].get(
            evidence['target']['instance_id'], {})
        if evidence['baseline_id'] not in entries.values():
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Baseline is no longer published immutably.', 5)
        bundle = (Path(plan['storage'])/'baselines'/evidence['target']['instance_id'] /
                  evidence['baseline_id'])
        self.preparations.baselines.verify_path(
            bundle, expected_instance=evidence['target']['instance_id'], indexed=True,
            deadline=deadline)
        previous = self.preparations._artifact(path/'previous-guest-manifest.json', deadline)
        guest = self.preparations._artifact(path/'guest-manifest.json', deadline)
        artifacts = deepcopy(evidence['new_generation']['artifacts'])
        artifacts['guest-manifest.json'] = guest
        generation = {
            'schema_version': 1,
            'baseline_id': evidence['baseline_id'],
            'preparation_operation_id': evidence['preparation_operation_id'],
            'activation_operation_id': source['id'],
            'generation_id': evidence['generation_id'],
            'path': str(path),
            'files': self.activation._bindings(path, deadline),
            'artifacts': artifacts,
            'previous_guest_manifest': previous,
        }
        if 'baseline_disk' in evidence['new_generation']:
            generation['baseline_disk'] = deepcopy(
                evidence['new_generation']['baseline_disk'])
        return path, generation

    def _domain_kind(self, record, source, path):
        domain = self.backend.domain(record['domain_uuid'], missing_ok=True)
        if domain is None or domain.isActive():
            return 'unclear', domain
        raw = domain.XMLDesc(0).encode()
        if hashlib.sha256(raw).hexdigest() == source['restore']['old_generation']['domain_xml_sha256']:
            return 'old', domain
        try:
            root = _parse_xml(raw)
            owner = root.find(f'./metadata/{{{OWNER_NS}}}owner')
            expected_owner = {key: record[key] for key in ('lab_id','instance_id','domain_uuid')}
            valid = (root.findtext('uuid') == record['domain_uuid']
                     and root.findtext('name') == record['name']
                     and owner is not None and owner.attrib == expected_owner
                     and self.preparations._domain_storage_valid(
                         root, Path(json.loads((self.store.paths.data/'instances'/record['instance_id'] /
                                               'instance.json').read_bytes()).get('storage', '.')),
                         path/'disk.qcow2', path/'nvram.fd',
                         Path(self.preparations._plan()['storage'])/'baselines' /
                         record['instance_id']/source['restore']['baseline_id']/'disk.qcow2'))
            return ('new' if valid else 'unclear'), domain
        except (LabError, OSError, ValueError, TypeError, json.JSONDecodeError):
            return 'unclear', domain

    @staticmethod
    def _old_registry(record, source):
        evidence = source['restore']; source_index = record['journal'].index(source)
        reconstructed = {key: deepcopy(value) for key, value in record.items()
                         if key != 'requires_review'}
        reconstructed['journal'] = deepcopy(record['journal'][:source_index])
        reconstructed['state'] = evidence['old_state']
        return hashlib.sha256(canonical(reconstructed)).hexdigest() == evidence['old_generation']['registry_sha256']

    def _analysis(self, record, source, deadline):
        evidence = source['restore']; old = evidence['old_generation']
        values, identities = self._private(record)
        path = Path(evidence['new_generation']['directory'])
        domain_kind, domain = self._domain_kind(record, source, path)
        if domain is None or (domain is not None and domain.isActive()):
            return {'classification': 'unclear', 'reason': 'domain-missing-or-active'}

        old_hashes = {
            'instance.json': old['instance_manifest']['sha256'],
            'domain.xml': old['domain_manifest']['sha256'],
            'guest-manifest.json': old['guest_manifest']['sha256'],
        }
        kinds = {name: ('old' if hashlib.sha256(values[name]).hexdigest() == digest else 'unknown')
                 for name, digest in old_hashes.items()}
        if domain_kind == 'old' and all(value == 'old' for value in kinds.values()) \
                and self._old_registry(record, source):
            try:
                owner = RealOwnership(self.store, self.backend, record['journal'][-1]['id'],
                                      recover_restore=True)
                data = owner.verify(record, domain)
                disk, nvram = self.preparations._active_paths(data)
                if (not self._binding_matches(disk, old['disk'])
                        or not self._binding_matches(nvram, old['nvram'])):
                    raise ValueError
            except (LabError, ValueError):
                return {'classification': 'unclear', 'reason': 'old-ownership-mismatch'}
            return {'classification': 'old-complete', 'domain': domain}

        try:
            generation_path, generation = self._generation(source, deadline)
        except LabError as error:
            if error.detail['code'] == 'DEADLINE_EXCEEDED':
                raise
            return {'classification': 'unclear', 'reason': 'generation-invalid'}
        new_raw = {
            'domain.xml': (generation_path/'domain.xml').read_bytes(),
            'guest-manifest.json': (generation_path/'guest-manifest.json').read_bytes(),
        }
        for name in ('domain.xml','guest-manifest.json'):
            if values[name] == new_raw[name]:
                kinds[name] = 'new'
        try:
            instance_value = json.loads(values['instance.json'])
        except (ValueError, TypeError, json.JSONDecodeError):
            return {'classification': 'unclear', 'reason': 'instance-manifest-invalid'}
        if kinds['instance.json'] == 'old':
            desired_data = deepcopy(instance_value); desired_data['restore_generation'] = generation
            desired_instance = canonical(desired_data)
        elif (isinstance(instance_value, dict)
              and instance_value.get('restore_generation') == generation
              and values['instance.json'] == canonical(instance_value)):
            kinds['instance.json'] = 'new'; desired_data = instance_value
            desired_instance = values['instance.json']
        else:
            return {'classification': 'unclear', 'reason': 'instance-manifest-unknown'}
        desired = {**new_raw, 'instance.json': desired_instance}
        manifest = {item['path']: item for item in record['manifest']}
        for name in desired:
            registry_identity = {key: manifest[name][key] for key in ('device','inode')}
            binding_name = {'instance.json':'instance_manifest', 'domain.xml':'domain_manifest',
                            'guest-manifest.json':'guest_manifest'}[name]
            expected_old = {key: old[binding_name][key] for key in ('device','inode')}
            if kinds[name] == 'old' and registry_identity != expected_old:
                return {'classification': 'unclear', 'reason': 'old-registry-binding-mismatch'}
            if kinds[name] == 'new' and registry_identity not in (expected_old, identities[name]):
                return {'classification': 'unclear', 'reason': 'new-registry-binding-mismatch'}
        progressed = ('redefining' in source['events']
                      or any(item['kind'] == 'restore_recovery' for item in record['journal'][record['journal'].index(source)+1:]))
        if domain_kind != 'new' or not progressed or any(value == 'unknown' for value in kinds.values()):
            return {'classification': 'unclear', 'reason': 'mixed-or-unjournaled-state'}
        if all(value == 'new' for value in kinds.values()) \
                and all({key: manifest[name][key] for key in ('device','inode')} == identities[name]
                        for name in desired):
            try:
                RealOwnership(self.store, self.backend, record['journal'][-1]['id'],
                              recover_restore=True).verify(record, domain)
            except LabError:
                return {'classification': 'unclear', 'reason': 'new-ownership-mismatch'}
            return {'classification': 'new-complete', 'domain': domain,
                    'generation': generation, 'desired': desired}
        return {'classification': 'resume-new', 'domain': domain,
                'generation': generation, 'desired': desired, 'kinds': kinds}

    def _mark_failed(self, instance_id, operation_id):
        try:
            self.store.advance(instance_id, operation_id, 'failed', failed=True)
        except BaseException:
            pass

    def recover(self, target, source_id, deadline):
        if not _uuid(source_id):
            fail('RESTORE_OPERATION_INVALID', 'validation', 'Restore operation ID is invalid.', 2)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record = self.store.inspect(initial['instance_id'])
            source, tail = self._source(record, source_id)
            if tail and tail[-1]['status'] == 'complete':
                observed = self._analysis(record, source, deadline)['classification']
                expected = ('old-complete' if tail[-1]['recovery']['classification'] == 'old-complete'
                            else 'new-complete')
                if observed != expected:
                    fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                         'Already completed recovery no longer matches the resources.', 5)
                return self._result(record, source, tail[-1]['id'], observed, True)
            if source['status'] == 'complete' and not tail:
                observed = self._analysis(record, source, deadline)['classification']
                if observed != 'new-complete':
                    fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                         'Completed restore no longer matches the resources.', 5)
                return self._result(record, source, None, observed, True)
            if not record['requires_review']:
                fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                     'Restore source is not open and has no recovery completion.', 4)
            analysis = self._analysis(record, source, deadline)
            classification = analysis['classification']
            if classification == 'unclear':
                fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                     f"Restore state is inconsistent ({analysis['reason']}).", 5,
                     'Inspect journal, registry, domain XML, and generation manually; do not start or delete anything.')
            evidence = {
                'source_operation': source_id,
                'classification': classification,
                'baseline_id': source['restore']['baseline_id'],
                'generation_id': source['restore']['generation_id'],
                'lifecycle_state': source['restore']['old_state'],
            }
            recovery_id = self.store.begin_restore_recovery(record, source_id, evidence)
            try:
                current = self.store.inspect(record['instance_id'])
                if classification == 'resume-new':
                    self.store.advance(record['instance_id'], recovery_id, 'resolving')
                    current = self.store.inspect(record['instance_id'])
                    refreshed = self._analysis(current, source, deadline)
                    if refreshed['classification'] not in {'resume-new','new-complete'}:
                        fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                             'Restore state changed before the recovery mutation.', 5)
                    if refreshed['classification'] == 'resume-new':
                        for name, kind in refreshed['kinds'].items():
                            if kind == 'old':
                                self.activation._replace_private(
                                    current, name, refreshed['desired'][name])
                        private = self.store.paths.data/'instances'/record['instance_id']
                        identities = {name: _identity(private/name)
                                      for name in ('instance.json','domain.xml','guest-manifest.json')}
                        self.store.replace_instance_bindings(current, recovery_id, identities)
                    verified = self.store.inspect(record['instance_id'])
                    RealOwnership(self.store, self.backend, recovery_id,
                                  recover_restore=True).verify(
                                      verified, self.backend.domain(record['domain_uuid']))
                    self.store.resolve_restore_recovery(
                        record['instance_id'], recovery_id, from_resolving=True)
                else:
                    refreshed = self._analysis(current, source, deadline)
                    if refreshed['classification'] != classification:
                        fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                             'Complete state changed before recovery completion.', 5)
                    self.store.resolve_restore_recovery(
                        record['instance_id'], recovery_id, from_resolving=False)
                final = self.store.inspect(record['instance_id'])
                return self._result(final, source, recovery_id, classification, False)
            except BaseException:
                self._mark_failed(record['instance_id'], recovery_id)
                raise

    def cleanup_generations(self, record, data):
        """Inventory only journal-bound complete generations for destroy."""
        operations = [item for item in record['journal'] if item['kind'] == 'restore_activation']
        if not operations:
            return {}
        instance_root = (Path(data['storage']).parent/'.restore-staging'/record['instance_id'])
        expected_paths = {Path(item['restore']['new_generation']['directory']): item
                          for item in operations}
        if len(expected_paths) != len(operations):
            fail('RESTORE_GENERATION_CLEANUP_UNSUPPORTED', 'cleanup',
                 'Multiple restore operations claim the same generation.', 4)
        try:
            with _restore_directory(instance_root) as parent:
                entries = {instance_root/name for name in os.listdir(parent)}
        except LabError:
            fail('RESTORE_GENERATION_CLEANUP_UNSUPPORTED', 'cleanup',
                 'Restore generation root is missing or unsafe.', 4)
        if entries != set(expected_paths):
            fail('RESTORE_GENERATION_CLEANUP_UNSUPPORTED', 'cleanup',
                 'Unbound or missing restore generation blocks cleanup.', 4)
        result = {}
        for path, source in expected_paths.items():
            evidence = source['restore']; old = evidence['old_generation']
            try:
                with _restore_directory(path) as parent:
                    if set(os.listdir(parent)) != ACTIVE_FILES:
                        raise ValueError
                preparation = self.preparations._validate_manifest(
                    _read_json(path/'preparation.json'), path, require_prepared=True)
                old_binding = {key: old[key] for key in (
                    'registry_sha256', 'last_operation_id', 'domain_xml_sha256',
                    'disk', 'nvram')}
                target = evidence['target']
                if (preparation['operation_id'] != evidence['preparation_operation_id']
                        or preparation['generation_id'] != evidence['generation_id']
                        or preparation['baseline_id'] != evidence['baseline_id']
                        or preparation['current_generation'] != old_binding
                        or preparation['artifacts'] != evidence['new_generation']['artifacts']
                        or any(preparation['target'][key] != target[key]
                               for key in ('lab_id', 'instance_id', 'domain_uuid'))):
                    raise ValueError
                for name, binding in evidence['new_generation']['artifacts'].items():
                    if not self._binding_matches(path/name, binding,
                                                 mutable=name in {'disk.qcow2','nvram.fd'}):
                        raise ValueError
                if (not self._content_matches(path/'guest-manifest.json',
                                              evidence['new_generation']['guest_manifest'])
                        or not self._content_matches(path/'previous-guest-manifest.json',
                                                     old['guest_manifest'])):
                    raise ValueError
                activation = _read_json(path/'activation.json')
                expected_fields = {
                    'schema_version', 'activation_operation_id',
                    'preparation_operation_id', 'generation_id', 'baseline_id',
                    'target', 'artifacts', 'previous_guest_manifest',
                    'guest_manifest_source',
                }
                if (not isinstance(activation, dict)
                        or set(activation) != expected_fields
                        or activation['schema_version'] != 1
                        or activation['activation_operation_id'] != source['id']
                        or activation.get('preparation_operation_id')
                           != evidence['preparation_operation_id']
                        or activation['generation_id'] != evidence['generation_id']
                        or activation['baseline_id'] != evidence['baseline_id']
                        or activation['target'] != preparation['target']
                        or activation['artifacts'] != evidence['new_generation']['artifacts']
                        or activation['previous_guest_manifest'] != old['guest_manifest']
                        or activation['guest_manifest_source']
                           != evidence['new_generation']['guest_manifest']):
                    raise ValueError
                identities = {name: _identity(path/name) for name in ACTIVE_FILES}
            except (LabError, OSError, ValueError, TypeError, KeyError):
                fail('RESTORE_GENERATION_CLEANUP_UNSUPPORTED', 'cleanup',
                     'Partial or changed restore generation blocks cleanup.', 4)
            result[path] = identities
        return result

    @staticmethod
    def remove_generations(generations, active_path):
        """Delete only the previously bound exact inventory fd-relatively."""
        for path, identities in generations.items():
            with _restore_directory(path) as parent:
                names = set(os.listdir(parent))
                allowed_missing = {'nvram.fd'} if path == active_path else set()
                if (not names <= set(identities)
                        or not (set(identities) - names) <= allowed_missing):
                    fail('OWNERSHIP_MISMATCH', 'cleanup',
                         'Restore generation changed after cleanup approval.', 5)
                remaining = set(names)
                for name in sorted(names):
                    if set(os.listdir(parent)) != remaining \
                            or _identity(path/name) != identities[name]:
                        fail('OWNERSHIP_MISMATCH', 'cleanup',
                             'Restore file was replaced before cleanup.', 5)
                    os.unlink(name, dir_fd=parent)
                    remaining.remove(name)
                    os.fsync(parent)
            os.rmdir(path)
        if generations:
            instance_root = next(iter(generations)).parent
            with _restore_directory(instance_root) as parent:
                if os.listdir(parent):
                    fail('OWNERSHIP_MISMATCH', 'cleanup',
                         'Unknown restore generation remains after cleanup.', 5)
            os.rmdir(instance_root)

    @staticmethod
    def _result(record, source, recovery_id, classification, idempotent):
        return {
            'vm_name': record['name'], 'instance_id': record['instance_id'],
            'domain_uuid': record['domain_uuid'],
            'source_operation_id': source['id'],
            'recovery_operation_id': recovery_id,
            'baseline_id': source['restore']['baseline_id'],
            'generation_id': source['restore']['generation_id'],
            'classification': classification,
            'resolved': classification != 'unclear',
            'requires_review': record.get('requires_review', False),
            'idempotent': idempotent,
        }


class RestoreStartRecoveryManager:
    """Resolve only a failed start of a complete restore generation."""

    def __init__(self, lifecycle, *, clock, tool):
        self.lifecycle = lifecycle
        self.store = lifecycle.store
        self.backend = lifecycle.backend
        self.clock = clock
        self.restore = RestoreRecoveryManager(lifecycle, clock=clock, tool=tool)
        self.access = self.restore.activation.access

    @staticmethod
    def _source(record, source_id):
        source = next((item for item in record['journal'] if item['id'] == source_id), None)
        if source is None:
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Failed start is not the bound recovery state.', 4)
        tail = record['journal'][record['journal'].index(source) + 1:]
        if ((not tail and not record.get('requires_review'))
                or (tail and tail[-1]['status'] != 'complete'
                    and not record.get('requires_review'))):
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Start failure is no longer the current blocking state.', 4)
        return source, tail

    def _bound(self, record, source, tail, deadline):
        if (not self.store._recoverable_start(source)
                or any(item.get('kind') != 'restore_start_recovery'
                       or item.get('recovery', {}).get('source_operation') != source['id']
                       for item in tail)):
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Start failure was superseded by an unknown or competing operation.', 4)
        domain = self.backend.domain(record['domain_uuid'])
        try:
            managed = domain.hasManagedSaveImage(0)
            runtime_id = domain.ID()
        except (AttributeError, TypeError, ValueError):
            fail('RECOVERY_RUNTIME_UNCONFIRMED', 'recovery',
                 'Inactive libvirt runtime state cannot be established completely.', 5)
        if domain.isActive() or managed or runtime_id != -1:
            fail('RECOVERY_STATE_CONFLICT', 'recovery',
                 'Restore-start recovery requires a powered-off domain without managed-save or QEMU runtime state.', 4)
        latest = record['journal'][-1]
        if latest['id'] == source['id']:
            owner = RealOwnership(self.store, self.backend, source['id'],
                                  recover_failed_start=True)
        elif latest.get('kind') == 'restore_start_recovery':
            owner = RealOwnership(self.store, self.backend, latest['id'], recover_restore=True)
        else:
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Start failure is no longer the current recovery branch.', 4)
        data = owner.verify(record, domain)
        domain_root = _parse_xml(domain.XMLDesc(0).encode())
        if (domain_root.findtext('uuid') != record['domain_uuid']
                or domain_root.findtext('name') != record['name']):
            fail('OWNERSHIP_MISMATCH', 'recovery',
                 'Domain XML identity conflicts with the registry and libvirt object.', 5)
        generation = data.get('restore_generation')
        if not generation:
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'Failed start does not use an active restore generation.', 4)
        activation = next((item for item in record['journal']
                           if item['id'] == generation.get('activation_operation_id')), None)
        if (activation is None or activation.get('kind') != 'restore_activation'
                or activation.get('status') != 'complete'
                or activation.get('phase') != 'activated'):
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Active generation has no completely finished restore source.', 5)
        path, observed = self.restore._generation(activation, deadline)
        if observed != generation:
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Registry and complete restore generation conflict.', 5)
        plan = self.restore.preparations._plan()
        if (record['uri'] != plan['uri'] or data['network_uuid'] != plan['network_uuid']
                or data['pool_uuid'] != plan['pool_uuid']):
            fail('HOST_RESOURCES_CHANGED', 'recovery',
                 'Restore instance and qualified host evidence use different resources.', 5)
        bundle = (Path(plan['storage'])/'baselines'/record['instance_id'] /
                  activation['restore']['baseline_id'])
        self.restore.preparations.baselines.verify_path(
            bundle, expected_instance=record['instance_id'], indexed=True,
            deadline=deadline)
        current_baseline = self.restore.preparations._file_binding(
            bundle/'disk.qcow2', deadline)
        expected_baseline = generation.get('baseline_disk')
        recovery_bindings = [item['recovery']['baseline_disk'] for item in tail
                             if 'baseline_disk' in item.get('recovery', {})]
        if expected_baseline is None and recovery_bindings:
            expected_baseline = recovery_bindings[-1]
        if (expected_baseline is not None and expected_baseline != current_baseline
                or any(binding != current_baseline for binding in recovery_bindings)):
            fail('RESTORE_RECOVERY_UNCLEAR', 'recovery',
                 'Baseline disk was replaced after it was bound to the journal.', 5)
        baseline_binding = expected_baseline or current_baseline
        self.access.worker(plan)
        return domain, data, activation, path, bundle, baseline_binding, plan

    def _ready(self, path, bundle, baseline_binding, plan, deadline):
        try:
            self.access.verify(path, plan, deadline, baseline=bundle,
                               baseline_binding=baseline_binding)
            return True
        except LabError as error:
            if error.detail['code'] != 'RESTORE_ACCESS_INVALID':
                raise
            return False

    def _mark_failed(self, instance_id, operation_id):
        try:
            self.store.advance(instance_id, operation_id, 'failed', failed=True)
        except BaseException:
            pass

    def recover(self, target, source_id, deadline):
        if not _uuid(source_id):
            fail('RESTORE_OPERATION_INVALID', 'validation',
                 'Failed start operation ID is invalid.', 2)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record = self.store.inspect(initial['instance_id'])
            source, tail = self._source(record, source_id)
            _domain, _data, activation, path, bundle, baseline_binding, plan = self._bound(
                record, source, tail, deadline)
            if tail and tail[-1]['status'] == 'complete':
                if not self._ready(path, bundle, baseline_binding, plan, deadline):
                    fail('RESTORE_ACCESS_INVALID', 'recovery',
                         'Completed recovery no longer matches access permissions.', 5)
                return self._result(record, source, activation, tail[-1]['id'], True)
            if tail and tail[-1]['status'] == 'pending':
                operation_id = tail[-1]['id']
            else:
                if not tail and self._ready(path, bundle, baseline_binding, plan, deadline):
                    fail('RESTORE_ACCESS_NOT_CAUSE', 'recovery',
                         'QEMU access contract is already complete; other start failures are not repaired.', 4)
                self.access.repairable(path, plan, deadline)
                self.access.repairable_baseline(bundle, plan, deadline)
                evidence = {
                    'source_operation': source_id,
                    'restore_activation': activation['id'],
                    'baseline_id': activation['restore']['baseline_id'],
                    'generation_id': activation['restore']['generation_id'],
                    'lifecycle_state': activation['restore']['old_state'],
                    'baseline_disk': baseline_binding,
                }
                operation_id = self.store.begin_restore_start_recovery(
                    record, source_id, evidence)
            try:
                current = self.store.inspect(record['instance_id'])
                operation = current['journal'][-1]
                if operation['phase'] == 'planned':
                    self.store.advance(record['instance_id'], operation_id, 'repairing_access')
                    current = self.store.inspect(record['instance_id'])
                    operation = current['journal'][-1]
                if operation['phase'] == 'repairing_access':
                    (_domain, _data, _activation, path, bundle,
                     baseline_binding, plan) = self._bound(
                        current, source, current['journal'][current['journal'].index(source)+1:],
                        deadline)
                    if not self._ready(path, bundle, baseline_binding, plan, deadline):
                        self.access.repairable(path, plan, deadline)
                        self.access.repairable_baseline(bundle, plan, deadline)
                        self.access.apply(path, plan, deadline, baseline=bundle,
                                          baseline_binding=baseline_binding)
                    self.store.advance(record['instance_id'], operation_id, 'access_ready')
                    current = self.store.inspect(record['instance_id'])
                    operation = current['journal'][-1]
                if operation['phase'] != 'access_ready':
                    fail('RECOVERY_STATE_CONFLICT', 'recovery',
                         'Unknown restore-start recovery phase remains blocked.', 4)
                (_domain, _data, _activation, path, bundle,
                 baseline_binding, plan) = self._bound(
                    current, source, current['journal'][current['journal'].index(source)+1:],
                    deadline)
                self.access.verify(path, plan, deadline, baseline=bundle,
                                   baseline_binding=baseline_binding)
                self.store.resolve_restore_start_recovery(record['instance_id'], operation_id)
                final = self.store.inspect(record['instance_id'])
                return self._result(final, source, activation, operation_id, False)
            except BaseException:
                self._mark_failed(record['instance_id'], operation_id)
                raise

    @staticmethod
    def _result(record, source, activation, recovery_id, idempotent):
        return {
            'vm_name': record['name'], 'instance_id': record['instance_id'],
            'domain_uuid': record['domain_uuid'],
            'source_operation_id': source['id'],
            'restore_activation_operation_id': activation['id'],
            'recovery_operation_id': recovery_id,
            'baseline_id': activation['restore']['baseline_id'],
            'generation_id': activation['restore']['generation_id'],
            'resolved': True, 'started': False,
            'requires_review': record.get('requires_review', False),
            'idempotent': idempotent,
        }
