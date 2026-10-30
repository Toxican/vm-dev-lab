#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Plan and apply project-owned libvirt network and pool resources.

"""Explicit manual host administration only. Never invoke from vmctl.

plan: inventory local state without a libvirt connection and emit a review plan.
apply: confirm a separately approved plan by hash; no package or service management.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

NS = 'https://vm-dev-lab.invalid/host-setup/v1'
ET.register_namespace('vdl', NS)
RECORD = Path('/etc/vm-dev-lab/host-setup.json')
LIMIT = 1024 * 1024


class SetupError(Exception):
    pass


def require(condition, message):
    if not condition: raise SetupError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def plan_hash(value):
    return hashlib.sha256(canonical({k: v for k, v in value.items() if k != 'sha256'})).hexdigest()


def parse_xml(text):
    require(len(text.encode()) <= LIMIT and '<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper(), 'Unsafe XML.')
    try: return ET.fromstring(text)
    except ET.ParseError: raise SetupError('Invalid inventory XML.') from None


def bounded_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Plan or record is not a regular file.')
        data = stream.read(LIMIT + 1)
    require(len(data) <= LIMIT, 'JSON exceeds the limit.')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Doppelte JSON-Felder.')
            result[key] = value
        return result
    try: return json.loads(data, object_pairs_hook=unique)
    except (ValueError, RecursionError): raise SetupError('Invalid JSON.') from None


@contextmanager
def root_directory(path):
    """Reject symlinks and user-replaceable parents for root write access."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'An absolute normalized path is required.')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Parent path is not controlled exclusively by the administrator.')
        yield fd
    finally: os.close(fd)


class System:
    def run(self, args):
        # Use only fixed argv templates in the program; never shell code from the plan.
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
                                env={**os.environ, 'LC_ALL': 'C'})
        require(len(result.stdout) + len(result.stderr) <= LIMIT, 'Tool output is too large.')
        if result.returncode != 0:
            stdout = result.stdout.decode('utf-8', errors='replace') if result.stdout else '<empty>'
            stderr = result.stderr.decode('utf-8', errors='replace') if result.stderr else '<empty>'
            raise SetupError('Command failed: ' + ' '.join(args)
                             + f' (exit code {result.returncode}; no automatic repair)'
                             + '\nstdout:\n' + stdout + '\nstderr:\n' + stderr)
        return result.stdout.decode('utf-8')

    def host_id(self):
        return hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()

    def firmware_hash(self, path):
        path = Path(path)
        require(path.is_absolute() and '..' not in path.parts, 'Firmware path must be absolute and normalized.')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= 64 * 1024 ** 2,
                    'Firmware is not a size-limited regular file.')
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024): digest.update(chunk)
        return digest.hexdigest()

    def policy(self, kind, name):
        base = Path('/etc/libvirt/qemu/networks' if kind == 'network' else '/etc/libvirt/storage')
        link = base / 'autostart' / (name + '.xml')
        if not os.path.lexists(link): return False
        require(link.is_symlink() and link.resolve() == (base / (name + '.xml')).resolve(), 'Unknown autostart association; do not modify it.')
        return True

    def account(self, name):
        try: account = pwd.getpwnam(name)
        except KeyError: raise SetupError('Unknown user account: ' + name) from None
        return {'name': account.pw_name, 'uid': account.pw_uid, 'gid': account.pw_gid}

    def inventory(self, live=False):
        result = {'networks': [], 'pools': [], 'domains': []}
        for kind, folder in (('networks', Path('/etc/libvirt/qemu/networks')), ('pools', Path('/etc/libvirt/storage')), ('domains', Path('/etc/libvirt/qemu'))):
            require(folder.is_dir() and not folder.is_symlink(), 'Unsupported or missing libvirt configuration path: ' + str(folder))
            for path in sorted(folder.glob('*.xml')):
                # Do not bypass root-protected definitions or accept an incomplete view.
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Inventory file is not regular.')
                    raw = stream.read(LIMIT + 1)
                require(len(raw) <= LIMIT, 'Inventory is too large.')
                result[kind].append(raw.decode())
        if live:
            for kind, list_command, dump_command in (('networks', 'net-list', 'net-dumpxml'), ('pools', 'pool-list', 'pool-dumpxml'), ('domains', 'list', 'dumpxml')):
                ids = self.virsh(list_command, '--all', '--uuid', readonly=True).split()
                require(len(ids) <= 1024, 'Inventory limit exceeded.')
                for identity in ids:
                    require(str(uuid.UUID(identity)) == identity, 'Invalid inventory UUID.')
                    result[kind].append(self.virsh(dump_command, identity, readonly=True))
        return result

    def routes(self):
        routes = json.loads(self.run(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
        return [(row.get('dev', ''), str(ipaddress.ip_network(row['dst'], strict=False))) for row in routes if row.get('dst') not in (None, 'default')]

    def addresses(self):
        data = json.loads(self.run(['ip', '-j', 'address', 'show']))
        return [(row['ifname'], str(ipaddress.ip_interface(f"{ip['local']}/{ip['prefixlen']}").network))
                for row in data for ip in row.get('addr_info', []) if ip['family'] == 'inet']

    def links(self):
        return [row['ifname'] for row in json.loads(self.run(['ip', '-j', 'link', 'show']))]

    def qemu_config(self):
        values = {}
        for line in Path('/etc/libvirt/qemu.conf').read_text().splitlines():
            match = re.fullmatch(r'\s*(user|group)\s*=\s*"([^"\n]+)"\s*(?:#.*)?', line)
            if match: values[match[1]] = match[2]
        return values

    def prerequisites(self):
        required = ('virsh', 'ip', 'setfacl', 'getfacl', 'dnsmasq', 'qemu-img')
        return [name for name in required if shutil.which(name) is None]

    def storage_parent(self, path):
        with root_directory(Path(path).parent): pass
        info = os.statvfs(Path(path).parent)
        return info.f_bavail * info.f_frsize

    def normalized_path(self, path):
        return Path(path).resolve()

    def storage_info(self, path):
        try: info = os.lstat(path)
        except FileNotFoundError: return None
        require(stat.S_ISDIR(info.st_mode), 'Storage path is not a regular directory (symlink or file).')
        return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid}

    def record(self):
        try:
            with root_directory(RECORD.parent):
                info = os.lstat(RECORD)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o777 == 0o600, 'Unsafe setup record.')
                return bounded_json(RECORD)
        except FileNotFoundError: return None

    @contextmanager
    def apply_lock(self):
        # Only after complete preflight validation and an explicitly confirmed apply.
        with root_directory(RECORD.parent.parent) as fd:
            try: os.mkdir(RECORD.parent.name, 0o700, dir_fd=fd)
            except FileExistsError: pass
        with root_directory(RECORD.parent) as parent:
            info = os.fstat(parent)
            require(info.st_mode & 0o777 == 0o700, 'Setup record directory must be 0700; do not change it automatically.')
            fd = os.open('setup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and info.st_mode & 0o777 == 0o600, 'Unsafe setup lock file.')
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise SetupError('Another setup is running.') from None
                yield
            finally: os.close(fd)

    def save(self, value):
        with root_directory(RECORD.parent) as fd:
            name = '.setup-' + str(uuid.uuid4())
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(out, 'wb') as stream:
                stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
            os.rename(name, RECORD.name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)

    def make_storage(self, plan):
        path = Path(plan['storage'])
        with root_directory(path.parent) as parent:
            os.mkdir(path.name, 0o700, dir_fd=parent)  # No mkdir -p or chmod on foreign files.
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchown(fd, plan['owner']['uid'], plan['owner']['gid']); os.fsync(fd)
            finally: os.close(fd)
            os.fsync(parent)
        # Only the just-created owned directory; no recursion and no group change.
        self.run(['setfacl', '--set', access_acl(plan), '--', str(path)])
        self.run(['setfacl', '--default', '--set', access_acl(plan), '--', str(path)])
        return self.storage_info(path)

    def acl(self, path):
        return self.run(['getfacl', '--numeric', '--omit-header', '--', path])

    def storage_entries(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return sorted(os.listdir(fd))
        finally:
            os.close(fd)

    def storage_mounts(self, path):
        """Find mount targets in storage and a bind mount of storage itself."""
        storage = Path(path)
        identity = self.storage_info(storage)
        require(identity is not None, 'Storage directory is missing.')
        mounts = []
        raw = Path('/proc/self/mountinfo').read_bytes()
        require(len(raw) <= LIMIT, 'Mount inventory exceeds the limit.')
        try:
            mountinfo = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise SetupError('Mount inventory is not valid UTF-8.') from None
        for line in mountinfo.splitlines():
            fields = line.split()
            require(len(fields) >= 10 and '-' in fields, 'Invalid mount inventory.')
            encoded = fields[4]
            mountpoint = re.sub(
                r'\\([0-7]{3})', lambda item: chr(int(item.group(1), 8)), encoded)
            candidate = Path(mountpoint)
            if candidate == storage or storage in candidate.parents:
                mounts.append(mountpoint)
                continue
            try:
                info = os.lstat(candidate)
            except (FileNotFoundError, PermissionError):
                continue
            if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (
                    identity['device'], identity['inode']):
                mounts.append(mountpoint)
        return sorted(set(mounts))

    def pool_volumes(self, identity):
        output = self.virsh('vol-list', identity, '--name', readonly=True)
        return sorted(line.strip() for line in output.splitlines() if line.strip())

    def defined_identities(self, kind):
        command = 'net-list' if kind == 'network' else 'pool-list'
        identities = self.virsh(command, '--all', '--uuid', readonly=True).split()
        require(len(identities) <= 1024, 'Inventory limit exceeded.')
        for identity in identities:
            require(str(uuid.UUID(identity)) == identity, 'Invalid inventory UUID.')
        return sorted(set(identities))

    def firewall_records(self):
        from vm_dev_lab.trusted_lab_firewall import RECORD as trusted_record
        paths = {'trusted-lab': Path(trusted_record),
                 'legacy': RECORD.with_name('firewall.json')}
        result = {}
        for name, path in paths.items():
            try:
                with root_directory(path.parent):
                    info = os.lstat(path)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                            and info.st_nlink == 1
                            and info.st_mode & 0o777 == 0o600,
                            'Unsafe firewall record: ' + str(path))
                    result[name] = bounded_json(path)
            except FileNotFoundError:
                result[name] = None
        return result

    def lock_available(self):
        path = RECORD.with_name('setup.lock')
        try:
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise SetupError('Setup lock file is missing; inspect the state manually.') from None
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and info.st_nlink == 1 and info.st_mode & 0o777 == 0o600,
                    'Unsafe setup lock file.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError('Another setup is running.') from None
            fcntl.flock(fd, fcntl.LOCK_UN)
            return True
        finally:
            os.close(fd)

    def disable_autostart(self, kind, identity):
        command = 'net-autostart' if kind == 'network' else 'pool-autostart'
        self.virsh(command, identity, '--disable')

    def undefine(self, kind, identity):
        command = 'net-undefine' if kind == 'network' else 'pool-undefine'
        self.virsh(command, identity)

    def remove_storage(self, path, expected):
        path = Path(path)
        with root_directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent)
            try:
                info = os.fstat(fd)
                actual = {'device': info.st_dev, 'inode': info.st_ino,
                          'uid': info.st_uid, 'gid': info.st_gid}
                require(actual == expected, 'Storage directory was replaced.')
                require(not os.listdir(fd), 'Storage directory is not empty.')
            finally:
                os.close(fd)
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and {
                'device': info.st_dev, 'inode': info.st_ino,
                'uid': info.st_uid, 'gid': info.st_gid} == expected,
                    'Storage directory was replaced before rmdir.')
            os.rmdir(path.name, dir_fd=parent)
            os.fsync(parent)

    def virsh(self, *args, readonly=False):
        return self.run(['virsh', *(['--readonly'] if readonly else []), '-c', 'qemu:///system', *args])

    def defined(self, kind, identity):
        return self.virsh('net-dumpxml' if kind == 'network' else 'pool-dumpxml', identity, readonly=True)

    def active(self, kind, identity):
        text = self.virsh('net-info' if kind == 'network' else 'pool-info', identity, readonly=True)
        fields = dict((k.strip(), v.strip()) for k, v in (line.split(':', 1) for line in text.splitlines() if ':' in line))
        return fields.get('Active') == 'yes' if kind == 'network' else fields.get('State') == 'running'

    def define(self, xml, kind):
        # Generate XML exclusively from the confirmed data model, never arbitrary commands or files.
        with tempfile.NamedTemporaryFile(mode='w', prefix='definition-', suffix='.xml', dir=RECORD.parent) as file:
            file.write(xml); file.flush(); os.fsync(file.fileno())
            self.virsh('net-define' if kind == 'network' else 'pool-define', file.name)


def access_acl(plan):
    return f"u::rwx,u:{plan['owner']['uid']}:rwx,u:{plan['qemu']['uid']}:rwx,g::---,m::rwx,o::---"


def definitions(plan):
    net = ipaddress.ip_network(plan['subnet'])
    network = ET.Element('network', ipv6='no')
    ET.SubElement(network, 'name').text = plan['network']
    ET.SubElement(network, 'uuid').text = plan['network_uuid']
    metadata = ET.SubElement(network, 'metadata')
    ET.SubElement(metadata, '{' + NS + '}managed', setup_id=plan['setup_id'])
    ET.SubElement(network, 'forward', mode='nat')
    ET.SubElement(network, 'bridge', name=plan['bridge'], stp='on', delay='0')
    ip = ET.SubElement(network, 'ip', address=str(net.network_address + 1), prefix=str(net.prefixlen))
    dhcp = ET.SubElement(ip, 'dhcp')
    ET.SubElement(dhcp, 'range', start=str(net.network_address + 10), end=str(net.broadcast_address - 1))
    pool = ET.Element('pool', type='dir')
    ET.SubElement(pool, 'name').text = plan['pool']
    ET.SubElement(pool, 'uuid').text = plan['pool_uuid']
    # Never enable NOCOW silently on Btrfs.
    ET.SubElement(ET.SubElement(pool, 'features'), 'cow', state='yes')
    target = ET.SubElement(pool, 'target')
    ET.SubElement(target, 'path').text = plan['storage']
    permissions = ET.SubElement(target, 'permissions')
    ET.SubElement(permissions, 'mode').text = '0770'
    ET.SubElement(permissions, 'owner').text = str(plan['owner']['uid'])
    ET.SubElement(permissions, 'group').text = str(plan['owner']['gid'])
    return ET.tostring(network, encoding='unicode'), ET.tostring(pool, encoding='unicode')


def verify_definition(plan, kind, text):
    root = parse_xml(text)
    require(root.tag == ('network' if kind == 'network' else 'pool'), 'Incorrect resource type.')
    require(root.findtext('name') == plan['network' if kind == 'network' else 'pool']
            and root.findtext('uuid') == plan['network_uuid' if kind == 'network' else 'pool_uuid'], 'Definition does not belong to the plan.')
    if kind == 'network':
        require(root.get('ipv6') in (None, 'no'), 'IPv6 policy differs.')
        marker = root.find('./metadata/{' + NS + '}managed')
        require(marker is not None and marker.get('setup_id') == plan['setup_id'], 'Network ownership marker is missing.')
        require(root.find('forward') is not None and root.find('forward').get('mode') == 'nat', 'NAT mode differs.')
        require(root.find('bridge') is not None and root.find('bridge').get('name') == plan['bridge'], 'Bridge differs.')
        ips = root.findall('ip'); network = ipaddress.ip_network(plan['subnet'])
        require(len(ips) == 1 and ips[0].get('address') == str(network.network_address + 1)
                and ipaddress.ip_network(f"{ips[0].get('address')}/{ips[0].get('prefix') or ips[0].get('netmask')}", strict=False) == network, 'Gateway or subnet differs.')
        ranges = ips[0].findall('./dhcp/range')
        require(len(ranges) == 1 and ranges[0].get('start') == str(network.network_address + 10)
                and ranges[0].get('end') == str(network.broadcast_address - 1), 'DHCP range differs.')
    else:
        require(root.get('type') == 'dir' and root.findtext('./target/path') == plan['storage'], 'Pool type or path differs.')
        require(root.find('./features/cow') is not None and root.find('./features/cow').get('state') == 'yes', 'COW policy differs.')
        require(root.findtext('./target/permissions/owner') == str(plan['owner']['uid'])
                and root.findtext('./target/permissions/group') == str(plan['owner']['gid'])
                and int(root.findtext('./target/permissions/mode') or '0', 8) == 0o770, 'Pool target permissions differ.')


def validate_plan(plan):
    common = {'schema_version','uri','host_id','setup_id','network','network_uuid','pool','pool_uuid','bridge','subnet','storage','owner','qemu','mode','activate','min_free_gib','reserve_gib','sha256'}
    fields = common if plan.get('schema_version') == 1 else common | {'firmware'}
    require(isinstance(plan, dict) and set(plan) == fields, 'Unbekannte/fehlende Planfelder.')
    require(type(plan['schema_version']) is int and plan['schema_version'] in (1, 2) and plan['uri'] == 'qemu:///system', 'Unknown setup contract.')
    require(re.fullmatch(r'[0-9a-f]{64}', plan['host_id']) is not None, 'Invalid host binding.')
    for key in ('setup_id','network_uuid','pool_uuid'): require(str(uuid.UUID(plan[key])) == plan[key], 'Invalid UUID.')
    require(len({plan[k] for k in ('setup_id','network_uuid','pool_uuid')}) == 3, 'UUIDs are not distinct.')
    for key in ('network','pool'): require(re.fullmatch(r'vm-dev-lab[a-z0-9-]{0,40}', plan[key]) is not None, 'Only explicit vm-dev-lab names are allowed; default remains prohibited.')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,14}', plan['bridge']) is not None, 'Invalid bridge name.')
    network = ipaddress.ip_network(plan['subnet'])
    require(network.version == 4 and network.prefixlen == 24 and any(network.subnet_of(ipaddress.ip_network(n)) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')), 'A private IPv4 /24 is required.')
    path = Path(plan['storage'])
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) >= 4 and not any(ord(c) < 32 for c in str(path)), 'Invalid dedicated storage path.')
    for account in ('owner','qemu'):
        require(set(plan[account]) == {'name','uid','gid'} and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', plan[account]['name']) is not None, 'Invalid account.')
        require(all(type(plan[account][k]) is int and plan[account][k] > 0 for k in ('uid','gid')), 'Root or zero identities are not allowed for guest or developer accounts.')
    require(plan['owner']['uid'] != plan['qemu']['uid'], 'Developer and QEMU identities are not distinct.')
    require(plan['mode'] in ('manual','permanent') and type(plan['activate']) is bool, 'Define the operating mode explicitly.')
    require(all(type(plan[k]) is int and 1 <= plan[k] <= 16384 for k in ('min_free_gib','reserve_gib')), 'Invalid storage budget.')
    if plan['schema_version'] == 2:
        firmware = plan['firmware']
        require(isinstance(firmware, dict) and set(firmware) == {'code','vars','code_sha256','vars_sha256'},
                'Invalid firmware binding.')
        for kind in ('code', 'vars'):
            path = Path(firmware[kind])
            require(path.is_absolute() and '..' not in path.parts and
                    re.fullmatch(r'[0-9a-f]{64}', firmware[kind + '_sha256']) is not None,
                    'Invalid firmware path or hash.')
    require(plan_hash(plan) == plan['sha256'], 'Plan was modified; create and review a new plan.')


def preflight(plan, system, live=False, record=None):
    validate_plan(plan)
    require(plan['host_id'] == system.host_id(), 'Plan belongs to a different host.')
    if plan['schema_version'] == 2:
        for kind in ('code', 'vars'):
            require(system.firmware_hash(plan['firmware'][kind]) == plan['firmware'][kind + '_sha256'],
                    'Firmware changed after planning.')
    require(not system.prerequisites(), 'Setup tools are missing: ' + ', '.join(system.prerequisites()))
    for key in ('owner','qemu'): require(system.account(plan[key]['name']) == plan[key], 'Accounts, UIDs, or GIDs changed.')
    configured = system.qemu_config().get('user')
    require(configured is None or configured in (plan['qemu']['name'], '+' + str(plan['qemu']['uid'])), 'qemu.conf conflicts with the explicitly selected worker; resolve manually.')
    require(system.storage_parent(plan['storage']) >= (plan['min_free_gib'] + plan['reserve_gib']) * 1024 ** 3, 'Free space is below the budget plus host reserve.')
    existing = system.storage_info(plan['storage'])
    if record:
        require(record.get('status') == 'complete' and record.get('plan') == plan, 'Partial or different setup; no automatic retry or adoption of foreign resources.')
        require(existing == record.get('storage_identity'), 'Storage directory was modified or replaced.')
        acl = system.acl(plan['storage'])
        for line in access_acl(plan).split(','):
            mapped = line.replace('u:', 'user:', 1).replace('g:', 'group:', 1).replace('m:', 'mask:', 1).replace('o:', 'other:', 1)
            require(mapped in acl.splitlines() and 'default:' + mapped in acl.splitlines(), 'ACL differs; no automatic repair.')
    else:
        require(existing is None, 'Storage path exists without an owned root record; do not adopt or modify it.')
    roots = {kind: [parse_xml(x) for x in values] for kind, values in system.inventory(live).items()}
    seen = {'networks': False, 'pools': False}
    for kind in ('networks','pools'):
        own_name = plan['network' if kind == 'networks' else 'pool']
        own_uuid = plan['network_uuid' if kind == 'networks' else 'pool_uuid']
        for root in roots[kind]:
            name, identity = root.findtext('name'), root.findtext('uuid')
            is_own = name == own_name or identity == own_uuid
            if is_own:
                require(record is not None and name == own_name and identity == own_uuid, 'Name or UUID is already occupied; do not adopt a foreign resource.')
                verify_definition(plan, 'network' if kind == 'networks' else 'pool', ET.tostring(root, encoding='unicode'))
                seen[kind] = True
                continue
            if kind == 'networks':
                bridge = root.find('bridge')
                require(bridge is None or bridge.get('name') != plan['bridge'], 'Bridge is already used elsewhere.')
                for p in root.findall('ip'):
                    other = ipaddress.ip_network(f"{p.get('address')}/{p.get('prefix') or p.get('netmask')}", strict=False)
                    require(other.version != 4 or not other.overlaps(ipaddress.ip_network(plan['subnet'])), 'Subnet conflicts with a defined network.')
            else:
                target = root.findtext('./target/path')
                if target:
                    a, b = system.normalized_path(target), system.normalized_path(plan['storage'])
                    require(a != b and a not in b.parents and b not in a.parents, 'Pool paths overlap.')
    if record:
        require(all(seen.values()), 'Owned network or pool definition is missing; do not reconstruct it automatically.')
        for kind, name in (('network', plan['network']), ('pool', plan['pool'])):
            require(system.policy(kind, name) == (plan['mode'] == 'permanent'), 'Autostart policy differs; do not change it automatically.')
    for domain in roots['domains']:
        if record: continue  # Inspect without mutation; do not declare any domain as owned.
        require(not any(n.get('network') == plan['network'] for n in domain.findall('./devices/interface/source')), 'Existing domain references the planned network name; resolve manually.')
        for source in domain.findall('./devices/disk/source'):
            if source.get('file'):
                file = system.normalized_path(source.get('file'))
                storage = system.normalized_path(plan['storage'])
                require(file != storage and storage not in file.parents, 'Vorhandene Domain referenziert geplanten Storagepfad.')
    net = ipaddress.ip_network(plan['subnet'])
    for interface, route in system.routes():
        other = ipaddress.ip_network(route)
        if record and interface == plan['bridge'] and other.subnet_of(net): continue  # Only for a previously verified owned network.
        require(not net.overlaps(other), 'Subnet conflicts with a host or VPN route.')
    for interface, subnet in system.addresses():
        if record and interface == plan['bridge']:
            require(ipaddress.ip_network(subnet) == net, 'Owned bridge address does not match the plan.')
            continue
        require(not net.overlaps(ipaddress.ip_network(subnet)), 'Subnet conflicts with a host address.')
    require(plan['bridge'] not in system.links() or record is not None, 'Bridge exists without setup evidence.')


def make_plan(args, system):
    firmware = {'code': args.firmware_code, 'vars': args.firmware_vars,
                'code_sha256': system.firmware_hash(args.firmware_code),
                'vars_sha256': system.firmware_hash(args.firmware_vars)}
    plan = dict(schema_version=2, uri='qemu:///system', host_id=system.host_id(), setup_id=str(uuid.uuid4()), network=args.network,
                network_uuid=str(uuid.uuid4()), pool=args.pool, pool_uuid=str(uuid.uuid4()), bridge=args.bridge,
                subnet=str(ipaddress.ip_network(args.subnet)), storage=args.storage,
                owner=system.account(args.owner), qemu=system.account(args.qemu_user), mode=args.mode,
                activate=args.activate, min_free_gib=args.min_free_gib, reserve_gib=args.reserve_gib,
                firmware=firmware)
    plan['sha256'] = plan_hash(plan)
    require(system.record() is None, 'Setup record exists; inspect the existing original plan and do not establish a new owner.')
    preflight(plan, system)
    return plan


def apply(plan, system, confirmation, acknowledge):
    validate_plan(plan)
    require(confirmation == plan['sha256'] and acknowledge, 'Plan hash and explicit acknowledgement of possible libvirt socket activation are required.')
    record = system.record()
    preflight(plan, system, live=True, record=record)
    if record: return 'Already configured and verified; no change.'
    with system.apply_lock():
        require(system.record() is None, 'Setup started concurrently; abort.')
        preflight(plan, system, live=True)
        journal = dict(plan=plan, status='pending', completed=[])
        system.save(journal)
        try:
            journal['storage_identity'] = system.make_storage(plan)
            journal['completed'].append('storage-directory-and-acl'); system.save(journal)
            network, pool = definitions(plan)
            system.define(network, 'network')
            journal['completed'].append('network-defined'); system.save(journal)
            system.define(pool, 'pool')
            journal['completed'].append('pool-defined'); system.save(journal)
            for kind, identity in (('net', plan['network_uuid']), ('pool', plan['pool_uuid'])):
                role = 'network' if kind == 'net' else 'pool'
                verify_definition(plan, role, system.defined(role, identity))
                if plan['mode'] == 'permanent': system.virsh(kind + '-autostart', identity)
                if plan['activate']:
                    verify_definition(plan, role, system.defined(role, identity))
                    system.virsh(kind + '-start', identity)
                    require(system.active(role, identity), 'Start of owned resource was not confirmed.')
            journal['status'] = 'complete'
            preflight(plan, system, live=True, record=journal)
            system.save(journal)
        except BaseException:
            journal['status'] = 'partial'
            try: system.save(journal)
            except Exception: pass
            raise
    return 'Owned resources configured. No packages, global services, or foreign resources were changed. MAC and VM qualification remain pending.'


class FirewallSystem(System):
    """Legacy firewall path retained only for old record status/removal."""
    firewall_path = RECORD.with_name('firewall.json')

    def firewall_snapshot(self):
        from vm_dev_lab.firewall import collect
        def read(path):
            with open(path) as stream:
                value = stream.read(LIMIT + 1)
            require(len(value) <= LIMIT, 'Firewall inventory is too large.')
            return value
        snapshot = collect(self.run, read)
        if snapshot['managers']['ufw'] == 'active':
            from vm_dev_lab.ufw import observe
            snapshot['ufw'] = observe(self.run, read)
            snapshot['ufw']['boot_id'] = read('/proc/sys/kernel/random/boot_id').strip()
        return snapshot

    def firewall_record(self):
        try:
            with root_directory(self.firewall_path.parent):
                info = os.lstat(self.firewall_path)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and info.st_mode & 0o777 == 0o600, 'Unsafe firewall record.')
                return bounded_json(self.firewall_path)
        except FileNotFoundError: return None

    firewall_lock = System.apply_lock

    def firewall_save(self, value):
        with root_directory(self.firewall_path.parent) as fd:
            name = '.firewall-' + str(uuid.uuid4())
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(out, 'wb') as stream:
                stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
            os.rename(name, self.firewall_path.name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)

    def firewall_batch(self, commands):
        with root_directory(self.firewall_path.parent):
            with tempfile.NamedTemporaryFile(mode='w', dir=self.firewall_path.parent, prefix='.nft-', suffix='.json') as stream:
                json.dump({'nftables': commands}, stream); stream.flush(); os.fsync(stream.fileno())
                self.run(['nft', '--check', '-j', '-f', stream.name])
                self.run(['nft', '-j', '-f', stream.name])

    @contextmanager
    def ufw_file_lock(self):
        # Same POSIX lock as UFW 0.36.2. Release before invoking its CLI.
        fd=os.open('/run/ufw.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode & 0o022, 'Unsafe UFW lock.')
            try: fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise SetupError('UFW is currently being administered; no concurrent file changes.') from None
            yield
        finally: os.close(fd)

    def ufw_write(self, path, before, after, mode=None):
        # Exact expected bytes plus root-controlled parents; never overwrite drift.
        from vm_dev_lab.ufw_sync import read_root
        path = Path(path)
        with root_directory(path.parent) as fd:
            if before is None:
                require(not os.path.lexists(path), 'Support file already exists; do not adopt it: '+str(path))
                selected_mode = mode or 0o600
            else:
                require(read_root(str(path)).decode() == before, 'File changed in the meantime: '+str(path))
                selected_mode = os.lstat(path).st_mode & 0o777
            temp = '.ufw-'+str(uuid.uuid4())
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, selected_mode, dir_fd=fd)
            with os.fdopen(out, 'wb') as stream:
                os.fchmod(stream.fileno(), selected_mode)
                stream.write(after.encode()); stream.flush(); os.fsync(stream.fileno())
            os.rename(temp, path.name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)

    def ufw_support_preflight(self, plan):
        from vm_dev_lab.ufw_sync import read_root
        for path, change in plan['files'].items():
            require(read_root(path).decode()==change['before'], 'Root file or plan differs: '+path)
        if not plan['libvirt_exception']: return
        from vm_dev_lab.ufw import HELPER, AFTER, hook_path
        require(not os.path.lexists(HELPER) and not os.path.lexists(hook_path(plan['setup_id'])), 'Helper or network hook exists without an owned record; do not adopt it.')
        require(os.stat(AFTER).st_mode & 0o111, 'UFW after.init is not executable; do not repair permissions without authorization.')
        # Missing root-owned hook directories are explicitly included in the plan.
        for path in ('/etc/libvirt', '/etc/vm-dev-lab'):
            with root_directory(path): pass
        for path in ('/etc/libvirt/hooks', '/etc/libvirt/hooks/network.d'):
            if os.path.lexists(path):
                with root_directory(path): pass

    def ufw_support_install(self, plan, journal):
        if not plan['libvirt_exception']: return
        from vm_dev_lab.ufw import HELPER, hook_path
        for folder in ('/etc/libvirt/hooks', '/etc/libvirt/hooks/network.d'):
            if not os.path.lexists(folder):
                with root_directory(Path(folder).parent) as fd:
                    os.mkdir(Path(folder).name, 0o755, dir_fd=fd); os.fsync(fd)
                info=os.stat(folder)
                journal['created_dirs'].append({'path':folder,'device':info.st_dev,'inode':info.st_ino})
                self.firewall_save(journal)
        self.ufw_write(HELPER, None, plan['helper'], 0o600)
        self.ufw_write(hook_path(plan['setup_id']), None, plan['hook'], 0o755)

    def ufw_support_check(self, plan, partial=False):
        if not plan['libvirt_exception']: return
        from vm_dev_lab.ufw import HELPER, hook_path
        from vm_dev_lab.ufw_sync import read_root
        for path, expected in ((HELPER, plan['helper']), (hook_path(plan['setup_id']), plan['hook'])):
            if partial and not os.path.lexists(path): continue
            require(read_root(path).decode()==expected, 'Owned helper or hook file changed: '+path)
        if os.path.lexists(hook_path(plan['setup_id'])):
            require(os.stat(hook_path(plan['setup_id'])).st_mode & 0o111, 'Network hook is not executable.')

    def ufw_exception_check(self, plan, mutate=False):
        if not plan['libvirt_exception']: return
        from vm_dev_lab.ufw import HELPER
        from vm_dev_lab import ufw_sync
        if mutate: self.run(['/usr/bin/python3', HELPER])
        snapshot=self.firewall_snapshot()
        result=ufw_sync.sync({'status':'complete','plan':plan}, self.defined_without_connection(plan), snapshot['nft'],
                             lambda *args: (_ for _ in ()).throw(SetupError('Owned libvirt exception is missing; status does not repair anything.')))
        require(result=='unchanged', 'libvirt network or exception is not active; network readiness is unverified.')

    def defined_without_connection(self, plan):
        from vm_dev_lab.ufw_sync import read_root
        text=read_root('/etc/libvirt/qemu/networks/'+plan['setup']['network']+'.xml').decode()
        verify_definition(plan['setup'], 'network', text)
        return text

    def ufw_exception_remove(self, plan):
        if not plan['libvirt_exception']: return
        from vm_dev_lab.ufw import HELPER
        if os.path.lexists(HELPER): self.run(['/usr/bin/python3', HELPER, '--remove'])
        else:
            require(not any('rule' in r and r['rule'].get('comment')==plan['libvirt_exception']['comment'] for r in self.firewall_snapshot()['nft']['nftables']), 'Helper is missing while an exception exists; targeted review is required.')

    def ufw_reload(self):
        # Never enable/disable UFW. Separate approval must cover this reload.
        require(self.run(['ufw','status']).startswith('Status: active'), 'UFW is not active; abort.')
        self.run(['ufw','reload'])

    def ufw_support_remove(self, plan):
        if not plan['libvirt_exception']: return
        from vm_dev_lab.ufw import HELPER, hook_path
        from vm_dev_lab.ufw_sync import read_root
        for path, expected in ((hook_path(plan['setup_id']),plan['hook']), (HELPER,plan['helper'])):
            if os.path.lexists(path):
                require(read_root(path).decode()==expected, 'Support file changed; do not remove it.')
                with root_directory(Path(path).parent) as fd: os.unlink(Path(path).name, dir_fd=fd); os.fsync(fd)
        record=self.firewall_record()
        for item in reversed(record.get('created_dirs', [])):
            path=item['path']; info=os.lstat(path)
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(item['device'],item['inode']), 'Owned hook directory was replaced.')
            if not list(Path(path).iterdir()):
                with root_directory(Path(path).parent) as fd: os.rmdir(Path(path).name, dir_fd=fd); os.fsync(fd)


class TrustedLabSystem(FirewallSystem):
    """Small UFW-CLI adapter with a distinct record from historical firewalls."""
    from vm_dev_lab.trusted_lab_firewall import RECORD as _record_name
    firewall_path = Path(_record_name)

    def ufw_state(self):
        return {'status': self.run(['ufw', 'status']), 'added': self.run(['ufw', 'show', 'added'])}

    def ufw_rule(self, argv, remove=False):
        require(isinstance(argv, list) and argv and argv[0] in ('allow', 'route') and
                'comment' in argv and not any(value in argv for value in ('default', 'enable', 'disable', 'reload')),
                'Only fixed marked allow and route rules are permitted.')
        command = list(argv)
        if remove:
            command = (['route', 'delete'] + command[1:]) if command[0] == 'route' else ['delete'] + command
        return self.run(['ufw', *command])

    def trusted_write(self, path, text, mode):
        path = Path(path)
        require(not os.path.lexists(path), 'Owned support file already exists; do not adopt it: ' + str(path))
        with root_directory(path.parent) as fd:
            temp = '.trusted-lab-' + str(uuid.uuid4())
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
            with os.fdopen(out, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(text.encode()); stream.flush(); os.fsync(stream.fileno())
            os.rename(temp, path.name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)

    def trusted_support_preflight(self, plan):
        from vm_dev_lab.trusted_lab_firewall import HELPER, SYNC_LOCK, hook_path
        require(not os.path.lexists(HELPER) and not os.path.lexists(SYNC_LOCK) and
                not os.path.lexists(hook_path(plan['setup_id'])),
                'Owned trusted-lab support file exists without a current record; do not adopt it.')
        for path in ('/etc/libvirt', '/etc/vm-dev-lab'):
            with root_directory(path): pass
        for path in ('/etc/libvirt/hooks', '/etc/libvirt/hooks/network.d'):
            if os.path.lexists(path):
                with root_directory(path): pass

    def trusted_support_install(self, plan, journal):
        from vm_dev_lab.trusted_lab_firewall import HELPER, hook_path
        for folder in ('/etc/libvirt/hooks', '/etc/libvirt/hooks/network.d'):
            if not os.path.lexists(folder):
                with root_directory(Path(folder).parent) as fd:
                    os.mkdir(Path(folder).name, 0o755, dir_fd=fd); os.fsync(fd)
                info = os.stat(folder)
                journal['created_dirs'].append({'path': folder, 'device': info.st_dev, 'inode': info.st_ino})
                self.firewall_save(journal)
        self.trusted_write(HELPER, plan['helper'], 0o600)
        self.trusted_write(hook_path(plan['setup_id']), plan['hook'], 0o755)

    def trusted_support_check(self, plan, partial=False):
        from vm_dev_lab.trusted_lab_firewall import HELPER, hook_path
        from vm_dev_lab.trusted_lab_sync import read_root
        for path, expected in ((HELPER, plan['helper']), (hook_path(plan['setup_id']), plan['hook'])):
            if partial and not os.path.lexists(path):
                continue
            require(read_root(path).decode() == expected, 'Owned support file is missing or changed: ' + path)
        if os.path.lexists(hook_path(plan['setup_id'])):
            require(os.stat(hook_path(plan['setup_id'])).st_mode & 0o111, 'Owned network hook is not executable.')

    def trusted_support_absent(self, plan):
        from vm_dev_lab.trusted_lab_firewall import HELPER, SYNC_LOCK, hook_path
        require(not os.path.lexists(HELPER) and not os.path.lexists(SYNC_LOCK) and
                not os.path.lexists(hook_path(plan['setup_id'])),
                'Owned support file remained after removal.')

    def trusted_support_remove(self, plan, record):
        from vm_dev_lab.trusted_lab_firewall import HELPER, SYNC_LOCK, hook_path
        from vm_dev_lab.trusted_lab_sync import read_root
        for path, expected in ((hook_path(plan['setup_id']), plan['hook']), (HELPER, plan['helper'])):
            if os.path.lexists(path):
                require(read_root(path).decode() == expected, 'Owned support file changed; do not remove it: ' + path)
                with root_directory(Path(path).parent) as fd:
                    os.unlink(Path(path).name, dir_fd=fd); os.fsync(fd)
        if os.path.lexists(SYNC_LOCK):
            info = os.lstat(SYNC_LOCK)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                    info.st_mode & 0o777 == 0o600, 'Unsafe owned synchronization lock.')
            with root_directory(Path(SYNC_LOCK).parent) as fd:
                os.unlink(Path(SYNC_LOCK).name, dir_fd=fd); os.fsync(fd)
        for item in reversed(record.get('created_dirs', [])):
            path = item['path']; info = os.lstat(path)
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (item['device'], item['inode']),
                    'Owned hook directory was replaced.')
            if not list(Path(path).iterdir()):
                with root_directory(Path(path).parent) as fd:
                    os.rmdir(Path(path).name, dir_fd=fd); os.fsync(fd)

    def trusted_ingress_sync(self, plan):
        from vm_dev_lab.trusted_lab_firewall import HELPER
        return self.run(['/usr/bin/python3', HELPER, '--sync']).strip()

    def trusted_ingress_status(self, plan):
        from vm_dev_lab.trusted_lab_firewall import HELPER
        return self.run(['/usr/bin/python3', HELPER, '--check']).strip()

    def trusted_ingress_remove(self, plan):
        from vm_dev_lab.trusted_lab_firewall import HELPER
        if not os.path.lexists(HELPER):
            return 'absent'
        return self.run(['/usr/bin/python3', HELPER, '--remove']).strip()



def firewall_command(args):
    from vm_dev_lab import trusted_lab_firewall as trusted
    if args.command == 'firewall-plan':
        # Exported setup record is data only, not admin authority. No host or
        # foreign firewall inventory is part of the standard planner.
        record = bounded_json(args.setup_record)
        require(record.get('status') == 'complete', 'A complete setup record is required.')
        validate_plan(record['plan'])
        plan = trusted.build_plan(record['plan'], bounded_json(args.policy))
        print(json.dumps(plan, indent=2)); return 0
    require(os.geteuid() == 0, 'Firewall administration requires separate manual approval; no privilege fallback.')
    host_system = System()
    record = host_system.record()
    require(record and record.get('status') == 'complete', 'Owned completed host setup is missing.')
    validate_plan(record['plan'])
    require(record['plan']['host_id'] == host_system.host_id(), 'Host setup belongs to a different host.')
    # Check actual own network definition without making a libvirt connection.
    roots = [x for x in host_system.inventory()['networks'] if parse_xml(x).findtext('uuid') == record['plan']['network_uuid']]
    require(len(roots) == 1, 'Owned network definition is missing or ambiguous.')
    verify_definition(record['plan'], 'network', roots[0])
    plan = bounded_json(args.plan)
    if plan.get('backend') == trusted.BACKEND:
        system = TrustedLabSystem()
        if args.command == 'firewall-apply':
            print(trusted.apply(plan, record['plan'], system, args.confirm))
        elif args.command == 'firewall-uninstall':
            print(trusted.uninstall(plan, system, args.confirm))
        else:
            print(json.dumps(trusted.status(plan, system.firewall_record(), system)))
    else:
        # Existing records are not reinterpreted. Their old implementation is
        # reachable only for explicit status/removal, never for a new apply.
        require(args.command != 'firewall-apply',
                'Do not reinstall a historical firewall plan; only status or removal with the original record is allowed.')
        from vm_dev_lab import firewall
        system = FirewallSystem()
        own = system.firewall_record()
        if args.command == 'firewall-uninstall':
            print(firewall.uninstall(plan, system, args.confirm))
        elif plan.get('backend') == 'ufw-framework-v1':
            from vm_dev_lab import ufw
            print(json.dumps(ufw.status(plan, own, system.firewall_snapshot(), system)))
        else:
            firewall.owned_state(plan, own, system.firewall_snapshot())
            print(json.dumps({'rules_present': True, 'network_ready': False, 'persistence':'runtime-only'}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    plan_parser = sub.add_parser('plan', help='Local root inventory and JSON proposal; no libvirt connection')
    plan_parser.add_argument('--owner', required=True)
    plan_parser.add_argument('--qemu-user', required=True, help='Explicitly qualified unprivileged QEMU account')
    plan_parser.add_argument('--mode', choices=('manual','permanent'), required=True)
    plan_parser.add_argument('--network', default='vm-dev-lab-nat')
    plan_parser.add_argument('--pool', default='vm-dev-lab')
    plan_parser.add_argument('--bridge', default='virbr-vdl')
    plan_parser.add_argument('--subnet', default='192.168.124.0/24')
    plan_parser.add_argument('--storage', default='/var/lib/libvirt/vm-dev-lab')
    plan_parser.add_argument('--min-free-gib', type=int, default=60)
    plan_parser.add_argument('--reserve-gib', type=int, default=20)
    plan_parser.add_argument('--firmware-code', required=True, help='Explicitly qualified OVMF CODE file')
    plan_parser.add_argument('--firmware-vars', required=True, help='Explicitly qualified OVMF VARS template')
    plan_parser.add_argument('--activate', action='store_true', help='Start only owned resources during a later apply')
    apply_parser = sub.add_parser('apply', help='Apply a reviewed plan after separate approval')
    apply_parser.add_argument('--plan', required=True)
    apply_parser.add_argument('--confirm', required=True, help='SHA256 from the reviewed plan')
    apply_parser.add_argument('--ack-libvirt-activation', action='store_true')
    fp = sub.add_parser('firewall-plan', help='Simple trusted-lab UFW CLI plan from setup record and policy')
    for name in ('setup-record', 'policy'): fp.add_argument('--'+name, required=True)
    for name in ('firewall-apply', 'firewall-status', 'firewall-uninstall'):
        fp = sub.add_parser(name, help='Separate manual firewall operation; no VM management')
        fp.add_argument('--plan', required=True)
        if name != 'firewall-status': fp.add_argument('--confirm', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command.startswith('firewall-'):
            return firewall_command(args)
        require(os.geteuid() == 0, 'Complete inventory or setup requires manual sudo; no automatic sudo fallback.')
        system = System()
        if args.command == 'plan':
            plan = make_plan(args, system)
            print(json.dumps(plan, indent=2, sort_keys=True))
            print('Plan only. apply may activate libvirt daemons and existing autostart policies. No service, boot, or package management.', file=sys.stderr)
            print('Network and pool XML:\n' + '\n'.join(definitions(plan)), file=sys.stderr)
        else:
            print(apply(bounded_json(args.plan), system, args.confirm, args.ack_libvirt_activation))
        return 0
    except (SetupError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print('ABORT: ' + str(error) + '\nNo automatic rollback or cleanup. Inspect the setup record after a partial operation.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
