# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Orchestrate VM lifecycle operations with ownership and state checks.

"""P06 lifecycle built from P03 state and the qualified P05 components."""
from copy import deepcopy
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import time
import xml.etree.ElementTree as ET
from uuid import UUID, uuid4

from .errors import LabError
from .guest.exec import (ADAPTER_VERSION, PROTOCOL_VERSION, RESPONSE_LIMIT,
                         STREAM_LIMIT, remote_command, request as exec_request,
                         response as exec_response, validate_argv)
from .guest.files import (ADAPTER_VERSION as FILE_ADAPTER_VERSION,
                          PROTOCOL_VERSION as FILE_PROTOCOL_VERSION,
                          RESPONSE_LIMIT as FILE_RESPONSE_LIMIT, HostDestination,
                          download_batch, endpoints as copy_endpoints,
                          manifest_digest, remote_command as file_remote_command,
                          request as file_request, response as file_response,
                          scan_host_source, upload_batch)
from .guest.ssh import (MARKER, Binding, bootstrap, client_identity, public_key,
                        sftp_arguments, ssh_arguments)
from .libvirt_backend import (OWNER_NS, LibvirtBackend, domain_capabilities,
                              immutable_backing_store, network_identity, pool_identity,
                              resolved_create_backing_store)
from .process import exchange as exchange_tool, run as run_tool
from .provisioning.arch import GUEST_MANIFEST, validate_guest_manifest
from .provisioning.cloudinit import render_seed, write_seed_iso
from .resources import ResourceLedger, allocated_bytes, request as resource_request
from .state import StatePaths, StateStore, directory, private_file
from .release import ARCH_IMAGE_SHA256, ARCH_TRUST
from .storage.images import ImageCache

FIRMWARE_CODE = Path('/usr/share/edk2/x64/OVMF_CODE.4m.fd')
FIRMWARE_VARS = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
FIRMWARE_HASHES = {
    'code': '2febd26c0b4cf95a636a941afa37d64a552723443ed9ac72f763f6840da98cb4',
    'vars': '5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e',
}
RUNTIME_FILES = ('base.qcow2', 'work.qcow2', 'nvram.fd', 'seed.iso', 'serial.log')
PRIVATE_FILES = ('domain.xml', 'instance.json', 'guest-manifest.json', 'user-data', 'meta-data', 'network-config', 'seed.iso')
LOG_DEFAULT_BYTES = 16 * 1024
LOG_MAX_BYTES = 64 * 1024
GUEST_REPORT_COMMAND = (f"cloud-init status --wait >/dev/null 2>&1; status=$?; "
                        f"printf '%s\\n' \"$status\"; cat {GUEST_MANIFEST} 2>/dev/null || true; exit 0")


def firmware_binding(plan):
    """New records bind firmware per host; v1 remains an explicit legacy contract."""
    value = plan.get('firmware')
    if value is None:
        return {'code': FIRMWARE_CODE, 'vars': FIRMWARE_VARS,
                'code_sha256': FIRMWARE_HASHES['code'],
                'vars_sha256': FIRMWARE_HASHES['vars']}
    return {'code': Path(value['code']), 'vars': Path(value['vars']),
            'code_sha256': value['code_sha256'],
            'vars_sha256': value['vars_sha256']}


def fail(code, phase, message, status=6, hint=None, retryable=False):
    raise LabError(status, code, phase, message, hint or
                   'Inspect instance status and diagnostics; do not modify foreign resources.', retryable)


def _sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        fail('PATH_UNSAFE', 'ownership', 'Symlink in instance resources was rejected.', 5)
    return {'device': info.st_dev, 'inode': info.st_ino}


def _write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def load_host_record(path=None):
    """Read existing setup evidence automatically without a root-record hash prompt."""
    if path is None:
        configured = os.environ.get('VM_DEV_LAB_HOST_RECORD')
        candidates = ([Path(configured)] if configured else []) + [
            Path('/etc/vm-dev-lab/host-setup.json'),
        ]
        path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        fail('HOST_RECORD_MISSING', 'preflight', 'No completed host setup evidence found.', 3,
             'Configure host setup once as described in docs/INSTALLATION.md or set VM_DEV_LAB_HOST_RECORD.')
    try:
        path = Path(path)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode): raise ValueError
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream: raw = stream.read(65537)
        if len(raw) > 65536: raise ValueError
        record = json.loads(raw)
        if set(record) != {'completed', 'plan', 'status', 'storage_identity'} or record['status'] != 'complete': raise ValueError
        plan = record['plan']
        common = {'schema_version','uri','host_id','setup_id','network','network_uuid','pool','pool_uuid','bridge',
                  'subnet','storage','owner','qemu','mode','activate','min_free_gib','reserve_gib','sha256'}
        version = plan.get('schema_version')
        fields = common if version == 1 else common | {'firmware'}
        if set(plan) != fields or version not in (1, 2) or plan['uri'] != 'qemu:///system': raise ValueError
        expected = hashlib.sha256(_canonical({k: v for k, v in plan.items() if k != 'sha256'})).hexdigest()
        if expected != plan['sha256']: raise ValueError
        if hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest() != plan['host_id']: raise ValueError
        if plan['owner']['uid'] != os.geteuid() or pwd.getpwuid(os.geteuid()).pw_name != plan['owner']['name']: raise ValueError
        storage = Path(plan['storage'])
        info = os.lstat(storage)
        identity = record['storage_identity']
        actual = {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid}
        if not stat.S_ISDIR(info.st_mode) or identity != actual: raise ValueError
        if version == 2:
            firmware = plan['firmware']
            if set(firmware) != {'code', 'vars', 'code_sha256', 'vars_sha256'}: raise ValueError
            for kind in ('code', 'vars'):
                firmware_path = Path(firmware[kind])
                if (not firmware_path.is_absolute() or '..' in firmware_path.parts
                        or not firmware_path.is_file()
                        or _sha(firmware_path) != firmware[kind + '_sha256']):
                    raise ValueError
        return deepcopy(plan)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        fail('HOST_RECORD_INVALID', 'preflight', 'Host-setup evidence is missing, changed, or belongs to another host.', 5,
             'Inspect the existing host-setup record and storage path read-only; do not relabel them.')


class RealOwnership:
    """P03 registry with real libvirt and storage resources bound to a manifest."""
    def __init__(self, store, backend, operation_id=None, recover_failed_start=False,
                 recover_failed_create=False, recover_restore=False,
                 read_only_diagnostic=False):
        self.store, self.backend, self.operation_id = store, backend, operation_id
        self.recover_failed_start = recover_failed_start
        self.recover_failed_create = recover_failed_create
        self.recover_restore = recover_restore
        self.read_only_diagnostic = read_only_diagnostic

    def inspect(self, target):
        return self.store.inspect(target)

    def _private(self, record):
        self.store._registered(record, self.operation_id, self.recover_failed_start,
                               self.recover_failed_create, self.recover_restore,
                               self.read_only_diagnostic)
        with self.store.selection(record, self.operation_id, self.recover_failed_start,
                                  self.recover_failed_create, self.recover_restore,
                                  self.read_only_diagnostic):
            path = self.store.paths.data / 'instances' / record['instance_id'] / 'instance.json'
            try:
                raw = path.read_bytes()
                if len(raw) > 65536: raise ValueError
                value = json.loads(raw)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                fail('OWNERSHIP_MISMATCH', 'ownership', 'Instance manifest is missing or corrupted.', 5)
        return value

    def files(self, record):
        data = self._private(record)
        required = {'schema_version','lab_id','instance_id','domain_uuid','name','uri','storage','directory','files',
                    'mac','network','network_uuid','pool','pool_uuid','image_sha256','seed','ssh_user',
                    'requested_packages'}
        if (set(data) not in (required, required | {'restore_generation'}) or data['schema_version'] != 1
                or any(data[k] != record[k] for k in ('lab_id','instance_id','domain_uuid','name','uri'))):
            fail('OWNERSHIP_MISMATCH', 'ownership', 'Manifest identity does not match the registry.', 5)
        storage = Path(data['storage'])
        if storage.name != record['instance_id'] or _identity(storage) != data['directory']:
            fail('OWNERSHIP_MISMATCH', 'ownership', 'Instance directory was replaced.', 5)
        if set(data['files']) != set(RUNTIME_FILES) or set(p.name for p in storage.iterdir()) != set(RUNTIME_FILES):
            fail('OWNERSHIP_MISMATCH', 'ownership', 'Runtime files are missing or contain unknown resources.', 5)
        allowed_uids = {os.geteuid()}
        try: allowed_uids.add(pwd.getpwnam('libvirt-qemu').pw_uid)
        except KeyError: pass
        for name, expected in data['files'].items():
            info = os.lstat(storage / name)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in allowed_uids
                    or _identity(storage / name) != expected):
                fail('OWNERSHIP_MISMATCH', 'ownership', 'Runtime file was replaced or has a foreign owner.', 5)
        if 'restore_generation' in data:
            generation = data['restore_generation']
            fields = {'schema_version','baseline_id','preparation_operation_id','activation_operation_id',
                      'generation_id','path','files','artifacts','previous_guest_manifest'}
            try:
                path = Path(generation['path'])
                expected_path = (storage.parent / '.restore-staging' / record['instance_id'] /
                                 generation['preparation_operation_id'])
                names = {'disk.qcow2','nvram.fd','domain.xml','preparation.json','activation.json',
                         'guest-manifest.json','previous-guest-manifest.json'}
                if (not isinstance(generation, dict)
                        or set(generation) not in (fields, fields | {'baseline_disk'})
                        or generation['schema_version'] != 1 or path != expected_path
                        or not re.fullmatch(r'[0-9a-f]{64}', generation['baseline_id'])
                        or any(str(UUID(generation[key])) != generation[key]
                               for key in ('preparation_operation_id','activation_operation_id',
                                           'generation_id'))
                        or set(generation['files']) != names
                        or set(item.name for item in path.iterdir()) != names
                        or set(generation['artifacts']) != {'disk.qcow2','nvram.fd','domain.xml',
                                                            'guest-manifest.json'}):
                    raise ValueError
                if 'baseline_disk' in generation:
                    baseline_disk = generation['baseline_disk']
                    expected_baseline = (storage.parent/'baselines'/record['instance_id'] /
                                         generation['baseline_id']/'disk.qcow2')
                    if (set(baseline_disk) != {'path','device','inode','size','sha256'}
                            or baseline_disk['path'] != str(expected_baseline)
                            or _identity(expected_baseline)
                               != {key:baseline_disk[key] for key in ('device','inode')}):
                        raise ValueError
                for name, expected in generation['files'].items():
                    info = os.lstat(path / name)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid not in allowed_uids
                            or set(expected) != {'path','device','inode','size','sha256'}
                            or expected['path'] != str(path/name)
                            or _identity(path / name)
                               != {key: expected[key] for key in ('device','inode')}
                            or (name not in {'disk.qcow2','nvram.fd'}
                                and (info.st_size != expected['size']
                                     or _sha(path/name) != expected['sha256']))):
                        raise ValueError
                for name, artifact in generation['artifacts'].items():
                    if (set(artifact) != {'path','device','inode','size','sha256'}
                            or artifact['path'] != str(path / name)
                            or _identity(path / name) != {key: artifact[key] for key in ('device','inode')}
                            or (name not in {'disk.qcow2','nvram.fd'}
                                and (os.lstat(path / name).st_size != artifact['size']
                                     or _sha(path / name) != artifact['sha256']))):
                        raise ValueError
                previous = generation['previous_guest_manifest']
                if (set(previous) != {'path','device','inode','size','sha256'}
                        or previous['path'] != str(path/'previous-guest-manifest.json')
                        or _identity(path/'previous-guest-manifest.json')
                           != {key: previous[key] for key in ('device','inode')}
                        or os.lstat(path/'previous-guest-manifest.json').st_size != previous['size']
                        or _sha(path/'previous-guest-manifest.json') != previous['sha256']):
                    raise ValueError
            except (KeyError, OSError, TypeError, ValueError):
                fail('OWNERSHIP_MISMATCH', 'ownership',
                     'Active restore generation is incomplete or was changed.', 5)
        return data

    def guest_manifest(self, record):
        data = self._private(record)
        path = self.store.paths.data / 'instances' / record['instance_id'] / 'guest-manifest.json'
        try:
            raw = path.read_bytes()
            if len(raw) > 65536:
                raise ValueError
            value = json.loads(raw)
            expected = {'schema_version', 'cloud_init', 'ssh_ready', 'project_ready', 'provisioning'}
            if (not isinstance(value, dict) or set(value) != expected or value['schema_version'] != 1
                    or value['cloud_init'] not in {'pending', 'completed', 'failed'}
                    or type(value['ssh_ready']) is not bool or type(value['project_ready']) is not bool
                    or (value['project_ready'] and (not value['ssh_ready'] or value['cloud_init'] != 'completed'))):
                raise ValueError
            validate_guest_manifest(value['provisioning'], data['requested_packages'], data['ssh_user'])
            return value
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            fail('GUEST_MANIFEST_INVALID', 'ownership', 'Local guest manifest is missing or corrupted.', 5)

    def verify(self, record, domain):
        data = self.files(record)
        if domain is None or domain.UUIDString() != record['domain_uuid'] or domain.name() != record['name'] or domain.autostart() != 0:
            fail('OWNERSHIP_MISMATCH', 'ownership', 'Domain identity or autostart conflicts with the registry.', 5)
        expected_owner = {key: record[key] for key in ('lab_id','instance_id','domain_uuid')}
        storage = Path(data['storage'])
        generation = data.get('restore_generation')
        work = Path(generation['path'])/'disk.qcow2' if generation else storage/'work.qcow2'
        nvram = Path(generation['path'])/'nvram.fd' if generation else storage/'nvram.fd'

        def verify_xml(text, *, persistent):
            root = ET.fromstring(text)
            owner = root.find(f'./metadata/{{{OWNER_NS}}}owner')
            disk_entries = root.findall('./devices/disk')
            sources = [entry.find('source') for entry in disk_entries]
            disks = [source.get('file') for source in sources if source is not None]
            network = root.findall('./devices/interface')
            work_disk = next((entry for entry in disk_entries
                              if entry.find('source') is not None
                              and entry.find('source').get('file') == str(work)), None)
            if generation:
                backing_valid = (work_disk is not None and immutable_backing_store(
                    work_disk, storage.parent/'baselines'/record['instance_id'] /
                    generation['baseline_id']/'disk.qcow2'))
            else:
                driver = work_disk.find('driver') if work_disk is not None else None
                backing_valid = (work_disk is not None
                                 and driver is not None
                                 and driver.attrib == {'name': 'qemu', 'type': 'qcow2'}
                                 and (work_disk.find('backingStore') is None if persistent
                                      else resolved_create_backing_store(
                                          work_disk, storage/'base.qcow2')))
            serial = root.find('./devices/serial/source')
            if (owner is None or owner.attrib != expected_owner
                    or len(disks) != len(disk_entries)
                    or sorted(disks) != sorted([str(work), str(storage/'seed.iso')])
                    or not backing_valid
                    or root.findtext('./os/nvram') != str(nvram)
                    or serial is None or serial.get('path') != str(storage/'serial.log')
                    or len(network) != 1 or network[0].find('source') is None
                    or network[0].find('source').get('network') != data['network']
                    or network[0].find('mac') is None
                    or network[0].find('mac').get('address') != data['mac']
                    or root.find('./devices/filesystem') is not None
                    or root.find('./devices/hostdev') is not None):
                fail('OWNERSHIP_MISMATCH', 'ownership',
                     'Domain metadata or resource paths differ.', 5)

        verify_xml(domain.XMLDesc(0), persistent=not bool(domain.isActive()))
        if domain.isActive():
            verify_xml(domain.XMLDesc(2), persistent=True)
        return data


class _BootstrapBackend:
    def __init__(self, backend): self.backend = backend
    def inspect(self, identity): return self.backend.domain(identity)


def domain_xml(record, config, data, firmware_code=FIRMWARE_CODE):
    storage = Path(data['storage'])
    root = ET.Element('domain', type='kvm')
    ET.SubElement(root, 'name').text = record['name']; ET.SubElement(root, 'uuid').text = record['domain_uuid']
    metadata = ET.SubElement(root, 'metadata')
    ET.SubElement(metadata, f'{{{OWNER_NS}}}owner', {key: record[key] for key in ('lab_id','instance_id','domain_uuid')})
    ET.SubElement(root, 'memory', unit='MiB').text = str(config['memory_mib'])
    ET.SubElement(root, 'vcpu').text = str(config['cpus'])
    osxml = ET.SubElement(root, 'os'); ET.SubElement(osxml, 'type', arch='x86_64', machine='q35').text = 'hvm'
    ET.SubElement(osxml, 'loader', readonly='yes', type='pflash').text = str(firmware_code)
    ET.SubElement(osxml, 'nvram').text = str(storage/'nvram.fd'); ET.SubElement(osxml, 'boot', dev='hd')
    features = ET.SubElement(root, 'features'); ET.SubElement(features, 'acpi'); ET.SubElement(features, 'apic')
    ET.SubElement(root, 'cpu', mode='host-passthrough')
    ET.SubElement(root, 'on_poweroff').text = 'destroy'; ET.SubElement(root, 'on_reboot').text = 'restart'
    devices = ET.SubElement(root, 'devices'); ET.SubElement(devices, 'emulator').text = '/usr/bin/qemu-system-x86_64'
    for name, device, bus, target in [('work.qcow2','disk','virtio','vda'), ('seed.iso','cdrom','sata','sda')]:
        disk = ET.SubElement(devices, 'disk', type='file', device=device)
        ET.SubElement(disk, 'driver', name='qemu', type='qcow2' if device == 'disk' else 'raw')
        ET.SubElement(disk, 'source', file=str(storage/name)); ET.SubElement(disk, 'target', dev=target, bus=bus)
        if device == 'cdrom': ET.SubElement(disk, 'readonly')
    interface = ET.SubElement(devices, 'interface', type='network')
    ET.SubElement(interface, 'mac', address=data['mac']); ET.SubElement(interface, 'source', network=data['network'])
    ET.SubElement(interface, 'model', type='virtio')
    serial = ET.SubElement(devices, 'serial', type='file')
    ET.SubElement(serial, 'source', path=str(storage/'serial.log'), append='on'); ET.SubElement(serial, 'target', port='0')
    return ET.tostring(root, encoding='unicode')


class Lifecycle:
    def __init__(self, *, paths=None, backend=None, host_record=None, clock=time.monotonic, sleeper=time.sleep,
                 runner=subprocess.run, exec_runner=exchange_tool, file_runner=exchange_tool,
                 sftp_runner=exchange_tool, host_source_scanner=scan_host_source,
                 host_destination_factory=HostDestination, uuid_factory=uuid4):
        self.paths = paths or StatePaths.from_environment()
        self.store = StateStore(self.paths)
        self.resources = ResourceLedger(self.store)
        self.backend = backend or LibvirtBackend()
        self.host_record = host_record
        self.clock, self.sleep, self.runner = clock, sleeper, runner
        self.exec_runner, self.uuid_factory = exec_runner, uuid_factory
        self.file_runner, self.sftp_runner = file_runner, sftp_runner
        self.host_source_scanner = host_source_scanner
        self.host_destination_factory = host_destination_factory

    def close(self): self.backend.close()

    def _deadline(self, deadline, phase='lifecycle'):
        if self.clock() >= deadline:
            fail('DEADLINE_EXCEEDED', phase, 'Overall deadline exceeded.', 7, retryable=True)

    def _host(self, config=None):
        plan = deepcopy(self.host_record) if self.host_record is not None else load_host_record()
        if config and config['network']['name'] != plan['network']:
            fail('NETWORK_NOT_QUALIFIED', 'preflight', 'Profile does not require the qualified lab network.', 3)
        network = self.backend.network(plan['network_uuid'])
        pool = self.backend.pool(plan['pool_uuid'])
        if (not network.isActive() or not pool.isActive()
                or not network_identity(network.XMLDesc(0), {'name':plan['network'],'uuid':plan['network_uuid'],'mode':'nat','subnet':plan['subnet']})
                or not pool_identity(pool.XMLDesc(0), {'name':plan['pool'],'uuid':plan['pool_uuid']}, plan['storage'])):
            fail('HOST_RESOURCES_CHANGED', 'preflight', 'Lab network or pool is inactive or differs from setup evidence.', 3)
        firmware = firmware_binding(plan)
        for key in ('code', 'vars'):
            path = firmware[key]
            if not path.is_file() or _sha(path) != firmware[key + '_sha256']:
                fail('FIRMWARE_CHANGED', 'preflight', 'Qualified OVMF pair is missing or changed.', 3)
        capabilities = self.backend.connect().getDomainCapabilities(None, 'x86_64', 'q35', 'kvm', 0)
        if not domain_capabilities(capabilities, str(firmware['code'])):
            fail('HOST_CAPABILITY_MISSING', 'preflight',
                 'KVM, q35, UEFI, or safe backing-store capability is missing.', 3)
        return plan

    def _verify_image(self, config):
        path = Path(config['base_image']['path'])
        if config['guest_os'] != 'arch' or config['base_image']['sha256'].lower() != ARCH_IMAGE_SHA256:
            fail('IMAGE_NOT_VERIFIED', 'image-verification', 'P06 supports only the accepted Arch cloud image.', 3)
        if path.name != 'image.qcow2' or path.parent.name != ARCH_IMAGE_SHA256:
            fail('IMAGE_NOT_VERIFIED', 'image-verification', 'Image path is not a bound P05 cache entry.', 3)
        manifest = ImageCache(path.parent.parent).verify_entry(ARCH_IMAGE_SHA256, ARCH_TRUST)
        if manifest['image']['sha256'] != config['base_image']['sha256'].lower():
            fail('IMAGE_NOT_VERIFIED', 'image-verification', 'Profile and cache manifest conflict.', 3)
        return path, manifest

    def _run(self, args, deadline, *, timeout=30):
        remaining = deadline - self.clock()
        if remaining <= 0: fail('DEADLINE_EXCEEDED', 'lifecycle', 'Overall deadline exceeded.', 7, retryable=True)
        status, output = run_tool(args, timeout=min(timeout, max(0.1, remaining)))
        return subprocess.CompletedProcess(args, status, output, b'')

    def _create_files(self, record, resolved, plan, image, deadline):
        self._deadline(deadline, 'allocating')
        instance = record['instance_id']; private = self.paths.data/'instances'/instance
        with directory(self.paths.data/'instances') as parent:
            os.mkdir(instance, 0o700, dir_fd=parent); os.fsync(parent)
        identity = client_identity(self.paths.data/'clients', instance)
        self._deadline(deadline, 'allocating')
        client_public = (identity/'id_ed25519.pub').read_text().strip()
        mac = '52:54:00:' + ':'.join(f'{value:02x}' for value in secrets.token_bytes(3))
        if any(mac in domain.XMLDesc(0) for domain in self.backend.connect().listAllDomains(0)):
            fail('MAC_CONFLICT', 'allocating', 'Generated MAC is already in use.', 4)
        runtime = Path(plan['storage'])/instance
        os.mkdir(runtime, 0o770)
        seed = render_seed(resolved, record, [client_public, *resolved.config['vm']['ssh']['public_keys']], network_mac=mac)
        for name, text in (('user-data',seed.user_data),('meta-data',seed.meta_data),('network-config',seed.network_config)):
            _write_new(private/name, text.encode())
        write_seed_iso(seed, private/'seed.iso')
        self._deadline(deadline, 'allocating')
        os.chmod(private/'seed.iso', 0o600)
        with open(image, 'rb') as source:
            fd = os.open(runtime/'base.qcow2', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o440)
            with os.fdopen(fd, 'wb') as target:
                while chunk := source.read(1024*1024):
                    if self.clock() >= deadline: fail('DEADLINE_EXCEEDED', 'allocating', 'Deadline exceeded while copying the base image.', 7)
                    target.write(chunk)
                target.flush(); os.fsync(target.fileno())
        _write_new(runtime/'work.qcow2', b'', 0o660)
        result = self._run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(runtime/'base.qcow2'),
                            str(runtime/'work.qcow2'),f"{resolved.config['vm']['disk_gib']}G"], deadline)
        if result.returncode:
            fail('DISK_CREATE_FAILED', 'allocating', 'Working disk could not be created.')
        firmware = firmware_binding(plan)
        _write_new(runtime/'nvram.fd', firmware['vars'].read_bytes(), 0o660)
        _write_new(runtime/'seed.iso', (private/'seed.iso').read_bytes(), 0o440)
        _write_new(runtime/'serial.log', b'', 0o660)
        self._deadline(deadline, 'allocating')
        data = {
            'schema_version':1, 'lab_id':record['lab_id'], 'instance_id':instance,
            'domain_uuid':record['domain_uuid'], 'name':record['name'], 'uri':record['uri'],
            'storage':str(runtime), 'directory':_identity(runtime),
            'files':{name:_identity(runtime/name) for name in RUNTIME_FILES}, 'mac':mac,
            'network':plan['network'], 'network_uuid':plan['network_uuid'],
            'pool':plan['pool'], 'pool_uuid':plan['pool_uuid'], 'image_sha256':ARCH_IMAGE_SHA256,
            'seed':vars(seed.binding), 'ssh_user':resolved.config['vm']['ssh']['user'],
            'requested_packages':resolved.config['vm']['packages'],
        }
        pending = {
            'schema_version': 1, 'cloud_init': 'pending', 'ssh_ready': False, 'project_ready': False,
            'provisioning': {
                'schema_version': 1, 'adapter': 'arch-pacman-v1', 'status': 'provisioning',
                'requested_packages': resolved.config['vm']['packages'], 'installed_packages': {},
                'user': {'name': data['ssh_user'], 'valid': False},
                'ssh': {'public_key_login': True, 'password_authentication': None},
                'transaction': {'attempted': bool(resolved.config['vm']['packages']), 'exit_code': None},
                'error': None,
            },
        }
        _write_new(private/'instance.json', _canonical(data))
        _write_new(private/'guest-manifest.json', _canonical(pending))
        xml = domain_xml(record, resolved.config['vm'], data, firmware['code'])
        _write_new(private/'domain.xml', xml.encode())
        self.store.register_instance_files(record, record['journal'][-1]['id'], PRIVATE_FILES)
        return data, xml

    def _readiness(self, record, ownership, deadline, bootstrap_seed=True):
        data = ownership.verify(record, self.backend.domain(record['domain_uuid']))
        serial_path = Path(data['storage'])/'serial.log'; serial = ''
        pinned = not bootstrap_seed
        while self.clock() < deadline:
            ownership.verify(self.store.inspect(record['instance_id']), self.backend.domain(record['domain_uuid']))
            domain = self.backend.domain(record['domain_uuid'])
            if not domain.isActive(): fail('DOMAIN_STOPPED', 'readiness', 'Guest stopped during readiness validation.', 6)
            if serial_path.stat().st_size > 1024*1024: fail('SERIAL_LIMIT', 'readiness', 'Serial log exceeds 1 MiB.', 6)
            serial = serial_path.read_text(errors='replace')
            leases = self.backend.ipv4_leases(data['network_uuid'], data['mac'])
            if len(leases) != 1 or (bootstrap_seed and MARKER not in serial):
                self.sleep(1)
                continue
            address = leases[0]
            identity = self.paths.data/'clients'/record['instance_id']
            if not pinned:
                scan = self._run(['ssh-keyscan','-T','5','-t','ed25519',address], deadline, timeout=10)
                lines = [line for line in scan.stdout.decode(errors='replace').splitlines() if line and not line.startswith('#')]
                keys = {public_key(' '.join(line.split()[1:]))[0] for line in lines if len(line.split()) >= 3}
                if scan.returncode or len(keys) != 1:
                    self.sleep(1)
                    continue
                binding = Binding(**data['seed'])
                bootstrap(ownership, _BootstrapBackend(self.backend), binding,
                          lambda domain_uuid, limit: serial, next(iter(keys)), identity,
                          timeout=max(0.1, deadline-self.clock()))
                pinned = True
            args = ssh_arguments(identity, record['instance_id'], address, data['ssh_user'])
            check = self._run(args + ['true'], deadline, timeout=max(1, deadline-self.clock()))
            if check.returncode == 0:
                return address
            self.sleep(1)
        fail('GUEST_NOT_READY', 'readiness', 'No authenticated IPv4 or SSH readiness within the deadline.', 7,
             'Inspect the domain, DHCP lease, serial host-key evidence, and SSH readiness.', True)

    def _persist_guest_manifest(self, record, ownership, value):
        raw = _canonical(value)
        if len(raw) > 65536:
            fail('GUEST_MANIFEST_INVALID', 'provisioning', 'Guest manifest exceeds the limit.', 8)
        with ownership.store.selection(record, ownership.operation_id, ownership.recover_failed_start) as parent:
            fd = os.open('guest-manifest.json', os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)

    def _project_readiness(self, record, ownership, address, deadline):
        data = ownership.verify(record, self.backend.domain(record['domain_uuid']))
        args = ssh_arguments(self.paths.data/'clients'/record['instance_id'], record['instance_id'],
                             address, data['ssh_user'])
        try:
            report = self._run(args + [GUEST_REPORT_COMMAND], deadline,
                               timeout=max(0.1, deadline-self.clock()))
        except LabError as error:
            if error.exit_code == 7:
                fail('PROVISIONING_TIMEOUT', 'provisioning',
                     'Cloud-init or guest provisioning remained incomplete within the overall deadline.', 7,
                     'Inspect guest and cloud-init status; do not infer project-ready state.', True)
            raise
        if report.returncode == 255:
            fail('SSH_TRANSPORT_FAILED', 'provisioning', 'Verified SSH connection failed during guest validation.', 6,
                 'Inspect network and guest status; do not treat provisioning as complete.', True)
        if report.returncode != 0 or len(report.stdout) > 65536:
            fail('GUEST_REPORT_FAILED', 'provisioning', 'Guest status could not be read safely.', 8)
        first, separator, payload = report.stdout.partition(b'\n')
        try:
            cloud_status = int(first)
            guest = json.loads(payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            fail('GUEST_MANIFEST_INVALID', 'provisioning', 'Cloud-init or guest-manifest output is incomplete.', 8)
        guest = validate_guest_manifest(guest, data['requested_packages'], data['ssh_user'])
        local = {'schema_version': 1, 'cloud_init': 'completed' if cloud_status == 0 else 'failed',
                 'ssh_ready': True, 'project_ready': False, 'provisioning': guest}
        if cloud_status != 0:
            self._persist_guest_manifest(record, ownership, local)
            if guest['error'] in {'PACKAGE_TRANSACTION_FAILED', 'PACKAGE_MISSING'}:
                fail(guest['error'], 'provisioning', 'Arch package transaction or version check failed.', 8,
                     'Inspect the package list, mirror state, and cloud-init diagnostics in the guest.')
            if guest['error'] == 'USER_SSH_INVALID':
                fail('GUEST_CONFIG_INVALID', 'provisioning', 'User or SSH configuration in the guest is invalid.', 8)
            fail('CLOUD_INIT_FAILED', 'provisioning', 'Cloud-init did not report successful completion.', 8)
        complete = (guest['status'] == 'project-ready' and guest['error'] is None
                    and guest['user']['valid'] and all(guest['ssh'].values())
                    and set(guest['installed_packages']) == set(data['requested_packages'])
                    and (guest['transaction']['exit_code'] == 0 if data['requested_packages']
                         else guest['transaction']['exit_code'] is None))
        if not complete:
            self._persist_guest_manifest(record, ownership, local)
            fail('PROJECT_NOT_READY', 'provisioning', 'Not all defined guest checks succeeded.', 8)
        local['project_ready'] = True
        self._persist_guest_manifest(record, ownership, local)
        return local

    def create(self, resolved, name, no_start, deadline):
        self._deadline(deadline, 'preflight')
        vm = resolved.config['vm']
        image, image_manifest = self._verify_image(vm)
        self._deadline(deadline, 'image-verification')
        plan = self._host(vm)
        self._deadline(deadline, 'preflight')
        available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:'))) * 1024
        if available < (vm['memory_mib'] + 4096) * 1024**2:
            fail('MEMORY_BUDGET', 'preflight', 'VM commitment plus 4 GiB host reserve is unavailable.', 3)
        if shutil.disk_usage(plan['storage']).free < (vm['disk_gib'] + plan['reserve_gib']) * 1024**3:
            fail('STORAGE_BUDGET', 'preflight', 'Storage budget plus host reserve is unavailable.', 3)
        self._deadline(deadline, 'preflight')
        self.store.initialize()
        wanted = resource_request(
            instances=1, vcpus=vm['cpus'], memory_mib=vm['memory_mib'],
            virtual_disk_bytes=vm['disk_gib'] * 1024 ** 3,
            staging_bytes=vm['disk_gib'] * 1024 ** 3)
        record = self.resources.reserve_create(
            name, wanted,
            host_storage_bytes=max(
                0, shutil.disk_usage(plan['storage']).free
                   - plan['reserve_gib'] * 1024 ** 3),
            host_memory_mib=max(0, available // 1024 ** 2 - 4096))
        op = record['journal'][-1]['id']
        with self.store.lock(record['instance_id']):
            try:
                if self.backend.domain(record['domain_uuid'], missing_ok=True) is not None:
                    fail('DOMAIN_CONFLICT', 'preflight', 'Reserved domain UUID already exists.', 4)
                if any(domain.name() == name for domain in self.backend.connect().listAllDomains(0)):
                    fail('DOMAIN_CONFLICT', 'preflight', 'Domain name is already in use in libvirt.', 4)
                self.store.advance(record['instance_id'], op, 'allocating')
                record = self.store.inspect(record['instance_id'])
                data, xml = self._create_files(record, resolved, plan, image, deadline)
                ownership = RealOwnership(self.store, self.backend, op)
                domain = self.backend.define(xml); ownership.verify(self.store.inspect(record['instance_id']), domain)
                self.store.advance(record['instance_id'], op, 'defined', complete=no_start)
                if not no_start:
                    self.store.advance(record['instance_id'], op, 'booting')
                    self.backend.start(record['domain_uuid'])
                    self.store.advance(record['instance_id'], op, 'provisioning')
                    current = self.store.inspect(record['instance_id'])
                    address = self._readiness(current, ownership, deadline)
                    readiness = self._project_readiness(current, ownership, address, deadline)
                    self.store.advance(record['instance_id'], op, 'ready', complete=True)
                else:
                    address = None
                    readiness = ownership.guest_manifest(self.store.inspect(record['instance_id']))
                final = self.store.inspect(record['instance_id'])
                self.resources.bind(
                    final['instance_id'], op,
                    resource_request(
                        instances=1, vcpus=vm['cpus'], memory_mib=vm['memory_mib'],
                        virtual_disk_bytes=vm['disk_gib'] * 1024 ** 3,
                        storage_bytes=allocated_bytes(data['storage']), operations=0))
                return {'name':name, 'instance_id':final['instance_id'], 'domain_uuid':final['domain_uuid'],
                        'power_state':'shutoff' if no_start else 'running', 'ipv4':address,
                        'image_sha256':image_manifest['image']['sha256'], 'network':data['network'],
                        'readiness':readiness}
            except BaseException:
                try: self.store.advance(record['instance_id'], op, 'failed', failed=True)
                except Exception: pass
                try: self.resources.review(record['instance_id'], op)
                except Exception: pass
                raise

    def _owned(self, target, operation_id=None):
        record = self.store.inspect(target)
        if record['requires_review'] and operation_id is None:
            fail('REVIEW_REQUIRED', 'state', 'Incomplete operation blocks further mutations.', 4)
        domain = self.backend.domain(record['domain_uuid'])
        owner = RealOwnership(self.store, self.backend, operation_id)
        data = owner.verify(record, domain)
        return record, domain, owner, data

    def status(self, target):
        record = self.store.inspect(target)
        domain = self.backend.domain(record['domain_uuid'], missing_ok=True)
        data = None; power = 'missing'
        if domain is not None:
            power = 'running' if domain.isActive() else 'shutoff'
            if not record['requires_review']:
                owner = RealOwnership(self.store, self.backend)
                data = owner.verify(record, domain)
        leases = self.backend.ipv4_leases(data['network_uuid'], data['mac']) if data and domain.isActive() else []
        readiness = owner.guest_manifest(record) if data else None
        return {'name':record['name'],'instance_id':record['instance_id'],'domain_uuid':record['domain_uuid'],
                'lifecycle_state':record['state'],'power_state':power,'ipv4':leases,
                'requires_review':record['requires_review'],'last_operation':record['journal'][-1],
                'readiness':readiness}

    @staticmethod
    def _operation_summary(operation, *, current, resolved_by):
        result = {
            'id': operation['id'], 'kind': operation['kind'],
            'phase': operation['phase'], 'last_safe': operation['last_safe'],
            'status': operation['status'], 'events': list(operation['events']),
            'current': current,
            'blocking': current and operation['status'] != 'complete',
            'resolved_by': resolved_by,
            'error_code': None,
        }
        if operation['kind'] == 'exec':
            evidence = operation['exec']
            result['exec'] = {
                key: deepcopy(evidence[key]) for key in (
                    'protocol_version', 'adapter_version', 'job_id', 'outcome',
                    'started', 'pid', 'pgid', 'guest_exit_code', 'ssh_exit_code',
                    'stdout', 'stderr')
            }
        if operation['kind'] == 'copy':
            result['transfer'] = deepcopy(operation['transfer'])
        return result

    @staticmethod
    def _resolved_operations(journal):
        resolved = {}
        for operation in journal:
            recovery = operation.get('recovery')
            if (operation['status'] == 'complete' and isinstance(recovery, dict)
                    and isinstance(recovery.get('source_operation'), str)):
                resolved.setdefault(recovery['source_operation'], []).append(operation['id'])
            elif operation['kind'] == 'start_recovery' and operation['status'] == 'complete':
                index = journal.index(operation)
                if index:
                    resolved.setdefault(journal[index - 1]['id'], []).append(operation['id'])
        return resolved

    def list_instances(self):
        """Return only registered owned instances; never inventory foreign domains."""
        instances = []
        for record in self.store.inventory():
            latest = record['journal'][-1]
            base = {
                'name': record['name'], 'instance_id': record['instance_id'],
                'domain_uuid': record['domain_uuid'],
                'lifecycle_state': record['state'],
                'requires_review': record['requires_review'],
                'last_operation': self._operation_summary(
                    latest, current=True,
                    resolved_by=self._resolved_operations(record['journal']).get(latest['id'], [])),
            }
            if record['state'] == 'destroyed':
                instances.append({**base, 'power_state': 'removed', 'readiness': None,
                                  'qualification': 'tombstone', 'diagnostic_error': None})
                continue
            try:
                if record['requires_review']:
                    domain = self.backend.domain(record['domain_uuid'])
                    owner, _data = self._diagnostic_owner(record, domain)
                    power = 'running' if domain.isActive() else 'shutoff'
                    readiness = owner.guest_manifest(record)
                    qualification = 'review-required'
                else:
                    status = self.status(record['instance_id'])
                    power, readiness = status['power_state'], status['readiness']
                    qualification = 'verified'
                instances.append({
                    **base, 'power_state': power,
                    'readiness': readiness, 'qualification': qualification,
                    'diagnostic_error': None,
                })
            except LabError as error:
                instances.append({
                    **base, 'power_state': 'unknown', 'readiness': None,
                    'qualification': 'error', 'diagnostic_error': error.detail,
                })
        return {
            'instances': instances,
            'active_count': sum(item['lifecycle_state'] != 'destroyed' for item in instances),
            'tombstone_count': sum(item['lifecycle_state'] == 'destroyed' for item in instances),
        }

    @staticmethod
    def _redact_log(text):
        text = re.sub(
            r'-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----',
            '[REDACTED PRIVATE KEY]', text, flags=re.DOTALL | re.IGNORECASE)
        return re.sub(
            r'(?im)\b(password|passwd|token|secret|authorization|private[_-]?key)'
            r'(\s*[:=]\s*)([^\s]+)', r'\1\2[REDACTED]', text)

    def _diagnostic_owner(self, record, domain):
        latest = record['journal'][-1]
        owner = RealOwnership(
            self.store, self.backend, latest['id'], read_only_diagnostic=True,
        ) if record['requires_review'] else RealOwnership(self.store, self.backend)
        return owner, owner.verify(record, domain)

    def logs(self, target, operation_id=None, max_bytes=LOG_DEFAULT_BYTES):
        """Bound serial log tail plus read-only journal diagnostics."""
        if type(max_bytes) is not int or not 1 <= max_bytes <= LOG_MAX_BYTES:
            fail('LOG_LIMIT_INVALID', 'diagnostics', 'Log limit is outside the permitted range.', 2,
                 f'Use --max-bytes between 1 and {LOG_MAX_BYTES}.')
        record = self.store.inspect(target)
        journal = record['journal']
        selected = next((item for item in journal if item['id'] == operation_id), None) if operation_id else journal[-1]
        if selected is None:
            fail('OPERATION_NOT_FOUND', 'diagnostics', 'Operation UUID does not belong to this instance.', 4,
                 'Obtain the UUID from the journal with vmctl logs VM without --operation.')
        resolved = self._resolved_operations(journal)
        operations = [self._operation_summary(
            item, current=item is journal[-1], resolved_by=resolved.get(item['id'], []))
            for item in journal]
        serial = {'available': False, 'text': '', 'bytes_returned': 0,
                  'source_size': None, 'truncated': False, 'untrusted': True,
                  'error': None}
        if record['state'] != 'destroyed':
            domain = self.backend.domain(record['domain_uuid'])
            owner, data = self._diagnostic_owner(record, domain)
            path = Path(data['storage']) / 'serial.log'
            expected = data['files']['serial.log']
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                fail('LOG_IO', 'diagnostics', 'Bound serial log cannot be read safely.', 6,
                     'Inspect file binding and permissions; do not change permissions automatically.')
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or (info.st_dev, info.st_ino) != (expected['device'], expected['inode'])):
                    fail('OWNERSHIP_MISMATCH', 'diagnostics',
                         'Serial log was replaced or is not regular.', 5)
                start = max(0, info.st_size - max_bytes)
                os.lseek(fd, start, os.SEEK_SET)
                raw = os.read(fd, max_bytes)
                text = self._redact_log(raw.decode('utf-8', errors='replace'))
                encoded = text.encode('utf-8')
                if len(encoded) > max_bytes:
                    encoded = encoded[:max_bytes]
                    text = encoded.decode('utf-8', errors='ignore')
                serial.update(available=True, text=text,
                              bytes_returned=len(text.encode('utf-8')),
                              source_size=info.st_size, truncated=start > 0)
                if selected['kind'] == 'create' and selected['phase'] == 'failed':
                    guest = owner.guest_manifest(record)
                    code = guest['provisioning'].get('error')
                    next(item for item in operations if item['id'] == selected['id'])['error_code'] = code
                owner.verify(record, self.backend.domain(record['domain_uuid']))
            finally:
                os.close(fd)
        return {
            'name': record['name'], 'instance_id': record['instance_id'],
            'domain_uuid': record['domain_uuid'], 'lifecycle_state': record['state'],
            'requires_review': record['requires_review'],
            'current_operation': operations[-1],
            'selected_operation': next(item for item in operations if item['id'] == selected['id']),
            'operations': operations, 'serial_log': serial,
            'follow_supported': False,
        }

    def restart(self, target, deadline):
        """Use one shared deadline but deliberately retain two journal operations."""
        self._deadline(deadline, 'restart')
        stopped = self.stop(target, deadline, force=False)
        if stopped['power_state'] != 'shutoff':
            fail('SHUTDOWN_UNCONFIRMED', 'restart',
                 'Graceful shutdown was not confirmed unambiguously.', 6,
                 'Inspect domain status and journal; do not trigger an automatic start.')
        self._deadline(deadline, 'restart')
        return self.start(stopped['instance_id'], deadline)

    def start(self, target, deadline):
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            if initial['requires_review']:
                return self._recover_start(initial, deadline)
            record, domain, owner, data = self._owned(initial['instance_id'])
            if domain.isActive(): return self.status(record['instance_id'])
            plan = self._host({'network': {'name': data['network']}})
            if data['network_uuid'] != plan['network_uuid'] or data['pool_uuid'] != plan['pool_uuid']:
                fail('HOST_RESOURCES_CHANGED', 'preflight', 'Instance and current host setup use different resource UUIDs.', 5)
            generation = data.get('restore_generation')
            if generation:
                from .baselines import BaselineManager
                from .restore import RestoreRuntimeAccess
                access = RestoreRuntimeAccess(
                    clock=self.clock,
                    tool=lambda argv, limit: self._run(
                        argv, limit, timeout=max(0.1, limit-self.clock())),
                    lookup=getattr(self, 'qemu_lookup', pwd.getpwnam),
                    lookup_uid=getattr(self, 'uid_lookup', pwd.getpwuid),
                    lookup_gid=getattr(self, 'gid_lookup', grp.getgrgid))
                activation = next((item for item in record['journal']
                                   if item['id'] == generation.get('activation_operation_id')),
                                  None)
                if (activation is None or activation.get('kind') != 'restore_activation'
                        or activation.get('status') != 'complete'
                        or activation.get('phase') != 'activated'
                        or activation.get('restore', {}).get('baseline_id')
                           != generation.get('baseline_id')):
                    fail('RESTORE_ACCESS_INVALID', 'preflight',
                         'Active restore generation has no unambiguous baseline binding.', 5)
                baselines = BaselineManager(
                    self, clock=self.clock,
                    tool=lambda argv, limit: self._run(
                        argv, limit, timeout=max(0.1, limit-self.clock())))
                baseline = baselines.verify(
                    record['instance_id'], generation['baseline_id'], deadline)
                baseline_binding = generation.get('baseline_disk')
                if baseline_binding is None:
                    recovery = next((item.get('recovery') for item in reversed(record['journal'])
                                     if item.get('kind') == 'restore_start_recovery'
                                     and item.get('status') == 'complete'
                                     and item.get('recovery', {}).get('restore_activation')
                                        == generation['activation_operation_id']
                                     and 'baseline_disk' in item.get('recovery', {})), None)
                    baseline_binding = recovery and recovery['baseline_disk']
                if baseline_binding is None:
                    fail('RESTORE_ACCESS_INVALID', 'preflight',
                         'Baseline disk has no persisted inode binding.', 5)
                access.verify(Path(generation['path']), plan, deadline,
                              baseline=Path(baseline['path']),
                              baseline_binding=baseline_binding)
            self._deadline(deadline, 'preflight')
            op = self.store.begin(record, 'start'); owner.operation_id = op
            try:
                owner.verify(self.store.inspect(record['instance_id']), domain)
                self.store.advance(record['instance_id'], op, 'booting'); self.backend.start(record['domain_uuid'])
                identity = self.paths.data/'clients'/record['instance_id']
                first_boot = not os.path.lexists(identity/'known_hosts')
                current = self.store.inspect(record['instance_id'])
                address = self._readiness(current, owner, deadline, bootstrap_seed=first_boot)
                self._project_readiness(current, owner, address, deadline)
                self.store.advance(record['instance_id'], op, 'ready', complete=True)
            except BaseException:
                try: self.store.advance(record['instance_id'], op, 'failed', failed=True)
                except Exception: pass
                raise
        return self.status(record['instance_id'])

    def _recover_start(self, record, deadline):
        failed = record['journal'][-1]
        if not self.store._recoverable_start(failed):
            fail('REVIEW_REQUIRED', 'recovery', 'Only an exactly matching failed start can be continued.', 4)
        domain = self.backend.domain(record['domain_uuid'])
        owner = RealOwnership(self.store, self.backend, failed['id'], recover_failed_start=True)
        data = owner.verify(record, domain)
        if not domain.isActive():
            fail('RECOVERY_STATE_CONFLICT', 'recovery', 'Failed start is no longer active in reality.', 4,
                 'Inspect the state manually; do not force a start or cleanup mutation.')
        plan = self._host({'network': {'name': data['network']}})
        if data['network_uuid'] != plan['network_uuid'] or data['pool_uuid'] != plan['pool_uuid']:
            fail('HOST_RESOURCES_CHANGED', 'recovery', 'Instance and current host setup use different resource UUIDs.', 5)
        self._deadline(deadline, 'recovery')
        address = self._readiness(record, owner, deadline, bootstrap_seed=False)
        self._project_readiness(record, owner, address, deadline)
        current = self.store.inspect(record['instance_id'])
        owner.verify(current, self.backend.domain(record['domain_uuid']))
        operation = self.store.begin_start_recovery(current)
        current = self.store.inspect(record['instance_id'])
        owner.operation_id = operation
        owner.recover_failed_start = False
        owner.verify(current, self.backend.domain(record['domain_uuid']))
        self.store.advance(record['instance_id'], operation, 'ready', complete=True)
        return self.status(record['instance_id'])

    def stop(self, target, deadline, force=False):
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record, domain, owner, _ = self._owned(initial['instance_id'])
            if not domain.isActive(): return self.status(record['instance_id'])
            op = self.store.begin(record, 'shutdown'); owner.operation_id = op
            try:
                owner.verify(self.store.inspect(record['instance_id']), domain); self.backend.request_shutdown(record['domain_uuid'])
                while domain.isActive() and self.clock() < deadline: self.sleep(1)
                if domain.isActive():
                    if not force: fail('SHUTDOWN_TIMEOUT', 'shutdown', 'Guest does not respond to graceful shutdown.', 7,
                                       'Retry with a longer deadline; use hard power-off deliberately with --force --yes only.')
                    owner.verify(self.store.inspect(record['instance_id']), domain)
                    self.store.mark_force_stop(record['instance_id'], op)
                    self.backend.force_stop(record['domain_uuid'])
                owner.verify(self.store.inspect(record['instance_id']), domain)
                self.store.advance(record['instance_id'], op, 'defined', complete=True)
            except BaseException:
                try: self.store.advance(record['instance_id'], op, 'failed', failed=True)
                except Exception: pass
                raise
        return self.status(record['instance_id'])

    def snapshot(self, target, name, readiness, deadline):
        """Create a P08-A bundle without restore or domain mutation."""
        from .baselines import BaselineManager
        manager = BaselineManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.create(target, name, readiness, deadline)

    def verify_snapshot(self, target, baseline_id, deadline):
        from .baselines import BaselineManager
        manager = BaselineManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.verify(target, baseline_id, deadline)

    def list_snapshots(self, target, deadline):
        from .baselines import BaselineManager
        manager = BaselineManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.list(target, deadline)

    def prepare_restore(self, target, baseline_id, operation_id, deadline):
        """Perform P08-B1 staging without switching domain, registry, or runtime state."""
        from .restore import RestorePreparationManager
        manager = RestorePreparationManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.prepare(target, baseline_id, operation_id, deadline)

    def inspect_restore_preparation(self, target, baseline_id, operation_id, deadline):
        from .restore import RestorePreparationManager
        manager = RestorePreparationManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.inspect(target, baseline_id, operation_id, deadline)

    def activate_restore(self, target, baseline_id, operation_id, deadline):
        """Switch to a reverified B1 generation for P08-B2 without starting it."""
        from .restore import RestoreActivationManager
        manager = RestoreActivationManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.activate(target, baseline_id, operation_id, deadline)

    def recover_restore(self, target, operation_id, deadline):
        """Recover an unambiguously bound restore activation for P08-B3."""
        from .restore import RestoreRecoveryManager
        manager = RestoreRecoveryManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.recover(target, operation_id, deadline)

    def recover_restore_start(self, target, operation_id, deadline):
        """Resolve an ACL-related failed start without starting the domain."""
        from .restore import RestoreStartRecoveryManager
        manager = RestoreStartRecoveryManager(
            self, clock=self.clock,
            tool=lambda argv, limit: self._run(
                argv, limit, timeout=max(0.1, limit-self.clock())))
        return manager.recover(target, operation_id, deadline)

    def cleanup_staging(self, target, kind, operation_id, deadline):
        """P09-C: remove only explicitly bound failed staging."""
        from .staging_cleanup import StagingCleanupManager
        self._deadline(deadline, 'staging-cleanup')
        return StagingCleanupManager(self).cleanup(
            target, kind, operation_id, deadline)

    def ssh(self, target, deadline):
        record, domain, owner, data = self._owned(target)
        if not domain.isActive(): fail('DOMAIN_NOT_RUNNING', 'ssh', 'VM is not running.', 4)
        leases = self.backend.ipv4_leases(data['network_uuid'], data['mac'])
        if len(leases) != 1: fail('SSH_TARGET_UNAVAILABLE', 'ssh', 'No unambiguous IPv4 address for the registered MAC.', 6, retryable=True)
        args = ssh_arguments(self.paths.data/'clients'/record['instance_id'], record['instance_id'], leases[0], data['ssh_user'])
        remaining = deadline-self.clock()
        if remaining <= 0: fail('DEADLINE_EXCEEDED', 'ssh', 'Overall deadline exceeded before SSH.', 7)
        try:
            result = self.runner(args, timeout=remaining)
        except subprocess.TimeoutExpired:
            fail('DEADLINE_EXCEEDED', 'ssh', 'Interactive SSH session reached the overall deadline.', 7,
                 'Reconnect with a longer --timeout deadline if needed.', True)
        except FileNotFoundError:
            fail('SSH_CLIENT_MISSING', 'ssh', 'OpenSSH client was not found.', 3,
                 'Provide OpenSSH as described in docs/INSTALLATION.md; do not install anything automatically.')
        return result.returncode

    @staticmethod
    def _exec_evidence(job_id, argv, outcome='dispatched', **changes):
        evidence = {
            'protocol_version': PROTOCOL_VERSION,
            'adapter_version': ADAPTER_VERSION,
            'job_id': job_id,
            'argv_sha256': hashlib.sha256(_canonical(argv)).hexdigest(),
            'argv_count': len(argv),
            'outcome': outcome,
            'started': None,
            'pid': None,
            'pgid': None,
            'guest_exit_code': None,
            'ssh_exit_code': None,
            'stdout': None,
            'stderr': None,
        }
        evidence.update(changes)
        return evidence

    @staticmethod
    def _exec_stream_evidence(value):
        return {key: value[key] for key in (
            'bytes_total', 'bytes_captured', 'bytes_returned', 'truncated', 'redacted')}

    def exec(self, target, argv, deadline, operation_id):
        """P11-A: exactly one argv-bound guest job without a PTY or retry."""
        argv = validate_argv(argv)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record, domain, owner, data = self._owned(initial['instance_id'])
            if not domain.isActive():
                fail('DOMAIN_NOT_RUNNING', 'exec', 'VM is not running.', 4)
            if record['state'] != 'ready':
                fail('GUEST_NOT_READY', 'exec',
                     'Lifecycle has no confirmed ready state.', 4,
                     'Qualify the VM normally with vmctl start; do not reinterpret an external start.')
            readiness = owner.guest_manifest(record)
            if not readiness['ssh_ready'] or not readiness['project_ready']:
                fail('GUEST_NOT_READY', 'exec', 'Guest is not fully project-ready.', 4,
                     'Inspect status and the bound guest manifest; do not force execution.')
            leases = self.backend.ipv4_leases(data['network_uuid'], data['mac'])
            if len(leases) != 1:
                fail('SSH_TARGET_UNAVAILABLE', 'exec',
                     'No unambiguous IPv4 address for the registered MAC.', 6,
                     'Inspect the DHCP lease and guest status; do not retry the job automatically.', True)
            remaining = deadline - self.clock()
            if remaining <= 0:
                fail('DEADLINE_EXCEEDED', 'exec', 'Overall deadline exceeded before exec.', 7)
            job_id = str(self.uuid_factory())
            guest_timeout = remaining - 1 if remaining > 2 else remaining * .8
            frame, _ = exec_request(job_id, argv, guest_timeout, STREAM_LIMIT)
            identity = self.paths.data / 'clients' / record['instance_id']
            ssh = ssh_arguments(identity, record['instance_id'], leases[0], data['ssh_user'])
            ssh = [*ssh[:-2], '-T', *ssh[-2:], remote_command()]
            evidence = self._exec_evidence(job_id, argv)
            self.store.begin_exec(record, operation_id, evidence)
            exchange = self.exec_runner(ssh, frame, remaining, RESPONSE_LIMIT)
            if exchange.timed_out:
                outcome = 'timed_out'
                evidence = self._exec_evidence(job_id, argv, outcome)
                self.store.complete_exec(record['instance_id'], operation_id, outcome, evidence)
                return self._exec_result(record, operation_id, job_id, outcome, evidence)
            if exchange.output_limited:
                outcome = 'protocol_failed'
                evidence = self._exec_evidence(job_id, argv, outcome, ssh_exit_code=exchange.returncode)
                self.store.complete_exec(record['instance_id'], operation_id, outcome, evidence)
                return self._exec_result(record, operation_id, job_id, outcome, evidence)
            if exchange.returncode != 0:
                outcome = 'transport_failed'
                evidence = self._exec_evidence(job_id, argv, outcome,
                                               ssh_exit_code=exchange.returncode)
                self.store.complete_exec(record['instance_id'], operation_id, outcome, evidence)
                return self._exec_result(record, operation_id, job_id, outcome, evidence)
            try:
                answer = exec_response(exchange.stdout, job_id)
            except LabError:
                outcome = 'protocol_failed'
                evidence = self._exec_evidence(job_id, argv, outcome, ssh_exit_code=0)
                self.store.complete_exec(record['instance_id'], operation_id, outcome, evidence)
                return self._exec_result(record, operation_id, job_id, outcome, evidence)
            outcome = ('timed_out' if answer['state'] == 'timed_out' else
                       'completed' if answer['guest_exit_code'] == 0 else 'guest_failed')
            evidence = self._exec_evidence(
                job_id, argv, outcome, started=answer['started'], pid=answer['pid'],
                pgid=answer['pgid'], guest_exit_code=answer['guest_exit_code'],
                ssh_exit_code=0, stdout=self._exec_stream_evidence(answer['stdout']),
                stderr=self._exec_stream_evidence(answer['stderr']))
            owner.verify(self.store.inspect(record['instance_id']),
                         self.backend.domain(record['domain_uuid']))
            self.store.complete_exec(record['instance_id'], operation_id, outcome, evidence)
            return self._exec_result(record, operation_id, job_id, outcome, evidence, answer)

    @staticmethod
    def _exec_result(record, operation_id, job_id, outcome, evidence, answer=None):
        return {
            'name': record['name'], 'instance_id': record['instance_id'],
            'domain_uuid': record['domain_uuid'], 'operation_id': operation_id,
            'job_id': job_id, 'protocol_version': PROTOCOL_VERSION,
            'adapter_version': ADAPTER_VERSION, 'outcome': outcome,
            'guest_started': evidence['started'], 'guest_pid': evidence['pid'],
            'guest_pgid': evidence['pgid'], 'guest_exit_code': evidence['guest_exit_code'],
            'ssh_exit_code': evidence['ssh_exit_code'],
            'stdout': deepcopy(answer['stdout']) if answer else None,
            'stderr': deepcopy(answer['stderr']) if answer else None,
            'output_untrusted': True,
        }

    @staticmethod
    def _transfer_evidence(transfer_id, spec, overwrite, outcome='dispatched', **changes):
        evidence = {
            'protocol_version': FILE_PROTOCOL_VERSION,
            'adapter_version': FILE_ADAPTER_VERSION,
            'transfer_id': transfer_id,
            'direction': spec['direction'],
            'guest_path': spec['guest_path'],
            'host_path_sha256': hashlib.sha256(
                str(Path(spec['host_path']).absolute()).encode()).hexdigest(),
            'outcome': outcome, 'kind': None, 'file_count': None,
            'total_bytes': None, 'manifest_sha256': None,
            'ssh_exit_code': None, 'overwrite': overwrite,
            'source_commit': (spec.get('source_git') or {}).get('commit'),
            'source_dirty': (spec.get('source_git') or {}).get('dirty'),
        }
        evidence.update(changes)
        return evidence

    def _file_control(self, ssh, action, transfer_id, path, deadline, **values):
        remaining = deadline - self.clock()
        if remaining <= 0:
            return None, 'timed_out', None
        frame = file_request(action, transfer_id, path, **values)
        command = [*ssh[:-2], '-T', *ssh[-2:], file_remote_command()]
        exchange = self.file_runner(command, frame, remaining, FILE_RESPONSE_LIMIT + 64)
        if exchange.timed_out:
            return None, 'timed_out', None
        if exchange.output_limited or exchange.returncode != 0:
            return None, 'transport_failed', exchange.returncode
        try:
            answer = file_response(exchange.stdout, transfer_id, action)
        except LabError:
            return None, 'transport_failed', 0
        if not answer['ok']:
            outcome = ('integrity_failed' if answer['code'] == 'COPY_INTEGRITY_MISMATCH'
                       else 'file_failed')
            return answer, outcome, 0
        return answer, None, 0

    def _finish_transfer(self, record, operation_id, transfer_id, spec, overwrite,
                         outcome, manifest=None, kind=None, ssh_exit_code=None):
        files = manifest or []
        evidence = self._transfer_evidence(
            transfer_id, spec, overwrite, outcome,
            kind=kind, file_count=len(files) if files else None,
            total_bytes=sum(item['size'] for item in files) if files else None,
            manifest_sha256=manifest_digest(kind, files) if files and kind else None,
            ssh_exit_code=ssh_exit_code)
        self.store.complete_transfer(record['instance_id'], operation_id, outcome, evidence)
        return {
            'name': record['name'], 'instance_id': record['instance_id'],
            'domain_uuid': record['domain_uuid'], 'operation_id': operation_id,
            'transfer_id': transfer_id, 'protocol_version': FILE_PROTOCOL_VERSION,
            'adapter_version': FILE_ADAPTER_VERSION, 'direction': spec['direction'],
            'guest_path': spec['guest_path'], 'outcome': outcome,
            'kind': kind, 'file_count': len(files) if files else None,
            'total_bytes': sum(item['size'] for item in files) if files else None,
            'manifest_sha256': manifest_digest(kind, files) if files and kind else None,
            'files': deepcopy(files) if files else None, 'overwrite': overwrite,
            'ssh_exit_code': ssh_exit_code,
            'source_git': deepcopy(spec.get('source_git')),
        }

    def copy(self, source, destination, overwrite, deadline, operation_id):
        """P11-B: one manifested SFTP transfer without free-form batch paths."""
        spec = copy_endpoints(source, destination)
        initial = self.store.inspect(spec['vm'])
        transfer_id = str(self.uuid_factory())
        host_source = None; host_destination = None
        if spec['direction'] == 'host-to-guest':
            host_source = self.host_source_scanner(spec['host_path'])
            spec['source_git'] = host_source.git
            kind = host_source.kind; manifest = host_source.public_manifest()
        else:
            spec['source_git'] = None
            host_destination = self.host_destination_factory(
                spec['host_path'], transfer_id, overwrite)
            kind = None; manifest = None
        try:
            with self.store.lock(initial['instance_id']):
                record, domain, owner, data = self._owned(initial['instance_id'])
                if not domain.isActive():
                    fail('DOMAIN_NOT_RUNNING', 'copy', 'VM is not running.', 4)
                if record['state'] != 'ready':
                    fail('GUEST_NOT_READY', 'copy', 'Lifecycle has no confirmed ready state.', 4)
                readiness = owner.guest_manifest(record)
                if not readiness['ssh_ready'] or not readiness['project_ready']:
                    fail('GUEST_NOT_READY', 'copy', 'Guest is not fully project-ready.', 4)
                leases = self.backend.ipv4_leases(data['network_uuid'], data['mac'])
                if len(leases) != 1:
                    fail('SSH_TARGET_UNAVAILABLE', 'copy', 'No unambiguous IPv4 address for the registered MAC.', 6)
                if deadline - self.clock() <= 0:
                    fail('DEADLINE_EXCEEDED', 'copy', 'Overall deadline exceeded before copy.', 7)
                identity = self.paths.data / 'clients' / record['instance_id']
                ssh = ssh_arguments(identity, record['instance_id'], leases[0], data['ssh_user'])
                sftp = sftp_arguments(identity, record['instance_id'], leases[0], data['ssh_user'])
                initial_evidence = self._transfer_evidence(
                    transfer_id, spec, overwrite,
                    kind=kind, file_count=len(manifest) if manifest else None,
                    total_bytes=sum(item['size'] for item in manifest) if manifest else None,
                    manifest_sha256=manifest_digest(kind, manifest) if manifest else None)
                self.store.begin_transfer(record, operation_id, initial_evidence)

                if spec['direction'] == 'host-to-guest':
                    answer, outcome, code = self._file_control(
                        ssh, 'prepare-upload', transfer_id, spec['guest_path'], deadline,
                        kind=kind, files=manifest, overwrite=overwrite)
                    if outcome:
                        return self._finish_transfer(record, operation_id, transfer_id, spec,
                                                     overwrite, outcome, manifest, kind, code)
                    host_source.verify()
                    remaining = deadline - self.clock()
                    exchange = self.sftp_runner(
                        sftp, upload_batch(transfer_id, host_source), remaining,
                        FILE_RESPONSE_LIMIT)
                    if exchange.timed_out or exchange.returncode != 0 or exchange.output_limited:
                        outcome = 'timed_out' if exchange.timed_out else 'transport_failed'
                        return self._finish_transfer(record, operation_id, transfer_id, spec,
                                                     overwrite, outcome, manifest, kind,
                                                     exchange.returncode)
                    host_source.verify()
                    answer, outcome, code = self._file_control(
                        ssh, 'finalize-upload', transfer_id, spec['guest_path'], deadline,
                        kind=kind, files=manifest, overwrite=overwrite)
                else:
                    answer, outcome, code = self._file_control(
                        ssh, 'prepare-download', transfer_id, spec['guest_path'], deadline,
                        kind=None, files=None, overwrite=overwrite)
                    if not outcome:
                        kind, manifest = answer['kind'], answer['files']
                        remaining = deadline - self.clock()
                        exchange = self.sftp_runner(
                            sftp, download_batch(transfer_id, manifest, host_destination.staging),
                            remaining, FILE_RESPONSE_LIMIT)
                        if exchange.timed_out or exchange.returncode != 0 or exchange.output_limited:
                            host_destination.cleanup(len(manifest))
                            outcome = 'timed_out' if exchange.timed_out else 'transport_failed'
                            code = exchange.returncode
                        else:
                            try:
                                host_destination.finalize(kind, manifest)
                            except LabError as error:
                                outcome = ('integrity_failed'
                                           if error.detail['code'] == 'COPY_INTEGRITY_MISMATCH'
                                           else 'file_failed')
                                code = 0
                if outcome:
                    return self._finish_transfer(record, operation_id, transfer_id, spec,
                                                 overwrite, outcome, manifest, kind, code)
                answer, outcome, code = self._file_control(
                    ssh, 'cleanup', transfer_id, spec['guest_path'], deadline,
                    kind=None, files=None, overwrite=False)
                if outcome:
                    return self._finish_transfer(record, operation_id, transfer_id, spec,
                                                 overwrite, outcome, manifest, kind, code)
                owner.verify(self.store.inspect(record['instance_id']),
                             self.backend.domain(record['domain_uuid']))
                return self._finish_transfer(record, operation_id, transfer_id, spec,
                                             overwrite, 'completed', manifest, kind, 0)
        finally:
            if host_source is not None: host_source.close()
            if host_destination is not None: host_destination.close()

    @staticmethod
    def _domain_digest(domain):
        return hashlib.sha256(domain.XMLDesc(0).encode()).hexdigest()

    def _client_cleanup_evidence(self, record, *, allow_unpinned=False):
        path = self.paths.data/'clients'/record['instance_id']
        with directory(path) as parent:
            folder = os.fstat(parent)
            names = {entry.name for entry in path.iterdir()}
            base = {'id_ed25519', 'id_ed25519.pub'}
            complete = base | {'known_hosts'}
            if names != complete and not (allow_unpinned and names == base):
                fail('OWNERSHIP_MISMATCH', 'recovery',
                     'SSH client directory is incomplete or contains unknown files.', 5)
            files = {}
            for name in sorted(names):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    modes = {0o600, 0o644} if name == 'id_ed25519.pub' else {0o600}
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in modes):
                        fail('OWNERSHIP_MISMATCH', 'recovery',
                             'SSH client file is not associated unambiguously with the instance.', 5)
                    files[name] = {'device': info.st_dev, 'inode': info.st_ino}
                finally:
                    os.close(fd)
        return {'client_directory': {'device': folder.st_dev, 'inode': folder.st_ino},
                'client_files': files, 'hostkey_pinned': 'known_hosts' in files}

    def _failed_create_allows_unpinned_hostkey(self, record, guest):
        latest = record['journal'][-1]
        source_id = (latest.get('recovery', {}).get('source_operation')
                     if latest.get('kind') == 'failed_create_cleanup' else latest.get('id'))
        source = next((item for item in record['journal'] if item.get('id') == source_id), None)
        return (self.store._recoverable_failed_create(source)
                and guest['cloud_init'] == 'pending'
                and guest['ssh_ready'] is False
                and guest['project_ready'] is False
                and guest['provisioning']['status'] == 'provisioning'
                and guest['provisioning']['error'] is None)

    def _cleanup_evidence(self, record, owner, domain):
        data = owner.verify(record, domain)
        manifest = self.paths.data/'instances'/record['instance_id']/'instance.json'
        guest_path = self.paths.data/'instances'/record['instance_id']/'guest-manifest.json'
        guest = owner.guest_manifest(record)
        if guest['project_ready'] or guest['provisioning']['status'] == 'project-ready':
            fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                 'A guest already verified as project-ready is not a failed-Create cleanup target.', 4)
        evidence = self._client_cleanup_evidence(
            record, allow_unpinned=self._failed_create_allows_unpinned_hostkey(record, guest))
        evidence.update(domain_xml_sha256=self._domain_digest(domain),
                        instance_manifest_sha256=_sha(manifest),
                        guest_manifest_sha256=_sha(guest_path),
                        registry={key: record[key]
                                  for key in ('lab_id', 'instance_id', 'domain_uuid', 'uri', 'name')},
                        runtime={'storage': data['storage'],
                                 'directory': deepcopy(data['directory']),
                                 'files': deepcopy(data['files'])},
                        source_failure={
                            'cloud_init': guest['cloud_init'],
                            'provisioning_status': guest['provisioning']['status'],
                            'error': guest['provisioning']['error'],
                        })
        return evidence

    def _verify_client_cleanup(self, record, recovery, *, allow_missing=False,
                               expect_absent=False):
        path = self.paths.data/'clients'/record['instance_id']
        if not os.path.lexists(path):
            if allow_missing or expect_absent:
                return None
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'SSH client directory is unexpectedly missing.', 5)
        if expect_absent:
            fail('RECOVERY_STATE_CONFLICT', 'cleanup',
                 'SSH client directory still exists after documented cleanup.', 5)
        with directory(path) as parent:
            info = os.fstat(parent)
            if recovery['client_directory'] != {'device': info.st_dev, 'inode': info.st_ino}:
                fail('OWNERSHIP_MISMATCH', 'cleanup', 'SSH client directory was replaced.', 5)
            names = {entry.name for entry in path.iterdir()}
            expected = set(recovery['client_files'])
            if not names <= expected or (not allow_missing and names != expected):
                fail('OWNERSHIP_MISMATCH', 'cleanup',
                     'SSH client files are unexpectedly missing or contain unknown files.', 5)
            for name in names:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    modes = {0o600, 0o644} if name == 'id_ed25519.pub' else {0o600}
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in modes
                            or recovery['client_files'][name]
                            != {'device': info.st_dev, 'inode': info.st_ino}):
                        fail('OWNERSHIP_MISMATCH', 'cleanup', 'SSH client file was replaced.', 5)
                finally:
                    os.close(fd)
            return True

    def _verify_runtime_cleanup(self, record, data, *, allow_missing=False,
                                allowed_missing=frozenset(), expect_absent=False):
        path = Path(data['storage'])
        if not os.path.lexists(path):
            if allow_missing or expect_absent:
                return
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Runtime directory is unexpectedly missing.', 5)
        if expect_absent:
            fail('RECOVERY_STATE_CONFLICT', 'cleanup',
                 'Runtime directory still exists after documented cleanup.', 5)
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or _identity(path) != data['directory']):
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Runtime directory was replaced.', 5)
        names = {entry.name for entry in path.iterdir()}
        expected = set(data['files'])
        missing = expected - names
        if (not names <= expected
                or (not allow_missing and not missing <= set(allowed_missing))):
            fail('OWNERSHIP_MISMATCH', 'cleanup',
                 'Runtime files are unexpectedly missing or contain unknown files.', 5)
        allowed_uids = {os.geteuid()}
        try:
            allowed_uids.add(pwd.getpwnam('libvirt-qemu').pw_uid)
        except KeyError:
            pass
        for name in names:
            info = os.lstat(path/name)
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_nlink != 1 or info.st_uid not in allowed_uids
                    or _identity(path/name) != data['files'][name]):
                fail('OWNERSHIP_MISMATCH', 'cleanup', 'Runtime file was replaced.', 5)

    def _verify_private_cleanup(self, record, *, allow_missing=False, expect_absent=False):
        path = self.paths.data/'instances'/record['instance_id']
        if not os.path.lexists(path):
            if allow_missing or expect_absent:
                return
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Private instance directory is unexpectedly missing.', 5)
        if expect_absent:
            fail('RECOVERY_STATE_CONFLICT', 'cleanup',
                 'Private instance directory still exists after documented cleanup.', 5)
        with directory(path) as parent:
            info = os.fstat(parent)
            if record['directory'] != {'device': info.st_dev, 'inode': info.st_ino}:
                fail('OWNERSHIP_MISMATCH', 'cleanup', 'Private instance directory was replaced.', 5)
            expected = {item['path']: item for item in record['manifest']}
            names = {entry.name for entry in path.iterdir()}
            if not names <= set(expected) or (not allow_missing and names != set(expected)):
                fail('OWNERSHIP_MISMATCH', 'cleanup',
                     'Private instance files are unexpectedly missing or contain unknown files.', 5)
            for name in names:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    info = private_file(fd)
                    item = expected[name]
                    if (info.st_dev, info.st_ino) != (item['device'], item['inode']):
                        fail('OWNERSHIP_MISMATCH', 'cleanup', 'Private instance file was replaced.', 5)
                finally:
                    os.close(fd)

    def _cleanup_manifest(self, record, recovery):
        manifest = self.paths.data/'instances'/record['instance_id']/'instance.json'
        guest_path = self.paths.data/'instances'/record['instance_id']/'guest-manifest.json'
        try:
            if _sha(manifest) != recovery['instance_manifest_sha256']:
                fail('OWNERSHIP_MISMATCH', 'cleanup',
                     'Instance manifest changed after approval.', 5)
            if _sha(guest_path) != recovery['guest_manifest_sha256']:
                fail('OWNERSHIP_MISMATCH', 'cleanup',
                     'Guest manifest changed after approval.', 5)
            data = json.loads(manifest.read_bytes())
            guest = json.loads(guest_path.read_bytes())
        except LabError:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Instance manifest is no longer readable.', 5)
        if any(data.get(key) != record[key]
               for key in ('lab_id', 'instance_id', 'domain_uuid', 'name', 'uri')):
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Instance manifest conflicts with the registry.', 5)
        runtime = {'storage': data.get('storage'), 'directory': data.get('directory'),
                   'files': data.get('files')}
        if runtime != recovery['runtime']:
            fail('OWNERSHIP_MISMATCH', 'cleanup',
                 'Runtime manifest conflicts with the bound cleanup evidence.', 5)
        source_failure = {
            'cloud_init': guest.get('cloud_init'),
            'provisioning_status': guest.get('provisioning', {}).get('status'),
            'error': guest.get('provisioning', {}).get('error'),
        }
        if source_failure != recovery['source_failure']:
            fail('OWNERSHIP_MISMATCH', 'cleanup',
                 'Documented provisioning cause was changed.', 5)
        return data

    def _require_cleanup_domain_absent(self, record):
        if self.backend.domain(record['domain_uuid'], missing_ok=True) is not None:
            fail('RECOVERY_STATE_CONFLICT', 'cleanup',
                 'Domain is present again after documented undefine.', 5)

    def _verify_cleanup_domain(self, record, owner, recovery, *, allow_missing=False):
        domain = self.backend.domain(record['domain_uuid'], missing_ok=True)
        if domain is None:
            if allow_missing:
                return None
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Bound domain is missing before the undefine intent.', 5)
        owner.verify(record, domain)
        if self._domain_digest(domain) != recovery['domain_xml_sha256']:
            fail('OWNERSHIP_MISMATCH', 'cleanup', 'Domain XML changed after approval.', 5)
        if domain.isActive():
            fail('DOMAIN_RUNNING', 'cleanup', 'Failed Create domain is still active.', 4,
                 'Shut down the domain cleanly and inspect the state again.')
        return domain

    def recover_failed_cleanup(self, target, source_operation, deadline):
        """Resumable manifest-bound cleanup of a P07 provisioning failure."""
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record = self.store.inspect(initial['instance_id'])
            last = record['journal'][-1]
            if self.store._recoverable_failed_create(last):
                if last['id'] != source_operation:
                    fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                         'Operation ID does not belong to the current failed Create.', 4)
                owner = RealOwnership(self.store, self.backend, last['id'],
                                      recover_failed_create=True)
                domain = self.backend.domain(record['domain_uuid'], missing_ok=True)
                if domain is None:
                    fail('OWNERSHIP_MISMATCH', 'recovery',
                         'Domain is missing before the bound recovery operation begins.', 5)
                if domain.isActive():
                    fail('DOMAIN_RUNNING', 'recovery',
                         'Failed Create domain must be powered off.', 4)
                evidence = self._cleanup_evidence(record, owner, domain)
                operation = self.store.begin_failed_create_cleanup(
                    record, source_operation, evidence)
            elif last['kind'] == 'failed_create_cleanup' and last['status'] == 'pending':
                if last['recovery']['source_operation'] != source_operation:
                    fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                         'Recovery is bound to a different failed Create operation.', 4)
                operation = last['id']
            else:
                fail('RECOVERY_SOURCE_MISMATCH', 'recovery',
                     'No matching failed Create or resumable cleanup exists.', 4)

            while True:
                self._deadline(deadline, 'failed-create-cleanup')
                record = self.store.inspect(initial['instance_id'])
                cleanup = record['journal'][-1]
                recovery = cleanup['recovery']
                phase = cleanup['phase']
                owner = RealOwnership(self.store, self.backend, operation)
                if recovery['registry'] != {key: record[key]
                                            for key in ('lab_id', 'instance_id', 'domain_uuid',
                                                        'uri', 'name')}:
                    fail('OWNERSHIP_MISMATCH', 'recovery',
                         'Registry identity differs from the bound cleanup evidence.', 5)

                if phase == 'planned':
                    domain = self._verify_cleanup_domain(record, owner, recovery)
                    if self._cleanup_evidence(record, owner, domain) != {
                            key: value for key, value in recovery.items()
                            if key != 'source_operation'}:
                        fail('OWNERSHIP_MISMATCH', 'cleanup',
                             'Cleanup evidence no longer matches the resources.', 5)
                    self.store.advance(record['instance_id'], operation, 'undefining')
                elif phase == 'undefining':
                    domain = self._verify_cleanup_domain(record, owner, recovery, allow_missing=True)
                    if domain is not None:
                        self.backend.undefine(record['domain_uuid'])
                    if self.backend.domain(record['domain_uuid'], missing_ok=True) is not None:
                        fail('UNDEFINE_FAILED', 'cleanup', 'Domain still exists after undefine.', 6)
                    self.store.advance(record['instance_id'], operation, 'undefined')
                elif phase == 'undefined':
                    self._require_cleanup_domain_absent(record)
                    data = self._cleanup_manifest(record, recovery)
                    # With VIR_DOMAIN_UNDEFINE_NVRAM, libvirt removes exactly the
                    # bound NVRAM file as part of the confirmed undefine.
                    self._verify_runtime_cleanup(record, data, allowed_missing={'nvram.fd'})
                    self._verify_client_cleanup(record, recovery)
                    self._verify_private_cleanup(record)
                    self.store.advance(record['instance_id'], operation, 'removing_runtime')
                elif phase == 'removing_runtime':
                    self._require_cleanup_domain_absent(record)
                    data = self._cleanup_manifest(record, recovery)
                    self._verify_runtime_cleanup(record, data, allow_missing=True)
                    runtime = Path(data['storage'])
                    if os.path.lexists(runtime):
                        parent = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            info = os.fstat(parent)
                            if data['directory'] != {'device': info.st_dev, 'inode': info.st_ino}:
                                fail('OWNERSHIP_MISMATCH', 'cleanup',
                                     'Runtime directory was replaced before deletion.', 5)
                            for name in sorted(os.listdir(parent)):
                                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                        or data['files'].get(name)
                                        != {'device': info.st_dev, 'inode': info.st_ino}):
                                    fail('OWNERSHIP_MISMATCH', 'cleanup',
                                         'Runtime file was replaced before deletion.', 5)
                                os.unlink(name, dir_fd=parent)
                            os.fsync(parent)
                        finally:
                            os.close(parent)
                        if _identity(runtime) != data['directory']:
                            fail('OWNERSHIP_MISMATCH', 'cleanup',
                                 'Runtime directory was replaced during deletion.', 5)
                        os.rmdir(runtime)
                    self.store.advance(record['instance_id'], operation, 'runtime_removed')
                elif phase == 'runtime_removed':
                    self._require_cleanup_domain_absent(record)
                    data = self._cleanup_manifest(record, recovery)
                    self._verify_runtime_cleanup(record, data, expect_absent=True)
                    self._verify_client_cleanup(record, recovery)
                    self._verify_private_cleanup(record)
                    self.store.advance(record['instance_id'], operation, 'removing_client')
                elif phase == 'removing_client':
                    self._require_cleanup_domain_absent(record)
                    data = self._cleanup_manifest(record, recovery)
                    self._verify_runtime_cleanup(record, data, expect_absent=True)
                    self._verify_client_cleanup(record, recovery, allow_missing=True)
                    client = self.paths.data/'clients'/record['instance_id']
                    if os.path.lexists(client):
                        with directory(client) as parent:
                            info = os.fstat(parent)
                            if recovery['client_directory'] != {
                                    'device': info.st_dev, 'inode': info.st_ino}:
                                fail('OWNERSHIP_MISMATCH', 'cleanup',
                                     'SSH client directory was replaced before deletion.', 5)
                            for name in sorted(os.listdir(parent)):
                                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                        or recovery['client_files'].get(name)
                                        != {'device': info.st_dev, 'inode': info.st_ino}):
                                    fail('OWNERSHIP_MISMATCH', 'cleanup',
                                         'SSH client file was replaced before deletion.', 5)
                                os.unlink(name, dir_fd=parent)
                            os.fsync(parent)
                        os.rmdir(client)
                    self.store.advance(record['instance_id'], operation, 'client_removed')
                elif phase == 'client_removed':
                    self._require_cleanup_domain_absent(record)
                    data = self._cleanup_manifest(record, recovery)
                    self._verify_runtime_cleanup(record, data, expect_absent=True)
                    self._verify_client_cleanup(record, recovery, expect_absent=True)
                    self._verify_private_cleanup(record)
                    self.store.advance(record['instance_id'], operation, 'removing_private')
                elif phase == 'removing_private':
                    self._require_cleanup_domain_absent(record)
                    self._verify_runtime_cleanup(record, recovery['runtime'], expect_absent=True)
                    self._verify_client_cleanup(record, recovery, expect_absent=True)
                    self._verify_private_cleanup(record, allow_missing=True)
                    private = self.paths.data/'instances'/record['instance_id']
                    if os.path.lexists(private):
                        with directory(private) as parent:
                            info = os.fstat(parent)
                            if record['directory'] != {'device': info.st_dev, 'inode': info.st_ino}:
                                fail('OWNERSHIP_MISMATCH', 'cleanup',
                                     'Private instance directory was replaced before deletion.', 5)
                            expected = {item['path']: item for item in record['manifest']}
                            for name in sorted(os.listdir(parent)):
                                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                                item = expected.get(name)
                                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                        or item is None or (item['device'], item['inode'])
                                        != (info.st_dev, info.st_ino)):
                                    fail('OWNERSHIP_MISMATCH', 'cleanup',
                                         'Private instance file was replaced before deletion.', 5)
                                os.unlink(name, dir_fd=parent)
                            os.fsync(parent)
                        os.rmdir(private)
                    self.store.advance(record['instance_id'], operation, 'private_removed')
                elif phase == 'private_removed':
                    self._require_cleanup_domain_absent(record)
                    self._verify_runtime_cleanup(record, recovery['runtime'], expect_absent=True)
                    self._verify_client_cleanup(record, recovery, expect_absent=True)
                    self._verify_private_cleanup(record, expect_absent=True)
                    self.store.advance(record['instance_id'], operation, 'clearing_manifest')
                elif phase == 'clearing_manifest':
                    self._require_cleanup_domain_absent(record)
                    self._verify_runtime_cleanup(record, recovery['runtime'], expect_absent=True)
                    self._verify_client_cleanup(record, recovery, expect_absent=True)
                    self._verify_private_cleanup(record, expect_absent=True)
                    if record['directory'] is not None or record['manifest']:
                        self.store.clear_instance_files(record, operation)
                    current = self.store.inspect(record['instance_id'])
                    self.store.complete_destroy(current['instance_id'], operation)
                elif phase == 'destroyed':
                    break
                else:
                    fail('STATE_CONFLICT', 'recovery', 'Unbekannte Cleanup-Phase.', 4)

            final = self.store.inspect(initial['instance_id'])
            return {'name': final['name'], 'instance_id': final['instance_id'],
                    'domain_uuid': final['domain_uuid'], 'power_state': 'removed',
                    'removed': True, 'recovery_operation': operation,
                    'source_operation': source_operation}

    def destroy(self, target, deadline):
        status = self.status(target)
        if status['power_state'] == 'running': self.stop(target, deadline)
        initial = self.store.inspect(target)
        with self.store.lock(initial['instance_id']):
            record, domain, owner, data = self._owned(initial['instance_id'])
            generations = {}; active_generation = None
            if 'restore_generation' in data:
                from .restore import RestoreRecoveryManager
                manager = RestoreRecoveryManager(
                    self, clock=self.clock,
                    tool=lambda argv, limit: self._run(
                        argv, limit, timeout=max(0.1, limit-self.clock())))
                generations = manager.cleanup_generations(record, data)
                active_generation = Path(data['restore_generation']['path'])
            op = self.store.begin(record, 'destroy'); owner.operation_id = op
            try:
                owner.verify(self.store.inspect(record['instance_id']), domain)
                runtime = Path(data['storage']); identities = deepcopy(data['files']); directory_id = data['directory']
                self.backend.undefine(record['domain_uuid']); self.store.advance(record['instance_id'], op, 'undefined')
                if _identity(runtime) != directory_id: fail('OWNERSHIP_MISMATCH', 'cleanup', 'Runtime directory was replaced before cleanup.', 5)
                present = {p.name for p in runtime.iterdir()}
                if not present <= set(RUNTIME_FILES): fail('OWNERSHIP_MISMATCH', 'cleanup', 'Unknown file blocks cleanup.', 5)
                for name in present:
                    if _identity(runtime/name) != identities[name]: fail('OWNERSHIP_MISMATCH', 'cleanup', 'Runtime file was replaced before cleanup.', 5)
                for name in present: os.unlink(runtime/name)
                os.rmdir(runtime)
                if generations:
                    manager.remove_generations(generations, active_generation)
                identity = self.paths.data/'clients'/record['instance_id']
                with directory(identity) as parent:
                    allowed = {'id_ed25519','id_ed25519.pub','known_hosts'}
                    names = {p.name for p in identity.iterdir()}
                    if not names <= allowed: fail('OWNERSHIP_MISMATCH', 'cleanup', 'Unknown SSH file blocks cleanup.', 5)
                    for name in names: os.unlink(name, dir_fd=parent)
                os.rmdir(identity)
                private = self.paths.data/'instances'/record['instance_id']
                with self.store.selection(self.store.inspect(record['instance_id']), op) as parent:
                    for item in self.store.inspect(record['instance_id'])['manifest']:
                        os.unlink(item['path'], dir_fd=parent)
                    os.fsync(parent)
                os.rmdir(private)
                self.store.clear_instance_files(self.store.inspect(record['instance_id']), op)
                self.store.complete_destroy(record['instance_id'], op)
            except BaseException:
                try: self.store.advance(record['instance_id'], op, 'failed', failed=True)
                except Exception: pass
                raise
        return {'name':record['name'],'instance_id':record['instance_id'],'domain_uuid':record['domain_uuid'],
                'power_state':'removed','removed':True}
