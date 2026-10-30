# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Manage pinned guest SSH identities and strict client parameters.

"""Public SSH identity, domain-bound bootstrap, and safe client parameters."""
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
from uuid import UUID, uuid4

from ..errors import LabError
from ..process import run
from ..state import directory, private_file

MARKER = 'VM_DEV_LAB_HOSTKEY_V1 '


def fail(code, message, status=5):
    raise LabError(status, code, 'ssh-bootstrap', message,
                   'Inspect the bound domain and instance ID and the public host key; do not disable checks or remove known_hosts.')


def public_key(key):
    if not isinstance(key, str) or any(ord(c) < 32 or ord(c) == 127 for c in key): raise ValueError
    parts = key.split()
    allowed = {'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'}
    if len(parts) < 2 or parts[0] not in allowed or len(key) > 16384: raise ValueError
    raw = base64.b64decode(parts[1], validate=True)
    fields, data = [], raw
    while data:
        if len(data) < 4: raise ValueError
        size = int.from_bytes(data[:4], 'big')
        if size == 0 or size > len(data) - 4: raise ValueError
        fields.append(data[4:4 + size]); data = data[4 + size:]
    if len(fields) != (2 if parts[0] == 'ssh-ed25519' else 3) or fields[0] != parts[0].encode(): raise ValueError
    if parts[0] == 'ssh-ed25519' and len(fields[1]) != 32: raise ValueError
    if parts[0].startswith('ecdsa-') and fields[1] != parts[0].removeprefix('ecdsa-sha2-').encode(): raise ValueError
    canonical = parts[0] + ' ' + base64.b64encode(raw).decode()
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
    return canonical, fingerprint


@dataclass(frozen=True)
class Binding:
    lab_id: str
    instance_id: str
    domain_uuid: str
    seed_instance_id: str

    def __post_init__(self):
        for value in vars(self).values():
            try:
                if str(UUID(value)) != value: raise ValueError
            except (ValueError, TypeError, AttributeError): fail('BOOTSTRAP_BINDING_INVALID', 'Invalid identity binding.')


def client_identity(root, instance_id, runner=run):
    """Create keys explicitly only in a new instance-owned directory."""
    try:
        if str(UUID(instance_id)) != instance_id: raise ValueError
    except (ValueError, TypeError, AttributeError): fail('BOOTSTRAP_BINDING_INVALID', 'Invalid instance identifier.')
    root = Path(root).absolute()
    if '..' in root.parts: fail('SSH_PATH_UNSAFE', 'Path traversal is not allowed.')
    with directory(root, create=True) as parent:
        try:
            os.stat(instance_id, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail('CLIENT_KEY_EXISTS', 'Instance identity exists; do not overwrite it.', 4)
        staging = '.identity-' + str(uuid4())
        os.mkdir(staging, 0o700, dir_fd=parent)
        path = root / staging
        status, _ = runner(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path / 'id_ed25519')])
        if status: fail('CLIENT_KEY_FAILED', 'SSH client identity could not be created.', 6)
        with directory(path) as fd:
            for name in ('id_ed25519', 'id_ed25519.pub'):
                key = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if name.endswith('.pub'):
                        # ssh-keygen creates public keys as 0644; normalize only the owned file.
                        info = os.fstat(key)
                        if info.st_uid != os.geteuid() or info.st_nlink != 1: fail('SSH_PATH_UNSAFE', 'Unsafe public key.')
                        public_key(os.read(key, 16385).decode().strip())
                    else: private_file(key)
                    os.fsync(key)
                finally: os.close(key)
            os.fsync(fd)
        # rename must never replace an existing instance.
        # Atomic mkdir reserves the final directory before moving owned files.
        try: os.mkdir(instance_id, 0o700, dir_fd=parent)
        except FileExistsError: fail('CLIENT_KEY_EXISTS', 'Instance identity exists; do not overwrite it.', 4)
        with directory(root / instance_id) as target:
            for name in ('id_ed25519', 'id_ed25519.pub'):
                os.rename(path / name, name, dst_dir_fd=target)
            os.fsync(target)
        os.rmdir(staging, dir_fd=parent); os.fsync(parent)
    return root / instance_id


def bootstrap(store, backend, binding, serial_reader, presented_key, identity_dir, timeout=30):
    """serial_reader(uuid, deadline) must be bound by the later libvirt adapter.

    A network key alone, logs of arbitrary provenance, or a self-asserted UUID
    are not bootstrap evidence. The channel adapter is qualified only in the real spike.
    """
    if timeout <= 0: fail('BOOTSTRAP_TIMEOUT', 'Bootstrap deadline exceeded.', 7)
    deadline = time.monotonic() + timeout
    record = store.inspect(binding.instance_id)
    if any(record[k] != getattr(binding, k) for k in ('lab_id', 'instance_id', 'domain_uuid')):
        fail('BOOTSTRAP_BINDING_INVALID', 'Seed and registered domain do not match.')
    store.verify(record, backend.inspect(binding.domain_uuid))
    text = serial_reader(binding.domain_uuid, deadline)
    if time.monotonic() >= deadline: fail('BOOTSTRAP_TIMEOUT', 'Bootstrap deadline exceeded.', 7)
    if not isinstance(text, str) or len(text.encode()) > 1024 * 1024: fail('BOOTSTRAP_MISSING', 'Serial evidence is missing or too large.')
    matches = []
    for line in text.splitlines():
        if line.startswith(MARKER):
            try:
                value = json.loads(line[len(MARKER):])
                if set(value) != {'instance_id', 'fingerprint'}: raise ValueError
                if value['instance_id'] == binding.seed_instance_id: matches.append(value['fingerprint'])
            except (ValueError, TypeError): fail('BOOTSTRAP_MISSING', 'Invalid serial host-key evidence.')
    try: canonical, fingerprint = public_key(presented_key)
    except ValueError: fail('HOSTKEY_INVALID', 'Invalid public network host key.')
    if not canonical.startswith('ssh-ed25519 '): fail('HOSTKEY_INVALID', 'Bootstrap candidate requires an Ed25519 host key.')
    if len(matches) != 1: fail('BOOTSTRAP_MISSING', 'No unambiguous evidence for exactly this seed instance ID.')
    if matches[0] != fingerprint: fail('HOSTKEY_MISMATCH', 'Serial and presented host keys do not match.')
    # Check again after reading: registry and domain must not change in the meantime.
    current = store.inspect(binding.instance_id)
    if current != record: fail('BOOTSTRAP_BINDING_INVALID', 'Registry changed during bootstrap.')
    store.verify(current, backend.inspect(binding.domain_uuid))
    line = f'vm-dev-lab-{binding.instance_id} {canonical}\n'.encode()
    identity_dir = Path(identity_dir).absolute()
    if identity_dir.name != binding.instance_id or '..' in identity_dir.parts:
        fail('SSH_PATH_UNSAFE', 'Client directory must be associated with exactly this instance.')
    with directory(identity_dir) as parent:
        for name in ('id_ed25519', 'id_ed25519.pub'):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                if name.endswith('.pub'): public_key(os.read(fd, 16385).decode().strip())
                else: private_file(fd)
            finally: os.close(fd)
        try:
            fd = os.open('known_hosts', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        except FileExistsError:
            fd = os.open('known_hosts', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                private_file(fd)
                if os.read(fd, 16385) != line: fail('HOSTKEY_MISMATCH', 'Existing host identity will not be replaced.')
            finally: os.close(fd)
        else:
            with os.fdopen(fd, 'wb') as out:
                out.write(line); out.flush(); os.fsync(out.fileno())
            os.fsync(parent)
    return dict(instance_id=binding.instance_id, domain_uuid=binding.domain_uuid,
                seed_instance_id=binding.seed_instance_id, fingerprint=fingerprint)


def ssh_arguments(identity_dir, instance_id, address, user):
    try:
        if str(UUID(instance_id)) != instance_id: raise ValueError
        ipaddress.ip_address(address)
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user) or user == 'root': raise ValueError
    except (ValueError, TypeError, AttributeError): fail('SSH_TARGET_INVALID', 'Invalid SSH target.')
    path = Path(identity_dir).absolute()
    if path.name != instance_id or '..' in path.parts: fail('SSH_PATH_UNSAFE', 'Falsches Instanzverzeichnis.')
    with directory(path) as parent:
        for name in ('id_ed25519', 'known_hosts'):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                private_file(fd)
                if name == 'known_hosts':
                    content = os.read(fd, 16385).decode()
                    prefix = f'vm-dev-lab-{instance_id} '
                    if not content.startswith(prefix) or len(content.splitlines()) != 1: fail('HOSTKEY_MISMATCH', 'known_hosts does not match the instance.')
                    public_key(content[len(prefix):].strip())
            finally: os.close(fd)
    return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', f'UserKnownHostsFile={path / "known_hosts"}',
            '-o', f'HostKeyAlias=vm-dev-lab-{instance_id}', '-o', 'ConnectTimeout=10',
            '-i', str(path / 'id_ed25519'), '-l', user, '--', address]


def sftp_arguments(identity_dir, instance_id, address, user):
    """Use the same identity check; batch data arrives exclusively via stdin."""
    ssh = ssh_arguments(identity_dir, instance_id, address, user)
    # ssh ends with -l USER -- ADDRESS. sftp uses USER@ADDRESS instead;
    # both values were already validated strictly by ssh_arguments.
    common = ssh[1:-4]
    return ['sftp', *common, '-b', '-', '--', f'{user}@{address}']
