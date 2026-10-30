# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Render NoCloud data and build bounded offline seed media.

"""NoCloud data and explicit offline ISO creation; no VM or host management."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from uuid import uuid4

import yaml

from ..errors import LabError
from ..guest.ssh import Binding, public_key
from ..process import run
from .arch import provisioning_script
from ..state import directory

# Controlled internal guest step, not a freely configurable profile hook.
# Public host key only; never private keys on the serial console.
HOSTKEY_SCRIPT = '''import base64, hashlib, json
from pathlib import Path
key = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[1]
fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(key, validate=True)).digest()).decode().rstrip('=')
instance = Path('/var/lib/cloud/data/instance-id').read_text().strip()
record = 'VM_DEV_LAB_HOSTKEY_V1 ' + json.dumps({'instance_id': instance, 'fingerprint': fingerprint}) + '\\n'
with open('/dev/ttyS0', 'w') as console:
    console.write(record)
'''


@dataclass(frozen=True)
class Seed:
    binding: Binding
    user_data: str
    meta_data: str
    network_config: str
    sha256: str


def render_seed(resolved, record, client_public_keys, *, network_mac=None):
    if not resolved.complete or not resolved.config['vm']['ssh']['enabled']:
        raise LabError(3, 'CONFIG_INCOMPLETE', 'seed', 'Complete SSH configuration is required.', 'Validate the profile offline; do not force approval.')
    try:
        keys = [public_key(key)[0] for key in client_public_keys]
        if not keys or len(keys) > 32 or len(set(keys)) != len(keys): raise ValueError
    except (ValueError, TypeError):
        raise LabError(2, 'CLIENT_KEY_INVALID', 'seed', 'Only unambiguous public client keys are allowed.', 'Do not pass private keys or authorized_keys options.') from None
    from ..state import identifier
    identifier(record['name'])
    if (not isinstance(network_mac, str)
            or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', network_mac)
            or int(network_mac[:2], 16) & 1 or network_mac.lower() == '00:00:00:00:00:00'):
        raise LabError(2, 'SEED_NETWORK_INVALID', 'seed', 'An explicit unicast MAC for the guest NIC is required.',
                       'Use the same registered MAC for the domain and NoCloud network configuration.')
    binding = Binding(record['lab_id'], record['instance_id'], record['domain_uuid'], str(uuid4()))
    vm = resolved.config['vm']
    # Revalidating semantics also protects internal callers from modified ConfigResults.
    from ..config import ConfigLoader
    ConfigLoader._semantics(resolved.config)
    provisioner = provisioning_script(vm['packages'], vm['ssh']['user'])
    data = dict(users=[dict(name=vm['ssh']['user'], lock_passwd=True, shell='/bin/bash', ssh_authorized_keys=keys)],
                ssh_pwauth=False, disable_root=True, ssh_deletekeys=True, ssh_genkeytypes=['ed25519'],
                ssh_publish_hostkeys=dict(enabled=False), ssh=dict(emit_keys_to_console=False),
                package_update=False,
                write_files=[
                    dict(path='/usr/local/libexec/vm-dev-lab-hostkey', owner='root:root', permissions='0644', content=HOSTKEY_SCRIPT),
                    dict(path='/usr/local/libexec/vm-dev-lab-arch-provision', owner='root:root', permissions='0700', content=provisioner),
                ],
                runcmd=[['python3', '/usr/local/libexec/vm-dev-lab-hostkey'],
                        ['/usr/local/libexec/vm-dev-lab-arch-provision']])
    user = '#cloud-config\n' + yaml.safe_dump(data, sort_keys=True)
    meta = yaml.safe_dump({'instance-id': binding.seed_instance_id, 'local-hostname': record['name'],
                           'dsmode': 'local'}, sort_keys=True)
    network = yaml.safe_dump({'version': 2, 'ethernets': {'lab': {
        'match': {'macaddress': network_mac.lower()}, 'dhcp4': True, 'dhcp6': False}}}, sort_keys=True)
    h = hashlib.sha256(user.encode() + b'\0' + meta.encode() + b'\0' + network.encode()).hexdigest()
    return Seed(binding, user, meta, network, h)


def write_seed_iso(seed, output, runner=run):
    """Explicit offline media creation; include all three NoCloud files.

    Write output only to an existing private directory; never replace existing targets.
    No download, libvirt contact, or guest start.
    """
    output = Path(output).absolute()
    if '..' in output.parts or not seed.network_config:
        raise LabError(2, 'SEED_NETWORK_INVALID', 'seed', 'Network configuration or output path is invalid.',
                       'Provide a complete seed and private target directory.')
    with directory(output.parent) as parent:
        if os.path.lexists(output):
            raise LabError(4, 'SEED_EXISTS', 'seed', 'Seed target already exists.', 'Do not overwrite existing media.')
        with tempfile.TemporaryDirectory(prefix='.seed-', dir=output.parent) as temp:
            stage = Path(temp)
            for name, value in (('user-data', seed.user_data), ('meta-data', seed.meta_data),
                                ('network-config', seed.network_config)):
                fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    stream.write(value); stream.flush(); os.fsync(stream.fileno())
            status, _ = runner(['cloud-localds', '--network-config', str(stage / 'network-config'),
                                str(stage / 'seed.iso'), str(stage / 'user-data'), str(stage / 'meta-data')])
            if status:
                raise LabError(6, 'SEED_TOOL_FAILED', 'seed', 'Seed tool failed.',
                               'Inspect the tool and inputs; do not use incomplete media.')
            fd = os.open(stage / 'seed.iso', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_nlink != 1 or not 0 < info.st_size <= 8 * 1024 ** 2):
                    raise LabError(6, 'SEED_TOOL_FAILED', 'seed', 'Unsafe or incomplete seed media.',
                                   'Inspect tool output; do not use the media.')
                os.fsync(fd)
            finally:
                os.close(fd)
            # link also fails if the target was created in the meantime.
            try:
                os.link(stage / 'seed.iso', output.name, dst_dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                raise LabError(4, 'SEED_EXISTS', 'seed', 'Seed target already exists.',
                               'Do not overwrite it; inspect the concurrent run.') from None
            os.fsync(parent)
    return output
