# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Inspect host prerequisites through read-only qualification gates.

"""P04: bounded read-only host diagnostics with an explicit live gate."""
from dataclasses import dataclass
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import time
from urllib.parse import urlencode
from uuid import UUID

from .errors import LabError
from . import libvirt_backend as backend

LIMIT = 1024 * 1024


class ProbeError(Exception):
    pass


@dataclass
class HostRequest:
    config: dict
    live: bool = False


def load_request(filename=None, live=False):
    config = {'schema_version': 1, 'uri': 'qemu:///system', 'operating_model': 'unspecified'}
    if filename:
        try:
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result: raise ValueError
                    result[key] = value
                return result
            config = json.loads(raw, object_pairs_hook=unique)
            _validate_config(config)
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            raise LabError(2, 'HOST_CONFIG_INVALID', 'parse', 'Invalid host-resources file.',
                           'Check JSON fields, UUIDs, and absolute paths against docs/HOST-SETUP.md.') from None
    return HostRequest(config, live)


def _validate_config(config):
    def obj(value, allowed, required=()):
        if not isinstance(value, dict) or set(value) - set(allowed) or not set(required) <= set(value): raise ValueError
    def path(value):
        if (not isinstance(value, str) or len(value) > 4096 or not Path(value).is_absolute()
                or '..' in Path(value).parts or any(ord(c) < 32 for c in value)): raise ValueError
    def identity(value):
        obj(value, ('name', 'uuid', 'mode', 'subnet'), ('name', 'uuid'))
        if not isinstance(value['name'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value['name']): raise ValueError
        if not isinstance(value['uuid'], str) or str(UUID(value['uuid'])) != value['uuid']: raise ValueError
    obj(config, ('schema_version', 'uri', 'operating_model', 'firmware', 'storage', 'network', 'endpoints'), ('schema_version', 'uri'))
    if type(config['schema_version']) is not int or config['schema_version'] != 1: raise ValueError
    if config['uri'] not in ('qemu:///system', 'qemu:///session'): raise ValueError
    if config.get('operating_model', 'unspecified') not in ('manual', 'permanent', 'unspecified'): raise ValueError
    if 'firmware' in config:
        obj(config['firmware'], ('code', 'vars'), ('code', 'vars'))
        for value in config['firmware'].values(): path(value)
        if config['firmware']['code'] == config['firmware']['vars']: raise ValueError
    if 'storage' in config:
        storage = config['storage']
        obj(storage, ('path', 'min_free_gib', 'pool'), ('path', 'min_free_gib', 'pool'))
        path(storage['path'])
        if type(storage['min_free_gib']) is not int or not 1 <= storage['min_free_gib'] <= 16384: raise ValueError
        identity(storage['pool'])
        if set(storage['pool']) != {'name', 'uuid'}: raise ValueError
    if 'network' in config:
        identity(config['network'])
        if set(config['network']) != {'name', 'uuid', 'mode', 'subnet'}: raise ValueError
        if config['network']['mode'] not in ('nat', 'isolated'): raise ValueError
        ipaddress.ip_network(config['network']['subnet'])
    if 'endpoints' in config:
        obj(config['endpoints'], ('qemu', 'network', 'storage'))
        for endpoint in config['endpoints'].values():
            obj(endpoint, ('unit', 'socket', 'mode'), ('unit', 'socket', 'mode'))
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]*\.service', endpoint['unit']): raise ValueError
            if endpoint['mode'] not in ('direct', 'legacy'): raise ValueError
            path(endpoint['socket'])


class LocalProbe:
    """Injectable host boundary. Subprocesses have deadlines and output limits, without shell or TTY."""
    def __init__(self, deadline):
        self.deadline = deadline

    def run(self, argv):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise LabError(7, 'DEADLINE_EXCEEDED', 'host-check', 'Host diagnostics deadline exceeded.', 'Review the overall deadline; do not perform repairs.')
        env = {**os.environ, 'LC_ALL': 'C', 'LIBVIRT_AUTOSTART': '0'}
        # Do not evaluate client configuration, aliases, or SSH agents; use explicit local URIs.
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env) as child:
            output = bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    deadline = min(self.deadline, time.monotonic() + 10)
                    while True:
                        timeout = deadline - time.monotonic()
                        if timeout <= 0 or not selector.select(timeout): raise ProbeError('Deadline exceeded')
                        chunk = os.read(child.stdout.fileno(), 65536)
                        if not chunk: break
                        output.extend(chunk)
                        if len(output) > LIMIT: raise ProbeError('Output limit exceeded')
                child.wait(timeout=max(.001, deadline - time.monotonic()))
                if child.returncode != 0: raise ProbeError('Query failed (permissions, reachability, or tool)')
                return output.decode('utf-8')
            except BaseException:
                child.kill(); child.wait()
                raise

    def tool(self, name):
        return shutil.which(name)

    def machine(self):
        return platform.machine()

    def release(self):
        data = platform.freedesktop_os_release()
        return {k: data.get(k, '') for k in ('ID', 'VERSION_ID')}

    def binding(self):
        return importlib.util.find_spec('libvirt') is not None

    def kvm(self):
        return stat.S_ISCHR(os.stat('/dev/kvm').st_mode), os.access('/dev/kvm', os.R_OK | os.W_OK)

    def firmware(self, code, variables):
        return (code != variables and all(Path(p).is_file() and Path(p).stat().st_size > 0
                                         and os.access(p, os.R_OK) for p in (code, variables)))

    def storage(self, path):
        if not Path(path).is_dir() or Path(path).is_symlink(): raise ProbeError('Storage path is missing or is a symlink')
        info = os.statvfs(path)
        return info.f_bavail * info.f_frsize, os.access(path, os.R_OK | os.W_OK | os.X_OK)

    def service(self, unit, session):
        args = ['systemctl', *(['--user'] if session else []), 'show', '--no-pager',
                '--property=LoadState,ActiveState,SubState,MainPID,TriggeredBy', unit]
        text = self.run(args)
        return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

    def services(self, session):
        text = self.run(['systemctl', *(['--user'] if session else []), 'list-unit-files', '--type=service', '--no-legend', '--no-pager'])
        return [line.split()[0] for line in text.splitlines()
                if re.fullmatch(r'(libvirtd|virt(qemu|network|storage|proxy)d)\.service', line.split()[0] if line.split() else '')]

    def owns_socket(self, endpoint, pid, kind):
        expected = 'libvirtd' if endpoint['mode'] == 'legacy' else {'qemu': 'virtqemud', 'network': 'virtnetworkd', 'storage': 'virtstoraged'}[kind]
        if Path(os.readlink(f'/proc/{pid}/exe')).name != expected: return False
        socket_path = endpoint['socket']
        if not stat.S_ISSOCK(os.lstat(socket_path).st_mode): return False
        # Never connect as a reachability test. The PID must own the listener.
        inode = None
        for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
            fields = line.split()
            if (len(fields) == 8 and fields[-1] == socket_path
                    and int(fields[3], 16) & 0x10000 and fields[4] == '0001'):
                inode = fields[6]
        if inode is None: return False
        return any(os.readlink(fd) == f'socket:[{inode}]' for fd in Path(f'/proc/{pid}/fd').iterdir())

    def live_gate(self, endpoint, session, kind):
        before = self.service(endpoint['unit'], session)
        if not {'LoadState', 'ActiveState', 'SubState', 'MainPID', 'TriggeredBy'} <= set(before) or before.get('LoadState') != 'loaded':
            raise ProbeError('Service or activation state was not fully established')
        if before.get('ActiveState') != 'active' or before.get('SubState') != 'running':
            raise ProbeError('Daemon is inactive; do not connect or activate it')
        if not before.get('MainPID', '').isdigit() or int(before['MainPID']) <= 0: raise ProbeError('Daemon PID was not established')
        for unit in before.get('TriggeredBy', '').split():
            if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.socket', unit): raise ProbeError('Unknown activation path')
            status = self.service(unit, session)
            if status.get('LoadState') != 'loaded' or status.get('ActiveState') != 'inactive':
                raise ProbeError('Socket activation was not ruled out; live query is blocked')
        if not self.owns_socket(endpoint, int(before['MainPID']), kind):
            raise ProbeError('Listener ownership was not established read-only')
        if self.service(endpoint['unit'], session) != before: raise ProbeError('Daemon state changed')


def diagnose(request, probe):
    config = request.config
    session = config['uri'] == 'qemu:///session'
    checks = []
    def add(name, status, message, hint, required=True, details=None):
        checks.append(dict(name=name, status=status, message=message, hint=hint, required=required, details=details or {}))
    def attempt(name, action, hint, required=True):
        try: action()
        except ProbeError as error:
            add(name, 'UNVERIFIED', str(error), hint, required)
        except (OSError, ValueError, subprocess.SubprocessError, AttributeError):
            add(name, 'UNVERIFIED', 'Read-only query did not succeed; no repair was performed.', hint, required)
    def basic():
        machine = probe.machine()
        add('architecture', 'PASS' if machine == 'x86_64' else 'FAIL', 'Detected host architecture.', 'x86_64 Linux is the initial support target.', details={'architecture': machine})
        add('distribution', 'PASS', 'Host data read without a distribution assumption.', 'Qualify specific host versions.', False, probe.release())
        exists, access = probe.kvm()
        add('kvm', 'PASS' if exists and access else ('WARN' if exists and not session else 'FAIL'), 'KVM device and user access checked.', 'Qualify QEMU service access under system libvirt separately; do not change permissions.', details={'character_device': exists, 'current_user_rw': access})
    attempt('platform', basic, 'Inspect host platform and KVM read-only.')
    for tool in ('qemu-system-x86_64', 'qemu-img', 'virsh'):
        def check_tool(tool=tool):
            path = probe.tool(tool)
            if not path:
                add(tool, 'FAIL', 'Tool is missing.', 'The operator must provide the required package separately.'); return
            lines = probe.run([path, '--version']).splitlines()
            if not lines: raise ProbeError('Empty version output; tool is unverified')
            version = lines[0][:160]
            add(tool, 'PASS', 'Tool version read.', 'A version is not yet operational evidence.', details={'version': version})
        attempt(tool, check_tool, 'Provide the tool and version locally; no automatic installation.')
    def qcow():
        path = probe.tool('qemu-img')
        if not path: return
        text = probe.run([path, '--help'])
        add('qcow2', 'PASS' if re.search(r'\bqcow2\b', text) else 'FAIL', 'qcow2 format support checked.', 'Provide a supported qemu-img.')
    attempt('qcow2', qcow, 'Check qemu-img format support.')
    attempt('python_binding', lambda: add('python_binding', 'PASS' if probe.binding() else 'FAIL', 'Binding checked in the current Python environment.', 'Provide libvirt-python separately as described in docs/INSTALLATION.md.'), 'Check the Python environment and binding.')
    def services():
        units = set(probe.services(session)) | {v['unit'] for v in config.get('endpoints', {}).values()}
        for unit in sorted(units):
            data = probe.service(unit, session)
            add('service:' + unit, 'PASS' if data.get('ActiveState') == 'active' else 'WARN', 'Service state read without opening a connection.', 'Manual and permanent operation are allowed; diagnostics switch nothing.', False, data)
    attempt('services', services, 'systemd query is unavailable; no start or sudo fallback.', False)
    firmware = config.get('firmware')
    if firmware:
        attempt('firmware', lambda: add('firmware', 'PASS' if probe.firmware(firmware['code'], firmware['vars']) else 'FAIL', 'Explicit code and variable templates checked for presence and readability.', 'Select a matching x86_64 UEFI pair; boot evidence follows in P05.'), 'Inspect firmware files read-only.')
    else:
        add('firmware', 'UNVERIFIED', 'No firmware pair selected.', 'Inspect firmware manifests and select code and variable paths explicitly.')
    storage = config.get('storage')
    if storage:
        def space():
            available, access = probe.storage(storage['path'])
            add('storage_space', 'PASS' if access and available >= storage['min_free_gib'] * 1024 ** 3 else 'FAIL', 'Free space and user access checked.', 'Have the operator qualify the storage path, reserve, and QEMU or LSM access.', details={'available_bytes': available, 'current_user_rwx': access})
        attempt('storage_space', space, 'Do not create a missing storage path automatically.')
    else:
        add('storage_space', 'UNVERIFIED', 'No storage path or budget approved.', 'An operator decision on existing or dedicated storage is required.')
    add('authorization', 'UNVERIFIED', 'Read permissions do not confirm later mutation rights or QEMU or LSM access.', 'Run a separate bounded domain and storage trial only with VM approval.', False)
    if session:
        add('session_support', 'WARN', 'Session mode detected; network, USB, and confinement matrix remains open.', 'System mode is the initial target; do not switch modes silently.')
    for kind in ('qemu', 'network', 'storage'):
        expected = config.get('network') if kind == 'network' else (storage.get('pool') if kind == 'storage' and storage else firmware)
        if not expected:
            add('backend:' + kind, 'UNVERIFIED', 'Expected resource identity is missing.', 'Have the operator specify UUID, mode, subnet, storage, or firmware.'); continue
        if not request.live:
            add('backend:' + kind, 'UNVERIFIED', 'No live query requested.', 'Explicit --live requires safe endpoints that are already running.'); continue
        endpoint = config.get('endpoints', {}).get(kind)
        if not endpoint:
            add('backend:' + kind, 'UNVERIFIED', 'No explicit daemon endpoint specified.', 'Qualify the endpoint and unit locally; do not assume default sockets.'); continue
        def live(kind=kind, endpoint=endpoint, expected=expected):
            probe.live_gate(endpoint, session, kind)
            driver = 'qemu' if endpoint['mode'] == 'legacy' else kind
            uri = f'{driver}+unix:///{"session" if session else "system"}?' + urlencode({'socket': endpoint['socket'], 'mode': endpoint['mode']})
            if kind == 'qemu': args = ['domcapabilities', '--virttype', 'kvm', '--arch', 'x86_64']
            else: args = ['net-dumpxml' if kind == 'network' else 'pool-dumpxml', expected['uuid']]
            path = probe.tool('virsh')
            if not path: raise ProbeError('virsh is missing')
            text = probe.run([path, '--readonly', '--connect', uri, *args])
            if kind == 'qemu': valid = backend.domain_capabilities(text, expected['code'])
            elif kind == 'network': valid = backend.network_identity(text, expected)
            else: valid = backend.pool_identity(text, expected, storage['path'])
            details = {}
            if kind != 'qemu':
                probe.live_gate(endpoint, session, kind)
                info_text = probe.run([path, '--readonly', '--connect', uri, 'net-info' if kind == 'network' else 'pool-info', expected['uuid']])
                info = dict((key.strip(), value.strip()) for key, value in
                            (line.split(':', 1) for line in info_text.splitlines() if ':' in line))
                details = {key: info.get(key, 'unverified') for key in ('Active', 'State', 'Persistent', 'Autostart')}
                active = info.get('Active') == 'yes' if kind == 'network' else info.get('State') == 'running'
                valid = valid and active and info.get('Persistent') == 'yes'
            add('backend:' + kind, 'PASS' if valid else 'FAIL', 'Read-only capability and identity, and active or persistent state where applicable, were compared.', 'Do not repair deviations; qualify resource selection and support.', details=details)
        attempt('backend:' + kind, live, 'Daemon or socket state or read permissions do not allow a safe query; do not activate anything.')
    add('network_readiness', 'UNVERIFIED', 'Read-only structural diagnostics prove neither host, guest, or VM communication nor internet or LAN policy.',
        'Validate one-time host setup separately; vmctl does not inventory or modify the firewall.', False)
    add('network_isolation', 'WARN', 'NAT does not isolate the host, LAN, or neighboring guests; default is not evidence of lab ownership.', 'Consider a dedicated network for lab management; validate offline and egress policy separately.', False)
    qualified = all(c['status'] == 'PASS' for c in checks if c['required'])
    return dict(uri=config['uri'], operating_model=config.get('operating_model', 'unspecified'),
                live_requested=request.live, infrastructure_qualified=qualified, network_ready=False,
                checks=checks, notice='Read-only diagnostics only; no VM or image approval and no ownership evidence.')
