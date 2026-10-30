# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test canonical host resource planning and apply safeguards.

"""Setup script only with an injected in-memory system; never real host changes."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import posixpath
import os
import subprocess
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
# The file name is deliberately executable manually, not a package or CLI backend.
import importlib.util
spec = importlib.util.spec_from_file_location('host_setup', ROOT / 'scripts/setup-host.py')
setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)


class FakeSystem:
    def __init__(self):
        self.objects = {'networks': [], 'pools': [], 'domains': []}
        self.state = None
        self.directory = None
        self.commands = []
        self.route_values = [('lan0', '192.168.100.0/24'), ('virbr0', '192.168.122.0/24')]
        self.address_values = [('lan0', '192.168.100.0/24')]
        self.link_values = ['lo', 'lan0', 'virbr0']
        self.policies = {}
        self.space = 100 * 1024 ** 3
        self.failure = None
        self.qemu = {}
        self.tools_missing = []
        self.host = 'a' * 64
        self.locked = False
        self.firmware = {'/firmware/CODE.fd': 'c' * 64,
                         '/firmware/VARS.fd': 'd' * 64}

    def effective_uid(self): return 0
    def host_id(self): return self.host
    def firmware_hash(self, path):
        if path not in self.firmware: raise setup.SetupError('Firmware is missing')
        return self.firmware[path]
    def account(self, name): return dict(name=name, uid=1000 if name == 'developer' else 949, gid=1000 if name == 'developer' else 949)
    def qemu_config(self): return self.qemu
    def prerequisites(self): return self.tools_missing
    def storage_parent(self, path): return self.space
    def normalized_path(self, path): return Path(posixpath.normpath(path))
    def storage_info(self, path): return deepcopy(self.directory)
    def record(self): return deepcopy(self.state)
    def inventory(self, live=False): return deepcopy(self.objects)
    def routes(self): return self.route_values
    def addresses(self): return self.address_values
    def links(self): return self.link_values
    def policy(self, kind, name): return self.policies.get(kind, False)
    def acl(self, path):
        value = setup.access_acl(self.state['plan'])
        lines = [line.replace('u:', 'user:', 1).replace('g:', 'group:', 1).replace('m:', 'mask:', 1).replace('o:', 'other:', 1) for line in value.split(',')]
        return '\n'.join(lines + ['default:' + line for line in lines])

    @contextmanager
    def apply_lock(self):
        if self.locked: raise setup.SetupError('locked')
        self.locked = True
        try: yield
        finally: self.locked = False

    def save(self, value): self.state = deepcopy(value)
    def make_storage(self, plan):
        self.commands.append(('mkdir-and-acl', plan['storage']))
        self.directory = dict(device=1, inode=100, uid=plan['owner']['uid'], gid=plan['owner']['gid'])
        return deepcopy(self.directory)
    def define(self, xml, kind):
        if self.failure == kind: raise setup.SetupError('injected define failure')
        self.commands.append(('define', kind))
        self.objects['networks' if kind == 'network' else 'pools'].append(xml)
    def defined(self, kind, identity):
        return next(text for text in self.objects['networks' if kind == 'network' else 'pools'] if ET.fromstring(text).findtext('uuid') == identity)
    def active(self, kind, identity): return (kind + '-start', identity) in self.commands or ('net-start', identity) in self.commands
    def virsh(self, command, identity):
        if self.failure == command: raise setup.SetupError('injected command failure')
        self.commands.append((command, identity))
        if command.endswith('-autostart'):
            self.policies['network' if command.startswith('net-') else 'pool'] = True


class HostSetupTests(unittest.TestCase):
    def test_system_run_reports_exitcode_stdout_and_stderr(self):
        result = SimpleNamespace(returncode=23, stdout=b'backend stdout\n', stderr=b'backend stderr\n')
        with patch.object(setup.subprocess, 'run', return_value=result):
            with self.assertRaises(setup.SetupError) as caught:
                setup.System().run(['fixed-tool', '--fixed-option'])
        message = str(caught.exception)
        self.assertIn('fixed-tool --fixed-option', message)
        self.assertIn('exit code 23', message)
        self.assertIn('stdout:\nbackend stdout\n', message)
        self.assertIn('stderr:\nbackend stderr\n', message)

    def test_project_interpreter_imports_firewall_in_isolated_subprocess(self):
        # No root or host probes: offline planning must reach input validation.
        # -I removes cwd/PYTHONPATH help; the installed project must resolve itself.
        with tempfile.TemporaryDirectory() as folder:
            missing = str(Path(folder) / 'absent.json')
            result = subprocess.run(
                [sys.executable, '-I', str(ROOT / 'scripts/setup-host.py'),
                 'firewall-plan', '--setup-record', missing,
                 '--policy', missing],
                cwd=ROOT, env={'PATH': os.defpath}, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('ABORT: ', result.stderr)
        self.assertIn(missing, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn('ModuleNotFoundError', result.stderr)

    def setUp(self):
        self.system = FakeSystem()
        self.args = SimpleNamespace(owner='developer', qemu_user='libvirt-qemu', mode='manual',
                    network='vm-dev-lab-nat', pool='vm-dev-lab', bridge='virbr-vdl',
                    subnet='192.168.124.0/24', storage='/var/lib/libvirt/vm-dev-lab',
                    min_free_gib=60, reserve_gib=20, activate=False,
                    firmware_code='/firmware/CODE.fd', firmware_vars='/firmware/VARS.fd')

    def plan(self): return setup.make_plan(self.args, self.system)
    def apply(self, plan): return setup.apply(plan, self.system, plan['sha256'], True)
    def reject(self, callback):
        with self.assertRaises(setup.SetupError): callback()

    def test_plan_is_pure_and_produces_explicit_non_default_xml(self):
        plan = self.plan()
        self.assertEqual(self.system.commands, [])
        self.assertIsNone(self.system.state)
        net, pool = map(ET.fromstring, setup.definitions(plan))
        self.assertEqual(net.find('bridge').get('name'), 'virbr-vdl')
        self.assertEqual(net.find('./ip/dhcp/range').get('start'), '192.168.124.10')
        self.assertEqual(net.find('./ip/dhcp/range').get('end'), '192.168.124.254')
        self.assertEqual(pool.findtext('./target/path'), '/var/lib/libvirt/vm-dev-lab')
        self.assertEqual(pool.findtext('./target/permissions/mode'), '0770')
        self.assertEqual(pool.find('./features/cow').get('state'), 'yes')
        self.assertFalse(plan['activate'])
        self.assertEqual(plan['schema_version'], 2)
        self.assertEqual(plan['firmware']['code_sha256'], 'c' * 64)

    def test_manual_apply_only_defines_own_resources_and_is_idempotent(self):
        plan = self.plan(); self.apply(plan)
        self.assertEqual(self.system.state['status'], 'complete')
        before = list(self.system.commands)
        self.assertEqual(len(before), 3)
        self.assertIn('Already configured', self.apply(plan))
        self.assertEqual(before, self.system.commands)
        self.assertFalse(any('autostart' in c[0] or 'start' in c[0] for c in before))

    def test_permanent_and_activate_only_target_approved_uuids(self):
        self.args.mode = 'permanent'; self.args.activate = True
        plan = self.plan(); self.apply(plan)
        targets = [c[1] for c in self.system.commands if c[0].endswith(('-start', '-autostart'))]
        self.assertEqual(set(targets), {plan['network_uuid'], plan['pool_uuid']})
        self.assertNotIn('default', targets)
        self.assertEqual(self.system.state['status'], 'complete')

    def test_hash_acknowledgement_and_host_binding_are_required(self):
        plan = self.plan()
        self.reject(lambda: setup.apply(plan, self.system, 'wrong', True))
        self.reject(lambda: setup.apply(plan, self.system, plan['sha256'], False))
        changed = deepcopy(plan); changed['storage'] = '/etc/another-path'
        self.reject(lambda: self.apply(changed))
        self.system.host = 'b' * 64
        self.reject(lambda: self.apply(plan))
        self.assertEqual(self.system.commands, [])

    def test_routes_addresses_bridges_and_budgets_abort_before_mutation(self):
        plan = self.plan()
        for field, value in (('route_values', [('vpn0', '192.168.0.0/16')]),
                             ('address_values', [('vpn0', '192.168.124.0/24')]),
                             ('link_values', ['virbr-vdl']), ('space', 1024),
                             ('tools_missing', ['setfacl']), ('qemu', {'user': 'another-qemu'})):
            system = FakeSystem(); setattr(system, field, value)
            self.reject(lambda: setup.apply(plan, system, plan['sha256'], True))
            self.assertEqual(system.commands, [])

    def test_foreign_names_uuids_subnets_pool_paths_and_domain_refs_are_not_adopted(self):
        plan = self.plan()
        cases = [('networks', f'<network><name>{plan["network"]}</name><uuid>{plan["network_uuid"]}</uuid></network>'),
                 ('networks', '<network><name>foreign</name><ip address="192.168.124.1" prefix="24"/></network>'),
                 ('pools', '<pool type="dir"><name>foreign</name><target><path>/var/lib/libvirt</path></target></pool>'),
                 ('pools', '<pool type="dir"><name>foreign</name><target><path>/var/lib/libvirt/images/../vm-dev-lab</path></target></pool>'),
                 ('domains', '<domain><devices><interface><source network="vm-dev-lab-nat"/></interface></devices></domain>'),
                 ('domains', '<domain><devices><disk><source file="/var/lib/libvirt/vm-dev-lab/disk.qcow2"/></disk></devices></domain>')]
        for kind, text in cases:
            system = FakeSystem(); system.objects[kind].append(text)
            before = deepcopy(system.objects)
            self.reject(lambda: setup.apply(plan, system, plan['sha256'], True))
            self.assertEqual(before, system.objects)
            self.assertEqual(system.commands, [])
        system = FakeSystem(); system.directory = dict(device=1,inode=10,uid=1000,gid=1000)
        self.reject(lambda: setup.apply(plan, system, plan['sha256'], True))
        self.assertEqual(system.commands, [])

    def test_partial_failure_preserves_record_and_never_cleans_up(self):
        plan = self.plan(); self.system.failure = 'pool'
        self.reject(lambda: self.apply(plan))
        self.assertEqual(self.system.state['status'], 'partial')
        self.assertEqual(self.system.state['completed'], ['storage-directory-and-acl', 'network-defined'])
        before = list(self.system.commands)
        self.reject(lambda: self.apply(plan))
        self.assertEqual(before, self.system.commands)
        self.assertFalse(any('destroy' in c[0] or 'delete' in c[0] or 'undefine' in c[0] for c in before))

    def test_completed_resource_or_policy_changes_are_not_repaired(self):
        plan = self.plan(); self.apply(plan)
        before = list(self.system.commands)
        self.system.objects['networks'][0] = self.system.objects['networks'][0].replace('setup_id=', 'other=')
        self.reject(lambda: self.apply(plan))
        self.assertEqual(before, self.system.commands)
        self.system.objects['networks'][0] = setup.definitions(plan)[0]
        self.system.objects['networks'][0] = self.system.objects['networks'][0].replace('ipv6="no"', 'ipv6="yes"')
        self.reject(lambda: self.apply(plan))
        self.assertEqual(before, self.system.commands)
        self.system.objects['networks'][0] = setup.definitions(plan)[0]
        self.system.policies['network'] = True
        self.reject(lambda: self.apply(plan))
        self.assertEqual(before, self.system.commands)

    def test_rerun_detects_vpn_subroute_and_inode_replacement(self):
        plan = self.plan(); self.apply(plan)
        self.system.route_values.append(('vpn0', '192.168.124.128/25'))
        self.reject(lambda: self.apply(plan))
        self.system.route_values.pop()
        self.system.directory['inode'] += 1
        self.reject(lambda: self.apply(plan))

    def test_no_unsafe_names_root_identities_or_public_subnets(self):
        for key, value in (('network', 'default'), ('pool', 'default'), ('subnet', '127.0.0.0/24'),
                           ('subnet', '8.8.8.0/24'), ('subnet', '192.168.124.0/25'),
                           ('storage', '/var/lib/../etc/escape'), ('bridge', 'bad;command')):
            plan = self.plan(); plan[key] = value; plan['sha256'] = setup.plan_hash(plan)
            self.reject(lambda: self.apply(plan))
        plan = self.plan(); plan['owner']['uid'] = 0; plan['sha256'] = setup.plan_hash(plan)
        self.reject(lambda: self.apply(plan))
        self.assertEqual(self.system.commands, [])


if __name__ == '__main__': unittest.main()
