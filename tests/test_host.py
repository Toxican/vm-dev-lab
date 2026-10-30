# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test read-only host diagnostics and live-access safety gates.

"""P04: Diagnostics and activation gates without real host or libvirt access."""
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from vm_dev_lab.cli import main
from vm_dev_lab.errors import LabError
from vm_dev_lab.host import HostRequest, LocalProbe, ProbeError, diagnose, load_request
from vm_dev_lab import libvirt_backend as backend
from jsonschema import Draft202012Validator

NETWORK_UUID = '11111111-1111-4111-8111-111111111111'
POOL_UUID = '22222222-2222-4222-8222-222222222222'
CONFIG = dict(schema_version=1, uri='qemu:///system', operating_model='manual',
              firmware=dict(code='/firmware/CODE.fd', vars='/firmware/VARS.fd'),
              storage=dict(path='/lab/storage', min_free_gib=10, pool=dict(name='lab', uuid=POOL_UUID)),
              network=dict(name='lab', uuid=NETWORK_UUID, mode='nat', subnet='10.42.0.0/24'),
              endpoints={kind: dict(unit='labor-' + kind + '.service', socket='/sockets/' + kind, mode='direct') for kind in ('qemu', 'network', 'storage')})
CAPS = ('<domainCapabilities><arch>x86_64</arch><domain>kvm</domain>'
        '<os><loader supported="yes"><value>/firmware/CODE.fd</value></loader></os>'
        '<features><backingStoreInput supported="yes"/></features></domainCapabilities>')
NETWORK = f'<network><name>lab</name><uuid>{NETWORK_UUID}</uuid><forward mode="nat"/><ip address="10.42.0.1" prefix="24"/></network>'
POOL = f'<pool type="dir"><name>lab</name><uuid>{POOL_UUID}</uuid><target><path>/lab/storage</path></target></pool>'


class FakeProbe(LocalProbe):
    def __init__(self, deadline=100):
        super().__init__(deadline)
        self.commands = []
        self.unit_state = 'active'
        self.socket_state = 'inactive'
        self.owner = True
        self.binding_present = True
        self.architecture = 'x86_64'
        self.free = 100 * 1024 ** 3
        self.user_access = True
        self.bad_xml = False
        self.missing = set()

    def tool(self, name): return None if name in self.missing else '/mock/' + name
    def machine(self): return self.architecture
    def release(self): return dict(ID='test', VERSION_ID='fixture')
    def binding(self): return self.binding_present
    def kvm(self): return True, self.user_access
    def firmware(self, code, variables): return True
    def storage(self, path): return self.free, self.user_access
    def services(self, session): return ['labor-qemu.service']
    def service(self, unit, session):
        return dict(LoadState='loaded', ActiveState=self.socket_state if unit.endswith('.socket') else self.unit_state,
                    SubState='running', MainPID='42', TriggeredBy='' if unit.endswith('.socket') else 'labor.socket')
    def firewall(self): raise AssertionError('vmctl must not inventory the firewall')
    def owns_socket(self, endpoint, pid, kind): return self.owner
    def run(self, args):
        self.commands.append(args)
        if args[-1] == '--version': return 'fixture version 1\n'
        if args[-1] == '--help': return 'Supported formats: raw qcow2\n'
        if '--connect' not in args or '--readonly' not in args: raise AssertionError('No non-read-only connections')
        if self.bad_xml: return '<bad/>'
        if 'net-info' in args: return 'Active: yes\nPersistent: yes\nAutostart: yes\n'
        if 'pool-info' in args: return 'State: running\nPersistent: yes\nAutostart: yes\n'
        if 'domcapabilities' in args: return CAPS
        if 'net-dumpxml' in args: return NETWORK
        if 'pool-dumpxml' in args: return POOL
        raise AssertionError(args)


class HostTests(unittest.TestCase):
    def test_default_never_connects_or_assumes_default_resources(self):
        probe = FakeProbe()
        report = diagnose(load_request(), probe)
        self.assertFalse(report['infrastructure_qualified'])
        self.assertTrue(any(c['status'] == 'UNVERIFIED' for c in report['checks']))
        self.assertFalse(any('--connect' in args for args in probe.commands))

    def test_explicit_live_identity_capabilities_and_space(self):
        probe = FakeProbe()
        report = diagnose(HostRequest(deepcopy(CONFIG), True), probe)
        self.assertTrue(report['infrastructure_qualified'])
        calls = [args for args in probe.commands if '--connect' in args]
        self.assertEqual(len(calls), 5)
        self.assertIn(NETWORK_UUID, calls[1])
        self.assertIn(POOL_UUID, calls[3])
        self.assertTrue(all('--readonly' in args for args in calls))
        self.assertTrue(all('socket=' in args[3] and 'mode=direct' in args[3] for args in calls))

    def test_inactive_daemons_active_sockets_or_unknown_owner_prevent_connections(self):
        for change in (dict(unit_state='inactive'), dict(socket_state='active'), dict(socket_state='activating'), dict(owner=False)):
            probe = FakeProbe()
            for key, value in change.items(): setattr(probe, key, value)
            report = diagnose(HostRequest(deepcopy(CONFIG), True), probe)
            self.assertFalse(report['infrastructure_qualified'])
            self.assertFalse(any('--connect' in args for args in probe.commands))

    def test_incomplete_or_changing_service_observation_is_not_sufficient(self):
        probe = FakeProbe()
        with patch.object(probe, 'service', return_value={'ActiveState': 'active'}):
            with self.assertRaises(ProbeError): probe.live_gate(CONFIG['endpoints']['qemu'], False, 'qemu')
        original = probe.service
        def changing(unit, session):
            data = original(unit, session)
            if unit.endswith('.service'):
                data['MainPID'] = str(changing.counter)
                changing.counter += 1
            return data
        changing.counter = 42
        with patch.object(probe, 'service', side_effect=changing):
            with self.assertRaises(ProbeError): probe.live_gate(CONFIG['endpoints']['qemu'], False, 'qemu')

    def test_gate_errors_and_bad_xml_never_become_pass(self):
        probe = FakeProbe(); probe.bad_xml = True
        report = diagnose(HostRequest(deepcopy(CONFIG), True), probe)
        self.assertFalse(report['infrastructure_qualified'])
        self.assertTrue(all(c['status'] != 'PASS' for c in report['checks'] if c['name'].startswith('backend:')))
        with patch.object(probe, 'live_gate', side_effect=PermissionError):
            probe.commands.clear()
            diagnose(HostRequest(deepcopy(CONFIG), True), probe)
            self.assertFalse(any('--connect' in args for args in probe.commands))

    def test_resource_identity_mismatch_and_extra_networks_are_rejected(self):
        self.assertTrue(backend.network_identity(NETWORK, CONFIG['network']))
        self.assertFalse(backend.network_identity(NETWORK.replace(NETWORK_UUID, POOL_UUID), CONFIG['network']))
        self.assertFalse(backend.network_identity(NETWORK.replace('</network>', '<ip family="ipv6" address="fd00::1" prefix="64"/></network>'), CONFIG['network']))
        self.assertFalse(backend.network_identity(NETWORK.replace('nat', 'bridge'), CONFIG['network']))
        self.assertTrue(backend.pool_identity(POOL, CONFIG['storage']['pool'], '/lab/storage'))
        self.assertFalse(backend.pool_identity(POOL, CONFIG['storage']['pool'], '/other'))
        self.assertFalse(backend.pool_identity(POOL.replace('type="dir"', 'type="logical"'), CONFIG['storage']['pool'], '/lab/storage'))
        self.assertFalse(backend.domain_capabilities(CAPS.replace('kvm', 'qemu'), '/firmware/CODE.fd'))
        self.assertFalse(backend.domain_capabilities(
            CAPS.replace('backingStoreInput supported="yes"',
                         'backingStoreInput supported="no"'), '/firmware/CODE.fd'))
        for text in ('<!DOCTYPE network [<!ENTITY x "unsafe">]><network/>', '<broken', '<x/>', 'x' * (1024 * 1024 + 1)):
            with self.assertRaises(ValueError): backend.xml(text, 'network')

    def test_missing_dependencies_wrong_architecture_and_space_are_explicit(self):
        probe = FakeProbe(); probe.binding_present = False; probe.architecture = 'aarch64'; probe.free = 0; probe.missing = {'qemu-img'}
        report = diagnose(HostRequest(deepcopy(CONFIG)), probe)
        failures = {c['name'] for c in report['checks'] if c['status'] == 'FAIL'}
        self.assertTrue({'python_binding', 'architecture', 'storage_space', 'qemu-img'} <= failures)
        self.assertFalse(report['infrastructure_qualified'])

    def test_session_and_operating_models_do_not_change_services(self):
        for model in ('manual', 'permanent'):
            config = deepcopy(CONFIG); config['operating_model'] = model; config['uri'] = 'qemu:///session'
            probe = FakeProbe()
            report = diagnose(HostRequest(config), probe)
            self.assertEqual(report['operating_model'], model)
            self.assertTrue(any(c['name'] == 'session_support' for c in report['checks']))
            self.assertFalse(any('--connect' in args for args in probe.commands))

    def test_resource_config_rejects_unknown_fields_paths_versions_and_options(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'host.json'
            path.write_text(json.dumps(CONFIG))
            self.assertEqual(load_request(path).config, CONFIG)
            for change in (lambda c: c.update(uri='qemu+ssh://remote/system'), lambda c: c.update(schema_version=True),
                           lambda c: c.update(unknown='secret'), lambda c: c['network'].update(uuid='default'),
                           lambda c: c['storage'].update(path='../escape'), lambda c: c['network'].update(subnet='invalid'),
                           lambda c: c['endpoints']['qemu'].update(unit='start virtqemud.service')):
                config = deepcopy(CONFIG); change(config); path.write_text(json.dumps(config))
                with self.assertRaises(LabError): load_request(path)
            for raw in ('{"schema_version":1,"schema_version":1}', 'x' * 65537, '{broken'):
                path.write_text(raw)
                with self.assertRaises(LabError): load_request(path)
            path.unlink(); path.symlink_to('/not/read')
            with self.assertRaises(LabError): load_request(path)

    def test_command_runner_bounds_output_timeout_and_never_waits_for_stdin(self):
        probe = LocalProbe(time.monotonic() + 5)
        self.assertEqual(probe.run([sys.executable, '-c', 'import sys; print(len(sys.stdin.read()))']).strip(), '0')
        with patch('vm_dev_lab.host.LIMIT', 128):
            with self.assertRaises(ProbeError):
                probe.run([sys.executable, '-c', 'print("x" * 4096)'])
        with self.assertRaises(ProbeError):
            LocalProbe(time.monotonic() + .1).run([sys.executable, '-c', 'import time; time.sleep(3)'])
        with self.assertRaises(LabError) as caught:
            LocalProbe(time.monotonic() - 1).run(['never-executed'])
        self.assertEqual(caught.exception.exit_code, 7)

    def test_cli_json_and_text_diagnostics_have_no_fixture_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'host.json'; path.write_text(json.dumps(CONFIG))
            before = path.read_bytes()
            schema = json.loads((ROOT / 'src/vm_dev_lab/result-schema.json').read_text())
            for live in (False, True):
                out, err = StringIO(), StringIO()
                with patch('vm_dev_lab.host.LocalProbe', FakeProbe), redirect_stdout(out), redirect_stderr(err):
                    code = main(['--json', '--non-interactive', 'check-host', '--resources', str(path), *(['--live'] if live else [])])
                self.assertEqual(code, 0 if live else 3)
                report = json.loads(out.getvalue()); Draft202012Validator(schema).validate(report)
                self.assertEqual(err.getvalue(), '')
                self.assertEqual(report['command'], 'check-host')
            out, err = StringIO(), StringIO()
            with patch('vm_dev_lab.host.LocalProbe', FakeProbe), redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(['check-host']), 3)
            self.assertIn('UNVERIFIED:', out.getvalue())
            self.assertIn('HOST_NOT_QUALIFIED', err.getvalue())
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(temp).iterdir()), [path])
