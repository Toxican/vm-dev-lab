# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test NoCloud media, SSH identity, and bootstrap safeguards.

"""P05: NoCloud and SSH contracts only with P03 fake domains and temporary keys."""
from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import yaml
from jsonschema import Draft4Validator
from vm_dev_lab.config import ConfigLoader
from vm_dev_lab.errors import LabError
from vm_dev_lab.fake_backend import FakeBackend
from vm_dev_lab.guest.ssh import (MARKER, bootstrap, client_identity, public_key,
                                  sftp_arguments, ssh_arguments)
from vm_dev_lab.operations import OfflineLab
from vm_dev_lab.provisioning.cloudinit import HOSTKEY_SCRIPT, render_seed, write_seed_iso
from vm_dev_lab.state import StatePaths, StateStore
from test_config import public_key as fixture_key


@unittest.skipUnless(shutil.which('ssh-keygen'), 'ssh-keygen is missing; no installation')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'profiles').mkdir()
        data = dict(schema_version=1, ready=True, vm=dict(name='guest', guest_os='arch',
                    base_image=dict(path='../images/base.fixture', sha256='a' * 64),
                    network=dict(name='lab'), ssh=dict(public_keys=[fixture_key()])))
        (self.root / 'profiles/guest.yaml').write_text(json.dumps(data))
        self.resolved = ConfigLoader(self.root).load('guest')
        self.store = StateStore(StatePaths(self.root / 'data', self.root / 'state', self.root / 'runtime'))
        self.store.initialize(); self.backend = FakeBackend()
        self.record = OfflineLab(self.store, self.backend).create(self.resolved)
        self.identity = client_identity(self.root / 'clients', self.record['instance_id'])
        self.client_public = (self.identity / 'id_ed25519.pub').read_text().strip()
        self.seed = render_seed(self.resolved, self.record, [self.client_public], network_mac='52:54:00:12:34:56')
        self.host_key = fixture_key()

    def marker(self, seed=None, key=None):
        return MARKER + json.dumps({'instance_id': (seed or self.seed).binding.seed_instance_id,
                                  'fingerprint': public_key(key or self.host_key)[1]}) + '\n'

    def pin(self, text=None, key=None, reader=None):
        return bootstrap(self.store, self.backend, self.seed.binding,
                         reader or (lambda domain, deadline: text if text is not None else self.marker()),
                         key or self.host_key, self.identity)

    def fail(self, callback, code):
        with self.assertRaises(LabError) as caught: callback()
        self.assertEqual(caught.exception.detail['code'], code)

    def test_seed_has_fresh_instance_id_only_public_keys_and_no_privilege_hooks_from_profile(self):
        user, meta = yaml.safe_load(self.seed.user_data), yaml.safe_load(self.seed.meta_data)
        self.assertFalse(user['ssh_pwauth']); self.assertTrue(user['disable_root'])
        self.assertTrue(user['ssh_deletekeys']); self.assertEqual(user['ssh_genkeytypes'], ['ed25519'])
        self.assertTrue(user['users'][0]['lock_passwd'])
        self.assertNotIn('sudo', user['users'][0]); self.assertNotIn('passwd', user['users'][0])
        self.assertEqual(user['users'][0]['ssh_authorized_keys'], [public_key(self.client_public)[0]])
        self.assertFalse(user['package_update']); self.assertNotIn('packages', user)
        self.assertFalse(user['ssh']['emit_keys_to_console'])
        other = render_seed(self.resolved, self.record, [self.client_public], network_mac='52:54:00:12:34:56')
        self.assertNotEqual(meta['instance-id'], yaml.safe_load(other.meta_data)['instance-id'])
        self.assertNotIn('PRIVATE KEY', self.seed.user_data + self.seed.meta_data)
        self.assertEqual(self.seed.binding.domain_uuid, self.record['domain_uuid'])
        self.assertEqual(user['runcmd'], [['python3', '/usr/local/libexec/vm-dev-lab-hostkey'],
                                         ['/usr/local/libexec/vm-dev-lab-arch-provision']])
        provisioner = next(item for item in user['write_files']
                           if item['path'] == '/usr/local/libexec/vm-dev-lab-arch-provision')
        self.assertEqual(provisioner['permissions'], '0700')
        self.assertNotIn('sudo', provisioner['content'])

    def test_seed_rejects_private_keys_empty_keys_and_unready_profile(self):
        for keys in ([], ['-----BEGIN OPENSSH PRIVATE KEY-----'], [self.client_public, self.client_public], ['command="evil" ' + self.client_public]):
            self.fail(lambda: render_seed(self.resolved, self.record, keys, network_mac='52:54:00:12:34:56'), 'CLIENT_KEY_INVALID')
        self.resolved.incomplete = ['not ready']
        self.fail(lambda: render_seed(self.resolved, self.record, [self.client_public], network_mac='52:54:00:12:34:56'), 'CONFIG_INCOMPLETE')

    def test_package_omission_satisfies_upstream_nonempty_array_contract(self):
        # cloud-init 26.2: $defs.cc_package_update_upgrade_install.properties.packages.minItems=1
        # https://github.com/canonical/cloud-init/blob/26.2/cloudinit/config/schemas/schema-cloud-config-v1.json
        validator = Draft4Validator({'type': 'object', 'properties': {
            'packages': {'type': 'array', 'minItems': 1}}})
        old = yaml.safe_load(self.seed.user_data); old['packages'] = []
        self.assertEqual([list(e.path) for e in validator.iter_errors(old)], [['packages']])
        self.assertFalse(list(validator.iter_errors(yaml.safe_load(self.seed.user_data))))

    def test_seed_requires_explicit_unicast_mac_and_hash_binds_network(self):
        for mac in (None, '', 'eth0', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:54:00:12:34:56'):
            self.fail(lambda: render_seed(self.resolved, self.record, [self.client_public], network_mac=mac),
                      'SEED_NETWORK_INVALID')
        seed = render_seed(self.resolved, self.record, [self.client_public], network_mac='52:54:AB:12:34:56')
        network = yaml.safe_load(seed.network_config)
        self.assertEqual(network['version'], 2)
        nic = network['ethernets']['lab']
        self.assertEqual(nic['match'], {'macaddress': '52:54:ab:12:34:56'})
        self.assertTrue(nic['dhcp4']); self.assertFalse(nic['dhcp6'])
        self.assertNotIn('set-name', nic)  # No assumption about eth0, ens3, or renaming.
        self.assertEqual(yaml.safe_load(seed.meta_data)['dsmode'], 'local')
        import hashlib
        self.assertEqual(seed.sha256, hashlib.sha256(seed.user_data.encode() + b'\0'
                         + seed.meta_data.encode() + b'\0' + seed.network_config.encode()).hexdigest())

    def test_media_includes_network_and_refuses_overwrite_race_and_tool_failure(self):
        folder = self.root / 'media'; folder.mkdir(mode=0o700)
        target = folder / 'seed.iso'
        calls = []
        def tool(argv):
            self.assertEqual(argv[0:2], ['cloud-localds', '--network-config'])
            self.assertEqual(Path(argv[2]).read_text(), self.seed.network_config)
            self.assertEqual(Path(argv[4]).read_text(), self.seed.user_data)
            self.assertEqual(Path(argv[5]).read_text(), self.seed.meta_data)
            calls.append(argv); Path(argv[3]).write_bytes(b'iso-fixture')
            return 0, b''
        write_seed_iso(self.seed, target, runner=tool)
        self.assertEqual(target.read_bytes(), b'iso-fixture')
        self.fail(lambda: write_seed_iso(self.seed, target, runner=tool), 'SEED_EXISTS')
        self.assertEqual(len(calls), 1)
        self.fail(lambda: write_seed_iso(self.seed, folder / 'failed.iso', runner=lambda argv: (1, b'')),
                  'SEED_TOOL_FAILED')
        def race(argv):
            Path(argv[3]).write_bytes(b'iso-fixture'); (folder / 'race.iso').write_bytes(b'foreign')
            return 0, b''
        self.fail(lambda: write_seed_iso(self.seed, folder / 'race.iso', runner=race), 'SEED_EXISTS')
        self.assertEqual((folder / 'race.iso').read_bytes(), b'foreign')

    @unittest.skipUnless(shutil.which('cloud-localds') and shutil.which('isoinfo'), 'Seed tools are missing')
    def test_real_seed_iso_contains_all_three_nocloud_files_without_guest(self):
        folder = self.root / 'real-media'; folder.mkdir(mode=0o700)
        target = write_seed_iso(self.seed, folder / 'seed.iso')
        for name, expected in (('user-data', self.seed.user_data), ('meta-data', self.seed.meta_data),
                               ('network-config', self.seed.network_config)):
            result = subprocess.run(['isoinfo', '-R', '-i', str(target), '-x', '/' + name],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.decode(), expected)

    def test_controlled_guest_script_emits_only_expected_public_fingerprint(self):
        captures = []
        class PublicPath:
            def __init__(self, name): self.name = name
            def read_text(inner):
                if inner.name == '/etc/ssh/ssh_host_ed25519_key.pub': return self.host_key
                self.assertEqual(inner.name, '/var/lib/cloud/data/instance-id')
                return self.seed.binding.seed_instance_id
        class Console(StringIO):
            def __exit__(inner, *args): captures.append(inner.getvalue())
        def console(path, mode):
            self.assertEqual((path, mode), ('/dev/ttyS0', 'w'))
            return Console()
        with patch('pathlib.Path', PublicPath), patch('builtins.open', side_effect=console):
            exec(compile(HOSTKEY_SCRIPT, '<controlled guest fixture>', 'exec'), {})
        self.assertEqual(captures, [self.marker()])

    def test_bound_bootstrap_pins_key_and_ssh_options_are_strict(self):
        calls = []
        def serial(domain, deadline):
            calls.append(domain); return self.marker()
        evidence = self.pin(reader=serial)
        self.assertEqual(calls, [self.record['domain_uuid']])
        self.assertEqual(evidence['fingerprint'], public_key(self.host_key)[1])
        before = (self.identity / 'known_hosts').read_bytes()
        self.pin()  # Reapplying the same pin is idempotent.
        self.assertEqual(before, (self.identity / 'known_hosts').read_bytes())
        args = ssh_arguments(self.identity, self.record['instance_id'], '192.0.2.10', 'developer')
        for option in ('StrictHostKeyChecking=yes', 'BatchMode=yes', 'ForwardAgent=no', 'IdentityAgent=none', 'IdentitiesOnly=yes'):
            self.assertIn(option, args)
        self.assertIn('GlobalKnownHostsFile=/dev/null', args)
        self.assertEqual(args[-2:], ['--', '192.0.2.10'])
        self.assertNotIn('StrictHostKeyChecking=no', args)
        sftp = sftp_arguments(self.identity, self.record['instance_id'],
                              '192.0.2.10', 'developer')
        self.assertEqual(sftp[0], 'sftp')
        self.assertIn('StrictHostKeyChecking=yes', sftp)
        self.assertIn('BatchMode=yes', sftp)
        self.assertEqual(sftp[-4:], ['-b', '-', '--', 'developer@192.0.2.10'])

    def test_missing_duplicate_stale_or_mismatched_bootstrap_fails_without_pin(self):
        stale = replace(self.seed, binding=replace(self.seed.binding, seed_instance_id='00000000-0000-4000-8000-000000000000'))
        for text in ('', self.marker(stale), self.marker() * 2, MARKER + '{bad', 'x' * (1024 * 1024 + 1)):
            self.fail(lambda: self.pin(text), 'BOOTSTRAP_MISSING')
            self.assertFalse((self.identity / 'known_hosts').exists())
        other_key = self.client_public
        self.fail(lambda: self.pin(key=other_key), 'HOSTKEY_MISMATCH')
        self.assertFalse((self.identity / 'known_hosts').exists())

    def test_existing_mismatch_is_preserved_and_global_paths_are_rejected(self):
        self.pin()
        path = self.identity / 'known_hosts'
        replacement = f'vm-dev-lab-{self.record["instance_id"]} {public_key(self.client_public)[0]}\n'
        path.write_text(replacement)
        self.fail(self.pin, 'HOSTKEY_MISMATCH')
        self.assertEqual(path.read_text(), replacement)
        self.fail(lambda: bootstrap(self.store, self.backend, self.seed.binding, lambda *a: self.marker(), self.host_key, self.root), 'SSH_PATH_UNSAFE')

    def test_domain_registry_change_and_wrong_binding_cannot_pin(self):
        wrong = replace(self.seed.binding, domain_uuid='00000000-0000-4000-8000-000000000000')
        reader = unittest.mock.Mock(return_value=self.marker())
        self.fail(lambda: bootstrap(self.store, self.backend, wrong, reader, self.host_key, self.identity), 'BOOTSTRAP_BINDING_INVALID')
        reader.assert_not_called()
        def changed(domain, deadline):
            self.backend.domains[domain]['metadata']['lab_id'] = wrong.domain_uuid
            return self.marker()
        self.fail(lambda: self.pin(reader=changed), 'OWNERSHIP_MISMATCH')
        self.assertFalse((self.identity / 'known_hosts').exists())

    def test_client_key_and_known_hosts_cannot_be_replaced_or_symlinked(self):
        private = (self.identity / 'id_ed25519').read_bytes()
        self.fail(lambda: client_identity(self.root / 'clients', self.record['instance_id']), 'CLIENT_KEY_EXISTS')
        self.assertEqual(private, (self.identity / 'id_ed25519').read_bytes())
        foreign = self.root / 'foreign'; foreign.write_text('unchanged')
        (self.identity / 'known_hosts').symlink_to(foreign)
        with self.assertRaises((LabError, OSError)): self.pin()
        self.assertEqual(foreign.read_text(), 'unchanged')

    def test_timeout_and_no_network_commands(self):
        with patch('vm_dev_lab.guest.ssh.time.monotonic', side_effect=[0, 2]):
            with self.assertRaises(LabError) as caught:
                bootstrap(self.store, self.backend, self.seed.binding, lambda *a: self.marker(), self.host_key, self.identity, timeout=1)
            self.assertEqual(caught.exception.exit_code, 7)
        with patch('socket.socket', side_effect=AssertionError('No network')), patch('subprocess.Popen', side_effect=AssertionError('No client launch')):
            self.pin()
            ssh_arguments(self.identity, self.record['instance_id'], '192.0.2.10', 'developer')
