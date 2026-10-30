# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test Arch guest package and readiness validation with local fakes.

"""P07: Arch package adapter and readiness only with local process and SSH fakes."""
import json
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.errors import LabError
from vm_dev_lab.provisioning.arch import GUEST_MANIFEST, provisioning_script, validate_guest_manifest


class ArchAdapterTests(unittest.TestCase):
    def test_controlled_script_installs_exact_packages_and_records_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'manifest.json'
            source = provisioning_script(['git', 'python'], 'developer').replace(repr(GUEST_MANIFEST), repr(str(target)), 1)
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[:2] == ['/usr/bin/sshd', '-T']:
                    return subprocess.CompletedProcess(argv, 0, 'PasswordAuthentication no\nPubkeyAuthentication yes\n', '')
                if argv[:2] == ['/usr/bin/pacman', '-Syu']:
                    return subprocess.CompletedProcess(argv, 0, '', '')
                if argv[:2] == ['/usr/bin/pacman', '-Q']:
                    return subprocess.CompletedProcess(argv, 0, 'git 2.51.0-1\npython 3.14.0-1\n', '')
                raise AssertionError(argv)

            account = SimpleNamespace(pw_uid=1000, pw_dir='/home/developer')
            with patch.object(subprocess, 'run', side_effect=run), patch.object(pwd, 'getpwnam', return_value=account):
                exec(compile(source, '<arch-provisioner>', 'exec'), {})
            value = json.loads(target.read_text())
            self.assertEqual(value['status'], 'project-ready')
            self.assertEqual(value['installed_packages'], {'git': '2.51.0-1', 'python': '3.14.0-1'})
            self.assertIn(['/usr/bin/pacman', '-Syu', '--needed', '--noconfirm', '--', 'git', 'python'], calls)
            self.assertNotIn('sudo', source)

    def test_adapter_rejects_shell_fragments_and_manifest_version_mismatch(self):
        for packages in (['--needed'], ['git;reboot'], ['git', 'git']):
            with self.subTest(packages=packages), self.assertRaises(LabError):
                provisioning_script(packages, 'developer')
        value = {'schema_version':1,'adapter':'arch-pacman-v1','status':'project-ready',
                 'requested_packages':['git'],'installed_packages':{'git':'invalid version with spaces'},
                 'user':{'name':'developer','uid':1000,'home':'/home/developer','valid':True},
                 'ssh':{'public_key_login':True,'password_authentication':True},
                 'transaction':{'attempted':True,'exit_code':0},'error':None}
        with self.assertRaises(LabError) as caught:
            validate_guest_manifest(value, ['git'], 'developer')
        self.assertEqual(caught.exception.detail['code'], 'GUEST_MANIFEST_INVALID')

    def test_failed_transaction_still_records_observed_package_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'manifest.json'
            source=provisioning_script(['git','missing-package'],'developer').replace(
                repr(GUEST_MANIFEST),repr(str(target)),1)
            def run(argv,**kwargs):
                if argv[:2] == ['/usr/bin/sshd','-T']:
                    return subprocess.CompletedProcess(argv,0,'PasswordAuthentication no\nPubkeyAuthentication yes\n','')
                if argv[:2] == ['/usr/bin/pacman','-Syu']:
                    return subprocess.CompletedProcess(argv,1,'','')
                return subprocess.CompletedProcess(argv,1,'git 2.51.0-1\n','')
            account=SimpleNamespace(pw_uid=1000,pw_dir='/home/developer')
            with patch.object(subprocess,'run',side_effect=run), patch.object(pwd,'getpwnam',return_value=account), \
                    self.assertRaises(SystemExit):
                exec(compile(source,'<arch-provisioner>','exec'),{})
            value=json.loads(target.read_text())
            self.assertEqual(value['status'],'failed')
            self.assertEqual(value['error'],'PACKAGE_TRANSACTION_FAILED')
            self.assertEqual(value['installed_packages'],{'git':'2.51.0-1'})
if __name__ == '__main__':
    unittest.main()
