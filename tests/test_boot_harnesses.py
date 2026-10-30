# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test bounded boot harness plans, reports, and cleanup evidence.

"""Result evaluation only; the real harness is never invoked in run mode."""
import json
import importlib.util
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from vm_dev_lab.testing import spike_exit_code


class BootHarnessTests(unittest.TestCase):
    def success(self):
        return dict(spike_ok=True, cleanup_ok=True, domain_removed=True,
                    runtime_files_removed=True, client_identity_removed=True)

    def test_caught_test_failure_is_not_successful_cleanup(self):
        report = self.success()
        report.update(spike_ok=False, spike_error={'message': 'guest readiness failed'})
        self.assertEqual(spike_exit_code(report), 1)

    def test_incomplete_cleanup_and_truthy_strings_never_pass(self):
        for key in self.success():
            for value in (False, None, 'true', 1):
                report = self.success(); report[key] = value
                self.assertEqual(spike_exit_code(report), 1)
            report = self.success(); del report[key]
            self.assertEqual(spike_exit_code(report), 1)
        for value in (None, [], {}, 'success'):
            self.assertEqual(spike_exit_code(value), 1)
        report = self.success(); report['cleanup_error'] = {'message': 'ownership unclear'}
        self.assertEqual(spike_exit_code(report), 1)
        self.assertEqual(spike_exit_code(self.success()), 0)

    def test_new_run_uses_distinct_paths_and_rejects_historical_or_invalid_ids(self):
        spec = importlib.util.spec_from_file_location(
            'p05_paths', ROOT / 'tests/harnesses/single_vm_boot.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        old = (module.REPORT, module.STORE_ROOT, module.STORAGE)
        for value in ('03b9fac2-744d-414a-9c75-44124734b794', '../old', 'bad'):
            with self.assertRaises(ValueError): module.configure_run(value)
            self.assertEqual((module.REPORT, module.STORE_ROOT, module.STORAGE), old)
        run_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        module.configure_run(run_id)
        self.assertEqual(module.REPORT, ROOT / 'local/p05-runs' / run_id / 'report.json')
        self.assertEqual(module.STORE_ROOT, ROOT / 'local/p05-runs' / run_id / 'private')
        self.assertNotEqual(module.STORAGE, old[2])
        self.assertEqual(module.DOMAIN, '854180f4-c272-417f-b2c9-7c70ba7ef403')
        self.assertEqual(module.STORAGE,
                         Path('/var/lib/libvirt/vm-dev-lab-desktop') / run_id)

    def test_desktop_spike_uses_the_approved_resources_and_limits(self):
        spec = importlib.util.spec_from_file_location(
            'p05_desktop', ROOT / 'tests/harnesses/single_vm_boot.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(module.URI, 'qemu:///system')
        self.assertEqual(module.NET, 'vm-dev-lab-desktop-nat')
        self.assertEqual(module.NETID, 'f5a7cb75-8bb6-4c13-9e80-a69502b7d0da')
        self.assertEqual(module.POOLID, '4eeab8ed-f150-4d2f-8cd0-76f4d6be3e5c')
        self.assertEqual((module.VCPU, module.MEMORY_MIB, module.DISK_GIB), (1, 1024, 15))
        xml = module.specification({'lab_id': 'lab', 'instance_id': 'instance',
                                    'domain_uuid': module.DOMAIN}, '52:54:00:12:34:56')
        self.assertIn('<memory unit="MiB">1024</memory>', xml)
        self.assertIn('<vcpu>1</vcpu>', xml)
        self.assertIn('network="vm-dev-lab-desktop-nat"', xml)
        self.assertIn(os.geteuid(), module.runtime_uids())
        try:
            libvirt_uid = pwd.getpwnam('libvirt-qemu').pw_uid
        except KeyError:
            pass
        else:
            self.assertIn(libvirt_uid, module.runtime_uids())

        alternate = module.specification(
            {'lab_id': 'lab', 'instance_id': 'instance',
             'domain_uuid': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},
            '52:54:00:65:43:21', name='p05-stage-b-vm2',
            domain_uuid='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            storage=Path('/var/lib/libvirt/vm-dev-lab-desktop/run/vm2'))
        self.assertIn('<name>p05-stage-b-vm2</name>', alternate)
        self.assertIn('<uuid>bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb</uuid>', alternate)
        self.assertIn('/var/lib/libvirt/vm-dev-lab-desktop/run/vm2/work.qcow2', alternate)

    def test_actual_report_only_entrypoint_returns_process_failure_without_libvirt(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'report.json'
            # -S excludes site-packages; report-only evaluation does not require libvirt.
            for report, expected in ((self.success(), 0),
                                     ({**self.success(), 'spike_ok': False}, 1),
                                     ({**self.success(), 'cleanup_ok': False}, 1)):
                path.write_text(json.dumps(report))
                result = subprocess.run([sys.executable, '-S',
                                         str(ROOT / 'tests/harnesses/single_vm_boot.py'),
                                         '--report-only', str(path)], cwd=temp,
                                        env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['exit_code'], expected)
                self.assertEqual(set(Path(temp).iterdir()), {path})
            path.write_text('{invalid')
            result = subprocess.run([sys.executable, '-S',
                                     str(ROOT / 'tests/harnesses/single_vm_boot.py'),
                                     '--report-only', str(path)],
                                    env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            result = subprocess.run([sys.executable, '-S',
                                     str(ROOT / 'tests/harnesses/single_vm_boot.py')], cwd=temp,
                                    env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)  # Never enter the run path without an explicit mode.

    def test_two_vm_plan_is_exact_bounded_and_report_only(self):
        spec = importlib.util.spec_from_file_location(
            'p05_two', ROOT / 'tests/harnesses/multi_vm_boot.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        run_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'
        storage=Path('/var/lib/libvirt/vm-dev-lab-desktop')/run_id
        report={'run_id':run_id,'deadline_epoch':time.time()+60,'guests':[
            {'name':'p05-stage-b-vm1','domain_uuid':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
             'vcpus':1,'memory_mib':1024,'disk_gib':15,'storage_path':str(storage/'vm1')},
            {'name':'p05-stage-b-vm2','domain_uuid':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
             'vcpus':1,'memory_mib':1024,'disk_gib':15,'storage_path':str(storage/'vm2')}]
        }
        self.assertEqual(module.validate_plan(report),(run_id,report['guests'],storage))
        self.assertEqual((module.MEM_BEFORE,module.MEM_RESERVE,module.STORAGE_BEFORE,
                          module.ACTUAL_LIMIT,module.TEST_SECONDS,module.SHUTDOWN_SECONDS),
                         (10*1024**3,8*1024**3,80*1024**3,40*1024**3,1800,120))
        duplicate=json.loads(json.dumps(report)); duplicate['guests'][1]['domain_uuid']=duplicate['guests'][0]['domain_uuid']
        with self.assertRaises(RuntimeError): module.validate_plan(duplicate)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'report.json'; path.write_text(json.dumps(self.success()))
            result=subprocess.run([sys.executable,'-S',
                                   str(ROOT/'tests/harnesses/multi_vm_boot.py'),
                                   '--report-only',str(path)],cwd=ROOT,
                                  env={**os.environ,'PYTHONPATH':str(ROOT/'src')},
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
