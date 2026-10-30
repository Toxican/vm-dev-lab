# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test CLI parsing, JSON output, planning, and error boundaries.

"""P02: CLI and JSON contract, offline plans, and error boundaries."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from uuid import UUID

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from vm_dev_lab.cli import main
from vm_dev_lab.errors import ExitCode, LabError
from test_config import public_key

RESULT_SCHEMA = json.loads((ROOT / 'src/vm_dev_lab/result-schema.json').read_text())
Draft202012Validator.check_schema(RESULT_SCHEMA)
VALIDATOR = Draft202012Validator(RESULT_SCHEMA)


class CLIContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'profiles').mkdir()
        self.profile = dict(schema_version=1, ready=True, vm=dict(
            name='test', guest_os='debian', base_image=dict(path='../images/base.qcow2', sha256='a' * 64),
            network=dict(name='lab'), ssh=dict(public_keys=[public_key()])))
        self.write_profile()

    def write_profile(self):
        (self.root / 'profiles/test.yaml').write_text(yaml.safe_dump(self.profile))

    def invoke(self, args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def json_call(self, args, expected):
        code, stdout, stderr = self.invoke(['--json', *args])
        self.assertEqual(code, expected, stderr + stdout)
        result = json.loads(stdout)  # Extra text or multiple objects must fail.
        VALIDATOR.validate(result)
        UUID(result['operation_id'])
        self.assertEqual(result['ok'], code == 0)
        self.assertEqual(stderr, '')
        return result

    def test_successful_validation_and_help_have_one_schema_valid_object(self):
        result = self.json_call(['config', 'validate', 'test', '--root', str(self.root)], 0)
        self.assertEqual(result['state'], 'validated')
        self.assertFalse(result['data']['verified_for_execution'])
        self.assertEqual(result['command'], 'config validate')
        for args in (['--help'], ['config', '--help'], ['create', '--help'], ['recover', '--help'],
                     ['cleanup', '--help'], ['list', '--help'], ['restart', '--help'],
                     ['logs', '--help'], ['exec', '--help'], ['copy', '--help']):
            with self.subTest(args=args):
                self.assertIn('usage:', self.json_call(args, 0)['data']['help'])

    def test_incomplete_and_invalid_config_have_diagnostic_codes(self):
        self.profile['ready'] = False
        self.write_profile()
        result = self.json_call(['config', 'validate', 'test', '--root', str(self.root)], 3)
        self.assertEqual(result['error']['code'], 'CONFIG_INCOMPLETE')
        self.assertTrue(result['data']['incomplete'])
        self.profile['vm']['cpus'] = True
        self.write_profile()
        result = self.json_call(['config', 'validate', 'test', '--root', str(self.root)], 2)
        self.assertEqual(result['error']['code'], 'CONFIG_INVALID')
        invalid_root = self.json_call(['config', 'validate', 'test', '--root', '\0'], 2)
        self.assertEqual(invalid_root['error']['code'], 'CONFIG_INVALID')
        self.assertIn('$.vm.cpus', result['error']['message'])

    def test_parse_errors_never_leak_arguments_and_remain_json(self):
        for args in ([], ['bogus'], ['create'], ['--timeout', 'secret'],
                     ['--unknown', 'PRIVATE_SECRET'], ['--js', 'create', 'test'],
                     ['create', 'test', '--timeout', '2'],
                     ['snapshot', 'test'], ['snapshot', 'test', 'baseline', '--list'],
                     ['list', 'test'], ['logs', 'test', '--follow'],
                     ['logs', 'test', '--operation', 'not-a-uuid'],
                     ['logs', 'test', '--max-bytes', '0'],
                     ['exec', 'test'], ['exec', 'test', '--'],
                     ['exec', 'test', 'true'], ['exec', 'test', '--bad'],
                     ['recover', 'test'], ['recover', 'test', '--cleanup-failed',
                                           '--operation', 'not-a-uuid'],
                     ['cleanup', 'test'],
                     ['cleanup', 'test', '--baseline-staging', '--restore-staging',
                      '--operation', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                     ['cleanup', 'test', '--restore-staging', '--operation', 'not-a-uuid']):
            with self.subTest(args=args):
                result = self.json_call(args, 2)
                self.assertEqual(result['error']['code'], 'CLI_INVALID')
                self.assertNotIn('PRIVATE_SECRET', json.dumps(result))

    def test_timeouts_reject_nonpositive_and_nonfinite_values(self):
        for timeout in ('0', '-1', 'nan', 'inf', '-inf'):
            with self.subTest(timeout=timeout):
                self.json_call([f'--timeout={timeout}', 'config', 'validate', 'test', '--root', str(self.root)], 2)
        with patch('vm_dev_lab.cli.time.monotonic', side_effect=[0, 2]):
            result = self.json_call(['--timeout', '1', 'config', 'validate', 'test', '--root', str(self.root)], 7)
        self.assertEqual(result['error']['code'], 'DEADLINE_EXCEEDED')
        with patch('vm_dev_lab.cli.time.monotonic', side_effect=[0, 0, 0, 2]):
            self.json_call(['--timeout', '1', 'config', 'validate', 'test', '--root', str(self.root)], 7)
        with patch('vm_dev_lab.cli.time.monotonic', side_effect=[0, 0, 2]):
            self.json_call(['--timeout', '1', 'config', 'validate', 'test', '--root', str(self.root)], 7)

    def test_create_plan_contains_intent_and_unverified_checks(self):
        args = ['--non-interactive', '--dry-run', '--yes', 'create', 'test', '--name', 'ci-42', '--root', str(self.root)]
        result = self.json_call(args, 0)
        plan = result['data']['plan']
        self.assertEqual(result['state'], 'planned')
        self.assertFalse(plan['can_execute'])
        self.assertEqual(plan['target'], {'name': 'ci-42', 'uuid': None})
        self.assertEqual(set(plan['checks'].values()), {'unverified'})
        self.assertIn('ssh-readiness', [s['phase'] for s in plan['steps']])
        self.assertIn('project-readiness', [s['phase'] for s in plan['steps']])
        self.assertEqual(plan['requested']['packages'], result['data']['config']['vm']['packages'])
        self.assertEqual(result['data']['origins']['$.vm.name'], '<cli>')
        no_start = self.json_call([*args, '--no-start'], 0)['data']['plan']
        self.assertNotIn('boot', [s['phase'] for s in no_start['steps']])
        self.assertEqual(no_start, self.json_call([*args, '--no-start'], 0)['data']['plan'])
        self.profile['vm']['name'] = 'different-template-name'
        self.write_profile()
        default = self.json_call(['--dry-run', 'create', 'test', '--root', str(self.root)], 0)
        self.assertEqual(default['vm']['name'], 'test')

    def test_cli_name_override_can_fill_missing_profile_name(self):
        self.profile['vm']['name'] = None
        self.write_profile()
        self.json_call(['--dry-run', 'create', 'test', '--name', 'ci', '--root', str(self.root)], 0)
        self.json_call(['--dry-run', 'create', 'test', '--name', '../escape', '--root', str(self.root)], 2)

    def test_draft_dry_run_is_blocked_and_yes_cannot_release_it(self):
        self.profile['ready'] = False
        self.write_profile()
        result = self.json_call(['--yes', '--dry-run', 'create', 'test', '--root', str(self.root)], 3)
        self.assertFalse(result['data']['plan']['can_execute'])
        self.assertTrue(result['data']['plan']['blocked_by'])
        self.assertFalse(result['data']['config']['ready'])
        self.assertFalse(result['data']['config']['vm']['usb']['enabled'])

    def test_unknown_ownership_is_never_invented_for_other_plans(self):
        for args in (['start', 'test'], ['stop', 'test', '--force'],
                     ['snapshot', 'test', 'base', '--readiness', 'project-ready'],
                     ['restore', 'test', 'base', '--start'], ['destroy', 'test'],
                     ['cleanup', 'test', '--restore-staging', '--operation',
                      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                     ['recover', 'test', '--cleanup-failed', '--operation',
                      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']):
            with self.subTest(args=args):
                result = self.json_call(['--dry-run', '--yes', *args], 3)
                self.assertEqual(result['error']['code'], 'STATE_UNAVAILABLE')
                self.assertIsNone(result['data'])
        for args in (['status', 'test'], ['snapshot', 'test', '--list'], ['config', 'validate', 'test']):
            self.json_call(['--dry-run', *args], 2)

    def test_lifecycle_p08a_and_restore_preparation_dispatch_while_switch_stays_explicit(self):
        common = {'name':'test','instance_id':'11111111-1111-4111-8111-111111111111',
                  'domain_uuid':'22222222-2222-4222-8222-222222222222','power_state':'running'}
        lifecycle = MagicMock()
        lifecycle.create.return_value = common
        lifecycle.start.return_value = common
        lifecycle.stop.return_value = {**common, 'power_state':'shutoff'}
        lifecycle.status.return_value = common
        lifecycle.list_instances.return_value = {'instances':[common], 'active_count':1,
                                                   'tombstone_count':0}
        lifecycle.restart.return_value = common
        lifecycle.logs.return_value = {
            **common, 'requires_review':False, 'current_operation':{},
            'selected_operation':{}, 'operations':[],
            'serial_log':{'available':True,'text':'','bytes_returned':0,
                          'source_size':0,'truncated':False,'untrusted':True,
                          'error':None}, 'follow_supported':False}
        lifecycle.exec.return_value = {
            **common, 'operation_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'job_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            'protocol_version':1,'adapter_version':'vm-dev-lab-exec-v1',
            'outcome':'completed','guest_started':True,'guest_pid':123,'guest_pgid':123,
            'guest_exit_code':0,'ssh_exit_code':0,
            'stdout':{'encoding':'base64','data':'','bytes_total':0,'bytes_captured':0,
                      'bytes_returned':0,'truncated':False,'redacted':False},
            'stderr':{'encoding':'base64','data':'','bytes_total':0,'bytes_captured':0,
                      'bytes_returned':0,'truncated':False,'redacted':False},
            'output_untrusted':True}
        lifecycle.destroy.return_value = {**common, 'power_state':'removed', 'removed':True}
        lifecycle.recover_failed_cleanup.return_value = {
            **common, 'power_state':'removed', 'removed':True,
            'source_operation':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'recovery_operation':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'}
        lifecycle.recover_restore.return_value = {
            **common, 'source_operation_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'recovery_operation_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            'classification':'new-complete', 'resolved':True,
            'requires_review':False, 'idempotent':False}
        lifecycle.recover_restore_start.return_value = {
            **common, 'source_operation_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'restore_activation_operation_id':'55555555-5555-4555-8555-555555555555',
            'recovery_operation_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            'resolved':True, 'started':False, 'requires_review':False,
            'idempotent':False}
        lifecycle.cleanup_staging.return_value = {
            **common, 'staging_kind':'restore',
            'source_operation':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'cleanup_operation':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            'removed':True, 'removed_files':['disk.qcow2','preparation.json'],
            'released_resources':{'instances':0,'vcpus':0,'memory_mib':0,
                                  'virtual_disk_bytes':4096,'storage_bytes':0,
                                  'staging_bytes':8192,'operations':1},
            'idempotent':False}
        baseline_id = 'a' * 64
        lifecycle.snapshot.return_value = {**common, 'baseline_id':baseline_id, 'verified':True}
        lifecycle.verify_snapshot.return_value = {**common, 'baseline_id':baseline_id, 'verified':True}
        lifecycle.list_snapshots.return_value = {**common, 'baselines':[]}
        lifecycle.prepare_restore.return_value = {
            **common, 'baseline_id':baseline_id,
            'restore_operation_id':'33333333-3333-4333-8333-333333333333',
            'generation_id':'44444444-4444-4444-8444-444444444444',
            'status':'prepared','prepared':True,'activation_permitted':False}
        lifecycle.inspect_restore_preparation.return_value = deepcopy(
            lifecycle.prepare_restore.return_value)
        lifecycle.activate_restore.return_value = {
            **common, 'baseline_id':baseline_id,
            'restore_operation_id':'33333333-3333-4333-8333-333333333333',
            'activation_operation_id':'55555555-5555-4555-8555-555555555555',
            'generation_id':'44444444-4444-4444-8444-444444444444',
            'restored':True, 'started':False}
        with patch('vm_dev_lab.lifecycle.Lifecycle', return_value=lifecycle):
            for args in (['create','test','--root',str(self.root)], ['list'], ['start','test'],
                         ['stop','test'], ['restart','test'], ['status','test'],
                         ['logs','test','--operation','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                          '--max-bytes','1024'],
                         ['exec','test','--','python','-c','print(1)','space value','','-x'],
                         ['destroy','test'],
                         ['snapshot','test','project-base','--readiness','project-ready'],
                         ['snapshot','test','--verify',baseline_id], ['snapshot','test','--list'],
                         ['cleanup','test','--restore-staging','--operation',
                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                         ['recover','test','--cleanup-failed','--operation',
                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                         ['recover','test','--restore','--operation',
                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                         ['recover','test','--restore-start','--operation',
                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']):
                with self.subTest(args=args):
                    result = self.json_call(['--non-interactive','--yes',*args], 0)
                    self.assertIn('lifecycle', result['data'])
            prepared = self.json_call([
                '--non-interactive','--yes','restore','test',baseline_id,'--prepare'], 0)
            self.assertTrue(prepared['data']['lifecycle']['prepared'])
            inspected = self.json_call([
                '--non-interactive','restore','test',baseline_id,'--inspect-preparation',
                '33333333-3333-4333-8333-333333333333'], 0)
            self.assertTrue(inspected['data']['lifecycle']['prepared'])
            activated = self.json_call([
                '--non-interactive','--yes','restore','test',baseline_id,
                '--activate-preparation','33333333-3333-4333-8333-333333333333'], 0)
            self.assertTrue(activated['data']['lifecycle']['restored'])
            self.assertFalse(activated['data']['lifecycle']['started'])
        lifecycle.close.assert_called()
        result = self.json_call(['restore','test',baseline_id,'--start'], 2)
        self.assertEqual(result['error']['code'], 'OPTION_UNSUPPORTED')
        result = self.json_call([
            'recover','test','--migrate-legacy-dac','--operation',
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'], 2)
        self.assertEqual(result['error']['code'], 'CLI_INVALID')
        self.json_call(['--non-interactive', 'ssh', 'test'], 2)

    def test_exec_maps_guest_transport_timeout_and_protocol_outcomes_with_data(self):
        common = {'name':'test','instance_id':'11111111-1111-4111-8111-111111111111',
                  'domain_uuid':'22222222-2222-4222-8222-222222222222',
                  'operation_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                  'job_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                  'protocol_version':1,'adapter_version':'vm-dev-lab-exec-v1',
                  'guest_started':None,'guest_pid':None,'guest_pgid':None,
                  'guest_exit_code':None,'ssh_exit_code':None,
                  'stdout':None,'stderr':None,'output_untrusted':True}
        cases = (
            ('completed',0,0,None),
            ('guest_failed',8,255,'GUEST_COMMAND_FAILED'),
            ('timed_out',7,None,'GUEST_COMMAND_TIMEOUT'),
            ('transport_failed',6,None,'SSH_TRANSPORT_FAILED'),
            ('protocol_failed',6,None,'EXEC_PROTOCOL_INVALID'),
        )
        for outcome,code,guest,error in cases:
            lifecycle=MagicMock()
            lifecycle.exec.return_value={**common,'outcome':outcome,'guest_exit_code':guest}
            with self.subTest(outcome=outcome), patch(
                    'vm_dev_lab.lifecycle.Lifecycle',return_value=lifecycle):
                result=self.json_call(['exec','test','--','program','a b','', '-x'],code)
                self.assertEqual(result['data']['lifecycle']['job_id'],common['job_id'])
                self.assertEqual(result['data']['lifecycle']['guest_exit_code'],guest)
                if error is not None:
                    self.assertEqual(result['error']['code'],error)
                lifecycle.exec.assert_called_once()

    def test_exec_dry_run_is_rejected_and_arguments_do_not_leak_on_parse_error(self):
        result=self.json_call(['--dry-run','exec','test','--','PRIVATE_SECRET'],2)
        self.assertEqual(result['error']['code'],'OPTION_UNSUPPORTED')
        self.assertNotIn('PRIVATE_SECRET',json.dumps(result))

    def test_copy_dispatches_both_directions_and_maps_outcomes(self):
        common = {'name':'test','instance_id':'11111111-1111-4111-8111-111111111111',
                  'domain_uuid':'22222222-2222-4222-8222-222222222222',
                  'operation_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                  'transfer_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                  'protocol_version':1,'adapter_version':'vm-dev-lab-files-v1',
                  'direction':'host-to-guest','guest_path':'target','kind':'file',
                  'file_count':1,'total_bytes':1,'manifest_sha256':'a'*64,
                  'files':[{'path':'x','size':1,'sha256':'b'*64}],
                  'overwrite':False,'ssh_exit_code':0}
        cases=(('completed',0,None),('timed_out',7,'COPY_TIMEOUT'),
               ('transport_failed',6,'SFTP_TRANSPORT_FAILED'),
               ('integrity_failed',6,'COPY_INTEGRITY_MISMATCH'),
               ('file_failed',5,'COPY_FILE_REJECTED'))
        for outcome,code,error in cases:
            lifecycle=MagicMock(); lifecycle.copy.return_value={**common,'outcome':outcome}
            with self.subTest(outcome=outcome), patch(
                    'vm_dev_lab.lifecycle.Lifecycle',return_value=lifecycle):
                result=self.json_call(['copy','host','test:/target','--overwrite'],code)
            self.assertEqual(result['data']['lifecycle']['transfer_id'],common['transfer_id'])
            if error:self.assertEqual(result['error']['code'],error)
            lifecycle.copy.assert_called_once()
        lifecycle=MagicMock(); lifecycle.copy.return_value={
            **common,'direction':'guest-to-host','outcome':'completed'}
        with patch('vm_dev_lab.lifecycle.Lifecycle',return_value=lifecycle):
            self.json_call(['copy','test:/result','host-result'],0)

    def test_copy_dry_run_and_secret_path_parse_errors_are_safe(self):
        result=self.json_call(['--dry-run','copy','PRIVATE_SECRET','test:/target'],2)
        self.assertEqual(result['error']['code'],'OPTION_UNSUPPORTED')
        self.assertNotIn('PRIVATE_SECRET',json.dumps(result))
        for args,code in ((['copy','host-a','host-b'],'COPY_ENDPOINT_INVALID'),
                          (['copy','a:/x','b:/y'],'COPY_ENDPOINT_INVALID'),
                          (['copy','test:/../escape','host'],'COPY_PATH_INVALID')):
            with self.subTest(args=args):
                result=self.json_call(args,2)
                self.assertEqual(result['error']['code'],code)

    def test_destructive_modes_require_confirmation_noninteractively(self):
        for args in (['destroy','test'], ['stop','test','--force'],
                     ['restore','test','a'*64,'--prepare'],
                     ['restore','test','a'*64,'--activate-preparation',
                      '33333333-3333-4333-8333-333333333333'],
                     ['cleanup','test','--baseline-staging','--operation',
                      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                     ['recover','test','--cleanup-failed','--operation',
                      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                     ['recover','test','--restore','--operation',
                      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
                     ['recover','test','--restore-start','--operation',
                      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']):
            result = self.json_call(['--non-interactive',*args], 5)
            self.assertEqual(result['error']['code'], 'CONFIRMATION_REQUIRED')

    def test_text_streams_separate_results_and_errors(self):
        self.profile['ready'] = False
        self.write_profile()
        code, out, err = self.invoke(['config', 'validate', 'test', '--root', str(self.root)])
        self.assertEqual(code, 3)
        self.assertIn('Schema valid', out)
        self.assertNotIn('ERROR', out)
        self.assertIn('CONFIG_INCOMPLETE', err)
        code, out, err = self.invoke(['create', 'test'])
        self.assertEqual((code, out), (2, ''))
        self.assertIn('Operation ID', err)

    def test_all_error_classes_and_interruption_have_stable_codes(self):
        for code in (1, 2, 3, 4, 5, 6, 7, 8, 130):
            error = LabError(code, 'TEST_FAILURE', 'fixture', 'Controlled test failure.', 'Check the test prerequisite.', retryable=code == 4)
            with self.subTest(code=code), patch('vm_dev_lab.cli._dispatch', side_effect=error):
                result = self.json_call(['status', 'test'], code)
                self.assertEqual(result['error']['retryable'], code == 4)
        with patch('vm_dev_lab.cli._dispatch', side_effect=KeyboardInterrupt):
            self.assertEqual(self.json_call(['status', 'test'], 130)['error']['code'], 'INTERRUPTED')
        with patch('vm_dev_lab.cli._dispatch', side_effect=RuntimeError('PRIVATE_SECRET')):
            result = self.json_call(['status', 'test'], 1)
            self.assertNotIn('PRIVATE_SECRET', json.dumps(result))
        self.assertEqual({int(c) for c in ExitCode}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 130})

    def test_missing_dependency_is_a_prerequisite_error(self):
        with patch.dict(sys.modules, {'vm_dev_lab.config': None}):
            result = self.json_call(['config', 'validate', 'test'], 3)
            self.assertEqual(result['error']['code'], 'DEPENDENCY_MISSING')

    def test_no_host_calls_state_writes_images_or_prompts(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() if p.is_file() else None for p in self.root.rglob('*')}
        real_open = __import__('os').open
        def read_only_open(path, flags, *args, **kwargs):
            import os
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            return real_open(path, flags, *args, **kwargs)
        with ExitStack() as stack:
            for target in ('subprocess.run', 'subprocess.Popen', 'socket.socket', 'builtins.input',
                           'os.mkdir', 'os.remove', 'os.rename', 'os.replace', 'os.unlink'):
                stack.enter_context(patch(target, side_effect=AssertionError('No side effects')))
            stack.enter_context(patch('os.open', side_effect=read_only_open))
            self.json_call(['--dry-run', '--non-interactive', 'create', 'test', '--root', str(self.root)], 0)
            self.json_call(['config', 'validate', 'test', '--root', str(self.root)], 0)
        after = {str(p.relative_to(self.root)): p.read_bytes() if p.is_file() else None for p in self.root.rglob('*')}
        self.assertEqual(before, after)
        self.assertFalse((self.root / 'images').exists())

    def test_entrypoint_in_pipe_has_clean_json_and_exit_status(self):
        for args, code in ((['--json', '--non-interactive', '--dry-run', 'create', 'test', '--root', str(self.root)], 0),
                           (['--json', 'create'], 2), (['--json', '--help'], 0)):
            result = subprocess.run([sys.executable, str(ROOT / 'vmctl'), *args], cwd=self.root,
                                    input='', text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, code)
            VALIDATOR.validate(json.loads(result.stdout))
            self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
