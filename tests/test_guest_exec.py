# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test authenticated guest command protocol and output limits.

"""P11-A: self-contained guest adapter and bounded host process, offline only."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from vm_dev_lab.errors import LabError
from vm_dev_lab.guest.exec import (ADAPTER_SOURCE, ADAPTER_VERSION, PROTOCOL_VERSION,
                                   RESPONSE_LIMIT, decode_frame, encode_frame,
                                   remote_command, request, response)
from vm_dev_lab.process import exchange


class GuestExecProtocolTests(unittest.TestCase):
    def adapter(self, argv, *, timeout=2, limit=65536):
        job = str(uuid4())
        frame, value = request(job, argv, timeout, limit)
        process = subprocess.run([sys.executable, '-c', ADAPTER_SOURCE], input=frame,
                                 capture_output=True, timeout=5)
        self.assertEqual((process.returncode, process.stderr), (0, b''))
        return value, response(process.stdout, job)

    def test_arguments_are_exact_and_never_enter_remote_command(self):
        marker = 'HOST_INJECTION_MARKER;$(false)'
        argv = [sys.executable, '-c', 'import json,sys;print(json.dumps(sys.argv[1:]))',
                'space value', "quote'\"", 'Gruesse-ä', '', '-leading', marker]
        request_value, result = self.adapter(argv)
        self.assertEqual(request_value['argv'], argv)
        decoded = base64.b64decode(result['stdout']['data']).decode().strip()
        self.assertEqual(json.loads(decoded), argv[3:])
        self.assertNotIn(marker, remote_command())
        self.assertNotIn('sudo', remote_command())
        self.assertNotIn('systemd-run', remote_command())
        self.assertEqual(set(request_value), {
            'protocol_version', 'adapter_version', 'job_id', 'argv',
            'timeout_ms', 'output_limit'})
        self.assertTrue(result['started'])
        self.assertEqual(result['pid'], result['pgid'])

    def test_guest_exitcodes_including_255_are_protocol_data(self):
        for code in (0, 1, 8, 127, 255):
            with self.subTest(code=code):
                _, result = self.adapter([sys.executable, '-c', f'raise SystemExit({code})'])
                self.assertEqual(result['guest_exit_code'], code)
                self.assertEqual(result['state'], 'completed')

    def test_missing_program_is_guest_127_without_process_group(self):
        _, result = self.adapter(['/definitely/missing/vm-dev-lab-command'])
        self.assertEqual(result['guest_exit_code'], 127)
        self.assertFalse(result['started'])
        self.assertIsNone(result['pid'])

    def test_binary_outputs_are_separate_bounded_and_marked_truncated(self):
        code = ('import os; os.write(1, bytes(range(256))*4); '
                'os.write(2, b"stderr\\x00"*100)')
        _, result = self.adapter([sys.executable, '-c', code], limit=32)
        self.assertEqual(result['stdout']['bytes_returned'], 32)
        self.assertEqual(result['stderr']['bytes_returned'], 32)
        self.assertTrue(result['stdout']['truncated'])
        self.assertTrue(result['stderr']['truncated'])
        self.assertEqual(len(base64.b64decode(result['stdout']['data'])), 32)

    def test_guest_timeout_has_job_and_process_group_but_no_exitcode(self):
        _, result = self.adapter([sys.executable, '-c', 'import time; time.sleep(2)'],
                                 timeout=.02)
        self.assertEqual(result['state'], 'timed_out')
        self.assertTrue(result['started'])
        self.assertIsNone(result['guest_exit_code'])
        self.assertEqual(result['pid'], result['pgid'])

    def test_wrong_version_job_frame_and_output_contract_are_rejected(self):
        job = str(uuid4())
        stream = {'encoding':'base64','data':'','bytes_total':0,'bytes_captured':0,
                  'bytes_returned':0,'truncated':False,'redacted':False}
        valid = {'protocol_version':PROTOCOL_VERSION,'adapter_version':ADAPTER_VERSION,
                 'job_id':job,'state':'completed','started':False,'pid':None,'pgid':None,
                 'guest_exit_code':127,'stdout':stream,'stderr':stream}
        cases = []
        for change in ({'protocol_version':2}, {'job_id':str(uuid4())},
                       {'adapter_version':'other'}):
            value = {**valid, **change}; cases.append(encode_frame(value, RESPONSE_LIMIT))
        cases.extend((b'garbage', encode_frame({**valid, 'stdout':{}}, RESPONSE_LIMIT)))
        for raw in cases:
            with self.subTest(raw=raw[:30]), self.assertRaises(LabError) as caught:
                response(raw, job)
            self.assertEqual(caught.exception.detail['code'], 'EXEC_PROTOCOL_INVALID')

    def test_request_rejects_empty_program_nul_oversize_and_bad_job(self):
        bad = ([], [''], ['x\0y'], ['x' * 16385])
        for argv in bad:
            with self.subTest(argv=argv[:1]), self.assertRaises(LabError):
                request(str(uuid4()), argv, 1)
        with self.assertRaises(LabError):
            request('not-a-job', ['true'], 1)

    def test_private_keys_and_common_credentials_are_redacted(self):
        code = ('print("-----BEGIN OPENSSH PRIVATE KEY-----\\nprivate\\n"'
                '+"-----END OPENSSH PRIVATE KEY-----")\nprint("token=hunter2")')
        _, result = self.adapter([sys.executable, '-c', code])
        output = base64.b64decode(result['stdout']['data'])
        self.assertTrue(result['stdout']['redacted'])
        self.assertNotIn(b'private\n', output)
        self.assertNotIn(b'hunter2', output)

    def test_redaction_expansion_remains_inside_stream_limit(self):
        code = 'print("token=x "*20000)'
        _, result = self.adapter([sys.executable, '-c', code])
        self.assertLessEqual(result['stdout']['bytes_returned'], 65536)
        self.assertTrue(result['stdout']['redacted'])
        self.assertNotIn(b'token=x', base64.b64decode(result['stdout']['data']))

    def test_host_exchange_separates_streams_timeout_and_output_limit(self):
        result = exchange(
            [sys.executable, '-c',
             'import os,sys; data=sys.stdin.buffer.read(); os.write(1,data); os.write(2,b"err")'],
            b'input', timeout=2, limit=64)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'input', b'err'))
        timeout = exchange([sys.executable, '-c', 'import time;time.sleep(2)'],
                           b'', timeout=.02, limit=64)
        self.assertTrue(timeout.timed_out)
        limited = exchange([sys.executable, '-c', 'print("x"*1000)'],
                           b'', timeout=2, limit=32)
        self.assertTrue(limited.output_limited)


if __name__ == '__main__':
    unittest.main()
