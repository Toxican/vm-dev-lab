# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Validate and execute authenticated guest command requests.

"""Versioned argv-safe protocol for non-interactive guest commands."""
import base64
import json
import math
import re
import shlex
from uuid import UUID

from ..errors import LabError


PROTOCOL_VERSION = 1
ADAPTER_VERSION = 'vm-dev-lab-exec-v1'
FRAME_PREFIX = b'VMDEVLAB-EXEC/1 '
REQUEST_LIMIT = 64 * 1024
RESPONSE_LIMIT = 256 * 1024
STREAM_LIMIT = 64 * 1024
MAX_ARGV = 256
MAX_ARGUMENT_BYTES = 16 * 1024
MAX_TIMEOUT = 24 * 60 * 60


def _fail(code, message, exit_code=6):
    raise LabError(exit_code, code, 'exec', message,
                   'Inspect the guest job ID and bound operation diagnostics; do not retry the command automatically.',
                   retryable=exit_code in {6, 7})


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def validate_argv(argv):
    if (not isinstance(argv, list) or not 1 <= len(argv) <= MAX_ARGV
            or any(not isinstance(value, str) or '\0' in value
                   or len(value.encode('utf-8')) > MAX_ARGUMENT_BYTES for value in argv)
            or not argv[0]):
        _fail('EXEC_ARGUMENT_INVALID', 'Guest program or arguments are invalid.', 2)
    return list(argv)


def encode_frame(value, limit):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(raw) > limit:
        _fail('EXEC_PROTOCOL_LIMIT', 'Exec protocol frame exceeds the limit.', 2)
    return FRAME_PREFIX + str(len(raw)).encode('ascii') + b'\n' + raw


def decode_frame(raw, limit):
    if not isinstance(raw, bytes) or len(raw) > limit:
        _fail('EXEC_PROTOCOL_INVALID', 'Exec protocol response is missing or too large.')
    header, separator, payload = raw.partition(b'\n')
    if not separator or not header.startswith(FRAME_PREFIX):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec protocol response has no valid frame.')
    length = header[len(FRAME_PREFIX):]
    if not re.fullmatch(rb'[0-9]{1,9}', length) or int(length) != len(payload):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec protocol length does not match.')
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec protocol response is not valid JSON.')


def request(job_id, argv, timeout, output_limit=STREAM_LIMIT):
    argv = validate_argv(argv)
    if (not _uuid(job_id) or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool) or not math.isfinite(timeout)
            or not 0 < timeout <= MAX_TIMEOUT
            or type(output_limit) is not int or not 1 <= output_limit <= STREAM_LIMIT):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec request has invalid limits.', 2)
    value = {
        'protocol_version': PROTOCOL_VERSION,
        'adapter_version': ADAPTER_VERSION,
        'job_id': job_id,
        'argv': argv,
        'timeout_ms': max(1, int(timeout * 1000)),
        'output_limit': output_limit,
    }
    return encode_frame(value, REQUEST_LIMIT), value


def _stream(value):
    if not isinstance(value, dict) or set(value) != {
            'encoding', 'data', 'bytes_total', 'bytes_captured', 'bytes_returned',
            'truncated', 'redacted'}:
        _fail('EXEC_PROTOCOL_INVALID', 'Exec output contract is incomplete.')
    if (value['encoding'] != 'base64' or type(value['bytes_total']) is not int
            or type(value['bytes_captured']) is not int
            or type(value['bytes_returned']) is not int
            or type(value['truncated']) is not bool
            or type(value['redacted']) is not bool
            or not 0 <= value['bytes_returned'] <= STREAM_LIMIT
            or not 0 <= value['bytes_captured'] <= min(STREAM_LIMIT, value['bytes_total'])
            or value['truncated'] != (value['bytes_total'] > value['bytes_captured'])
            or (not value['redacted'] and value['bytes_returned'] != value['bytes_captured'])):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec output metadata is invalid.')
    try:
        decoded = base64.b64decode(value['data'], validate=True)
    except (ValueError, TypeError):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec output is not valid base64.')
    if len(decoded) != value['bytes_returned']:
        _fail('EXEC_PROTOCOL_INVALID', 'Exec output size does not match.')
    return dict(value)


def response(raw, job_id):
    value = decode_frame(raw, RESPONSE_LIMIT)
    expected = {'protocol_version', 'adapter_version', 'job_id', 'state', 'started',
                'pid', 'pgid', 'guest_exit_code', 'stdout', 'stderr'}
    if (not isinstance(value, dict) or set(value) != expected
            or value['protocol_version'] != PROTOCOL_VERSION
            or value['adapter_version'] != ADAPTER_VERSION
            or value['job_id'] != job_id
            or value['state'] not in {'completed', 'timed_out'}
            or type(value['started']) is not bool):
        _fail('EXEC_PROTOCOL_INVALID', 'Exec response is not bound to the version and job.')
    if value['started']:
        if (type(value['pid']) is not int or value['pid'] <= 0
                or value['pgid'] != value['pid']):
            _fail('EXEC_PROTOCOL_INVALID', 'Exec process-group binding is invalid.')
    elif value['pid'] is not None or value['pgid'] is not None:
        _fail('EXEC_PROTOCOL_INVALID', 'Guest job that was not started reports a process group.')
    code = value['guest_exit_code']
    if value['state'] == 'timed_out':
        if code is not None:
            _fail('EXEC_PROTOCOL_INVALID', 'A timeout must not claim a guest exit code.')
    elif type(code) is not int or not 0 <= code <= 255:
        _fail('EXEC_PROTOCOL_INVALID', 'Guest exit code is invalid.')
    value['stdout'] = _stream(value['stdout'])
    value['stderr'] = _stream(value['stderr'])
    return value


# This source is transferred as a fixed controlled remote command.
# User input appears exclusively in the framed stdin protocol.
ADAPTER_SOURCE = r'''
import base64, json, os, re, selectors, signal, subprocess, sys, time, uuid
PREFIX=b'VMDEVLAB-EXEC/1 '
PROTOCOL=1
ADAPTER='vm-dev-lab-exec-v1'
REQUEST_LIMIT=65536
STREAM_LIMIT=65536
child=None

def frame(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    sys.stdout.buffer.write(PREFIX+str(len(raw)).encode('ascii')+b'\n'+raw)
    sys.stdout.buffer.flush()

def output(data,total):
    raw=bytes(data)
    value=re.sub(rb'-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----',
                 b'[REDACTED PRIVATE KEY]',raw,flags=re.DOTALL|re.IGNORECASE)
    value=re.sub(rb'(?im)\b(password|passwd|token|secret|authorization|private[_-]?key)'
                 rb'(\s*[:=]\s*)([^\s]+)',rb'\1\2[REDACTED]',value)
    value=value[:STREAM_LIMIT]
    return {'encoding':'base64','data':base64.b64encode(value).decode('ascii'),
            'bytes_total':total,'bytes_captured':len(raw),'bytes_returned':len(value),
            'truncated':total>len(raw),'redacted':value!=raw}

def stop_group(sig=signal.SIGTERM):
    global child
    # The group ID remains bound by the group leader that has not yet been waited for,
    # even if it has already exited and a child holds the pipes
    # open. Therefore always address the bound group.
    if child is not None:
        try: os.killpg(child.pid,sig)
        except ProcessLookupError: pass

def interrupted(signum,_frame):
    stop_group(signal.SIGTERM)
    if child is not None and child.poll() is None:
        try: child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            stop_group(signal.SIGKILL); child.wait()
    raise SystemExit(128+signum)

for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
    signal.signal(sig,interrupted)

header=sys.stdin.buffer.readline(64)
if not header.startswith(PREFIX): raise SystemExit(120)
length=header[len(PREFIX):].strip()
if not re.fullmatch(rb'[0-9]{1,9}',length): raise SystemExit(120)
size=int(length)
if size>REQUEST_LIMIT: raise SystemExit(120)
raw=sys.stdin.buffer.read(size)
if len(raw)!=size or sys.stdin.buffer.read(1): raise SystemExit(120)
try: request=json.loads(raw)
except Exception: raise SystemExit(120)
if (set(request)!={'protocol_version','adapter_version','job_id','argv','timeout_ms','output_limit'}
    or request['protocol_version']!=PROTOCOL or request['adapter_version']!=ADAPTER): raise SystemExit(120)
try: uuid.UUID(request['job_id'])
except Exception: raise SystemExit(120)
argv=request['argv']; limit=request['output_limit']; timeout_ms=request['timeout_ms']
if (not isinstance(argv,list) or not 1<=len(argv)<=256 or not argv[0]
    or any(not isinstance(v,str) or '\0' in v or len(v.encode('utf-8'))>16384 for v in argv)
    or type(limit) is not int or not 1<=limit<=STREAM_LIMIT
    or type(timeout_ms) is not int or not 1<=timeout_ms<=86400000): raise SystemExit(120)
stdout=bytearray(); stderr=bytearray(); totals=[0,0]
try:
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           shell=False,start_new_session=True,close_fds=True)
except FileNotFoundError:
    frame({'protocol_version':PROTOCOL,'adapter_version':ADAPTER,'job_id':request['job_id'],
           'state':'completed','started':False,'pid':None,'pgid':None,'guest_exit_code':127,
           'stdout':output(stdout,0),'stderr':output(stderr,0)})
    raise SystemExit(0)
except OSError:
    frame({'protocol_version':PROTOCOL,'adapter_version':ADAPTER,'job_id':request['job_id'],
           'state':'completed','started':False,'pid':None,'pgid':None,'guest_exit_code':126,
           'stdout':output(stdout,0),'stderr':output(stderr,0)})
    raise SystemExit(0)
deadline=time.monotonic()+timeout_ms/1000
timed_out=False
with selectors.DefaultSelector() as selector:
    selector.register(child.stdout,selectors.EVENT_READ,0)
    selector.register(child.stderr,selectors.EVENT_READ,1)
    while selector.get_map():
        remaining=deadline-time.monotonic()
        if remaining<=0:
            timed_out=True
            break
        events=selector.select(remaining)
        if not events:
            timed_out=True
            break
        for key,_ in events:
            chunk=os.read(key.fd,65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            index=key.data; totals[index]+=len(chunk); target=stdout if index==0 else stderr
            target.extend(chunk[:max(0,limit-len(target))])
if timed_out:
    stop_group(signal.SIGTERM)
    try: child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        stop_group(signal.SIGKILL); child.wait()
    code=None; state='timed_out'
else:
    code=child.wait()
    if code<0: code=128+min(127,-code)
    code=min(255,code); state='completed'
frame({'protocol_version':PROTOCOL,'adapter_version':ADAPTER,'job_id':request['job_id'],
       'state':state,'started':True,'pid':child.pid,'pgid':child.pid,'guest_exit_code':code,
       'stdout':output(stdout,totals[0]),'stderr':output(stderr,totals[1])})
'''.strip()


def remote_command():
    """Fixed shell string; intentionally contains no user input."""
    return 'python3 -c ' + shlex.quote(ADAPTER_SOURCE)
