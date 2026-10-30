# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Validate manifests and transfer bounded files through guest SFTP.

"""P11-B: bounded file manifests and a fixed SFTP guest adapter."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from uuid import UUID

from ..errors import LabError
from .exec import decode_frame, encode_frame


PROTOCOL_VERSION = 1
ADAPTER_VERSION = 'vm-dev-lab-files-v1'
REQUEST_LIMIT = 128 * 1024
RESPONSE_LIMIT = 128 * 1024
MAX_FILES = 256
MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_TOTAL_SIZE = 64 * 1024 * 1024
MAX_PATH_BYTES = 512
MAX_DEPTH = 16
WORKSPACE = '.local/share/vm-dev-lab/workspace'
TRANSFERS = '.local/share/vm-dev-lab/transfers'
FORBIDDEN_NAMES = {
    '.env', '.git', '.ssh', '.cache', '.venv', '__pycache__', '.pytest_cache',
    '.vm-dev-lab', 'local', 'registry.json', 'instance.json',
    'guest-manifest.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa',
    '.aws', '.gnupg', '.npmrc', '.pypirc', 'credentials', 'credentials.json',
    'secrets', 'secrets.json',
}
FORBIDDEN_SUFFIXES = {'.qcow2', '.img', '.iso', '.fd', '.pem', '.key', '.p12', '.pfx'}


def _fail(code, message, status=5):
    raise LabError(status, code, 'copy', message,
                   'Inspect the transfer ID and bound operation diagnostics; do not retry automatically.')


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def guest_path(value):
    """Interpret VM:/path relative to the fixed workspace."""
    if not isinstance(value, str) or '\0' in value or any(ord(c) < 32 for c in value):
        _fail('COPY_PATH_INVALID', 'Guest path is invalid.', 2)
    value = value[1:] if value.startswith('/') else value
    path = PurePosixPath(value)
    parts = path.parts
    if (not parts or any(part in {'', '.', '..'} for part in parts)
            or len(parts) > MAX_DEPTH or len(value.encode('utf-8')) > MAX_PATH_BYTES):
        _fail('COPY_PATH_INVALID', 'Guest path leaves the managed workspace.', 2)
    for part in parts:
        if len(part.encode('utf-8')) > 255 or forbidden(part):
            _fail('COPY_PATH_FORBIDDEN', 'Guest path contains a forbidden name.', 5)
    return '/'.join(parts)


def forbidden(name):
    lower = name.lower()
    return lower in FORBIDDEN_NAMES or any(lower.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def endpoint(value):
    match = re.fullmatch(
        r'([a-z][a-z0-9-]{0,62}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}):(/.*)',
        value or '')
    return (match.group(1), guest_path(match.group(2))) if match else None


def endpoints(source, destination):
    left, right = endpoint(source), endpoint(destination)
    if (left is None) == (right is None):
        _fail('COPY_ENDPOINT_INVALID', 'Exactly one endpoint must be VM:/path.', 2)
    if left:
        return {'direction': 'guest-to-host', 'vm': left[0], 'guest_path': left[1],
                'host_path': destination}
    return {'direction': 'host-to-guest', 'vm': right[0], 'guest_path': right[1],
            'host_path': source}


def _entry(relative, info, digest):
    return {'path': relative, 'size': info.st_size, 'sha256': digest}


class HostSource:
    """Opened host source; SFTP reads only through inherited /proc/self/fd aliases."""
    def __init__(self, root, kind, entries, handles, directory_identity, git, staging):
        self.root, self.kind, self.entries = root, kind, entries
        self.handles, self.directory_identity = handles, directory_identity
        self.git = git
        self.staging = staging

    def close(self):
        for handle in self.handles:
            handle.close()
        self.staging.cleanup()

    def verify(self):
        info = os.lstat(self.root)
        if (info.st_dev, info.st_ino) != self.directory_identity:
            _fail('COPY_SOURCE_CHANGED', 'Host source was replaced.', 5)
        for entry, handle in zip(self.entries, self.handles):
            info = os.fstat(handle.fileno())
            if (info.st_dev != entry['device'] or info.st_ino != entry['inode']
                    or info.st_size != entry['size'] or info.st_nlink != 1):
                _fail('COPY_SOURCE_CHANGED', 'Host source file was replaced.', 5)
            os.lseek(handle.fileno(), 0, os.SEEK_SET); digest = hashlib.sha256()
            while True:
                chunk = os.read(handle.fileno(), 1024 * 1024)
                if not chunk: break
                digest.update(chunk)
            os.lseek(handle.fileno(), 0, os.SEEK_SET)
            if digest.hexdigest() != entry['sha256']:
                _fail('COPY_SOURCE_CHANGED', 'Host source file changed during transfer.', 5)

    def public_manifest(self):
        return [{key: entry[key] for key in ('path', 'size', 'sha256')}
                for entry in self.entries]


def scan_host_source(value):
    path = Path(value).absolute()
    if forbidden(path.name):
        _fail('COPY_PATH_FORBIDDEN', 'Host source is a blocked project or secret path.', 5)
    try:
        root_info = os.lstat(path)
    except OSError:
        _fail('COPY_SOURCE_INVALID', 'Host source is unreadable.', 4)
    if stat.S_ISLNK(root_info.st_mode):
        _fail('COPY_SOURCE_INVALID', 'Symlinks are not valid transfer sources.', 5)
    kind = 'file' if stat.S_ISREG(root_info.st_mode) else 'directory' if stat.S_ISDIR(root_info.st_mode) else None
    if kind is None or (kind == 'file' and root_info.st_nlink != 1):
        _fail('COPY_SOURCE_INVALID', 'Only regular files and directories without hard links are allowed.', 5)
    candidates = [(path, path.name)] if kind == 'file' else []
    if kind == 'directory':
        for current, directories, files in os.walk(path, topdown=True, followlinks=False):
            directories.sort(); files.sort()
            # Repository metadata is never transferred; commit and dirty state
            # is collected separately and with bounds.
            directories[:] = [name for name in directories if name != '.git']
            relative_dir = Path(current).relative_to(path)
            depth = len(relative_dir.parts)
            if depth >= MAX_DEPTH and directories:
                _fail('COPY_PATH_LIMIT', 'Host source tree is too deep.', 5)
            for name in directories:
                child = Path(current) / name
                info = os.lstat(child)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or forbidden(name):
                    _fail('COPY_SOURCE_INVALID', 'Host source tree contains blocked or non-regular entries.', 5)
            for name in files:
                relative = str((relative_dir / name).as_posix())
                candidates.append((Path(current) / name, relative))
    if not candidates or len(candidates) > MAX_FILES:
        _fail('COPY_FILE_LIMIT', 'File count is outside the transfer limit.', 5)
    handles, entries, total = [], [], 0
    staging = tempfile.TemporaryDirectory(prefix='vm-dev-lab-copy-', dir='/tmp')
    try:
        for index, (candidate, relative) in enumerate(candidates):
            parts = PurePosixPath(relative).parts
            if (len(parts) > MAX_DEPTH or len(relative.encode('utf-8')) > MAX_PATH_BYTES
                    or any(forbidden(part) for part in parts)):
                _fail('COPY_PATH_FORBIDDEN', 'Host source contains blocked names or paths.', 5)
            guest_path('/' + relative)
            try:
                fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                _fail('COPY_SOURCE_INVALID', 'Host source was replaced or is not a regular file.', 5)
            handle = os.fdopen(fd, 'rb', closefd=True); handles.append(handle)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_size > MAX_FILE_SIZE):
                _fail('COPY_FILE_LIMIT', 'Host source contains no allowed regular file.', 5)
            digest = hashlib.sha256()
            probe = bytearray()
            staged = os.open(Path(staging.name)/f'{index:08d}',
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(staged, 'wb') as staged_file:
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk: break
                    digest.update(chunk)
                    if len(probe) < 65536: probe.extend(chunk[:65536-len(probe)])
                    staged_file.write(chunk)
                staged_file.flush(); os.fsync(staged_file.fileno())
            if re.search(rb'-----BEGIN [^-\r\n]{0,64}PRIVATE KEY-----', probe,
                         flags=re.IGNORECASE):
                _fail('COPY_SECRET_FORBIDDEN', 'Host source contains private key material.', 5)
            os.lseek(fd, 0, os.SEEK_SET)
            total += info.st_size
            if total > MAX_TOTAL_SIZE:
                _fail('COPY_TOTAL_LIMIT', 'Total transfer is too large.', 5)
            entries.append({**_entry(relative, info, digest.hexdigest()),
                            'device': info.st_dev, 'inode': info.st_ino})
        return HostSource(path, kind, entries, handles,
                          (root_info.st_dev, root_info.st_ino), git_metadata(path), staging)
    except BaseException:
        for handle in handles: handle.close()
        staging.cleanup()
        raise


def git_metadata(path):
    directory = path if path.is_dir() else path.parent
    def run(*arguments):
        try:
            result = subprocess.run(['git', '-C', str(directory), *arguments],
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout if result.returncode == 0 and len(result.stdout) <= 65536 else None
    root = run('rev-parse', '--show-toplevel')
    commit = run('rev-parse', 'HEAD')
    status = run('status', '--porcelain', '--untracked-files=normal')
    if root is None or commit is None or status is None:
        return None
    try:
        repository = Path(root.decode().strip()).resolve()
        if repository not in (path.resolve(), *path.resolve().parents):
            return None
        value = commit.decode().strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        return None
    return {'commit': value, 'dirty': bool(status.strip())}


def manifest_digest(kind, manifest):
    raw = json.dumps({'kind': kind, 'files': manifest}, sort_keys=True,
                     separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(raw) > RESPONSE_LIMIT:
        _fail('COPY_MANIFEST_LIMIT', 'Transfer manifest is too large.', 5)
    return hashlib.sha256(raw).hexdigest()


def request(action, transfer_id, path, *, kind=None, files=None, overwrite=False):
    if action not in {'prepare-upload', 'finalize-upload', 'prepare-download', 'cleanup'} or not _uuid(transfer_id):
        _fail('COPY_PROTOCOL_INVALID', 'File-adapter request is invalid.', 2)
    if action in {'prepare-upload', 'finalize-upload'}:
        validate_manifest(kind, files)
    elif kind is not None or files is not None:
        _fail('COPY_PROTOCOL_INVALID', 'File adapter request contains unexpected manifest data.', 2)
    value = {'protocol_version': PROTOCOL_VERSION, 'adapter_version': ADAPTER_VERSION,
             'action': action, 'transfer_id': transfer_id, 'path': guest_path(path),
             'kind': kind, 'files': files, 'overwrite': bool(overwrite)}
    return encode_frame(value, REQUEST_LIMIT)


def response(raw, transfer_id, action):
    value = decode_frame(raw, RESPONSE_LIMIT)
    required = {'protocol_version', 'adapter_version', 'action', 'transfer_id',
                'ok', 'code', 'kind', 'files'}
    if (not isinstance(value, dict) or set(value) != required
            or value['protocol_version'] != PROTOCOL_VERSION
            or value['adapter_version'] != ADAPTER_VERSION or value['action'] != action
            or value['transfer_id'] != transfer_id or type(value['ok']) is not bool
            or (value['code'] is not None and not isinstance(value['code'], str))):
        _fail('COPY_PROTOCOL_INVALID', 'File-adapter response is not bound.', 6)
    if value['ok'] and action == 'cleanup':
        if value['kind'] is not None or value['files'] is not None:
            _fail('COPY_PROTOCOL_INVALID', 'Cleanup response claims a transfer manifest.', 6)
    elif value['ok']:
        validate_manifest(value['kind'], value['files'])
    elif value['kind'] is not None or value['files'] is not None:
        _fail('COPY_PROTOCOL_INVALID', 'Error response claims a transfer manifest.', 6)
    return value


def validate_manifest(kind, files):
    if kind not in {'file', 'directory'} or not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        _fail('COPY_MANIFEST_INVALID', 'Transfer manifest is invalid.', 6)
    total = 0; names = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {'path', 'size', 'sha256'}:
            _fail('COPY_MANIFEST_INVALID', 'Transfer manifest is incomplete.', 6)
        path = guest_path('/' + item['path'])
        if (path in names or type(item['size']) is not int or not 0 <= item['size'] <= MAX_FILE_SIZE
                or not isinstance(item['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            _fail('COPY_MANIFEST_INVALID', 'Transfer manifest contains invalid files.', 6)
        names.add(path); total += item['size']
    if total > MAX_TOTAL_SIZE:
        _fail('COPY_TOTAL_LIMIT', 'Transfer manifest exceeds the total limit.', 6)
    return files


def upload_batch(transfer_id, source):
    base = f'{TRANSFERS}/{transfer_id}/incoming'
    lines = [f'put {source.staging.name}/{index:08d} {base}/{index:08d}'
             for index in range(len(source.handles))]
    return ('\n'.join(lines) + '\n').encode('ascii')


def download_batch(transfer_id, files, staging):
    base = f'{TRANSFERS}/{transfer_id}/outgoing'
    lines = [f'get {base}/{index:08d} {staging}/{index:08d}'
             for index in range(len(files))]
    return ('\n'.join(lines) + '\n').encode('ascii')


class HostDestination:
    """Operation-bound host staging with atomic publication."""
    def __init__(self, value, transfer_id, overwrite):
        if not _uuid(transfer_id):
            _fail('COPY_PROTOCOL_INVALID', 'Transfer ID is invalid.', 2)
        self.path = Path(value).absolute()
        self.parent = self.path.parent
        self.transfer_id, self.overwrite = transfer_id, overwrite
        self.staging = None; self.parent_fd = None; self.target_identity = None
        if any(forbidden(part) for part in self.path.parts):
            _fail('COPY_DESTINATION_FORBIDDEN', 'Host target is blocked as a private or internal path.', 5)
        try:
            info = os.lstat(self.parent)
        except OSError:
            _fail('COPY_DESTINATION_INVALID', 'Host target directory is missing.', 4)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or self.parent.resolve() != self.parent):
            _fail('COPY_DESTINATION_INVALID', 'Host target directory is not bound safely.', 5)
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.staging = tempfile.mkdtemp(prefix=f'vm-dev-lab-{transfer_id}-', dir='/tmp')
        except OSError:
            self.close()
            _fail('COPY_DESTINATION_INVALID', 'Private host staging could not be created.', 6)
        if os.path.lexists(self.path):
            target = os.lstat(self.path)
            self.target_identity = (target.st_dev, target.st_ino)
            if (stat.S_ISLNK(target.st_mode) or target.st_uid != os.geteuid()
                    or not (stat.S_ISREG(target.st_mode) or stat.S_ISDIR(target.st_mode))
                    or (stat.S_ISREG(target.st_mode) and target.st_nlink != 1)
                    or not overwrite):
                self.close()
                _fail('COPY_TARGET_EXISTS', 'Host target exists; --overwrite is absent or the target is a symlink.', 4)
            if stat.S_ISDIR(target.st_mode):
                for current, directories, files in os.walk(self.path, followlinks=False):
                    for name in [*directories, *files]:
                        info = os.lstat(Path(current)/name)
                        if (forbidden(name) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
                                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                            self.close()
                            _fail('COPY_TARGET_EXISTS', 'Existing host target contains unsafe entries.', 5)

    def close(self):
        if getattr(self, 'parent_fd', None) is not None:
            os.close(self.parent_fd); self.parent_fd = None
        if self.staging is not None:
            shutil.rmtree(self.staging, ignore_errors=True); self.staging = None

    def _staged(self, index):
        return Path(self.staging) / f'{index:08d}'

    def cleanup(self, count):
        for index in range(count):
            try: self._staged(index).unlink()
            except FileNotFoundError: pass

    def finalize(self, kind, files):
        validate_manifest(kind, files)
        publish = self.parent / f'.vm-dev-lab-publish-{self.transfer_id}'
        backup = self.parent / f'.vm-dev-lab-replaced-{self.transfer_id}'
        if os.path.lexists(publish) or os.path.lexists(backup):
            _fail('COPY_DESTINATION_INVALID', 'Operation-bound host staging already exists.', 4)
        try:
            if kind == 'directory':
                publish.mkdir(mode=0o700)
            for index, item in enumerate(files):
                staged = self._staged(index)
                info = os.lstat(staged)
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != os.geteuid() or info.st_nlink != 1
                        or info.st_size != item['size']):
                    _fail('COPY_INTEGRITY_MISMATCH', 'Received host-staging file is invalid.', 6)
                digest = hashlib.sha256(staged.read_bytes()).hexdigest()
                if digest != item['sha256']:
                    _fail('COPY_INTEGRITY_MISMATCH', 'Received file has an incorrect SHA256.', 6)
                destination = publish / item['path'] if kind == 'directory' else publish
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(staged, destination); os.chmod(destination, 0o600)
                staged.unlink()
            replaced = False
            if os.path.lexists(self.path):
                current = os.lstat(self.path)
                if (self.target_identity is None
                        or (current.st_dev, current.st_ino) != self.target_identity
                        or stat.S_ISLNK(current.st_mode) or not self.overwrite):
                    _fail('COPY_TARGET_EXISTS', 'Host target was created concurrently.', 4)
            elif self.target_identity is not None:
                _fail('COPY_TARGET_EXISTS', 'Existing host target was removed concurrently.', 4)
            if os.path.lexists(self.path):
                os.rename(self.path, backup)
                replaced = True
            try:
                os.rename(publish, self.path)
            except BaseException:
                if replaced and not os.path.lexists(self.path): os.rename(backup, self.path)
                raise
            if backup.exists():
                if backup.is_dir(): shutil.rmtree(backup)
                else: backup.unlink()
        except BaseException:
            if publish.exists():
                if publish.is_dir(): shutil.rmtree(publish)
                else: publish.unlink()
            raise


def remote_command():
    return 'python3 -c ' + shlex.quote(ADAPTER_SOURCE)


# The adapter receives only validated JSON. SFTP itself sees only
# the fixed ASCII staging paths TRANSFERS/<UUID>/{incoming,outgoing}/NNNNNNNN.
ADAPTER_SOURCE = r'''
import hashlib,json,os,pathlib,pwd,re,shutil,stat,sys,uuid
PREFIX=b'VMDEVLAB-EXEC/1 '; PROTOCOL=1; ADAPTER='vm-dev-lab-files-v1'
MAX_FILES=256; MAX_FILE=16777216; MAX_TOTAL=67108864; MAX_PATH=512; MAX_DEPTH=16
FORBIDDEN={'.env','.git','.ssh','.cache','.venv','__pycache__','.pytest_cache','.vm-dev-lab','local','registry.json','instance.json','guest-manifest.json','id_rsa','id_ed25519','id_ecdsa','id_dsa','.aws','.gnupg','.npmrc','.pypirc','credentials','credentials.json','secrets','secrets.json'}
SUFFIXES={'.qcow2','.img','.iso','.fd','.pem','.key','.p12','.pfx'}
def frame(value):
 raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
 sys.stdout.buffer.write(PREFIX+str(len(raw)).encode()+b'\n'+raw);sys.stdout.buffer.flush()
def reply(action,tid,ok,code=None,kind=None,files=None):
 frame({'protocol_version':PROTOCOL,'adapter_version':ADAPTER,'action':action,'transfer_id':tid,'ok':ok,'code':code,'kind':kind,'files':files})
def badname(name):
 low=name.lower();return low in FORBIDDEN or any(low.endswith(x) for x in SUFFIXES)
def rel(value):
 if not isinstance(value,str) or '\0' in value or any(ord(c)<32 for c in value): raise ValueError
 value=value[1:] if value.startswith('/') else value;p=pathlib.PurePosixPath(value)
 if not p.parts or len(p.parts)>MAX_DEPTH or len(value.encode())>MAX_PATH or any(x in {'','.','..'} or badname(x) or len(x.encode())>255 for x in p.parts): raise ValueError
 return pathlib.Path(*p.parts)
def safe_dir(path,create=False):
 if create:path.mkdir(mode=0o700,parents=True,exist_ok=True)
 info=path.lstat()
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError
 return path
def chain(root,parts):
 current=safe_dir(root)
 for part in parts:
  current=safe_dir(current/part,True)
 return current
def digest(path):
 h=hashlib.sha256();total=0;probe=bytearray()
 with path.open('rb') as f:
  while True:
   b=f.read(1048576)
   if not b:break
   total+=len(b)
   if total>MAX_FILE:raise ValueError
   h.update(b)
   if len(probe)<65536:probe.extend(b[:65536-len(probe)])
 if re.search(rb'-----BEGIN [^-\r\n]{0,64}PRIVATE KEY-----',probe,flags=re.IGNORECASE):raise ValueError
 return total,h.hexdigest()
def valid_file(path):
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:raise ValueError
 return digest(path)
def safe_tree(path):
 if path.is_dir():
  for item in path.rglob('*'):
   info=item.lstat()
   if badname(item.name) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink!=1):raise ValueError
def target_state(workspace,target):
 current=workspace
 for part in target.parts[:-1]:
  candidate=current/part
  if not candidate.exists():return {'exists':False,'device':None,'inode':None}
  current=safe_dir(candidate)
 final=current/target.name
 if not os.path.lexists(final):return {'exists':False,'device':None,'inode':None}
 info=final.lstat()
 if stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink!=1):raise ValueError
 safe_tree(final)
 return {'exists':True,'device':info.st_dev,'inode':info.st_ino}
def validate(files):
 if not isinstance(files,list) or not 1<=len(files)<=MAX_FILES:raise ValueError
 total=0;seen=set()
 for x in files:
  if not isinstance(x,dict) or set(x)!={'path','size','sha256'}:raise ValueError
  p=rel(x['path'])
  if str(p) in seen or type(x['size']) is not int or not 0<=x['size']<=MAX_FILE or not isinstance(x['sha256'],str) or len(x['sha256'])!=64:raise ValueError
  int(x['sha256'],16);seen.add(str(p));total+=x['size']
 if total>MAX_TOTAL:raise ValueError
 if len(json.dumps(files,separators=(',',':'),ensure_ascii=True).encode('ascii'))>120000:raise ValueError
 return files
header=sys.stdin.buffer.readline(64);length=header[len(PREFIX):].strip() if header.startswith(PREFIX) else b''
if not length.isdigit() or int(length)>131072:raise SystemExit(120)
raw=sys.stdin.buffer.read(int(length))
try:
 r=json.loads(raw)
 if set(r)!={'protocol_version','adapter_version','action','transfer_id','path','kind','files','overwrite'} or r['protocol_version']!=PROTOCOL or r['adapter_version']!=ADAPTER or r['action'] not in {'prepare-upload','finalize-upload','prepare-download','cleanup'} or type(r['overwrite']) is not bool:raise ValueError
 action=r['action'];tid=r['transfer_id']
 if str(uuid.UUID(tid))!=tid:raise ValueError
 target=rel(r['path'])
 if action in {'prepare-upload','finalize-upload'}:
  if r['kind'] not in {'file','directory'}:raise ValueError
 else:
  if r['kind'] is not None or r['files'] is not None:raise ValueError
except Exception:raise SystemExit(120)
try:
 home=pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir);safe_dir(home)
 base=chain(home,('.local','share','vm-dev-lab'));workspace=chain(base,('workspace',));transfers=chain(base,('transfers',));transfer=transfers/tid
 if action=='prepare-upload':
  files=validate(r['files'])
  if transfer.exists():raise FileExistsError
  safe_dir(transfer/'incoming',True);binding=target_state(workspace,target)
  if binding['exists'] and not r['overwrite']:raise FileExistsError
  (transfer/'binding.json').write_text(json.dumps(binding,separators=(',',':')));os.chmod(transfer/'binding.json',0o600)
  reply(action,tid,True,kind=r['kind'],files=files)
 elif action=='finalize-upload':
  files=validate(r['files']);incoming=safe_dir(transfer/'incoming');publish=transfer/'publish'
  if publish.exists():raise FileExistsError
  if r['kind']=='directory':safe_dir(publish,True)
  for i,item in enumerate(files):
   source=incoming/f'{i:08d}';size,sha=valid_file(source)
   if size!=item['size'] or sha!=item['sha256']:raise ArithmeticError
   destination=(publish/rel(item['path'])) if r['kind']=='directory' else publish
   destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   shutil.copyfile(source,destination);os.chmod(destination,0o600)
   if valid_file(destination)!=(size,sha):raise ArithmeticError
  binding=json.loads((transfer/'binding.json').read_text());current=target_state(workspace,target)
  if current!=binding:raise FileExistsError
  parent=workspace
  for part in target.parts[:-1]:parent=safe_dir(parent/part,True)
  final=parent/target.name;backup=transfer/'replaced'
  replaced=False
  if final.exists() or final.is_symlink():
   if not r['overwrite'] or final.is_symlink():raise FileExistsError
   os.rename(final,backup);replaced=True
  try:os.rename(publish,final)
  except BaseException:
   if replaced and not final.exists():os.rename(backup,final)
   raise
  reply(action,tid,True,kind=r['kind'],files=files)
 elif action=='prepare-download':
  source=workspace
  for part in target.parts[:-1]:source=safe_dir(source/part)
  source=source/target.name
  if source.is_symlink() or not source.exists():raise ValueError
  kind='file' if source.is_file() else 'directory' if source.is_dir() else None
  if kind is None:raise ValueError
  entries=[source] if kind=='file' else sorted(source.rglob('*'))
  if kind=='directory':
   for p in entries:
    if p.is_symlink() or not (p.is_file() or p.is_dir()):raise ValueError
  paths=[source] if kind=='file' else [p for p in entries if p.is_file()]
  if not paths or len(paths)>MAX_FILES:raise ValueError
  files=[];out=safe_dir(transfer/'outgoing',True) if not transfer.exists() else None
  for i,p in enumerate(paths):
   relative=p.name if kind=='file' else p.relative_to(source).as_posix();rel(relative)
   size,sha=valid_file(p);files.append({'path':relative,'size':size,'sha256':sha})
   shutil.copyfile(p,out/f'{i:08d}');os.chmod(out/f'{i:08d}',0o600)
  validate(files);reply(action,tid,True,kind=kind,files=files)
 elif action=='cleanup':
  safe_dir(transfer);shutil.rmtree(transfer);reply(action,tid,True)
 else:raise ValueError
except FileExistsError:reply(action,tid,False,'COPY_TARGET_EXISTS')
except ArithmeticError:reply(action,tid,False,'COPY_INTEGRITY_MISMATCH')
except OSError as e:reply(action,tid,False,'COPY_NO_SPACE' if getattr(e,'errno',None)==28 else 'COPY_GUEST_FILE_ERROR')
except Exception:reply(action,tid,False,'COPY_GUEST_FILE_ERROR')
'''.strip()
