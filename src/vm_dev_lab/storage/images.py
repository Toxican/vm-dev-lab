# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Verify and import local signed images into an immutable cache.

"""Explicit import of local signed images; no download or lifecycle."""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
from urllib.parse import urlsplit
from uuid import uuid4

from ..errors import LabError
from ..process import run
from ..state import directory, private_file


def reject(code, message, status=5):
    raise LabError(status, code, 'image-verification', message,
                   'Inspect trust anchor, signature, and artifact; do not force approval or cache repair.')


@dataclass(frozen=True)
class ImageSpec:
    publisher: str
    version: str
    filename: str
    source_url: str
    sha256: str
    size_bytes: int
    max_virtual_bytes: int

    def __post_init__(self):
        if (not all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', v)
                    for v in (self.publisher, self.version, self.filename))
                or self.version.lower() in {'latest', 'current'}
                or not isinstance(self.sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.sha256)
                or type(self.size_bytes) is not int or not 104 <= self.size_bytes <= 64 * 1024 ** 3
                or type(self.max_virtual_bytes) is not int or not 1 <= self.max_virtual_bytes <= 16 * 1024 ** 4):
            reject('IMAGE_SPEC_INVALID', 'Invalid or unpinned image description.', 2)
        url = urlsplit(self.source_url)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment
                or url.path.rsplit('/', 1)[-1] != self.filename):
            reject('IMAGE_SPEC_INVALID', 'Specify an HTTPS origin and versioned file name.', 2)


@dataclass(frozen=True)
class TrustPolicy:
    publisher: str
    primary_fingerprints: tuple
    keyring_sha256: str
    approval_reference: str

    def __post_init__(self):
        if (not isinstance(self.approval_reference, str) or not 1 <= len(self.approval_reference) <= 1024
                or not isinstance(self.publisher, str) or not self.publisher
                or not isinstance(self.primary_fingerprints, (tuple, list)) or not self.primary_fingerprints
                or any(not isinstance(f, str) or not re.fullmatch(r'[0-9A-F]{40}|[0-9A-F]{64}', f) for f in self.primary_fingerprints)
                or not isinstance(self.keyring_sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.keyring_sha256)):
            reject('TRUST_ANCHOR_MISSING', 'Explicit publisher or key trust anchor is missing.')
        object.__setattr__(self, 'primary_fingerprints', tuple(self.primary_fingerprints))


@contextmanager
def input_file(path):
    """Open a regular file without symlinks in any path component."""
    path = Path(path).absolute()
    if '..' in path.parts: reject('IMAGE_PATH_UNSAFE', 'Path traversal is not allowed.')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2: flags |= os.O_DIRECTORY
            new = os.open(part, flags, dir_fd=fd); os.close(fd); fd = new
        if not stat.S_ISREG(os.fstat(fd).st_mode): reject('IMAGE_PATH_UNSAFE', 'Only regular source files are allowed.')
        yield fd
    except OSError:
        reject('IMAGE_PATH_UNSAFE', 'File is missing, unsafe, or unreadable.')
    finally:
        os.close(fd)


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while data := os.read(fd, 1024 * 1024): h.update(data)
    os.lseek(fd, 0, os.SEEK_SET)
    return h.hexdigest()


def header(fd, spec):
    raw = os.pread(fd, 104, 0)
    if len(raw) < 104 or raw[:4] != b'QFI\xfb': reject('IMAGE_FORMAT_UNSAFE', 'No supported qcow2 header.')
    version = struct.unpack_from('>I', raw, 4)[0]
    backing, backing_size = struct.unpack_from('>QI', raw, 8)
    cluster_bits = struct.unpack_from('>I', raw, 20)[0]
    virtual = struct.unpack_from('>Q', raw, 24)[0]
    crypt = struct.unpack_from('>I', raw, 32)[0]
    if version not in (2, 3) or backing or backing_size or crypt or not 9 <= cluster_bits <= 21 or not 0 < virtual <= spec.max_virtual_bytes:
        reject('IMAGE_FORMAT_UNSAFE', 'Backing, encryption, size, or header is not allowed.')
    if version == 3 and (struct.unpack_from('>Q', raw, 72)[0] != 0
                         or not 104 <= struct.unpack_from('>I', raw, 100)[0] <= min(1 << cluster_bits, spec.size_bytes)):
        reject('IMAGE_FORMAT_UNSAFE', 'External data or unknown or unsafe qcow2 features were rejected.')
    return virtual


def signature_status(returncode, output, policy):
    try: lines = output.decode('utf-8').splitlines()
    except UnicodeError: reject('SIGNATURE_INVALID', 'Invalid GnuPG status channel.')
    records = [line.split()[1:] for line in lines if line.startswith('[GNUPG:] ')]
    bad = {'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED', 'SIGEXPIRED', 'FAILURE', 'NODATA'}
    valid = [r for r in records if r and r[0] == 'VALIDSIG']
    if returncode or any(r and r[0] in bad for r in records) or len(valid) != 1:
        reject('SIGNATURE_INVALID', 'Signature is missing, invalid, expired, or ambiguous.')
    value = valid[0]
    if (len(value) not in (10, 11) or value[8] not in {'8', '9', '10'}
            or not re.fullmatch(r'[0-9A-F]{40}|[0-9A-F]{64}', value[1])):
        reject('SIGNATURE_INVALID', 'Signature status or hash algorithm is unsupported.')
    primary = value[10] if len(value) == 11 else value[1]
    if primary not in policy.primary_fingerprints:
        reject('SIGNER_NOT_APPROVED', 'Signature does not belong to the specified publisher key.')
    return dict(primary_fingerprint=primary, signing_fingerprint=value[1], hash_algorithm=value[8])


class ImageCache:
    def __init__(self, root, runner=run):
        self.root, self.run = Path(root).absolute(), runner
        if '..' in self.root.parts: reject('IMAGE_PATH_UNSAFE', 'Cache path contains root traversal.')

    def _verify(self, path, spec, policy):
        if spec.publisher != policy.publisher: reject('SIGNER_NOT_APPROVED', 'Publisher and trust anchor do not match.')
        with input_file(path / 'keyring.gpg') as key, input_file(path / 'image.qcow2') as image, input_file(path / 'signature.asc') as sig:
            if not 1 <= os.fstat(key).st_size <= 8 * 1024 * 1024 or not 1 <= os.fstat(sig).st_size <= 65536:
                reject('IMAGE_SIZE_LIMIT', 'Signature or keyring is outside the limits.')
            if os.fstat(image).st_size != spec.size_bytes or digest(image) != spec.sha256:
                reject('IMAGE_HASH_MISMATCH', 'Image size or SHA256 does not match.')
            if digest(key) != policy.keyring_sha256: reject('TRUST_ANCHOR_MISMATCH', 'Keyring does not match the approved hash.')
            # gpgv ignores key expiration and revocation; gpg honors them.
            # Use a dedicated short-lived context without access to production keyrings.
            with tempfile.TemporaryDirectory(prefix='.verify-', dir=self.root) as context:
                public_ring = Path(context) / 'public.gpg'
                fd = os.open(public_ring, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as out:
                    os.lseek(key, 0, os.SEEK_SET)
                    out.write(os.read(key, 8 * 1024 * 1024)); out.flush(); os.fsync(out.fileno())
                result, output = self.run(['gpg', '--no-options', '--homedir', context, '--batch',
                                           '--no-default-keyring', '--keyring', str(public_ring),
                                           '--no-auto-key-retrieve', '--no-auto-key-import',
                                           '--status-fd=1', '--verify', '--',
                                           f'/proc/self/fd/{sig}', f'/proc/self/fd/{image}'], pass_fds=(sig, image))
            signer = signature_status(result, output, policy)
            virtual = header(image, spec)  # Before qemu-img, do not open external paths from the header.
            status, raw = self.run(['qemu-img', 'info', '--output=json', '-f', 'qcow2', f'/proc/self/fd/{image}'], pass_fds=(image,))
            try: info = json.loads(raw)
            except (ValueError, TypeError): reject('IMAGE_FORMAT_UNSAFE', 'Image tool did not return valid JSON.')
            if (status or not isinstance(info, dict) or info.get('format') != 'qcow2'
                    or type(info.get('virtual-size')) is not int or info['virtual-size'] != virtual
                    or any(k in info for k in ('backing-filename', 'full-backing-filename', 'backing-filename-format'))):
                reject('IMAGE_FORMAT_UNSAFE', 'Format, backing, or size was not confirmed by the image tool.')
            specific = info.get('format-specific', {})
            if not isinstance(specific, dict) or not isinstance(specific.get('data', {}), dict):
                reject('IMAGE_FORMAT_UNSAFE', 'Invalid format-specific metadata.')
            data = specific.get('data', {})
            if any(data.get(k) for k in ('data-file', 'data-file-raw', 'encrypt', 'corrupt', 'dirty-flag')):
                reject('IMAGE_FORMAT_UNSAFE', 'External or unsafe image states are not allowed.')
            if digest(image) != spec.sha256: reject('IMAGE_HASH_MISMATCH', 'Image changed during validation.')
            return dict(schema_version=1, image=asdict(spec), signature=signer,
                        keyring_sha256=policy.keyring_sha256, approval_reference=policy.approval_reference,
                        signature_sha256=digest(sig), virtual_size=virtual)

    def import_local(self, spec, image, signature, keyring, policy):
        """Copy only explicitly supplied local files; no network code."""
        with directory(self.root, create=True) as parent:
            lock = os.open('cache.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                private_file(lock)
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: reject('CACHE_LOCKED', 'Cache import is already active.', 4)
                if os.path.lexists(self.root / spec.sha256):
                    manifest = self.verify_entry(spec.sha256, policy)
                    if manifest['image'] != asdict(spec): reject('CACHE_CONFLICT', 'Content ID has different provenance.', 4)
                    return manifest
                name = '.staging-' + str(uuid4())
                os.mkdir(name, 0o700, dir_fd=parent)
                staging = self.root / name
                with directory(staging) as stage:
                    for source, target, maximum in ((image, 'image.qcow2', spec.size_bytes), (signature, 'signature.asc', 65536), (keyring, 'keyring.gpg', 8 * 1024 * 1024)):
                        with input_file(source) as origin:
                            if os.fstat(origin).st_size > maximum: reject('IMAGE_SIZE_LIMIT', 'Source file exceeds the limit.')
                            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage)
                            with os.fdopen(fd, 'wb') as out:
                                total = 0
                                while chunk := os.read(origin, min(1024 * 1024, maximum + 1 - total)):
                                    total += len(chunk)
                                    if total > maximum: reject('IMAGE_SIZE_LIMIT', 'Source exceeds the limit while copying.')
                                    out.write(chunk)
                                out.flush(); os.fsync(out.fileno())
                    manifest = self._verify(staging, spec, policy)
                    fd = os.open('manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage)
                    with os.fdopen(fd, 'w') as out:
                        json.dump(manifest, out, sort_keys=True); out.flush(); os.fsync(out.fileno())
                    for target in ('image.qcow2', 'signature.asc', 'keyring.gpg', 'manifest.json'):
                        os.chmod(target, 0o400, dir_fd=stage, follow_symlinks=False)
                    os.fchmod(stage, 0o500); os.fsync(stage)
                os.rename(name, spec.sha256, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                return manifest
            finally:
                os.close(lock)

    def verify_entry(self, sha256, policy):
        if not re.fullmatch('[0-9a-f]{64}', sha256): reject('IMAGE_SPEC_INVALID', 'Invalid cache ID.', 2)
        path = self.root / sha256
        with input_file(path / 'manifest.json') as fd:
            raw = os.read(fd, 65537)
        try:
            if len(raw) > 65536: raise ValueError
            manifest = json.loads(raw)
            if set(manifest) != {'schema_version', 'image', 'signature', 'keyring_sha256', 'approval_reference', 'signature_sha256', 'virtual_size'} or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1: raise ValueError
            spec = ImageSpec(**manifest['image'])
        except (ValueError, TypeError, KeyError): reject('CACHE_INVALID', 'Unknown or corrupted cache manifest.')
        if spec.sha256 != sha256: reject('CACHE_INVALID', 'Cache path and image ID do not match.')
        derived = self._verify(path, spec, policy)
        if derived != manifest: reject('CACHE_INVALID', 'Stored evidence differs from revalidation.')
        return derived
