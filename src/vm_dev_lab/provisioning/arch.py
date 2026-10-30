# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Define pinned Arch image, package, and readiness contracts.

"""Controlled Arch adapters; no free-form package-manager or shell fragments from profiles."""
import json
import re

from ..storage.images import ImageSpec, reject

PACKAGE = re.compile(r'[A-Za-z0-9][A-Za-z0-9@+_.:-]{0,127}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.:@~-]{0,255}\Z')
GUEST_MANIFEST = '/var/lib/vm-dev-lab/provisioning-v1.json'


def cloud_image_spec(version, source_url, sha256, size_bytes, max_virtual_bytes):
    if not isinstance(version, str) or not re.fullmatch(r'20[0-9]{6}\.[0-9]+', version):
        reject('IMAGE_SPEC_INVALID', 'A versioned Arch cloud-image ID is required.', 2)
    return ImageSpec('archlinux', version, f'Arch-Linux-x86_64-cloudimg-{version}.qcow2',
                     source_url, sha256, size_bytes, max_virtual_bytes)


def provisioning_script(packages, user):
    """Create the sole privileged Arch package step for NoCloud.

    Package names were already constrained by the profile schema and are still
    revalidated. The guest receives neither a free-form hook nor sudo rules.
    """
    if (not isinstance(packages, list) or len(packages) > 256
            or len(set(packages)) != len(packages)
            or any(not isinstance(name, str) or not PACKAGE.fullmatch(name) for name in packages)
            or not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user)
            or user == 'root'):
        reject('PACKAGE_SPEC_INVALID', 'Invalid Arch package or user specification.', 2)
    config = json.dumps({'packages': packages, 'user': user}, sort_keys=True, separators=(',', ':'))
    # The embedded JSON is read as data. subprocess receives only
    # argument lists; package-manager and profile values are never evaluated by a shell.
    return f'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

CONFIG = json.loads({config!r})
TARGET = Path({GUEST_MANIFEST!r})

def publish(value):
    TARGET.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    stage = TARGET.with_name('.' + TARGET.name + '.tmp')
    stage.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\\n')
    os.chmod(stage, 0o644)
    os.replace(stage, TARGET)

manifest = {{
    'schema_version': 1,
    'adapter': 'arch-pacman-v1',
    'status': 'provisioning',
    'requested_packages': CONFIG['packages'],
    'installed_packages': {{}},
    'user': {{'name': CONFIG['user'], 'valid': False}},
    'ssh': {{'public_key_login': True, 'password_authentication': None}},
    'transaction': {{'attempted': bool(CONFIG['packages']), 'exit_code': None}},
    'error': None,
}}
publish(manifest)

try:
    account = pwd.getpwnam(CONFIG['user'])
    manifest['user'] = {{'name': CONFIG['user'], 'uid': account.pw_uid,
                        'home': account.pw_dir,
                        'valid': account.pw_uid >= 1000 and account.pw_dir == '/home/' + CONFIG['user']}}
    sshd = subprocess.run(['/usr/bin/sshd', '-T'], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, timeout=30, check=False)
    settings = {{line.split(None, 1)[0].lower(): line.split(None, 1)[1].lower()
                for line in sshd.stdout.splitlines() if len(line.split(None, 1)) == 2}}
    manifest['ssh']['password_authentication'] = settings.get('passwordauthentication') == 'no'
    manifest['ssh']['public_key_login'] = settings.get('pubkeyauthentication') == 'yes'
    if not manifest['user']['valid'] or sshd.returncode != 0 or not all(manifest['ssh'].values()):
        manifest['error'] = 'USER_SSH_INVALID'
        raise RuntimeError

    if CONFIG['packages']:
        transaction = subprocess.run(
            ['/usr/bin/pacman', '-Syu', '--needed', '--noconfirm', '--', *CONFIG['packages']],
            stdin=subprocess.DEVNULL, timeout=None, check=False)
        manifest['transaction']['exit_code'] = transaction.returncode
        query = subprocess.run(['/usr/bin/pacman', '-Q', '--', *CONFIG['packages']],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, timeout=60, check=False)
        versions = {{}}
        for line in query.stdout.splitlines():
            name, separator, version = line.partition(' ')
            if separator and name in CONFIG['packages']:
                versions[name] = version
        manifest['installed_packages'] = versions
        if transaction.returncode != 0:
            manifest['error'] = 'PACKAGE_TRANSACTION_FAILED'
            raise RuntimeError
        if query.returncode != 0 or set(versions) != set(CONFIG['packages']):
            manifest['error'] = 'PACKAGE_MISSING'
            raise RuntimeError

    manifest['status'] = 'project-ready'
    publish(manifest)
except BaseException:
    manifest['status'] = 'failed'
    if manifest['error'] is None:
        manifest['error'] = 'PROVISIONING_FAILED'
    publish(manifest)
    sys.exit(1)
'''


def validate_guest_manifest(value, packages, user):
    """Validate only the small non-secret P07 guest manifest."""
    expected = {'schema_version', 'adapter', 'status', 'requested_packages', 'installed_packages',
                'user', 'ssh', 'transaction', 'error'}
    try:
        if (not isinstance(value, dict) or set(value) != expected or value['schema_version'] != 1
                or value['adapter'] != 'arch-pacman-v1'
                or value['status'] not in {'provisioning', 'project-ready', 'failed'}
                or value['requested_packages'] != packages
                or set(value['installed_packages']) - set(packages)
                or any(not PACKAGE.fullmatch(name) or not VERSION.fullmatch(version)
                       for name, version in value['installed_packages'].items())
                or set(value['user']) not in ({'name', 'valid'}, {'name', 'uid', 'home', 'valid'})
                or value['user']['name'] != user or type(value['user']['valid']) is not bool
                or ('uid' in value['user'] and (type(value['user']['uid']) is not int
                    or value['user']['uid'] < 0 or value['user']['home'] != '/home/' + user))
                or set(value['ssh']) != {'public_key_login', 'password_authentication'}
                or any(item not in {True, False, None} for item in value['ssh'].values())
                or set(value['transaction']) != {'attempted', 'exit_code'}
                or type(value['transaction']['attempted']) is not bool
                or (value['transaction']['exit_code'] is not None
                    and (type(value['transaction']['exit_code']) is not int
                         or not 0 <= value['transaction']['exit_code'] <= 255))
                or value['error'] not in {None, 'USER_SSH_INVALID', 'PACKAGE_TRANSACTION_FAILED',
                                          'PACKAGE_MISSING', 'PROVISIONING_FAILED'}):
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        reject('GUEST_MANIFEST_INVALID', 'Guest manifest is missing or violates the P07 contract.', 8)
    return value
