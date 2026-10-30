# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Apply the owned libvirt ingress exception from UFW hooks.

"""Installed root-owned helper for one libvirt ingress exception, no libvirt API.

Only UFW reload / the owned network's started/updated hook invokes this file.
No VM lifecycle, daemon, package installation, whole-table flush or global policy.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = '/etc/vm-dev-lab'
LIMIT = 1024 * 1024


def require(value, message):
    if not value: raise ValueError(message)


def read_root(path):
    # Every parent must remain under administrative control.
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe parent path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o022, 'Unsafe root file')
        value = f.read(LIMIT+1)
    require(len(value) <= LIMIT, 'File limit')
    return value


def read_record():
    path=ROOT+'/firewall.json'
    value=read_root(path)
    require(os.lstat(path).st_mode & 0o777 == 0o600, 'Firewall record must remain 0600')
    return json.loads(value)


def sync(record, xml, ruleset, run, remove=False):
    plan = record['plan']; spec = plan['libvirt_exception']
    if spec is None: return 'not-required'
    require(plan['backend'] == 'ufw-framework-v1', 'Incorrect backend record')
    expected = hashlib.sha256(json.dumps({k:v for k,v in plan.items() if k!='sha256'}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(expected == plan['sha256'], 'Recordplan manipuliert')
    require(record['status'] in ('pending', 'complete', 'review_required', 'removing', 'removed'), 'Unknown journal status')
    if not remove and record['status'] in ('removing', 'removed', 'review_required'): return 'blocked-by-journal'
    require('<!DOCTYPE' not in xml.upper() and '<!ENTITY' not in xml.upper() and len(xml.encode()) <= LIMIT, 'Unsafe network XML')
    net = ET.fromstring(xml); setup = plan['setup']
    marker = net.find('./metadata/{https://vm-dev-lab.invalid/host-setup/v1}managed')
    require(net.tag == 'network' and net.findtext('name') == setup['network'] and net.findtext('uuid') == plan['network_uuid']
            and marker is not None and marker.get('setup_id') == plan['setup_id']
            and net.find('bridge').get('name') == setup['bridge'] and net.find('forward').get('mode') == 'nat', 'Network ownership differs')
    rows = ruleset['nftables']
    rules = [r['rule'] for r in rows if 'rule' in r]
    own = [r for r in rules if r.get('comment') == spec['comment']]
    require(len(own) <= 1, 'Duplicate owned libvirt exception')
    for rule in own:
        require({k:v for k,v in rule.items() if k!='handle'} == spec and type(rule.get('handle')) is int, 'Owned exception changed')
    if remove:
        if own:
            run(['nft', '-j', '-f', '-'], {'nftables':[{'delete':{'rule':{k:own[0][k] for k in ('family','table','chain','handle')}}}]})
        return 'removed'
    if own:
        chain_rules=[r for r in rules if all(r.get(k)==spec[k] for k in ('family','table','chain'))]
        reject=next((r for r in chain_rules if any(e.get('match',{}).get('right')==setup['bridge'] for e in r.get('expr',[])) and any('reject' in e for e in r.get('expr',[]))), None)
        require(reject is not None and chain_rules.index(own[0]) < chain_rules.index(reject), 'Owned exception was moved behind the libvirt reject')
        return 'unchanged'
    chain = any('chain' in r and all(r['chain'].get(k)==spec[k] for k in ('family','table')) and r['chain'].get('name')==spec['chain'] for r in rows)
    if not chain: return 'deferred-network-inactive'
    # Never accept an unrelated table/chain based solely on its name.
    require(any('table' in r and r['table'].get('family')=='ip' and r['table'].get('name')=='libvirt_network'
                and r['table'].get('comment','').startswith('Managed by libvirt for virtual networks:') for r in rows), 'libvirt table provenance is missing')
    require(any(r.get('family')=='ip' and r.get('table')=='libvirt_network' and r.get('chain')=='guest_input'
                and any(e.get('match',{}).get('right')==setup['bridge'] for e in r.get('expr',[]))
                and any('reject' in e for e in r.get('expr',[])) for r in rules), 'Owned network filter was not confirmed')
    run(['nft', '-j', '-f', '-'], {'nftables':[{'insert':{'rule':spec}}]})
    return 'inserted-owned-exception'


def execute(argv, data=None):
    p = subprocess.run(argv, **({'stdin': subprocess.DEVNULL} if data is None else {'input': json.dumps(data).encode()}),
                       capture_output=True, timeout=15, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(p.returncode == 0 and len(p.stdout)+len(p.stderr) <= LIMIT, 'Firewall tool failed')
    return p.stdout.decode()


def main():
    require(os.geteuid()==0 and sys.argv[1:] in ([], ['--remove']), 'Only manually approved root or hook execution is allowed')
    record = read_record()
    plan = record['plan']
    require(read_root(__file__).decode()==plan['helper'], 'Installed helper is not identical to the root record')
    # Separate short lock: UFW reload can run inside the setup administration lock.
    fd = os.open(ROOT+'/ufw-sync.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info=os.fstat(fd); require(info.st_uid==0 and info.st_nlink==1 and stat.S_ISREG(info.st_mode) and info.st_mode & 0o777==0o600, 'Unsafe synchronization lock')
        deadline=time.monotonic()+3
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                require(time.monotonic()<deadline, 'Another synchronization exceeds the lock deadline')
                time.sleep(.05)
        # Reread after taking the lock so removing cannot reactivate a stale plan.
        record=read_record()
        setup=record['plan']['setup']
        if '--remove' not in sys.argv and record['status'] in ('pending','complete'):
            for path, change in record['plan']['files'].items():
                require(read_root(path).decode()==change['after'], 'Persistent UFW files are incomplete or changed')
        require(setup['network'].startswith('vm-dev-lab') and '/' not in setup['network'], 'Invalid owned network name')
        xml=read_root('/etc/libvirt/qemu/networks/'+setup['network']+'.xml').decode()
        outcome=sync(record, xml, json.loads(execute(['nft','-j','list','ruleset'])), execute, '--remove' in sys.argv)
        print(outcome)
    finally: os.close(fd)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('vm-dev-lab UFW/libvirt synchronization blocked: '+str(error), file=sys.stderr)
        raise SystemExit(1)
