# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test lifecycle state transitions with local libvirt and file fakes.

"""P06: real contract with fully local libvirt and file fakes."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))

from vm_dev_lab.errors import LabError
from vm_dev_lab.guest.exec import (ADAPTER_VERSION, PROTOCOL_VERSION, REQUEST_LIMIT,
                                   RESPONSE_LIMIT, decode_frame, encode_frame)
from vm_dev_lab.guest.files import (ADAPTER_VERSION as FILE_ADAPTER_VERSION,
                                    PROTOCOL_VERSION as FILE_PROTOCOL_VERSION)
from vm_dev_lab.lifecycle import Lifecycle, PRIVATE_FILES, RUNTIME_FILES, RealOwnership, domain_xml
from vm_dev_lab.process import ExchangeResult
from vm_dev_lab.resources import request as resource_request
from vm_dev_lab.state import StatePaths, StateStore, directory


class Domain:
    def __init__(self, name, uuid, xml):
        self._name=name; self._uuid=uuid; self._xml=xml; self._inactive_xml=xml; self.running=False
    def name(self): return self._name
    def UUIDString(self): return self._uuid
    def XMLDesc(self, flags): return self._inactive_xml if flags & 2 else self._xml
    def autostart(self): return 0
    def isActive(self): return int(self.running)
    def ID(self): return 7 if self.running else -1
    def hasManagedSaveImage(self, flags): return 0


class Backend:
    def __init__(self):
        self.domains={}; self.undefined=[]; self.undefine_error=None
        self.remove_nvram_on_undefine=None
    def close(self): pass
    def connect(self): return self
    def getDomainCapabilities(self, *_args):
        return ('<domainCapabilities><features>'
                '<backingStoreInput supported="yes"/>'
                '</features></domainCapabilities>')
    def listAllDomains(self, flags): return list(self.domains.values())
    def define(self, xml):
        root=ET.fromstring(xml); uuid=root.findtext('uuid')
        domain=Domain(root.findtext('name'),uuid,xml); self.domains[uuid]=domain
        return domain
    def domain(self, uuid, missing_ok=False):
        value=self.domains.get(uuid)
        if value is None and not missing_ok: raise AssertionError('missing domain')
        return value
    def start(self, uuid): self.domains[uuid].running=True; return self.domains[uuid]
    def request_shutdown(self, uuid): self.domains[uuid].running=False; return self.domains[uuid]
    def force_stop(self, uuid): self.domains[uuid].running=False; return self.domains[uuid]
    def undefine(self, uuid):
        if self.undefine_error: raise self.undefine_error
        if self.remove_nvram_on_undefine is not None:
            self.remove_nvram_on_undefine.unlink()
        self.undefined.append(uuid); del self.domains[uuid]
    def ipv4_leases(self, network_uuid, mac): return ['192.0.2.10']


def guest_manifest(*, status='project-ready', error=None, installed=None,
                   user_valid=True, password_authentication=True, transaction_exit=0):
    return {
        'schema_version':1,'adapter':'arch-pacman-v1','status':status,
        'requested_packages':['git'],'installed_packages':{'git':'2.51.0-1'} if installed is None else installed,
        'user':{'name':'developer','uid':1000,'home':'/home/developer','valid':user_valid},
        'ssh':{'public_key_login':True,'password_authentication':password_authentication},
        'transaction':{'attempted':True,'exit_code':transaction_exit},'error':error}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.paths=StatePaths(self.root/'data',self.root/'state',self.root/'run')
        self.store=StateStore(self.paths); self.store.initialize()
        self.backend=Backend()
        self.plan={'uri':'qemu:///system',
                   'network':'vm-dev-lab-test','network_uuid':'33333333-3333-4333-8333-333333333333',
                   'pool':'vm-dev-lab-pool','pool_uuid':'44444444-4444-4444-8444-444444444444',
                   'storage':str(self.root/'storage'),'reserve_gib':20,
                   'owner':{'name':'test-owner','uid':os.geteuid(),'gid':os.getegid()},
                   'qemu':{'name':'qemu-worker','uid':12345,'gid':12346}}
        (self.root/'storage').mkdir()
        self.record=self.store.reserve('arch-test'); self.op=self.record['journal'][-1]['id']
        self.store.advance(self.record['instance_id'],self.op,'allocating')
        self.record=self.store.inspect(self.record['instance_id'])
        self.data,self.domain=self._resources(self.record)
        self.backend.domains[self.record['domain_uuid']]=self.domain
        self.store.advance(self.record['instance_id'],self.op,'defined',complete=True)
        self.lifecycle=Lifecycle(paths=self.paths,backend=self.backend,host_record=self.plan,sleeper=lambda _:None)
        self.accounts = {
            'test-owner': SimpleNamespace(
                pw_name='test-owner', pw_uid=os.geteuid(), pw_gid=os.getegid()),
            'qemu-worker': SimpleNamespace(
                pw_name='qemu-worker', pw_uid=12345, pw_gid=12346),
        }
        self.accounts_by_uid = {account.pw_uid: account
                                for account in self.accounts.values()}
        self.groups_by_gid = {
            os.getegid(): SimpleNamespace(gr_gid=os.getegid()),
            12346: SimpleNamespace(gr_gid=12346),
        }
        self.lifecycle.qemu_lookup = lambda name: self.accounts[name]
        self.lifecycle.uid_lookup = lambda uid: self.accounts_by_uid[uid]
        self.lifecycle.gid_lookup = lambda gid: self.groups_by_gid[gid]

    def _write(self,path,data=b'x'):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(data)

    @staticmethod
    def _id(path):
        info=os.lstat(path); return {'device':info.st_dev,'inode':info.st_ino}

    def _resources(self,record):
        private=self.paths.data/'instances'/record['instance_id']
        with directory(self.paths.data/'instances') as parent: os.mkdir(record['instance_id'],0o700,dir_fd=parent)
        runtime=Path(self.plan['storage'])/record['instance_id']; runtime.mkdir(mode=0o700)
        for name in RUNTIME_FILES: self._write(runtime/name)
        data={'schema_version':1,'lab_id':record['lab_id'],'instance_id':record['instance_id'],
              'domain_uuid':record['domain_uuid'],'name':record['name'],'uri':record['uri'],
              'storage':str(runtime),'directory':self._id(runtime),
              'files':{name:self._id(runtime/name) for name in RUNTIME_FILES},'mac':'52:54:00:12:34:56',
              'network':self.plan['network'],'network_uuid':self.plan['network_uuid'],
              'pool':self.plan['pool'],'pool_uuid':self.plan['pool_uuid'],'image_sha256':'a'*64,
              'seed':{'lab_id':record['lab_id'],'instance_id':record['instance_id'],'domain_uuid':record['domain_uuid'],
                      'seed_instance_id':'55555555-5555-4555-8555-555555555555'},'ssh_user':'developer',
              'requested_packages':['git']}
        config={'cpus':1,'memory_mib':512}
        xml=domain_xml(record,config,data)
        guest={'schema_version':1,'cloud_init':'completed','ssh_ready':True,'project_ready':True,
               'provisioning':{'schema_version':1,'adapter':'arch-pacman-v1','status':'project-ready',
                 'requested_packages':['git'],'installed_packages':{'git':'2.51.0-1'},
                 'user':{'name':'developer','uid':1000,'home':'/home/developer','valid':True},
                 'ssh':{'public_key_login':True,'password_authentication':True},
                 'transaction':{'attempted':True,'exit_code':0},'error':None}}
        contents={'instance.json':json.dumps(data).encode(),'domain.xml':xml.encode(),'user-data':b'user',
                  'guest-manifest.json':json.dumps(guest).encode(),'meta-data':b'meta',
                  'network-config':b'network','seed.iso':b'seed'}
        for name,value in contents.items(): self._write(private/name,value)
        self.store.register_instance_files(record,record['journal'][-1]['id'],PRIVATE_FILES)
        clients=self.paths.data/'clients'/record['instance_id']; clients.mkdir(parents=True,mode=0o700)
        for name in ('id_ed25519','id_ed25519.pub','known_hosts'): self._write(clients/name)
        return data,Domain(record['name'],record['domain_uuid'],xml)

    def _failed_create(self):
        private=self.paths.data/'instances'/self.record['instance_id']
        guest={'schema_version':1,'cloud_init':'failed','ssh_ready':True,'project_ready':False,
               'provisioning':guest_manifest(status='failed',error='USER_SSH_INVALID',installed={},
                                             user_valid=False,password_authentication=False,
                                             transaction_exit=None)}
        (private/'guest-manifest.json').write_bytes(json.dumps(guest).encode())
        with self.store.lock('global'):
            state=self.store._read(); current=state['instances'][self.record['instance_id']]
            operation=current['journal'][-1]
            operation.update(phase='failed',last_safe='booting',status='review_required',
                             events=['planned','allocating','defined','booting','provisioning','failed'])
            current['state']='failed'; self.store._write(state)
        record=self.store.inspect(self.record['instance_id'])
        return record['journal'][-1]['id'],deepcopy(record['journal'][-1])

    def _failed_create_before_hostkey(self):
        private=self.paths.data/'instances'/self.record['instance_id']
        guest={'schema_version':1,'cloud_init':'pending','ssh_ready':False,'project_ready':False,
               'provisioning':guest_manifest(status='provisioning',error=None,installed={},
                                             user_valid=False,password_authentication=None,
                                             transaction_exit=None)}
        (private/'guest-manifest.json').write_bytes(json.dumps(guest).encode())
        known_hosts=self.paths.data/'clients'/self.record['instance_id']/'known_hosts'
        known_hosts.unlink()
        with self.store.lock('global'):
            state=self.store._read(); current=state['instances'][self.record['instance_id']]
            operation=current['journal'][-1]
            operation.update(phase='failed',last_safe='booting',status='review_required',
                             events=['planned','allocating','defined','booting','provisioning','failed'])
            current['state']='failed'; self.store._write(state)
        return self.store.inspect(self.record['instance_id'])['journal'][-1]['id']

    def _recover(self,source):
        return self.lifecycle.recover_failed_cleanup('arch-test',source,time.monotonic()+10)

    def _second_instance(self, name='arch-second'):
        record=self.store.reserve(name); operation=record['journal'][-1]['id']
        self.store.advance(record['instance_id'],operation,'allocating')
        record=self.store.inspect(record['instance_id'])
        data,domain=self._resources(record)
        self.backend.domains[record['domain_uuid']]=domain
        self.store.advance(record['instance_id'],operation,'defined',complete=True)
        return self.store.inspect(record['instance_id']),data,domain

    def test_p09_list_shows_only_registry_instances_and_tombstones(self):
        second,_data,second_domain=self._second_instance()
        second_domain.running=True
        self.backend.domains['99999999-9999-4999-8999-999999999999'] = Domain(
            'foreign','99999999-9999-4999-8999-999999999999','<domain/>')
        listed=self.lifecycle.list_instances()
        self.assertEqual([item['name'] for item in listed['instances']],
                         ['arch-second','arch-test'])
        running=next(item for item in listed['instances']
                     if item['instance_id'] == second['instance_id'])
        self.assertEqual((running['power_state'],running['qualification']),
                         ('running','verified'))
        self.assertTrue(running['readiness']['project_ready'])
        self.lifecycle.destroy('arch-test',time.monotonic()+10)
        listed=self.lifecycle.list_instances()
        tombstone=next(item for item in listed['instances']
                       if item['instance_id'] == self.record['instance_id'])
        self.assertEqual((tombstone['power_state'],tombstone['qualification']),
                         ('removed','tombstone'))
        self.assertEqual((listed['active_count'],listed['tombstone_count']),(1,1))

    def test_p09_list_empty_and_running_does_not_invent_readiness(self):
        guest={'schema_version':1,'cloud_init':'pending','ssh_ready':False,
               'project_ready':False,
               'provisioning':guest_manifest(status='provisioning',installed={},
                   user_valid=False,password_authentication=None,transaction_exit=None)}
        path=self.paths.data/'instances'/self.record['instance_id']/'guest-manifest.json'
        path.write_bytes(json.dumps(guest).encode())
        self.domain.running=True
        item=self.lifecycle.list_instances()['instances'][0]
        self.assertEqual(item['power_state'],'running')
        self.assertFalse(item['readiness']['ssh_ready'])
        self.assertFalse(item['readiness']['project_ready'])
        with self.store.lock('global'):
            state=self.store._read(); state['instances']={}; self.store._write(state)
        self.assertEqual(self.lifecycle.list_instances(),{
            'instances':[], 'active_count':0, 'tombstone_count':0})

    def test_p09_list_distinguishes_review_and_resolved_history(self):
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',side_effect=LabError(
                    7,'GUEST_NOT_READY','readiness','timeout','inspect')):
            with self.assertRaises(LabError):
                self.lifecycle.start('arch-test',time.monotonic()+10)
        blocked=self.lifecycle.list_instances()['instances'][0]
        self.assertTrue(blocked['requires_review'])
        self.assertEqual(blocked['qualification'],'review-required')
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',return_value='192.0.2.10'), patch.object(
                self.lifecycle,'_project_readiness',return_value={}):
            self.lifecycle.start('arch-test',time.monotonic()+10)
        resolved=self.lifecycle.list_instances()['instances'][0]
        self.assertFalse(resolved['requires_review'])
        self.assertEqual(resolved['qualification'],'verified')
        self.assertEqual(resolved['last_operation']['kind'],'start_recovery')

    def test_p09_list_marks_one_ownership_error_without_hiding_others(self):
        second,data,_domain=self._second_instance()
        path=Path(data['storage'])/'work.qcow2'; path.rename(path.with_name('old'))
        self._write(path,b'foreign')
        listed=self.lifecycle.list_instances()['instances']
        first=next(item for item in listed if item['instance_id'] == self.record['instance_id'])
        broken=next(item for item in listed if item['instance_id'] == second['instance_id'])
        self.assertEqual(first['qualification'],'verified')
        self.assertEqual(broken['qualification'],'error')
        self.assertEqual(broken['diagnostic_error']['code'],'OWNERSHIP_MISMATCH')

    def test_p09_logs_are_bounded_binary_safe_and_redacted(self):
        path=Path(self.data['storage'])/'serial.log'
        path.write_bytes(b'A'*80+b'\xff\npassword=hunter2\ntoken:abc\n'
                         b'-----BEGIN OPENSSH PRIVATE KEY-----\nprivate\n'
                         b'-----END OPENSSH PRIVATE KEY-----\n')
        result=self.lifecycle.logs('arch-test',max_bytes=128)
        log=result['serial_log']
        self.assertTrue(log['available']); self.assertTrue(log['truncated'])
        self.assertLessEqual(log['bytes_returned'],128)
        self.assertNotIn('hunter2',log['text']); self.assertNotIn('abc',log['text'])
        self.assertNotIn('private\n',log['text'])
        self.assertTrue(log['untrusted']); self.assertFalse(result['follow_supported'])
        self.assertEqual(result['selected_operation']['id'],self.op)

    def test_p09_logs_select_history_and_reject_unknown_operation(self):
        result=self.lifecycle.logs('arch-test',operation_id=self.op)
        self.assertEqual(result['selected_operation']['kind'],'create')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.logs('arch-test','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
        self.assertEqual(caught.exception.detail['code'],'OPERATION_NOT_FOUND')

    def test_p09_logs_allow_bound_incomplete_journal_but_reject_path_attacks(self):
        self.domain.running=True
        with patch.object(self.backend,'request_shutdown',return_value=self.domain), \
                self.assertRaises(LabError):
            self.lifecycle.stop('arch-test',deadline=0)
        result=self.lifecycle.logs('arch-test')
        self.assertTrue(result['requires_review'])
        self.assertTrue(result['current_operation']['blocking'])
        self.assertTrue(result['serial_log']['available'])
        path=Path(self.data['storage'])/'serial.log'; path.unlink(); path.symlink_to('/etc/passwd')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.logs('arch-test')
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_p09_logs_reject_foreign_runtime_inventory_and_invalid_limit(self):
        self._write(Path(self.data['storage'])/'foreign.log',b'foreign')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.logs('arch-test')
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.logs('arch-test',max_bytes=65537)
        self.assertEqual(caught.exception.detail['code'],'LOG_LIMIT_INVALID')

    def test_p09_logs_recheck_rotation_after_read(self):
        path=Path(self.data['storage'])/'serial.log'; real_read=os.read
        exchanged={'done':False}
        def read(fd,size):
            value=real_read(fd,size)
            if not exchanged['done']:
                exchanged['done']=True
                path.rename(path.with_name('old-serial.log'))
                self._write(path,b'replacement')
            return value
        with patch('vm_dev_lab.lifecycle.os.read',side_effect=read), \
                self.assertRaises(LabError) as caught:
            self.lifecycle.logs('arch-test')
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_p09_restart_composes_graceful_stop_and_start(self):
        self.domain.running=True
        deadline=time.monotonic()+10
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',return_value='192.0.2.10'), patch.object(
                self.lifecycle,'_project_readiness',return_value={}):
            result=self.lifecycle.restart('arch-test',deadline)
        self.assertEqual((result['power_state'],result['lifecycle_state']),('running','ready'))
        journal=self.store.inspect('arch-test')['journal']
        self.assertEqual([item['kind'] for item in journal],['create','shutdown','start'])
        self.assertTrue(all(item['status'] == 'complete' for item in journal))

    def test_p09_restart_starts_already_shutoff_instance_without_shutdown_journal(self):
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',return_value='192.0.2.10'), patch.object(
                self.lifecycle,'_project_readiness',return_value={}):
            self.lifecycle.restart('arch-test',time.monotonic()+10)
        self.assertEqual([item['kind'] for item in self.store.inspect('arch-test')['journal']],
                         ['create','start'])

    def test_p09_restart_never_starts_after_stop_failure_or_expired_deadline(self):
        with patch.object(self.lifecycle,'stop',side_effect=LabError(
                7,'SHUTDOWN_TIMEOUT','shutdown','timeout','inspect')), patch.object(
                self.lifecycle,'start') as start, self.assertRaises(LabError):
            self.lifecycle.restart('arch-test',time.monotonic()+10)
        start.assert_not_called()
        moments=iter((0,2))
        lifecycle=Lifecycle(paths=self.paths,backend=self.backend,host_record=self.plan,
                            clock=lambda: next(moments),sleeper=lambda _:None)
        with patch.object(lifecycle,'stop',return_value={
                'power_state':'shutoff','instance_id':self.record['instance_id']}), patch.object(
                lifecycle,'start') as start, self.assertRaises(LabError) as caught:
            lifecycle.restart('arch-test',deadline=1)
        self.assertEqual(caught.exception.detail['code'],'DEADLINE_EXCEEDED')
        start.assert_not_called()

    def test_p09_restart_does_not_retry_failed_start(self):
        with patch.object(self.lifecycle,'stop',return_value={
                'power_state':'shutoff','instance_id':self.record['instance_id']}), patch.object(
                self.lifecycle,'start',side_effect=LabError(
                    6,'DOMAIN_START_FAILED','start','failed','inspect')) as start, \
                self.assertRaises(LabError):
            self.lifecycle.restart('arch-test',time.monotonic()+10)
        self.assertEqual(start.call_count,1)

    def test_p09_restart_preserves_real_start_failure_after_completed_stop(self):
        self.domain.running=True
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',side_effect=LabError(
                    7,'GUEST_NOT_READY','readiness','timeout','inspect')), \
                self.assertRaises(LabError):
            self.lifecycle.restart('arch-test',time.monotonic()+10)
        journal=self.store.inspect('arch-test')['journal']
        self.assertEqual([item['kind'] for item in journal],['create','shutdown','start'])
        self.assertEqual(journal[-2]['status'],'complete')
        self.assertEqual((journal[-1]['status'],journal[-1]['phase']),
                         ('review_required','failed'))

    def test_p09_restart_ownership_and_lock_conflicts_precede_mutation(self):
        self.domain.running=True; before=deepcopy(self.store.inspect('arch-test')['journal'])
        with self.store.lock(self.record['instance_id']), self.assertRaises(LabError) as caught:
            self.lifecycle.restart('arch-test',time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'LOCK_CONFLICT')
        self.assertTrue(self.domain.running)
        path=Path(self.data['storage'])/'work.qcow2'; path.rename(path.with_name('old'))
        self._write(path,b'foreign')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.restart('arch-test',time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.assertTrue(self.domain.running)
        self.assertEqual(self.store.inspect('arch-test')['journal'],before)

    def test_status_start_stop_are_uuid_bound_and_idempotent(self):
        status=self.lifecycle.status('arch-test')
        self.assertEqual((status['power_state'],status['lifecycle_state']),('shutoff','defined'))
        with patch.object(self.lifecycle,'_host',return_value=self.plan), \
                patch.object(self.lifecycle,'_readiness',return_value='192.0.2.10'), \
                patch.object(self.lifecycle,'_project_readiness',return_value={}):
            started=self.lifecycle.start('arch-test',time.monotonic()+10)
            self.assertEqual((started['power_state'],started['lifecycle_state']),('running','ready'))
            journal=len(self.store.inspect('arch-test')['journal'])
            self.lifecycle.start('arch-test',time.monotonic()+10)
            self.assertEqual(len(self.store.inspect('arch-test')['journal']),journal)
        stopped=self.lifecycle.stop('arch-test',time.monotonic()+10)
        self.assertEqual((stopped['power_state'],stopped['lifecycle_state']),('shutoff','defined'))
        journal=len(self.store.inspect('arch-test')['journal'])
        self.lifecycle.stop('arch-test',time.monotonic()+10)
        self.assertEqual(len(self.store.inspect('arch-test')['journal']),journal)

    def test_force_stop_intent_is_journaled_and_cannot_look_graceful(self):
        self.domain.running=True
        with patch.object(self.backend, 'request_shutdown', return_value=self.domain):
            self.lifecycle.stop('arch-test', deadline=0, force=True)
        operation=self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual(operation['events'], ['planned','forcing','defined'])
        self.assertEqual(operation['status'], 'complete')

    def test_first_start_after_no_start_requests_hostkey_bootstrap(self):
        known_hosts=self.paths.data/'clients'/self.record['instance_id']/'known_hosts'
        known_hosts.unlink()
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',return_value='192.0.2.10') as readiness, patch.object(
                self.lifecycle,'_project_readiness',return_value={}):
            self.lifecycle.start('arch-test',time.monotonic()+10)
        self.assertTrue(readiness.call_args.kwargs['bootstrap_seed'])

    def test_create_no_start_defines_owned_domain_without_readiness(self):
        vm={'guest_os':'arch','cpus':1,'memory_mib':512,'disk_gib':1,
            'network':{'name':self.plan['network']}}
        resolved=SimpleNamespace(config={'vm':vm},complete=True)
        image_manifest={'image':{'sha256':'a'*64}}
        def files(record,resolved_config,plan,image,deadline):
            data,domain=self._resources(record)
            return data,domain.XMLDesc(0)
        with patch.object(self.lifecycle,'_verify_image',return_value=(self.root/'image.qcow2',image_manifest)), \
                patch.object(self.lifecycle,'_host',return_value=self.plan), \
                patch.object(self.lifecycle,'_create_files',side_effect=files), \
                patch('vm_dev_lab.lifecycle.Path.read_text',return_value='MemAvailable: 99999999 kB\n'), \
                patch('vm_dev_lab.lifecycle.shutil.disk_usage',return_value=SimpleNamespace(free=100*1024**3)), \
                patch.object(self.lifecycle,'_readiness',side_effect=AssertionError('no readiness')):
            result=self.lifecycle.create(resolved,'arch-second',True,time.monotonic()+10)
        self.assertEqual((result['power_state'],result['ipv4']),('shutoff',None))
        record=self.store.inspect('arch-second')
        self.assertEqual((record['state'],record['journal'][-1]['status']),('defined','complete'))
        self.assertFalse(self.backend.domain(record['domain_uuid']).running)

    def test_create_budget_rejection_does_not_publish_planned_record(self):
        vm={'guest_os':'arch','cpus':2,'memory_mib':512,'disk_gib':1,
            'network':{'name':self.plan['network']}}
        resolved=SimpleNamespace(config={'vm':vm},complete=True)
        image_manifest={'image':{'sha256':'a'*64}}
        with self.store.lock('global'):
            state=self.store._read(); state['resources']['limits']['vcpus']=1
            self.store._write(state)
        registry=self.paths.state/'registry.json'; before=registry.read_bytes()
        domains=set(self.backend.domains)
        with patch.object(self.lifecycle,'_verify_image',return_value=(self.root/'image.qcow2',image_manifest)), \
                patch.object(self.lifecycle,'_host',return_value=self.plan), \
                patch('vm_dev_lab.lifecycle.Path.read_text',return_value='MemAvailable: 99999999 kB\n'), \
                patch('vm_dev_lab.lifecycle.shutil.disk_usage',return_value=SimpleNamespace(free=100*1024**3)):
            with self.assertRaises(LabError) as caught:
                self.lifecycle.create(resolved,'budget-rejected',True,time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'RESOURCE_VCPU_BUDGET')
        self.assertEqual(registry.read_bytes(),before)
        self.assertEqual(set(self.backend.domains),domains)

    def test_atomic_admission_keeps_failed_create_cleanup_contract(self):
        wanted=resource_request(instances=1,vcpus=1,memory_mib=512,
                                virtual_disk_bytes=1024,staging_bytes=1024)
        record=self.lifecycle.resources.reserve_create('atomic-failed',wanted)
        operation=record['journal'][-1]['id']
        self.store.advance(record['instance_id'],operation,'allocating')
        record=self.store.inspect(record['instance_id'])
        data,domain=self._resources(record); self.backend.domains[record['domain_uuid']]=domain
        self.store.advance(record['instance_id'],operation,'defined')
        self.store.advance(record['instance_id'],operation,'booting')
        self.store.advance(record['instance_id'],operation,'provisioning')
        guest={'schema_version':1,'cloud_init':'failed','ssh_ready':True,'project_ready':False,
               'provisioning':guest_manifest(status='failed',error='USER_SSH_INVALID',installed={},
                                             user_valid=False,password_authentication=False,
                                             transaction_exit=None)}
        private=self.paths.data/'instances'/record['instance_id']
        (private/'guest-manifest.json').write_bytes(json.dumps(guest).encode())
        self.store.advance(record['instance_id'],operation,'failed',failed=True)
        self.lifecycle.resources.review(record['instance_id'],operation)

        result=self.lifecycle.recover_failed_cleanup(
            record['instance_id'],operation,time.monotonic()+10)
        self.assertTrue(result['removed'])
        current=self.store.inspect(record['instance_id'])
        self.assertEqual((current['state'],current['journal'][-1]['kind'],
                          current['journal'][-1]['status']),
                         ('destroyed','failed_create_cleanup','complete'))
        reservation=self.lifecycle.resources.inventory()['reservations'][operation]
        self.assertEqual(reservation['state'],'released')

    def test_ownership_mismatch_blocks_backend_mutation(self):
        runtime=Path(self.data['storage']); original=runtime/'work.qcow2'; backup=runtime/'backup'
        original.rename(backup); self._write(original,b'foreign')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test',time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.assertFalse(self.domain.running)

    def test_active_create_accepts_only_resolved_owned_backing_chain(self):
        inactive=self.domain._inactive_xml
        root=ET.fromstring(inactive)
        disk=next(entry for entry in root.findall('./devices/disk')
                  if entry.get('device') == 'disk')
        backing=ET.SubElement(disk,'backingStore',type='file',index='1')
        ET.SubElement(backing,'format',type='qcow2')
        ET.SubElement(backing,'source',file=str(Path(self.data['storage'])/'base.qcow2'))
        ET.SubElement(backing,'backingStore')
        live=ET.tostring(root,encoding='unicode')
        self.domain._xml=live; self.domain.running=True
        owner=RealOwnership(self.store,self.backend)
        owner.verify(self.store.inspect('arch-test'),self.domain)

        mutations=(
            lambda value: value.find('./backingStore/source').set('file','/foreign/base.qcow2'),
            lambda value: value.find('./backingStore/format').set('type','raw'),
            lambda value: value.find('driver').set('cache','writeback'),
            lambda value: ET.SubElement(value.find('./backingStore/backingStore'),
                                        'backingStore'),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed=ET.fromstring(live); work=next(entry for entry in changed.findall('./devices/disk')
                                                    if entry.get('device') == 'disk')
                mutation(work); self.domain._xml=ET.tostring(changed,encoding='unicode')
                with self.assertRaises(LabError) as caught:
                    owner.verify(self.store.inspect('arch-test'),self.domain)
                self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.domain._xml=live

        persistent=ET.fromstring(inactive)
        persistent.find('./devices/disk/source').set('file','/foreign/work.qcow2')
        self.domain._inactive_xml=ET.tostring(persistent,encoding='unicode')
        with self.assertRaises(LabError) as caught:
            owner.verify(self.store.inspect('arch-test'),self.domain)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_destroy_removes_only_manifested_instance_resources(self):
        result=self.lifecycle.destroy('arch-test',time.monotonic()+10)
        self.assertTrue(result['removed']); self.assertFalse(Path(self.data['storage']).exists())
        self.assertFalse((self.paths.data/'instances'/self.record['instance_id']).exists())
        self.assertFalse((self.paths.data/'clients'/self.record['instance_id']).exists())
        tombstone=self.store.inspect(self.record['instance_id'])
        self.assertEqual(tombstone['state'],'destroyed')
        self.assertEqual((tombstone['directory'],tombstone['manifest']),(None,[]))

    def test_failed_create_cleanup_is_bound_and_preserves_source_failure(self):
        source,original=self._failed_create()
        result=self._recover(source)
        self.assertTrue(result['removed'])
        record=self.store.inspect(self.record['instance_id'])
        self.assertEqual(record['journal'][0],original)
        cleanup=record['journal'][1]
        self.assertEqual((cleanup['kind'],cleanup['status'],cleanup['phase']),
                         ('failed_create_cleanup','complete','destroyed'))
        self.assertEqual(cleanup['recovery']['source_operation'],source)
        self.assertEqual(cleanup['recovery']['source_failure']['error'],'USER_SSH_INVALID')
        self.assertFalse(Path(self.data['storage']).exists())

    def test_failed_create_cleanup_accepts_exact_pre_hostkey_state(self):
        source=self._failed_create_before_hostkey()
        result=self._recover(source)
        self.assertTrue(result['removed'])
        cleanup=self.store.inspect(self.record['instance_id'])['journal'][-1]
        self.assertFalse(cleanup['recovery']['hostkey_pinned'])
        self.assertEqual(set(cleanup['recovery']['client_files']),
                         {'id_ed25519','id_ed25519.pub'})

    def test_failed_create_cleanup_requires_known_hosts_after_pinning(self):
        source,_=self._failed_create()
        (self.paths.data/'clients'/self.record['instance_id']/'known_hosts').unlink()
        before=deepcopy(self.store.inspect('arch-test')['journal'])
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.assertEqual(self.store.inspect('arch-test')['journal'],before)

    def test_failed_create_cleanup_rejects_foreign_client_file_before_intent(self):
        source=self._failed_create_before_hostkey()
        client=self.paths.data/'clients'/self.record['instance_id']
        self._write(client/'foreign')
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_failed_create_cleanup_rejects_client_inode_exchange_after_intent(self):
        source=self._failed_create_before_hostkey(); real_advance=self.lifecycle.store.advance
        def interrupt(instance,operation,phase,**kwargs):
            if phase == 'undefining':
                raise SystemExit('injected after cleanup intent')
            return real_advance(instance,operation,phase,**kwargs)
        with patch.object(self.lifecycle.store,'advance',side_effect=interrupt), \
                self.assertRaises(SystemExit):
            self._recover(source)
        client=self.paths.data/'clients'/self.record['instance_id']
        (client/'id_ed25519').unlink(); self._write(client/'id_ed25519',b'foreign')
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_failed_create_cleanup_rejects_client_symlink_after_intent(self):
        source=self._failed_create_before_hostkey(); real_advance=self.lifecycle.store.advance
        def interrupt(instance,operation,phase,**kwargs):
            if phase == 'undefining':
                raise SystemExit('injected after cleanup intent')
            return real_advance(instance,operation,phase,**kwargs)
        with patch.object(self.lifecycle.store,'advance',side_effect=interrupt), \
                self.assertRaises(SystemExit):
            self._recover(source)
        client=self.paths.data/'clients'/self.record['instance_id']
        (client/'id_ed25519.pub').unlink()
        (client/'id_ed25519.pub').symlink_to(client/'id_ed25519')
        with self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'PATH_UNSAFE')

    def test_failed_create_cleanup_rejects_wrong_operation_and_active_domain(self):
        source,_=self._failed_create(); before=deepcopy(self.store.inspect('arch-test')['journal'])
        with self.assertRaises(LabError) as caught:
            self._recover('00000000-0000-4000-8000-000000000000')
        self.assertEqual(caught.exception.detail['code'],'RECOVERY_SOURCE_MISMATCH')
        self.assertEqual(self.store.inspect('arch-test')['journal'],before)
        self.domain.running=True
        with self.assertRaises(LabError) as caught: self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'DOMAIN_RUNNING')
        self.assertEqual(self.store.inspect('arch-test')['journal'],before)

    def test_failed_create_cleanup_rejects_domain_uuid_and_metadata_changes(self):
        source,_=self._failed_create()
        self.domain._uuid='66666666-6666-4666-8666-666666666666'
        with self.assertRaises(LabError) as caught: self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.domain._uuid=self.record['domain_uuid']
        root=ET.fromstring(self.domain._xml)
        next(iter(root.find('metadata'))).set('lab_id','foreign')
        self.domain._xml=ET.tostring(root,encoding='unicode')
        with self.assertRaises(LabError) as caught: self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_failed_create_cleanup_rejects_inode_change(self):
        source,_=self._failed_create(); runtime=Path(self.data['storage'])
        original=runtime/'work.qcow2'; original_identity=self._id(original)
        displaced=self.root/'displaced-work.qcow2'; original.rename(displaced)
        self._write(original,b'replaced')
        self.assertEqual(self._id(displaced),original_identity)
        self.assertNotEqual(self._id(original),original_identity)
        with self.assertRaises(LabError) as caught: self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_failed_create_cleanup_rejects_unknown_file_before_recovery(self):
        source,_=self._failed_create()
        self._write(Path(self.data['storage'])/'unknown.data')
        with self.assertRaises(LabError) as caught: self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_failed_create_cleanup_undefine_failure_is_resumable(self):
        source,_=self._failed_create()
        self.backend.undefine_error=LabError(6,'UNDEFINE_FAILED','cleanup','injected','inspect')
        with self.assertRaises(LabError): self._recover(source)
        record=self.store.inspect('arch-test')
        self.assertEqual(record['journal'][-1]['phase'],'undefining')
        self.assertIn(record['domain_uuid'],self.backend.domains)
        self.backend.undefine_error=None
        self.assertTrue(self._recover(source)['removed'])

    def test_failed_create_cleanup_resumes_after_undefine_before_journal_advance(self):
        source,_=self._failed_create(); real_advance=self.lifecycle.store.advance; interrupted={'done':False}
        self.backend.remove_nvram_on_undefine=Path(self.data['storage'])/'nvram.fd'
        def advance(instance,operation,phase,**kwargs):
            if phase == 'undefined' and not interrupted['done']:
                interrupted['done']=True; raise SystemExit('injected interruption')
            return real_advance(instance,operation,phase,**kwargs)
        with patch.object(self.lifecycle.store,'advance',side_effect=advance),self.assertRaises(SystemExit):
            self._recover(source)
        record=self.store.inspect('arch-test')
        self.assertEqual(record['journal'][-1]['phase'],'undefining')
        self.assertNotIn(record['domain_uuid'],self.backend.domains)
        self.assertTrue(self._recover(source)['removed'])

    def test_failed_create_cleanup_resumes_partial_file_removal(self):
        source,_=self._failed_create(); runtime=Path(self.data['storage']); real_unlink=os.unlink
        interrupted={'done':False}
        def unlink(path,*args,**kwargs):
            result=real_unlink(path,*args,**kwargs)
            if kwargs.get('dir_fd') is not None and not interrupted['done']:
                interrupted['done']=True; raise SystemExit('injected interruption')
            return result
        with patch('vm_dev_lab.lifecycle.os.unlink',side_effect=unlink),self.assertRaises(SystemExit):
            self._recover(source)
        record=self.store.inspect('arch-test')
        self.assertEqual(record['journal'][-1]['phase'],'removing_runtime')
        self.assertLess(len(list(runtime.iterdir())),len(RUNTIME_FILES))
        self.assertTrue(self._recover(source)['removed'])

    def test_failed_create_cleanup_rejects_unknown_file_during_resume(self):
        source,_=self._failed_create(); runtime=Path(self.data['storage']); real_unlink=os.unlink
        interrupted={'done':False}
        def unlink(path,*args,**kwargs):
            result=real_unlink(path,*args,**kwargs)
            if kwargs.get('dir_fd') is not None and not interrupted['done']:
                interrupted['done']=True; raise SystemExit
            return result
        with patch('vm_dev_lab.lifecycle.os.unlink',side_effect=unlink),self.assertRaises(SystemExit):
            self._recover(source)
        self._write(runtime/'foreign')
        with self.assertRaises(LabError) as caught: self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')

    def test_failed_create_cleanup_obeys_instance_lock(self):
        source,_=self._failed_create()
        with self.store.lock(self.record['instance_id']),self.assertRaises(LabError) as caught:
            self._recover(source)
        self.assertEqual(caught.exception.detail['code'],'LOCK_CONFLICT')

    def test_failed_start_is_preserved_and_recovered_by_new_operation(self):
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',side_effect=LabError(7,'GUEST_NOT_READY','readiness','timeout','inspect')):
            with self.assertRaises(LabError): self.lifecycle.start('arch-test',time.monotonic()+10)
        record=self.store.inspect('arch-test')
        self.assertTrue(record['requires_review']); self.assertEqual(record['journal'][-1]['phase'],'failed')
        failed=record['journal'][-1].copy()
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',return_value='192.0.2.10'), patch.object(
                self.lifecycle,'_project_readiness',return_value={}):
            result=self.lifecycle.start('arch-test',time.monotonic()+10)
        record=self.store.inspect('arch-test')
        self.assertEqual(result['lifecycle_state'],'ready')
        self.assertEqual(record['journal'][-2],failed)
        self.assertEqual((record['journal'][-1]['kind'],record['journal'][-1]['status']),
                         ('start_recovery','complete'))
        self.assertFalse(record['requires_review'])

    def test_recovery_rejects_inactive_domain_without_new_journal(self):
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',side_effect=LabError(7,'GUEST_NOT_READY','readiness','timeout','inspect')):
            with self.assertRaises(LabError): self.lifecycle.start('arch-test',time.monotonic()+10)
        self.domain.running=False
        before=self.store.inspect('arch-test')['journal']
        with self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test',time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'RECOVERY_STATE_CONFLICT')
        self.assertEqual(self.store.inspect('arch-test')['journal'],before)

    def test_recovery_ownership_mismatch_prevents_new_journal(self):
        with patch.object(self.lifecycle,'_host',return_value=self.plan), patch.object(
                self.lifecycle,'_readiness',side_effect=LabError(7,'GUEST_NOT_READY','readiness','timeout','inspect')):
            with self.assertRaises(LabError): self.lifecycle.start('arch-test',time.monotonic()+10)
        before=self.store.inspect('arch-test')['journal']
        runtime=Path(self.data['storage']); original=runtime/'work.qcow2'; original.rename(runtime/'replaced')
        self._write(original,b'foreign')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.start('arch-test',time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.assertEqual(self.store.inspect('arch-test')['journal'],before)

    def test_ssh_timeout_and_missing_client_are_classified(self):
        self.domain.running=True
        cases=((subprocess.TimeoutExpired(['ssh'],1),'DEADLINE_EXCEEDED'),
               (FileNotFoundError(),'SSH_CLIENT_MISSING'))
        for error,code in cases:
            with self.subTest(code=code):
                self.lifecycle.runner=Mock(side_effect=error)
                with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh']), \
                        self.assertRaises(LabError) as caught:
                    self.lifecycle.ssh('arch-test',time.monotonic()+10)
                self.assertEqual(caught.exception.detail['code'],code)

    def test_restart_readiness_retries_stale_lease_until_ssh_is_ready(self):
        self.domain.running=True
        owner=Mock()
        owner.verify.return_value=self.data
        attempts=[subprocess.CompletedProcess(['ssh'],255,b'',b''),
                  subprocess.CompletedProcess(['ssh'],0,b'',b'')]
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh']), \
                patch.object(self.lifecycle,'_run',side_effect=attempts) as run:
            address=self.lifecycle._readiness(self.store.inspect('arch-test'),owner,time.monotonic()+10,
                                              bootstrap_seed=False)
        self.assertEqual(address,'192.0.2.10')
        self.assertEqual(run.call_count,2)

    def _project_probe(self, guest, cloud=0, returncode=0):
        self.domain.running=True
        owner=RealOwnership(self.store,self.backend)
        output=f'{cloud}\n'.encode()+json.dumps(guest).encode()
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh']), patch.object(
                self.lifecycle,'_run',return_value=subprocess.CompletedProcess(['ssh'],returncode,output,b'')):
            return self.lifecycle._project_readiness(self.store.inspect('arch-test'),owner,
                                                     '192.0.2.10',time.monotonic()+10)

    def test_project_readiness_persists_versions_and_distinct_status(self):
        result=self._project_probe(guest_manifest())
        self.assertTrue(result['ssh_ready']); self.assertTrue(result['project_ready'])
        self.assertEqual(result['provisioning']['installed_packages']['git'],'2.51.0-1')
        self.assertEqual(self.lifecycle.status('arch-test')['readiness'],result)

    def test_package_failures_never_report_project_ready(self):
        cases=((guest_manifest(status='failed',error='PACKAGE_TRANSACTION_FAILED',installed={},transaction_exit=1),
                'PACKAGE_TRANSACTION_FAILED'),
               (guest_manifest(status='failed',error='PACKAGE_MISSING',installed={},transaction_exit=0),
                'PACKAGE_MISSING'))
        for value,code in cases:
            with self.subTest(code=code), self.assertRaises(LabError) as caught:
                self._project_probe(value,cloud=2)
            self.assertEqual(caught.exception.detail['code'],code)
            persisted=self.lifecycle.status('arch-test')['readiness']
            self.assertTrue(persisted['ssh_ready']); self.assertFalse(persisted['project_ready'])

    def test_invalid_guest_config_and_false_success_are_rejected(self):
        invalid=guest_manifest(status='failed',error='USER_SSH_INVALID',installed={},
                               user_valid=False,password_authentication=False,transaction_exit=None)
        with self.assertRaises(LabError) as caught: self._project_probe(invalid,cloud=2)
        self.assertEqual(caught.exception.detail['code'],'GUEST_CONFIG_INVALID')
        with self.assertRaises(LabError) as caught:
            self._project_probe(guest_manifest(status='provisioning',installed={},transaction_exit=None))
        self.assertEqual(caught.exception.detail['code'],'PROJECT_NOT_READY')

    def test_project_timeout_disconnect_and_invalid_report_are_classified(self):
        self.domain.running=True; owner=RealOwnership(self.store,self.backend); record=self.store.inspect('arch-test')
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh']), patch.object(
                self.lifecycle,'_run',side_effect=LabError(7,'TOOL_TIMEOUT','verification','timeout','inspect')):
            with self.assertRaises(LabError) as caught:
                self.lifecycle._project_readiness(record,owner,'192.0.2.10',time.monotonic()+10)
        self.assertEqual(caught.exception.detail['code'],'PROVISIONING_TIMEOUT')
        with self.assertRaises(LabError) as caught: self._project_probe(guest_manifest(),returncode=255)
        self.assertEqual(caught.exception.detail['code'],'SSH_TRANSPORT_FAILED')
        with self.assertRaises(LabError) as caught: self._project_probe({'not':'a manifest'})
        self.assertEqual(caught.exception.detail['code'],'GUEST_MANIFEST_INVALID')

    @staticmethod
    def _exec_response(request, code=0, *, state='completed', started=True,
                       stdout=b'out', stderr=b'err'):
        def stream(value):
            import base64
            return {'encoding':'base64','data':base64.b64encode(value).decode(),
                    'bytes_total':len(value),'bytes_captured':len(value),
                    'bytes_returned':len(value),'truncated':False,'redacted':False}
        return encode_frame({
            'protocol_version':PROTOCOL_VERSION,'adapter_version':ADAPTER_VERSION,
            'job_id':request['job_id'],'state':state,'started':started,
            'pid':4321 if started else None,'pgid':4321 if started else None,
            'guest_exit_code':None if state == 'timed_out' else code,
            'stdout':stream(stdout),'stderr':stream(stderr)}, RESPONSE_LIMIT)

    def _exec(self, argv, runner):
        self.domain.running=True
        self._exec_ready()
        self.lifecycle.exec_runner=runner
        operation=str(uuid4())
        with patch('vm_dev_lab.lifecycle.ssh_arguments',
                   return_value=['ssh','-F','/dev/null','--','192.0.2.10']):
            result=self.lifecycle.exec('arch-test',argv,time.monotonic()+10,operation)
        return operation,result

    def _exec_ready(self):
        record=self.store.inspect('arch-test')
        if record['state'] != 'ready':
            operation=self.store.begin(record,'start')
            self.store.advance(record['instance_id'],operation,'booting')
            self.store.advance(record['instance_id'],operation,'ready',complete=True)

    def test_exec_preserves_argv_job_process_group_outputs_and_journal(self):
        argv=['python','-c','print(1)','space value',"quote'\"",'Gruesse-ä','','-x',
              'HOST_INJECTION_MARKER;$(false)']
        calls=[]
        def runner(arguments,payload,timeout,limit):
            request=decode_frame(payload,REQUEST_LIMIT); calls.append((arguments,request,timeout,limit))
            self.assertNotIn(argv[-1],arguments[-1])
            self.assertIn('-T',arguments)
            return ExchangeResult(0,self._exec_response(request,stdout=b'hello',stderr=b'warning'),b'')
        operation,result=self._exec(argv,runner)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][1]['argv'],argv)
        self.assertEqual(result['operation_id'],operation)
        self.assertEqual(result['outcome'],'completed')
        self.assertEqual((result['guest_pid'],result['guest_pgid']),(4321,4321))
        self.assertEqual(result['stdout']['bytes_returned'],5)
        journal=self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((journal['id'],journal['kind'],journal['phase']),
                         (operation,'exec','completed'))
        self.assertNotIn('argv',journal['exec'])
        logged=self.lifecycle.logs('arch-test',operation_id=operation)
        self.assertEqual(logged['selected_operation']['exec']['job_id'],result['job_id'])

    def test_exec_distinguishes_guest_255_transport_255_timeout_and_bad_protocol(self):
        def guest(arguments,payload,timeout,limit):
            request=decode_frame(payload,REQUEST_LIMIT)
            return ExchangeResult(0,self._exec_response(request,code=255),b'')
        _,result=self._exec(['false'],guest)
        self.assertEqual((result['outcome'],result['guest_exit_code'],result['ssh_exit_code']),
                         ('guest_failed',255,0))
        for exchange,outcome in (
                (ExchangeResult(255,b'',b'secret transport detail'),'transport_failed'),
                (ExchangeResult(-9,b'',b'',timed_out=True),'timed_out'),
                (ExchangeResult(0,b'bad frame',b''),'protocol_failed')):
            calls=Mock(return_value=exchange)
            _,result=self._exec(['true'],calls)
            self.assertEqual(result['outcome'],outcome)
            self.assertIsNone(result['guest_exit_code'])
            calls.assert_called_once()

    def test_exec_guest_timeout_preserves_bound_job_without_exitcode(self):
        def runner(arguments,payload,timeout,limit):
            request=decode_frame(payload,REQUEST_LIMIT)
            return ExchangeResult(0,self._exec_response(
                request,state='timed_out',stdout=b'partial',stderr=b''),b'')
        operation,result=self._exec(['sleep','99'],runner)
        self.assertEqual(result['outcome'],'timed_out')
        self.assertTrue(result['guest_started'])
        self.assertIsNone(result['guest_exit_code'])
        self.assertEqual(self.store.inspect('arch-test')['journal'][-1]['id'],operation)

    def test_exec_crash_leaves_nonblocking_unknown_job_and_never_retries(self):
        runner=Mock(side_effect=RuntimeError('simulated host process crash'))
        with self.assertRaises(RuntimeError): self._exec(['true'],runner)
        runner.assert_called_once()
        current=self.store.inspect('arch-test')
        self.assertFalse(current['requires_review'])
        self.assertEqual(current['journal'][-1]['phase'],'dispatched')
        self.assertEqual(current['journal'][-1]['exec']['outcome'],'dispatched')

    def test_exec_blocks_inactive_unready_reviewed_hostkey_and_ownership_targets(self):
        runner=Mock(side_effect=AssertionError('transport must not start'))
        self.lifecycle.exec_runner=runner
        operation=str(uuid4())
        with self.assertRaises(LabError) as caught:
            self.lifecycle.exec('arch-test',['true'],time.monotonic()+10,operation)
        self.assertEqual(caught.exception.detail['code'],'DOMAIN_NOT_RUNNING')
        runner.assert_not_called()

        self.domain.running=True
        self._exec_ready()
        original_uuid=self.domain._uuid; self.domain._uuid=str(uuid4())
        with self.assertRaises(LabError) as caught:
            self.lifecycle.exec('arch-test',['true'],time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.domain._uuid=original_uuid

        guest_path=self.paths.data/'instances'/self.record['instance_id']/'guest-manifest.json'
        original_guest=guest_path.read_bytes(); guest=json.loads(original_guest)
        guest['project_ready']=False; guest_path.write_text(json.dumps(guest))
        with self.assertRaises(LabError) as caught:
            self.lifecycle.exec('arch-test',['true'],time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'GUEST_NOT_READY')
        guest_path.write_bytes(original_guest)

        with patch('vm_dev_lab.lifecycle.ssh_arguments',
                   side_effect=LabError(5,'HOSTKEY_MISMATCH','ssh','mismatch','inspect')):
            with self.assertRaises(LabError) as caught:
                self.lifecycle.exec('arch-test',['true'],time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'HOSTKEY_MISMATCH')

        record=self.store.inspect('arch-test')
        failed=self.store.begin(record,'start')
        self.store.advance(record['instance_id'],failed,'booting')
        self.store.advance(record['instance_id'],failed,'failed',failed=True)
        with self.assertRaises(LabError) as caught:
            self.lifecycle.exec('arch-test',['true'],time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'REVIEW_REQUIRED')

    def test_exec_blocks_expired_deadline_and_runtime_symlink_before_transport(self):
        runner=Mock(side_effect=AssertionError('transport must not start'))
        self.lifecycle.exec_runner=runner
        self.domain.running=True
        self._exec_ready()
        with self.assertRaises(LabError) as caught:
            self.lifecycle.exec('arch-test',['true'],time.monotonic()-1,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'DEADLINE_EXCEEDED')
        runner.assert_not_called()

        serial=Path(self.data['storage'])/'serial.log'
        serial.unlink()
        serial.symlink_to(Path(self.data['storage'])/'disk.qcow2')
        with self.assertRaises(LabError) as caught:
            self.lifecycle.exec('arch-test',['true'],time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        runner.assert_not_called()

    @staticmethod
    def _file_response(request, *, ok=True, code=None, kind=None, files=None):
        if ok and request['action'] == 'cleanup':
            kind=None; files=None
        elif ok:
            kind = kind or request['kind']; files = files or request['files']
        return encode_frame({
            'protocol_version':FILE_PROTOCOL_VERSION,
            'adapter_version':FILE_ADAPTER_VERSION,
            'action':request['action'],'transfer_id':request['transfer_id'],
            'ok':ok,'code':code,'kind':kind if ok else None,
            'files':files if ok else None}, 128*1024)

    def test_copy_upload_uses_fixed_sftp_batch_manifest_and_journal(self):
        source=self.root/"project quote'ä"; source.mkdir(); (source/'a file').write_bytes(b'hello')
        self.domain.running=True; self._exec_ready(); controls=[]; sftp_calls=[]
        def control(arguments,payload,timeout,limit):
            request=decode_frame(payload,128*1024); controls.append((arguments,request))
            return ExchangeResult(0,self._file_response(request),b'')
        def sftp(arguments,payload,timeout,limit):
            sftp_calls.append((arguments,payload))
            self.assertNotIn(str(source).encode(),payload)
            return ExchangeResult(0,b'',b'')
        self.lifecycle.file_runner=control; self.lifecycle.sftp_runner=sftp
        operation=str(uuid4())
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh','--','192.0.2.10']), patch(
                'vm_dev_lab.lifecycle.sftp_arguments',return_value=['sftp','--','developer@192.0.2.10']):
            result=self.lifecycle.copy(str(source),'arch-test:/work tree',False,
                                       time.monotonic()+10,operation)
        self.assertEqual(result['outcome'],'completed')
        self.assertEqual((result['file_count'],result['total_bytes']),(1,5))
        self.assertEqual(len(sftp_calls),1); self.assertEqual(len(controls),3)
        self.assertEqual([item[1]['action'] for item in controls],
                         ['prepare-upload','finalize-upload','cleanup'])
        self.assertEqual((source/'a file').read_bytes(),b'hello')
        journal=self.store.inspect('arch-test')['journal'][-1]
        self.assertEqual((journal['kind'],journal['phase'],journal['id']),
                         ('copy','completed',operation))
        self.assertNotIn(str(source),json.dumps(journal))
        first=self.lifecycle.logs('arch-test',operation_id=operation)
        second=self.lifecycle.logs('arch-test',operation_id=operation)
        self.assertEqual(first['selected_operation']['transfer'],
                         second['selected_operation']['transfer'])

    def test_copy_download_is_explicit_and_binds_untrusted_manifest(self):
        self.domain.running=True; self._exec_ready(); finalized=[]
        manifest=[{'path':'result.bin','size':3,'sha256':'a'*64}]
        class Destination:
            def __init__(inner,*_args):
                inner.parent_fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
                inner.staging=str(self.root)
            def finalize(inner,kind,files): finalized.append((kind,files))
            def cleanup(inner,count): finalized.append(('cleanup',count))
            def close(inner): os.close(inner.parent_fd)
        def control(arguments,payload,timeout,limit):
            request=decode_frame(payload,128*1024)
            return ExchangeResult(0,self._file_response(
                request,kind='file',files=manifest),b'')
        self.lifecycle.file_runner=control
        self.lifecycle.sftp_runner=Mock(return_value=ExchangeResult(0,b'',b''))
        self.lifecycle.host_destination_factory=Destination
        operation=str(uuid4())
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh','--','192.0.2.10']), patch(
                'vm_dev_lab.lifecycle.sftp_arguments',return_value=['sftp','--','developer@192.0.2.10']):
            result=self.lifecycle.copy('arch-test:/results/result.bin',str(self.root/'out'),
                                       False,time.monotonic()+10,operation)
        self.assertEqual(result['direction'],'guest-to-host')
        self.assertEqual(result['files'],manifest)
        self.assertEqual(finalized,[('file',manifest)])
        self.lifecycle.sftp_runner.assert_called_once()

    def test_copy_transport_integrity_timeout_and_crash_never_retry(self):
        source=self.root/'source'; source.write_bytes(b'x')
        self.domain.running=True; self._exec_ready()
        def prepare(arguments,payload,timeout,limit):
            request=decode_frame(payload,128*1024)
            return ExchangeResult(0,self._file_response(request),b'')
        cases=(
            (Mock(return_value=ExchangeResult(255,b'',b'failure')),'transport_failed'),
            (Mock(return_value=ExchangeResult(-9,b'',b'',timed_out=True)),'timed_out'),
        )
        for runner,outcome in cases:
            self.lifecycle.file_runner=prepare; self.lifecycle.sftp_runner=runner
            with self.subTest(outcome=outcome), patch(
                    'vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh','--','192.0.2.10']), patch(
                    'vm_dev_lab.lifecycle.sftp_arguments',return_value=['sftp','--','developer@192.0.2.10']):
                result=self.lifecycle.copy(str(source),'arch-test:/target',False,
                                           time.monotonic()+10,str(uuid4()))
            self.assertEqual(result['outcome'],outcome); runner.assert_called_once()

        def integrity(arguments,payload,timeout,limit):
            request=decode_frame(payload,128*1024)
            if request['action']=='finalize-upload':
                return ExchangeResult(0,self._file_response(
                    request,ok=False,code='COPY_INTEGRITY_MISMATCH'),b'')
            return ExchangeResult(0,self._file_response(request),b'')
        self.lifecycle.file_runner=integrity
        self.lifecycle.sftp_runner=Mock(return_value=ExchangeResult(0,b'',b''))
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh','--','192.0.2.10']), patch(
                'vm_dev_lab.lifecycle.sftp_arguments',return_value=['sftp','--','developer@192.0.2.10']):
            result=self.lifecycle.copy(str(source),'arch-test:/target',False,
                                       time.monotonic()+10,str(uuid4()))
        self.assertEqual(result['outcome'],'integrity_failed')

        def no_space(arguments,payload,timeout,limit):
            request=decode_frame(payload,128*1024)
            if request['action']=='finalize-upload':
                return ExchangeResult(0,self._file_response(
                    request,ok=False,code='COPY_NO_SPACE'),b'')
            return ExchangeResult(0,self._file_response(request),b'')
        self.lifecycle.file_runner=no_space
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh','--','192.0.2.10']), patch(
                'vm_dev_lab.lifecycle.sftp_arguments',return_value=['sftp','--','developer@192.0.2.10']):
            result=self.lifecycle.copy(str(source),'arch-test:/target',False,
                                       time.monotonic()+10,str(uuid4()))
        self.assertEqual(result['outcome'],'file_failed')

        crash=Mock(side_effect=RuntimeError('simulated crash'))
        self.lifecycle.file_runner=crash
        with patch('vm_dev_lab.lifecycle.ssh_arguments',return_value=['ssh','--','192.0.2.10']), patch(
                'vm_dev_lab.lifecycle.sftp_arguments',return_value=['sftp','--','developer@192.0.2.10']), self.assertRaises(RuntimeError):
            self.lifecycle.copy(str(source),'arch-test:/target',False,
                                time.monotonic()+10,str(uuid4()))
        crash.assert_called_once()
        self.assertEqual(self.store.inspect('arch-test')['journal'][-1]['phase'],'dispatched')

    def test_copy_blocks_inactive_foreign_unready_hostkey_and_reviewed_vm(self):
        source=self.root/'source'; source.write_bytes(b'x')
        runner=Mock(side_effect=AssertionError('transport must not start'))
        self.lifecycle.file_runner=runner; self.lifecycle.sftp_runner=runner
        with self.assertRaises(LabError) as caught:
            self.lifecycle.copy(str(source),'arch-test:/target',False,
                                time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'DOMAIN_NOT_RUNNING')
        self.domain.running=True; self._exec_ready()
        original=self.domain._uuid; self.domain._uuid=str(uuid4())
        with self.assertRaises(LabError) as caught:
            self.lifecycle.copy(str(source),'arch-test:/target',False,
                                time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'OWNERSHIP_MISMATCH')
        self.domain._uuid=original
        guest_path=self.paths.data/'instances'/self.record['instance_id']/'guest-manifest.json'
        raw=guest_path.read_bytes(); guest=json.loads(raw); guest['project_ready']=False
        guest_path.write_text(json.dumps(guest))
        with self.assertRaises(LabError) as caught:
            self.lifecycle.copy(str(source),'arch-test:/target',False,
                                time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'GUEST_NOT_READY')
        guest_path.write_bytes(raw)
        with patch('vm_dev_lab.lifecycle.ssh_arguments',
                   side_effect=LabError(5,'HOSTKEY_MISMATCH','ssh','mismatch','inspect')):
            with self.assertRaises(LabError) as caught:
                self.lifecycle.copy(str(source),'arch-test:/target',False,
                                    time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'HOSTKEY_MISMATCH')
        record=self.store.inspect('arch-test'); failed=self.store.begin(record,'start')
        self.store.advance(record['instance_id'],failed,'booting')
        self.store.advance(record['instance_id'],failed,'failed',failed=True)
        with self.assertRaises(LabError) as caught:
            self.lifecycle.copy(str(source),'arch-test:/target',False,
                                time.monotonic()+10,str(uuid4()))
        self.assertEqual(caught.exception.detail['code'],'REVIEW_REQUIRED')
        runner.assert_not_called()


if __name__=='__main__': unittest.main()
