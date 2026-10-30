# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Run a bounded report-only two-VM boot acceptance harness.

"""Historical bounded two-VM boot harness; no VM management."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import time
import uuid

from vm_dev_lab.guest.ssh import bootstrap, client_identity, public_key, ssh_arguments, MARKER
from vm_dev_lab.state import StatePaths, StateStore, directory
from vm_dev_lab.testing import spike_exit_code

ROOT=Path.cwd()
BASE_SPEC=importlib.util.spec_from_file_location(
    'p05_single', ROOT/'tests/harnesses/single_vm_boot.py')
p05=importlib.util.module_from_spec(BASE_SPEC); BASE_SPEC.loader.exec_module(p05)
IMAGE=p05.IMAGE; NET=p05.NET; NETID=p05.NETID; POOLID=p05.POOLID; URI=p05.URI
VCPU=1; MEMORY_MIB=1024; DISK_GIB=15
MEM_BEFORE=10*1024**3; MEM_RESERVE=8*1024**3; STORAGE_BEFORE=80*1024**3
ACTUAL_LIMIT=40*1024**3; TEST_SECONDS=1800; SHUTDOWN_SECONDS=120
NAMES=('p05-stage-b-vm1','p05-stage-b-vm2')


def require(value,message): p05.require(value,message)
def available_memory():
    return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                    if line.startswith('MemAvailable:')))*1024
def actual_bytes(root):
    return sum(path.stat(follow_symlinks=False).st_blocks*512 for path in Path(root).rglob('*')
               if path.is_file() and not path.is_symlink())


def validate_plan(report):
    run_id=report.get('run_id')
    require(str(uuid.UUID(run_id))==run_id,'Invalid run ID')
    guests=report.get('guests')
    require(isinstance(guests,list) and len(guests)==2,'Exactly two guests are required')
    require(tuple(item.get('name') for item in guests)==NAMES,'Unexpected domain names')
    identities=[item.get('domain_uuid') for item in guests]
    require(len(set(identities))==2 and all(str(uuid.UUID(value))==value for value in identities),
            'Domain UUIDs are missing or collide')
    run_storage=Path('/var/lib/libvirt/vm-dev-lab-desktop')/run_id
    for index,item in enumerate(guests,1):
        require(item.get('vcpus')==VCPU and item.get('memory_mib')==MEMORY_MIB and
                item.get('disk_gib')==DISK_GIB,'Resource limit differs')
        require(item.get('storage_path')==str(run_storage/f'vm{index}'),'Storage path differs')
    require(report.get('deadline_epoch',0)>time.time(),'Test deadline expired')
    return run_id,guests,run_storage


def prepare_guest(item,run_id,run_storage,store,connection,record,operation):
    from vm_dev_lab.config import ConfigLoader
    from vm_dev_lab.provisioning.cloudinit import render_seed, write_seed_iso
    instance=record['instance_id']
    store.advance(instance,operation,'allocating')
    private=store.paths.data/'instances'/instance
    with directory(private,create=True): pass
    store.update(instance,operation,lambda current: current.update(directory=p05.identities(private)))
    identity=client_identity(store.paths.data.parent/'clients',instance)
    public=(identity/'id_ed25519.pub').read_text().strip()
    profile_name=f'p05-two-{run_id}-{item["name"][-3:]}'
    profile_path=ROOT/'local/profiles'/f'{profile_name}.yaml'
    config={'schema_version':1,'ready':True,'vm':{
        'name':item['name'],'guest_os':'arch',
        'base_image':{'path':str(ROOT/'local/p05-image-cache'/IMAGE/'image.qcow2'),'sha256':IMAGE},
        'cpus':VCPU,'memory_mib':MEMORY_MIB,'disk_gib':DISK_GIB,
        'network':{'name':NET},'ssh':{'user':'developer','public_keys':[public]}}}
    p05.write_new(profile_path,json.dumps(config).encode())
    profile_identity=p05.identities(profile_path); profile_hash=p05.sha(profile_path)
    resolved=ConfigLoader(ROOT/'local').load(profile_name)
    require(resolved.complete,'Profile is incomplete')
    mac='52:54:00:'+':'.join(f'{value:02x}' for value in secrets.token_bytes(3))
    require(not any(mac in domain.XMLDesc(0) for domain in connection.listAllDomains(0)),
            'MAC conflict')
    seed=render_seed(resolved,store.inspect(instance),[public],network_mac=mac)
    for name,value in (('user-data',seed.user_data),('meta-data',seed.meta_data),
                       ('network-config',seed.network_config)):
        p05.write_new(private/name,value.encode())
    storage=Path(item['storage_path']); os.mkdir(storage,0o770)
    source=ROOT/'local/p05-image-cache'/IMAGE/'image.qcow2'
    require(p05.sha(source)==IMAGE,'Cache changed')
    with open(source,'rb') as incoming:
        fd=os.open(storage/'base.qcow2',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o440)
        with os.fdopen(fd,'wb') as output:
            shutil.copyfileobj(incoming,output); output.flush(); os.fsync(output.fileno())
    p05.write_new(storage/'work.qcow2',b'',0o660)
    result=p05.timed(['qemu-img','create','-f','qcow2','-F','qcow2','-b',
                      str(storage/'base.qcow2'),str(storage/'work.qcow2'),f'{DISK_GIB}G'])
    require(result.returncode==0,result.stderr.decode(errors='replace'))
    p05.write_new(storage/'nvram.fd',Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd').read_bytes(),0o660)
    def seed_tool(argv):
        result=p05.timed(argv); return result.returncode,result.stdout
    write_seed_iso(seed,private/'seed.iso',runner=seed_tool)
    private_seed_identity=p05.identities(private/'seed.iso')
    p05.write_new(storage/'seed.iso',(private/'seed.iso').read_bytes(),0o440)
    p05.write_new(storage/'serial.log',b'',0o660)
    data={'run_id':run_id,'domain_uuid':item['domain_uuid'],'instance_id':instance,
          'root':str(storage),'directory':p05.identities(storage),
          'files':{name:p05.identities(storage/name) for name in p05.FILES},'mac':mac}
    manifest_file=private/'runtime-manifest.json'; p05.write_new(manifest_file,json.dumps(data).encode())
    ownership=p05.Ownership(store,record,operation,manifest_file,
                            domain_uuid=item['domain_uuid'],run_id=run_id,
                            storage=storage,name=item['name'])
    ownership.files()
    xml=p05.specification(store.inspect(instance),mac,name=item['name'],
                          domain_uuid=item['domain_uuid'],storage=storage)
    p05.write_new(private/'domain.xml',xml.encode())
    domain=connection.defineXML(xml); ownership.verify(store.inspect(instance),domain)
    store.advance(instance,operation,'defined')
    return dict(item=item,record=record,operation=operation,instance=instance,private=private,
                identity=identity,profile_path=profile_path,profile_identity=profile_identity,
                profile_hash=profile_hash,mac=mac,seed=seed,storage=storage,
                manifest_file=manifest_file,ownership=ownership,domain=domain,
                private_seed_identity=private_seed_identity,address=None,serial='',ssh_args=None)


def cleanup_guest(guest,store,success,report):
    ownership=guest['ownership']; domain=guest['domain']; instance=guest['instance']
    ownership.files(); serial_data=(guest['storage']/'serial.log').read_bytes()
    require(len(serial_data)<=1024*1024,'Serielles Diagnoselimit')
    diagnostic=guest['private']/'serial-diagnostic.log'
    if not diagnostic.exists(): p05.write_new(diagnostic,serial_data)
    ownership.verify(store.inspect(instance),domain)
    if success:
        current=store.inspect(instance); shutdown=store.begin(current,'shutdown')
        store.advance(instance,shutdown,'defined',complete=True)
        current=store.inspect(instance); operation=store.begin(current,'destroy')
        ownership.operation=operation; guest['operation']=operation
    ownership.verify(store.inspect(instance),domain)
    domain.undefineFlags(p05.libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
    data=json.loads(guest['manifest_file'].read_text())
    if not (guest['storage']/'nvram.fd').exists():
        p05.write_new(guest['private']/'nvram-removed-by-libvirt',
                      b'owned NVRAM removed by undefine\n')
        data['files'].pop('nvram.fd')
    for name,identity in data['files'].items():
        require(p05.identities(guest['storage']/name)==identity,'Cleanup identity differs')
    require(set(path.name for path in guest['storage'].iterdir())==set(data['files']),
            'Foreign cleanup paths')
    for name in data['files']: os.unlink(guest['storage']/name)
    os.rmdir(guest['storage'])
    with directory(guest['private']) as fd:
        require(p05.identities(guest['private']/'seed.iso')==guest['private_seed_identity'],
                'Private seed was replaced')
        os.unlink('seed.iso',dir_fd=fd)
    with directory(guest['identity']) as fd:
        allowed={'id_ed25519','id_ed25519.pub','known_hosts'}
        require(set(path.name for path in guest['identity'].iterdir())<=allowed,
                'Unknown client files')
        for path in list(guest['identity'].iterdir()): os.unlink(path.name,dir_fd=fd)
    os.rmdir(guest['identity'])
    require(p05.identities(guest['profile_path'])==guest['profile_identity'] and
            p05.sha(guest['profile_path'])==guest['profile_hash'],'Temporary profile changed')
    os.unlink(guest['profile_path'])
    if success:
        store.advance(instance,guest['operation'],'undefined')
        store.advance(instance,guest['operation'],'destroyed',complete=True)
    else:
        store.advance(instance,guest['operation'],'failed',failed=True)
    report['cleanup'][guest['item']['name']]={'domain_removed':True,'runtime_files_removed':True,
                                               'client_identity_removed':True,'profile_removed':True}


def run_approved_spike():
    import libvirt
    from vm_dev_lab.libvirt_backend import domain_capabilities
    p05.libvirt=libvirt
    report_path=Path(args.report); report=json.loads(report_path.read_text())
    run_id,items,run_storage=validate_plan(report)
    p05.deadline=report['deadline_epoch']
    require(any(step.get('phase')=='image-verification' and step.get('ok')
                for step in report.get('steps',[])),'Image not verified')
    require(report.get('firmware_hashes')=={
        'code':p05.sha('/usr/share/edk2/x64/OVMF_CODE.4m.fd'),
        'vars':p05.sha('/usr/share/edk2/x64/OVMF_VARS.4m.fd')},'Firmware changed')
    require(available_memory()>=MEM_BEFORE,'Less than 10 GiB MemAvailable before allocation')
    require(shutil.disk_usage(run_storage.parent).free>=STORAGE_BEFORE,'Less than 80 GiB of free storage')
    require(not run_storage.exists(),'Run storage already exists')
    store_root=ROOT/'local/p05-two-runs'/run_id/'private'
    require(not store_root.exists(),'Run registry already exists')
    require(not list(Path('/etc/libvirt/qemu/autostart').iterdir()),'Foreign domain autostart')
    connection=libvirt.open(URI); p05.connection=connection
    existing=connection.listAllDomains(0)
    require(not any(domain.name() in NAMES or domain.UUIDString() in {i['domain_uuid'] for i in items}
                    for domain in existing),'Test domain already exists')
    capabilities=connection.getDomainCapabilities(None,'x86_64','q35','kvm',0)
    require(domain_capabilities(capabilities,'/usr/share/edk2/x64/OVMF_CODE.4m.fd'),
            'UEFI capabilities differ')
    p05.write_new(report_path.parent/'domain-capabilities.xml',capabilities.encode())
    for resource in (connection.networkLookupByUUIDString(NETID),
                     connection.storagePoolLookupByUUIDString(POOLID)):
        require(resource.isActive()==1 and resource.autostart()==1,'Lab resource changed')
    paths=StatePaths(store_root/'data',store_root/'state',store_root/'runtime')
    store=StateStore(paths); store.initialize()
    (ROOT/'local/profiles').mkdir(exist_ok=True)
    os.mkdir(run_storage,0o770)
    guests=[]; success=False
    report['cleanup']={}
    reservations=[]
    for item in items:
        record=store.reserve(item['name']); operation=record['journal'][-1]['id']
        store.update(record['instance_id'],operation,
                     lambda current,identity=item['domain_uuid']: current.update(domain_uuid=identity))
        reservations.append((item,store.inspect(record['instance_id']),operation))
    locks=ExitStack()
    for instance in sorted(record['instance_id'] for _,record,_ in reservations):
        locks.enter_context(store.lock(instance))
    try:
        for item,record,operation in reservations:
            guests.append(prepare_guest(item,run_id,run_storage,store,connection,record,operation))
            require(actual_bytes(run_storage)<=ACTUAL_LIMIT,'Actual run allocation exceeds 40 GiB')
        if True:
            for guest in guests:
                require(available_memory()>=MEM_BEFORE,'Less than 10 GiB MemAvailable before VM start')
                guest['ownership'].verify(store.inspect(guest['instance']),guest['domain'])
                guest['domain'].create()
                store.advance(guest['instance'],guest['operation'],'booting')
                store.advance(guest['instance'],guest['operation'],'provisioning')
            require(available_memory()>=MEM_RESERVE,'Less than 8 GiB of host reserve after VM starts')
            ready_deadline=min(time.time()+600,p05.deadline)
            network=connection.networkLookupByUUIDString(NETID)
            while time.time()<ready_deadline:
                require(available_memory()>=MEM_RESERVE,'Host reserve fell below the limit during bootstrap')
                all_ready=True
                for guest in guests:
                    guest['ownership'].verify(store.inspect(guest['instance']),guest['domain'])
                    require(guest['domain'].isActive()==1,'Guest terminated unexpectedly')
                    require((guest['storage']/'serial.log').stat().st_size<=1024*1024,
                            'Serial log limit')
                    guest['serial']=(guest['storage']/'serial.log').read_text(errors='replace')
                    leases=network.DHCPLeases(guest['mac'],0)
                    ipv4=[row['ipaddr'] for row in leases
                          if row.get('type')==libvirt.VIR_IP_ADDR_TYPE_IPV4]
                    if MARKER in guest['serial'] and len(set(ipv4))==1:
                        guest['address']=ipv4[0]
                    else: all_ready=False
                if all_ready: break
                time.sleep(1)
            require(all(guest['address'] for guest in guests),'Readiness or DHCP deadline')
            require(len({guest['address'] for guest in guests})==2,'DHCP addresses are ambiguous')
            for guest in guests:
                scan=p05.timed(['ssh-keyscan','-T','5','-t','ed25519',guest['address']],10)
                require(scan.returncode==0,'No network host key')
                keys=[public_key(' '.join(line.split()[1:]))[0]
                      for line in scan.stdout.decode().splitlines() if line and not line.startswith('#')]
                require(len(set(keys))==1,'Ambiguous network host key')
                result=bootstrap(guest['ownership'],p05.Backend(guest['item']['domain_uuid']),
                    guest['seed'].binding,
                    lambda identity,limit,g=guest:(g['ownership'].verify(
                        store.inspect(g['instance']),connection.lookupByUUIDString(identity)),g['serial'])[1],
                    keys[0],guest['identity'])
                guest['ssh_args']=ssh_arguments(guest['identity'],guest['instance'],
                                                guest['address'],'developer')
                status=p05.timed(guest['ssh_args']+['cloud-init status --wait'],120)
                require(status.returncode==0 and b'status: done' in status.stdout,'Cloud-init is not complete')
                proof=p05.timed(guest['ssh_args']+['printf P05_TWO_VM_READY'],20)
                require(proof.returncode==0 and proof.stdout==b'P05_TWO_VM_READY','SSH evidence')
                guest['bootstrap']=result
            vm1,vm2=guests
            report['vm_connectivity']={
                f'{vm1["item"]["name"]}_to_{vm2["item"]["name"]}':
                    p05.guest_tcp(vm1['ssh_args'],'VM1 to VM2 failed',vm2['address'],(22,)),
                f'{vm2["item"]["name"]}_to_{vm1["item"]["name"]}':
                    p05.guest_tcp(vm2['ssh_args'],'VM2 to VM1 failed',vm1['address'],(22,)),
            }
            require(actual_bytes(run_storage)<=ACTUAL_LIMIT,'Actual run allocation exceeds 40 GiB')
            report['actual_runtime_bytes']=actual_bytes(run_storage)
            report['mem_available_during_bytes']=available_memory()
            for guest in guests:
                store.advance(guest['instance'],guest['operation'],'ready',complete=True)
            report['guest_results']=[dict(name=guest['item']['name'],
                domain_uuid=guest['item']['domain_uuid'],instance_id=guest['instance'],
                mac=guest['mac'],ipv4=guest['address'],bootstrap=guest['bootstrap'],
                cloud_init='status: done',ssh_ready=True) for guest in guests]
            success=True
    except Exception as error:
        report['spike_error']={'type':type(error).__name__,'message':str(error)}
    finally:
        try:
            for guest in guests:
                if guest.get('domain') is not None:
                    guest['ownership'].verify(store.inspect(guest['instance']),guest['domain'])
                    if guest['domain'].isActive(): guest['domain'].shutdown()
            stop=time.time()+SHUTDOWN_SECONDS
            while any(guest['domain'].isActive() for guest in guests) and time.time()<stop:
                time.sleep(1)
            for guest in guests:
                if guest['domain'].isActive():
                    guest['ownership'].verify(store.inspect(guest['instance']),guest['domain'])
                    guest['domain'].destroy()
            for guest in guests: cleanup_guest(guest,store,success,report)
            if run_storage.exists(): os.rmdir(run_storage)
            report.update(domain_removed=len(report['cleanup'])==2,
                          runtime_files_removed=len(report['cleanup'])==2,
                          client_identity_removed=len(report['cleanup'])==2,
                          cleanup_ok=len(report['cleanup'])==2)
        except Exception as cleanup:
            report['cleanup_error']={'type':type(cleanup).__name__,'message':str(cleanup)}
        report['spike_ok']=success; report['completed_epoch']=time.time()
        report_path.write_text(json.dumps(report,indent=2)+'\n')
        locks.close()
        connection.close()
    return report


def main(argv=None):
    import argparse
    global args
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--report-only',type=Path)
    mode.add_argument('--run-approved-spike',action='store_true')
    parser.add_argument('--report',type=Path)
    args=parser.parse_args(argv)
    if args.report_only:
        require(args.report is None,'Report path specified twice')
        report=json.loads(args.report_only.read_text())
    else:
        require(args.report is not None,'--report is required for the real run')
        report=run_approved_spike()
    code=spike_exit_code(report)
    print(json.dumps({'exit_code':code,'test_and_cleanup_passed':code==0}))
    return code


if __name__=='__main__': raise SystemExit(main())
