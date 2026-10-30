# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Run a bounded report-only single-VM boot acceptance harness.

"""Historical bounded single-VM boot harness; no VM management."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shlex
import shutil
import stat
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from vm_dev_lab.state import StateStore, StatePaths, directory, private_file
from vm_dev_lab.guest.ssh import client_identity, bootstrap, ssh_arguments, public_key, MARKER
from vm_dev_lab.testing import spike_exit_code

ROOT=Path.cwd(); REPORT=ROOT/'local/p05-real-report.json'
RUN='03b9fac2-744d-414a-9c75-44124734b794'; DOMAIN='854180f4-c272-417f-b2c9-7c70ba7ef403'; NAME='p05-arch-bootstrap-01'
IMAGE='08754e28d91b1680086c6211ef4df13559e766fff7cdb4006489b14b5d281f08'
NET='vm-dev-lab-desktop-nat'; NETID='f5a7cb75-8bb6-4c13-9e80-a69502b7d0da'; POOLID='4eeab8ed-f150-4d2f-8cd0-76f4d6be3e5c'
NS='https://vm-dev-lab.invalid/p05-owner/v1'; URI='qemu:///system'
VCPU=1; MEMORY_MIB=1024; DISK_GIB=15
STORE_ROOT=ROOT/'local/p05-private'; STORAGE=Path('/var/lib/libvirt/vm-dev-lab-desktop')/RUN
FILES=('base.qcow2','work.qcow2','nvram.fd','seed.iso','serial.log')

def configure_run(run_id):
    """Create a new explicit run identity; never repurpose historical files."""
    global RUN, REPORT, STORE_ROOT, STORAGE
    if str(uuid.UUID(run_id))!=run_id or run_id=='03b9fac2-744d-414a-9c75-44124734b794':
        raise ValueError('A new canonical run UUID is required; the historical run remains locked')
    RUN=run_id
    REPORT=ROOT/'local/p05-runs'/RUN/'report.json'
    STORE_ROOT=ROOT/'local/p05-runs'/RUN/'private'
    STORAGE=Path('/var/lib/libvirt/vm-dev-lab-desktop')/RUN

def require(ok,message):
    if not ok: raise RuntimeError(message)
def write_new(path,data,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def timed(args,seconds=20):
    require(time.time()<deadline,'Overall deadline exceeded')
    result=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=min(seconds,max(1,deadline-time.time())))
    require(len(result.stdout)+len(result.stderr)<=1024*1024,'Output limit')
    return result

def guest_tcp(args,label,host,ports):
    """Bounded outbound TCP evidence from the guest without a host listener."""
    script=("import socket,sys; host=sys.argv[1]; ports=[int(v) for v in sys.argv[2:]]; "
            "errors=[]; "
            "\nfor port in ports:\n"
            " try:\n  socket.create_connection((host,port),5).close(); print(f'{host}:{port}'); sys.exit(0)\n"
            " except OSError as error: errors.append(f'{port}:{error}')\n"
            "print('; '.join(errors),file=sys.stderr); sys.exit(1)")
    command='python -c '+shlex.quote(script)+' '+shlex.join([host,*[str(port) for port in ports]])
    result=timed(args+[command],20)
    require(result.returncode==0,label+': '+result.stderr.decode(errors='replace'))
    return result.stdout.decode().strip()

def identities(path):
    info=os.lstat(path)
    require(not stat.S_ISLNK(info.st_mode),'Symlink rejected')
    return dict(device=info.st_dev,inode=info.st_ino)

def runtime_uids():
    """The caller and the libvirt QEMU account configured on this host."""
    allowed={os.geteuid()}
    try: allowed.add(pwd.getpwnam('libvirt-qemu').pw_uid)
    except KeyError: pass
    return allowed

class Ownership:
    """P03 registry, locks, and journal with an owned real path manifest.

    StateStore.selection intentionally remains fixture-only; real files receive
    additional positive checks, without renamed fixtures or fake domains.
    """
    def __init__(self,store,record,operation,manifest_file,*,domain_uuid=DOMAIN,run_id=RUN,
                 storage=STORAGE,name=NAME):
        self.store=store; self.id=record['instance_id']; self.operation=operation; self.manifest_file=manifest_file
        self.domain_uuid=domain_uuid; self.run_id=run_id; self.storage=Path(storage); self.name=name
    def inspect(self,target): return self.store.inspect(target)
    def files(self):
        with directory(self.manifest_file.parent):
            fd=os.open(self.manifest_file,os.O_RDONLY|os.O_NOFOLLOW)
            try: private_file(fd); data=json.loads(os.read(fd,65537))
            finally: os.close(fd)
        require(data['instance_id']==self.id and data['domain_uuid']==self.domain_uuid and
                data['run_id']==self.run_id,'Manifest identity')
        require(data['root']==str(self.storage) and data['directory']==identities(self.storage),'Runtime directory was replaced')
        require(set(data['files'])==set(FILES) and set(p.name for p in self.storage.iterdir())==set(FILES),'Unknown runtime files')
        for name,expected in data['files'].items():
            path=self.storage/name; info=os.lstat(path)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid in runtime_uids(),
                    'Unsafe runtime file')
            require(identities(path)==expected,'Runtime file was replaced')
        return data
    def verify(self,record,domain):
        self.store._registered(record,self.operation)
        data=self.files()
        require(domain.UUIDString()==self.domain_uuid and domain.name()==self.name and domain.autostart()==0,
                'Incorrect domain or autostart')
        root=ET.fromstring(domain.XMLDesc(0))
        marker=root.find('./metadata/{'+NS+'}owner')
        require(marker is not None and marker.attrib=={k:record[k] for k in ('lab_id','instance_id','domain_uuid')},'Domain metadata')
        paths=[d.find('source').get('file') for d in root.findall('./devices/disk')]
        require(sorted(paths)==sorted([str(self.storage/'work.qcow2'),str(self.storage/'seed.iso')]),'Disk paths differ')
        require(root.findtext('./os/nvram')==str(self.storage/'nvram.fd'),'NVRAM differs')
        require(root.find('./devices/serial/source').get('path')==str(self.storage/'serial.log'),'Serial path differs')
        nets=root.findall('./devices/interface')
        require(len(nets)==1 and nets[0].find('source').get('network')==NET,'Network differs')
        require(nets[0].find('mac').get('address')==data['mac'],'MAC differs')
        require(root.find('./devices/filesystem') is None and root.find('./devices/hostdev') is None,'Disallowed devices')
        return root

class Backend:
    def __init__(self,domain_uuid=DOMAIN): self.domain_uuid=domain_uuid
    def inspect(self,identity):
        require(identity==self.domain_uuid,'Foreign UUID')
        return connection.lookupByUUIDString(identity)

def specification(record,mac,*,name=NAME,domain_uuid=DOMAIN,storage=STORAGE):
    storage=Path(storage)
    root=ET.Element('domain',type='kvm'); ET.SubElement(root,'name').text=name; ET.SubElement(root,'uuid').text=domain_uuid
    meta=ET.SubElement(root,'metadata'); ET.SubElement(meta,'{'+NS+'}owner',{k:record[k] for k in ('lab_id','instance_id','domain_uuid')})
    ET.SubElement(root,'memory',unit='MiB').text=str(MEMORY_MIB); ET.SubElement(root,'vcpu').text=str(VCPU)
    osxml=ET.SubElement(root,'os'); ET.SubElement(osxml,'type',arch='x86_64',machine='q35').text='hvm'
    ET.SubElement(osxml,'loader',readonly='yes',type='pflash').text='/usr/share/edk2/x64/OVMF_CODE.4m.fd'
    ET.SubElement(osxml,'nvram').text=str(storage/'nvram.fd'); ET.SubElement(osxml,'boot',dev='hd')
    features=ET.SubElement(root,'features'); ET.SubElement(features,'acpi'); ET.SubElement(features,'apic')
    ET.SubElement(root,'cpu',mode='host-passthrough'); ET.SubElement(root,'on_poweroff').text='destroy'; ET.SubElement(root,'on_reboot').text='restart'
    devices=ET.SubElement(root,'devices'); ET.SubElement(devices,'emulator').text='/usr/bin/qemu-system-x86_64'
    for name,device,bus,target in [('work.qcow2','disk','virtio','vda'),('seed.iso','cdrom','sata','sda')]:
        disk=ET.SubElement(devices,'disk',type='file',device=device); ET.SubElement(disk,'driver',name='qemu',type='qcow2' if device=='disk' else 'raw')
        ET.SubElement(disk,'source',file=str(storage/name)); ET.SubElement(disk,'target',dev=target,bus=bus)
        if device=='cdrom': ET.SubElement(disk,'readonly')
    net=ET.SubElement(devices,'interface',type='network'); ET.SubElement(net,'mac',address=mac); ET.SubElement(net,'source',network=NET); ET.SubElement(net,'model',type='virtio')
    serial=ET.SubElement(devices,'serial',type='file'); ET.SubElement(serial,'source',path=str(storage/'serial.log'),append='on'); ET.SubElement(serial,'target',port='0')
    return ET.tostring(root,encoding='unicode')

def run_approved_spike():
    global connection, deadline, libvirt
    import libvirt
    from vm_dev_lab.config import ConfigLoader
    from vm_dev_lab.libvirt_backend import domain_capabilities
    from vm_dev_lab.provisioning.cloudinit import render_seed, write_seed_iso
    report=json.loads(REPORT.read_text()); deadline=report['deadline_epoch']
    require(time.time()<deadline,'Approved runtime expired')
    require(report['domain_uuid']==DOMAIN and report['run_id']==RUN,'Incorrect plan')
    require(any(s.get('phase')=='image-verification' and s.get('ok') for s in report['steps']),'No verified image')
    require(report.get('firmware_hashes')=={'code':sha('/usr/share/edk2/x64/OVMF_CODE.4m.fd'),'vars':sha('/usr/share/edk2/x64/OVMF_VARS.4m.fd')},'Firmware changed since preflight')
    require(not list(Path('/etc/libvirt/qemu/autostart').iterdir()),'Foreign domain autostart')
    mem=dict((k,int(v.split()[0])*1024) for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()) if k=='MemAvailable')
    require(mem['MemAvailable']>=6*1024**3 and shutil.disk_usage(STORAGE.parent).free>=80*1024**3,'Budget is insufficient')
    require(not STORAGE.exists() and not STORE_ROOT.exists(),'Run already exists; no retry')
    connection=libvirt.open(URI)
    require(not any(d.name()==NAME or d.UUIDString()==DOMAIN for d in connection.listAllDomains(0)),'Domain exists')
    capabilities=connection.getDomainCapabilities(None,'x86_64','q35','kvm',0)
    require(domain_capabilities(capabilities,'/usr/share/edk2/x64/OVMF_CODE.4m.fd'),'UEFI capabilities differ')
    write_new(REPORT.parent/'domain-capabilities.xml',capabilities.encode())
    report['steps'].append({'phase':'qemu-capabilities','ok':True})
    for obj in (connection.networkLookupByUUIDString(NETID),connection.storagePoolLookupByUUIDString(POOLID)):
        require(obj.isActive()==1 and obj.autostart()==1,'Desktop lab resource is inactive or changed')
    paths=StatePaths(STORE_ROOT/'data',STORE_ROOT/'state',STORE_ROOT/'runtime')
    store=StateStore(paths); store.initialize(); record=store.reserve(NAME); op=record['journal'][-1]['id']
    store.update(record['instance_id'],op,lambda current: current.update(domain_uuid=DOMAIN))
    record=store.inspect(record['instance_id']); instance=record['instance_id']; ownership=None; domain=None; success=False
    with store.lock(instance):
        try:
            store.advance(instance,op,'allocating')
            private=paths.data/'instances'/instance
            with directory(private,create=True): pass
            inode=identities(private); store.update(instance,op,lambda current: current.update(directory=inode))
            identity=client_identity(STORE_ROOT/'clients',instance)
            public=(identity/'id_ed25519.pub').read_text().strip()
            config_root=ROOT/'local'; (config_root/'profiles').mkdir(exist_ok=True)
            conf={'schema_version':1,'ready':True,'vm':{'name':NAME,'guest_os':'arch','base_image':{'path':str((ROOT/'local/p05-image-cache'/IMAGE/'image.qcow2')),'sha256':IMAGE},'cpus':VCPU,'memory_mib':MEMORY_MIB,'disk_gib':DISK_GIB,'network':{'name':NET},'ssh':{'user':'developer','public_keys':[public]}}}
            profile='p05-'+RUN
            profile_path=config_root/'profiles'/f'{profile}.yaml'
            write_new(profile_path,json.dumps(conf).encode())
            profile_identity=identities(profile_path); profile_hash=sha(profile_path)
            resolved=ConfigLoader(config_root).load(profile); require(resolved.complete,'Profile is incomplete')
            mac='52:54:00:'+':'.join(f'{v:02x}' for v in secrets.token_bytes(3))
            require(not any(mac in d.XMLDesc(0) for d in connection.listAllDomains(0)),'MAC conflict')
            seed=render_seed(resolved,store.inspect(instance),[public],network_mac=mac)
            write_new(private/'user-data',seed.user_data.encode()); write_new(private/'meta-data',seed.meta_data.encode())
            write_new(private/'network-config',seed.network_config.encode())
            os.mkdir(STORAGE,0o770)
            source=ROOT/'local/p05-image-cache'/IMAGE/'image.qcow2'
            require(sha(source)==IMAGE,'Cache changed')
            with open(source,'rb') as src:
                fd=os.open(STORAGE/'base.qcow2',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o440)
                with os.fdopen(fd,'wb') as out: shutil.copyfileobj(src,out); out.flush(); os.fsync(out.fileno())
            write_new(STORAGE/'work.qcow2',b'',0o660)
            r=timed(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(STORAGE/'base.qcow2'),str(STORAGE/'work.qcow2'),f'{DISK_GIB}G']); require(r.returncode==0,r.stderr.decode())
            write_new(STORAGE/'nvram.fd',Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd').read_bytes(),0o660)
            def seed_tool(argv):
                result=timed(argv)
                return result.returncode,result.stdout
            write_seed_iso(seed,private/'seed.iso',runner=seed_tool)
            private_seed_identity=identities(private/'seed.iso')
            write_new(STORAGE/'seed.iso',(private/'seed.iso').read_bytes(),0o440); write_new(STORAGE/'serial.log',b'',0o660)
            data={'run_id':RUN,'domain_uuid':DOMAIN,'instance_id':instance,'root':str(STORAGE),'directory':identities(STORAGE),'files':{name:identities(STORAGE/name) for name in FILES},'mac':mac}
            manifest_file=private/'runtime-manifest.json'; write_new(manifest_file,json.dumps(data).encode())
            ownership=Ownership(store,record,op,manifest_file); ownership.files()
            xml=specification(store.inspect(instance),mac); write_new(private/'domain.xml',xml.encode())
            print('Define exactly one test domain',flush=True)
            domain=connection.defineXML(xml); ownership.verify(store.inspect(instance),domain)
            store.advance(instance,op,'defined')
            available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
            require(available>=6*1024**3,'RAM reserve before boot is insufficient')
            require(time.time()<deadline,'Overall deadline'); domain.create(); store.advance(instance,op,'booting'); store.advance(instance,op,'provisioning')
            ready_deadline=min(time.time()+600,deadline); network=connection.networkLookupByUUIDString(NETID)
            address=None; serial=''
            while time.time()<ready_deadline:
                ownership.verify(store.inspect(instance),domain)
                require(domain.isActive()==1,'Guest terminated unexpectedly')
                require((STORAGE/'serial.log').stat().st_size<=1024*1024,'Serial log limit')
                serial=(STORAGE/'serial.log').read_text(errors='replace')
                leases=network.DHCPLeases(mac,0)
                ipv4=[row['ipaddr'] for row in leases if row.get('type')==libvirt.VIR_IP_ADDR_TYPE_IPV4]
                report['guest_ipv4_observed']=bool(ipv4)
                if MARKER in serial and len(set(ipv4))==1: address=ipv4[0]; break
                time.sleep(1)
            require(address is not None,'Readiness-/Fingerprintfrist')
            r=timed(['ssh-keyscan','-T','5','-t','ed25519',address],10); require(r.returncode==0,'No presented network key')
            keys=[public_key(' '.join(line.split()[1:]))[0] for line in r.stdout.decode().splitlines() if line and not line.startswith('#')]
            require(len(set(keys))==1,'Ambiguous network key')
            result=bootstrap(ownership,Backend(),seed.binding,lambda identity,limit:(ownership.verify(store.inspect(instance),connection.lookupByUUIDString(identity)),serial)[1],keys[0],identity)
            args=ssh_arguments(identity,instance,address,'developer')
            remaining=max(1,min(120,ready_deadline-time.time()))
            r=timed(args+['cloud-init status --wait'],remaining); require(r.returncode==0,'Cloud-init final status: '+r.stderr.decode()); report['cloud_init']=r.stdout.decode()
            r=timed(args+['printf P05_SSH_READY'],20); require(r.returncode==0 and r.stdout==b'P05_SSH_READY','SSH evidence')
            report['connectivity']={
                'host_to_vm':'authenticated-ssh',
                'vm_to_host':guest_tcp(args,'VM to host failed','192.168.123.1',(53,)),
                'vm_to_internet':guest_tcp(args,'VM to internet failed','1.1.1.1',(443,)),
                'vm_to_lan':guest_tcp(args,'VM to LAN failed','192.168.100.250',(80,443)),
            }
            before=sha(identity/'known_hosts'); mismatch=identity/'mismatch_known_hosts'; write_new(mismatch,('vm-dev-lab-'+instance+' '+public_key(public)[0]+'\n').encode())
            bad=[value.replace(str(identity/'known_hosts'),str(mismatch)) for value in args]
            r=timed(bad+['true'],20); require(r.returncode==255 and b'Host key verification failed' in r.stderr,'Host-key mismatch was not established')
            require(sha(identity/'known_hosts')==before,'Valid pin changed')
            store.advance(instance,op,'ready',complete=True)
            report['bootstrap']=result; report['ssh_ready']=True; report['hostkey_mismatch_rejected']=True; success=True
        except Exception as error:
            report['spike_error']={'type':type(error).__name__,'message':str(error)}
            print('SPIKE ERROR:',type(error).__name__,str(error),flush=True)
        finally:
            try:
                if domain is None and ownership is not None:
                    try: domain=connection.lookupByUUIDString(DOMAIN)
                    except libvirt.libvirtError as missing:
                        require(missing.get_error_code()==libvirt.VIR_ERR_NO_DOMAIN,'Domainzustand unklar')
                if ownership is not None:
                    ownership.files()
                    serial_data=(STORAGE/'serial.log').read_bytes()
                    require(len(serial_data)<=1024*1024,'Serial log limit during diagnostics')
                    write_new(private/'serial-diagnostic.log',serial_data)
                if domain is not None:
                    ownership.verify(store.inspect(instance),domain)
                    if domain.isActive():
                        domain.shutdown(); stop=time.time()+120
                        while domain.isActive() and time.time()<stop: time.sleep(1)
                        if domain.isActive(): ownership.verify(store.inspect(instance),domain); domain.destroy()
                    ownership.verify(store.inspect(instance),domain)
                    if success:
                        rec=store.inspect(instance); shutdown=store.begin(rec,'shutdown'); store.advance(instance,shutdown,'defined',complete=True)
                        rec=store.inspect(instance); op=store.begin(rec,'destroy'); ownership.operation=op
                    ownership.verify(store.inspect(instance),domain); domain.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
                    report['domain_removed']=True
                if ownership is not None:
                    # libvirt may already remove exactly the registered NVRAM on undefine.
                    if not (STORAGE/'nvram.fd').exists() and report.get('domain_removed'):
                        write_new(private/'nvram-removed-by-libvirt',b'owned NVRAM removed by undefine\n')
                        data=json.loads(manifest_file.read_text()); data['files'].pop('nvram.fd')
                        for name,item in data['files'].items(): require(identities(STORAGE/name)==item,'Cleanup identity differs')
                        require(set(p.name for p in STORAGE.iterdir())==set(data['files']),'Foreign cleanup paths')
                        names=list(data['files'])
                    else: ownership.files(); names=list(FILES)
                    require(identities(STORAGE)==data['directory'],'Directory was replaced')
                    for name in names: os.unlink(STORAGE/name)
                    os.rmdir(STORAGE); report['runtime_files_removed']=True
                if 'private_seed_identity' in locals():
                    with directory(private) as fd:
                        require(identities(private/'seed.iso')==private_seed_identity,'Private seed ISO was replaced')
                        os.unlink('seed.iso',dir_fd=fd)
                    report['private_seed_iso_removed']=True
                if ownership is None: require(not STORAGE.exists(),'Incomplete staging without a complete manifest; targeted review is required')
                if 'identity' in locals():
                    with directory(identity) as fd:
                        allowed={'id_ed25519','id_ed25519.pub','known_hosts','mismatch_known_hosts'}
                        require(set(p.name for p in identity.iterdir())<=allowed,'Unknown client files')
                        for name in list(identity.iterdir()): os.unlink(name.name,dir_fd=fd)
                    os.rmdir(identity); report['client_identity_removed']=True
                if 'profile_path' in locals():
                    require(identities(profile_path)==profile_identity and sha(profile_path)==profile_hash,
                            'Temporary profile changed')
                    os.unlink(profile_path); report['profile_removed']=True
                if success:
                    store.advance(instance,op,'undefined'); store.advance(instance,op,'destroyed',complete=True)
                else:
                    store.advance(instance,op,'failed',failed=True)
                report['cleanup_ok']=True
            except Exception as cleanup:
                report['cleanup_error']={'type':type(cleanup).__name__,'message':str(cleanup)}
                print('CLEANUP BLOCKED:',str(cleanup),flush=True)
            report['instance_id']=instance; report['completed_epoch']=time.time(); report['spike_ok']=success
            REPORT.write_text(json.dumps(report,indent=2)+'\n'); connection.close()
            print(json.dumps(report,indent=2),flush=True)

    return report


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--report-only',type=Path,help='Evaluate JSON results only; no VM or host action')
    mode.add_argument('--run-approved-spike',action='store_true',help='Requires explicit test approval; no retry or journal reset')
    parser.add_argument('--run-id',help='New approved run UUID, only with --run-approved-spike')
    args=parser.parse_args(argv)
    if bool(args.run_id)!=bool(args.run_approved_spike):
        parser.error('--run-approved-spike requires --run-id; report mode accepts no run ID')
    try:
        if args.run_approved_spike:
            configure_run(args.run_id)
        report=json.loads(args.report_only.read_text()) if args.report_only else run_approved_spike()
        code=spike_exit_code(report)
        print(json.dumps({'exit_code':code,'test_and_cleanup_passed':code==0}))
        return code
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print('ABORT: '+str(error))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
