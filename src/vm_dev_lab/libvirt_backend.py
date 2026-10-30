# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Implement bounded VM lifecycle operations through libvirt.

"""Bounded libvirt backend; no connection or host change during import."""
import ipaddress
import xml.etree.ElementTree as ET

from .errors import LabError

OWNER_NS = 'https://vm-dev-lab.invalid/owner/v1'


def backend_error(code, message, status=6, retryable=False):
    raise LabError(status, code, 'libvirt', message,
                   'Inspect libvirt state and instance diagnostics; do not modify foreign resources.', retryable)


def xml(text, root):
    if len(text.encode()) > 1024 * 1024 or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('XML limit or disallowed declaration')
    try:
        element = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError('Invalid XML') from error
    if element.tag != root:
        raise ValueError('Unexpected XML format')
    return element


def domain_capabilities(text, firmware_code):
    root = xml(text, 'domainCapabilities')
    loader = root.find('./os/loader')
    return (root.findtext('arch') == 'x86_64' and root.findtext('domain') == 'kvm'
            and loader is not None and loader.get('supported') == 'yes'
            and firmware_code in [v.text for v in loader.findall('value')]
            and root.find('./features/backingStoreInput') is not None
            and root.find('./features/backingStoreInput').get('supported') == 'yes')


def backing_store_input(text):
    root = xml(text, 'domainCapabilities')
    feature = root.find('./features/backingStoreInput')
    return feature is not None and feature.get('supported') == 'yes'


def immutable_backing_store(disk, expected_path):
    """Verify the single explicit qcow2 base exempted from DAC relabeling."""
    stores = disk.findall('backingStore')
    if len(stores) != 1:
        return False
    store = stores[0]
    children = list(store)
    store_attributes = set(store.attrib)
    if (store_attributes not in ({'type'}, {'type', 'index'})
            or store.get('type') != 'file'
            or ('index' in store.attrib
                and (not store.get('index', '').isdigit() or int(store.get('index')) < 1))
            or [child.tag for child in children] != ['format', 'source', 'backingStore']
            or children[0].attrib != {'type': 'qcow2'} or list(children[0])
            or children[1].attrib != {'file': str(expected_path)}
            or len(list(children[1])) != 1
            or list(children[1])[0].tag != 'seclabel'
            or list(children[1])[0].attrib != {'model': 'dac', 'relabel': 'no'}
            or list(list(children[1])[0])
            or children[2].attrib or list(children[2])):
        return False
    return all(not (element.text or '').strip()
               for element in (store, children[0], children[1],
                               list(children[1])[0], children[2]))


def resolved_create_backing_store(disk, expected_path):
    """Verify libvirt's resolved single qcow2 base for a Create disk."""
    stores = disk.findall('backingStore')
    if not stores:
        return True
    if len(stores) != 1:
        return False
    store = stores[0]
    children = list(store)
    if (set(store.attrib) not in ({'type'}, {'type', 'index'})
            or store.get('type') != 'file'
            or ('index' in store.attrib
                and (not store.get('index', '').isdigit()
                     or int(store.get('index')) < 1))
            or [child.tag for child in children] != ['format', 'source', 'backingStore']
            or children[0].attrib != {'type': 'qcow2'} or list(children[0])
            or children[1].attrib != {'file': str(expected_path)} or list(children[1])
            or children[2].attrib or list(children[2])):
        return False
    return all(not (element.text or '').strip()
               for element in (store, children[0], children[1], children[2]))


def set_immutable_backing_store(disk, path):
    """Replace the XML backing description with the narrowly bound DAC contract."""
    for current in disk.findall('backingStore'):
        disk.remove(current)
    source = disk.find('source')
    if source is None:
        raise ValueError('Disk source is missing')
    store = ET.Element('backingStore', type='file')
    ET.SubElement(store, 'format', type='qcow2')
    backing_source = ET.SubElement(store, 'source', file=str(path))
    ET.SubElement(backing_source, 'seclabel', model='dac', relabel='no')
    ET.SubElement(store, 'backingStore')
    disk.insert(list(disk).index(source) + 1, store)


def network_identity(text, expected):
    root = xml(text, 'network')
    forward = root.find('forward')
    mode = 'isolated' if forward is None else forward.get('mode')
    networks = []
    for entry in root.findall('ip'):
        address = entry.get('address')
        mask = entry.get('prefix') or entry.get('netmask')
        networks.append(str(ipaddress.ip_network(f'{address}/{mask}', strict=False)))
    # Do not silently accept unverified additional IPv6 or a second subnet.
    return (root.findtext('name') == expected['name'] and root.findtext('uuid') == expected['uuid']
            and mode == expected['mode'] and networks == [str(ipaddress.ip_network(expected['subnet']))])


def pool_identity(text, expected, storage_path):
    root = xml(text, 'pool')
    return (root.findtext('name') == expected['name'] and root.findtext('uuid') == expected['uuid']
            and root.get('type') == 'dir' and root.findtext('./target/path') == storage_path)


class LibvirtBackend:
    """Sole real lifecycle adapter, with an injectable connection for offline tests."""

    def __init__(self, uri='qemu:///system', connection=None, libvirt_module=None):
        if uri != 'qemu:///system':
            backend_error('URI_UNSUPPORTED', 'P06 supports only qemu:///system.', 3)
        self.uri = uri
        self._connection = connection
        self._libvirt = libvirt_module

    def connect(self):
        if self._connection is None:
            try:
                if self._libvirt is None:
                    import libvirt as module
                    self._libvirt = module
                self._connection = self._libvirt.open(self.uri)
                if self._connection is None:
                    raise RuntimeError('libvirt.open returned no connection')
            except Exception:
                backend_error('LIBVIRT_UNAVAILABLE', 'System libvirt is unreachable or the Python binding is missing.', 3, True)
        return self._connection

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                # An already completed lifecycle action must not be made to fail by
                # make releasing the client handle appear to fail afterward.
                # The next call opens a new connection.
                pass
            finally:
                self._connection = None

    def _missing(self, error):
        return (self._libvirt is not None and hasattr(error, 'get_error_code')
                and error.get_error_code() == getattr(self._libvirt, 'VIR_ERR_NO_DOMAIN', object()))

    def domain(self, domain_uuid, missing_ok=False):
        try:
            return self.connect().lookupByUUIDString(domain_uuid)
        except Exception as error:
            if missing_ok and self._missing(error):
                return None
            backend_error('DOMAIN_LOOKUP_FAILED', 'Domain could not be read unambiguously by UUID.', 6, True)

    def define(self, domain_xml):
        try:
            return self.connect().defineXML(domain_xml)
        except Exception:
            backend_error('DOMAIN_DEFINE_FAILED', 'Domain definition failed.')

    def start(self, domain_uuid):
        domain = self.domain(domain_uuid)
        if domain.isActive():
            return domain
        try:
            domain.create()
            if not domain.isActive():
                backend_error('DOMAIN_START_UNCONFIRMED', 'libvirt did not confirm the domain start.')
            return domain
        except LabError:
            raise
        except Exception:
            backend_error('DOMAIN_START_FAILED', 'Domain could not be started.', 6, True)

    def request_shutdown(self, domain_uuid):
        domain = self.domain(domain_uuid)
        if not domain.isActive():
            return domain
        try:
            domain.shutdown()
            return domain
        except Exception:
            backend_error('DOMAIN_SHUTDOWN_FAILED', 'Graceful shutdown could not be requested.', 6, True)

    def force_stop(self, domain_uuid):
        domain = self.domain(domain_uuid)
        if domain.isActive():
            try:
                domain.destroy()
            except Exception:
                backend_error('DOMAIN_FORCE_STOP_FAILED', 'Hard power-off failed.')
        return domain

    def undefine(self, domain_uuid):
        domain = self.domain(domain_uuid)
        if domain.isActive():
            backend_error('DOMAIN_RUNNING', 'A running domain will not be undefined.', 4)
        try:
            flags = getattr(self._libvirt, 'VIR_DOMAIN_UNDEFINE_NVRAM', 0) if self._libvirt else 0
            domain.undefineFlags(flags)
        except Exception:
            backend_error('DOMAIN_UNDEFINE_FAILED', 'Domain definition could not be removed.')
        if self.domain(domain_uuid, missing_ok=True) is not None:
            backend_error('DOMAIN_UNDEFINE_UNCONFIRMED', 'Domain definition is still present.')

    def network(self, network_uuid):
        try:
            return self.connect().networkLookupByUUIDString(network_uuid)
        except Exception:
            backend_error('NETWORK_NOT_QUALIFIED', 'Qualified lab network is missing or its UUID does not match.', 3)

    def pool(self, pool_uuid):
        try:
            return self.connect().storagePoolLookupByUUIDString(pool_uuid)
        except Exception:
            backend_error('POOL_NOT_QUALIFIED', 'Qualified storage pool is missing or its UUID does not match.', 3)

    def ipv4_leases(self, network_uuid, mac):
        try:
            kind = getattr(self._libvirt, 'VIR_IP_ADDR_TYPE_IPV4', 0)
            return sorted({lease['ipaddr'] for lease in self.network(network_uuid).DHCPLeases(mac, 0)
                           if lease.get('type') == kind and lease.get('ipaddr')})
        except LabError:
            raise
        except Exception:
            backend_error('DHCP_LEASE_FAILED', 'DHCP lease could not be read.', 6, True)
