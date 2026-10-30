# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test the bounded libvirt backend through offline fakes.

"""Offline contract of the narrow P06 libvirt adapter."""
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))

from vm_dev_lab.libvirt_backend import LibvirtBackend


class MissingDomain(Exception):
    def get_error_code(self): return 42


class Module:
    VIR_ERR_NO_DOMAIN=42
    VIR_DOMAIN_UNDEFINE_NVRAM=8
    VIR_IP_ADDR_TYPE_IPV4=0


class Domain:
    def __init__(self,connection,name,uuid):
        self.connection=connection; self._name=name; self._uuid=uuid; self.running=False; self.undefine_flags=None
    def name(self): return self._name
    def UUIDString(self): return self._uuid
    def isActive(self): return int(self.running)
    def create(self): self.running=True
    def shutdown(self): self.running=False
    def destroy(self): self.running=False
    def undefineFlags(self,flags):
        self.undefine_flags=flags; del self.connection.domains[self._uuid]


class Network:
    def DHCPLeases(self,mac,flags):
        return [{'type':0,'ipaddr':'192.0.2.20'},{'type':1,'ipaddr':'2001:db8::20'},
                {'type':0,'ipaddr':'192.0.2.20'}]


class Connection:
    def __init__(self): self.domains={}; self.closed=False
    def close(self): self.closed=True
    def lookupByUUIDString(self,uuid):
        if uuid not in self.domains: raise MissingDomain()
        return self.domains[uuid]
    def defineXML(self,text):
        root=ET.fromstring(text); domain=Domain(self,root.findtext('name'),root.findtext('uuid'))
        self.domains[domain.UUIDString()]=domain; return domain
    def networkLookupByUUIDString(self,uuid): return Network()


class LibvirtBackendTests(unittest.TestCase):
    def setUp(self):
        self.connection=Connection()
        self.backend=LibvirtBackend(connection=self.connection,libvirt_module=Module)

    def test_define_start_shutdown_force_and_undefine_are_uuid_bound(self):
        uuid='11111111-1111-4111-8111-111111111111'
        xml=f'<domain><name>arch-test</name><uuid>{uuid}</uuid></domain>'
        domain=self.backend.define(xml)
        self.assertIs(self.backend.start(uuid),domain); self.assertTrue(domain.running)
        self.assertIs(self.backend.start(uuid),domain)
        self.backend.request_shutdown(uuid); self.assertFalse(domain.running)
        domain.running=True; self.backend.force_stop(uuid); self.assertFalse(domain.running)
        self.backend.undefine(uuid)
        self.assertEqual(domain.undefine_flags,Module.VIR_DOMAIN_UNDEFINE_NVRAM)
        self.assertIsNone(self.backend.domain(uuid,missing_ok=True))

    def test_ipv4_leases_are_filtered_and_deduplicated(self):
        self.assertEqual(self.backend.ipv4_leases('network-uuid','52:54:00:12:34:56'),['192.0.2.20'])

    def test_close_releases_injected_connection(self):
        self.backend.close()
        self.assertTrue(self.connection.closed)


if __name__ == '__main__': unittest.main()
