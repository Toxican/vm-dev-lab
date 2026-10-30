# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Inspect host capabilities and build mutation-free environment plans.

"""Passive host-environment checks and mutation-free planning for HS-C1."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import xml.etree.ElementTree as ET
from uuid import UUID, uuid4

from vm_dev_lab.process import exchange
from vm_dev_lab.version import VERSION

from .arch_packages import LocalSystem, build_report as build_package_report
from .contracts import CATALOG_NAME, CATALOG_VERSION, SCHEMA_VERSION, Status, canonical


DOC_ENV = "docs/HOST-SETUP.md#hostumgebung-check-und-plan"
DOC_HOST = "docs/INSTALLATION.md#host-einrichten"
DOC_SERVICES = "docs/HOST-SETUP.md#libvirt-dienste"
DOC_REQUIREMENTS = "docs/INSTALLATION.md#hostvoraussetzungen"
RECORD_PATH = "/etc/vm-dev-lab/host-setup.json"
READ_LIMIT = 1024 * 1024
SETUP_NS = "https://vm-dev-lab.invalid/host-setup/v1"
FIRMWARE_MIN = 1024 * 1024
FIRMWARE_MAX = 64 * 1024 * 1024
MIN_MEMORY = 4 * 1024 ** 3
MIN_CPUS = 2
SOCKETS = ("virtqemud.socket", "virtnetworkd.socket", "virtstoraged.socket")
TOOLS = (
    ("qemu-system-x86_64", "QEMU-x86_64-Systememulation"),
    ("qemu-img", "qcow2 and image operations"),
    ("virsh", "libvirt-Verwaltungsclient"),
    ("cloud-localds", "NoCloud-Seedmedien"),
    ("ssh", "Guest access with host-key binding"),
    ("sftp", "Bound file transfer"),
    ("gpg", "Image signature verification"),
)
PYTHON_DEPENDENCIES = (
    ("yaml", "PyYAML"), ("jinja2", "Jinja2"), ("jsonschema", "jsonschema"),
    ("libvirt", "libvirt-python"),
)


def _utc(now):
    return now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _check(check_id, status, observed, purpose, evidence_level, *, required=True,
           documentation=DOC_ENV, reason=None, proposed_change=None,
           manual_action=None, error_reason=None):
    return {
        "id": check_id,
        "status": Status(status).value,
        "required": required,
        "package": None,
        "purpose": purpose,
        "observed": observed,
        "proposed_change": proposed_change,
        "executed_change": None,
        "error_reason": error_reason,
        "documentation": documentation,
        "manual_action": manual_action,
        "evidence_level": evidence_level,
        "reason": reason or observed,
    }


def environment_plan_hash(report):
    material = {key: value for key, value in report.items()
                if key not in {"generated_at", "operation_id", "plan_sha256"}}
    return hashlib.sha256(canonical(material)).hexdigest()


def _setup_hash(plan):
    material = {key: value for key, value in plan.items() if key != "sha256"}
    return hashlib.sha256(canonical(material)).hexdigest()


def _validate_host_record(record, expected_host_id):
    if not isinstance(record, dict) or set(record) != {
            "completed", "plan", "status", "storage_identity"}:
        raise ValueError("Host record fields do not match v2")
    if record["status"] != "complete" or not isinstance(record["completed"], list):
        raise ValueError("Host record is not complete")
    plan = record["plan"]
    required = {
        "schema_version", "uri", "host_id", "setup_id", "network", "network_uuid",
        "pool", "pool_uuid", "bridge", "subnet", "storage", "owner", "qemu", "mode",
        "activate", "min_free_gib", "reserve_gib", "sha256", "firmware",
    }
    if (not isinstance(plan, dict) or set(plan) != required or plan["schema_version"] != 2
            or plan["uri"] != "qemu:///system" or plan["host_id"] != expected_host_id
            or not re.fullmatch(r"[0-9a-f]{64}", plan.get("sha256", ""))
            or _setup_hash(plan) != plan["sha256"]):
        raise ValueError("Host record plan is invalid, changed, or belongs to another host")
    try:
        identifiers = [str(UUID(plan[key])) for key in ("setup_id", "network_uuid", "pool_uuid")]
        network = ipaddress.ip_network(plan["subnet"])
    except (ValueError, TypeError, KeyError) as error:
        raise ValueError("Host record resources are invalid") from error
    private_networks = tuple(ipaddress.ip_network(value) for value in
                             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    storage_path = Path(plan["storage"])
    if (identifiers != [plan[key] for key in ("setup_id", "network_uuid", "pool_uuid")]
            or len(set(identifiers)) != 3 or network.version != 4 or network.prefixlen != 24
            or not any(network.subnet_of(parent) for parent in private_networks)
            or any(not re.fullmatch(r"vm-dev-lab[a-z0-9-]{0,40}", plan[key])
                   for key in ("network", "pool"))
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,14}", plan["bridge"])
            or not storage_path.is_absolute() or ".." in storage_path.parts
            or len(storage_path.parts) < 4
            or any(ord(character) < 32 for character in str(storage_path))
            or plan["mode"] not in {"manual", "permanent"} or type(plan["activate"]) is not bool
            or any(type(plan[key]) is not int or not 1 <= plan[key] <= 16384
                   for key in ("min_free_gib", "reserve_gib"))):
        raise ValueError("Host record resources violate the setup contract")
    for role in ("owner", "qemu"):
        identity = plan[role]
        if (not isinstance(identity, dict) or set(identity) != {"name", "uid", "gid"}
                or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", identity["name"])
                or type(identity["uid"]) is not int or identity["uid"] <= 0
                or type(identity["gid"]) is not int or identity["gid"] <= 0):
            raise ValueError("Host record identity is invalid")
    if plan["owner"]["uid"] == plan["qemu"]["uid"]:
        raise ValueError("Operator and QEMU service identities are not distinct")
    firmware = plan["firmware"]
    if not isinstance(firmware, dict) or set(firmware) != {
            "code", "vars", "code_sha256", "vars_sha256"}:
        raise ValueError("Firmware binding is missing")
    for kind in ("code", "vars"):
        path = Path(firmware[kind])
        if (not path.is_absolute() or ".." in path.parts
                or not re.fullmatch(r"[0-9a-f]{64}", firmware[kind + "_sha256"])):
            raise ValueError("Firmware binding is invalid")
    if firmware["code"] == firmware["vars"]:
        raise ValueError("Firmware CODE and VARS are not distinct")
    storage = record["storage_identity"]
    if (not isinstance(storage, dict) or set(storage) != {"device", "inode", "uid", "gid"}
            or any(type(storage[key]) is not int or storage[key] < 0 for key in storage)):
        raise ValueError("Storage identity is invalid")
    return plan


class LocalEnvironmentSystem(LocalSystem):
    """Narrow passive host boundary; no libvirt connection or mutation."""

    def kernel(self):
        return {"system": platform.system(), "release": platform.release()}

    def hardware(self):
        def read(path):
            with open(path, "rb") as stream:
                data = stream.read(READ_LIMIT + 1)
            if len(data) > READ_LIMIT:
                raise OSError("Hardware file exceeds the read limit")
            return data.decode("utf-8")
        cpuinfo = read("/proc/cpuinfo")
        flags = set(re.findall(r"^(?:flags|Features)\s*:\s*(.*)$", cpuinfo, re.MULTILINE)[0].split()) \
            if re.search(r"^(?:flags|Features)\s*:", cpuinfo, re.MULTILINE) else set()
        memory = read("/proc/meminfo")
        match = re.search(r"^MemTotal:\s*([0-9]+)\s+kB$", memory, re.MULTILINE)
        if not match:
            raise OSError("MemTotal is missing")
        cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
        return {"virtualization": bool(flags & {"vmx", "svm"}),
                "logical_cpus": cpus, "memory_bytes": int(match.group(1)) * 1024}

    def kvm_device(self):
        try:
            info = os.lstat("/dev/kvm")
        except FileNotFoundError:
            return {"state": "missing"}
        return {"state": "present", "character_device": stat.S_ISCHR(info.st_mode),
                "current_process_rw": os.access("/dev/kvm", os.R_OK | os.W_OK)}

    def tool(self, name):
        path = shutil.which(name)
        if not path:
            return {"state": "missing", "path": None}
        info = os.stat(path, follow_symlinks=True)
        return {"state": "present", "path": path,
                "regular": stat.S_ISREG(info.st_mode), "executable": os.access(path, os.X_OK)}

    def python_dependency(self, module):
        return importlib.util.find_spec(module) is not None

    def socket_state(self, unit):
        systemctl = shutil.which("systemctl")
        if not systemctl:
            return {"state": "unavailable", "reason": "systemctl is missing"}
        result = exchange([systemctl, "show", "--no-pager",
                           "--property=LoadState,ActiveState,SubState,UnitFileState", unit],
                          b"", timeout=10, limit=64 * 1024)
        if result.timed_out or result.output_limited or result.returncode != 0:
            return {"state": "unavailable", "reason": "systemd state is unreadable"}
        try:
            values = dict(line.split("=", 1) for line in result.stdout.decode("utf-8").splitlines()
                          if "=" in line)
        except UnicodeDecodeError:
            return {"state": "unavailable", "reason": "systemd output is not UTF-8"}
        return {"state": "observed", **values}

    def setup_host_id(self):
        with open("/etc/machine-id", "rb") as stream:
            return hashlib.sha256(stream.read(4096)).hexdigest()

    def host_record(self):
        path = Path(RECORD_PATH)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return {"state": "missing"}
        except PermissionError:
            return {"state": "unavailable", "reason": "Host record requires administrative read access"}
        try:
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_size > READ_LIMIT
                        or info.st_uid != 0 or info.st_nlink != 1
                        or info.st_mode & 0o777 != 0o600):
                    raise ValueError("Host record file is unsafe")
                raw = stream.read(READ_LIMIT + 1)
            if len(raw) > READ_LIMIT:
                raise ValueError("Host record is too large")
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON key")
                    result[key] = value
                return result
            return {"state": "present", "record": json.loads(raw, object_pairs_hook=unique)}
        except (OSError, ValueError, json.JSONDecodeError) as error:
            return {"state": "invalid", "reason": str(error)}

    def firmware_file(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= FIRMWARE_MAX:
                    return {"state": "invalid", "reason": "Firmware type or size is invalid"}
                digest = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            return {"state": "present", "regular": stat.S_ISREG(info.st_mode),
                    "size": info.st_size, "sha256": digest.hexdigest(),
                    "device": info.st_dev, "inode": info.st_ino}
        except (OSError, ValueError) as error:
            return {"state": "unavailable", "reason": str(error)}

    def account(self, name):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
        return {"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid}

    def operator_observation(self):
        uid = os.geteuid()
        if uid != 0:
            entry = pwd.getpwuid(uid)
            return {"effective_uid": uid, "operator": {"name": entry.pw_name,
                    "uid": entry.pw_uid, "gid": entry.pw_gid}, "source": "effective-user"}
        user, sudo_uid = os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID")
        if (not user or not sudo_uid or not sudo_uid.isdigit() or int(sudo_uid) <= 0):
            return {"effective_uid": 0, "operator": None, "source": "unresolved"}
        account = self.account(user)
        if not account or account["uid"] != int(sudo_uid):
            return {"effective_uid": 0, "operator": None, "source": "invalid-sudo-hint"}
        return {"effective_uid": 0, "operator": account, "source": "validated-sudo-hint"}

    def qemu_config(self):
        try:
            text = self._read("/etc/libvirt/qemu.conf")
        except (OSError, UnicodeError) as error:
            return {"state": "unavailable", "reason": str(error)}
        values = {}
        for line in text.splitlines():
            match = re.fullmatch(r'\s*(user|group)\s*=\s*"([^"\n]+)"\s*(?:#.*)?', line)
            if match:
                values[match.group(1)] = match.group(2)
        return {"state": "observed", "values": values}

    def static_resources(self, plan):
        def roots(folder):
            base = Path(folder)
            if not base.is_dir() or base.is_symlink():
                raise OSError("libvirt configuration directory is missing or unsafe")
            result = []
            for path in sorted(base.glob("*.xml")):
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    raw = stream.read(READ_LIMIT + 1)
                if not stat.S_ISREG(info.st_mode) or len(raw) > READ_LIMIT:
                    raise OSError("libvirt XML is unsafe or too large")
                text = raw.decode("utf-8")
                if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                    raise ValueError("unsafe XML")
                result.append(ET.fromstring(text))
            return result
        try:
            networks = roots("/etc/libvirt/qemu/networks")
            pools = roots("/etc/libvirt/storage")
            expected_network = [root for root in networks
                                if root.findtext("name") == plan["network"]
                                or root.findtext("uuid") == plan["network_uuid"]]
            expected_pool = [root for root in pools
                             if root.findtext("name") == plan["pool"]
                             or root.findtext("uuid") == plan["pool_uuid"]]
            if len(expected_network) != 1 or len(expected_pool) != 1:
                return {"state": "conflict", "reason": "Network or pool is missing, or name or UUID conflicts"}
            network, pool = expected_network[0], expected_pool[0]
            marker = network.find("./metadata/{" + SETUP_NS + "}managed")
            ip = network.find("ip")
            network_range = ip.find("./dhcp/range") if ip is not None else None
            expected_subnet = ipaddress.ip_network(plan["subnet"])
            prefix = (ip.get("prefix") or ip.get("netmask")) if ip is not None else None
            if (network.findtext("name") != plan["network"]
                    or network.findtext("uuid") != plan["network_uuid"]
                    or network.get("ipv6") not in {None, "no"}
                    or marker is None or marker.get("setup_id") != plan["setup_id"]
                    or network.find("forward") is None
                    or network.find("forward").get("mode") != "nat"
                    or network.find("bridge") is None
                    or network.find("bridge").get("name") != plan["bridge"]
                    or ip is None or ip.get("address") is None or prefix is None
                    or str(ipaddress.ip_network(ip.get("address") + "/" + prefix,
                                               strict=False)) != plan["subnet"]
                    or network_range is None
                    or network_range.get("start") != str(expected_subnet.network_address + 10)
                    or network_range.get("end") != str(expected_subnet.broadcast_address - 1)):
                return {"state": "conflict", "reason": "Owned network definition differs from the host record"}
            permissions = pool.find("./target/permissions")
            if (pool.get("type") != "dir" or pool.findtext("name") != plan["pool"]
                    or pool.findtext("uuid") != plan["pool_uuid"]
                    or pool.findtext("./target/path") != plan["storage"]
                    or pool.find("./features/cow") is None
                    or pool.find("./features/cow").get("state") != "yes"
                    or permissions is None
                    or permissions.findtext("owner") != str(plan["owner"]["uid"])
                    or permissions.findtext("group") != str(plan["owner"]["gid"])
                    or permissions.findtext("mode") != "0770"):
                return {"state": "conflict", "reason": "Owned pool definition differs from the host record"}
            own_subnet = ipaddress.ip_network(plan["subnet"])
            for other in networks:
                if other is network:
                    continue
                bridge = other.find("bridge")
                if bridge is not None and bridge.get("name") == plan["bridge"]:
                    return {"state": "conflict", "reason": "Bridge is occupied by a foreign network"}
                for other_ip in other.findall("ip"):
                    other_prefix = other_ip.get("prefix") or other_ip.get("netmask")
                    if other_ip.get("address") and other_prefix:
                        subnet = ipaddress.ip_network(other_ip.get("address") + "/" +
                                                     other_prefix, strict=False)
                        if subnet.version == 4 and subnet.overlaps(own_subnet):
                            return {"state": "conflict", "reason": "Subnet conflicts with a foreign network"}
            for other in pools:
                target = other.findtext("./target/path")
                if other is not pool and target:
                    own_path = Path(plan["storage"]).resolve(strict=False)
                    other_path = Path(target).resolve(strict=False)
                    if (own_path == other_path or own_path in other_path.parents
                            or other_path in own_path.parents):
                        return {"state": "conflict", "reason": "Storage path overlaps a foreign pool"}

            permanent = plan["mode"] == "permanent"
            for folder, name in (("/etc/libvirt/qemu/networks/autostart", plan["network"]),
                                 ("/etc/libvirt/storage/autostart", plan["pool"])):
                policy_path = Path(folder) / (name + ".xml")
                try:
                    policy_info = os.lstat(policy_path)
                    configured = True
                except FileNotFoundError:
                    configured = False
                    policy_info = None
                if configured and (not stat.S_ISLNK(policy_info.st_mode)
                                   or policy_path.resolve(strict=True)
                                   != (Path(folder).parent / (name + ".xml")).resolve(strict=True)):
                    return {"state": "conflict", "reason": "Autostart policy is not an unambiguous link"}
                if configured != permanent:
                    return {"state": "conflict", "reason": "Autostart policy differs from the host record"}

            ip_tool = shutil.which("ip")
            if not ip_tool:
                return {"state": "unavailable", "reason": "ip tool is missing"}

            def ip_json(arguments):
                result = exchange([ip_tool, "-j", *arguments], b"", timeout=10,
                                  limit=256 * 1024)
                if result.timed_out or result.output_limited or result.returncode != 0:
                    raise OSError("passive ip inventory failed")
                value = json.loads(result.stdout.decode("utf-8"))
                if not isinstance(value, list) or len(value) > 4096:
                    raise ValueError("ip inventory is invalid or too large")
                return value

            for route in ip_json(["-4", "route", "show", "table", "all"]):
                destination = route.get("dst")
                if destination in {None, "default"}:
                    continue
                other = ipaddress.ip_network(destination, strict=False)
                if (route.get("dev") == plan["bridge"] and other.subnet_of(own_subnet)):
                    continue
                if own_subnet.overlaps(other):
                    return {"state": "conflict", "reason": "Subnet conflicts with a host or VPN route"}
            for link in ip_json(["-4", "address", "show"]):
                interface = link.get("ifname")
                for address in link.get("addr_info", []):
                    if address.get("family") != "inet":
                        continue
                    other = ipaddress.ip_interface(
                        f"{address.get('local')}/{address.get('prefixlen')}").network
                    if interface == plan["bridge"]:
                        if other != own_subnet:
                            return {"state": "conflict", "reason": "Owned bridge address differs"}
                    elif own_subnet.overlaps(other):
                        return {"state": "conflict", "reason": "Subnet conflicts with a host address"}
            return {"state": "verified"}
        except PermissionError:
            return {"state": "unavailable", "reason": "Static libvirt inventory requires administrative read access"}
        except (OSError, ValueError, ET.ParseError, UnicodeError) as error:
            return {"state": "unavailable", "reason": str(error)}

    def storage(self, plan, expected_identity):
        try:
            info = os.lstat(plan["storage"])
            space = os.statvfs(plan["storage"])
        except (OSError, ValueError) as error:
            return {"state": "unavailable", "reason": str(error)}
        acl_verified = False
        getfacl = shutil.which("getfacl")
        if getfacl:
            result = exchange([getfacl, "-cpn", "--", plan["storage"]], b"",
                              timeout=10, limit=64 * 1024)
            if not result.timed_out and not result.output_limited and result.returncode == 0:
                try:
                    lines = set(result.stdout.decode("utf-8").splitlines())
                    required = {f"user:{plan['owner']['uid']}:rwx",
                                f"user:{plan['qemu']['uid']}:rwx", "mask::rwx",
                                f"default:user:{plan['owner']['uid']}:rwx",
                                f"default:user:{plan['qemu']['uid']}:rwx", "default:mask::rwx"}
                    acl_verified = required <= lines
                except UnicodeDecodeError:
                    pass
        return {"state": "present", "regular_directory": stat.S_ISDIR(info.st_mode),
                "identity": {"device": info.st_dev, "inode": info.st_ino,
                             "uid": info.st_uid, "gid": info.st_gid},
                "available_bytes": space.f_bavail * space.f_frsize,
                "acl_verified": acl_verified}


def _normalize_package_checks(report):
    checks = []
    for original in report["checks"]:
        check = dict(original)
        check["evidence_level"] = "passive"
        check["reason"] = original["observed"]
        checks.append(check)
    return checks


def _hardware_checks(system):
    checks = []
    try:
        kernel = system.kernel()
        valid = kernel.get("system") == "Linux" and bool(kernel.get("release"))
        checks.append(_check("environment.kernel", Status.PASS if valid else Status.BLOCKED,
                             f"{kernel.get('system') or 'unknown'} {kernel.get('release') or 'without release'}",
                             "Verify a suitable Linux kernel", "passive",
                             documentation=DOC_REQUIREMENTS,
                             manual_action=None if valid else "Qualify the kernel platform manually."))
    except Exception as error:
        checks.append(_check("environment.kernel", Status.FAILED, "Unable to determine kernel",
                             "Verify a suitable Linux kernel", "not-checked",
                             documentation=DOC_REQUIREMENTS, error_reason=str(error),
                             manual_action="Resolve the kernel state manually."))
    try:
        hardware = system.hardware()
        checks.append(_check("environment.cpu.virtualization",
                             Status.PASS if hardware["virtualization"] else Status.BLOCKED,
                             "VMX or SVM present" if hardware["virtualization"] else "VMX or SVM not detected",
                             "Verify hardware virtualization", "passive",
                             documentation=DOC_REQUIREMENTS,
                             manual_action=None if hardware["virtualization"] else
                             "Resolve CPU or firmware virtualization outside the assistant."))
        cpus = hardware["logical_cpus"]
        checks.append(_check("environment.cpu.capacity", Status.PASS if cpus >= MIN_CPUS else Status.BLOCKED,
                             f"{cpus} available logical CPUs", "Check basic CPU capacity",
                             "passive", documentation=DOC_REQUIREMENTS,
                             manual_action=None if cpus >= MIN_CPUS else "Provide at least two CPUs."))
        memory = hardware["memory_bytes"]
        checks.append(_check("environment.memory", Status.PASS if memory >= MIN_MEMORY else Status.BLOCKED,
                             f"{memory} bytes total memory", "Check basic RAM capacity",
                             "passive", documentation=DOC_REQUIREMENTS,
                             manual_action=None if memory >= MIN_MEMORY else "Provide at least 4 GiB of RAM."))
    except Exception as error:
        for check_id, purpose in (("environment.cpu.virtualization", "Verify hardware virtualization"),
                                  ("environment.cpu.capacity", "Check basic CPU capacity"),
                                  ("environment.memory", "Check basic RAM capacity")):
            checks.append(_check(check_id, Status.FAILED, "Unable to determine hardware data", purpose,
                                 "not-checked", documentation=DOC_REQUIREMENTS,
                                 error_reason=str(error), manual_action="Resolve the hardware state manually."))
    try:
        device = system.kvm_device()
        if device["state"] == "missing":
            checks.append(_check("environment.kvm.device", Status.BLOCKED, "/dev/kvm is missing",
                                 "Check the KVM character device", "passive", documentation=DOC_REQUIREMENTS,
                                 manual_action="Resolve the KVM, kernel, or firmware prerequisite manually."))
        elif not device.get("character_device"):
            checks.append(_check("environment.kvm.device", Status.BLOCKED,
                                 "/dev/kvm is not a character device", "Check the KVM character device",
                                 "passive", documentation=DOC_REQUIREMENTS,
                                 manual_action="Do not modify an unknown device node; operator review is required."))
        else:
            checks.append(_check("environment.kvm.device", Status.PASS,
                                 "/dev/kvm is a character device", "Check the KVM character device",
                                 "passive", documentation=DOC_REQUIREMENTS))
            access = bool(device.get("current_process_rw"))
            checks.append(_check("environment.kvm.access",
                                 Status.PASS if access else Status.MANUAL_REQUIRED,
                                 "current process has read/write access" if access else
                                 "Read/write access for the current process was not established",
                                 "Evaluate the observable KVM permission boundary", "passive",
                                 documentation=DOC_REQUIREMENTS, required=False,
                                 manual_action=None if access else
                                 "Qualify QEMU service access separately later; do not change permissions automatically."))
    except Exception as error:
        checks.append(_check("environment.kvm.device", Status.FAILED,
                             "Unable to check KVM device", "Check the KVM character device",
                             "not-checked", documentation=DOC_REQUIREMENTS,
                             error_reason=str(error), manual_action="Resolve the KVM device manually."))
    return checks


def _tool_checks(system):
    checks = []
    for name, purpose in TOOLS:
        check_name = name.replace("_", "-")
        try:
            tool = system.tool(name)
            present = (tool.get("state") == "present" and tool.get("regular")
                       and tool.get("executable"))
            checks.append(_check(f"environment.tool.{check_name}",
                                 Status.PASS if present else Status.ACTION_REQUIRED,
                                 f"present: {tool.get('path')}" if present else
                                 "missing or not regular or executable", purpose, "present" if present else "passive",
                                 documentation=DOC_REQUIREMENTS,
                                 reason="Existence is not runtime or capability evidence.",
                                 manual_action=None if present else "Correct the preceding package stage."))
        except Exception as error:
            checks.append(_check(f"environment.tool.{check_name}", Status.FAILED,
                                 "Unable to determine tool status", purpose, "not-checked",
                                 documentation=DOC_REQUIREMENTS, error_reason=str(error)))
    for module, label in PYTHON_DEPENDENCIES:
        try:
            present = system.python_dependency(module)
            checks.append(_check(f"environment.python.{module}",
                                 Status.PASS if present else Status.ACTION_REQUIRED,
                                 f"{label} importable" if present else f"{label} missing",
                                 "Check the declared Python runtime dependency", "present" if present else "passive",
                                 documentation="docs/INSTALLATION.md#entwicklungsumgebung",
                                 reason="Importability is not evidence of real libvirt operation.",
                                 manual_action=None if present else "Provide the Python dependency separately."))
        except Exception as error:
            checks.append(_check(f"environment.python.{module}", Status.FAILED,
                                 "Unable to check Python dependency",
                                 "Check the declared Python runtime dependency", "not-checked",
                                 error_reason=str(error)))
    checks.append(_check("environment.qemu.capabilities", Status.MANUAL_REQUIRED,
                         "no QEMU or KVM execution in the passive check",
                         "Keep runtime capabilities separate from binary existence", "not-checked",
                         documentation=DOC_REQUIREMENTS, required=False,
                         manual_action="Run active capability validation only with a later explicit opt-in."))
    return checks


def _socket_checks(system):
    checks, candidates = [], []
    for unit in SOCKETS:
        try:
            state = system.socket_state(unit)
        except Exception as error:
            state = {"state": "unavailable", "reason": str(error)}
        check_id = "environment.systemd." + unit.removesuffix(".socket")
        if state.get("state") != "observed":
            checks.append(_check(check_id, Status.MANUAL_REQUIRED,
                                 state.get("reason", "Unable to determine state"),
                                 f"Check modular socket {unit} passively", "not-checked",
                                 documentation=DOC_SERVICES,
                                 manual_action="Read systemd state administratively; do not start anything automatically."))
            continue
        load, active, file_state = (state.get("LoadState"), state.get("ActiveState"),
                                    state.get("UnitFileState"))
        if load == "not-found":
            status, observed, manual = Status.BLOCKED, "Unit is not installed", "Resolve the modular libvirt installation."
        elif load == "masked" or file_state == "masked":
            status, observed, manual = Status.MANUAL_REQUIRED, "Unit is masked", "Resolve masking or migration manually; do not unmask automatically."
        elif load == "loaded" and active == "active":
            status, observed, manual = Status.PASS, "Unit is present and active", None
        elif load == "loaded" and active == "inactive":
            status, observed, manual = Status.ACTION_REQUIRED, "Unit is present, unmasked, and inactive", None
            candidates.append(unit)
        else:
            status, observed, manual = Status.MANUAL_REQUIRED, "Unit state is ambiguous", "Resolve systemd configuration manually."
        checks.append(_check(check_id, status, observed,
                             f"Check modular socket {unit} passively", "passive",
                             documentation=DOC_SERVICES, manual_action=manual,
                             proposed_change=(f"Start socket {unit} later at runtime"
                                              if status == Status.ACTION_REQUIRED else None)))
    conflicts = []
    for unit in ("libvirtd.socket", "virtproxyd.socket"):
        try:
            state = system.socket_state(unit)
        except Exception as error:
            state = {"state": "unavailable", "reason": str(error)}
        if (state.get("state") == "observed" and state.get("LoadState") == "loaded"
                and state.get("ActiveState") == "active"):
            conflicts.append(unit)
    checks.append(_check("environment.systemd.legacy-conflict",
                         Status.MANUAL_REQUIRED if conflicts else Status.PASS,
                         "aktive monolithische/proxy Sockets: " + ", ".join(conflicts)
                         if conflicts else "no active monolithic or proxy configuration detected",
                         "Detect a parallel libvirt operating mode", "passive",
                         documentation=DOC_SERVICES,
                         manual_action="Resolve the existing libvirt topology manually; do not plan a migration."
                         if conflicts else None))
    return checks, candidates


def _record_checks(system, action):
    checks, plan = [], None
    try:
        observation = system.host_record()
    except Exception as error:
        observation = {"state": "invalid", "reason": str(error)}
    state = observation.get("state")
    if state == "missing":
        checks.append(_check("environment.host-record", Status.MANUAL_REQUIRED,
                             "Host record v2 is missing", "Check existing host-setup evidence",
                             "passive", documentation=DOC_HOST,
                             manual_action="Specify the operator, QEMU worker, firmware, and resources for setup-host.py plan."))
    elif state == "unavailable":
        checks.append(_check("environment.host-record", Status.MANUAL_REQUIRED,
                             observation.get("reason", "Host record is unreadable"),
                             "Check existing host-setup evidence", "not-checked",
                             documentation=DOC_HOST,
                             manual_action="Start privileged inventory explicitly at a later time."))
    elif state != "present":
        checks.append(_check("environment.host-record", Status.BLOCKED,
                             observation.get("reason", "Host record is invalid"),
                             "Check existing host-setup evidence", "passive",
                             documentation=DOC_HOST,
                             manual_action="Do not replace or adopt the record; resolve the state manually."))
    else:
        try:
            plan = _validate_host_record(observation["record"], system.setup_host_id())
            checks.append(_check("environment.host-record", Status.PASS,
                                 "completed host-bound host record v2",
                                 "Check existing host-setup evidence", "passive",
                                 documentation=DOC_HOST))
        except (ValueError, KeyError, TypeError) as error:
            checks.append(_check("environment.host-record", Status.BLOCKED,
                                 "Host record v2 is invalid or belongs to another host",
                                 "Check existing host-setup evidence", "passive",
                                 documentation=DOC_HOST, error_reason=str(error),
                                 manual_action="Do not replace the record or adopt foreign resources."))

    if plan is None:
        checks.extend([
            _check("environment.firmware.binding", Status.MANUAL_REQUIRED,
                   "no unambiguous firmware binding", "Bind OVMF CODE and VARS unambiguously",
                   "not-checked", documentation=DOC_HOST,
                   manual_action="Select the firmware pair explicitly in separate host-setup planning."),
            _check("environment.identity.operator", Status.MANUAL_REQUIRED,
                   "Lab operator is not bound in the host record", "Determine the regular lab operator",
                   "not-checked", documentation=DOC_HOST,
                   manual_action="Specify the operator explicitly; do not adopt root or SUDO_USER automatically."),
            _check("environment.identity.qemu", Status.MANUAL_REQUIRED,
                   "QEMU service user is not bound in the host record", "Determine the QEMU service identity",
                   "not-checked", documentation=DOC_HOST,
                   manual_action="Qualify the QEMU worker from qemu.conf and account resolution separately."),
            _check("environment.resources.ownership", Status.MANUAL_REQUIRED,
                   "Network, pool, and storage targets and ownership are not bound",
                   "Check existing or planned lab resources with ownership binding",
                   "not-checked", documentation=DOC_HOST,
                   manual_action="Use the existing setup-host.py plan contract; do not adopt defaults."),
        ])
        return checks, None

    operator = system.operator_observation()
    account = system.account(plan["owner"]["name"])
    operator_match = account == plan["owner"] and operator.get("operator") == plan["owner"]
    checks.append(_check("environment.identity.operator",
                         Status.PASS if operator_match else Status.MANUAL_REQUIRED,
                         "validated regular operator matches the host record" if operator_match else
                         "current operator indication does not safely match the host record",
                         "Determine the regular lab operator separately from root", "passive",
                         documentation=DOC_HOST,
                         manual_action=None if operator_match else
                         "Validate operator identity explicitly; do not reinterpret the host record."))
    qemu = system.account(plan["qemu"]["name"])
    config = system.qemu_config()
    values = config.get("values", {}) if config.get("state") == "observed" else {}
    configured_user = values.get("user")
    configured_group = values.get("group")
    config_match = (config.get("state") == "observed"
                    and configured_user in {None, plan["qemu"]["name"], "+" + str(plan["qemu"]["uid"])}
                    and configured_group in {None, plan["qemu"]["name"], "+" + str(plan["qemu"]["gid"])})
    qemu_valid = qemu == plan["qemu"] and config_match
    checks.append(_check("environment.identity.qemu", Status.PASS if qemu_valid else Status.BLOCKED,
                         "QEMU service account and qemu.conf match the host record" if qemu_valid else
                         "QEMU service account or qemu.conf differs from the host record",
                         "Check QEMU service identity against the host record", "passive",
                         documentation=DOC_HOST,
                         manual_action=None if qemu_valid else
                         "Resolve QEMU configuration and account manually."))

    firmware_ok = True
    first = {}
    for kind in ("code", "vars"):
        info = system.firmware_file(plan["firmware"][kind])
        first[kind] = info
        valid = (info.get("state") == "present" and info.get("regular")
                 and FIRMWARE_MIN <= info.get("size", 0) <= FIRMWARE_MAX
                 and info.get("sha256") == plan["firmware"][kind + "_sha256"])
        firmware_ok &= valid
        checks.append(_check(f"environment.firmware.{kind}",
                             Status.PASS if valid else Status.BLOCKED,
                             f"regular, {info.get('size')} bytes, bound to SHA256" if valid else
                             "missing, unsafe, unsuitable size, or hash mismatch",
                             f"Check OVMF {kind.upper()} against the host record", "passive",
                             documentation=DOC_HOST,
                             manual_action=None if valid else
                             "Do not replace firmware automatically; resolve the host record and package content."))
    if plan["firmware"]["code"] == plan["firmware"]["vars"]:
        firmware_ok = False
    if action == "plan" and firmware_ok:
        for kind in ("code", "vars"):
            second = system.firmware_file(plan["firmware"][kind])
            if second != first[kind]:
                firmware_ok = False
                checks.append(_check("environment.firmware.stability", Status.BLOCKED,
                                     f"Firmware file {kind} changed during planning",
                                     "Keep firmware identity stable until plan binding", "passive",
                                     documentation=DOC_HOST,
                                     manual_action="Create a new plan only after resolving firmware state."))
                break
    if firmware_ok and not any(c["id"] == "environment.firmware.stability" for c in checks):
        checks.append(_check("environment.firmware.stability", Status.PASS,
                             "firmware pair is unambiguous and stable during observation",
                             "Keep firmware identity stable until plan binding", "passive",
                             documentation=DOC_HOST))

    try:
        resources = system.static_resources(plan)
    except Exception as error:
        resources = {"state": "unavailable", "reason": str(error)}
    if resources.get("state") == "verified":
        resource_status, observed, manual = Status.PASS, "static network and pool definitions match the host record", None
    elif resources.get("state") == "conflict":
        resource_status, observed, manual = Status.BLOCKED, resources.get("reason", "Resource conflict"), "Do not adopt or remove foreign or unclear resources."
    else:
        resource_status, observed, manual = Status.MANUAL_REQUIRED, resources.get("reason", "Resource inventory incomplete"), "Run privileged static inventory explicitly later; no libvirt connection."
    checks.append(_check("environment.resources.ownership", resource_status, observed,
                         "Check network and pool names, UUIDs, bridge, subnet, and ownership",
                         "passive" if resources.get("state") in {"verified", "conflict"} else "not-checked",
                         documentation=DOC_HOST, manual_action=manual))

    storage = system.storage(plan, observation["record"]["storage_identity"])
    required_space = (plan["min_free_gib"] + plan["reserve_gib"]) * 1024 ** 3
    storage_valid = (storage.get("state") == "present" and storage.get("regular_directory")
                     and storage.get("identity") == observation["record"]["storage_identity"]
                     and storage.get("available_bytes", 0) >= required_space
                     and storage.get("acl_verified") is True)
    checks.append(_check("environment.storage", Status.PASS if storage_valid else Status.BLOCKED,
                         f"Storage identity bound; {storage.get('available_bytes')} bytes free"
                         if storage_valid else "Storage is missing, replaced, or below the reserve",
                         "Check directory storage and free space against the host record", "passive",
                         documentation=DOC_HOST,
                         manual_action=None if storage_valid else
                         "Do not create or repair storage; resolve path, inode, ownership, and reserve."))
    return checks, plan


def _aggregate_required(checks):
    relevant = [check for check in checks if check["required"]]
    priority = {Status.PASS.value: 0, Status.ACTION_REQUIRED.value: 1,
                Status.MANUAL_REQUIRED.value: 2, Status.BLOCKED.value: 3,
                Status.FAILED.value: 4}
    return max((check["status"] for check in relevant), key=priority.__getitem__)


def build_environment_report(action, system=None, now=None, operation_id_factory=None):
    if action not in {"check", "plan"}:
        raise ValueError("HS-C1 supports only environment check and plan")
    system = system or LocalEnvironmentSystem()
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    operation_id = operation_id_factory()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", operation_id):
        raise ValueError("Operation ID is not a UUIDv4")

    packages = build_package_report("check", system=system, now=now)
    checks = _normalize_package_checks(packages)
    checks.extend(_hardware_checks(system))
    checks.extend(_tool_checks(system))
    socket_checks, socket_candidates = _socket_checks(system)
    checks.extend(socket_checks)
    record_checks, record_plan = _record_checks(system, action)
    checks.extend(record_checks)
    checks.append(_check("environment.libvirt.api-access", Status.MANUAL_REQUIRED,
                         "no libvirt connection in the passive HS-C1 check",
                         "Qualify actual qemu:///system access separately", "not-checked",
                         required=False, documentation=DOC_HOST,
                         manual_action="A later active check requires its own opt-in; do not activate the socket implicitly."))

    blockers = [c["id"] for c in checks if c["required"]
                and c["status"] in {Status.BLOCKED.value, Status.FAILED.value}]
    manual = [{"id": c["id"], "reason": c["reason"],
               "manual_action": c["manual_action"], "documentation": c["documentation"]}
              for c in checks if c["status"] == Status.MANUAL_REQUIRED.value]
    candidate_ids = {"environment.systemd." + unit.removesuffix(".socket")
                     for unit in socket_candidates}
    safe_to_plan_sockets = all(
        c["status"] == Status.PASS.value
        or (c["id"] in candidate_ids and c["status"] == Status.ACTION_REQUIRED.value)
        for c in checks if c["required"])
    changes = []
    if action == "plan" and safe_to_plan_sockets:
        for unit in socket_candidates:
            changes.append({
                "id": "environment.action.start-" + unit.removesuffix(".socket"),
                "kind": "systemd-socket-runtime-start",
                "argv": ["/usr/bin/systemctl", "start", unit],
                "requires_root": True,
                "precondition_check": "environment.systemd." + unit.removesuffix(".socket"),
                "impact": "Starts only the existing modular socket at runtime; no boot activation.",
                "documentation": DOC_SERVICES,
            })
    elif action == "plan" and socket_candidates:
        manual.append({"id": "environment.decision.socket-actions-suppressed",
                       "reason": "Other required prerequisites are not all PASS",
                       "manual_action": "Resolve prerequisites and create a new plan; do not derive a partial action.",
                       "documentation": DOC_ENV})

    status = _aggregate_required(checks)
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "environment-check" if action == "check" else "environment-plan",
        "tool_version": VERSION,
        "generated_at": _utc(now),
        "stage": "environment",
        "status": status,
        "verification_level": "passive",
        "operation_id": operation_id,
        "host_binding": packages["host_binding"],
        "catalog": {"name": CATALOG_NAME, "version": CATALOG_VERSION},
        "checks": checks,
        "summary": packages["summary"],
        "environment_summary": {
            "planned_changes": [change["id"] for change in changes],
            "manual_decisions": [decision["id"] for decision in manual],
            "security_blockers": blockers,
            "not_actively_verified": [c["id"] for c in checks if c["evidence_level"] == "not-checked"],
            "host_record_setup_id": record_plan["setup_id"] if record_plan else None,
        },
        "planned_action": None,
        "environment_plan": None if action == "check" else {
            "changes": changes, "manual_decisions": manual, "security_blockers": blockers},
        "plan_sha256": None,
        "notice": "Passive HS-C1 check only; no libvirt connection, service activation, or host mutation.",
    }
    if action == "plan":
        report["plan_sha256"] = environment_plan_hash(report)
    return report
