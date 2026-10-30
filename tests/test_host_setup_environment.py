# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test passive Host Setup environment checks and plans.

from copy import deepcopy
from datetime import datetime, timezone
from importlib.resources import files
import io
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from vm_dev_lab.host_setup import cli
from vm_dev_lab.host_setup.contracts import canonical
from vm_dev_lab.host_setup.environment import build_environment_report

from tests.test_host_setup_packages import FakeSystem, installed_catalog


NOW = datetime(2026, 10, 30, 16, 0, tzinfo=timezone.utc)
OPERATION_A = "12345678-1234-4234-8234-123456789abc"
OPERATION_B = "87654321-4321-4321-8321-cba987654321"
HOST_ID = "a" * 64
CODE_HASH = "c" * 64
VARS_HASH = "d" * 64
STORAGE_IDENTITY = {"device": 8, "inode": 42, "uid": 1000, "gid": 1000}


def setup_hash(plan):
    material = {key: value for key, value in plan.items() if key != "sha256"}
    import hashlib
    return hashlib.sha256(canonical(material)).hexdigest()


def valid_record():
    plan = {
        "schema_version": 2,
        "uri": "qemu:///system",
        "host_id": HOST_ID,
        "setup_id": "11111111-1111-4111-8111-111111111111",
        "network": "vm-dev-lab-nat",
        "network_uuid": "22222222-2222-4222-8222-222222222222",
        "pool": "vm-dev-lab",
        "pool_uuid": "33333333-3333-4333-8333-333333333333",
        "bridge": "virbr-vdl",
        "subnet": "192.168.124.0/24",
        "storage": "/var/lib/libvirt/vm-dev-lab",
        "owner": {"name": "developer", "uid": 1000, "gid": 1000},
        "qemu": {"name": "libvirt-qemu", "uid": 949, "gid": 949},
        "mode": "manual",
        "activate": False,
        "min_free_gib": 60,
        "reserve_gib": 20,
        "firmware": {
            "code": "/firmware/OVMF_CODE.fd", "vars": "/firmware/OVMF_VARS.fd",
            "code_sha256": CODE_HASH, "vars_sha256": VARS_HASH,
        },
        "sha256": None,
    }
    plan["sha256"] = setup_hash(plan)
    return {"completed": ["storage", "network", "pool"], "plan": plan,
            "status": "complete", "storage_identity": dict(STORAGE_IDENTITY)}


def active_socket():
    return {"state": "observed", "LoadState": "loaded", "ActiveState": "active",
            "SubState": "listening", "UnitFileState": "enabled"}


def absent_socket():
    return {"state": "observed", "LoadState": "not-found", "ActiveState": "inactive",
            "SubState": "dead", "UnitFileState": ""}


class FakeEnvironmentSystem(FakeSystem):
    def __init__(self):
        super().__init__(installed=installed_catalog())
        self.kernel_value = {"system": "Linux", "release": "6.17.1-arch1-1"}
        self.hardware_value = {"virtualization": True, "logical_cpus": 8,
                               "memory_bytes": 16 * 1024 ** 3}
        self.kvm_value = {"state": "present", "character_device": True,
                          "current_process_rw": True}
        self.tools = {name: {"state": "present", "path": "/usr/bin/" + name,
                             "regular": True, "executable": True}
                      for name in ("qemu-system-x86_64", "qemu-img", "virsh", "cloud-localds",
                                   "ssh", "sftp", "gpg")}
        self.dependencies = {name: True for name in ("yaml", "jinja2", "jsonschema", "libvirt")}
        self.sockets = {name: active_socket() for name in
                        ("virtqemud.socket", "virtnetworkd.socket", "virtstoraged.socket")}
        self.sockets.update({"libvirtd.socket": absent_socket(),
                             "virtproxyd.socket": absent_socket()})
        self.record_value = {"state": "present", "record": valid_record()}
        self.firmware = {
            "/firmware/OVMF_CODE.fd": {"state": "present", "regular": True,
                                        "size": 4 * 1024 ** 2, "sha256": CODE_HASH,
                                        "device": 8, "inode": 10},
            "/firmware/OVMF_VARS.fd": {"state": "present", "regular": True,
                                        "size": 4 * 1024 ** 2, "sha256": VARS_HASH,
                                        "device": 8, "inode": 11},
        }
        self.firmware_sequences = {}
        self.accounts = {
            "developer": {"name": "developer", "uid": 1000, "gid": 1000},
            "libvirt-qemu": {"name": "libvirt-qemu", "uid": 949, "gid": 949},
        }
        self.operator_value = {"effective_uid": 1000,
                               "operator": deepcopy(self.accounts["developer"]),
                               "source": "effective-user"}
        self.qemu_config_value = {"state": "observed", "values": {
            "user": "libvirt-qemu", "group": "libvirt-qemu"}}
        self.resources_value = {"state": "verified"}
        self.storage_value = {"state": "present", "regular_directory": True,
                              "identity": dict(STORAGE_IDENTITY),
                              "available_bytes": 100 * 1024 ** 3,
                              "acl_verified": True}
        self.calls = []

    def kernel(self):
        self.calls.append(("kernel",))
        return deepcopy(self.kernel_value)

    def hardware(self):
        self.calls.append(("hardware",))
        return deepcopy(self.hardware_value)

    def kvm_device(self):
        self.calls.append(("kvm_device",))
        return deepcopy(self.kvm_value)

    def tool(self, name):
        self.calls.append(("tool", name))
        return deepcopy(self.tools[name])

    def python_dependency(self, module):
        self.calls.append(("python_dependency", module))
        return self.dependencies[module]

    def socket_state(self, unit):
        self.calls.append(("socket_state", unit))
        return deepcopy(self.sockets[unit])

    def setup_host_id(self):
        self.calls.append(("setup_host_id",))
        return HOST_ID

    def host_record(self):
        self.calls.append(("host_record",))
        return deepcopy(self.record_value)

    def firmware_file(self, path):
        self.calls.append(("firmware_file", path))
        sequence = self.firmware_sequences.get(path)
        if sequence:
            return deepcopy(sequence.pop(0) if len(sequence) > 1 else sequence[0])
        return deepcopy(self.firmware[path])

    def account(self, name):
        self.calls.append(("account", name))
        return deepcopy(self.accounts.get(name))

    def operator_observation(self):
        self.calls.append(("operator_observation",))
        return deepcopy(self.operator_value)

    def qemu_config(self):
        self.calls.append(("qemu_config",))
        return deepcopy(self.qemu_config_value)

    def static_resources(self, plan):
        self.calls.append(("static_resources", plan["setup_id"]))
        return deepcopy(self.resources_value)

    def storage(self, plan, expected_identity):
        self.calls.append(("storage", plan["storage"], deepcopy(expected_identity)))
        return deepcopy(self.storage_value)


class EnvironmentReportTests(unittest.TestCase):
    def report(self, action, system, operation=OPERATION_A):
        return build_environment_report(action, system=system, now=lambda: NOW,
                                        operation_id_factory=lambda: operation)

    def check(self, report, check_id):
        return next(check for check in report["checks"] if check["id"] == check_id)

    def test_complete_passive_environment_passes_without_claiming_active_capability(self):
        system = FakeEnvironmentSystem()
        report = self.report("check", system)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["artifact_type"], "environment-check")
        self.assertEqual(self.check(report, "environment.host-record")["status"], "PASS")
        self.assertEqual(self.check(report, "environment.firmware.code")["status"], "PASS")
        self.assertEqual(self.check(report, "environment.resources.ownership")["status"], "PASS")
        api = self.check(report, "environment.libvirt.api-access")
        self.assertEqual((api["status"], api["required"], api["evidence_level"]),
                         ("MANUAL_REQUIRED", False, "not-checked"))
        self.assertNotIn(("libvirt_connect",), system.calls)

    def test_plan_contains_only_inactive_unmasked_socket_runtime_start(self):
        system = FakeEnvironmentSystem()
        system.sockets["virtnetworkd.socket"] = {
            "state": "observed", "LoadState": "loaded", "ActiveState": "inactive",
            "SubState": "dead", "UnitFileState": "disabled"}
        report = self.report("plan", system)
        self.assertEqual(report["status"], "ACTION_REQUIRED")
        self.assertEqual(report["environment_plan"]["changes"], [{
            "id": "environment.action.start-virtnetworkd",
            "kind": "systemd-socket-runtime-start",
            "argv": ["/usr/bin/systemctl", "start", "virtnetworkd.socket"],
            "requires_root": True,
            "precondition_check": "environment.systemd.virtnetworkd",
            "impact": "Starts only the existing modular socket at runtime; no boot activation.",
            "documentation": "docs/HOST-SETUP.md#libvirt-dienste",
        }])
        self.assertRegex(report["plan_sha256"], r"^[0-9a-f]{64}$")

    def test_missing_packages_and_unsupported_platform_remain_visible(self):
        system = FakeEnvironmentSystem()
        del system.installed["libvirt"]
        result = self.report("plan", system)
        self.assertEqual(self.check(result, "packages.libvirt")["status"], "ACTION_REQUIRED")
        self.assertEqual(result["environment_plan"]["changes"], [])
        system = FakeEnvironmentSystem()
        system.os_release_text = "ID=cachyos\nID_LIKE=arch\n"
        result = self.report("check", system)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(system.queries, [])

    def test_virtualization_cpu_memory_and_kvm_fail_closed(self):
        cases = (
            (lambda s: s.hardware_value.update(virtualization=False), "environment.cpu.virtualization"),
            (lambda s: s.hardware_value.update(logical_cpus=1), "environment.cpu.capacity"),
            (lambda s: s.hardware_value.update(memory_bytes=2 * 1024 ** 3), "environment.memory"),
            (lambda s: setattr(s, "kvm_value", {"state": "missing"}), "environment.kvm.device"),
            (lambda s: setattr(s, "kvm_value", {"state": "present", "character_device": False,
                                                "current_process_rw": False}), "environment.kvm.device"),
        )
        for mutate, check_id in cases:
            with self.subTest(check_id=check_id):
                system = FakeEnvironmentSystem(); mutate(system)
                result = self.report("check", system)
                self.assertEqual(self.check(result, check_id)["status"], "BLOCKED")

    def test_kvm_permission_is_explicit_but_not_a_false_failure(self):
        system = FakeEnvironmentSystem()
        system.kvm_value["current_process_rw"] = False
        result = self.report("check", system)
        check = self.check(result, "environment.kvm.access")
        self.assertEqual((check["status"], check["required"]), ("MANUAL_REQUIRED", False))
        self.assertEqual(result["status"], "PASS")

    def test_missing_or_non_executable_tools_and_python_dependencies_are_actionable(self):
        system = FakeEnvironmentSystem()
        system.tools["qemu-img"] = {"state": "missing", "path": None}
        system.tools["gpg"]["executable"] = False
        system.dependencies["libvirt"] = False
        result = self.report("plan", system)
        for check_id in ("environment.tool.qemu-img", "environment.tool.gpg",
                         "environment.python.libvirt"):
            self.assertEqual(self.check(result, check_id)["status"], "ACTION_REQUIRED")
        self.assertEqual(result["environment_plan"]["changes"], [])

    def test_systemd_missing_masked_legacy_and_unavailable_are_not_planned(self):
        cases = (
            ("virtqemud.socket", absent_socket(), "BLOCKED"),
            ("virtqemud.socket", {"state": "observed", "LoadState": "masked",
                                  "ActiveState": "inactive", "SubState": "dead",
                                  "UnitFileState": "masked"}, "MANUAL_REQUIRED"),
            ("virtqemud.socket", {"state": "unavailable", "reason": "EACCES"}, "MANUAL_REQUIRED"),
        )
        for unit, state, expected in cases:
            with self.subTest(state=state):
                system = FakeEnvironmentSystem(); system.sockets[unit] = state
                result = self.report("plan", system)
                self.assertEqual(self.check(result, "environment.systemd.virtqemud")["status"], expected)
                self.assertEqual(result["environment_plan"]["changes"], [])
        system = FakeEnvironmentSystem()
        system.sockets["libvirtd.socket"] = active_socket()
        system.sockets["virtqemud.socket"] = {"state": "observed", "LoadState": "loaded",
                                                "ActiveState": "inactive", "SubState": "dead",
                                                "UnitFileState": "disabled"}
        result = self.report("plan", system)
        self.assertEqual(self.check(result, "environment.systemd.legacy-conflict")["status"],
                         "MANUAL_REQUIRED")
        self.assertEqual(result["environment_plan"]["changes"], [])

    def test_host_record_missing_unreadable_invalid_and_host_mismatch_are_distinct(self):
        cases = (
            ({"state": "missing"}, "MANUAL_REQUIRED"),
            ({"state": "unavailable", "reason": "EACCES"}, "MANUAL_REQUIRED"),
            ({"state": "invalid", "reason": "bad json"}, "BLOCKED"),
        )
        for record, expected in cases:
            with self.subTest(record=record):
                system = FakeEnvironmentSystem(); system.record_value = record
                result = self.report("check", system)
                self.assertEqual(self.check(result, "environment.host-record")["status"], expected)
                self.assertEqual(self.check(result, "environment.firmware.binding")["status"],
                                 "MANUAL_REQUIRED")
        system = FakeEnvironmentSystem(); system.record_value["record"]["plan"]["host_id"] = "b" * 64
        system.record_value["record"]["plan"]["sha256"] = setup_hash(system.record_value["record"]["plan"])
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.host-record")["status"], "BLOCKED")

    def test_firmware_missing_hash_size_and_plan_time_change_block(self):
        for mode in ("missing", "hash", "size"):
            with self.subTest(mode=mode):
                system = FakeEnvironmentSystem()
                info = system.firmware["/firmware/OVMF_CODE.fd"]
                if mode == "missing": info["state"] = "unavailable"
                if mode == "hash": info["sha256"] = "e" * 64
                if mode == "size": info["size"] = 64
                result = self.report("check", system)
                self.assertEqual(self.check(result, "environment.firmware.code")["status"], "BLOCKED")
        system = FakeEnvironmentSystem()
        original = deepcopy(system.firmware["/firmware/OVMF_CODE.fd"])
        changed = deepcopy(original); changed["inode"] = 99
        system.firmware_sequences["/firmware/OVMF_CODE.fd"] = [original, changed]
        result = self.report("plan", system)
        self.assertEqual(self.check(result, "environment.firmware.stability")["status"], "BLOCKED")
        self.assertEqual(result["environment_plan"]["changes"], [])

    def test_operator_and_qemu_identities_are_never_inferred_from_root(self):
        system = FakeEnvironmentSystem()
        system.operator_value = {"effective_uid": 0, "operator": None,
                                 "source": "invalid-sudo-hint"}
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.identity.operator")["status"],
                         "MANUAL_REQUIRED")
        system = FakeEnvironmentSystem(); system.accounts["libvirt-qemu"]["uid"] = 950
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.identity.qemu")["status"], "BLOCKED")
        system = FakeEnvironmentSystem(); system.qemu_config_value["values"]["user"] = "foreign"
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.identity.qemu")["status"], "BLOCKED")

    def test_resource_conflict_unknown_ownership_and_low_storage_are_conservative(self):
        system = FakeEnvironmentSystem(); system.resources_value = {
            "state": "conflict", "reason": "Network name is occupied by a foreign resource"}
        result = self.report("plan", system)
        self.assertEqual(self.check(result, "environment.resources.ownership")["status"], "BLOCKED")
        system = FakeEnvironmentSystem(); system.resources_value = {
            "state": "unavailable", "reason": "Root inventory was not performed"}
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.resources.ownership")["status"],
                         "MANUAL_REQUIRED")
        system = FakeEnvironmentSystem(); system.storage_value["available_bytes"] = 10 * 1024 ** 3
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.storage")["status"], "BLOCKED")
        system = FakeEnvironmentSystem(); system.storage_value["acl_verified"] = False
        result = self.report("check", system)
        self.assertEqual(self.check(result, "environment.storage")["status"], "BLOCKED")

    def test_plan_hash_is_reproducible_and_excludes_operation_id_and_timestamp(self):
        first = self.report("plan", FakeEnvironmentSystem(), OPERATION_A)
        second = build_environment_report(
            "plan", system=FakeEnvironmentSystem(),
            now=lambda: datetime(2026, 11, 1, tzinfo=timezone.utc),
            operation_id_factory=lambda: OPERATION_B)
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        changed = FakeEnvironmentSystem(); changed.hardware_value["memory_bytes"] += 1024
        third = self.report("plan", changed)
        self.assertNotEqual(first["plan_sha256"], third["plan_sha256"])

    def test_schema_check_ids_evidence_and_documentation_are_stable(self):
        schema = json.loads(files("vm_dev_lab.host_setup").joinpath("result-schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for action in ("check", "plan"):
            report = self.report(action, FakeEnvironmentSystem())
            validator.validate(report)
            ids = [check["id"] for check in report["checks"]]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue(all(check["evidence_level"] in
                                {"present", "passive", "active", "not-checked"}
                                and check["reason"] and "#" in check["documentation"]
                                for check in report["checks"]))


class EnvironmentCliTests(unittest.TestCase):
    def invoke(self, argv, system):
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.main(argv, system=system, now=lambda: NOW,
                        operation_id_factory=lambda: OPERATION_A,
                        stdout=stdout, stderr=stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_text_json_and_private_report(self):
        code, text, error = self.invoke(["environment", "check"], FakeEnvironmentSystem())
        self.assertEqual((code, error), (0, ""))
        self.assertIn("Host Setup - Environment", text)
        self.assertIn("environment.libvirt.api-access", text)
        code, raw, error = self.invoke(["environment", "plan", "--json"],
                                       FakeEnvironmentSystem())
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(raw)["artifact_type"], "environment-plan")
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "environment.json"
            code, _, error = self.invoke(["environment", "check", "--output", str(target)],
                                         FakeEnvironmentSystem())
            self.assertEqual((code, error), (0, ""))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(target.read_text())["operation_id"], OPERATION_A)

    def test_help_has_check_plan_and_apply(self):
        root = cli.parser()
        environment = root._subparsers._group_actions[0].choices["environment"]
        text = environment.format_help()
        self.assertIn("check", text)
        self.assertIn("plan", text)
        self.assertIn("apply", text)


if __name__ == "__main__":
    unittest.main()
