# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test ownership-safe planning and removal of host resources.

"""Test HS-D2 exclusively with in-memory resources."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET

from jsonschema import Draft202012Validator

from vm_dev_lab.host_setup import resources
from vm_dev_lab.host_setup.cli import main as cli_main, parser
from vm_dev_lab.host_setup.package_apply import RootRequiredError
from vm_dev_lab.host_setup.resource_uninstall import (
    UNINSTALL_APPLY, UNINSTALL_CHECK, UNINSTALL_PLAN, apply_uninstall_plan,
    build_uninstall_report, uninstall_plan_hash)
from tests.test_host_setup import FakeSystem


NOW = datetime(2026, 10, 30, 22, 0, tzinfo=timezone.utc)
OPERATION_ID = "22345678-1234-4234-9234-123456789abc"


def setup_arguments(mode="manual"):
    return SimpleNamespace(
        owner="developer", qemu_user="libvirt-qemu", mode=mode,
        network="vm-dev-lab-nat", pool="vm-dev-lab", bridge="virbr-vdl",
        subnet="192.168.124.0/24", storage="/var/lib/libvirt/vm-dev-lab",
        min_free_gib=60, reserve_gib=20, activate=False,
        firmware_code="/firmware/CODE.fd", firmware_vars="/firmware/VARS.fd")


class FakeUninstallSystem(FakeSystem):
    def __init__(self, mode="manual"):
        super().__init__()
        self.effective_uid_value = 0
        self.entries = []
        self.mounts = []
        self.volumes = []
        self.firewalls = {"trusted-lab": None, "legacy": None}
        self.active_values = {"network": False, "pool": False}
        self.uninstall_failure = None
        plan = resources.make_plan(setup_arguments(mode), self)
        resources.apply(plan, self, plan["sha256"], True)
        self.setup_commands = list(self.commands)
        self.commands.clear()

    def effective_uid(self):
        return self.effective_uid_value

    def lock_available(self):
        if self.locked:
            raise resources.SetupError("locked")
        return True

    def storage_entries(self, path):
        return list(self.entries)

    def storage_mounts(self, path):
        return list(self.mounts)

    def pool_volumes(self, identity):
        return list(self.volumes)

    def firewall_records(self):
        return deepcopy(self.firewalls)

    def active(self, kind, identity):
        return self.active_values[kind]

    def defined_identities(self, kind):
        bucket = "networks" if kind == "network" else "pools"
        return sorted(ET.fromstring(text).findtext("uuid")
                      for text in self.objects[bucket])

    def disable_autostart(self, kind, identity):
        self.commands.append((kind + "-autostart-disable", identity))
        if self.uninstall_failure == kind + "-autostart-disabled":
            raise resources.SetupError("injected " + self.uninstall_failure)
        self.policies[kind] = False

    def undefine(self, kind, identity):
        self.commands.append((kind + "-undefine", identity))
        if self.uninstall_failure == kind + "-undefined":
            raise resources.SetupError("injected " + self.uninstall_failure)
        bucket = "networks" if kind == "network" else "pools"
        self.objects[bucket] = [
            text for text in self.objects[bucket]
            if ET.fromstring(text).findtext("uuid") != identity]

    def remove_storage(self, path, expected):
        self.commands.append(("storage-rmdir", path))
        if self.uninstall_failure == "storage-directory-removed":
            raise resources.SetupError("injected storage-directory-removed")
        if self.entries or self.mounts:
            raise resources.SetupError("storage changed")
        self.directory = None


class HostResourceUninstallTests(unittest.TestCase):
    def setUp(self):
        self.system = FakeUninstallSystem()

    def report(self, action="uninstall-plan", system=None):
        return build_uninstall_report(
            action, system=system or self.system, now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_ID)

    def apply(self, report, system=None, confirmation=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "uninstall-plan.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            return apply_uninstall_plan(
                path, confirmation or report["plan_sha256"],
                system=system or self.system, now=lambda: NOW,
                operation_id_factory=lambda: OPERATION_ID)

    def test_check_and_plan_are_bound_and_mutation_free(self):
        before = deepcopy((self.system.objects, self.system.state,
                           self.system.directory, self.system.commands))
        check = self.report("uninstall-check")
        plan = self.report()
        self.assertEqual((check["artifact_type"], plan["artifact_type"]),
                         (UNINSTALL_CHECK, UNINSTALL_PLAN))
        self.assertEqual(check["status"], "ACTION_REQUIRED")
        self.assertIsNone(check["uninstall_plan"])
        self.assertEqual(plan["plan_sha256"], uninstall_plan_hash(plan))
        self.assertEqual(plan["uninstall_plan"]["steps"], [
            "pool-undefined", "network-undefined", "storage-directory-removed"])
        self.assertEqual(before, (self.system.objects, self.system.state,
                                  self.system.directory, self.system.commands))

    def test_success_removes_only_own_resources_and_writes_tombstone(self):
        self.system.objects["networks"].append(
            "<network><name>foreign</name><uuid>aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa</uuid></network>")
        self.system.objects["pools"].append(
            "<pool type='dir'><name>foreign</name><uuid>bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb</uuid><target><path>/foreign</path></target></pool>")
        plan = self.report()
        result = self.apply(plan)
        self.assertEqual((result["artifact_type"], result["status"],
                          result["uninstall_state"]),
                         (UNINSTALL_APPLY, "PASS", "removed"))
        self.assertEqual([item["outcome"] for item in result["execution"]],
                         ["succeeded", "succeeded", "succeeded"])
        self.assertIsNone(self.system.directory)
        self.assertEqual(self.system.state["status"], "removed")
        self.assertEqual(self.system.state["uninstall"]["status"], "removed")
        self.assertEqual(len(self.system.objects["networks"]), 1)
        self.assertEqual(len(self.system.objects["pools"]), 1)
        self.assertEqual(ET.fromstring(self.system.objects["networks"][0]).findtext("name"),
                         "foreign")

    def test_permanent_mode_disables_only_bound_autostart_first(self):
        system = FakeUninstallSystem("permanent")
        plan = self.report(system=system)
        self.assertEqual(plan["uninstall_plan"]["steps"][:2], [
            "pool-autostart-disabled", "network-autostart-disabled"])
        result = self.apply(plan, system=system)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual([command[0] for command in system.commands], [
            "pool-autostart-disable", "network-autostart-disable",
            "pool-undefine", "network-undefine", "storage-rmdir"])

    def test_record_states_missing_invalid_and_removed_block(self):
        for state in (None, "pending", "partial", "removed", "uninstall-partial"):
            with self.subTest(state=state):
                system = FakeUninstallSystem()
                if state is None:
                    system.state = None
                else:
                    system.state["status"] = state
                report = self.report(system=system)
                self.assertEqual(report["status"], "BLOCKED")
                self.assertIsNone(report["plan_sha256"])
                self.assertEqual(system.commands, [])

    def test_identity_xml_metadata_active_and_autostart_drift_block(self):
        cases = []
        host = FakeUninstallSystem(); host.host = "b" * 64; cases.append(host)
        xml = FakeUninstallSystem()
        xml.objects["networks"][0] = xml.objects["networks"][0].replace("mode=\"nat\"", "mode=\"route\"")
        cases.append(xml)
        metadata = FakeUninstallSystem()
        metadata.objects["networks"][0] = metadata.objects["networks"][0].replace("setup_id=", "other=")
        cases.append(metadata)
        active = FakeUninstallSystem(); active.active_values["pool"] = True; cases.append(active)
        policy = FakeUninstallSystem(); policy.policies["network"] = True; cases.append(policy)
        for system in cases:
            with self.subTest(system=cases.index(system)):
                self.assertEqual(self.report(system=system)["status"], "BLOCKED")
                self.assertEqual(system.commands, [])

    def test_references_volumes_content_mount_inode_owner_acl_and_firewall_block(self):
        cases = []
        domain = FakeUninstallSystem()
        domain.objects["domains"].append(
            '<domain><name>guest</name><devices><interface><source network="vm-dev-lab-nat"/></interface></devices></domain>')
        cases.append(domain)
        volume = FakeUninstallSystem(); volume.volumes = ["disk.qcow2"]; cases.append(volume)
        content = FakeUninstallSystem(); content.entries = ["unknown.img"]; cases.append(content)
        mount = FakeUninstallSystem(); mount.mounts = [mount.state["plan"]["storage"]]; cases.append(mount)
        inode = FakeUninstallSystem(); inode.directory["inode"] += 1; cases.append(inode)
        owner = FakeUninstallSystem(); owner.directory["uid"] += 1; cases.append(owner)
        acl = FakeUninstallSystem(); acl.acl = lambda path: "user::rwx"; cases.append(acl)
        firewall = FakeUninstallSystem()
        firewall.firewalls["trusted-lab"] = {"status": "complete", "plan": {}}
        cases.append(firewall)
        for system in cases:
            with self.subTest(system=cases.index(system)):
                report = self.report(system=system)
                self.assertEqual(report["status"], "BLOCKED")
                self.assertEqual(system.commands, [])

    def test_removed_firewall_records_must_match_setup(self):
        setup_id = self.system.state["plan"]["setup_id"]
        self.system.firewalls = {
            "trusted-lab": {"status": "removed", "plan": {"setup_id": setup_id}},
            "legacy": {"status": "removed", "plan": {"setup": {"setup_id": setup_id}}},
        }
        self.assertEqual(self.report()["status"], "ACTION_REQUIRED")
        self.system.firewalls["legacy"]["plan"]["setup"]["setup_id"] = (
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        self.assertEqual(self.report()["status"], "BLOCKED")

    def test_lock_and_non_root_block_without_inventory_mutation(self):
        self.system.locked = True
        self.assertEqual(self.report()["status"], "BLOCKED")
        system = FakeUninstallSystem(); system.effective_uid_value = 1000
        with self.assertRaises(RootRequiredError):
            self.report(system=system)
        self.assertEqual(system.commands, [])

    def test_hash_tamper_confirmation_and_artifact_rejected_before_host_query(self):
        report = self.report()
        before = deepcopy(self.system.commands)
        with self.assertRaises(ValueError):
            self.apply(report, confirmation="0" * 64)
        changed = deepcopy(report)
        changed["uninstall_plan"]["pool_uuid"] = changed["uninstall_plan"]["network_uuid"]
        changed["plan_sha256"] = uninstall_plan_hash(changed)
        with self.assertRaises(ValueError):
            self.apply(changed)
        changed = deepcopy(report)
        changed["artifact_type"] = UNINSTALL_CHECK
        changed["plan_sha256"] = uninstall_plan_hash(changed)
        with self.assertRaises(ValueError):
            self.apply(changed)
        self.assertEqual(before, self.system.commands)

    def test_apply_drift_rejects_before_intent(self):
        report = self.report()
        self.system.entries = ["appeared.img"]
        result = self.apply(report)
        self.assertEqual((result["status"], result["end_status"]),
                         ("BLOCKED", "rejected"))
        self.assertEqual(self.system.state["status"], "complete")
        self.assertEqual(self.system.commands, [])

    def test_each_teardown_failure_stops_without_retry_or_rollback(self):
        for mode, step in (("permanent", "pool-autostart-disabled"),
                           ("permanent", "network-autostart-disabled"),
                           ("manual", "pool-undefined"),
                           ("manual", "network-undefined"),
                           ("manual", "storage-directory-removed")):
            with self.subTest(step=step):
                system = FakeUninstallSystem(mode)
                report = self.report(system=system)
                system.uninstall_failure = step
                result = self.apply(report, system=system)
                self.assertEqual((result["status"], result["uninstall_state"]),
                                 ("FAILED", "partial"))
                self.assertEqual(system.state["status"], "uninstall-partial")
                outcomes = [item["outcome"] for item in result["execution"]]
                self.assertEqual(outcomes.count("unknown"), 1)
                self.assertTrue(all(value in {"succeeded", "unknown", "not-executed"}
                                    for value in outcomes))
                failed_index = outcomes.index("unknown")
                self.assertTrue(all(value == "not-executed"
                                    for value in outcomes[failed_index + 1:]))
                self.assertFalse(any("define" == command[0]
                                     for command in system.commands))

    def test_schema_cli_help_and_private_reports(self):
        schema = json.loads(Path(resources.__file__).with_name(
            "result-schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        check = self.report("uninstall-check")
        plan = self.report()
        Draft202012Validator(schema).validate(check)
        Draft202012Validator(schema).validate(plan)

        help_text = parser()._subparsers._group_actions[0].choices[
            "environment"].format_help()
        self.assertIn("uninstall-check", help_text)
        self.assertIn("uninstall-plan", help_text)
        self.assertIn("uninstall", help_text)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "uninstall-plan.json"
            code = cli_main(
                ["environment", "uninstall-plan", "--json", "--output", str(output)],
                system=self.system, now=lambda: NOW,
                operation_id_factory=lambda: OPERATION_ID,
                stdout=StringIO(), stderr=StringIO())
            self.assertEqual(code, 3)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            stored = json.loads(output.read_text())
            self.assertEqual(stored["artifact_type"], UNINSTALL_PLAN)
            result_path = Path(folder) / "uninstall-result.json"
            stdout, stderr = StringIO(), StringIO()
            code = cli_main(
                ["environment", "uninstall", "--plan", str(output),
                 "--confirm", stored["plan_sha256"], "--json",
                 "--output", str(result_path)],
                system=self.system, now=lambda: NOW,
                operation_id_factory=lambda: OPERATION_ID,
                stdout=stdout, stderr=stderr)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertEqual(result_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(stdout.getvalue())["artifact_type"],
                             UNINSTALL_APPLY)
            self.assertEqual(json.loads(result_path.read_text())["status"], "PASS")

    def test_apply_report_validates_against_public_schema(self):
        result = self.apply(self.report())
        schema = json.loads(Path(resources.__file__).with_name(
            "result-schema.json").read_text())
        Draft202012Validator(schema).validate(result)


if __name__ == "__main__":
    unittest.main()
