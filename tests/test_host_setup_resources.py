# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test Host Setup resource integration with the in-memory backend.

"""Test HS-C2b exclusively with the canonical in-memory backend."""
from copy import deepcopy
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vm_dev_lab.host_setup import resources
from vm_dev_lab.host_setup.cli import main as cli_main, parser
from vm_dev_lab.host_setup.package_apply import RootRequiredError
from vm_dev_lab.host_setup.resource_setup import (
    RESOURCE_APPLY, RESOURCE_PLAN, apply_resource_plan, build_resource_plan,
    resource_plan_hash)
from tests.test_host_setup import FakeSystem, setup
from tests.test_host_setup_environment import FakeEnvironmentSystem


NOW = datetime(2026, 10, 30, 20, 0, tzinfo=timezone.utc)
OPERATION_ID = "12345678-1234-4234-9234-123456789abc"


def arguments():
    return SimpleNamespace(
        owner="developer", qemu_user="libvirt-qemu", mode="manual",
        network="vm-dev-lab-nat", pool="vm-dev-lab", bridge="virbr-vdl",
        subnet="192.168.124.0/24", storage="/var/lib/libvirt/vm-dev-lab",
        min_free_gib=60, reserve_gib=20, activate=False,
        firmware_code="/firmware/CODE.fd", firmware_vars="/firmware/VARS.fd")


class HostResourceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.system = FakeSystem()
        self.environment = FakeEnvironmentSystem()
        self.environment.record_value = {"state": "missing"}

    def plan(self, system=None):
        return build_resource_plan(
            arguments(), system=system or self.system, now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_ID,
            environment_system=self.environment)

    def apply(self, report, system=None, confirmation=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "plan.json"
            path.write_text(json.dumps(report))
            return apply_resource_plan(
                path, confirmation or report["plan_sha256"],
                system=system or self.system, now=lambda: NOW,
                operation_id_factory=lambda: OPERATION_ID,
                environment_system=self.environment)

    def test_fresh_host_produces_visible_distinct_bound_plan(self):
        report = self.plan()
        self.assertEqual(report["artifact_type"], RESOURCE_PLAN)
        self.assertEqual(report["resource_state"], "fresh")
        self.assertEqual(report["status"], "ACTION_REQUIRED")
        self.assertEqual(report["plan_sha256"], resource_plan_hash(report))
        self.assertEqual(report["resource_plan"]["schema_version"], 2)
        self.assertEqual(report["resource_plan"]["owner"]["uid"], 1000)
        self.assertEqual(self.system.commands, [])
        self.assertIsNone(self.system.state)

    def test_complete_host_is_verified_without_duplicate_change(self):
        fresh = self.plan()
        resources.apply(fresh["resource_plan"], self.system,
                        fresh["resource_plan"]["sha256"], True)
        before = list(self.system.commands)
        complete = self.plan()
        self.assertEqual(complete["resource_state"], "complete")
        self.assertEqual(complete["status"], "PASS")
        result = self.apply(complete)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(before, self.system.commands)

    def test_pending_and_partial_records_block_without_retry(self):
        raw = resources.make_plan(arguments(), self.system)
        for state in ("pending", "partial"):
            system = FakeSystem()
            system.state = {"plan": deepcopy(raw), "status": state, "completed": []}
            report = self.plan(system)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["resource_state"], state)
            self.assertIsNone(report["plan_sha256"])
            self.assertEqual(system.commands, [])

    def test_foreign_resource_subnet_storage_and_prerequisites_block(self):
        cases = []
        foreign = FakeSystem()
        foreign.objects["networks"].append(
            '<network><name>foreign</name><ip address="192.168.124.1" prefix="24"/></network>')
        cases.append(foreign)
        storage = FakeSystem()
        storage.directory = {"device": 1, "inode": 2, "uid": 1000, "gid": 1000}
        cases.append(storage)
        missing = FakeSystem()
        missing.tools_missing = ["setfacl"]
        cases.append(missing)
        for system in cases:
            report = self.plan(system)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["resource_state"], "foreign-or-conflicting")
            self.assertEqual(system.commands, [])

    def test_missing_package_or_inactive_required_socket_blocks_plan(self):
        self.environment.installed.pop("qemu-desktop")
        report = self.plan()
        self.assertEqual(report["resource_state"], "prerequisite-blocked")
        self.assertIn("packages.qemu-desktop", report["checks"][0]["reason"])
        self.environment = FakeEnvironmentSystem()
        self.environment.record_value = {"state": "missing"}
        self.environment.sockets["virtnetworkd.socket"]["ActiveState"] = "inactive"
        report = self.plan()
        self.assertEqual(report["resource_state"], "prerequisite-blocked")
        self.assertIn("environment.systemd.virtnetworkd",
                      report["checks"][0]["reason"])
        self.assertEqual(self.system.commands, [])

    def test_apply_rejects_hash_tamper_and_socket_artifact(self):
        report = self.plan()
        with self.assertRaises(ValueError):
            self.apply(report, confirmation="0" * 64)
        changed = deepcopy(report)
        changed["resource_plan"]["storage"] = "/var/lib/libvirt/changed"
        with self.assertRaises(ValueError):
            self.apply(changed)
        socket = deepcopy(report)
        socket["artifact_type"] = "environment-plan"
        socket["plan_sha256"] = resource_plan_hash(socket)
        with self.assertRaises(ValueError):
            self.apply(socket)
        self.assertEqual(self.system.commands, [])

    def test_apply_requires_root_before_resource_inventory(self):
        report = self.plan()
        self.system.effective_uid = lambda: 1000
        with self.assertRaises(RootRequiredError):
            self.apply(report)
        self.assertEqual(self.system.commands, [])

    def test_apply_rechecks_host_and_resource_identity(self):
        report = self.plan()
        self.system.host = "b" * 64
        result = self.apply(report)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["resource_state"], "unknown")
        self.assertEqual(self.system.commands, [])

    def test_success_uses_canonical_apply_and_reports_bound_identities(self):
        report = self.plan()
        with patch.object(resources, "apply", wraps=resources.apply) as shared:
            result = self.apply(report)
        shared.assert_called_once()
        self.assertEqual(result["artifact_type"], RESOURCE_APPLY)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["resource_state"], "complete")
        self.assertEqual(result["identity_context"]["operator_identity"]["name"],
                         "developer")
        self.assertEqual(result["identity_context"]["qemu_service_identity"]["name"],
                         "libvirt-qemu")
        self.assertFalse(result["identity_context"]["sudo_hint_used_for_ownership"])

    def test_partial_failure_is_preserved_without_retry_or_rollback(self):
        report = self.plan()
        self.system.failure = "pool"
        result = self.apply(report)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["resource_state"], "partial")
        self.assertEqual(self.system.state["completed"],
                         ["storage-directory-and-acl", "network-defined"])
        before = list(self.system.commands)
        second = self.plan()
        self.assertEqual(second["status"], "BLOCKED")
        self.assertEqual(before, self.system.commands)
        self.assertFalse(any(command[0] in {"destroy", "undefine", "delete"}
                             for command in before))

    def test_script_and_assistant_export_same_core_functions(self):
        self.assertIs(setup.make_plan, resources.make_plan)
        self.assertIs(setup.preflight, resources.preflight)
        self.assertIs(setup.apply, resources.apply)
        self.assertIs(setup.definitions, resources.definitions)

    def test_resource_artifacts_validate_against_public_schema(self):
        schema = json.loads((Path(resources.__file__).with_name(
            "result-schema.json")).read_text())
        plan = self.plan()
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(plan)), [])
        applied = self.apply(plan)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(applied)), [])

    def test_cli_exposes_privileged_resource_plan_and_private_output(self):
        help_text = parser()._subparsers._group_actions[0].choices[
            "environment"]._subparsers._group_actions[0].choices[
                "plan"].format_help()
        self.assertIn("--resources", help_text)
        self.assertIn("--firmware-code", help_text)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "resource-plan.json"
            code = cli_main([
                "environment", "plan", "--resources",
                "--owner", "developer", "--qemu-user", "libvirt-qemu",
                "--mode", "manual", "--firmware-code", "/firmware/CODE.fd",
                "--firmware-vars", "/firmware/VARS.fd", "--output", str(output),
            ], system=self.system, now=lambda: NOW,
                operation_id_factory=lambda: OPERATION_ID,
                environment_system=self.environment, stdout=StringIO())
            self.assertEqual(code, 3)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text())["artifact_type"],
                             RESOURCE_PLAN)

    def test_cli_requires_all_explicit_resource_identities(self):
        error = StringIO()
        code = cli_main([
            "environment", "plan", "--resources", "--owner", "developer",
        ], system=self.system, now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_ID, stderr=error,
            environment_system=self.environment)
        self.assertEqual(code, 6)
        self.assertIn("--qemu-user", error.getvalue())
        self.assertEqual(self.system.commands, [])


if __name__ == "__main__":
    unittest.main()
