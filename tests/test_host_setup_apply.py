# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test confirmed package apply validation and execution boundaries.

import io
import json
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vm_dev_lab.host_setup import cli
from vm_dev_lab.host_setup.arch_packages import CATALOG, build_report
from vm_dev_lab.host_setup.contracts import bind_plan
from vm_dev_lab.host_setup.package_apply import ExecutionResult, LocalExecutor, apply_plan

from tests.test_host_setup_packages import FakeSystem, installed_catalog


NOW = datetime(2026, 10, 30, 14, 0, tzinfo=timezone.utc)
OPERATION_ID = "12345678-1234-4234-8234-123456789abc"


class FakeExecutor:
    def __init__(self, result=None, effect=None, error=None):
        self.result = result or ExecutionResult(True, 0, "succeeded")
        self.effect = effect
        self.error = error
        self.calls = []

    def execute(self, argv):
        self.calls.append(list(argv))
        if self.error:
            raise self.error
        if self.effect:
            self.effect(argv)
        return self.result


class PackageApplyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def make_plan(self, system, name="plan.json"):
        plan = build_report("plan", system=system, now=lambda: NOW)
        path = Path(self.folder.name) / name
        path.write_text(json.dumps(plan), encoding="utf-8")
        return path, plan

    def apply(self, path, confirmation, system, executor):
        return apply_plan(path, confirmation, system=system, executor=executor,
                          now=lambda: NOW, operation_id_factory=lambda: OPERATION_ID)

    def missing_system(self, *names):
        installed = installed_catalog()
        for name in names:
            del installed[name]
        return FakeSystem(installed=installed)

    def installer(self, system, result=None):
        def effect(argv):
            separator = argv.index("--")
            for name in argv[separator + 1:]:
                system.installed[name] = "installed-by-test"
        return FakeExecutor(result=result, effect=effect)

    def test_root_apply_runs_exact_pacman_argv_and_verifies(self):
        system = self.missing_system("dnsmasq", "curl")
        path, plan = self.make_plan(system)
        executor = self.installer(system)
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["end_status"], "verified")
        self.assertEqual(executor.calls, [["/usr/bin/pacman", "-Syu", "--needed",
                                           "--", "dnsmasq", "curl"]])
        self.assertEqual(result["execution"]["pacman_argv"], executor.calls[0])
        self.assertEqual(result["post_verification"]["status"], "PASS")
        self.assertEqual(len(system.queries), 3)

    def test_local_executor_uses_direct_argv_without_privilege_wrapper_or_shell(self):
        argv = ["/usr/bin/pacman", "-Syu", "--needed", "--", "dnsmasq"]
        with patch("vm_dev_lab.host_setup.package_apply.subprocess.run",
                   return_value=SimpleNamespace(returncode=0)) as runner:
            result = LocalExecutor().execute(argv)
        runner.assert_called_once_with(
            argv, check=False, env={"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertEqual(result, ExecutionResult(True, 0, "succeeded"))

    def test_non_root_apply_fails_before_host_query_or_package_operation(self):
        system = self.missing_system("dnsmasq")
        path, plan = self.make_plan(system)
        system.effective_uid_value = 1000
        executor = FakeExecutor()
        queries_before = len(system.queries)
        with self.assertRaisesRegex(ValueError, "sudo host-setup packages apply"):
            self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(len(system.queries), queries_before)
        self.assertEqual(executor.calls, [])

    def test_sudo_environment_is_only_an_ignored_or_unverified_hint(self):
        cases = (
            ({"user": None, "uid": None}, "absent"),
            ({"user": "tox", "uid": "1000"}, "present-unverified"),
            ({"user": "root", "uid": "0"}, "invalid-ignored"),
            ({"user": "tox", "uid": "0"}, "invalid-ignored"),
            ({"user": "tox", "uid": None}, "invalid-ignored"),
            ({"user": "../../bad", "uid": "1000"}, "invalid-ignored"),
        )
        for index, (environment, expected) in enumerate(cases):
            with self.subTest(environment=environment):
                system = self.missing_system("dnsmasq")
                system.sudo_environment_value = environment
                path, plan = self.make_plan(system, f"sudo-{index}.json")
                result = self.apply(path, plan["plan_sha256"], system,
                                    self.installer(system))
                identity = result["identity_context"]
                self.assertEqual(identity["effective_administrator_uid"], 0)
                self.assertEqual(identity["sudo_hint_status"], expected)
                self.assertIsNone(identity["operator_identity"])
                self.assertFalse(identity["sudo_hint_used_for_ownership"])
                self.assertIsNone(identity["qemu_service_identity"])

    def test_wrong_confirmation_and_tampered_plan_never_query_or_execute(self):
        for mode in ("confirmation", "tamper"):
            with self.subTest(mode=mode):
                system = self.missing_system("dnsmasq")
                path, plan = self.make_plan(system, mode + ".json")
                confirmation = "0" * 64
                if mode == "tamper":
                    plan["notice"] = "manipuliert"
                    path.write_text(json.dumps(plan), encoding="utf-8")
                    confirmation = plan["plan_sha256"]
                system.effective_uid_value = 1000
                executor = FakeExecutor()
                queries_before = len(system.queries)
                with self.assertRaisesRegex(ValueError,
                                            "Confirmation hash|Plan content"):
                    self.apply(path, confirmation, system, executor)
                self.assertEqual(len(system.queries), queries_before)
                self.assertEqual(executor.calls, [])

    def test_wrong_schema_catalog_or_artifact_is_rejected(self):
        changes = (("schema_version", 2), ("catalog", {"name": "arch-system-packages", "version": 2}),
                   ("artifact_type", "package-check"))
        for key, value in changes:
            with self.subTest(key=key):
                system = self.missing_system("dnsmasq")
                path, plan = self.make_plan(system, key + ".json")
                plan[key] = value
                plan["plan_sha256"] = bind_plan(plan)
                path.write_text(json.dumps(plan), encoding="utf-8")
                executor = FakeExecutor()
                with self.assertRaises(ValueError):
                    self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual(executor.calls, [])

    def test_other_host_or_changed_package_precondition_requires_new_plan(self):
        cases = ("host", "packages")
        for mode in cases:
            with self.subTest(mode=mode):
                system = self.missing_system("dnsmasq")
                path, plan = self.make_plan(system, mode + ".json")
                if mode == "host":
                    system.machine_id_value = "fedcba9876543210fedcba9876543210"
                else:
                    system.installed["curl"] = "changed-version"
                executor = FakeExecutor()
                result = self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual((result["status"], result["end_status"]),
                                 ("BLOCKED", "rejected"))
                self.assertEqual(executor.calls, [])
                self.assertFalse(result["post_verification"]["performed"])
                self.assertIn("new plan", result["manual_actions"][0])

    def test_unsupported_platform_conflict_and_database_failure_never_execute(self):
        factories = (
            lambda system: setattr(system, "os_release_text", "ID=cachyos\nID_LIKE=arch\n"),
            lambda system: system.installed.update({"iptables": "1.8.11"}),
            lambda system: setattr(system, "query_result",
                                   type("R", (), {"returncode": 2, "stdout": b"", "stderr": b"bad\n",
                                                   "timed_out": False, "output_limited": False})()),
        )
        for index, change in enumerate(factories):
            with self.subTest(index=index):
                system = self.missing_system("dnsmasq")
                path, plan = self.make_plan(system, f"blocked-{index}.json")
                change(system)
                executor = FakeExecutor()
                result = self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertEqual(executor.calls, [])

    def test_successful_exit_with_still_missing_package_fails(self):
        system = self.missing_system("dnsmasq")
        path, plan = self.make_plan(system)
        executor = FakeExecutor()
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual((result["status"], result["end_status"]), ("FAILED", "failed"))
        self.assertEqual(result["execution"]["returncode"], 0)
        self.assertEqual(result["post_verification"]["status"], "ACTION_REQUIRED")
        self.assertEqual(len(executor.calls), 1)

    def test_pacman_failures_are_not_retried_and_are_postchecked(self):
        cases = ((1, "lock"), (2, "database"), (4, "network"), (126, "authorization"),
                 (130, "aborted"))
        for code, label in cases:
            with self.subTest(label=label):
                system = self.missing_system("dnsmasq")
                path, plan = self.make_plan(system, label + ".json")
                executor = FakeExecutor(ExecutionResult(True, code, "failed", label))
                result = self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual((result["status"], result["end_status"]),
                                 ("FAILED", "failed"))
                self.assertEqual(len(executor.calls), 1)
                self.assertTrue(result["post_verification"]["performed"])
                self.assertIn("do not repeat", result["manual_actions"][0])

    def test_unknown_process_state_is_not_retried_and_stays_unknown(self):
        system = self.missing_system("dnsmasq")
        path, plan = self.make_plan(system)
        executor = FakeExecutor(error=RuntimeError("lost process status"))
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual((result["status"], result["end_status"]), ("FAILED", "unknown"))
        self.assertIsNone(result["execution"]["returncode"])
        self.assertEqual(len(executor.calls), 1)

    def test_semantically_hidden_packages_flags_and_shell_text_are_rejected(self):
        additions = ("--noconfirm", "evil;touch /tmp/not-executed", "extra-package")
        for addition in additions:
            with self.subTest(addition=addition):
                system = self.missing_system("dnsmasq")
                path, plan = self.make_plan(system, addition.replace("/", "_") + ".json")
                plan["planned_action"]["argv"].append(addition)
                plan["plan_sha256"] = bind_plan(plan)
                path.write_text(json.dumps(plan), encoding="utf-8")
                executor = FakeExecutor()
                with self.assertRaises(ValueError):
                    self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual(executor.calls, [])

    def test_duplicate_keys_symlink_and_oversized_plan_are_rejected(self):
        system = self.missing_system("dnsmasq")
        path, plan = self.make_plan(system)
        duplicate = Path(self.folder.name) / "duplicate.json"
        duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        link = Path(self.folder.name) / "link.json"
        link.symlink_to(path)
        large = Path(self.folder.name) / "large.json"
        large.write_bytes(b" " * (1024 * 1024 + 1))
        for candidate in (duplicate, link, large):
            with self.subTest(candidate=candidate.name), self.assertRaises((OSError, ValueError)):
                self.apply(candidate, plan["plan_sha256"], system, FakeExecutor())

    def test_apply_result_is_schema_valid_and_contains_no_process_output(self):
        system = self.missing_system("dnsmasq")
        path, plan = self.make_plan(system)
        result = self.apply(path, plan["plan_sha256"], system, self.installer(system))
        schema = json.loads(files("vm_dev_lab.host_setup").joinpath("result-schema.json").read_text())
        Draft202012Validator(schema).validate(result)
        self.assertEqual(result["operation_id"], OPERATION_ID)
        self.assertEqual(result["confirmed_plan_sha256"], plan["plan_sha256"])
        self.assertNotIn("stdout", result["execution"])
        self.assertNotIn("stderr", result["execution"])
        self.assertNotIn("privilege_argv", result["execution"])
        self.assertEqual(result["execution"]["output_capture"], "none-interactive-terminal")


class PackageApplyCliTests(unittest.TestCase):
    def test_apply_requires_plan_and_confirmation(self):
        for argv in (["packages", "apply"], ["packages", "apply", "--plan", "x"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as result:
                cli.parser().parse_args(argv)
            self.assertEqual(result.exception.code, 2)

    def test_non_root_cli_returns_policy_error_and_sudo_hint(self):
        with tempfile.TemporaryDirectory() as folder:
            system = FakeSystem(installed=installed_catalog())
            del system.installed["dnsmasq"]
            plan = build_report("plan", system=system, now=lambda: NOW)
            path = Path(folder) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            system.effective_uid_value = 1000
            executor = FakeExecutor()
            stdout, stderr = io.StringIO(), io.StringIO()
            code = cli.main(
                ["packages", "apply", "--plan", str(path), "--confirm",
                 plan["plan_sha256"]], system=system, executor=executor,
                now=lambda: NOW, operation_id_factory=lambda: OPERATION_ID,
                stdout=stdout, stderr=stderr)
            self.assertEqual(code, 5)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("ROOT_REQUIRED", stderr.getvalue())
            self.assertIn("sudo host-setup packages apply", stderr.getvalue())
            self.assertEqual(executor.calls, [])

    def test_apply_json_and_private_report(self):
        with tempfile.TemporaryDirectory() as folder:
            system = FakeSystem(installed=installed_catalog())
            del system.installed["dnsmasq"]
            plan = build_report("plan", system=system, now=lambda: NOW)
            plan_path = Path(folder) / "plan.json"
            output_path = Path(folder) / "result.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            def effect(argv):
                system.installed["dnsmasq"] = "installed-by-test"
            executor = FakeExecutor(effect=effect)
            stdout, stderr = io.StringIO(), io.StringIO()
            code = cli.main(["packages", "apply", "--plan", str(plan_path),
                             "--confirm", plan["plan_sha256"], "--json", "--output", str(output_path)],
                            system=system, executor=executor, now=lambda: NOW,
                            operation_id_factory=lambda: OPERATION_ID,
                            stdout=stdout, stderr=stderr)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertEqual(json.loads(stdout.getvalue())["artifact_type"], "package-apply")
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output_path.read_text())["operation_id"], OPERATION_ID)

    def test_existing_output_blocks_before_executor(self):
        with tempfile.TemporaryDirectory() as folder:
            system = FakeSystem(installed=installed_catalog())
            del system.installed["dnsmasq"]
            plan = build_report("plan", system=system, now=lambda: NOW)
            plan_path = Path(folder) / "plan.json"
            output_path = Path(folder) / "existing.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            output_path.write_text("keep", encoding="utf-8")
            executor = FakeExecutor()
            code = cli.main(["packages", "apply", "--plan", str(plan_path),
                             "--confirm", plan["plan_sha256"], "--output", str(output_path)],
                            system=system, executor=executor, now=lambda: NOW,
                            operation_id_factory=lambda: OPERATION_ID,
                            stdout=io.StringIO(), stderr=io.StringIO())
            self.assertEqual(code, 6)
            self.assertEqual(executor.calls, [])
            self.assertEqual(output_path.read_text(), "keep")

    def test_root_cannot_create_report_in_user_owned_project_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            system = FakeSystem(installed=installed_catalog())
            del system.installed["dnsmasq"]
            plan = build_report("plan", system=system, now=lambda: NOW)
            plan_path = Path(folder) / "plan.json"
            output_path = Path(folder) / "root-owned.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            executor = FakeExecutor()
            with patch("vm_dev_lab.host_setup.cli.os.geteuid", return_value=0):
                code = cli.main(
                    ["packages", "apply", "--plan", str(plan_path), "--confirm",
                     plan["plan_sha256"], "--output", str(output_path)],
                    system=system, executor=executor, now=lambda: NOW,
                    operation_id_factory=lambda: OPERATION_ID,
                    stdout=io.StringIO(), stderr=io.StringIO())
            self.assertEqual(code, 6)
            self.assertEqual(executor.calls, [])
            self.assertFalse(output_path.exists())

    def test_package_help_exposes_apply_and_root_help_exposes_environment(self):
        packages = cli.parser()._subparsers._group_actions[0].choices["packages"]
        help_text = packages.format_help()
        self.assertIn("apply", help_text)
        self.assertIn("environment", cli.parser().format_help())


if __name__ == "__main__":
    unittest.main()
