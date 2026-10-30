# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test confirmed environment apply validation and socket actions.

from importlib.resources import files
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vm_dev_lab.host_setup import cli
from vm_dev_lab.host_setup.environment import (
    build_environment_report, environment_plan_hash)
from vm_dev_lab.host_setup.environment_apply import (
    LocalSocketExecutor, SocketExecutionResult, apply_environment_plan)

from tests.test_host_setup_environment import (
    NOW, OPERATION_A, FakeEnvironmentSystem, active_socket)


class FakeSocketExecutor:
    def __init__(self, system, results=None, mutate=True, error=None):
        self.system = system
        self.results = list(results or [])
        self.mutate = mutate
        self.error = error
        self.calls = []

    def execute(self, argv):
        self.calls.append(list(argv))
        if self.error:
            raise self.error
        result = (self.results.pop(0) if self.results
                  else SocketExecutionResult(True, 0, "succeeded"))
        if self.mutate and result.outcome == "succeeded" and result.returncode == 0:
            self.system.sockets[argv[2]] = active_socket()
        return result


class EnvironmentApplyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def make_plan(self, system, units=("virtnetworkd.socket",), name="plan.json"):
        for unit in units:
            system.sockets[unit] = {
                "state": "observed", "LoadState": "loaded",
                "ActiveState": "inactive", "SubState": "dead",
                "UnitFileState": "disabled"}
        plan = build_environment_report(
            "plan", system=system, now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_A)
        path = Path(self.folder.name) / name
        path.write_text(json.dumps(plan), encoding="utf-8")
        return path, plan

    def apply(self, path, confirmation, system, executor):
        return apply_environment_plan(
            path, confirmation, system=system, executor=executor,
            now=lambda: NOW, operation_id_factory=lambda: OPERATION_A)

    def test_one_and_multiple_socket_starts_use_fixed_order_and_verify(self):
        for units in (("virtnetworkd.socket",),
                      ("virtqemud.socket", "virtnetworkd.socket",
                       "virtstoraged.socket")):
            with self.subTest(units=units):
                system = FakeEnvironmentSystem()
                path, plan = self.make_plan(system, units, "-".join(units) + ".json")
                executor = FakeSocketExecutor(system)
                result = self.apply(path, plan["plan_sha256"], system, executor)
                expected = [["/usr/bin/systemctl", "start", unit] for unit in units]
                self.assertEqual(executor.calls, expected)
                self.assertEqual((result["status"], result["end_status"]),
                                 ("PASS", "verified"))
                self.assertEqual(result["execution"]["successful_actions"],
                                 ["environment.action.start-" +
                                  unit.removesuffix(".socket") for unit in units])
                self.assertTrue(result["post_verification"]["performed"])
                self.assertEqual(result["post_verification"]["status"], "PASS")
                self.assertFalse(any(call[0] == "libvirt_connect"
                                     for call in system.calls))

    def test_valid_empty_plan_succeeds_without_mutation(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system, ())
        executor = FakeSocketExecutor(system)
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(executor.calls, [])
        self.assertEqual(result["execution"]["actions"], [])
        self.assertEqual((result["status"], result["end_status"]),
                         ("PASS", "verified"))

        blocked = FakeEnvironmentSystem()
        blocked.record_value = {"state": "missing"}
        blocked_path, blocked_plan = self.make_plan(
            blocked, (), "blocked-empty.json")
        blocked_executor = FakeSocketExecutor(blocked)
        with self.assertRaisesRegex(ValueError, "no exactly executable"):
            self.apply(blocked_path, blocked_plan["plan_sha256"], blocked,
                       blocked_executor)
        self.assertEqual(blocked_executor.calls, [])

    def test_confirmation_tampering_schema_and_artifact_fail_before_host_query(self):
        cases = ("confirmation", "tamper", "schema", "artifact")
        for mode in cases:
            with self.subTest(mode=mode):
                system = FakeEnvironmentSystem()
                path, plan = self.make_plan(system, name=mode + ".json")
                confirmation = plan["plan_sha256"]
                if mode == "confirmation":
                    confirmation = "0" * 64
                elif mode == "tamper":
                    plan["notice"] = "manipuliert"
                elif mode == "schema":
                    plan["schema_version"] = 2
                    plan["plan_sha256"] = environment_plan_hash(plan)
                    confirmation = plan["plan_sha256"]
                elif mode == "artifact":
                    plan["artifact_type"] = "environment-check"
                    plan["plan_sha256"] = environment_plan_hash(plan)
                    confirmation = plan["plan_sha256"]
                path.write_text(json.dumps(plan), encoding="utf-8")
                calls_before = list(system.calls)
                executor = FakeSocketExecutor(system)
                with self.assertRaises(ValueError):
                    self.apply(path, confirmation, system, executor)
                self.assertEqual(system.calls, calls_before)
                self.assertEqual(executor.calls, [])

    def test_unallowed_unit_and_shell_text_are_rejected_even_with_new_hash(self):
        for unit in ("virtlogd.socket", "virtnetworkd.socket;touch-x"):
            with self.subTest(unit=unit):
                system = FakeEnvironmentSystem()
                path, plan = self.make_plan(system, name=unit.replace("/", "_") + ".json")
                change = plan["environment_plan"]["changes"][0]
                change["argv"][2] = unit
                change["id"] = "environment.action.start-virtlogd"
                change["precondition_check"] = "environment.systemd.virtlogd"
                plan["environment_summary"]["planned_changes"] = [change["id"]]
                plan["plan_sha256"] = environment_plan_hash(plan)
                path.write_text(json.dumps(plan), encoding="utf-8")
                executor = FakeSocketExecutor(system)
                with self.assertRaises(ValueError):
                    self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual(executor.calls, [])

    def test_non_root_fails_after_plan_validation_but_before_host_preflight(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)
        system.effective_uid_value = 1000
        calls_before = list(system.calls)
        executor = FakeSocketExecutor(system)
        with self.assertRaisesRegex(ValueError,
                                    "sudo host-setup environment apply"):
            self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(system.calls, calls_before)
        self.assertEqual(executor.calls, [])

    def test_host_firmware_package_and_socket_drift_require_new_plan(self):
        for mode in ("host", "firmware", "package", "socket"):
            with self.subTest(mode=mode):
                system = FakeEnvironmentSystem()
                path, plan = self.make_plan(system, name=mode + ".json")
                if mode == "host":
                    system.machine_id_value = "f" * 32
                elif mode == "firmware":
                    system.firmware["/firmware/OVMF_CODE.fd"]["sha256"] = "e" * 64
                elif mode == "package":
                    del system.installed["dnsmasq"]
                else:
                    system.sockets["virtnetworkd.socket"] = active_socket()
                executor = FakeSocketExecutor(system)
                result = self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual((result["status"], result["end_status"]),
                                 ("BLOCKED", "rejected"))
                self.assertEqual(executor.calls, [])
                self.assertFalse(result["post_verification"]["performed"])

    def test_mask_between_preflight_and_action_blocks_without_systemctl(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)
        original = system.socket_state
        observations = 0

        def socket_state(unit):
            nonlocal observations
            if unit == "virtnetworkd.socket":
                observations += 1
                if observations >= 2:
                    return {"state": "observed", "LoadState": "masked",
                            "ActiveState": "inactive", "SubState": "dead",
                            "UnitFileState": "masked"}
            return original(unit)

        system.socket_state = socket_state
        executor = FakeSocketExecutor(system)
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(executor.calls, [])
        self.assertEqual(result["execution"]["not_executed_actions"],
                         ["environment.action.start-virtnetworkd"])
        self.assertEqual((result["status"], result["end_status"]),
                         ("BLOCKED", "failed"))

    def test_failed_timeout_and_unknown_process_are_not_retried(self):
        cases = (
            (SocketExecutionResult(True, 1, "failed", "systemctl failed"),
             "failed", "failed"),
            (SocketExecutionResult(True, None, "unknown", "timeout"),
             "unknown", "unknown"),
        )
        for process, outcome, end_status in cases:
            with self.subTest(outcome=outcome):
                system = FakeEnvironmentSystem()
                path, plan = self.make_plan(system, name=outcome + ".json")
                executor = FakeSocketExecutor(system, [process])
                result = self.apply(path, plan["plan_sha256"], system, executor)
                self.assertEqual(len(executor.calls), 1)
                self.assertEqual(result["execution"]["actions"][0]["outcome"],
                                 outcome)
                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(result["end_status"], end_status)
                self.assertTrue(result["post_verification"]["performed"])

    def test_exception_is_unknown_and_never_retried(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)
        executor = FakeSocketExecutor(system, error=RuntimeError("lost status"))
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual((result["status"], result["end_status"]),
                         ("FAILED", "unknown"))

        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system, name="post-error.json")
        executor = FakeSocketExecutor(system)
        original = system.operator_observation
        calls = 0

        def operator_observation():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError("postcheck interrupted")
            return original()

        system.operator_observation = operator_observation
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual((result["status"], result["end_status"]),
                         ("FAILED", "unknown"))
        self.assertTrue(result["post_verification"]["performed"])
        self.assertEqual(result["post_verification"]["status"], "FAILED")

    def test_successful_exit_without_active_socket_fails_postcheck(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)
        executor = FakeSocketExecutor(system, mutate=False)
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(result["execution"]["successful_actions"],
                         ["environment.action.start-virtnetworkd"])
        self.assertEqual((result["status"], result["end_status"]),
                         ("FAILED", "failed"))
        self.assertEqual(result["post_verification"]["status"],
                         "ACTION_REQUIRED")

    def test_new_conflict_after_start_prevents_verified_success(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)

        class ConflictExecutor(FakeSocketExecutor):
            def execute(inner_self, argv):
                result = super().execute(argv)
                system.sockets["libvirtd.socket"] = active_socket()
                return result

        result = self.apply(path, plan["plan_sha256"], system,
                            ConflictExecutor(system))
        self.assertEqual((result["status"], result["end_status"]),
                         ("FAILED", "failed"))
        self.assertEqual(result["post_verification"]["status"],
                         "MANUAL_REQUIRED")

    def test_partial_failure_preserves_success_and_marks_remaining_unexecuted(self):
        system = FakeEnvironmentSystem()
        units = ("virtqemud.socket", "virtnetworkd.socket",
                 "virtstoraged.socket")
        path, plan = self.make_plan(system, units)
        executor = FakeSocketExecutor(system, [
            SocketExecutionResult(True, 0, "succeeded"),
            SocketExecutionResult(True, 5, "failed", "unit failed"),
        ])
        result = self.apply(path, plan["plan_sha256"], system, executor)
        self.assertEqual(len(executor.calls), 2)
        self.assertEqual(result["execution"]["successful_actions"],
                         ["environment.action.start-virtqemud"])
        self.assertEqual(result["execution"]["failed_actions"],
                         ["environment.action.start-virtnetworkd"])
        self.assertEqual(result["execution"]["not_executed_actions"],
                         ["environment.action.start-virtstoraged"])
        self.assertEqual((result["status"], result["end_status"]),
                         ("FAILED", "failed"))
        self.assertEqual(system.sockets["virtqemud.socket"]["ActiveState"],
                         "active")
        self.assertTrue(all(call[1] == "start" for call in executor.calls))
        schema = json.loads(files("vm_dev_lab.host_setup").joinpath(
            "result-schema.json").read_text())
        Draft202012Validator(schema).validate(result)

    def test_local_executor_has_timeout_minimal_environment_and_no_shell(self):
        argv = ["/usr/bin/systemctl", "start", "virtqemud.socket"]
        with patch("vm_dev_lab.host_setup.environment_apply.subprocess.run",
                   return_value=SimpleNamespace(returncode=0)) as runner:
            result = LocalSocketExecutor().execute(argv)
        runner.assert_called_once_with(
            argv, check=False, timeout=20,
            env={"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.assertEqual(result, SocketExecutionResult(True, 0, "succeeded"))
        with patch("vm_dev_lab.host_setup.environment_apply.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(argv, 20)):
            timed_out = LocalSocketExecutor().execute(argv)
        self.assertEqual(timed_out.outcome, "unknown")
        self.assertTrue(timed_out.started)

    def test_schema_report_and_private_cli_output(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)
        executor = FakeSocketExecutor(system)
        result = self.apply(path, plan["plan_sha256"], system, executor)
        schema = json.loads(files("vm_dev_lab.host_setup").joinpath(
            "result-schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)

        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system, name="cli-plan.json")
        target = Path(self.folder.name) / "apply-report.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.main(
            ["environment", "apply", "--plan", str(path), "--confirm",
             plan["plan_sha256"], "--json", "--output", str(target)],
            system=system, executor=FakeSocketExecutor(system), now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_A,
            stdout=stdout, stderr=stderr)
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(stdout.getvalue())["artifact_type"],
                         "environment-apply")
        self.assertEqual(json.loads(target.read_text())["end_status"], "verified")

        text_system = FakeEnvironmentSystem()
        text_path, text_plan = self.make_plan(
            text_system, name="text-plan.json")
        text_stdout, text_stderr = io.StringIO(), io.StringIO()
        code = cli.main(
            ["environment", "apply", "--plan", str(text_path), "--confirm",
             text_plan["plan_sha256"]], system=text_system,
            executor=FakeSocketExecutor(text_system), now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_A,
            stdout=text_stdout, stderr=text_stderr)
        self.assertEqual((code, text_stderr.getvalue()), (0, ""))
        self.assertIn("Apply: verified", text_stdout.getvalue())
        self.assertIn("[succeeded] virtnetworkd.socket", text_stdout.getvalue())

        existing = Path(self.folder.name) / "existing.json"
        existing.write_text("already here")
        blocked_system = FakeEnvironmentSystem()
        blocked_path, blocked_plan = self.make_plan(
            blocked_system, name="blocked-output-plan.json")
        blocked_executor = FakeSocketExecutor(blocked_system)
        code = cli.main(
            ["environment", "apply", "--plan", str(blocked_path), "--confirm",
             blocked_plan["plan_sha256"], "--output", str(existing)],
            system=blocked_system, executor=blocked_executor, now=lambda: NOW,
            operation_id_factory=lambda: OPERATION_A,
            stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(code, 6)
        self.assertEqual(blocked_executor.calls, [])

    def test_help_exposes_environment_apply_and_requires_plan_confirmation(self):
        root = cli.parser()
        environment = root._subparsers._group_actions[0].choices["environment"]
        help_text = environment.format_help()
        self.assertIn("apply", help_text)
        with self.assertRaises(SystemExit):
            root.parse_args(["environment", "apply"])

    def test_symlink_duplicate_and_oversized_plan_are_rejected(self):
        system = FakeEnvironmentSystem()
        path, plan = self.make_plan(system)
        duplicate = Path(self.folder.name) / "duplicate.json"
        duplicate.write_text('{"schema_version":1,"schema_version":1}')
        link = Path(self.folder.name) / "link.json"
        link.symlink_to(path)
        large = Path(self.folder.name) / "large.json"
        large.write_bytes(b"x" * (1024 * 1024 + 1))
        for candidate in (duplicate, link, large):
            with self.subTest(candidate=candidate.name):
                executor = FakeSocketExecutor(system)
                with self.assertRaises((OSError, ValueError)):
                    self.apply(candidate, plan["plan_sha256"], system, executor)
                self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
