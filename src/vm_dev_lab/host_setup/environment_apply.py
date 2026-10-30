# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Validate and apply plans for bounded modular socket activation.

"""Confirmed environment apply limited to modular socket starts."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
import hmac
import json
import re
import subprocess
from uuid import uuid4

from jsonschema import Draft202012Validator

from vm_dev_lab.version import VERSION

from .contracts import CATALOG_NAME, CATALOG_VERSION, SCHEMA_VERSION, Status
from .environment import SOCKETS, build_environment_report, environment_plan_hash
from .package_apply import RootRequiredError, read_plan


DOC_APPLY = "docs/HOST-SETUP.md#hostumgebung-check-und-plan"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMCTL_ENV = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"}
SYSTEMCTL_TIMEOUT = 20


@dataclass(frozen=True)
class SocketExecutionResult:
    started: bool
    returncode: int | None
    outcome: str
    error_reason: str | None = None


class LocalSocketExecutor:
    """Fixed systemctl process boundary without shell or internal privilege elevation."""

    def execute(self, argv):
        try:
            completed = subprocess.run(
                argv, check=False, timeout=SYSTEMCTL_TIMEOUT, env=SYSTEMCTL_ENV,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return SocketExecutionResult(
                True, None, "unknown", "systemctl deadline was exceeded")
        except OSError as error:
            return SocketExecutionResult(False, None, "not-executed", str(error))
        except KeyboardInterrupt:
            return SocketExecutionResult(
                True, None, "unknown", "Execution was interrupted")
        return SocketExecutionResult(
            True, completed.returncode,
            "succeeded" if completed.returncode == 0 else "failed")


def _utc(now):
    return now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _expected_change(unit):
    stem = unit.removesuffix(".socket")
    return {
        "id": "environment.action.start-" + stem,
        "kind": "systemd-socket-runtime-start",
        "argv": [SYSTEMCTL, "start", unit],
        "requires_root": True,
        "precondition_check": "environment.systemd." + stem,
        "impact": ("Starts only the existing modular socket at runtime; "
                   "no boot activation."),
        "documentation": "docs/HOST-SETUP.md#libvirt-dienste",
    }


def _validate_plan(plan, confirmation):
    schema = json.loads(files("vm_dev_lab.host_setup").joinpath(
        "result-schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(plan),
                    key=lambda item: list(item.path))
    if errors:
        raise ValueError("Plan does not match the versioned JSON contract")
    if (plan.get("schema_version") != SCHEMA_VERSION
            or plan.get("artifact_type") != "environment-plan"
            or plan.get("stage") != "environment"
            or plan.get("catalog") != {
                "name": CATALOG_NAME, "version": CATALOG_VERSION}):
        raise ValueError("Plan schema, artifact, or catalog version does not match")
    actual_hash = environment_plan_hash(plan)
    recorded_hash = plan.get("plan_sha256")
    if not isinstance(recorded_hash, str) or not hmac.compare_digest(
            actual_hash, recorded_hash):
        raise ValueError("Plan content and stored plan hash do not match")
    if not isinstance(confirmation, str) or not re.fullmatch(
            r"[0-9a-f]{64}", confirmation):
        raise ValueError(
            "Confirmation must be a complete lowercase SHA256")
    if not hmac.compare_digest(confirmation, actual_hash):
        raise ValueError("Confirmation hash does not match the plan")

    environment_plan = plan["environment_plan"]
    changes = environment_plan["changes"]
    expected = []
    units = []
    for unit in SOCKETS:
        change = _expected_change(unit)
        if change in changes:
            expected.append(change)
            units.append(unit)
    candidate_ids = {change["precondition_check"] for change in expected}
    required_checks_valid = all(
        check["status"] == Status.PASS.value
        or (check["id"] in candidate_ids
            and check["status"] == Status.ACTION_REQUIRED.value)
        for check in plan["checks"] if check["required"])
    expected_status = (Status.ACTION_REQUIRED.value if expected
                       else Status.PASS.value)
    if (changes != expected or len(units) != len(set(units))
            or environment_plan["security_blockers"]
            or plan["environment_summary"]["security_blockers"]
            or plan["environment_summary"]["planned_changes"]
            != [change["id"] for change in expected]
            or not required_checks_valid or plan["status"] != expected_status
            or plan["planned_action"] is not None):
        raise ValueError(
            "Plan contains no exactly executable HS-C2a socket action")
    return actual_hash, units


def _identity_context(system):
    try:
        effective_uid = system.effective_uid()
    except Exception as error:
        raise ValueError("Effective process identity cannot be determined") from error
    if type(effective_uid) is not int or effective_uid < 0:
        raise ValueError("Effective UID is invalid")
    return {
        "effective_administrator_uid": effective_uid,
        "operator_identity": None,
        "operator_source": "validated-by-environment-preflight",
        "sudo_hint_used_for_ownership": False,
        "qemu_service_identity": None,
    }


def _precondition_allows_start(state):
    return (state.get("state") == "observed"
            and state.get("LoadState") == "loaded"
            and state.get("ActiveState") == "inactive"
            and state.get("UnitFileState") != "masked")


def _action_record(change, result, reason=None):
    return {
        "id": change["id"],
        "unit": change["argv"][2],
        "argv": list(change["argv"]),
        "started": result.started,
        "returncode": result.returncode,
        "outcome": result.outcome,
        "error_reason": reason or result.error_reason,
    }


def _not_executed(change, reason):
    return _action_record(
        change, SocketExecutionResult(False, None, "not-executed"), reason)


def _execution_summary(records):
    by_outcome = {
        "successful_actions": "succeeded",
        "failed_actions": "failed",
        "not_executed_actions": "not-executed",
        "unknown_actions": "unknown",
    }
    return {
        "actions": records,
        **{key: [record["id"] for record in records
                 if record["outcome"] == outcome]
           for key, outcome in by_outcome.items()},
        "output_capture": "none",
    }


def _post_record(report):
    return {
        "performed": True,
        "status": report["status"],
        "host_binding": report["host_binding"],
        "checks": report["checks"],
        "summary": report["summary"],
        "environment_summary": report["environment_summary"],
    }


def apply_environment_plan(plan_path, confirmation, *, system=None,
                           executor=None, now=None, operation_id_factory=None):
    """Execute only confirmed modular socket starts and verify them once."""
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    plan = read_plan(plan_path)
    actual_hash, units = _validate_plan(plan, confirmation)

    if system is None:
        from .environment import LocalEnvironmentSystem
        system = LocalEnvironmentSystem()
    identity_context = _identity_context(system)
    if identity_context["effective_administrator_uid"] != 0:
        raise RootRequiredError(
            "environment apply requires effective UID 0; start the confirmed "
            "start the invocation explicitly with sudo host-setup environment apply")

    current = build_environment_report(
        "plan", system=system, now=now,
        operation_id_factory=operation_id_factory)
    current_hash = current["plan_sha256"]
    operation_id = operation_id_factory()
    if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            operation_id):
        raise ValueError("Operation ID is not a valid UUIDv4")

    base = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "environment-apply",
        "tool_version": VERSION,
        "generated_at": _utc(now),
        "completed_at": None,
        "stage": "environment",
        "status": Status.BLOCKED.value,
        "verification_level": "active",
        "operation_id": operation_id,
        "identity_context": identity_context,
        "host_binding": current["host_binding"],
        "catalog": current["catalog"],
        "checks": current["checks"],
        "summary": current["summary"],
        "environment_summary": current["environment_summary"],
        "planned_action": None,
        "environment_plan": plan["environment_plan"],
        "plan_sha256": actual_hash,
        "confirmed_plan_sha256": confirmation,
        "precondition_plan_sha256": current_hash,
        "start_status": "not-started",
        "end_status": "rejected",
        "execution": None,
        "post_verification": {
            "performed": False, "status": None, "host_binding": None,
            "checks": [], "summary": None, "environment_summary": None},
        "manual_actions": [],
        "documentation": [DOC_APPLY],
        "notice": ("The report is evidence; no automatic resume, "
                   "recovery, or rollback of started sockets."),
    }
    if not hmac.compare_digest(current_hash, actual_hash):
        base["completed_at"] = _utc(now)
        base["manual_actions"] = [
            "Host or socket prerequisites changed; create and review a new plan."]
        return base

    executor = executor or LocalSocketExecutor()
    records = []
    aborted = False
    for index, unit in enumerate(units):
        change = plan["environment_plan"]["changes"][index]
        try:
            state = system.socket_state(unit)
        except Exception as error:
            state = {"state": "unavailable", "reason": str(error)}
        if not _precondition_allows_start(state):
            records.append(_not_executed(
                change, "Socket state differed from the plan immediately before start"))
            aborted = True
        else:
            try:
                result = executor.execute(list(change["argv"]))
            except Exception as error:
                result = SocketExecutionResult(
                    True, None, "unknown", str(error))
            records.append(_action_record(change, result))
            if result.outcome != "succeeded" or result.returncode != 0:
                aborted = True
        if aborted:
            for remaining in plan["environment_plan"]["changes"][index + 1:]:
                records.append(_not_executed(
                    remaining, "Not executed after a previous failure"))
            break

    base["start_status"] = ("started" if any(record["started"] for record in records)
                            else "not-started")
    base["execution"] = _execution_summary(records)
    try:
        post = build_environment_report(
            "check", system=system, now=now,
            operation_id_factory=operation_id_factory)
    except Exception as error:
        base["post_verification"] = {
            "performed": True, "status": Status.FAILED.value,
            "host_binding": None, "checks": [], "summary": None,
            "environment_summary": None}
        base["completed_at"] = _utc(now)
        base["status"] = Status.FAILED.value
        base["end_status"] = "unknown"
        base["manual_actions"] = [
            "Passive post-check failed unexpectedly: " + str(error),
            "Inspect socket states manually; do not repeat or roll back any action automatically.",
        ]
        return base
    base["post_verification"] = _post_record(post)
    base["completed_at"] = _utc(now)

    all_succeeded = all(record["outcome"] == "succeeded"
                        and record["returncode"] == 0 for record in records)
    success = (not aborted and all_succeeded
               and post["status"] == Status.PASS.value
               and all(next(check for check in post["checks"]
                            if check["id"] == "environment.systemd."
                            + unit.removesuffix(".socket"))["status"]
                       == Status.PASS.value for unit in units))
    if success:
        base["status"] = Status.PASS.value
        base["end_status"] = "verified"
        base["notice"] = (
            "Confirmed socket starts and expected runtime state verified; "
            "libvirt, QEMU, and VM function remain unverified.")
    else:
        unknown = any(record["outcome"] == "unknown" for record in records)
        attempted = any(record["started"] for record in records)
        base["status"] = (Status.FAILED.value if attempted or unknown
                          else Status.BLOCKED.value)
        base["end_status"] = "unknown" if unknown else "failed"
        base["manual_actions"] = [
            "Inspect socket states and the systemd journal manually; do not repeat this run automatically.",
            "Already started sockets are not stopped or rolled back automatically.",
        ]
    return base
