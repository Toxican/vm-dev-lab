# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Validate and execute host-bound Arch package installation plans.

"""Confirmed package operation strictly bound to a plan and host for HS-B2."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from uuid import uuid4

from jsonschema import Draft202012Validator

from vm_dev_lab.version import VERSION

from .arch_packages import CATALOG, PACMAN, build_report
from .contracts import CATALOG_NAME, CATALOG_VERSION, SCHEMA_VERSION, Status, bind_plan


PLAN_LIMIT = 1024 * 1024
DOC_APPLY = "docs/HOST-SETUP.md#paket-check-plan-und-installation"
PACMAN_ENV = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"}


@dataclass(frozen=True)
class ExecutionResult:
    started: bool
    returncode: int | None
    outcome: str
    error_reason: str | None = None


class RootRequiredError(ValueError):
    """The confirmed apply was not started as an administrative process."""


class LocalExecutor:
    """Interactive process boundary without in-program privilege elevation."""

    def execute(self, argv):
        try:
            completed = subprocess.run(argv, check=False, env=PACMAN_ENV)
        except OSError as error:
            return ExecutionResult(False, None, "not-started", str(error))
        except KeyboardInterrupt:
            return ExecutionResult(True, None, "unknown", "Execution was interrupted")
        return ExecutionResult(True, completed.returncode,
                               "succeeded" if completed.returncode == 0 else "failed")


def _utc(now):
    return now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def read_plan(path):
    target = Path(path)
    if not target.name or target.name in {".", ".."}:
        raise ValueError("invalid plan path")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > PLAN_LIMIT:
            raise ValueError("Plan is not a bounded regular file")
        data = bytearray()
        while len(data) <= PLAN_LIMIT:
            chunk = os.read(fd, min(65536, PLAN_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > PLAN_LIMIT:
            raise ValueError("Plan exceeds the size limit")
    finally:
        os.close(fd)
    try:
        return json.loads(bytes(data), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Plan is not valid unambiguous UTF-8 JSON") from error


def _validate_plan(plan, confirmation):
    schema = json.loads(files("vm_dev_lab.host_setup").joinpath("result-schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(plan), key=lambda item: list(item.path))
    if errors:
        raise ValueError("Plan does not match the versioned JSON contract")
    if (plan.get("schema_version") != SCHEMA_VERSION
            or plan.get("artifact_type") != "package-plan"
            or plan.get("catalog") != {"name": CATALOG_NAME, "version": CATALOG_VERSION}):
        raise ValueError("Plan schema, artifact, or catalog version does not match")
    actual_hash = bind_plan(plan)
    recorded_hash = plan.get("plan_sha256")
    if not isinstance(recorded_hash, str) or not hmac.compare_digest(actual_hash, recorded_hash):
        raise ValueError("Plan content and stored plan hash do not match")
    if not isinstance(confirmation, str) or not re.fullmatch(r"[0-9a-f]{64}", confirmation):
        raise ValueError("Confirmation must be a complete lowercase SHA256")
    if not hmac.compare_digest(confirmation, actual_hash):
        raise ValueError("Confirmation hash does not match the plan")
    missing = plan["summary"]["missing_packages"]
    allowed = [spec.name for spec in CATALOG]
    expected = [name for name in allowed if name in missing]
    action = plan.get("planned_action")
    if (not missing or expected != missing or plan["summary"]["blocking_checks"]
            or plan["summary"]["conflicts"] or action is None
            or action.get("packages") != missing
            or action.get("argv") != [PACMAN, "-Syu", "--needed", "--", *missing]
            or action.get("requires_separate_approval") is not True):
        raise ValueError("Plan contains no exactly executable HS-B2 package action")
    return actual_hash


def _execution_record(result, pacman_argv):
    return {
        "pacman_argv": pacman_argv,
        "started": result.started,
        "returncode": result.returncode,
        "outcome": result.outcome,
        "error_reason": result.error_reason,
        "output_capture": "none-interactive-terminal",
    }


def _identity_context(system):
    try:
        effective_uid = system.effective_uid()
    except Exception as error:
        raise ValueError("Effective process identity cannot be determined") from error
    if type(effective_uid) is not int or effective_uid < 0:
        raise ValueError("Effective UID is invalid")
    try:
        hint = system.sudo_environment()
    except Exception:
        hint = None
    hint_status = "absent"
    if hint is not None:
        if not isinstance(hint, dict) or set(hint) != {"user", "uid"}:
            hint_status = "invalid-ignored"
        else:
            user, uid = hint["user"], hint["uid"]
            if user is None and uid is None:
                hint_status = "absent"
            elif (isinstance(user, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user)
                  and user != "root" and isinstance(uid, str)
                  and re.fullmatch(r"[1-9][0-9]{0,9}", uid)):
                hint_status = "present-unverified"
            else:
                hint_status = "invalid-ignored"
    return {
        "effective_administrator_uid": effective_uid,
        "operator_identity": None,
        "operator_source": "not-resolved-by-packages-apply",
        "sudo_hint_status": hint_status,
        "sudo_hint_used_for_ownership": False,
        "qemu_service_identity": None,
    }


def _post_record(report):
    return {
        "performed": True,
        "status": report["status"],
        "host_binding": report["host_binding"],
        "checks": report["checks"],
        "summary": report["summary"],
    }


def apply_plan(plan_path, confirmation, *, system=None, executor=None, now=None,
               operation_id_factory=None):
    """Apply exactly one confirmed plan; never adjust or repeat it."""
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    plan = read_plan(plan_path)
    actual_hash = _validate_plan(plan, confirmation)

    system = system or LocalSystem()
    identity_context = _identity_context(system)
    if identity_context["effective_administrator_uid"] != 0:
        raise RootRequiredError(
            "packages apply requires effective UID 0; start the confirmed invocation "
            "start explicitly with sudo host-setup packages apply")

    current = build_report("plan", system=system, now=now)
    current_hash = current["plan_sha256"]
    preconditions_match = hmac.compare_digest(current_hash, actual_hash)
    operation_id = operation_id_factory()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        operation_id):
        raise ValueError("Operation ID is not a valid UUIDv4")

    base = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "package-apply",
        "tool_version": VERSION,
        "generated_at": _utc(now),
        "completed_at": None,
        "stage": "packages",
        "status": Status.BLOCKED.value,
        "verification_level": "active",
        "operation_id": operation_id,
        "identity_context": identity_context,
        "host_binding": current["host_binding"],
        "catalog": current["catalog"],
        "checks": current["checks"],
        "summary": current["summary"],
        "planned_action": plan["planned_action"],
        "plan_sha256": actual_hash,
        "confirmed_plan_sha256": confirmation,
        "precondition_plan_sha256": current_hash,
        "start_status": "not-started",
        "end_status": "rejected",
        "execution": None,
        "post_verification": {"performed": False, "status": None, "host_binding": None,
                              "checks": [], "summary": None},
        "manual_actions": [],
        "documentation": [DOC_APPLY],
        "notice": "The report is evidence; no automatic resume or recovery.",
    }
    if not preconditions_match:
        base["completed_at"] = _utc(now)
        base["manual_actions"] = ["Host or package prerequisites changed; create and review a new plan."]
        return base

    executor = executor or LocalExecutor()
    pacman_argv = list(plan["planned_action"]["argv"])
    try:
        result = executor.execute(pacman_argv)
    except Exception as error:
        result = ExecutionResult(True, None, "unknown", str(error))
    base["start_status"] = "started" if result.started else "not-started"
    base["execution"] = _execution_record(result, pacman_argv)

    post = build_report("check", system=system, now=now)
    base["post_verification"] = _post_record(post)
    base["completed_at"] = _utc(now)
    success = (result.started and result.returncode == 0 and result.outcome == "succeeded"
               and post["status"] == Status.PASS.value
               and not post["summary"]["missing_packages"]
               and not post["summary"]["conflicts"])
    if success:
        base["status"] = Status.PASS.value
        base["end_status"] = "verified"
        base["notice"] = "Package prerequisites are met; HS-C host readiness is not established."
    else:
        base["status"] = Status.FAILED.value
        base["end_status"] = "unknown" if result.outcome == "unknown" else "failed"
        base["manual_actions"] = [
            "Inspect pacman output and package inventory manually; do not repeat this run automatically.",
            "An interruption does not guarantee that system changes were reverted.",
        ]
    return base
