# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Adapt environment plans to the canonical host resource setup engine.

"""HS-C2b adapter for the canonical host-resource contract."""
from __future__ import annotations

from datetime import datetime, timezone
from importlib.resources import files
import hashlib
import hmac
import json
import os
import re
from types import SimpleNamespace
from uuid import uuid4

from jsonschema import Draft202012Validator

from vm_dev_lab.version import VERSION

from .contracts import CATALOG_NAME, CATALOG_VERSION, SCHEMA_VERSION, Status, canonical
from .environment import LocalEnvironmentSystem, build_environment_report
from .package_apply import RootRequiredError, read_plan
from . import resources


DOC_RESOURCE = "docs/HOST-SETUP.md#labressourcen-planen-und-anlegen"
RESOURCE_PLAN = "environment-resource-plan"
RESOURCE_APPLY = "environment-resource-apply"
_RESOURCE_DECISION_CHECKS = {
    "environment.host-record",
    "environment.firmware.binding",
    "environment.identity.operator",
    "environment.identity.qemu",
    "environment.resources.ownership",
    "environment.qemu.capabilities",
}


def _utc(now):
    return now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def resource_plan_hash(report):
    material = {key: value for key, value in report.items()
                if key not in {"generated_at", "operation_id", "plan_sha256"}}
    return hashlib.sha256(canonical(material)).hexdigest()


def _host_binding(host_id):
    return {
        "machine_id_sha256": host_id,
        "architecture": None,
        "os": {"id": "arch", "name": "Arch Linux", "id_like": []},
        "package_manager": {"name": "pacman", "path": None},
    }


def _check(status, observed, *, reason=None, manual_action=None):
    return {
        "id": "environment.resources.inventory",
        "status": status,
        "required": True,
        "package": None,
        "purpose": "Qualify dedicated lab resources and host record v2",
        "observed": observed,
        "proposed_change": ("Apply the canonical host resource plan"
                            if status == Status.ACTION_REQUIRED.value else None),
        "executed_change": None,
        "error_reason": reason if status in {
            Status.BLOCKED.value, Status.FAILED.value} else None,
        "documentation": DOC_RESOURCE,
        "manual_action": manual_action,
        "evidence_level": "active",
        "reason": reason or observed,
    }


def _base(*, artifact_type, status, state, host_id, resource_plan, check,
          now, operation_id_factory, prerequisite_checks=None):
    planned = (["storage-directory-and-acl", "network-defined", "pool-defined"]
               if state == "fresh" else [])
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": artifact_type,
        "tool_version": VERSION,
        "generated_at": _utc(now),
        "stage": "environment",
        "status": status,
        "verification_level": "active",
        "operation_id": operation_id_factory(),
        "host_binding": _host_binding(host_id),
        "catalog": {"name": CATALOG_NAME, "version": CATALOG_VERSION},
        "checks": [check],
        "summary": {
            "fulfilled_packages": [], "missing_packages": [], "conflicts": [],
            "blocking_checks": ([] if status in {
                Status.PASS.value, Status.ACTION_REQUIRED.value}
                                else [check["id"]]),
        },
        "planned_action": None,
        "plan_sha256": None,
        "resource_state": state,
        "resource_plan": resource_plan,
        "resource_summary": {
            "planned_changes": planned,
            "record_status": (state if state in {"complete", "pending", "partial"}
                              else None),
        },
        "environment_prerequisites": prerequisite_checks or [],
        "documentation": [DOC_RESOURCE],
        "notice": ("Privileged libvirt inventory; not a passive check. "
                   "The report is not a resume token and performs no recovery."),
    }
    if artifact_type == RESOURCE_PLAN and resource_plan is not None and status in {
            Status.PASS.value, Status.ACTION_REQUIRED.value}:
        report["plan_sha256"] = resource_plan_hash(report)
    return report


def _prerequisites(environment_system, now, operation_id_factory):
    report = build_environment_report(
        "check", system=environment_system, now=now,
        operation_id_factory=operation_id_factory)
    checks = [check for check in report["checks"]
              if check["id"] not in _RESOURCE_DECISION_CHECKS]
    blockers = [check for check in checks if check["required"]
                and check["status"] != Status.PASS.value]
    return checks, blockers


def _effective_uid(system, explicit):
    if explicit is not None:
        return explicit
    method = getattr(system, "effective_uid", None)
    return method() if method else os.geteuid()


def _require_root(system, explicit):
    uid = _effective_uid(system, explicit)
    if type(uid) is not int or uid != 0:
        raise RootRequiredError(
            "Lab-resource inventory and apply require effective UID 0; "
            "start the entire invocation explicitly with sudo")
    return uid


def resource_arguments(namespace):
    """Map the CLI namespace to the unchanged setup-host.py contract."""
    return SimpleNamespace(
        owner=namespace.owner, qemu_user=namespace.qemu_user, mode=namespace.mode,
        network=namespace.network, pool=namespace.pool, bridge=namespace.bridge,
        subnet=namespace.subnet, storage=namespace.storage,
        min_free_gib=namespace.min_free_gib, reserve_gib=namespace.reserve_gib,
        activate=namespace.activate, firmware_code=namespace.firmware_code,
        firmware_vars=namespace.firmware_vars)


def build_resource_plan(namespace, *, system=None, now=None,
                        operation_id_factory=None, effective_uid=None,
                        environment_system=None):
    """Privileged but mutation-free resource inventory and planning."""
    system = system or resources.System()
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    _require_root(system, effective_uid)
    host_id = system.host_id()
    environment_system = environment_system or LocalEnvironmentSystem()
    prerequisite_checks, prerequisite_blockers = _prerequisites(
        environment_system, now, operation_id_factory)
    if prerequisite_blockers:
        ids = [check["id"] for check in prerequisite_blockers]
        return _base(
            artifact_type=RESOURCE_PLAN, status=Status.BLOCKED.value,
            state="prerequisite-blocked", host_id=host_id, resource_plan=None,
            check=_check(Status.BLOCKED.value,
                         "Resource planning is blocked by host prerequisites",
                         reason=", ".join(ids),
                         manual_action="Resolve package, KVM, or socket prerequisites separately"),
            now=now, operation_id_factory=operation_id_factory,
            prerequisite_checks=prerequisite_checks)
    record = system.record()
    if record is not None:
        state = record.get("status") if isinstance(record, dict) else "invalid"
        plan = record.get("plan") if isinstance(record, dict) else None
        if state in {"pending", "partial"}:
            return _base(
                artifact_type=RESOURCE_PLAN, status=Status.BLOCKED.value,
                state=state, host_id=host_id, resource_plan=plan,
                check=_check(Status.BLOCKED.value,
                             f"Host record is {state}",
                             reason="Partial state is neither continued nor repaired",
                             manual_action="Inspect the original record and resources manually"),
                now=now, operation_id_factory=operation_id_factory,
                prerequisite_checks=prerequisite_checks)
        if state != "complete" or not isinstance(plan, dict):
            return _base(
                artifact_type=RESOURCE_PLAN, status=Status.BLOCKED.value,
                state="invalid", host_id=host_id, resource_plan=plan,
                check=_check(Status.BLOCKED.value, "Host record is inconsistent",
                             reason="Unknown host record state",
                             manual_action="Inspect the original record manually"),
                now=now, operation_id_factory=operation_id_factory,
                prerequisite_checks=prerequisite_checks)
        try:
            resources.preflight(plan, system, live=False, record=record)
        except (resources.SetupError, OSError, ValueError, TypeError, KeyError) as error:
            return _base(
                artifact_type=RESOURCE_PLAN, status=Status.BLOCKED.value,
                state="complete", host_id=host_id, resource_plan=plan,
                check=_check(Status.BLOCKED.value,
                             "Complete record differs from the host state",
                             reason=str(error),
                             manual_action="Resolve the deviation manually; no repair"),
                now=now, operation_id_factory=operation_id_factory,
                prerequisite_checks=prerequisite_checks)
        return _base(
            artifact_type=RESOURCE_PLAN, status=Status.PASS.value,
            state="complete", host_id=host_id, resource_plan=plan,
            check=_check(Status.PASS.value,
                         "Owned complete host record v2 is qualified"),
            now=now, operation_id_factory=operation_id_factory,
            prerequisite_checks=prerequisite_checks)
    try:
        plan = resources.make_plan(resource_arguments(namespace), system)
    except (resources.SetupError, OSError, ValueError, TypeError, KeyError) as error:
        return _base(
            artifact_type=RESOURCE_PLAN, status=Status.BLOCKED.value,
            state="foreign-or-conflicting", host_id=host_id, resource_plan=None,
            check=_check(Status.BLOCKED.value,
                         "Fresh setup is blocked by the inventory result",
                         reason=str(error),
                         manual_action="Resolve the conflict or missing prerequisite manually"),
            now=now, operation_id_factory=operation_id_factory,
            prerequisite_checks=prerequisite_checks)
    return _base(
        artifact_type=RESOURCE_PLAN, status=Status.ACTION_REQUIRED.value,
        state="fresh", host_id=host_id, resource_plan=plan,
        check=_check(Status.ACTION_REQUIRED.value,
                     "No owned lab resources; a confirmed setup apply is required"),
        now=now, operation_id_factory=operation_id_factory,
        prerequisite_checks=prerequisite_checks)


def _validate_resource_plan(report, confirmation):
    schema = json.loads(files("vm_dev_lab.host_setup").joinpath(
        "result-schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(report),
                    key=lambda item: list(item.path))
    if errors:
        raise ValueError("Resource plan does not match the versioned JSON contract")
    if (report.get("artifact_type") != RESOURCE_PLAN
            or report.get("schema_version") != SCHEMA_VERSION
            or report.get("stage") != "environment"
            or report.get("resource_state") not in {"fresh", "complete"}
            or report.get("status") not in {
                Status.ACTION_REQUIRED.value, Status.PASS.value}
            or not isinstance(report.get("resource_plan"), dict)):
        raise ValueError("Artifact is not an executable HS-C2b resource plan")
    actual = resource_plan_hash(report)
    recorded = report.get("plan_sha256")
    if not isinstance(recorded, str) or not hmac.compare_digest(actual, recorded):
        raise ValueError("Resource plan was changed after planning")
    if not isinstance(confirmation, str) or not re.fullmatch(r"[0-9a-f]{64}", confirmation):
        raise ValueError("Confirmation must be a complete SHA256")
    if not hmac.compare_digest(actual, confirmation):
        raise ValueError("Confirmation hash does not match the resource plan")
    resources.validate_plan(report["resource_plan"])
    return actual


def apply_resource_plan(plan_path, confirmation, *, system=None, now=None,
                        operation_id_factory=None, effective_uid=None,
                        environment_system=None):
    """Execute a confirmed plan only through the canonical apply path."""
    report = read_plan(plan_path)
    actual = _validate_resource_plan(report, confirmation)
    system = system or resources.System()
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    uid = _require_root(system, effective_uid)
    plan = report["resource_plan"]
    environment_system = environment_system or LocalEnvironmentSystem()
    prerequisite_checks, prerequisite_blockers = _prerequisites(
        environment_system, now, operation_id_factory)
    if prerequisite_blockers or prerequisite_checks != report["environment_prerequisites"]:
        raise ValueError(
            "Package, KVM, or socket prerequisites differ from the confirmed plan")
    try:
        message = resources.apply(plan, system, plan["sha256"], True)
        current = system.record()
        state = (current.get("status") if isinstance(current, dict) else "unknown")
        succeeded = state == "complete"
        check = _check(
            Status.PASS.value if succeeded else Status.FAILED.value,
            message if succeeded else "Apply ended without a complete host record",
            reason=None if succeeded else "Post-check did not produce a complete record",
            manual_action=None if succeeded else "Inspect the original record and resources manually")
        result = _base(
            artifact_type=RESOURCE_APPLY,
            status=Status.PASS.value if succeeded else Status.FAILED.value,
            state=state, host_id=plan["host_id"], resource_plan=plan,
            check=check, now=now, operation_id_factory=operation_id_factory,
            prerequisite_checks=prerequisite_checks)
        result["end_status"] = "verified" if succeeded else "failed"
        result["execution"] = {"outcome": "succeeded" if succeeded else "failed",
                               "message": message}
    except (resources.SetupError, OSError, ValueError, TypeError, KeyError) as error:
        current = system.record()
        state = (current.get("status") if isinstance(current, dict) else "unknown")
        result = _base(
            artifact_type=RESOURCE_APPLY, status=Status.FAILED.value,
            state=state, host_id=plan["host_id"], resource_plan=plan,
            check=_check(Status.FAILED.value,
                         f"Resource apply aborted; record status: {state}",
                         reason=str(error),
                         manual_action="Inspect the original plan and record manually; do not apply again"),
            now=now, operation_id_factory=operation_id_factory,
            prerequisite_checks=prerequisite_checks)
        result["end_status"] = "failed"
        result["execution"] = {"outcome": "failed", "message": str(error)}
    result.update({
        "completed_at": _utc(now),
        "identity_context": {
            "effective_administrator_uid": uid,
            "operator_identity": plan["owner"],
            "operator_source": "confirmed-resource-plan",
            "sudo_hint_used_for_ownership": False,
            "qemu_service_identity": plan["qemu"],
        },
        "confirmed_plan_sha256": confirmation,
        "plan_sha256": actual,
        "manual_actions": ([] if result["status"] == Status.PASS.value else
                           [result["checks"][0]["manual_action"]]),
    })
    return result
