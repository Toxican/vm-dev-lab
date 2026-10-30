# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Plan and execute ownership-bound removal of lab host resources.

"""HS-D2 removal of owned host resources, bound to ownership evidence."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from uuid import uuid4

from jsonschema import Draft202012Validator

from vm_dev_lab.version import VERSION

from . import resources
from .contracts import CATALOG_NAME, CATALOG_VERSION, SCHEMA_VERSION, Status, canonical
from .package_apply import RootRequiredError, read_plan


DOC_UNINSTALL = "docs/HOST-SETUP.md#hostressourcen-sicher-entfernen"
UNINSTALL_CHECK = "environment-uninstall-check"
UNINSTALL_PLAN = "environment-uninstall-plan"
UNINSTALL_APPLY = "environment-uninstall-apply"
_ALLOWED_RECORD_FIELDS = {"plan", "status", "completed", "storage_identity"}
_STEP_ORDER = (
    "pool-autostart-disabled",
    "network-autostart-disabled",
    "pool-undefined",
    "network-undefined",
    "storage-directory-removed",
)


def _utc(now):
    return now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def uninstall_plan_hash(report):
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


def _check(status, observed, reason=None, manual_action=None):
    return {
        "id": "environment.resources.uninstall",
        "status": status,
        "required": True,
        "package": None,
        "purpose": "Qualify owned host resources for safe removal",
        "observed": observed,
        "proposed_change": ("Execute the bound resource uninstall"
                            if status == Status.ACTION_REQUIRED.value else None),
        "executed_change": None,
        "error_reason": reason if status in {
            Status.BLOCKED.value, Status.FAILED.value} else None,
        "documentation": DOC_UNINSTALL,
        "manual_action": manual_action,
        "evidence_level": "active",
        "reason": reason or observed,
    }


def _base(*, artifact_type, status, state, host_id, inventory, uninstall_plan,
          check, now, operation_id_factory):
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
            "fulfilled_packages": [],
            "missing_packages": [],
            "conflicts": [],
            "blocking_checks": ([] if status in {
                Status.PASS.value, Status.ACTION_REQUIRED.value}
                                else [check["id"]]),
        },
        "planned_action": None,
        "plan_sha256": None,
        "uninstall_state": state,
        "uninstall_inventory": inventory,
        "uninstall_plan": uninstall_plan,
        "documentation": [DOC_UNINSTALL],
        "notice": ("Privileged uninstall inventory for owned host resources; "
                   "no package, service, firewall, or recovery action."),
    }
    if artifact_type == UNINSTALL_PLAN and status == Status.ACTION_REQUIRED.value:
        report["plan_sha256"] = uninstall_plan_hash(report)
    return report


def _require_root(system, explicit):
    uid = explicit
    if uid is None:
        method = getattr(system, "effective_uid", None)
        uid = method() if method else os.geteuid()
    if type(uid) is not int or uid != 0:
        raise RootRequiredError(
            "Resource uninstall requires effective UID 0; start the entire invocation "
            "explicitly with sudo host-setup environment")
    return uid


def _canonical_xml(text):
    root = resources.parse_xml(text)
    for node in root.iter():
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None
    return ET.tostring(root, encoding="unicode")


def _expected_acl(plan):
    lines = []
    for line in resources.access_acl(plan).split(","):
        mapped = line.replace("u:", "user:", 1).replace(
            "g:", "group:", 1).replace("m:", "mask:", 1).replace(
                "o:", "other:", 1)
        lines.extend((mapped, "default:" + mapped))
    return sorted(lines)


def _actual_acl(system, path):
    return sorted(line.strip() for line in system.acl(path).splitlines()
                  if line.strip())


def _firewall_state(records, setup_id):
    result = {}
    for name in ("trusted-lab", "legacy"):
        record = records.get(name)
        if record is None:
            result[name] = "absent"
            continue
        resources.require(isinstance(record, dict) and record.get("status") == "removed",
                          f"Firewall record {name} is not removed.")
        plan = record.get("plan")
        resources.require(isinstance(plan, dict),
                          f"Firewall record {name} has no original plan.")
        bound = plan.get("setup_id")
        if bound is None and isinstance(plan.get("setup"), dict):
            bound = plan["setup"].get("setup_id")
        resources.require(bound == setup_id,
                          f"Firewall record {name} belongs to a different setup.")
        result[name] = "removed"
    return result


def _domain_references(plan, domain_xml):
    references = set()
    storage = Path(plan["storage"])
    for text in domain_xml:
        root = resources.parse_xml(text)
        identity = root.findtext("uuid") or root.findtext("name") or "unknown-domain"
        for source in root.findall("./devices/interface/source"):
            if source.get("network") == plan["network"]:
                references.add(identity + ":network")
        for source in root.findall("./devices/disk/source"):
            if source.get("pool") == plan["pool"]:
                references.add(identity + ":pool")
            filename = source.get("file")
            if filename:
                candidate = Path(filename)
                if candidate == storage or storage in candidate.parents:
                    references.add(identity + ":storage")
    return sorted(references)


def _verify_inventory_definitions(plan, inventory):
    for plural, kind in (("networks", "network"), ("pools", "pool")):
        own_name = plan["network" if kind == "network" else "pool"]
        own_uuid = plan["network_uuid" if kind == "network" else "pool_uuid"]
        matches = []
        for text in inventory[plural]:
            root = resources.parse_xml(text)
            if root.findtext("name") == own_name or root.findtext("uuid") == own_uuid:
                resources.verify_definition(plan, kind, text)
                matches.append(_canonical_xml(text))
        resources.require(matches and len(set(matches)) == 1,
                          f"Owned {kind} definition is missing or ambiguous.")


def qualify_uninstall(system, *, check_lock=True):
    """Complete administrative inventory without mutation."""
    record = system.record()
    resources.require(isinstance(record, dict), "Original host record is missing.")
    resources.require(set(record) == _ALLOWED_RECORD_FIELDS,
                      "Host record has unexpected fields or a partial journal.")
    resources.require(record.get("status") == "complete",
                      "Only a complete host record can be uninstalled.")
    plan = record.get("plan")
    resources.validate_plan(plan)
    resources.require(plan["host_id"] == system.host_id(),
                      "Host record belongs to a different host.")
    resources.require(record.get("completed") == [
        "storage-directory-and-acl", "network-defined", "pool-defined"],
        "Setup journal is incomplete or in an unexpected order.")
    if check_lock:
        system.lock_available()

    inventory = system.inventory(live=True)
    _verify_inventory_definitions(plan, inventory)
    network_xml = _canonical_xml(system.defined("network", plan["network_uuid"]))
    pool_xml = _canonical_xml(system.defined("pool", plan["pool_uuid"]))
    resources.verify_definition(plan, "network", network_xml)
    resources.verify_definition(plan, "pool", pool_xml)

    network_active = system.active("network", plan["network_uuid"])
    pool_active = system.active("pool", plan["pool_uuid"])
    resources.require(not network_active and not pool_active,
                      "Network and pool must be inactive before uninstall.")
    network_autostart = system.policy("network", plan["network"])
    pool_autostart = system.policy("pool", plan["pool"])
    expected_autostart = plan["mode"] == "permanent"
    resources.require(network_autostart == expected_autostart
                      and pool_autostart == expected_autostart,
                      "Autostart policy differs from the original plan.")

    references = _domain_references(plan, inventory["domains"])
    resources.require(not references, "Domain references owned host resources.")
    volumes = system.pool_volumes(plan["pool_uuid"])
    resources.require(not volumes, "Owned pool contains volumes.")

    storage = system.storage_info(plan["storage"])
    resources.require(storage == record.get("storage_identity"),
                      "Storage directory was changed or replaced.")
    entries = system.storage_entries(plan["storage"])
    resources.require(not entries, "Storage directory is not empty.")
    mounts = system.storage_mounts(plan["storage"])
    resources.require(not mounts, "Storage directory is a mount or bind-mount target.")
    acl = _actual_acl(system, plan["storage"])
    resources.require(acl == _expected_acl(plan),
                      "ACL state differs from exact setup evidence.")
    firewall = _firewall_state(system.firewall_records(), plan["setup_id"])

    return {
        "host_id": plan["host_id"],
        "setup_id": plan["setup_id"],
        "original_plan_sha256": plan["sha256"],
        "original_record_sha256": hashlib.sha256(canonical(record)).hexdigest(),
        "owner": deepcopy(plan["owner"]),
        "qemu": deepcopy(plan["qemu"]),
        "record_status": "complete",
        "network": {"name": plan["network"], "uuid": plan["network_uuid"],
                    "xml": network_xml, "active": network_active,
                    "autostart": network_autostart},
        "pool": {"name": plan["pool"], "uuid": plan["pool_uuid"],
                 "xml": pool_xml, "active": pool_active,
                 "autostart": pool_autostart, "volumes": volumes},
        "domain_references": references,
        "storage": {"path": plan["storage"], **storage, "entries": entries,
                    "mounts": mounts, "acl": acl},
        "firewall": firewall,
        "lock_available": True,
    }


def _steps(inventory):
    result = []
    if inventory["pool"]["autostart"]:
        result.append("pool-autostart-disabled")
    if inventory["network"]["autostart"]:
        result.append("network-autostart-disabled")
    result.extend(("pool-undefined", "network-undefined",
                   "storage-directory-removed"))
    return result


def build_uninstall_report(action, *, system=None, now=None,
                           operation_id_factory=None, effective_uid=None):
    system = system or resources.System()
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    _require_root(system, effective_uid)
    host_id = system.host_id()
    artifact = UNINSTALL_CHECK if action == "uninstall-check" else UNINSTALL_PLAN
    try:
        inventory = qualify_uninstall(system)
    except (resources.SetupError, OSError, ValueError, TypeError, KeyError) as error:
        return _base(
            artifact_type=artifact, status=Status.BLOCKED.value,
            state="blocked", host_id=host_id, inventory=None,
            uninstall_plan=None,
            check=_check(Status.BLOCKED.value, "Resource uninstall blocked",
                         str(error), "Inspect the original record and host resources manually"),
            now=now, operation_id_factory=operation_id_factory)
    plan = None
    if artifact == UNINSTALL_PLAN:
        plan = {
            "host_id": inventory["host_id"],
            "setup_id": inventory["setup_id"],
            "original_plan_sha256": inventory["original_plan_sha256"],
            "original_record_sha256": inventory["original_record_sha256"],
            "network_uuid": inventory["network"]["uuid"],
            "pool_uuid": inventory["pool"]["uuid"],
            "storage_identity": {key: inventory["storage"][key]
                                 for key in ("path", "device", "inode", "uid", "gid")},
            "acl": inventory["storage"]["acl"],
            "firewall": inventory["firewall"],
            "steps": _steps(inventory),
            "documentation": DOC_UNINSTALL,
        }
    return _base(
        artifact_type=artifact, status=Status.ACTION_REQUIRED.value,
        state="qualified", host_id=host_id, inventory=inventory,
        uninstall_plan=plan,
        check=_check(Status.ACTION_REQUIRED.value,
                     "Owned inactive and unused host resources can be removed"),
        now=now, operation_id_factory=operation_id_factory)


def _validate_plan(report, confirmation):
    schema = json.loads(files("vm_dev_lab.host_setup").joinpath(
        "result-schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(report),
                    key=lambda item: list(item.path))
    if errors:
        raise ValueError("Uninstall plan does not match the versioned JSON contract")
    if (report.get("artifact_type") != UNINSTALL_PLAN
            or report.get("schema_version") != SCHEMA_VERSION
            or report.get("stage") != "environment"
            or report.get("status") != Status.ACTION_REQUIRED.value
            or report.get("uninstall_state") != "qualified"
            or not isinstance(report.get("uninstall_inventory"), dict)
            or not isinstance(report.get("uninstall_plan"), dict)):
        raise ValueError("Artifact is not an executable HS-D2 uninstall plan")
    actual = uninstall_plan_hash(report)
    recorded = report.get("plan_sha256")
    if not isinstance(recorded, str) or not hmac.compare_digest(actual, recorded):
        raise ValueError("Uninstall plan was changed after planning")
    if not isinstance(confirmation, str) or not re.fullmatch(r"[0-9a-f]{64}", confirmation):
        raise ValueError("Confirmation must be a complete SHA256")
    if not hmac.compare_digest(actual, confirmation):
        raise ValueError("Confirmation hash does not match the uninstall plan")
    plan = report["uninstall_plan"]
    inventory = report["uninstall_inventory"]
    if plan.get("steps") != _steps(inventory) or any(
            step not in _STEP_ORDER for step in plan.get("steps", [])):
        raise ValueError("Uninstall plan contains no fixed removal order")
    if (plan.get("host_id") != inventory.get("host_id")
            or plan.get("setup_id") != inventory.get("setup_id")
            or plan.get("original_plan_sha256") != inventory.get("original_plan_sha256")
            or plan.get("original_record_sha256") != inventory.get("original_record_sha256")
            or plan.get("network_uuid") != inventory.get("network", {}).get("uuid")
            or plan.get("pool_uuid") != inventory.get("pool", {}).get("uuid")
            or plan.get("storage_identity") != {
                key: inventory.get("storage", {}).get(key)
                for key in ("path", "device", "inode", "uid", "gid")}
            or plan.get("firewall") != inventory.get("firewall")
            or plan.get("acl") != inventory.get("storage", {}).get("acl")):
        raise ValueError("Uninstall plan is not bound completely to the inventory")
    return actual


def _current_domain_references(system, plan):
    return _domain_references(plan, system.inventory(live=True)["domains"])


def _assert_definition(system, plan, kind, expected_xml):
    identity = plan["network_uuid" if kind == "network" else "pool_uuid"]
    actual = _canonical_xml(system.defined(kind, identity))
    resources.verify_definition(plan, kind, actual)
    resources.require(actual == expected_xml,
                      f"Owned {kind} definition drifted during uninstall.")
    resources.require(not system.active(kind, identity),
                      f"Owned {kind} resource became active during uninstall.")


def _perform_step(step, system, plan, inventory):
    if step == "pool-autostart-disabled":
        _assert_definition(system, plan, "pool", inventory["pool"]["xml"])
        resources.require(system.policy("pool", plan["pool"]),
                          "Pool autostart drifted.")
        resources.require(not system.pool_volumes(plan["pool_uuid"]),
                          "Pool now contains volumes.")
        resources.require(not _current_domain_references(system, plan),
                          "Domain now references owned resources.")
        system.disable_autostart("pool", plan["pool_uuid"])
        resources.require(not system.policy("pool", plan["pool"]),
                          "Pool autostart was not disabled.")
    elif step == "network-autostart-disabled":
        _assert_definition(system, plan, "network", inventory["network"]["xml"])
        resources.require(system.policy("network", plan["network"]),
                          "Network autostart drifted.")
        resources.require(not _current_domain_references(system, plan),
                          "Domain now references owned resources.")
        system.disable_autostart("network", plan["network_uuid"])
        resources.require(not system.policy("network", plan["network"]),
                          "Network autostart was not disabled.")
    elif step == "pool-undefined":
        _assert_definition(system, plan, "pool", inventory["pool"]["xml"])
        resources.require(not system.policy("pool", plan["pool"]),
                          "Pool autostart is still active.")
        resources.require(not system.pool_volumes(plan["pool_uuid"]),
                          "Pool now contains volumes.")
        resources.require(not _current_domain_references(system, plan),
                          "Domain now references owned resources.")
        system.undefine("pool", plan["pool_uuid"])
        resources.require(plan["pool_uuid"] not in system.defined_identities("pool"),
                          "Pool is still defined after undefine.")
    elif step == "network-undefined":
        _assert_definition(system, plan, "network", inventory["network"]["xml"])
        resources.require(not system.policy("network", plan["network"]),
                          "Network autostart is still active.")
        resources.require(not _current_domain_references(system, plan),
                          "Domain now references owned resources.")
        system.undefine("network", plan["network_uuid"])
        resources.require(plan["network_uuid"] not in system.defined_identities("network"),
                          "Network is still defined after undefine.")
    elif step == "storage-directory-removed":
        resources.require(plan["pool_uuid"] not in system.defined_identities("pool"),
                          "Pool is still defined before storage removal.")
        expected = inventory["storage"]
        actual = system.storage_info(plan["storage"])
        identity = {key: expected[key] for key in ("device", "inode", "uid", "gid")}
        resources.require(actual == identity, "Storage directory was replaced.")
        resources.require(not system.storage_entries(plan["storage"]),
                          "Storage directory is no longer empty.")
        resources.require(not system.storage_mounts(plan["storage"]),
                          "Storage directory was mounted.")
        resources.require(_actual_acl(system, plan["storage"]) == expected["acl"],
                          "ACL drifted during uninstall.")
        system.remove_storage(plan["storage"], identity)
        resources.require(system.storage_info(plan["storage"]) is None,
                          "Storage directory remained after rmdir.")
    else:
        raise resources.SetupError("Unknown uninstall step.")


def _execution_results(steps):
    return [{"id": step, "outcome": "not-executed", "error_reason": None}
            for step in steps]


def _apply_result(*, report, status, state, check, execution, host_id, now,
                  operation_id_factory, confirmation, actual, uid,
                  post_verification=None):
    result = _base(
        artifact_type=UNINSTALL_APPLY, status=status, state=state,
        host_id=host_id, inventory=report["uninstall_inventory"],
        uninstall_plan=report["uninstall_plan"], check=check,
        now=now, operation_id_factory=operation_id_factory)
    result.update({
        "completed_at": _utc(now),
        "confirmed_plan_sha256": confirmation,
        "precondition_plan_sha256": actual,
        "identity_context": {
            "effective_administrator_uid": uid,
            "operator_identity": report["uninstall_inventory"]["owner"],
            "operator_source": "confirmed-uninstall-plan",
            "sudo_hint_used_for_ownership": False,
            "qemu_service_identity": report["uninstall_inventory"]["qemu"],
        },
        "start_status": "started" if state != "rejected" else "not-started",
        "end_status": ("verified" if status == Status.PASS.value else
                       "rejected" if status == Status.BLOCKED.value else "failed"),
        "execution": execution,
        "post_verification": post_verification or {
            "performed": False, "status": None, "network_absent": False,
            "pool_absent": False, "storage_absent": False,
            "removed_record": False, "firewall_unchanged": False,
        },
        "manual_actions": ([] if status == Status.PASS.value else
                           [check["manual_action"]]),
        "plan_sha256": actual,
    })
    return result


def apply_uninstall_plan(plan_path, confirmation, *, system=None, now=None,
                         operation_id_factory=None, effective_uid=None):
    report = read_plan(plan_path)
    actual = _validate_plan(report, confirmation)
    system = system or resources.System()
    now = now or (lambda: datetime.now(timezone.utc))
    operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
    uid = _require_root(system, effective_uid)
    host_id = report["uninstall_plan"]["host_id"]
    steps = report["uninstall_plan"]["steps"]
    execution = _execution_results(steps)
    intent_started = False
    current_step = None
    try:
        with system.apply_lock():
            current = qualify_uninstall(system, check_lock=False)
            resources.require(current == report["uninstall_inventory"],
                              "Host state differs from the confirmed uninstall plan.")
            record = system.record()
            journal = {
                "plan_sha256": actual,
                "status": "uninstalling",
                "steps": deepcopy(execution),
                "current_step": None,
                "error": None,
            }
            record["status"] = "uninstalling"
            record["uninstall"] = journal
            intent_started = True
            system.save(record)
            for index, step in enumerate(steps):
                current_step = step
                journal["current_step"] = step
                system.save(record)
                try:
                    _perform_step(step, system, record["plan"], current)
                except BaseException as error:
                    execution[index]["outcome"] = "unknown"
                    execution[index]["error_reason"] = str(error)
                    journal["steps"] = deepcopy(execution)
                    journal["status"] = "uninstall-partial"
                    journal["error"] = str(error)
                    record["status"] = "uninstall-partial"
                    try:
                        system.save(record)
                    except Exception:
                        pass
                    check = _check(
                        Status.FAILED.value,
                        f"Uninstall stopped at {step}",
                        str(error),
                        "Inspect the original record, journal, and affected resource manually; do not apply again")
                    return _apply_result(
                        report=report, status=Status.FAILED.value,
                        state="partial", check=check, execution=execution,
                        host_id=host_id, now=now,
                        operation_id_factory=operation_id_factory,
                        confirmation=confirmation, actual=actual, uid=uid)
                execution[index]["outcome"] = "succeeded"
                journal["steps"] = deepcopy(execution)
                system.save(record)
            journal["status"] = "removed"
            journal["current_step"] = None
            record["status"] = "removed"
            system.save(record)
            resources.require(system.record().get("status") == "removed",
                              "Removed tombstone was not confirmed.")
            resources.require(
                record["plan"]["network_uuid"] not in system.defined_identities("network"),
                "Network definition remained during post-check.")
            resources.require(
                record["plan"]["pool_uuid"] not in system.defined_identities("pool"),
                "Pool definition remained during post-check.")
            resources.require(system.storage_info(record["plan"]["storage"]) is None,
                              "Storage directory remained during post-check.")
            resources.require(
                _firewall_state(system.firewall_records(), record["plan"]["setup_id"])
                == current["firewall"],
                "Firewall evidence drifted during resource uninstall.")
    except (resources.SetupError, OSError, ValueError, TypeError, KeyError) as error:
        if intent_started:
            for item in execution:
                if item["id"] == current_step and item["outcome"] == "not-executed":
                    item["outcome"] = "unknown"
                    item["error_reason"] = str(error)
                    break
            try:
                record["status"] = "uninstall-partial"
                record["uninstall"]["status"] = "uninstall-partial"
                record["uninstall"]["steps"] = deepcopy(execution)
                record["uninstall"]["error"] = str(error)
                system.save(record)
            except Exception:
                pass
            check = _check(
                Status.FAILED.value, "Uninstall stopped in a partial state",
                str(error),
                "Inspect the original record, journal, and resources manually; do not apply again")
            return _apply_result(
                report=report, status=Status.FAILED.value, state="partial",
                check=check, execution=execution, host_id=host_id, now=now,
                operation_id_factory=operation_id_factory,
                confirmation=confirmation, actual=actual, uid=uid)
        check = _check(Status.BLOCKED.value, "Uninstall aborted before mutation",
                       str(error), "Create a new uninstall plan only after manual resolution")
        return _apply_result(
            report=report, status=Status.BLOCKED.value, state="rejected",
            check=check, execution=execution, host_id=host_id, now=now,
            operation_id_factory=operation_id_factory,
            confirmation=confirmation, actual=actual, uid=uid)
    check = _check(Status.PASS.value,
                   "Owned host resources removed; removed tombstone verified")
    return _apply_result(
        report=report, status=Status.PASS.value, state="removed", check=check,
        execution=execution, host_id=host_id, now=now,
        operation_id_factory=operation_id_factory,
        confirmation=confirmation, actual=actual, uid=uid,
        post_verification={
            "performed": True, "status": Status.PASS.value,
            "network_absent": True, "pool_absent": True,
            "storage_absent": True, "removed_record": True,
            "firewall_unchanged": True,
        })
