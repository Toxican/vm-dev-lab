# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Parse and dispatch standalone Host Setup commands.

"""CLI for the standalone host-setup assistant."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from vm_dev_lab.errors import ExitCode
from vm_dev_lab.version import VERSION

from .arch_packages import build_report
from .contracts import Status
from .environment import build_environment_report
from .environment_apply import apply_environment_plan
from .package_apply import RootRequiredError, apply_plan
from .package_apply import read_plan
from .resource_setup import (
    RESOURCE_PLAN, apply_resource_plan, build_resource_plan)
from .resource_uninstall import (
    UNINSTALL_APPLY, UNINSTALL_CHECK, UNINSTALL_PLAN, apply_uninstall_plan,
    build_uninstall_report)


def parser():
    root = argparse.ArgumentParser(
        prog="host-setup",
        description="Check and plan host prerequisites, then apply them with confirmation")
    root.add_argument("--version", action="version", version=f"host-setup {VERSION}")
    stages = root.add_subparsers(dest="stage", required=True)
    packages = stages.add_parser("packages", help="Check, plan, and apply Arch system packages")
    actions = packages.add_subparsers(dest="action", required=True)
    for name, help_text in (("check", "Check package inventory read-only"),
                            ("plan", "Emit missing packages as a non-executing plan")):
        action = actions.add_parser(name, help=help_text)
        action.add_argument("--json", action="store_true", help="Write versioned JSON to stdout")
        action.add_argument("--output", metavar="FILE",
                            help="Create the JSON report as new and private (0600); never overwrite")
    apply = actions.add_parser("apply", help="Apply a confirmed package plan in a controlled manner")
    apply.add_argument("--plan", required=True, metavar="FILE",
                       help="Previously generated versioned package-plan")
    apply.add_argument("--confirm", required=True, metavar="PLAN-SHA256",
                       help="Complete SHA256 of the explicitly confirmed plan")
    apply.add_argument("--json", action="store_true", help="Write versioned JSON to stdout")
    apply.add_argument("--output", metavar="FILE",
                       help="Create the JSON report as new and private (0600); never overwrite")
    environment = stages.add_parser("environment", help="Check and plan the host environment passively")
    environment_actions = environment.add_subparsers(dest="action", required=True)
    for name, help_text in (("check", "Check host capabilities without intended mutation"),
                            ("plan", "Plan socket starts or privileged lab resources")):
        action = environment_actions.add_parser(name, help=help_text)
        action.add_argument("--json", action="store_true", help="Write versioned JSON to stdout")
        action.add_argument("--output", metavar="FILE",
                            help="Create the JSON report as new and private (0600); never overwrite")
        if name == "plan":
            action.add_argument("--resources", action="store_true",
                                help="Privileged lab-resource inventory and planning")
            action.add_argument("--owner")
            action.add_argument("--qemu-user")
            action.add_argument("--mode", choices=("manual", "permanent"))
            action.add_argument("--network", default="vm-dev-lab-nat")
            action.add_argument("--pool", default="vm-dev-lab")
            action.add_argument("--bridge", default="virbr-vdl")
            action.add_argument("--subnet", default="192.168.124.0/24")
            action.add_argument("--storage", default="/var/lib/libvirt/vm-dev-lab")
            action.add_argument("--min-free-gib", type=int, default=60)
            action.add_argument("--reserve-gib", type=int, default=20)
            action.add_argument("--firmware-code")
            action.add_argument("--firmware-vars")
            action.add_argument("--activate", action="store_true")
    environment_apply = environment_actions.add_parser(
        "apply", help="Execute a confirmed socket or lab-resource plan in a controlled manner")
    environment_apply.add_argument("--plan", required=True, metavar="FILE",
                                   help=("Previously generated versioned environment-plan "
                                         "or environment-resource-plan"))
    environment_apply.add_argument("--confirm", required=True, metavar="PLAN-SHA256",
                                   help="Complete SHA256 of the confirmed plan")
    environment_apply.add_argument("--json", action="store_true",
                                   help="Write versioned JSON to stdout")
    environment_apply.add_argument("--output", metavar="FILE",
                                   help="Create the JSON report as new and private (0600); never overwrite")
    for name, help_text in (
            ("uninstall-check", "Check owned host resources administratively without mutation"),
            ("uninstall-plan", "Create a bound plan for safe resource removal")):
        action = environment_actions.add_parser(name, help=help_text)
        action.add_argument("--json", action="store_true",
                            help="Write versioned JSON to stdout")
        action.add_argument("--output", metavar="FILE",
                            help="Create the JSON report as new and private (0600); never overwrite")
    uninstall = environment_actions.add_parser(
        "uninstall", help="Execute a confirmed resource uninstall in a controlled manner")
    uninstall.add_argument("--plan", required=True, metavar="FILE",
                           help="Previously generated environment-uninstall-plan")
    uninstall.add_argument("--confirm", required=True, metavar="PLAN-SHA256",
                           help="Complete SHA256 of the confirmed uninstall plan")
    uninstall.add_argument("--json", action="store_true",
                           help="Write versioned JSON to stdout")
    uninstall.add_argument("--output", metavar="FILE",
                           help="Create the JSON report as new and private (0600); never overwrite")
    return root


def _reserve_private(path):
    target = Path(path)
    if not target.name or target.name in {".", ".."}:
        raise ValueError("invalid output path")
    parent_info = os.stat(target.parent, follow_symlinks=False)
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid():
        raise OSError("Output directory is not owned by the effective process identity")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_mode & 0o777 != 0o600 or info.st_nlink != 1:
            raise OSError("Report file is not private and unambiguous")
        return target, fd
    except BaseException:
        os.close(fd)
        try:
            os.unlink(target)
        except OSError:
            pass
        raise


def _write_reserved(reservation, report):
    target, fd = reservation
    data = (json.dumps(report, ensure_ascii=True, allow_nan=False, sort_keys=True,
                       indent=2) + "\n").encode("utf-8")
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _discard_reserved(reservation):
    target, fd = reservation
    os.close(fd)
    try:
        os.unlink(target)
    except OSError:
        pass


def _write_private(path, report):
    _write_reserved(_reserve_private(path), report)


def _render_text(report, stream):
    if report["artifact_type"].startswith("environment-"):
        _render_environment_text(report, stream)
        return
    host = report["host_binding"]
    platform_name = host["os"]["name"] or host["os"]["id"] or "Unknown"
    print("Host Setup - Packages", file=stream)
    print(file=stream)
    print(f"Platform: {platform_name} ({host['architecture'] or 'unknown'})", file=stream)
    print(file=stream)
    for check in report["checks"]:
        if check["id"].startswith("platform.") and check["status"] != Status.PASS.value:
            print(f"[{check['status']}] {check['id']}: {check['observed']}", file=stream)
    for check in report["checks"]:
        if check["package"]:
            print(f"[{check['status']}] {check['package']}: {check['observed']}", file=stream)
    for check in report["checks"]:
        if check["id"].startswith("packages.conflict.") and check["status"] != Status.PASS.value:
            print(f"[{check['status']}] {check['id']}: {check['observed']}", file=stream)
    if report["artifact_type"] == "package-plan":
        print(file=stream)
        print("Geplante Installation:", file=stream)
        if report["planned_action"]:
            print("  " + " ".join(report["planned_action"]["packages"]), file=stream)
            print("  Note: " + report["planned_action"]["impact"], file=stream)
        else:
            print("  No automatically executable package action.", file=stream)
        print(f"Plan-SHA256: {report['plan_sha256']}", file=stream)
    print(file=stream)
    if report["artifact_type"] == "package-apply":
        print(f"Operation ID: {report['operation_id']}", file=stream)
        print(f"Apply: {report['end_status']}", file=stream)
        if report["execution"]:
            result = report["execution"]["returncode"]
            print(f"Pacman started: {report['execution']['started']}; exit code: {result}", file=stream)
        print("Note: " + report["notice"], file=stream)
    else:
        print("No changes were performed.", file=stream)


def _render_environment_text(report, stream):
    print("Host Setup - Environment", file=stream)
    print(file=stream)
    for check in report["checks"]:
        print(f"[{check['status']}] {check['id']}: {check['observed']} ",
              f"({check['evidence_level']})", sep="", file=stream)
    if report["artifact_type"] in {UNINSTALL_CHECK, UNINSTALL_PLAN}:
        print(file=stream)
        print(f"Uninstallzustand: {report['uninstall_state']}", file=stream)
        if report["uninstall_plan"]:
            for step in report["uninstall_plan"]["steps"]:
                print("  " + step, file=stream)
        if report["plan_sha256"]:
            print(f"Plan-SHA256: {report['plan_sha256']}", file=stream)
    elif report["artifact_type"] == RESOURCE_PLAN:
        print(file=stream)
        print(f"Ressourcenzustand: {report['resource_state']}", file=stream)
        for change in report["resource_summary"]["planned_changes"]:
            print("  " + change, file=stream)
        if report["plan_sha256"]:
            print(f"Plan-SHA256: {report['plan_sha256']}", file=stream)
    elif report["artifact_type"] == "environment-plan":
        print(file=stream)
        print("Planned changes:", file=stream)
        changes = report["environment_plan"]["changes"]
        if changes:
            for change in changes:
                print("  " + " ".join(change["argv"]), file=stream)
        else:
            print("  No safely executable change.", file=stream)
        print("Manual decisions:", file=stream)
        for decision in report["environment_plan"]["manual_decisions"]:
            print(f"  {decision['id']}: {decision['manual_action']}", file=stream)
        print(f"Plan-SHA256: {report['plan_sha256']}", file=stream)
    elif report["artifact_type"] in {
            "environment-apply", "environment-resource-apply", UNINSTALL_APPLY}:
        print(file=stream)
        print(f"Operation ID: {report['operation_id']}", file=stream)
        print(f"Apply: {report['end_status']}", file=stream)
        if report["artifact_type"] == UNINSTALL_APPLY:
            print(f"Uninstallzustand: {report['uninstall_state']}", file=stream)
            for action in report["execution"]:
                print(f"  [{action['outcome']}] {action['id']}", file=stream)
        elif report["artifact_type"] == "environment-resource-apply":
            print(f"Ressourcenzustand: {report['resource_state']}", file=stream)
            print(f"  [{report['execution']['outcome']}] {report['execution']['message']}",
                  file=stream)
        elif report["execution"] is not None:
            for action in report["execution"]["actions"]:
                print(f"  [{action['outcome']}] {action['unit']}", file=stream)
        if report["manual_actions"]:
            print("Manual follow-up actions:", file=stream)
            for action in report["manual_actions"]:
                print("  " + action, file=stream)
    print(file=stream)
    print(report["notice"], file=stream)


def _exit_code(status):
    return {
        Status.PASS.value: ExitCode.OK,
        Status.ACTION_REQUIRED.value: ExitCode.PREREQUISITE,
        Status.MANUAL_REQUIRED.value: ExitCode.PREREQUISITE,
        Status.BLOCKED.value: ExitCode.CONFLICT,
        Status.FAILED.value: ExitCode.OPERATION,
    }[status]


def main(argv=None, *, system=None, executor=None, now=None, operation_id_factory=None,
         stdout=None, stderr=None, environment_system=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = parser().parse_args(argv)
    reservation = None
    try:
        if args.action in {"apply", "uninstall"} and args.output:
            reservation = _reserve_private(args.output)
        if args.stage == "environment" and args.action == "uninstall":
            report = apply_uninstall_plan(
                args.plan, args.confirm, system=system, now=now,
                operation_id_factory=operation_id_factory)
        elif (args.stage == "environment"
              and args.action in {"uninstall-check", "uninstall-plan"}):
            report = build_uninstall_report(
                args.action, system=system, now=now,
                operation_id_factory=operation_id_factory)
        elif args.stage == "environment" and args.action == "apply":
            artifact = read_plan(args.plan).get("artifact_type")
            if artifact == RESOURCE_PLAN:
                report = apply_resource_plan(
                    args.plan, args.confirm, system=system, now=now,
                    operation_id_factory=operation_id_factory,
                    environment_system=environment_system)
            else:
                report = apply_environment_plan(
                    args.plan, args.confirm, system=system, executor=executor,
                    now=now, operation_id_factory=operation_id_factory)
        elif (args.stage == "environment" and args.action == "plan"
              and args.resources):
            missing = [name for name in ("owner", "qemu_user", "mode",
                                         "firmware_code", "firmware_vars")
                       if getattr(args, name) is None]
            if missing:
                raise ValueError("Missing for --resources: " + ", ".join(
                    "--" + name.replace("_", "-") for name in missing))
            report = build_resource_plan(
                args, system=system, now=now,
                operation_id_factory=operation_id_factory,
                environment_system=environment_system)
        elif args.stage == "environment":
            report = build_environment_report(args.action, system=system, now=now,
                                              operation_id_factory=operation_id_factory)
        elif args.action == "apply":
            report = apply_plan(args.plan, args.confirm, system=system, executor=executor,
                                now=now, operation_id_factory=operation_id_factory)
        else:
            report = build_report(args.action, system=system, now=now)
        if reservation:
            _write_reserved(reservation, report)
            reservation = None
        elif args.output:
            _write_private(args.output, report)
        if args.json:
            print(json.dumps(report, ensure_ascii=True, allow_nan=False, sort_keys=True), file=stdout)
        else:
            _render_text(report, stdout)
        return int(_exit_code(report["status"]))
    except RootRequiredError as error:
        if reservation:
            _discard_reserved(reservation)
        print(f"ERROR [ROOT_REQUIRED] {error}", file=stderr)
        return int(ExitCode.POLICY)
    except (OSError, ValueError) as error:
        if reservation:
            _discard_reserved(reservation)
        code = "PLAN_REJECTED" if args.action in {"apply", "uninstall"} else "REPORT_FAILED"
        print(f"ERROR [{code}] Task could not be executed safely: {error}", file=stderr)
        return int(ExitCode.OPERATION)


if __name__ == "__main__":
    raise SystemExit(main())
