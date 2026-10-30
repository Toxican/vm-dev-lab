# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Inspect Arch Linux packages and create a bound installation plan.

"""Passive Arch platform and package checks for HS-B1."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import re
import shlex

from vm_dev_lab.process import exchange
from vm_dev_lab.version import VERSION

from .contracts import (CATALOG_NAME, CATALOG_VERSION, SCHEMA_VERSION, Status,
                        aggregate_status, bind_plan)


DOC_PACKAGES = "docs/INSTALLATION.md#systempakete"
DOC_PLATFORM = "docs/INSTALLATION.md#hostvoraussetzungen"
DOC_PLAN = "docs/HOST-SETUP.md#paket-check-plan-und-installation"
PACMAN = "/usr/bin/pacman"
TEXT_LIMIT = 64 * 1024
QUERY_LIMIT = 128 * 1024


@dataclass(frozen=True)
class PackageSpec:
    name: str
    purpose: str
    required: bool = True
    documentation: str = DOC_PACKAGES

    @property
    def check_id(self):
        return "packages." + self.name


CATALOG = (
    PackageSpec("qemu-desktop", "QEMU system emulation for x86_64 VMs"),
    PackageSpec("qemu-img", "qcow2 validation, overlays, and offline image operations"),
    PackageSpec("libvirt", "modular daemons, virsh, and virt-host-validate"),
    PackageSpec("edk2-ovmf", "OVMF code and variable template for UEFI guests"),
    PackageSpec("dnsmasq", "DHCP and DNS for the dedicated libvirt NAT network"),
    PackageSpec("iptables-nft", "nft-based iptables contract required by libvirt"),
    PackageSpec("acl", "setfacl and getfacl for bound storage access"),
    PackageSpec("iproute2", "ip for route, address, and link inventory"),
    PackageSpec("openssh", "SSH client, SFTP, and key tools"),
    PackageSpec("cloud-image-utils", "cloud-localds for NoCloud seed media"),
    PackageSpec("gnupg", "signature and keyring validation for guest images"),
    PackageSpec("git", "repository access and source-state evidence"),
    PackageSpec("python", "project runtime and virtual Python environment"),
    PackageSpec("python-pip", "installation of declared Python dependencies"),
    PackageSpec("curl", "manual retrieval of pinned release artifacts"),
)
CONFLICT_PACKAGES = ("iptables",)


@dataclass(frozen=True)
class QueryResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_limited: bool = False


def _check(check_id, status, observed, *, purpose, documentation,
           package=None, required=True, proposed_change=None,
           error_reason=None, manual_action=None):
    return {
        "id": check_id,
        "status": Status(status).value,
        "required": required,
        "package": package,
        "purpose": purpose,
        "observed": observed,
        "proposed_change": proposed_change,
        "executed_change": None,
        "error_reason": error_reason,
        "documentation": documentation,
        "manual_action": manual_action,
    }


def parse_os_release(text):
    if not isinstance(text, str) or not text or len(text.encode("utf-8")) > TEXT_LIMIT:
        raise ValueError("os-release is missing or too large")
    values = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        if any(ord(char) < 32 and char != "\t" for char in raw):
            raise ValueError("control character in os-release")
        if "=" not in raw:
            raise ValueError("invalid os-release line")
        key, encoded = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            raise ValueError("invalid or duplicate os-release key")
        try:
            decoded = shlex.split(encoded, posix=True)
        except ValueError as error:
            raise ValueError("invalid os-release quoting") from error
        if len(decoded) != 1 or len(decoded[0]) > 4096:
            raise ValueError("invalid os-release value")
        values[key] = decoded[0]
        if len(values) > 128:
            raise ValueError("too many os-release fields")
    identity = values.get("ID", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", identity):
        raise ValueError("invalid or missing distribution ID")
    id_like = values.get("ID_LIKE", "").split()
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item)
           for item in id_like):
        raise ValueError("invalid ID_LIKE")
    return {"id": identity, "name": values.get("PRETTY_NAME") or values.get("NAME") or identity,
            "id_like": id_like}


def parse_package_query(result, names):
    """Treat only a completely explained pacman response as evidence."""
    names = tuple(names)
    if result.timed_out or result.output_limited:
        raise ValueError("package database query exceeded the deadline or output limit")
    try:
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("package database output is not UTF-8") from error
    installed = {}
    missing = set()
    for line in stdout.splitlines():
        fields = line.split(maxsplit=1)
        if (len(fields) != 2 or fields[0] not in names or fields[0] in installed
                or fields[0] in missing or not fields[1] or len(fields[1]) > 256):
            raise ValueError("unexpected pacman standard output")
        installed[fields[0]] = fields[1]
    for line in stderr.splitlines():
        match = re.fullmatch(r"error: package '([^']+)' was not found", line)
        if (not match or match.group(1) not in names or match.group(1) in missing
                or match.group(1) in installed):
            raise ValueError("unexpected pacman error output")
        missing.add(match.group(1))
    if set(installed) | missing != set(names):
        raise ValueError("pacman response is incomplete")
    expected_code = 0 if not missing else 1
    if result.returncode != expected_code:
        raise ValueError("pacman exit code does not match its output")
    return installed, missing


class LocalSystem:
    """Narrow passive system boundary; tests inject fakes exclusively."""

    def _read(self, path):
        with open(path, "rb") as stream:
            data = stream.read(TEXT_LIMIT + 1)
        if len(data) > TEXT_LIMIT:
            raise OSError("file exceeds the read limit")
        return data.decode("utf-8")

    def os_release(self):
        return self._read("/etc/os-release")

    def architecture(self):
        return platform.machine()

    def package_manager(self):
        path = Path(PACMAN)
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None

    def machine_id(self):
        return self._read("/etc/machine-id").strip()

    def effective_uid(self):
        return os.geteuid()

    def sudo_environment(self):
        return {"user": os.environ.get("SUDO_USER"), "uid": os.environ.get("SUDO_UID")}

    def query_packages(self, names, package_manager):
        try:
            result = exchange([package_manager, "-Q", "--", *names], b"", timeout=20,
                              limit=QUERY_LIMIT)
        except Exception:
            return QueryResult(127, b"", b"")
        return QueryResult(result.returncode, result.stdout, result.stderr,
                           result.timed_out, result.output_limited)


def _platform_checks(system):
    checks = []
    os_info = {"id": None, "name": None, "id_like": []}
    architecture = None
    package_manager = None
    machine_id_sha256 = None
    try:
        os_info = parse_os_release(system.os_release())
        if os_info["id"] == "arch":
            status, observed, manual = Status.PASS, "Arch Linux detected", None
        elif "arch" in os_info["id_like"] or os_info["id"] == "cachyos":
            status, observed, manual = (Status.BLOCKED,
                f"Unqualified Arch derivative detected: {os_info['id']}",
                "Qualify this distribution separately before creating a package plan.")
        else:
            status, observed, manual = (Status.BLOCKED,
                f"Unsupported distribution detected: {os_info['id']}",
                "Use only an explicitly qualified Arch Linux system.")
        checks.append(_check("platform.os", status, observed,
                             purpose="Verify the supported host distribution",
                             documentation=DOC_PLATFORM, manual_action=manual))
    except (OSError, UnicodeError, ValueError) as error:
        checks.append(_check("platform.os", Status.BLOCKED,
                             "Unable to determine operating-system information reliably",
                             purpose="Verify the supported host distribution",
                             documentation=DOC_PLATFORM, error_reason=str(error),
                             manual_action="Resolve manipulated or incomplete os-release data."))
    try:
        architecture = system.architecture()
        valid = architecture == "x86_64"
        checks.append(_check("platform.architecture", Status.PASS if valid else Status.BLOCKED,
                             architecture or "empty", purpose="Verify x86_64 as the initial target architecture",
                             documentation=DOC_PLATFORM,
                             manual_action=None if valid else "Only x86_64 is qualified in HS-B."))
    except Exception as error:
        checks.append(_check("platform.architecture", Status.BLOCKED, "Unable to determine architecture",
                             purpose="Verify x86_64 as the initial target architecture",
                             documentation=DOC_PLATFORM, error_reason=str(error),
                             manual_action="Resolve the host architecture manually."))
    try:
        package_manager = system.package_manager()
        checks.append(_check("platform.package-manager",
                             Status.PASS if package_manager == PACMAN else Status.BLOCKED,
                             package_manager or "pacman is not present at the expected path",
                             purpose="Verify the fixed Arch package manager binding",
                             documentation=DOC_PACKAGES,
                             manual_action=None if package_manager == PACMAN else
                             "Provide Arch pacman at /usr/bin/pacman; do not guess a replacement."))
    except Exception as error:
        checks.append(_check("platform.package-manager", Status.BLOCKED,
                             "Unable to determine package manager",
                             purpose="Verify the fixed Arch package manager binding",
                             documentation=DOC_PACKAGES, error_reason=str(error),
                             manual_action="Resolve the package-manager state manually."))
    try:
        machine_id = system.machine_id()
        if not re.fullmatch(r"[0-9a-f]{32}", machine_id):
            raise ValueError("machine-id does not have the expected format")
        machine_id_sha256 = hashlib.sha256(machine_id.encode("ascii")).hexdigest()
        checks.append(_check("platform.host-binding", Status.PASS,
                             "Machine ID bound as SHA256",
                             purpose="Bind the plan to the checked host", documentation=DOC_PLAN))
    except (OSError, UnicodeError, ValueError) as error:
        checks.append(_check("platform.host-binding", Status.FAILED,
                             "Unable to determine host binding",
                             purpose="Bind the plan to the checked host", documentation=DOC_PLAN,
                             error_reason=str(error),
                             manual_action="Check the valid local machine-id; do not apply an unbound plan."))
    return checks, {
        "machine_id_sha256": machine_id_sha256,
        "architecture": architecture,
        "os": os_info,
        "package_manager": {"name": "pacman", "path": package_manager},
    }


def _package_checks(system, package_manager):
    names = tuple(spec.name for spec in CATALOG) + CONFLICT_PACKAGES
    try:
        installed, missing = parse_package_query(
            system.query_packages(names, package_manager), names)
    except (OSError, ValueError) as error:
        checks = [_check(spec.check_id, Status.FAILED, "Unable to determine package status",
                         purpose=spec.purpose, documentation=spec.documentation,
                         package=spec.name, required=spec.required, error_reason=str(error),
                         manual_action="Inspect the local pacman database; do not treat the package as missing.")
                  for spec in CATALOG]
        checks.append(_check("packages.conflict.iptables-provider", Status.FAILED,
                             "Unable to determine iptables provider",
                             purpose="Rule out a conflict with an alternative iptables package",
                             documentation=DOC_PACKAGES, error_reason=str(error),
                             manual_action="Resolve the installed iptables provider manually."))
        return checks
    checks = []
    for spec in CATALOG:
        if spec.name in installed:
            checks.append(_check(spec.check_id, Status.PASS,
                                 f"installiert: {installed[spec.name]}", purpose=spec.purpose,
                                 documentation=spec.documentation, package=spec.name,
                                 required=spec.required))
        else:
            checks.append(_check(spec.check_id, Status.ACTION_REQUIRED,
                                 "confirmed not installed", purpose=spec.purpose,
                                 documentation=spec.documentation, package=spec.name,
                                 required=spec.required,
                                 proposed_change=f"Install package {spec.name} later after approval"))
    legacy = "iptables" in installed
    nft = "iptables-nft" in installed
    if legacy and nft:
        checks.append(_check("packages.conflict.iptables-provider", Status.BLOCKED,
                             "iptables and iptables-nft reported simultaneously",
                             purpose="Rule out a conflict with an alternative iptables package",
                             documentation=DOC_PACKAGES,
                             error_reason="Contradictory package database state",
                             manual_action="Resolve the package database and installed firewall provider manually."))
    elif legacy and not nft:
        checks.append(_check("packages.conflict.iptables-provider", Status.MANUAL_REQUIRED,
                             f"alternativer Provider installiert: iptables {installed['iptables']}",
                             purpose="Rule out a conflict with an alternative iptables package",
                             documentation=DOC_PACKAGES,
                             manual_action="Inspect the firewall and iptables contract; do not replace a provider automatically."))
    else:
        checks.append(_check("packages.conflict.iptables-provider", Status.PASS,
                             "no alternative iptables package installed",
                             purpose="Rule out a conflict with an alternative iptables package",
                             documentation=DOC_PACKAGES))
    return checks


def build_report(action, system=None, now=None):
    if action not in {"check", "plan"}:
        raise ValueError("HS-B1 supports only check and plan")
    system = system or LocalSystem()
    now = now or (lambda: datetime.now(timezone.utc))
    platform_checks, host = _platform_checks(system)
    platform_ready = all(check["status"] == Status.PASS.value for check in platform_checks)
    package_checks = (_package_checks(system, host["package_manager"]["path"])
                      if platform_ready else [])
    checks = platform_checks + package_checks
    fulfilled = [check["package"] for check in package_checks
                 if check["package"] and check["status"] == Status.PASS.value]
    missing = [check["package"] for check in package_checks
               if check["package"] and check["status"] == Status.ACTION_REQUIRED.value]
    conflicts = [check["id"] for check in checks
                 if check["id"].startswith("packages.conflict.")
                 and check["status"] != Status.PASS.value]
    blocking = [check["id"] for check in checks
                if check["status"] in {Status.MANUAL_REQUIRED.value, Status.BLOCKED.value,
                                       Status.FAILED.value}]
    status = aggregate_status(checks)
    planned_action = None
    if action == "plan" and missing and not blocking:
        planned_action = {
            "argv": [PACMAN, "-Syu", "--needed", "--", *missing],
            "packages": missing,
            "impact": "pacman -Syu may update existing system packages in addition to installing missing packages.",
            "requires_separate_approval": True,
        }
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "package-check" if action == "check" else "package-plan",
        "tool_version": VERSION,
        "generated_at": now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "stage": "packages",
        "status": status,
        "verification_level": "passive",
        "host_binding": host,
        "catalog": {"name": CATALOG_NAME, "version": CATALOG_VERSION},
        "checks": checks,
        "summary": {"fulfilled_packages": fulfilled, "missing_packages": missing,
                    "conflicts": conflicts, "blocking_checks": blocking},
        "planned_action": planned_action,
        "plan_sha256": None,
        "notice": "No changes were performed. Package status is checked again on every invocation.",
    }
    if action == "plan":
        report["plan_sha256"] = bind_plan(report)
    return report
