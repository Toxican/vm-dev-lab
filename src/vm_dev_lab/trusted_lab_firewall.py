# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Plan and manage the owned trusted-lab UFW policy.

"""Small one-time UFW setup for the trusted vm-dev-lab network.

The standard path owns four UFW CLI rules and one narrowly scoped libvirt
ingress exception.  It neither inventories nor interprets unrelated firewall
policy.  VM lifecycle code must not import or call this module.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shlex
import uuid


BACKEND = "ufw-cli-trusted-lab-v1"
RECORD = "/etc/vm-dev-lab/trusted-lab-firewall.json"
HELPER = "/etc/vm-dev-lab/trusted-lab-sync.py"
SYNC_LOCK = "/etc/vm-dev-lab/trusted-lab-sync.lock"


class FirewallError(ValueError):
    pass


def require(value, message):
    if not value:
        raise FirewallError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def marker(setup_id):
    return "vm-dev-lab:" + setup_id + ":trusted-lab:"


def hook_path(setup_id):
    return "/etc/libvirt/hooks/network.d/50-vm-dev-lab-trusted-" + setup_id[:12]


def validate_policy(policy):
    require(isinstance(policy, dict) and set(policy) == {"schema_version", "manager", "mode"},
            "Firewall policy requires exactly schema_version, manager, and mode.")
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1,
            "Unknown firewall policy version.")
    require(policy["manager"] == "ufw" and policy["mode"] == "trusted-lab",
            "Only the simple UFW trusted-lab mode is supported.")
    return policy


def rule_specs(setup):
    bridge = setup["bridge"]
    prefix = marker(setup["setup_id"])
    return [
        {"id": "host-in", "argv": ["allow", "in", "on", bridge, "comment", prefix + "host-in"]},
        {"id": "host-out", "argv": ["allow", "out", "on", bridge, "comment", prefix + "host-out"]},
        {"id": "route-from-lab", "argv": ["route", "allow", "in", "on", bridge, "comment", prefix + "route-from-lab"]},
        {"id": "route-to-lab", "argv": ["route", "allow", "out", "on", bridge, "comment", prefix + "route-to-lab"]},
    ]


def ingress_spec(setup):
    return {
        "family": "ip",
        "table": "libvirt_network",
        "chain": "guest_input",
        "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": setup["bridge"]}},
            {"accept": None},
        ],
        "comment": marker(setup["setup_id"]) + "libvirt-ingress",
    }


def hook_text(setup):
    return ("#!/bin/sh\n# " + marker(setup["setup_id"]) + "libvirt-hook\n"
            "if [ \"${1:-}\" = " + shlex.quote(setup["network"]) +
            " ] && { [ \"${2:-}\" = started ] || [ \"${2:-}\" = updated ]; }; then\n"
            "    exec /usr/bin/python3 " + HELPER + " --sync --active-event\n"
            "fi\nexit 0\n")


def build_plan(setup, policy):
    validate_policy(policy)
    require(isinstance(setup, dict) and setup.get("sha256") and setup.get("uri") == "qemu:///system",
            "A complete host-setup plan is required.")
    require(str(uuid.UUID(setup["setup_id"])) == setup["setup_id"] and
            str(uuid.UUID(setup["network_uuid"])) == setup["network_uuid"],
            "Invalid setup or network identity.")
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,14}", setup["bridge"]) is not None and
            setup["network"].startswith("vm-dev-lab") and setup["network"] != "default",
            "A dedicated vm-dev-lab network with a valid bridge is required.")
    helper = Path(__file__).with_name("trusted_lab_sync.py").read_text()
    plan = {
        "schema_version": 1,
        "backend": BACKEND,
        "host_id": setup["host_id"],
        "setup_id": setup["setup_id"],
        "network": setup["network"],
        "network_uuid": setup["network_uuid"],
        "bridge": setup["bridge"],
        "setup_sha256": setup["sha256"],
        "setup": deepcopy(setup),
        "policy": deepcopy(policy),
        "rules": rule_specs(setup),
        "ingress_exception": ingress_spec(setup),
        "helper": helper,
        "hook": hook_text(setup),
        "record_path": RECORD,
        "persistence": "ufw-user-rules plus owned libvirt network hook",
        "network_ready": False,
    }
    plan["sha256"] = digest(plan)
    return plan


def validate_plan(plan, setup=None):
    fields = {"schema_version", "backend", "host_id", "setup_id", "network", "network_uuid",
              "bridge", "setup_sha256", "setup", "policy", "rules", "ingress_exception",
              "helper", "hook", "record_path", "persistence", "network_ready", "sha256"}
    require(isinstance(plan, dict) and set(plan) == fields and plan["schema_version"] == 1 and
            plan["backend"] == BACKEND and plan["record_path"] == RECORD,
            "Unknown simple firewall plan.")
    require(plan["sha256"] == digest({k: v for k, v in plan.items() if k != "sha256"}),
            "Firewall plan was changed.")
    validate_policy(plan["policy"])
    require(plan["rules"] == rule_specs(plan["setup"]) and
            plan["ingress_exception"] == ingress_spec(plan["setup"]) and
            plan["hook"] == hook_text(plan["setup"]) and isinstance(plan["helper"], str) and plan["helper"],
            "Owned firewall objects are not canonical.")
    require(all(plan[key] == plan["setup"][key] for key in
                ("host_id", "setup_id", "network", "network_uuid", "bridge")) and
            plan["setup_sha256"] == plan["setup"]["sha256"], "Host setup binding in the plan differs.")
    if setup is not None:
        require(setup == plan["setup"] and setup["sha256"] == plan["setup_sha256"],
                "Host-setup binding changed.")
    return plan


def parse_added(text):
    commands = []
    for line in text.splitlines():
        if not line.startswith("ufw "):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as error:
            raise FirewallError("UFW rule output is not parseable.") from error
        require(tokens and tokens[0] == "ufw", "Unexpected UFW rule output.")
        commands.append(tokens[1:])
    return commands


def command_comment(command):
    if "comment" not in command:
        return ""
    index = command.index("comment")
    require(index + 1 < len(command), "UFW comment has no value.")
    return command[index + 1]


def inspect(plan, state, require_all):
    require(state["status"].startswith("Status: active"),
            "UFW must be active; the project neither activates nor deactivates it.")
    commands = parse_added(state["added"])
    prefix = marker(plan["setup_id"])
    own = [command for command in commands if command_comment(command).startswith(prefix)]
    expected = [rule["argv"] for rule in plan["rules"]]
    require(all(command in expected for command in own) and len(own) == len({tuple(c) for c in own}),
            "Unknown or duplicate rule in the owned UFW marker namespace.")
    if require_all:
        require(sorted(map(tuple, own)) == sorted(map(tuple, expected)),
                "Owned trusted-lab UFW rules are missing or differ.")
    return own


def status(plan, record, system):
    validate_plan(plan)
    require(record and record.get("status") == "complete" and record.get("plan") == plan,
            "Owned trusted-lab record is missing or requires review.")
    own = inspect(plan, system.ufw_state(), True)
    system.trusted_support_check(plan)
    ingress = system.trusted_ingress_status(plan)
    return {"status": "PASS", "rules_present": len(own), "persistence": plan["persistence"],
            "ingress_exception": ingress, "network_ready": False,
            "message": "Owned UFW CLI rules and support files confirmed; foreign firewall policy was not inventoried."}


def apply(plan, setup, system, confirmation):
    validate_plan(plan, setup)
    require(confirmation == plan["sha256"], "Confirm the specific firewall plan completely.")
    require(build_plan(setup, plan["policy"]) == plan,
            "Firewall plan does not come from the current implementation; create a new plan.")
    with system.firewall_lock():
        record = system.firewall_record()
        if record and record.get("status") == "complete":
            status(plan, record, system)
            return "unchanged"
        if record:
            require(record.get("status") == "removed" and record.get("plan", {}).get("setup_id") == plan["setup_id"],
                    "Owned firewall record requires review or belongs to a different setup.")
        require(not inspect(plan, system.ufw_state(), False),
                "Owned UFW rules exist without a complete current record; do not adopt them.")
        system.trusted_support_preflight(plan)
        journal = {"status": "pending", "plan": plan, "completed_rules": [], "created_dirs": []}
        system.firewall_save(journal)
        try:
            system.trusted_support_install(plan, journal)
            for rule in plan["rules"]:
                system.ufw_rule(rule["argv"])
                journal["completed_rules"].append(rule["id"])
                system.firewall_save(journal)
            journal["ingress_exception"] = system.trusted_ingress_sync(plan)
            inspect(plan, system.ufw_state(), True)
            system.trusted_support_check(plan)
            journal["status"] = "complete"
            system.firewall_save(journal)
            status(plan, journal, system)
        except BaseException:
            journal["status"] = "review_required"
            system.firewall_save(journal)
            raise
    return "applied-persistent-UFW-CLI"


def uninstall(plan, system, confirmation):
    validate_plan(plan)
    require(confirmation == plan["sha256"], "Confirm firewall removal separately and completely.")
    with system.firewall_lock():
        record = system.firewall_record()
        require(record and record.get("plan") == plan, "Matching owned trusted-lab record is missing.")
        own = inspect(plan, system.ufw_state(), False)
        if record.get("status") == "removed":
            require(not own, "Owned rules exist despite a removed record.")
            system.trusted_support_absent(plan)
            return "unchanged"
        require(record.get("status") in ("pending", "complete", "review_required", "removing"),
                "Unknown firewall journal status.")
        system.trusted_support_check(plan, partial=True)
        record["status"] = "removing"
        system.firewall_save(record)
        try:
            system.trusted_ingress_remove(plan)
            for rule in reversed(plan["rules"]):
                if rule["argv"] in own:
                    system.ufw_rule(rule["argv"], remove=True)
            require(not inspect(plan, system.ufw_state(), False), "Owned UFW rules remained.")
            system.trusted_support_remove(plan, record)
            system.trusted_support_absent(plan)
            system.firewall_save({"status": "removed", "plan": plan})
        except BaseException:
            record["status"] = "review_required"
            system.firewall_save(record)
            raise
    return "removed-owned-trusted-lab-rules"
