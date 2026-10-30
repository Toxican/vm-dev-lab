# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test trusted-lab UFW policy through offline adapters.

"""Simple trusted-lab UFW adapter; no real firewall, libvirt or root calls."""
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from vm_dev_lab import trusted_lab_firewall as fw
from vm_dev_lab import trusted_lab_sync as sync

import importlib.util
spec = importlib.util.spec_from_file_location("host_setup", ROOT / "scripts/setup-host.py")
setup_host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup_host)


SETUP = {
    "schema_version": 1,
    "uri": "qemu:///system",
    "host_id": "a" * 64,
    "setup_id": "11111111-1111-4111-8111-111111111111",
    "network": "vm-dev-lab-test-nat",
    "network_uuid": "22222222-2222-4222-8222-222222222222",
    "pool": "vm-dev-lab-test",
    "pool_uuid": "33333333-3333-4333-8333-333333333333",
    "bridge": "virbr-test",
    "subnet": "192.168.125.0/24",
    "storage": "/var/lib/libvirt/vm-dev-lab-test",
    "owner": {"name": "developer", "uid": 1000, "gid": 1000},
    "qemu": {"name": "libvirt-qemu", "uid": 949, "gid": 949},
    "mode": "permanent",
    "activate": False,
    "min_free_gib": 60,
    "reserve_gib": 20,
}
SETUP["sha256"] = setup_host.plan_hash(SETUP)
POLICY = {"schema_version": 1, "manager": "ufw", "mode": "trusted-lab"}


class FakeSystem:
    def __init__(self):
        self.record = None
        self.commands = []
        self.support = False
        self.ingress = "deferred-network-inactive"
        self.fail = None
        self.added = []

    @contextmanager
    def firewall_lock(self):
        yield

    def firewall_record(self):
        return deepcopy(self.record)

    def firewall_save(self, value):
        self.record = deepcopy(value)

    def ufw_state(self):
        lines = [shlex.join(["ufw", *command]) for command in self.added]
        return {"status": "Status: active\n", "added": "Added user rules:\n" + "\n".join(lines) + "\n"}

    def ufw_rule(self, argv, remove=False):
        action = ("delete" if remove else "add", tuple(argv))
        self.commands.append(action)
        if self.fail == action:
            raise OSError("injected UFW failure")
        if remove:
            self.added.remove(argv)
        elif argv not in self.added:
            self.added.append(deepcopy(argv))

    def trusted_support_preflight(self, plan):
        if self.support:
            raise fw.FirewallError("unexpected support")

    def trusted_support_install(self, plan, journal):
        self.commands.append(("support-install",))
        if self.fail == ("support-install",):
            raise OSError("injected support failure")
        self.support = True

    def trusted_support_check(self, plan, partial=False):
        if not self.support and not partial:
            raise fw.FirewallError("support missing")

    def trusted_support_absent(self, plan):
        if self.support:
            raise fw.FirewallError("support remains")

    def trusted_support_remove(self, plan, record):
        self.commands.append(("support-remove",))
        self.support = False

    def trusted_ingress_sync(self, plan):
        self.commands.append(("ingress-sync",))
        if self.fail == ("ingress-sync",):
            raise OSError("injected ingress failure")
        return self.ingress

    def trusted_ingress_status(self, plan):
        return self.ingress

    def trusted_ingress_remove(self, plan):
        self.commands.append(("ingress-remove",))
        self.ingress = "absent"
        return "removed"


class TrustedLabFirewallTests(unittest.TestCase):
    def plan(self, setup=SETUP, policy=POLICY):
        return fw.build_plan(deepcopy(setup), deepcopy(policy))

    def test_plan_has_only_four_unrestricted_bridge_rules(self):
        plan = self.plan()
        self.assertEqual(plan["backend"], fw.BACKEND)
        self.assertEqual([rule["id"] for rule in plan["rules"]],
                         ["host-in", "host-out", "route-from-lab", "route-to-lab"])
        text = json.dumps(plan["rules"])
        self.assertNotIn("port", text)
        self.assertNotIn("proto", text)
        self.assertNotIn("lan_access", json.dumps(plan))
        self.assertNotIn("lan_interface", json.dumps(plan))
        for rule in plan["rules"]:
            self.assertIn(SETUP["bridge"], rule["argv"])
            self.assertTrue(rule["argv"][-1].startswith(fw.marker(SETUP["setup_id"])))
        self.assertEqual(plan["ingress_exception"]["expr"][-1], {"accept": None})
        self.assertEqual(plan["ingress_exception"]["expr"][0]["match"]["right"], SETUP["bridge"])

    def test_policy_and_host_identity_are_strict_but_not_desktop_specific(self):
        for change in (
            lambda p: p.update(lan_access="allow"),
            lambda p: p.update(manager="nftables"),
            lambda p: p.update(mode="trusted-dev"),
            lambda p: p.update(schema_version=True),
        ):
            policy = deepcopy(POLICY); change(policy)
            with self.assertRaises(fw.FirewallError):
                self.plan(policy=policy)
        other = deepcopy(SETUP)
        other.update(host_id="b" * 64, setup_id="44444444-4444-4444-8444-444444444444",
                     network_uuid="55555555-5555-4555-8555-555555555555", bridge="virbr-lab2",
                     network="vm-dev-lab-second")
        other["sha256"] = setup_host.plan_hash(other)
        plan = self.plan(setup=other)
        self.assertIn("virbr-lab2", json.dumps(plan["rules"]))
        self.assertNotIn("virbr-test", json.dumps(plan["rules"]))

    def test_apply_status_idempotence_and_owned_removal(self):
        system = FakeSystem(); plan = self.plan()
        self.assertEqual(fw.apply(plan, SETUP, system, plan["sha256"]), "applied-persistent-UFW-CLI")
        self.assertEqual(system.record["status"], "complete")
        self.assertEqual(fw.status(plan, system.record, system)["rules_present"], 4)
        before = deepcopy(system.commands)
        self.assertEqual(fw.apply(plan, SETUP, system, plan["sha256"]), "unchanged")
        self.assertEqual(system.commands, before)
        self.assertEqual(fw.uninstall(plan, system, plan["sha256"]), "removed-owned-trusted-lab-rules")
        self.assertEqual(system.record["status"], "removed")
        self.assertEqual(system.added, [])
        self.assertFalse(system.support)
        flat = json.dumps(system.commands)
        for forbidden in ("reload", "default", "enable", "disable"):
            self.assertNotIn(forbidden, flat)
        self.assertEqual(fw.uninstall(plan, system, plan["sha256"]), "unchanged")

    def test_foreign_rules_are_ignored_but_own_marker_namespace_is_strict(self):
        system = FakeSystem(); plan = self.plan()
        foreign = ["deny", "from", "203.0.113.0/24", "comment", "operator-rule"]
        system.added.append(foreign)
        fw.apply(plan, SETUP, system, plan["sha256"])
        self.assertIn(foreign, system.added)
        fw.uninstall(plan, system, plan["sha256"])
        self.assertEqual(system.added, [foreign])
        system.record = None
        system.added.append(["allow", "in", "on", SETUP["bridge"], "comment",
                             fw.marker(SETUP["setup_id"]) + "unknown"])
        with self.assertRaises(fw.FirewallError):
            fw.apply(plan, SETUP, system, plan["sha256"])

    def test_partial_failure_is_reviewable_and_removes_only_observed_own_rules(self):
        system = FakeSystem(); plan = self.plan()
        failing = ("add", tuple(plan["rules"][2]["argv"]))
        system.fail = failing
        with self.assertRaises(OSError):
            fw.apply(plan, SETUP, system, plan["sha256"])
        self.assertEqual(system.record["status"], "review_required")
        self.assertEqual(len(system.added), 2)
        system.fail = None
        self.assertEqual(fw.uninstall(plan, system, plan["sha256"]), "removed-owned-trusted-lab-rules")
        self.assertEqual(system.added, [])

    def test_wrong_hash_modified_plan_and_inactive_ufw_fail_before_rules(self):
        system = FakeSystem(); plan = self.plan()
        with self.assertRaises(fw.FirewallError):
            fw.apply(plan, SETUP, system, "wrong")
        changed = deepcopy(plan); changed["rules"][0]["argv"][3] = "foreign0"
        with self.assertRaises(fw.FirewallError):
            fw.apply(changed, SETUP, system, changed["sha256"])
        with patch.object(system, "ufw_state", return_value={"status": "Status: inactive\n", "added": ""}):
            with self.assertRaises(fw.FirewallError):
                fw.apply(plan, SETUP, system, plan["sha256"])
        self.assertEqual(system.commands, [])

    def test_targeted_libvirt_inspection_does_not_classify_foreign_tables(self):
        plan = self.plan(); own_rule = deepcopy(plan["ingress_exception"]); own_rule["handle"] = 41
        reject = {"family": "ip", "table": "libvirt_network", "chain": "guest_input", "handle": 42,
                  "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}},
                                      "right": SETUP["bridge"]}}, {"reject": None}]}
        ruleset = {"nftables": [
            {"table": {"family": "ip", "name": "libvirt_network",
                       "comment": "Managed by libvirt for virtual networks: fixture"}},
            {"table": {"family": "ip", "name": "foreign-unrelated"}},
            {"rule": own_rule}, {"rule": reject},
        ]}
        own, found_reject = sync.inspect(plan, ruleset)
        self.assertEqual(own[0]["handle"], 41)
        self.assertEqual(found_reject["handle"], 42)
        ruleset["nftables"][2]["rule"]["expr"][-1] = {"drop": None}
        with self.assertRaises(ValueError):
            sync.inspect(plan, ruleset)

    def test_offline_cli_needs_no_snapshot_or_root_system(self):
        plan = self.plan()
        with tempfile.TemporaryDirectory() as folder:
            setup_path = Path(folder) / "setup.json"
            policy_path = Path(folder) / "policy.json"
            setup_path.write_text(json.dumps({"status": "complete", "plan": SETUP}))
            policy_path.write_text(json.dumps(POLICY))
            output = StringIO()
            with patch.object(setup_host, "TrustedLabSystem", side_effect=AssertionError("no host calls")), \
                    redirect_stdout(output):
                code = setup_host.main(["firewall-plan", "--setup-record", str(setup_path),
                                        "--policy", str(policy_path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue()), plan)

    def test_host_adapter_uses_only_exact_ufw_cli_add_and_delete_forms(self):
        system = setup_host.TrustedLabSystem()
        calls = []
        system.run = lambda argv: calls.append(argv) or "ok"
        host_rule, route_rule = self.plan()["rules"][0], self.plan()["rules"][2]
        system.ufw_rule(host_rule["argv"])
        system.ufw_rule(host_rule["argv"], remove=True)
        system.ufw_rule(route_rule["argv"])
        system.ufw_rule(route_rule["argv"], remove=True)
        self.assertEqual(calls, [
            ["ufw", *host_rule["argv"]],
            ["ufw", "delete", *host_rule["argv"]],
            ["ufw", *route_rule["argv"]],
            ["ufw", "route", "delete", *route_rule["argv"][1:]],
        ])
        self.assertFalse(any("--force" in call for call in calls))
        self.assertFalse(any(word in call for call in calls for word in ("reload", "default", "enable", "disable")))


if __name__ == "__main__":
    unittest.main()
