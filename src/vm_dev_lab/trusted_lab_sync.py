# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Reconcile one owned libvirt NAT ingress exception.

"""Installed helper for one owned libvirt NAT ingress exception.

This is deliberately not a general firewall manager.  It reads only the
project record, owned network XML and libvirt's one IPv4 table, and it changes
only the exact marker-bound rule from that record.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = "/etc/vm-dev-lab"
RECORD = ROOT + "/trusted-lab-firewall.json"
LOCK = ROOT + "/trusted-lab-sync.lock"
LIMIT = 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def read_root(path):
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "Unsafe parent path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                not info.st_mode & 0o022, "Unsafe root file")
        value = stream.read(LIMIT + 1)
    require(len(value) <= LIMIT, "File limit")
    return value


def execute(argv, data=None, missing_ok=False):
    kwargs = {"stdin": subprocess.DEVNULL} if data is None else {"input": json.dumps(data).encode()}
    result = subprocess.run(argv, **kwargs, capture_output=True, timeout=15,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(len(result.stdout) + len(result.stderr) <= LIMIT, "Firewall tool output is too large")
    if missing_ok and result.returncode != 0:
        return None
    require(result.returncode == 0, "Targeted libvirt rule operation failed")
    return result.stdout.decode()


def normalized(rule):
    return {k: ([{"counter": None} if set(item) == {"counter"} else item for item in v]
                if k == "expr" else v)
            for k, v in rule.items() if k != "handle"}


def network_owned(plan):
    path = "/etc/libvirt/qemu/networks/" + plan["network"] + ".xml"
    xml = read_root(path).decode()
    require("<!DOCTYPE" not in xml.upper() and "<!ENTITY" not in xml.upper(), "Unsafe network XML")
    root = ET.fromstring(xml)
    owner = root.find("./metadata/{https://vm-dev-lab.invalid/host-setup/v1}managed")
    require(root.tag == "network" and root.findtext("name") == plan["network"] and
            root.findtext("uuid") == plan["network_uuid"] and owner is not None and
            owner.get("setup_id") == plan["setup_id"] and root.find("bridge") is not None and
            root.find("bridge").get("name") == plan["bridge"] and root.find("forward") is not None and
            root.find("forward").get("mode") == "nat", "Owned libvirt network identity differs")


def inspect(plan, ruleset):
    spec = plan["ingress_exception"]
    rows = ruleset["nftables"]
    require(any(row.get("table", {}).get("family") == "ip" and
                row["table"].get("name") == "libvirt_network" and
                row["table"].get("comment", "").startswith("Managed by libvirt for virtual networks:")
                for row in rows), "libvirt table provenance is missing")
    rules = [row["rule"] for row in rows if "rule" in row and
             (row["rule"].get("family"), row["rule"].get("table"), row["rule"].get("chain")) ==
             ("ip", "libvirt_network", "guest_input")]
    own = [rule for rule in rules if rule.get("comment") == spec["comment"]]
    require(len(own) <= 1 and all(normalized(rule) == spec for rule in own),
            "Owned libvirt exception is unambiguously missing or changed")
    bridge = plan["bridge"]
    reject = next((rule for rule in rules if any(expr.get("match", {}).get("right") == bridge
                                                  for expr in rule.get("expr", [])) and
                   any("reject" in expr for expr in rule.get("expr", []))), None)
    if own:
        require(reject is not None and rules.index(own[0]) < rules.index(reject),
                "Owned libvirt exception is not before the network reject")
    return own, reject


def nft_batch(commands):
    execute(["nft", "-j", "-f", "-"], {"nftables": commands})


def operate(argv):
    record_raw = read_root(RECORD)
    require(os.lstat(RECORD).st_mode & 0o777 == 0o600, "Firewall record must be 0600")
    record = json.loads(record_raw)
    plan = record["plan"]
    expected = hashlib.sha256(json.dumps({k: v for k, v in plan.items() if k != "sha256"},
                                        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(plan["backend"] == "ufw-cli-trusted-lab-v1" and expected == plan["sha256"],
            "Invalid record plan")
    require(record.get("status") in ("pending", "complete", "review_required", "removing", "removed"),
            "Unknown record status")
    if argv[0] == "--sync" and record["status"] not in ("pending", "complete"):
        print("blocked-by-journal")
        return
    if argv == ["--check"]:
        require(record["status"] == "complete", "Firewall record is incomplete")
    require(read_root(__file__).decode() == plan["helper"], "Installed helper differs from the record")
    network_owned(plan)
    text = execute(["nft", "-j", "list", "table", "ip", "libvirt_network"], missing_ok=True)
    if text is None:
        require("--active-event" not in argv, "Libvirt table is absent after network start")
        print("deferred-network-inactive")
        return
    ruleset = json.loads(text)
    own, reject = inspect(plan, ruleset)
    if argv == ["--remove"]:
        if own:
            require(type(own[0].get("handle")) is int, "Owned rule handle is missing")
            nft_batch([{"delete": {"rule": {k: own[0][k] for k in ("family", "table", "chain", "handle")}}}])
        print("removed" if own else "absent")
        return
    if reject is None:
        require("--active-event" not in argv, "Owned libvirt network filter is absent after network start")
        print("deferred-network-inactive")
        return
    if argv == ["--check"]:
        require(own, "Owned libvirt ingress exception is missing")
        print("present")
        return
    if not own:
        nft_batch([{"insert": {"rule": plan["ingress_exception"]}}])
        print("inserted")
    else:
        print("unchanged")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    require(os.geteuid() == 0 and argv in (["--check"], ["--sync"], ["--sync", "--active-event"], ["--remove"]),
            "Only bounded root or hook operation is allowed")
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                info.st_mode & 0o777 == 0o600, "Unsafe synchronization lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        # The record is deliberately read only after the lock. A network hook
        # racing with uninstall must observe removing/removed and never revive.
        operate(argv)
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("vm-dev-lab trusted-lab synchronization blocked: " + str(error), file=sys.stderr)
        raise SystemExit(1)
