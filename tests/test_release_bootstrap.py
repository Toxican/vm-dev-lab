# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test release initialization and host-record binding offline.

"""Release 0.5 bootstrap using temporary offline fixtures exclusively."""
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import yaml

from vm_dev_lab.bootstrap import initialize
from vm_dev_lab.cli import main
from vm_dev_lab.config import ConfigLoader
from vm_dev_lab.lifecycle import load_host_record
from vm_dev_lab.release import ARCH_IMAGE_SHA256
from vm_dev_lab.state import StatePaths


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class ReleaseBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.storage = self.root / "storage"
        self.storage.mkdir(mode=0o700)
        self.code = self.root / "CODE.fd"
        self.variables = self.root / "VARS.fd"
        self.code.write_bytes(b"code-fixture")
        self.variables.write_bytes(b"vars-fixture")
        account = pwd.getpwuid(os.geteuid())
        plan = {
            "schema_version": 2, "uri": "qemu:///system",
            "host_id": hashlib.sha256(Path("/etc/machine-id").read_bytes()).hexdigest(),
            "setup_id": str(uuid4()), "network": "vm-dev-lab-fresh",
            "network_uuid": str(uuid4()), "pool": "vm-dev-lab-fresh",
            "pool_uuid": str(uuid4()), "bridge": "virbr-vdlf",
            "subnet": "192.168.125.0/24", "storage": str(self.storage),
            "owner": {"name": account.pw_name, "uid": account.pw_uid,
                      "gid": account.pw_gid},
            "qemu": {"name": "qemu-fixture", "uid": account.pw_uid + 10000,
                     "gid": account.pw_gid + 10000},
            "mode": "manual", "activate": False,
            "min_free_gib": 1, "reserve_gib": 1,
            "firmware": {
                "code": str(self.code), "vars": str(self.variables),
                "code_sha256": hashlib.sha256(self.code.read_bytes()).hexdigest(),
                "vars_sha256": hashlib.sha256(self.variables.read_bytes()).hexdigest(),
            },
        }
        plan["sha256"] = hashlib.sha256(canonical(plan)).hexdigest()
        info = self.storage.stat()
        record = {"completed": [], "plan": plan, "status": "complete",
                  "storage_identity": {"device": info.st_dev, "inode": info.st_ino,
                                       "uid": info.st_uid, "gid": info.st_gid}}
        self.record = self.root / "host-record.json"
        self.record.write_text(json.dumps(record))
        self.plan = plan

    def test_v2_host_record_binds_firmware_and_rejects_change(self):
        self.assertEqual(load_host_record(self.record), self.plan)
        self.code.write_bytes(b"changed")
        with self.assertRaises(Exception) as caught:
            load_host_record(self.record)
        self.assertEqual(caught.exception.detail["code"], "HOST_RECORD_INVALID")

    def test_init_creates_new_private_profile_registry_and_ledger(self):
        config_root = self.root / "local-config"
        paths = StatePaths(self.root / "data", self.root / "state", self.root / "run")
        manifest = {"image": {"sha256": ARCH_IMAGE_SHA256}}
        with patch("vm_dev_lab.bootstrap.ImageCache.verify_entry", return_value=manifest):
            result = initialize(config_root, self.record, paths)
            again = initialize(config_root, self.record, paths)
        self.assertEqual(result, again)
        self.assertEqual((config_root / "profiles/arch-local.yaml").stat().st_mode & 0o777, 0o600)
        profile = yaml.safe_load((config_root / "profiles/arch-local.yaml").read_text())
        self.assertEqual(profile["vm"]["network"]["name"], "vm-dev-lab-fresh")
        self.assertNotIn("desktop", json.dumps(profile))
        self.assertTrue(ConfigLoader(config_root).load("arch-local").complete)
        registry = json.loads((paths.state / "registry.json").read_text())
        self.assertEqual(registry["schema_version"], 2)
        self.assertEqual(registry["instances"], {})
        self.assertEqual(registry["resources"]["reservations"], {})

    def test_init_never_overwrites_a_different_local_binding(self):
        config_root = self.root / "local-config"
        paths = StatePaths(self.root / "data", self.root / "state", self.root / "run")
        manifest = {"image": {"sha256": ARCH_IMAGE_SHA256}}
        with patch("vm_dev_lab.bootstrap.ImageCache.verify_entry", return_value=manifest):
            initialize(config_root, self.record, paths)
            profile = config_root / "profiles/arch-local.yaml"
            profile.write_text("foreign: true\n")
            with self.assertRaisesRegex(ValueError, "different binding"):
                initialize(config_root, self.record, paths)
        self.assertEqual(profile.read_text(), "foreign: true\n")

    def test_init_rejects_legacy_host_record_for_a_new_binding(self):
        record = json.loads(self.record.read_text())
        record["plan"].pop("firmware")
        record["plan"]["schema_version"] = 1
        unsigned = {key: value for key, value in record["plan"].items()
                    if key != "sha256"}
        record["plan"]["sha256"] = hashlib.sha256(canonical(unsigned)).hexdigest()
        legacy = self.root / "legacy.json"
        legacy.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "host record v2"):
            initialize(self.root / "local-config", legacy,
                       StatePaths(self.root / "data", self.root / "state", self.root / "run"))

    def test_image_import_cli_uses_pinned_release_spec(self):
        manifest = {"image": {"sha256": ARCH_IMAGE_SHA256}}
        output = StringIO()
        with patch("vm_dev_lab.storage.images.ImageCache.import_local", return_value=manifest) as imported:
            with redirect_stdout(output):
                status = main(["--json", "image", "import", "--cache-root", str(self.root / "cache"),
                               "--image", str(self.root / "image"), "--signature", str(self.root / "sig"),
                               "--keyring", str(self.root / "keyring")])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["image"], manifest)
        spec = imported.call_args.args[0]
        self.assertEqual(spec.sha256, ARCH_IMAGE_SHA256)


if __name__ == "__main__":
    unittest.main()
