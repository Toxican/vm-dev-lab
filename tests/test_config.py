# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test bounded configuration loading and hostile input rejection.

"""P01: offline contracts and attack cases with isolated file fixtures."""
import base64
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vm_dev_lab.config import ConfigError, ConfigLoader, DEFAULTS, MAX_FILE_BYTES


def public_key():
    def field(value):
        return len(value).to_bytes(4, "big") + value
    return "ssh-ed25519 " + base64.b64encode(field(b"ssh-ed25519") + field(bytes(range(32)))).decode()


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "profiles").mkdir()
        (self.root / "templates").mkdir()
        self.loader = ConfigLoader(self.root)

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data) if not isinstance(data, str) else data)
        return path

    def base(self):
        return {"schema_version": 1, "vm": {"guest_os": "debian", "name": "test"}}

    def resolved(self, data):
        self.write("profiles/test.yaml", data)
        return self.loader.load("test")

    def test_repository_drafts_remain_incomplete_and_usb_disabled(self):
        loader = ConfigLoader(ROOT)
        for profile in ("templates/arch-base.yaml", "templates/cachyos-base.yaml"):
            with self.subTest(profile=profile):
                result = loader.load(profile)
                self.assertFalse(result.complete)
                self.assertFalse(result.config["vm"]["usb"]["enabled"])
                self.assertFalse(result.config["ready"])

    def test_merge_replaces_lists_preserves_mapping_and_origin(self):
        parent = self.base()
        parent["vm"].update(cpus=4, packages=["git", "python"], ssh={"user": "builder"})
        self.write("templates/base.yaml", parent)
        child = {"schema_version": 1, "extends": "../templates/base.yaml", "vm": {"packages": ["make"], "ssh": {"enabled": False}}}
        result = self.resolved(child)
        self.assertEqual(result.config["vm"]["cpus"], 4)
        self.assertEqual(result.config["vm"]["packages"], ["make"])
        self.assertEqual(result.config["vm"]["ssh"]["user"], "builder")
        self.assertEqual(result.origins["$.vm.cpus"], "templates/base.yaml")
        self.assertEqual(result.origins["$.vm.packages"], "profiles/test.yaml")
        self.assertEqual(result.origins["$.vm.audio.mode"], "<defaults>")
        self.assertEqual(self.loader.load("test").config, result.config)
        self.assertEqual(DEFAULTS["vm"]["packages"], [])

    def test_complete_configuration_is_not_host_or_image_verification(self):
        data = self.base()
        data["ready"] = True
        data["vm"].update(base_image={"path": "../images/base.qcow2", "sha256": "a" * 64},
                           network={"name": "lab"}, ssh={"public_keys": [public_key()]})
        result = self.resolved(data)
        self.assertTrue(result.complete)
        from vm_dev_lab.cli import main
        from contextlib import redirect_stdout
        from io import StringIO
        with redirect_stdout(StringIO()) as output:
            self.assertEqual(main(["config", "validate", "test", "--root", str(self.root)]), 0)
        self.assertIn("no start approval", output.getvalue())
        self.assertEqual(result.config["vm"]["base_image"]["path"], str(self.root / "images/base.qcow2"))
        # Completeness requires no image file and does not open one.
        self.assertFalse((self.root / "images/base.qcow2").exists())
        data["ready"] = False
        self.assertFalse(self.resolved(data).complete)

    def test_inherited_paths_remain_relative_to_declaring_file(self):
        data = self.base()
        data["vm"]["base_image"] = {"path": "../images/base.qcow2"}
        self.write("templates/base.yaml", data)
        self.write("profiles/nested/test.yaml", {"schema_version": 1, "extends": "../../templates/base.yaml", "vm": {}})
        result = self.loader.load("profiles/nested/test.yaml")
        self.assertEqual(result.config["vm"]["base_image"]["path"], str(self.root / "images/base.qcow2"))

    def test_invalid_types_ranges_names_and_unknown_fields(self):
        for field, value in (("cpus", True), ("cpus", 1.0), ("cpus", 0), ("cpus", 257),
                             ("memory_mib", -1), ("disk_gib", "30"), ("name", "../outside"),
                             ("name", "bad\n"), ("unknown", "value"), ("packages", ["--unsafe"]),
                             ("network", {"name": "x", "unknown": True}),
                             ("ssh", {"password_authentication": True}),
                             ("ssh", {"user": "root"}), ("ssh", {"public_keys": ["PRIVATE KEY"]}),
                             ("ssh", {"public_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AQ=="]}),
                             ("base_image", {"sha256": "bad"}),
                             ("usb", {"devices": [{"vendor_id": 12, "product_id": "0050"}]})):
            with self.subTest(field=field, value=value):
                data = self.base()
                data["vm"][field] = value
                with self.assertRaises(ConfigError) as caught:
                    self.resolved(data)
                self.assertIn("$.vm", str(caught.exception))
        for version in (True, 1.0, 2):
            data = self.base(); data["schema_version"] = version
            with self.assertRaisesRegex(ConfigError, "schema_version"):
                self.resolved(data)

    def test_invalid_parent_cannot_be_hidden_by_override(self):
        data = self.base(); data["vm"]["cpus"] = True
        self.write("templates/base.yaml", data)
        with self.assertRaisesRegex(ConfigError, "templates/base.yaml.*cpus"):
            self.resolved({"schema_version": 1, "extends": "../templates/base.yaml", "vm": {"cpus": 2}})

    def test_null_required_objects_and_missing_fields_are_errors(self):
        for data in ({"schema_version": 1, "vm": None}, {"schema_version": 1, "vm": {}},
                     {"schema_version": 1, "vm": {"guest_os": "arch", "ssh": None}},
                     {"vm": {"guest_os": "arch"}},
                     {"schema_version": 1, "vm": {"guest_os": "arch", "shares": [{"target": "/work"}]}}):
            with self.subTest(data=data), self.assertRaises(ConfigError):
                self.resolved(data)

    def test_yaml_duplicate_tags_aliases_merge_and_nonbasic_types(self):
        for body in ("schema_version: 1\nvm: {guest_os: arch, cpus: 2, cpus: 4}",
                     "schema_version: 1\nvm: !!map {guest_os: arch}",
                     "schema_version: 1\nvm: &vm {guest_os: arch, packages: [*vm]}",
                     "schema_version: 1\nvm: {<<: {guest_os: arch}}",
                     "schema_version: 1\nvm: {guest_os: 2026-10-26}",
                     "schema_version: 1\nvm: {guest_os: .nan}",
                     "!!python/object/apply:os.system ['false']", "schema_version: 1\nvm: {1: value}",
                     "schema_version: 1\nvm: [", "", "---\n{}\n---\n{}"):
            with self.subTest(body=body), self.assertRaises(ConfigError):
                self.resolved(body)

    def test_yaml_file_depth_and_node_limits(self):
        for body in ("#" * (MAX_FILE_BYTES + 1), "schema_version: 1\nvm: " + "[" * 40 + "0" + "]" * 40,
                     "schema_version: 1\nvm: [" + ",".join("0" for _ in range(4100)) + "]",
                     "schema_version: " + "9" * 5000 + "\nvm: {}"):
            with self.subTest(size=len(body)), self.assertRaises(ConfigError):
                self.resolved(body)

    def test_inheritance_cycle_and_exact_eight_file_limit(self):
        for index in range(8):
            data = self.base()
            if index < 7: data["extends"] = f"p{index + 1}.yaml"
            self.write(f"profiles/p{index}.yaml", data)
        self.loader.load("p0")
        data = self.base(); data["extends"] = "p8.yaml"
        self.write("profiles/p7.yaml", data); self.write("profiles/p8.yaml", self.base())
        with self.assertRaisesRegex(ConfigError, "eight"):
            self.loader.load("p0")
        self.write("profiles/p0.yaml", {"schema_version": 1, "extends": "p0.yaml", "vm": {}})
        with self.assertRaisesRegex(ConfigError, "cycle"):
            self.loader.load("p0")

    def test_config_paths_escape_symlinks_fifo_and_missing_files(self):
        for profile in ("../outside.yaml", "/etc/passwd", "profiles/nope.yaml", "https://example.invalid/a.yaml"):
            with self.subTest(profile=profile), self.assertRaises(ConfigError):
                self.loader.load(profile)
        self.write("templates/base.yaml", self.base())
        (self.root / "profiles/link.yaml").symlink_to(self.root / "templates/base.yaml")
        with self.assertRaises(ConfigError): self.loader.load("link")
        (self.root / "profiles/linked").symlink_to(self.root / "templates", target_is_directory=True)
        with self.assertRaises(ConfigError): self.loader.load("profiles/linked/base.yaml")
        os.mkfifo(self.root / "profiles/fifo.yaml")
        with self.assertRaises(ConfigError): self.loader.load("fifo")
        for parent in ("../../outside.yaml", "/etc/passwd", "https://example.invalid/a.yaml"):
            with self.subTest(parent=parent), self.assertRaises(ConfigError):
                self.resolved({"schema_version": 1, "extends": parent, "vm": {}})

    def test_data_paths_are_bounded_and_cannot_follow_symlinks(self):
        for image in ("../../outside.qcow2", "/etc/passwd", "${HOME}/image", "~/image", "https://example.invalid/base", "../.ssh/key", ".."):
            data = self.base(); data["vm"]["base_image"] = {"path": image}
            with self.subTest(image=image), self.assertRaisesRegex(ConfigError, "base_image.path"):
                self.resolved(data)
        (self.root / "images").symlink_to(self.root / "templates", target_is_directory=True)
        data = self.base(); data["vm"]["base_image"] = {"path": "../images/anything"}
        with self.assertRaisesRegex(ConfigError, "Symlink"): self.resolved(data)

    def test_features_require_explicit_matching_options(self):
        for update in ({"usb": {"devices": [{"vendor_id": "12ba", "product_id": "0050", "enabled": True}]}},
                       {"graphical": {"acceleration": True}}, {"audio": {"mode": "spice"}},
                       {"audio": {"mode": "usb"}}, {"install": {"method": "iso"}}):
            data = self.base(); data["vm"].update(update)
            with self.subTest(update=update), self.assertRaises(ConfigError): self.resolved(data)
        data = self.base(); data["vm"]["shares"] = [{"source": "../src", "target": "/work"}]
        self.assertTrue(self.resolved(data).config["vm"]["shares"][0]["read_only"])
        for target in ("/", "/../etc"):
            data["vm"]["shares"][0]["target"] = target
            with self.assertRaises(ConfigError): self.resolved(data)

    def test_cli_exit_codes_and_no_external_commands(self):
        from vm_dev_lab.cli import main
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        self.write("profiles/test.yaml", self.base())
        before = sorted(p.relative_to(self.root) for p in self.root.rglob("*"))
        with patch("subprocess.run", side_effect=AssertionError("No external invocation allowed")), \
                patch("socket.socket", side_effect=AssertionError("No network connection allowed")):
            with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as diagnostic:
                self.assertEqual(main(["config", "validate", "test", "--root", str(self.root)]), 3)
            self.assertIn("Not startable", diagnostic.getvalue())
            with redirect_stderr(StringIO()) as error:
                self.assertEqual(main(["config", "validate", "missing", "--root", str(self.root)]), 2)
            self.assertIn("ERROR", error.getvalue())
        self.assertEqual(before, sorted(p.relative_to(self.root) for p in self.root.rglob("*")))
        result = subprocess.run([sys.executable, str(ROOT / "vmctl"), "config", "validate", "templates/arch-base.yaml"], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 3)
        self.assertIn("Schema valid", result.stdout)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
