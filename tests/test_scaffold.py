# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test package scaffolding, templates, profiles, and CLI help offline.

"""Strictly local checks without backend or host changes."""
from pathlib import Path
import subprocess
import sys
import unittest
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from jsonschema import Draft4Validator

ROOT = Path(__file__).resolve().parents[1]


class ScaffoldTests(unittest.TestCase):
    def test_help(self):
        result = subprocess.run([sys.executable, str(ROOT / "vmctl"), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("create", result.stdout)

    def test_release_version_comes_from_package_source(self):
        result = subprocess.run([sys.executable, str(ROOT / "vmctl"), "--version"],
                                capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "vmctl 0.5.0"))

    def test_restore_requires_explicit_mode_and_documents_activation(self):
        args = [sys.executable, str(ROOT / "vmctl"), "restore", "sony-headset", "clean-base"]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("NOT_IMPLEMENTED", result.stderr)
        help_result = subprocess.run(
            [sys.executable, str(ROOT / "vmctl"), "restore", "--help"],
            capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--activate-preparation", help_result.stdout)
        self.assertIn("no implicit start", help_result.stdout)

    def test_public_templates_are_portable_and_fail_closed(self):
        for template in ("arch-base", "cachyos-base"):
            result = subprocess.run(
                [sys.executable, str(ROOT / "vmctl"), "config", "validate",
                 f"templates/{template}.yaml"],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn("CONFIG_INCOMPLETE", result.stderr)
            self.assertNotIn("p05-image-cache", result.stdout + result.stderr)
            self.assertNotIn("desktop-nat", result.stdout + result.stderr)

    def test_yaml_and_usb_defaults(self):
        for path in (ROOT / "templates").glob("*.yaml"):
            config = yaml.safe_load(path.read_text())
            self.assertEqual(config["schema_version"], 1)
            self.assertIs(config["vm"]["usb"]["enabled"], False)

    def test_cloud_init_renders_valid_yaml(self):
        env = Environment(loader=FileSystemLoader(ROOT / "cloud-init"), undefined=StrictUndefined)
        user = yaml.safe_load(env.get_template("user-data.j2").render(
            ssh_user="developer", ssh_public_keys=[], packages=["git"]))
        self.assertIs(user["ssh_pwauth"], False)
        self.assertIs(user["users"][0]["lock_passwd"], True)
        meta = yaml.safe_load(env.get_template("meta-data.j2").render(
            instance_id="test-instance", vm_name="sony-headset"))
        self.assertEqual(meta["local-hostname"], "sony-headset")

    def test_documentary_template_does_not_emit_invalid_empty_packages(self):
        env = Environment(loader=FileSystemLoader(ROOT / "cloud-init"), undefined=StrictUndefined)
        user = yaml.safe_load(env.get_template("user-data.j2").render(
            ssh_user="developer", ssh_public_keys=[], packages=[]))
        validator = Draft4Validator({'properties': {'packages': {'type': 'array', 'minItems': 1}}})
        self.assertFalse(list(validator.iter_errors(user)))


if __name__ == "__main__":
    unittest.main()
