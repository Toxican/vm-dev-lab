# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test Arch package inventory, planning, and report contracts.

import io
import json
from contextlib import redirect_stdout
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from vm_dev_lab.host_setup import cli
from vm_dev_lab.host_setup.arch_packages import (CATALOG, PACMAN, QueryResult,
                                                  build_report, parse_os_release)


NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


class FakeSystem:
    def __init__(self, *, os_release='ID=arch\nPRETTY_NAME="Arch Linux"\n',
                 architecture='x86_64', manager=PACMAN,
                 machine_id='0123456789abcdef0123456789abcdef', installed=None,
                 query_result=None, effective_uid=0, sudo_environment=None):
        self.os_release_text = os_release
        self.architecture_value = architecture
        self.manager = manager
        self.machine_id_value = machine_id
        self.installed = {} if installed is None else dict(installed)
        self.query_result = query_result
        self.effective_uid_value = effective_uid
        self.sudo_environment_value = ({"user": None, "uid": None}
                                       if sudo_environment is None else sudo_environment)
        self.queries = []

    def os_release(self):
        return self.os_release_text

    def architecture(self):
        return self.architecture_value

    def package_manager(self):
        return self.manager

    def machine_id(self):
        return self.machine_id_value

    def effective_uid(self):
        return self.effective_uid_value

    def sudo_environment(self):
        return self.sudo_environment_value

    def query_packages(self, names, package_manager):
        self.queries.append((tuple(names), package_manager))
        if self.query_result is not None:
            return self.query_result
        stdout = []
        stderr = []
        for name in names:
            if name in self.installed:
                stdout.append(f"{name} {self.installed[name]}")
            else:
                stderr.append(f"error: package '{name}' was not found")
        return QueryResult(0 if not stderr else 1,
                           ("\n".join(stdout) + ("\n" if stdout else "")).encode(),
                           ("\n".join(stderr) + ("\n" if stderr else "")).encode())


def installed_catalog():
    return {spec.name: f"1.0-{index}" for index, spec in enumerate(CATALOG, 1)}


class PackageReportTests(unittest.TestCase):
    def report(self, action, system):
        return build_report(action, system=system, now=lambda: NOW)

    def test_catalog_matches_documented_hs_b1_scope(self):
        self.assertEqual([spec.name for spec in CATALOG], [
            'qemu-desktop', 'qemu-img', 'libvirt', 'edk2-ovmf', 'dnsmasq',
            'iptables-nft', 'acl', 'iproute2', 'openssh', 'cloud-image-utils',
            'gnupg', 'git', 'python', 'python-pip', 'curl'])
        self.assertTrue(all(spec.required and spec.purpose and spec.documentation
                            and spec.check_id == 'packages.' + spec.name for spec in CATALOG))

    def test_complete_inventory_passes_without_install_plan(self):
        system = FakeSystem(installed=installed_catalog())
        result = self.report('plan', system)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['summary']['missing_packages'], [])
        self.assertIsNone(result['planned_action'])
        self.assertEqual(len(system.queries), 1)

    def test_partial_inventory_plans_only_missing_packages_in_catalog_order(self):
        installed = installed_catalog()
        del installed['dnsmasq']
        del installed['cloud-image-utils']
        result = self.report('plan', FakeSystem(installed=installed))
        self.assertEqual(result['status'], 'ACTION_REQUIRED')
        self.assertEqual(result['summary']['missing_packages'], ['dnsmasq', 'cloud-image-utils'])
        self.assertEqual(result['planned_action']['packages'], ['dnsmasq', 'cloud-image-utils'])
        self.assertEqual(result['planned_action']['argv'],
                         [PACMAN, '-Syu', '--needed', '--', 'dnsmasq', 'cloud-image-utils'])
        self.assertIn('update', result['planned_action']['impact'])

    def test_fully_missing_inventory_is_actionable_not_unavailable(self):
        result = self.report('check', FakeSystem())
        self.assertEqual(result['status'], 'ACTION_REQUIRED')
        self.assertEqual(result['summary']['missing_packages'], [spec.name for spec in CATALOG])
        self.assertTrue(all(check['status'] == 'ACTION_REQUIRED'
                            for check in result['checks'] if check['package']))

    def test_database_failure_is_failed_and_never_missing(self):
        failed = QueryResult(2, b'', b'error: database is inconsistent\n')
        result = self.report('plan', FakeSystem(query_result=failed))
        self.assertEqual(result['status'], 'FAILED')
        self.assertEqual(result['summary']['missing_packages'], [])
        self.assertIsNone(result['planned_action'])
        self.assertTrue(all(check['status'] == 'FAILED'
                            for check in result['checks'] if check['id'].startswith('packages.')))

    def test_timeout_and_unexpected_output_are_not_interpreted_as_missing(self):
        cases = [QueryResult(1, b'', b'', timed_out=True),
                 QueryResult(1, b'qemu-desktop 1\n', b'corrupt\n')]
        for query in cases:
            with self.subTest(query=query):
                result = self.report('check', FakeSystem(query_result=query))
                self.assertEqual(result['status'], 'FAILED')
                self.assertEqual(result['summary']['missing_packages'], [])

    def test_legacy_iptables_requires_manual_decision_and_suppresses_action(self):
        installed = installed_catalog()
        del installed['iptables-nft']
        installed['iptables'] = '1:1.8.11-2'
        result = self.report('plan', FakeSystem(installed=installed))
        self.assertEqual(result['status'], 'MANUAL_REQUIRED')
        self.assertEqual(result['summary']['conflicts'], ['packages.conflict.iptables-provider'])
        self.assertIsNone(result['planned_action'])
        conflict = next(check for check in result['checks']
                        if check['id'] == 'packages.conflict.iptables-provider')
        self.assertIn('do not replace a provider automatically', conflict['manual_action'])

    def test_inconsistent_dual_iptables_packages_block(self):
        installed = installed_catalog()
        installed['iptables'] = '1.8.11-2'
        result = self.report('plan', FakeSystem(installed=installed))
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIsNone(result['planned_action'])

    def test_only_exact_arch_x86_64_with_expected_pacman_is_queried(self):
        cases = [
            ('ID=cachyos\nID_LIKE=arch\n', 'x86_64', PACMAN),
            ('ID=ubuntu\nID_LIKE=debian\n', 'x86_64', PACMAN),
            ('ID=arch\n', 'aarch64', PACMAN),
            ('ID=arch\n', 'x86_64', None),
        ]
        for os_release, architecture, manager in cases:
            with self.subTest(os_release=os_release, architecture=architecture, manager=manager):
                system = FakeSystem(os_release=os_release, architecture=architecture, manager=manager)
                result = self.report('plan', system)
                self.assertIn(result['status'], {'BLOCKED', 'FAILED'})
                self.assertEqual(system.queries, [])
                self.assertIsNone(result['planned_action'])

    def test_malformed_or_manipulated_os_release_blocks_without_query(self):
        cases = ['', 'ID=arch\nID=cachyos\n', 'ID="unterminated\n',
                 'ID=arch\nMALFORMED\n', 'ID=$(touch /tmp/not-executed)\n']
        for os_release in cases:
            with self.subTest(os_release=os_release):
                system = FakeSystem(os_release=os_release)
                result = self.report('check', system)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertEqual(system.queries, [])

    def test_invalid_machine_id_fails_host_binding_without_query(self):
        system = FakeSystem(machine_id='not-a-machine-id')
        result = self.report('plan', system)
        self.assertEqual(result['status'], 'FAILED')
        self.assertIsNone(result['host_binding']['machine_id_sha256'])
        self.assertEqual(system.queries, [])

    def test_plan_hash_is_deterministic_and_excludes_report_timestamp(self):
        system_a = FakeSystem(installed={'qemu-desktop': '1.0-1'})
        system_b = FakeSystem(installed={'qemu-desktop': '1.0-1'})
        first = build_report('plan', system=system_a, now=lambda: NOW)
        later = build_report('plan', system=system_b,
                             now=lambda: datetime(2026, 10, 31, tzinfo=timezone.utc))
        self.assertEqual(first['plan_sha256'], later['plan_sha256'])
        self.assertRegex(first['plan_sha256'], r'^[0-9a-f]{64}$')
        changed = self.report('plan', FakeSystem(installed={'qemu-desktop': '2.0-1'}))
        self.assertNotEqual(first['plan_sha256'], changed['plan_sha256'])

    def test_json_schema_check_ids_and_documentation_references(self):
        schema = json.loads(files('vm_dev_lab.host_setup').joinpath('result-schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for action in ('check', 'plan'):
            report = self.report(action, FakeSystem(installed=installed_catalog()))
            validator.validate(report)
            ids = [check['id'] for check in report['checks']]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue(all('#' in check['documentation'] for check in report['checks']))
        invalid_check = self.report('check', FakeSystem(installed=installed_catalog()))
        invalid_check['plan_sha256'] = 'a' * 64
        self.assertFalse(validator.is_valid(invalid_check))
        invalid_plan = self.report('plan', FakeSystem(installed=installed_catalog()))
        invalid_plan['plan_sha256'] = None
        self.assertFalse(validator.is_valid(invalid_plan))
        apply_field_in_plan = self.report('plan', FakeSystem(installed=installed_catalog()))
        apply_field_in_plan['operation_id'] = '12345678-1234-4234-8234-123456789abc'
        self.assertFalse(validator.is_valid(apply_field_in_plan))

    def test_only_read_only_pacman_query_is_requested(self):
        system = FakeSystem(installed=installed_catalog())
        self.report('plan', system)
        names, manager = system.queries[0]
        self.assertEqual(manager, PACMAN)
        self.assertIn('iptables', names)
        self.assertNotIn('-S', names)

    def test_os_release_parser_does_not_execute_shell_syntax(self):
        with self.assertRaises(ValueError):
            parse_os_release('ID=$(false)\n')


class HostSetupCliTests(unittest.TestCase):
    def invoke(self, argv, system):
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = cli.main(argv, system=system, now=lambda: NOW,
                        stdout=stdout, stderr=stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_text_and_json_output(self):
        installed = installed_catalog()
        del installed['dnsmasq']
        code, text, error = self.invoke(['packages', 'plan'], FakeSystem(installed=installed))
        self.assertEqual(code, 3)
        self.assertEqual(error, '')
        self.assertIn('Host Setup - Packages', text)
        self.assertIn('[ACTION_REQUIRED] dnsmasq', text)
        self.assertIn('No changes were performed.', text)
        code, raw, error = self.invoke(['packages', 'check', '--json'],
                                       FakeSystem(installed=installed_catalog()))
        self.assertEqual((code, error), (0, ''))
        self.assertEqual(json.loads(raw)['artifact_type'], 'package-check')

    def test_unsupported_platform_is_visible_in_text(self):
        code, text, _ = self.invoke(['packages', 'check'],
                                    FakeSystem(os_release='ID=cachyos\nID_LIKE=arch\n'))
        self.assertEqual(code, 4)
        self.assertIn('[BLOCKED] platform.os', text)

    def test_optional_report_is_private_new_json_file(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'report.json'
            code, _, error = self.invoke(['packages', 'check', '--output', str(target)],
                                         FakeSystem(installed=installed_catalog()))
            self.assertEqual((code, error), (0, ''))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(target.read_text())['artifact_type'], 'package-check')
            code, _, error = self.invoke(['packages', 'check', '--output', str(target)],
                                         FakeSystem(installed=installed_catalog()))
            self.assertEqual(code, 6)
            self.assertIn('REPORT_FAILED', error)

    def test_help_lists_package_and_environment_stages(self):
        help_text = cli.parser().format_help()
        self.assertIn('packages', help_text)
        self.assertIn('environment', help_text)
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as exit_result:
            cli.parser().parse_args(['packages', '--help'])
        self.assertEqual(exit_result.exception.code, 0)
        self.assertIn('check', output.getvalue())
        self.assertIn('plan', output.getvalue())
        self.assertIn('apply', output.getvalue())
        self.assertNotIn('environment', output.getvalue())


if __name__ == '__main__':
    unittest.main()
