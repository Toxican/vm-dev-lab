# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Evaluate bounded VM boot-spike reports and cleanup evidence.

"""Evaluate the bounded P05 spike; no VM or lifecycle backend."""


def spike_exit_code(report):
    """Only verified test and cleanup success may produce exit code 0."""
    required = ('spike_ok', 'cleanup_ok', 'domain_removed', 'runtime_files_removed',
                'client_identity_removed')
    return 0 if (isinstance(report, dict) and not {'spike_error', 'cleanup_error'} & report.keys()
                 and all(report.get(key) is True for key in required)) else 1
