# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Define stable process exit codes and public error details.

"""Versioned error contract; no backend or state management."""
from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    INTERNAL = 1
    INVALID = 2
    PREREQUISITE = 3
    CONFLICT = 4
    POLICY = 5
    OPERATION = 6
    TIMEOUT = 7
    GUEST = 8
    INTERRUPTED = 130


class LabError(Exception):
    """Emit only deliberately approved diagnostics at the CLI boundary."""

    def __init__(self, exit_code, code, phase, message, hint, retryable=False):
        super().__init__(message)
        self.exit_code = ExitCode(exit_code)
        if self.exit_code == ExitCode.OK:
            raise ValueError("An error requires a failure exit code")
        self.detail = dict(code=code, phase=phase, message=message,
                           hint=hint, retryable=retryable)
