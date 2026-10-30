# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Define versioned Host Setup status, report, and plan contracts.

"""Small versioned contracts for host-setup checks and plans."""
from __future__ import annotations

import hashlib
import json
from enum import Enum


SCHEMA_VERSION = 1
CATALOG_NAME = "arch-system-packages"
CATALOG_VERSION = 1


class Status(str, Enum):
    PASS = "PASS"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


_PRIORITY = {
    Status.PASS: 0,
    Status.ACTION_REQUIRED: 1,
    Status.MANUAL_REQUIRED: 2,
    Status.BLOCKED: 3,
    Status.FAILED: 4,
}


def aggregate_status(checks):
    """Conservatively return the most severe check status actually present."""
    if not checks:
        return Status.FAILED.value
    return max((Status(check["status"]) for check in checks),
               key=_PRIORITY.__getitem__).value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def bind_plan(report):
    """Timestamp is report data, not a mutation-relevant plan binding."""
    material = {key: value for key, value in report.items()
                if key not in {"generated_at", "plan_sha256"}}
    return hashlib.sha256(canonical(material)).hexdigest()
