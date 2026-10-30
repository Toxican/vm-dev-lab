#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Provide the compatibility launcher for host resource setup.

"""Compatible manual entry point for the shared host-resource core."""

from vm_dev_lab.host_setup.resources import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
