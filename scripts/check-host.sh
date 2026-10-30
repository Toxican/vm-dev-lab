#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Check required host commands without changing system state.

# Read-only; do not modify services, networks, or storage pools.
set -u
missing=0
check() {
    if command -v "$1" >/dev/null 2>&1; then
        printf 'OK: %s\n' "$1"
    else
        printf 'MISSING: %s (%s)\n' "$1" "$2"
        missing=1
    fi
}
check qemu-system-x86_64 'QEMU for x86_64'
check qemu-img 'image tools'
check virsh 'libvirt client; service readiness is not checked'
check virt-install 'VM installation'
check python3 'Python >= 3.10 required'
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
        printf 'MISSING: Python >= 3.10\n'
        missing=1
    fi
fi
check cloud-init 'cloud-init validation tool; verify guest support separately'
check cloud-localds 'cloud-init seed tool'
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    printf 'OK: /dev/kvm exists and is accessible\n'
else
    printf 'MISSING: /dev/kvm or read/write permission\n'
    missing=1
fi
printf 'Notice: libvirt service, firmware, and guest compatibility were not checked.\n'
exit "$missing"
