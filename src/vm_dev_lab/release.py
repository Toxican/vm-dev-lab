# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Define release version, image, and trust constants.

"""Pinned artifact and version contracts used by the release."""
from .provisioning.arch import cloud_image_spec
from .storage.images import TrustPolicy


ARCH_IMAGE_SHA256 = "08754e28d91b1680086c6211ef4df13559e766fff7cdb4006489b14b5d281f08"
ARCH_IMAGE_SPEC = cloud_image_spec(
    "20261015.611680",
    "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg-20261015.611680.qcow2",
    ARCH_IMAGE_SHA256,
    576680960,
    2 * 1024 ** 3,
)
ARCH_TRUST = TrustPolicy(
    "archlinux",
    ("1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F",),
    "f21550af3ff9c63fee0f109127c1e61a54f0e382285eb3c557576770b7fb79c1",
    "Betreiberfreigabe 2026-10-26 fuer Arch cloudimg 20261015.611680; Phase5.md",
)
