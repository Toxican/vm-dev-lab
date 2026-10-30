# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Initialize local release configuration and state from a host record.

"""Fail-closed initialization of new local release state."""
import os
from pathlib import Path

import yaml

from .config import ConfigLoader
from .lifecycle import load_host_record
from .release import ARCH_IMAGE_SHA256, ARCH_TRUST
from .state import StatePaths, StateStore, directory
from .storage.images import ImageCache


def _profile(plan, image_path):
    return {
        "schema_version": 1,
        "ready": True,
        "vm": {
            "name": "arch-local",
            "guest_os": "arch",
            "install": {"method": "cloud-image"},
            "base_image": {"path": str(image_path), "sha256": ARCH_IMAGE_SHA256},
            "cpus": 2,
            "memory_mib": 2048,
            "disk_gib": 30,
            "network": {"type": "libvirt", "name": plan["network"]},
            "firmware": {"type": "uefi", "secure_boot": False},
            "packages": ["git", "python"],
            "ssh": {"enabled": True, "user": "developer",
                    "password_authentication": False, "public_keys": []},
            "usb": {"enabled": False, "devices": []},
            "snapshots": {"enabled": False, "mode": "offline-bundle"},
            "graphical": {"enabled": False, "acceleration": False},
            "audio": {"mode": "disabled"},
            "shares": [],
        },
    }


def initialize(config_root, host_record, paths=None):
    """Create only new local state and a revalidated profile binding."""
    root = Path(config_root).absolute()
    if ".." in root.parts or root == Path("/"):
        raise ValueError("Unsafe configuration root")
    plan = load_host_record(host_record)
    if plan.get("schema_version") != 2:
        raise ValueError("New initialization requires a firmware-bound host record v2")
    cache = root / "image-cache"
    manifest = ImageCache(cache).verify_entry(ARCH_IMAGE_SHA256, ARCH_TRUST)
    relative_image = (Path("..") / "image-cache" / ARCH_IMAGE_SHA256 /
                      "image.qcow2").as_posix()
    profile = _profile(plan, relative_image)
    payload = yaml.safe_dump(profile, sort_keys=False).encode("utf-8")

    paths = paths or StatePaths.from_environment()
    store = StateStore(paths)
    # External bindings are checked before the first persistent state change
    # completely verified.
    with directory(root, create=True):
        pass
    profiles = root / "profiles"
    with directory(profiles, create=True) as parent:
        name = "arch-local.yaml"
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
        except FileExistsError:
            current = profiles / name
            if current.read_bytes() != payload:
                raise ValueError("Local profile exists with a different binding")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
    store.initialize()
    resolved = ConfigLoader(root).load("arch-local")
    if not resolved.complete:
        raise ValueError("Generated local profile is incomplete")
    return {
        "config_root": str(root),
        "profile": "arch-local",
        "profile_path": str(profiles / "arch-local.yaml"),
        "host_setup_id": plan["setup_id"],
        "image_sha256": manifest["image"]["sha256"],
        "state": {"data": str(paths.data), "state": str(paths.state),
                  "runtime": str(paths.runtime)},
    }
