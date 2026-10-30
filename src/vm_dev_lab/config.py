# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Load, merge, and validate bounded YAML VM configurations.

"""Bounded offline configuration without host checks or VM operations."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from importlib.resources import files
import json
import math
import os
from pathlib import Path
import re
import stat

from jsonschema import Draft202012Validator
from jsonschema.validators import extend
import yaml
from yaml.events import AliasEvent

MAX_FILE_BYTES = 65536
MAX_DEPTH = 32
MAX_NODES = 4096
MAX_INHERITANCE = 8  # Including the profile itself
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
BASIC_TAGS = {f"tag:yaml.org,2002:{kind}" for kind in
              ("str", "null", "bool", "int", "float", "seq", "map")}


class ConfigError(ValueError):
    """User error with file context and field path, without foreign file content."""


class StrictLoader(yaml.SafeLoader):
    """Enforce limits before object construction; no aliases, explicit tags, or merge keys."""

    def __init__(self, stream):
        super().__init__(stream)
        self.depth = self.nodes = 0

    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, AliasEvent):
            raise ConfigError("$: YAML aliases are not allowed (limit 0)")
        if getattr(event, "tag", None) is not None:
            raise ConfigError("$: Explicit YAML tags are not allowed")
        self.depth += 1
        self.nodes += 1
        try:
            if self.depth > MAX_DEPTH or self.nodes > MAX_NODES:
                raise ConfigError("$: YAML depth or node count exceeds the limit")
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_object(self, node, deep=False):
        if node.tag not in BASIC_TAGS:
            raise ConfigError("$: Only basic YAML types are allowed")
        result = super().construct_object(node, deep)
        if isinstance(result, float) and not math.isfinite(result):
            raise ConfigError("$: Non-finite numbers are not allowed")
        return result

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConfigError("$: Mapping keys must be strings")
            if key in result:
                raise ConfigError(f"$.{key}: Duplicate mapping key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


SCHEMA = json.loads(files(__package__).joinpath("schema.json").read_text())
Draft202012Validator.check_schema(SCHEMA)


def _partial(schema):
    """Fragments may omit fields but may not set unknown or invalid fields."""
    if isinstance(schema, dict):
        return {key: _partial(value) for key, value in schema.items() if key != "required"}
    if isinstance(schema, list):
        return [_partial(value) for value in schema]
    return schema


StrictValidator = extend(Draft202012Validator, type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
    "integer", lambda checker, value: type(value) is int))

FRAGMENT_SCHEMA = _partial(SCHEMA)
FRAGMENT_SCHEMA["properties"]["extends"] = {"type": "string", "minLength": 1, "maxLength": 4096}
FRAGMENT_SCHEMA["required"] = ["schema_version", "vm"]

DEFAULTS = {
    "schema_version": 1, "ready": False,
    "vm": {
        "name": None, "architecture": "x86_64", "install": {"method": "cloud-image"},
        "base_image": {"path": None, "sha256": None},
        "cpus": 2, "memory_mib": 4096, "disk_gib": 30,
        "network": {"type": "libvirt", "name": None},
        "firmware": {"type": "uefi", "secure_boot": False}, "packages": [],
        "ssh": {"enabled": True, "user": "developer", "password_authentication": False, "public_keys": []},
        "usb": {"enabled": False, "devices": []},
        "snapshots": {"enabled": True, "mode": "offline-bundle"},
        "graphical": {"enabled": False, "acceleration": False},
        "audio": {"mode": "disabled"}, "shares": [],
    },
}


def _validate(data, schema):
    def check_strings(value, path="$"):
        if isinstance(value, str) and any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ConfigError(f"{path}: Control characters are not allowed")
        if isinstance(value, dict):
            for key, child in value.items():
                check_strings(key, path)
                check_strings(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                check_strings(child, f"{path}[{index}]")
    check_strings(data)
    errors = sorted(StrictValidator(schema).iter_errors(data),
                    key=lambda error: str(list(error.absolute_path)))
    if errors:
        error = errors[0]
        path = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.absolute_path)
        # Do not reproduce invalid values, such as accidentally supplied secrets.
        detail = error.validator
        if detail == "required" and isinstance(error.instance, dict):
            missing = sorted(set(error.schema["required"]) - set(error.instance))
            path += "." + missing[0]
        if detail == "additionalProperties" and isinstance(error.instance, dict):
            unknown = sorted(set(error.instance) - set(error.schema.get("properties", {})))
            path += "." + unknown[0]
        raise ConfigError(f"{path}: Schema violation ({detail})")


def _origins(value, source, prefix="$", result=None):
    if result is None:
        result = {}
    if isinstance(value, dict) and value:
        for key, child in value.items():
            _origins(child, source, f"{prefix}.{key}", result)
    else:
        result[prefix] = source
    return result


def _merge(base, update, origins, source, prefix="$"):
    result = deepcopy(base)
    for key, value in update.items():
        path = f"{prefix}.{key}"
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value, origins, source, path)
        else:
            result[key] = deepcopy(value)
            for old in list(origins):
                if old == path or old.startswith(path + "."):
                    del origins[old]
            _origins(value, source, path, origins)
    return result


@dataclass
class ConfigResult:
    config: dict
    origins: dict[str, str]
    incomplete: list[str]

    @property
    def complete(self):
        """Report configuration completeness only, not host or image approval."""
        return not self.incomplete


class ConfigLoader:
    """Read configuration files only below root/profiles and root/templates.

    File-descriptor-relative O_NOFOLLOW access prevents symlink swaps while reading YAML.
    Image and share paths are only normalized and validated, never opened.
    """

    def __init__(self, root):
        try:
            self.root = Path(root).resolve()
        except (OSError, ValueError, RuntimeError) as error:
            raise ConfigError("$: Invalid or unresolvable configuration root") from error

    def _bounded(self, value, directory, config=False):
        if "\x00" in value or ":" in value or "{{" in value or "}}" in value:
            raise ConfigError("$: Invalid path; URLs, variables, and templates are not allowed")
        candidate = Path(os.path.abspath(directory / value))
        try:
            relative = candidate.relative_to(self.root)
        except ValueError as error:
            raise ConfigError("$: Path leaves the allowed root") from error
        if config and (len(relative.parts) < 2 or relative.parts[0] not in {"profiles", "templates"}
                       or relative.suffix not in {".yaml", ".yml"}):
            raise ConfigError("$: Configuration path must be below profiles/ or templates/")
        return candidate

    def _read(self, path):
        fd = None
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            parts = path.relative_to(self.root).parts
            for index, part in enumerate(parts):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if index < len(parts) - 1:
                    flags |= os.O_DIRECTORY
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ConfigError("$: Configuration must be a regular file")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                data = stream.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise ConfigError("$: YAML file exceeds 64 KiB")
            return data.decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise ConfigError("$: File is unreadable (missing, symlink, permissions, or UTF-8)") from error
        finally:
            if fd is not None:
                os.close(fd)

    def _chain(self, path, seen):
        source = path.relative_to(self.root).as_posix()
        if path in seen:
            raise ConfigError(f"{source}: $.extends: Inheritance cycle")
        if len(seen) >= MAX_INHERITANCE:
            raise ConfigError(f"{source}: $.extends: More than eight inheritance levels")
        try:
            data = yaml.load(self._read(path), Loader=StrictLoader)
            _validate(data, FRAGMENT_SCHEMA)
            parent = data.pop("extends", None)
            if parent is not None:
                if Path(parent).is_absolute():
                    raise ConfigError("$.extends: Only relative references are allowed")
                try:
                    parent_path = self._bounded(parent, path.parent, config=True)
                except ConfigError as error:
                    raise ConfigError(f"$.extends: {error}") from error
                chain = self._chain(parent_path, seen + [path])
            else:
                chain = []
            # List items have safe defaults but are not merged with parent lists.
            for device in data.get("vm", {}).get("usb", {}).get("devices", []):
                device.setdefault("enabled", False)
                device.setdefault("serial", None)
            for share in data.get("vm", {}).get("shares", []):
                share.setdefault("read_only", True)
            section = data.get("vm", {}).get("base_image", {})
            if section.get("path") is not None:
                section["path"] = self._data_path(section["path"], path.parent, "$.vm.base_image.path")
            for index, share in enumerate(data.get("vm", {}).get("shares", [])):
                if "source" in share:
                    share["source"] = self._data_path(share["source"], path.parent, f"$.vm.shares[{index}].source")
            return chain + [(data, source)]
        except ConfigError as error:
            raise ConfigError(f"{source}: {error}") from error
        except (yaml.YAMLError, ValueError) as error:
            mark = getattr(error, "problem_mark", None)
            location = f" (line {mark.line + 1})" if mark else ""
            raise ConfigError(f"{source}: $: Invalid YAML{location}") from error

    def _data_path(self, value, directory, field):
        if "$" in value or "~" in value:
            raise ConfigError(f"{field}: Environment variables and home expansion are not allowed")
        try:
            path = self._bounded(value, directory)
            if path == self.root or path.relative_to(self.root).parts[0] in {".git", ".venv", ".ssh", ".aws", ".codex"}:
                raise ConfigError("Root or secrets directory is not an allowed image or share path")
            part = self.root
            for name in path.relative_to(self.root).parts:
                part = part / name
                if part.is_symlink():
                    raise ConfigError("Symlinks are not allowed")
            return str(path)
        except ConfigError as error:
            raise ConfigError(f"{field}: {error}") from error

    def load(self, profile):
        if NAME.fullmatch(profile):
            profile = f"profiles/{profile}.yaml"
        path = self._bounded(profile, self.root, config=True)
        origins = _origins(DEFAULTS, "<defaults>")
        config = deepcopy(DEFAULTS)
        for fragment, source in self._chain(path, []):
            config = _merge(config, fragment, origins, source)
        _validate(config, SCHEMA)
        self._semantics(config)
        vm = config["vm"]
        incomplete = []
        if not config["ready"]:
            incomplete.append("$.ready: false; not approved for creation")
        for field, value in (("name", vm["name"]), ("base_image.path", vm["base_image"]["path"]),
                             ("base_image.sha256", vm["base_image"]["sha256"]),
                             ("network.name", vm["network"]["name"])):
            if value is None:
                incomplete.append(f"$.vm.{field}: missing")
        # P06 creates a dedicated client identity per instance by default.
        # Additional public keys remain possible but are no longer a
        # prerequisite for a regular Create invocation.
        return ConfigResult(config, origins, incomplete)

    @staticmethod
    def _semantics(config):
        vm = config["vm"]
        # v1 reserves ISO installation but does not yet allow it as an executable plan.
        if vm["install"]["method"] != "cloud-image":
            raise ConfigError("$.vm.install.method: ISO adapter is not yet supported")
        if vm["ssh"]["user"] == "root":
            raise ConfigError("$.vm.ssh.user: Root login is not allowed")
        for index, key in enumerate(vm["ssh"]["public_keys"]):
            try:
                from .guest.ssh import public_key
                public_key(key)
            except (ValueError, IndexError) as error:
                raise ConfigError(f"$.vm.ssh.public_keys[{index}]: Invalid public SSH key format") from error
        for field, value in (("name", vm["name"]), ("guest_os", vm["guest_os"]), ("network.name", vm["network"]["name"])):
            if value is not None and not NAME.fullmatch(value):
                raise ConfigError(f"$.vm.{field}: Invalid name")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", vm["ssh"]["user"]):
            raise ConfigError("$.vm.ssh.user: Invalid user name")
        devices = vm["usb"]["devices"]
        identities = [(d["vendor_id"].lower(), d["product_id"].lower(), d["serial"]) for d in devices]
        if len(set(identities)) != len(identities):
            raise ConfigError("$.vm.usb.devices: Duplicate device selection")
        if not vm["usb"]["enabled"] and any(d["enabled"] for d in devices):
            raise ConfigError("$.vm.usb.enabled: Device activation requires global opt-in")
        if vm["audio"]["mode"] == "spice" and not vm["graphical"]["enabled"]:
            raise ConfigError("$.vm.audio.mode: SPICE audio requires a graphical profile")
        if vm["graphical"]["acceleration"] and not vm["graphical"]["enabled"]:
            raise ConfigError("$.vm.graphical.acceleration: requires a graphical profile")
        if vm["audio"]["mode"] == "usb" and not (vm["usb"]["enabled"] and any(d["enabled"] for d in devices)):
            raise ConfigError("$.vm.audio.mode: USB audio requires an enabled USB device")
        for index, share in enumerate(vm["shares"]):
            if not share["target"].startswith("/") or ".." in Path(share["target"]).parts or share["target"] == "/":
                raise ConfigError(f"$.vm.shares[{index}].target: Unsafe guest path")
