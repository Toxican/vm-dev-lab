# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Run bounded local subprocesses with separated diagnostic channels.

"""Bounded local tools with separate machine and diagnostic channels."""
import math
import os
import selectors
import subprocess
import time
from dataclasses import dataclass

from .errors import LabError


@dataclass(frozen=True)
class ExchangeResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_limited: bool = False


def run(argv, timeout=30, pass_fds=(), limit=1024 * 1024):
    if not math.isfinite(timeout) or timeout <= 0:
        raise LabError(7, 'TOOL_TIMEOUT', 'verification', 'Tool deadline exceeded.', 'Review the deadline; do not use an unverified fallback.')
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, pass_fds=pass_fds,
                                 env={**os.environ, 'LC_ALL': 'C'})
    except FileNotFoundError:
        raise LabError(3, 'TOOL_MISSING', 'verification', 'Required local tool is missing.', 'Review docs/INSTALLATION.md; do not install anything automatically.') from None
    try:
        output = bytearray(); total = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            selector.register(child.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise LabError(7, 'TOOL_TIMEOUT', 'verification', 'Tool deadline exceeded.', 'Do not infer approval; inspect the local operation.')
                for key, _ in selector.select(0):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj); continue
                    total += len(data)
                    if total > limit:
                        raise LabError(6, 'TOOL_OUTPUT_LIMIT', 'verification', 'Tool output exceeds the limit.', 'Inspect the input and tool locally.')
                    if key.fileobj is child.stdout: output.extend(data)
        child.wait(timeout=max(.001, deadline - time.monotonic()))
        return child.returncode, bytes(output)
    except subprocess.TimeoutExpired:
        raise LabError(7, 'TOOL_TIMEOUT', 'verification', 'Tool deadline exceeded.', 'Do not use an unverified fallback.') from None
    finally:
        if child.poll() is None: child.kill()
        child.wait()
        child.stdout.close(); child.stderr.close()


def exchange(argv, input_data, timeout=30, limit=256 * 1024):
    """Bound stdin, stdout, and stderr of a non-interactive subprocess."""
    if (not math.isfinite(timeout) or timeout <= 0 or not isinstance(input_data, bytes)
            or type(limit) is not int or limit <= 0):
        raise LabError(7, 'TOOL_TIMEOUT', 'exec', 'Tool deadline or protocol boundary is invalid.',
                       'Inspect the exec invocation and overall deadline; do not retry automatically.')
    try:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env={**os.environ, 'LC_ALL': 'C'})
    except FileNotFoundError:
        raise LabError(3, 'TOOL_MISSING', 'exec', 'OpenSSH client was not found.',
                       'Provide OpenSSH as described in docs/INSTALLATION.md; do not install anything automatically.') from None
    output = [bytearray(), bytearray()]
    sent = 0
    timed_out = output_limited = False
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 0)
            selector.register(child.stderr, selectors.EVENT_READ, 1)
            if input_data:
                selector.register(child.stdin, selectors.EVENT_WRITE, 2)
            else:
                child.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                events = selector.select(remaining)
                if not events:
                    timed_out = True
                    break
                for key, _ in events:
                    if key.data == 2:
                        try:
                            count = os.write(key.fd, input_data[sent:sent + 65536])
                        except BrokenPipeError:
                            count = 0
                        sent += count
                        if count == 0 or sent == len(input_data):
                            selector.unregister(key.fileobj)
                            child.stdin.close()
                        continue
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if sum(map(len, output)) + len(chunk) > limit:
                        output_limited = True
                        break
                    output[key.data].extend(chunk)
                if output_limited:
                    break
        if timed_out or output_limited:
            child.kill()
        try:
            child.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill(); child.wait()
        return ExchangeResult(child.returncode, bytes(output[0]), bytes(output[1]),
                              timed_out, output_limited)
    finally:
        if child.poll() is None:
            child.kill(); child.wait()
        if child.stdin and not child.stdin.closed:
            child.stdin.close()
        child.stdout.close(); child.stderr.close()
