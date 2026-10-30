# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Parse vmctl commands and dispatch guarded VM operations.

"""CLI contracts, offline planning, and the regular P06 libvirt lifecycle."""
import argparse
import json
import math
from pathlib import Path
import re
import sys
import time
from uuid import UUID, uuid4

from .errors import ExitCode, LabError
from .version import VERSION


class ParserExit(Exception):
    def __init__(self, status, text):
        self.status, self.text = status, text


class Parser(argparse.ArgumentParser):
    """Prevent argparse from writing uncontrolled text between JSON data."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('allow_abbrev', False)
        super().__init__(*args, **kwargs)

    def _print_message(self, message, file=None):
        if message:
            raise ParserExit(0, message)

    def error(self, message):
        # Argparse diagnostics may contain arbitrary argument values or secrets.
        raise LabError(2, 'CLI_INVALID', 'parse', 'Invalid or missing CLI arguments.',
                       'Check syntax with vmctl --help or vmctl COMMAND --help; place global options before the command.')


def parser():
    root = Parser(prog='vmctl', description='Safe libvirt Arch lifecycle with verified guest provisioning.')
    root.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    root.add_argument('--json', action='store_true', help='A versioned result object, including on failure')
    root.add_argument('--timeout', type=float, default=600, metavar='SECONDS', help='Overall deadline in seconds (positive and finite; default: 600)')
    root.add_argument('--non-interactive', action='store_true', help='No prompts; does not grant approval')
    root.add_argument('--dry-run', action='store_true', help='Offline Create plan; no mutation or live check')
    root.add_argument('--yes', action='store_true', help='Confirmation within policy; bypasses no safety check')
    commands = root.add_subparsers(dest='command', required=True)
    image = commands.add_parser('image', help='Verify and import a pinned base image locally')
    image_sub = image.add_subparsers(dest='image_command', required=True)
    image_import = image_sub.add_parser('import', help='Import local files into the private cache without downloading')
    image_import.add_argument('--cache-root', required=True, help='Neue/private Cachewurzel')
    image_import.add_argument('--image', required=True, help='Explicitly versioned qcow2 file')
    image_import.add_argument('--signature', required=True, help='Direkte abgetrennte Imagesignatur')
    image_import.add_argument('--keyring', required=True, help='Approved binary keyring')
    init = commands.add_parser('init', help='Initialize new private state and a local host profile')
    init.add_argument('--config-root', required=True, help='Private local configuration and cache root')
    init.add_argument('--host-record', required=True, help='Explicitly qualified host setup record')
    host = commands.add_parser('check-host', help='Read-only diagnostics; no service activation')
    host.add_argument('--resources', help='JSON with explicit host resources and daemon endpoints')
    host.add_argument('--live', action='store_true', help='Read-only API only for safely running endpoints without socket activation')
    config = commands.add_parser('config', help='Validate configuration offline')
    sub = config.add_subparsers(dest='config_command', required=True)
    validate = sub.add_parser('validate', help='Resolve and validate a profile')
    validate.add_argument('profile', help='Profile name or YAML under profiles/ or templates/')
    validate.add_argument('--root', default='.', help='Konfigurationswurzel (Standard: Arbeitsverzeichnis)')
    help_text = {
        'create':'Create an Arch VM; success only at project-ready', 'start':'Start a managed VM and verify guest readiness',
        'list':'List registered owned instances and tombstones',
        'restart':'Perform a graceful stop and regular start within one overall deadline',
        'logs':'Read the bound serial log and operation diagnostics',
        'exec':'Run a non-interactive guest command argv-safely without a PTY',
        'copy':'Transfer manifested files through bound SFTP',
        'stop':'Shut down a managed VM cleanly', 'status':'Show power, lifecycle, and guest readiness',
        'ssh':'Interactive SSH session with a verified host key', 'destroy':'Remove an owned VM and instance files',
        'recover':'Run bound Create, restore, or start recovery',
        'snapshot':'Create, list, or verify an immutable offline baseline',
        'restore':'Prepare, inspect, or transactionally activate a restore offline',
        'cleanup':'Explicitly clean up failed baseline or restore staging',
    }
    commands.add_parser('list', help=help_text['list'])
    for name in ('create', 'start', 'stop', 'restart', 'status', 'logs', 'ssh', 'exec', 'copy', 'snapshot', 'restore', 'cleanup', 'destroy', 'recover'):
        command = commands.add_parser(name, help=help_text[name])
        if name == 'copy':
            command.add_argument('source', help='Host path or VM:/relative-workspace-path')
            command.add_argument('destination', help='Host path or VM:/relative-workspace-path')
            command.add_argument('--overwrite', action='store_true',
                                 help='Replace an existing safe file or directory target in a controlled manner')
        else:
            command.add_argument('profile' if name == 'create' else 'vm', help='Profile name' if name == 'create' else 'Registered instance name or domain UUID')
        if name == 'exec':
            command.add_argument('program', nargs=argparse.REMAINDER,
                                 help='After --: program and unchanged arguments (at least one value)')
        if name == 'create':
            command.add_argument('--name', help='Separate instance name (default: profile name or YAML file stem)')
            command.add_argument('--no-start', action='store_true', help='Create and define only')
            command.add_argument('--root', default='.', help='Konfigurationswurzel (Standard: Arbeitsverzeichnis)')
        if name == 'stop':
            command.add_argument('--force', action='store_true', help='Hard power-off; confirmation required')
        if name == 'logs':
            command.add_argument('--operation', metavar='OPERATION-UUID',
                                 help='Diagnose a specific existing journal operation')
            command.add_argument('--max-bytes', type=int, default=16 * 1024, metavar='BYTES',
                                 help='Tail limit of 1..65536 bytes (default: 16384); --follow is not supported')
        if name == 'recover':
            mode = command.add_mutually_exclusive_group(required=True)
            mode.add_argument('--cleanup-failed', action='store_true',
                                 help='Clean up the exactly bound failed Create operation')
            mode.add_argument('--restore', action='store_true',
                              help='P08-B3: analyze and resolve a documented partial restore state')
            mode.add_argument('--restore-start', action='store_true',
                              help='Resolve an ACL-related restore start while the domain is powered off')
            command.add_argument('--operation', required=True, metavar='OPERATION-UUID',
                                 help='UUID of the original Create, restore, or start operation')
        if name == 'cleanup':
            mode = command.add_mutually_exclusive_group(required=True)
            mode.add_argument('--baseline-staging', action='store_true',
                              help='Failed unpublished baseline staging')
            mode.add_argument('--restore-staging', action='store_true',
                              help='Fehlgeschlagene, nie aktivierte Restorevorbereitung')
            command.add_argument('--operation', required=True, metavar='OPERATION-UUID',
                                 help='Exact UUID of the original staging operation')
        if name in ('snapshot', 'restore'):
            command.add_argument('snapshot', nargs='?' if name == 'snapshot' else None,
                                 help='Checkpoint name' if name == 'snapshot'
                                 else 'Immutable baseline ID (SHA256)')
        if name == 'snapshot':
            mode = command.add_mutually_exclusive_group()
            mode.add_argument('--list', action='store_true', help='List published baselines')
            mode.add_argument('--verify', metavar='BASELINE-ID', help='Verify a published baseline completely')
            command.add_argument('--readiness', choices=('clean','ssh-ready','project-ready'),
                                 help='Verified state for a new baseline')
        if name == 'restore':
            mode = command.add_mutually_exclusive_group()
            mode.add_argument('--prepare', action='store_true',
                              help='P08-B1: prepare an isolated generation without switching anything')
            mode.add_argument('--inspect-preparation', metavar='OPERATION-UUID',
                              help='Reverify the P08-B1 preparation status')
            mode.add_argument('--activate-preparation', metavar='OPERATION-UUID',
                              help='P08-B2: revalidate and switch disk and NVRAM together')
            command.add_argument('--start', action='store_true',
                                 help='Not supported; P08-B2 has no implicit start')
    return root


def _check_deadline(deadline, phase='offline'):
    if time.monotonic() >= deadline:
        raise LabError(7, 'DEADLINE_EXCEEDED', phase, 'Overall deadline exceeded.',
                       'No VM action was performed; review the deadline before retrying.')


def _identifier(value, field, allow_uuid=False):
    if allow_uuid:
        try:
            if str(UUID(value)) == value:
                return
        except ValueError:
            pass
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value):
        raise LabError(2, 'CLI_INVALID', 'parse', f'{field}: invalid name or UUID.',
                       'Use an ASCII name containing lowercase letters, digits, and hyphens.')


def _confirm(args, action, name):
    if args.yes:
        return
    if args.non_interactive or not sys.stdin.isatty():
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation',
                       f'{action} requires explicit confirmation.',
                       f'After reviewing the instance, invoke again with --yes: vmctl --yes {action} {name}')
    answer = input(f'{action} removes or discards state for {name}. Enter the instance name to confirm: ')
    if answer != name:
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation', 'Confirmation does not match the instance.',
                       'Command ended without changes; review the target again.')


def _confirm_prepare(args, name):
    if args.yes:
        return
    if args.non_interactive or not sys.stdin.isatty():
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation',
                       'restore --prepare requires explicit confirmation.',
                       f'After reviewing the instance and space requirements, invoke again with --yes: vmctl --yes restore {name} BASELINE-ID --prepare')
    answer = input(f'restore --prepare creates a new inactive generation for {name}. Enter the instance name to confirm: ')
    if answer != name:
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation',
                       'Confirmation does not match the instance.',
                       'Command ended without staging; review the target again.')


def _confirm_cleanup(args, name, kind, operation):
    if args.yes:
        return
    action = f'cleanup --{kind}-staging --operation {operation}'
    if args.non_interactive or not sys.stdin.isatty():
        raise LabError(
            5, 'CONFIRMATION_REQUIRED', 'confirmation',
            f'{action} requires explicit confirmation.',
            ('After reviewing the operation, inventory, and reservation, invoke again with --yes '
             f'run: vmctl --yes cleanup {name} --{kind}-staging '
             f'--operation {operation}'))
    answer = input(
        f'{action} removes the bound staging for {name}. '
        'Enter the instance name to confirm: ')
    if answer != name:
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation',
                       'Confirmation does not match the instance.',
                       'Command ended without cleanup; review the target again.')


def _confirm_activate(args, name):
    if args.yes:
        return
    if args.non_interactive or not sys.stdin.isatty():
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation',
                       'restore --activate-preparation requires explicit confirmation.',
                       f'After review, invoke again with --yes: vmctl --yes restore {name} BASELINE-ID --activate-preparation OPERATION-UUID')
    answer = input(f'restore discards the active guest state for {name}. Enter the instance name to confirm: ')
    if answer != name:
        raise LabError(5, 'CONFIRMATION_REQUIRED', 'confirmation',
                       'Confirmation does not match the instance.',
                       'Command ended without switching; review the target again.')


def _dispatch(args, result, deadline):
    result['command'] = 'config validate' if args.command == 'config' else args.command
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise LabError(2, 'CLI_INVALID', 'parse', '--timeout must be positive and finite.',
                       'Use a positive number of seconds.')
    if args.command == 'copy':
        from .guest.files import endpoints
        spec = endpoints(args.source, args.destination)
        args.vm = spec['vm']
    if args.command not in ('config', 'create', 'check-host', 'list', 'image', 'init'):
        _identifier(args.vm, 'VM', allow_uuid=True)
        is_name = bool(re.fullmatch(r'[a-z][a-z0-9-]{0,62}', args.vm))
        result['vm'] = {'name': args.vm if is_name else None, 'uuid': None if is_name else args.vm}
        if args.command in ('snapshot', 'restore'):
            snapshot = args.snapshot
            if args.command == 'restore' and args.start and not args.dry_run:
                raise LabError(2, 'OPTION_UNSUPPORTED', 'parse',
                               'P08-B2 activates offline only and does not start a VM.',
                               'Run restore without --start; a later start remains a separate vmctl invocation.')
            if args.command == 'snapshot':
                modes = int(bool(snapshot)) + int(args.list) + int(bool(args.verify))
                if modes != 1 or (snapshot and not args.readiness) or (not snapshot and args.readiness):
                    raise LabError(2, 'CLI_INVALID', 'parse',
                                   'snapshot requires NAME --readiness STATUS, --list, or --verify ID.',
                                   'Specify exactly one mode and, for creation, a verified readiness status.')
                if args.verify and not re.fullmatch(r'[0-9a-f]{64}', args.verify):
                    raise LabError(2, 'CLI_INVALID', 'parse', 'Baseline ID must have SHA256 format.',
                                   'Use the immutable ID from create or list.')
            if snapshot and (args.command == 'snapshot'
                             or not (args.prepare or args.inspect_preparation
                                     or args.activate_preparation)):
                _identifier(snapshot, 'Checkpoint')
            if args.command == 'restore':
                if (args.prepare or args.inspect_preparation or args.activate_preparation) and not re.fullmatch(r'[0-9a-f]{64}', snapshot or ''):
                    raise LabError(2, 'CLI_INVALID', 'parse',
                                   'Restore preparation requires an immutable baseline ID.',
                                   'Use the 64-character SHA256 ID from snapshot --list.')
                operation = args.inspect_preparation or args.activate_preparation
                if operation:
                    try:
                        if str(UUID(operation)) != operation:
                            raise ValueError
                    except (ValueError, TypeError, AttributeError):
                        raise LabError(2, 'CLI_INVALID', 'parse',
                                       'Restore operation: invalid UUID.',
                                       'Use the restore operation ID emitted by --prepare.')
        if args.command in ('recover', 'cleanup'):
            try:
                if str(UUID(args.operation)) != args.operation:
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                raise LabError(2, 'CLI_INVALID', 'parse', 'Operation: invalid UUID.',
                               'Use the source UUID associated with the selected recovery mode.')
        if args.command == 'logs' and args.operation:
            try:
                if str(UUID(args.operation)) != args.operation:
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                raise LabError(2, 'CLI_INVALID', 'parse', 'Operation: invalid UUID.',
                               'Use an operation UUID from the same instance.')
        if args.command == 'logs' and not 1 <= args.max_bytes <= 65536:
            raise LabError(2, 'CLI_INVALID', 'parse', '--max-bytes is outside the permitted range.',
                           'Use a value between 1 and 65536.')
        if args.command == 'exec':
            if not getattr(args, 'exec_separator', False) or not args.program or not args.program[0]:
                raise LabError(2, 'CLI_INVALID', 'parse',
                               'exec requires exactly -- PROGRAM [ARG ...] after the VM.',
                               'Example: vmctl exec arch-test -- uname -a')
    if args.command == 'ssh' and (args.json or args.non_interactive or args.dry_run):
        raise LabError(2, 'OPTION_UNSUPPORTED', 'parse', 'Interactive ssh supports neither JSON, non-interactive mode, nor dry-run.',
                       'Use the exec contract for automation.')
    if args.dry_run and args.command != 'create':
        if args.command in ('start', 'stop', 'restart', 'restore', 'cleanup', 'destroy', 'recover') or (args.command == 'snapshot' and not args.list):
            raise LabError(3, 'STATE_UNAVAILABLE', 'plan', 'A complete plan requires registry and ownership evidence; not yet implemented.',
                           'Wait for P03 and the respective lifecycle contract; do not use names as ownership evidence.')
        raise LabError(2, 'OPTION_UNSUPPORTED', 'parse', 'Dry-run is not supported for this command.',
                       'config validate is already offline; currently use dry-run only with create.')
    _check_deadline(deadline, 'host-check' if args.command == 'check-host' else 'offline')
    if args.command == 'image':
        from .release import ARCH_IMAGE_SPEC, ARCH_TRUST
        from .storage.images import ImageCache
        manifest = ImageCache(args.cache_root).import_local(
            ARCH_IMAGE_SPEC, args.image, args.signature, args.keyring, ARCH_TRUST)
        result['data'] = {'image': manifest, 'cache_root': str(Path(args.cache_root).absolute())}
        result['state'] = 'completed'
        return
    if args.command == 'init':
        from .bootstrap import initialize
        try:
            initialized = initialize(args.config_root, args.host_record)
        except ValueError as error:
            raise LabError(5, 'BOOTSTRAP_CONFLICT', 'initialization', str(error),
                           'Inspect existing bindings and paths; do not overwrite or adopt anything.') from error
        result['data'] = {'initialization': initialized}
        result['state'] = 'completed'
        return
    if args.command == 'check-host':
        from .host import LocalProbe, diagnose, load_request
        report = diagnose(load_request(args.resources, args.live), LocalProbe(deadline))
        result['data'] = {'host': report}
        if not report['infrastructure_qualified']:
            raise LabError(3, 'HOST_NOT_QUALIFIED', 'host-check', 'Host prerequisites are missing or unverified.',
                           'Inspect diagnostic entries; obtain an operator decision and do not repair automatically.')
        result['state'] = 'completed'
        return
    if args.command == 'config' or (args.command == 'create' and args.dry_run):
        try:
            from .config import ConfigError, ConfigLoader
        except ImportError as error:
            raise LabError(3, 'DEPENDENCY_MISSING', 'preflight', 'Python dependencies are missing.',
                           'Use the project environment described in docs/INSTALLATION.md.') from error
        try:
            resolved = ConfigLoader(args.root).load(args.profile)
        except ConfigError as error:
            raise LabError(2, 'CONFIG_INVALID', 'validation', str(error),
                           'Correct the named field or path in the configuration.') from error
        _check_deadline(deadline)
        vm = resolved.config['vm']
        if args.command == 'create':
            instance_name = args.name if args.name is not None else Path(args.profile).stem
            _identifier(instance_name, 'Instanzname')
            if vm['name'] != instance_name or args.name is not None:
                resolved.origins['$.vm.name'] = '<cli>'
            vm['name'] = instance_name
            resolved.incomplete = [reason for reason in resolved.incomplete if reason != '$.vm.name: missing']
        name = vm['name']
        if name is not None:
            _identifier(name, 'Instance name')
        result['vm'] = {'name': name, 'uuid': None}
        result['data'] = {'config': resolved.config, 'origins': resolved.origins,
                          'incomplete': resolved.incomplete, 'verified_for_execution': False}
        if args.command == 'create':
            from .planning import create_plan
            result['data']['plan'] = create_plan(resolved, name, args.no_start)
        if not resolved.complete:
            raise LabError(3, 'CONFIG_INCOMPLETE', 'validation', 'Not startable: configuration is incomplete.',
                           'Review missing data in data.incomplete; do not approve ready without further evidence.')
        result['state'] = 'planned' if args.command == 'create' else 'validated'
        return
    if args.command == 'restore' and not (args.prepare or args.inspect_preparation
                                          or args.activate_preparation):
        raise LabError(2, 'NOT_IMPLEMENTED', 'dispatch',
                       'restore requires preparation, inspection, or explicit activation.',
                       'Use --prepare, --inspect-preparation, or --activate-preparation.')
    from .lifecycle import Lifecycle
    lifecycle = Lifecycle()
    exec_error = None
    try:
        if args.command == 'create':
            try:
                from .config import ConfigError, ConfigLoader
            except ImportError as error:
                raise LabError(3, 'DEPENDENCY_MISSING', 'preflight', 'Python dependencies are missing.',
                               'Use the project environment described in docs/INSTALLATION.md.') from error
            try:
                resolved = ConfigLoader(args.root).load(args.profile)
            except ConfigError as error:
                raise LabError(2, 'CONFIG_INVALID', 'validation', str(error),
                               'Correct the named field or path in the configuration.') from error
            instance_name = args.name if args.name is not None else Path(args.profile).stem
            _identifier(instance_name, 'Instance name')
            resolved.config['vm']['name'] = instance_name
            resolved.incomplete = [reason for reason in resolved.incomplete if reason != '$.vm.name: missing']
            if not resolved.complete:
                result['data'] = {'config': resolved.config, 'origins': resolved.origins,
                                  'incomplete': resolved.incomplete, 'verified_for_execution': False}
                raise LabError(3, 'CONFIG_INCOMPLETE', 'validation', 'Not startable: configuration is incomplete.',
                               'Review missing data in data.incomplete.')
            data = lifecycle.create(resolved, instance_name, args.no_start, deadline)
        elif args.command == 'list':
            data = lifecycle.list_instances()
        elif args.command == 'start':
            data = lifecycle.start(args.vm, deadline)
        elif args.command == 'restart':
            data = lifecycle.restart(args.vm, deadline)
        elif args.command == 'stop':
            if args.force: _confirm(args, 'stop --force', args.vm)
            data = lifecycle.stop(args.vm, deadline, force=args.force)
        elif args.command == 'status':
            data = lifecycle.status(args.vm)
        elif args.command == 'logs':
            data = lifecycle.logs(args.vm, args.operation, args.max_bytes)
        elif args.command == 'ssh':
            status = lifecycle.ssh(args.vm, deadline)
            if status:
                raise LabError(6, 'SSH_FAILED', 'ssh', f'SSH exited with code {status}.',
                               'Inspect guest status and connection.', retryable=True)
            data = {'name': args.vm, 'ssh_exit_code': 0}
        elif args.command == 'exec':
            data = lifecycle.exec(args.vm, args.program, deadline, result['operation_id'])
            if data['outcome'] == 'guest_failed':
                exec_error = LabError(
                    8, 'GUEST_COMMAND_FAILED', 'exec',
                    'Guest command ran and ended with an error.',
                    'Inspect data.lifecycle.guest_exit_code and the bounded output.')
            elif data['outcome'] == 'timed_out':
                exec_error = LabError(
                    7, 'GUEST_COMMAND_TIMEOUT', 'exec',
                    'Guest job reached the exec deadline; its completion is unconfirmed.',
                    'Inspect the job ID and operation diagnostics; do not retry automatically.',
                    retryable=True)
            elif data['outcome'] == 'transport_failed':
                exec_error = LabError(
                    6, 'SSH_TRANSPORT_FAILED', 'exec',
                    'SSH transport ended without a bound guest response.',
                    'Inspect the job ID, guest status, and operation diagnostics; do not retry automatically.',
                    retryable=True)
            elif data['outcome'] == 'protocol_failed':
                exec_error = LabError(
                    6, 'EXEC_PROTOCOL_INVALID', 'exec',
                    'Guest response was incomplete, too large, or not bound to this job.',
                    'Inspect the job ID and operation diagnostics; do not treat the output as a guest result.')
        elif args.command == 'copy':
            data = lifecycle.copy(
                args.source, args.destination, args.overwrite, deadline,
                result['operation_id'])
            if data['outcome'] == 'timed_out':
                exec_error = LabError(
                    7, 'COPY_TIMEOUT', 'copy',
                    'File transfer reached the overall deadline; target completion is unconfirmed.',
                    'Inspect the transfer ID and operation diagnostics; do not retry automatically.', True)
            elif data['outcome'] == 'transport_failed':
                exec_error = LabError(
                    6, 'SFTP_TRANSPORT_FAILED', 'copy',
                    'SFTP or control transport ended without complete evidence.',
                    'Inspect the transfer ID and operation diagnostics; do not retry automatically.', True)
            elif data['outcome'] == 'integrity_failed':
                exec_error = LabError(
                    6, 'COPY_INTEGRITY_MISMATCH', 'copy',
                    'Transfer size or SHA256 does not match.',
                    'Inspect the transfer ID and staging diagnostics; do not use the target.')
            elif data['outcome'] == 'file_failed':
                exec_error = LabError(
                    5, 'COPY_FILE_REJECTED', 'copy',
                    'Guest or host file contract rejected the transfer.',
                    'Inspect paths, file types, limits, and --overwrite.')
        elif args.command == 'destroy':
            _confirm(args, 'destroy', args.vm)
            data = lifecycle.destroy(args.vm, deadline)
        elif args.command == 'cleanup':
            kind = 'baseline' if args.baseline_staging else 'restore'
            _confirm_cleanup(args, args.vm, kind, args.operation)
            data = lifecycle.cleanup_staging(args.vm, kind, args.operation, deadline)
        elif args.command == 'recover':
            if args.cleanup_failed:
                _confirm(args, 'recover --cleanup-failed', args.vm)
                data = lifecycle.recover_failed_cleanup(args.vm, args.operation, deadline)
            elif args.restore:
                _confirm(args, 'recover --restore', args.vm)
                data = lifecycle.recover_restore(args.vm, args.operation, deadline)
            elif args.restore_start:
                _confirm(args, 'recover --restore-start', args.vm)
                data = lifecycle.recover_restore_start(args.vm, args.operation, deadline)
        elif args.command == 'snapshot':
            if args.list:
                data = lifecycle.list_snapshots(args.vm, deadline)
            elif args.verify:
                data = lifecycle.verify_snapshot(args.vm, args.verify, deadline)
            else:
                data = lifecycle.snapshot(args.vm, args.snapshot, args.readiness, deadline)
        elif args.command == 'restore':
            if args.prepare:
                _confirm_prepare(args, args.vm)
                data = lifecycle.prepare_restore(
                    args.vm, args.snapshot, result['operation_id'], deadline)
            elif args.inspect_preparation:
                data = lifecycle.inspect_restore_preparation(
                    args.vm, args.snapshot, args.inspect_preparation, deadline)
            else:
                _confirm_activate(args, args.vm)
                data = lifecycle.activate_restore(
                    args.vm, args.snapshot, args.activate_preparation, deadline)
        result['data'] = {'lifecycle': data}
        result['vm'] = {'name': data.get('vm_name', data.get('name')),
                        'uuid': data.get('domain_uuid')}
        result['state'] = 'completed'
        if exec_error is not None:
            raise exec_error
        return
    finally:
        lifecycle.close()


def _render(result, json_mode):
    if json_mode:
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        return
    data = result['data']
    if data:
        if 'help' in data:
            print(data['help'], end='')
        elif 'host' in data:
            for check in data['host']['checks']:
                print(f"{check['status']}: {check['name']}: {check['message']} Remedy: {check['hint']}")
            print(data['host']['notice'])
        elif 'lifecycle' in data:
            print(json.dumps(data['lifecycle'], ensure_ascii=True, indent=2))
        elif 'image' in data or 'initialization' in data:
            print(json.dumps(data, ensure_ascii=True, indent=2))
        else:
            print('Schema valid; effective configuration and provenance:')
            print(json.dumps(data, ensure_ascii=True, indent=2))
            if result['ok']:
                print('Offline validation or plan only; no start approval or VM operation.')
    if result['error']:
        error = result['error']
        diagnostic = f"ERROR [{error['code']}] {error['message']}\nRemedy: {error['hint']}\nOperation ID: {result['operation_id']}"
        print(''.join(c if c.isprintable() or c == '\n' else f'\\u{ord(c):04x}' for c in diagnostic), file=sys.stderr)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    json_mode = '--json' in argv[:argv.index('--') if '--' in argv else len(argv)]
    result = dict(schema_version=1, operation_id=str(uuid4()), ok=False, command=None,
                  vm={'name': None, 'uuid': None}, state='failed', data=None, error=None, artifacts=[])
    exit_code = ExitCode.OK
    try:
        args = parser().parse_args(argv)
        if args.command == 'exec':
            index = argv.index('exec')
            args.exec_separator = len(argv) > index + 2 and argv[index + 2] == '--'
        deadline = time.monotonic() + args.timeout
        _dispatch(args, result, deadline)
        _check_deadline(deadline, 'host-check' if args.command == 'check-host' else 'offline')
    except ParserExit as help_result:
        result['data'] = {'help': help_result.text}
        result['state'] = 'completed'
    except LabError as error:
        result['error'], exit_code = error.detail, error.exit_code
    except KeyboardInterrupt:
        exit_code = ExitCode.INTERRUPTED
        result['error'] = dict(code='INTERRUPTED', phase='offline', message='Invocation interrupted; no VM action was performed.',
                               hint='Restart the offline invocation if needed.', retryable=False)
    except Exception:
        exit_code = ExitCode.INTERNAL
        result['error'] = dict(code='INTERNAL_ERROR', phase='internal', message='Unexpected internal error.',
                               hint='Report the operation ID and reproducible invocation; do not disclose secrets.', retryable=False)
    result['ok'] = exit_code == ExitCode.OK
    if not result['ok']:
        result['state'] = 'failed'
    _render(result, json_mode)
    return int(exit_code)


if __name__ == '__main__':
    raise SystemExit(main())
