# vmctl Reference

`vmctl` is the command-line interface for configuration, image trust, and the
lifecycle of project-owned lab VMs. The help shipped with the installed version
is authoritative for command syntax:

```bash
vmctl --help
vmctl <COMMAND> --help
```

The VM Core capabilities documented here were tested with real VMs in the
qualified development environment. This does not establish compatibility with
arbitrary Linux hosts.

## Global options

Global options precede the subcommand:

| Option | Effect |
| --- | --- |
| `--version` | print the installed version |
| `--json` | use machine-readable output |
| `--timeout SECONDS` | set a bounded operation deadline |
| `--non-interactive` | never prompt; uncertainty remains an error |
| `--dry-run` | request supported planning without mutation |
| `--yes` | provide an explicitly supported confirmation |

None of these options bypasses ownership, host, image, or state checks.
Interactive `ssh` supports neither JSON, dry-run, nor non-interactive mode.

## Preparation and diagnostics

| Command | Purpose |
| --- | --- |
| `image import` | verify and import a local image, signature, and keyring |
| `init` | create a configuration root and profile template |
| `check-host` | passively inspect VM runtime prerequisites |
| `config validate` | validate a profile, templates, and schemas without VM access |
| `list` | list project-owned instances and tombstones from the local registry |

Examples:

```bash
vmctl check-host
vmctl check-host --resources ./host-resources.json --live
vmctl config validate --root ./config arch-local
vmctl --json list
```

`--live` is read-only but requires access to the system libvirt socket. Missing
access is reported; `vmctl` never elevates privileges to repair it.

## VM lifecycle

| Command | Purpose |
| --- | --- |
| `create [--name NAME] [--no-start] [--root ROOT] PROFILE` | create a VM and optionally continue to `project-ready` |
| `start VM` | start a stopped project-owned VM |
| `stop [--force] VM` | stop a VM gracefully or, if explicit, forcibly |
| `restart VM` | restart a running project-owned VM under lifecycle checks |
| `status VM` | read the bound state |
| `destroy VM` | remove a project-owned VM and bound private files |
| `recover ... VM` | continue an unambiguously classifiable partial operation |

```bash
vmctl --dry-run create --root ./config arch-local --name dev-01
vmctl create --root ./config arch-local --name dev-01
vmctl status dev-01
vmctl stop dev-01
vmctl start dev-01
```

`--force` performs a hard VM stop and can damage guest data. Destroy and
recovery recheck the registry, domain identity, journals, and file ownership.
Ambiguous state remains blocked for operator review.

Recovery modes:

```bash
vmctl recover --cleanup-failed --operation OPERATION-UUID dev-01
vmctl recover --restore --operation OPERATION-UUID dev-01
vmctl recover --restore-start --operation OPERATION-UUID dev-01
```

Recovery is not a general automatic repair path. The operation ID must match
the stored journal for that instance.

## Guest access and diagnostics

| Command | Purpose |
| --- | --- |
| `ssh VM` | open an interactive, host-key-pinned SSH session |
| `exec VM -- PROGRAM ARGS...` | run an argv-safe guest command without a PTY |
| `copy [--overwrite] SOURCE DEST` | transfer a file through SFTP |
| `logs [--operation UUID] [--max-bytes N] VM` | read bounded local logs |

```bash
vmctl ssh dev-01
vmctl exec dev-01 -- uname -a
vmctl copy ./artifact.tar dev-01:incoming/artifact.tar
vmctl copy dev-01:results/report.json ./report.json
vmctl logs --max-bytes 16384 dev-01
```

For `copy`, exactly one endpoint must use the form `VM:relative/path`.
Absolute guest paths, path traversal, and silent overwrites are rejected.
`--overwrite` must be supplied explicitly.

## Baselines and restore

```bash
vmctl snapshot --list dev-01
vmctl snapshot --readiness project-ready dev-01 clean-install
vmctl snapshot --verify SNAPSHOT-ID dev-01
vmctl restore --prepare dev-01 SNAPSHOT-ID
vmctl restore --inspect-preparation OPERATION-UUID dev-01 SNAPSHOT-ID
vmctl restore --activate-preparation OPERATION-UUID dev-01 SNAPSHOT-ID
```

A baseline binds disk, NVRAM, domain configuration, and manifest. Restore is a
two-stage operation: `--prepare` creates an isolated generation;
`--activate-preparation` binds exactly that generation after full revalidation.
`restore --start` is not supported in 0.5.0. Staging cleanup requires the bound
operation:

```bash
vmctl cleanup --baseline-staging --operation OPERATION-UUID dev-01
vmctl cleanup --restore-staging --operation OPERATION-UUID dev-01
```

## Exit codes and JSON

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 1 | internal error |
| 2 | invalid invocation or input |
| 3 | missing or unverified prerequisite |
| 4 | conflict with existing state |
| 5 | policy or security rejection |
| 6 | failed operation |
| 7 | timeout |
| 8 | guest error |
| 130 | interrupted |

JSON errors include a stable error code, phase, message, hint, and whether a
retry can be considered. Never reinterpret `review_required` or recovery state
from the process exit code alone.

## State and security boundaries

- `vmctl` manages only registered resources with complete ownership bindings.
- The VM lifecycle does not manage host services, networks, or storage pools.
- A name, UUID, or matching path alone does not prove ownership.
- A dry run does not authorize a later real operation.
- Failed operations are preserved for diagnosis; they are not silently retried.
- USB, audio, a GUI, and arbitrary QEMU process control are not implemented.
