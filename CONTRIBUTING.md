# Contributing

Thank you for your interest in `vm-dev-lab`. The project is in early
development. Explicit security contracts and inspectable state transitions take
priority over a broad feature surface.

## Development environment

Python 3.10 or newer and the dependencies declared in `pyproject.toml` are
required:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

The optional `.[libvirt]` extra is needed only for real libvirt access. The
offline suite must not change host services, VMs, networks, or storage pools.
See [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) for the complete tool matrix.

## Developing changes

- Keep each change small and focused on one problem.
- Preserve the Python `src` layout and public CLI contracts.
- Keep libvirt as the only real VM lifecycle manager.
- Put distribution-specific behavior in guest adapters and project-specific
  requirements in profiles or clearly separated extensions.
- Report failures honestly; failed or unimplemented actions must not claim
  success.
- Add tests for relevant failure, ownership, and recovery cases.
- Update public documentation when observable behavior changes.
- Declare Python dependencies only in `pyproject.toml` and document their
  purpose in `docs/REQUIREMENTS.md`.

Do not copy third-party code without established provenance and licensing.
Keys, credentials, local host records, VM disks, images, and logs must not be
committed.

Contributions to project-owned code must be publishable under the MIT project
license. Do not remove notices belonging to other authors or represent their
rights as project-owned.

## Branches and pull requests

`main` is the stable development branch. Use short-lived branches:

- `feature/<short-name>` for new capabilities
- `fix/<short-name>` for corrections

Submit changes through a pull request against `main` and obtain review before
merge. The project does not use a complex GitFlow model. A pull request should
state its scope, security impact, tests, and any missing real-world validation.
Keep unrelated changes in separate branches.

## Repository structure

- `src/vm_dev_lab/` contains the Python implementation.
- `tests/` contains offline-suitable regression tests and bounded harnesses.
- `templates/` contains portable, secret-free YAML bases. The public
  `profiles/` directory contains no profile files; host-specific profiles are
  generated in a private configuration root.
- `cloud-init/` contains guest templates.
- `scripts/` contains deliberately invoked host tools.
- `docs/` contains public user and architecture documentation.

Local configuration, state, caches, images, and test artifacts belong in
ignored paths and must not become a second repository structure.

## Verification

Run the checks relevant to the change:

```bash
python -m unittest discover -s tests -v
./vmctl --help
host-setup --help
python -m compileall -q src tests
bash -n scripts/check-host.sh scripts/vm-host.sh
shellcheck scripts/check-host.sh scripts/vm-host.sh
git diff --check
```

If ShellCheck is unavailable, report that check as not run instead of
installing it without authorization. Real host or VM tests require explicit,
bounded authorization and resources with proven project ownership.

The VM Core has real-VM evidence from the qualified development environment.
Host Setup remains **Heavy Development / Experimental** and has only offline
fixture coverage. Never describe offline results as a fresh-host real-world
acceptance.

## Commits and reviews

Use concise, imperative commit messages. A review should answer:

- What problem does the change solve?
- Which security and ownership boundaries are affected?
- Which tests were run?
- Which real host or VM validation remains open?
- Does the change add dependencies or licensing obligations?

Do not force-push, rewrite history, or change remotes without explicit
agreement. A review must not present offline test results as real host
acceptance.

## Bug reports

Include the version, operating system, Python version, invoked command, process
exit code, and stable error code. Remove keys, user names, private paths, IP
addresses, UUIDs, and other local identifiers. For `review_required`, do not
manually delete files or libvirt resources; preserve the diagnostic evidence
and describe the observed state.
