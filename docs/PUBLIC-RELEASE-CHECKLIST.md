# Public Release Checklist

Status date: 2026-10-30. This checklist describes the prepared `0.5.0` file
set. It does not authorize publication or changes to Git remotes, history,
tags, or release platforms.

## Repository content

- [x] README provides a concise public project entry point
- [x] requirements, installation, CLI, Host Setup, and architecture are public
  and consistently documented in English
- [x] contribution guidance and changelog are present
- [x] historical phase, internal planning, and host evidence are excluded from
  the intended public documentation set
- [x] runtime diagnostics point to valid public documentation anchors
- [x] user-specific paths and private host evidence are absent from public docs
- [x] local images, disks, logs, and plans remain ignored and unversioned

## Development status

- [x] VM Core is described as real-VM-tested only in the qualified development
  environment
- [x] Host Setup is marked **Heavy Development / Experimental** and offline-only
- [x] fresh-host real-world acceptance remains explicitly open
- [x] offline clone, test, and package evidence is not presented as a complete
  real installation result

## Privacy and secret audit

The intended public file set was checked for private-key markers, common cloud
credentials, email addresses, user-specific home paths, large binaries, and
private host evidence. No usable secret or versioned VM artifact was identified.

Private IPv4 addresses remain as generic defaults, schema values, and isolated
test data. They do not identify a published real host. Some security tests
intentionally contain incomplete private-key markers, dummy values such as
`token=x`, and the reserved `example.invalid` domain to verify rejection and
redaction. They are not usable credentials.

The configured private Git remote is local repository metadata and is not part
of the future new public history. It must not be copied into public remote
configuration.

Before a later push, repeat:

```bash
git status --short --branch
git diff --cached --check
git grep -nEI 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}'
git ls-files
```

## Licensing

The project owner selected MIT (`SPDX: MIT`) for project-owned code.

- [x] official MIT text is present in `LICENSE`
- [x] `Copyright (c) 2026 André Manz` is recorded
- [x] SPDX license expression and license file are declared in `pyproject.toml`
- [x] README, changelog, and contribution guidance agree on MIT
- [x] direct Python dependencies were checked against their bundled license
  files and package metadata
- [x] external host tools are distinguished from the distributed Python package

The repository audit identified no embedded third-party source, external
binary, or copied third-party copyright header in the public Python code,
shell scripts, templates, or test fixtures. One comment references the external
cloud-init schema but does not copy its source.

PyYAML (MIT), Jinja2 (BSD-3-Clause), jsonschema (MIT), and optional
libvirt-python (LGPL-2.0-or-later) are installed separately and are not copied
into the project wheel. System tools are provided by the operating-system
distribution and retain their component-specific licenses. No additional
`NOTICE` file is required for the current repository and wheel content. This
technical inventory is not legal advice.

## Technical readiness

- [x] offline regression suite passed for the prepared functional release state
- [x] Python and shell syntax checks passed
- [x] ShellCheck passed
- [x] CLI examples were compared with parser and help contracts
- [x] an offline wheel was built and its metadata and contents inspected
- [x] Markdown links and obsolete documentation references were checked
- [x] `git diff --check` and the tracked-file audit passed
- [ ] a fresh installation on a supported real host has been qualified

The open item is a known `0.5.0` limitation. It must either be completed or
remain prominent in the public release description.

## Later release actions

These actions have deliberately not been performed:

- [x] choose the project license
- [ ] review the final export source commit
- [ ] create the independent public Git history
- [ ] configure the public remote
- [ ] create the version tag
- [ ] push and publish the release

Each remaining action requires separate explicit authorization.
