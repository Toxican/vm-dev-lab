# vm-dev-lab
> ****UNDER HEAVY DEVELOPMENT****

`vm-dev-lab` is a command-line Linux VM lab for isolated development and test
environments on a single QEMU/KVM and libvirt host. It combines declarative
profiles, trust-verified base images, guarded VM lifecycle operations, and a
separate Arch Linux host setup assistant.

> **Early Development Release 0.5.0:** Review every plan and diagnostic before
> confirming administrative or real VM operations.

## Development status

- **VM Core:** tested with real VMs in the qualified development environment
- **Host Setup:** **Heavy Development / Experimental**; implemented through the
  current uninstall workflow and tested only offline with fixtures
- **Fresh-host installation:** not yet independently validated end to end on a
  clean Arch Linux host

The lab separates development environments on its intended network. It is not
a security boundary for hostile guests and does not claim compatibility with
arbitrary Linux hosts.

## Why vm-dev-lab?

- libvirt remains the only manager of real VM lifecycles.
- Profiles and templates are validated before resources are created.
- Images are imported locally, immutably, and with signature evidence.
- A registry, operation journals, and locks protect partial state.
- Ownership checks prevent changes to unrelated libvirt resources.
- Resource accounting supports bounded multi-VM operation.
- Baseline and restore workflows bind disk, NVRAM, XML, and manifests.
- `exec` and `copy` use authenticated SSH with a pinned host key.
- Host changes follow an explicit check-plan-apply contract.

## Supported scope

The first supported host target is Arch Linux x86_64 with KVM, systemd,
modular system libvirt (`qemu:///system`), QEMU/qcow2, and OVMF. The current
guest adapter creates and provisions Arch Linux VMs through NoCloud and SSH.

Implemented VM Core capabilities include:

- image import, project initialization, and profile validation
- Create, Start, Stop, Restart, Status, and Destroy
- registry and CPU, memory, and storage resource accounting
- bounded logs and conservative recovery of interrupted operations
- Arch guest provisioning to a verified readiness state
- immutable baselines and prepared, transactional restore generations
- authenticated guest commands and SFTP-based file transfer
- ownership-checked cleanup and diagnostics

The experimental `host-setup` assistant provides passive host checks,
check-plan-apply package and environment workflows, dedicated lab network and
storage planning, and ownership-safe uninstall planning.

Version 0.5.0 does not provide a GUI, USB passthrough, audio integration, a
general ISO installer, or support for other host distributions.

## Requirements

- Linux x86_64 with hardware virtualization and accessible `/dev/kvm`
- Arch Linux for the automated host package workflow
- Python 3.10 or newer
- system libvirt, QEMU/qcow2, and OVMF
- OpenSSH, GnuPG, and the documented host tools
- a locally supplied and verified Arch cloud image with detached signature

See [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) for the authoritative package and tool
matrix and [docs/INSTALLATION.md](docs/INSTALLATION.md) for the installation
and initialization workflow.

## Development quickstart

```bash
git clone <REPOSITORY-URL> vm-dev-lab
cd vm-dev-lab
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
./vmctl --help
```

This workflow does not change host services or start a VM. Real libvirt access
also requires the optional Python binding:

```bash
python -m pip install -e '.[libvirt]'
```

## Inspect host readiness

`host-setup` separates passive checks, reproducible plans, and confirmed
changes. The following commands inspect or create local plan files; they do not
apply package or service changes:

```bash
host-setup packages check
host-setup packages plan --output package-plan.json
host-setup environment check
host-setup environment plan --output environment-plan.json
```

Package installation, service activation, network or pool creation, and
uninstall are real host changes. They require plan review, an explicit token,
and a deliberately root-started apply process. Because Host Setup is still
experimental and lacks fresh-host validation, do not treat these workflows as
generally production-ready. See [docs/HOST-SETUP.md](docs/HOST-SETUP.md).

## Initialize a project and VM

After host setup, import a reviewed local image and initialize the configuration
root:

```bash
vmctl image import \
  --image /path/to/Arch-Linux-x86_64-cloudimg.qcow2 \
  --signature /path/to/Arch-Linux-x86_64-cloudimg.qcow2.sig \
  --keyring /path/to/arch-image-signing.gpg

vmctl init --config-root ./config \
  --host-record /etc/vm-dev-lab/host-setup.json
vmctl config validate --root ./config arch-local
```

The repository-level `profiles/` directory is intentionally empty in public
releases. Operational profiles are host-specific files below the selected
private configuration root. The versioned `templates/` directory documents
portable bases and every supported configuration field.

Before creating a VM, add your public SSH key and reviewed resource settings to
the generated profile. A dry run validates the supported plan without changing
host or VM state:

```bash
vmctl --dry-run create --root ./config arch-local --name dev-01
```

A real Create operation may use only resources unambiguously assigned to this
lab. See [docs/VMCTL.md](docs/VMCTL.md) for lifecycle, baseline, restore,
guest-access, and cleanup commands.

## Security model

`vm-dev-lab` never treats a name as proof of ownership. Registry entries,
setup records, UUIDs, paths, file identities, and expected properties must
agree before mutation. Ambiguous or partial state results in an error or
`review_required`; it is not silently repaired. Unrelated domains, networks,
pools, volumes, and files remain untouched.

Local state, images, keys, VM disks, and setup plans do not belong in the
repository. The supplied `.gitignore` covers the intended local paths and
common secret formats, but it does not replace review before a commit.

## Documentation

- [Requirements](docs/REQUIREMENTS.md) – supported platform and dependency matrix
- [Installation](docs/INSTALLATION.md) – installation and initialization
- [vmctl reference](docs/VMCTL.md) – commands, contracts, and examples
- [Host Setup](docs/HOST-SETUP.md) – experimental check-plan-apply workflows
- [Architecture](docs/ARCHITECTURE.md) – components and trust boundaries
- [Contributing](CONTRIBUTING.md) – development and review workflow
- [Changelog](CHANGELOG.md) – public release changes

## Development checks

`pyproject.toml` is the authoritative Python dependency declaration. The test
suite uses offline mocks and isolated fixtures; real host or VM tests require a
separate, explicit authorization.

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
bash -n scripts/check-host.sh scripts/vm-host.sh
git diff --check
```

## License & Third-Party Components

The project code is licensed under the [MIT License](LICENSE). Third-party
components remain subject to their own licenses; the MIT license does not
replace or extend those terms.

Direct Python dependencies are installed separately and are not copied into
the `vm-dev-lab` wheel:

| Component | License | Purpose |
| --- | --- | --- |
| PyYAML | MIT | Parse YAML profiles and templates |
| Jinja2 | BSD-3-Clause | Render cloud-init templates |
| jsonschema | MIT | Validate configuration and result schemas |
| libvirt-python (optional `libvirt` extra) | LGPL-2.0-or-later | Access the libvirt API |

The host supplies external tools through its operating-system packages:

| Component | Package license summary | Purpose |
| --- | --- | --- |
| QEMU and qemu-img | QEMU emulator: GPL-2.0-only; components and firmware use additional compatible licenses | VM execution and qcow2 operations |
| libvirt | LGPL-2.1-or-later; the packaged distribution also contains GPL-3.0-or-later components | VM, network, and storage lifecycle |
| OpenSSH | BSD-style, ISC, MIT, 0BSD, and public-domain components | SSH, SFTP, and key tools |
| GnuPG | GPL, LGPL, and permissively licensed components | Image-signature verification |
| edk2-ovmf | Apache-2.0, BSD-2-Clause-Patent, and MIT components | UEFI firmware |
| dnsmasq, iptables-nft, cloud-image-utils | GPL-2.0-or-later, GPL-2.0-only, and GPL-3.0-only respectively | NAT services, packet-filter backend, and NoCloud media |
| ACL and iproute2 | acl: LGPL-2.1-or-later AND GPL-2.0-or-later; iproute2: GPL-2.0-or-later | Access control and network inspection |
| Git and curl | GPL-2.0-only and the curl license respectively | Source-state evidence and manual artifact retrieval |
| Python and pip | PSF-2.0 and MIT respectively | Runtime, virtual environments, and dependency installation |

This overview covers direct requirements; it does not replace the notices
shipped by each Python distribution or operating-system package. No third-party
source code or external binaries are bundled in the project wheel.
