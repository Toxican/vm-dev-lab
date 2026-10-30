# Installation

This guide covers installation of `vm-dev-lab 0.5.0` on its first supported
target: an Arch Linux x86_64 host with KVM and modular system libvirt. Other
host distributions are not automated or qualified.

Host Setup is **Heavy Development / Experimental**. Its current workflows are
implemented and tested offline with fixtures, but a complete fresh-host run has
not yet been independently validated on a clean Arch Linux system.

<a id="hostvoraussetzungen"></a>
## Host prerequisites

Before installation, verify the following conditions:

- x86_64 Linux with systemd
- hardware virtualization enabled and `/dev/kvm` accessible
- system libvirt available at `qemu:///system`
- QEMU with qcow2 support and OVMF firmware
- enough local storage for base images, overlays, and baselines
- a dedicated, conflict-free private IPv4 `/24` for the lab network
- Python 3.10 or newer

[REQUIREMENTS.md](REQUIREMENTS.md) is the authoritative package and tool
matrix. `host-setup packages check` passively checks the distribution,
architecture, and package state. It installs nothing. `vmctl check-host` checks
VM runtime prerequisites; `--live` additionally reads configured
infrastructure without changing it.

<a id="systempakete"></a>
## System packages

The Arch package catalog includes QEMU, libvirt, OVMF, networking, image,
signature, SSH, and Python tools. See the complete table in
[REQUIREMENTS.md](REQUIREMENTS.md#arch-linux-system-packages).

System packages are intentionally not installed by Python package setup.
`host-setup packages apply` consumes an unchanged, previously generated plan
and runs a confirmed `pacman -Syu --needed` transaction. This can update the
entire host. Review the experimental workflow in
[Host Setup](HOST-SETUP.md#package-check-plan-and-installation) before use.

<a id="entwicklungsumgebung"></a>
## Python environment

Clone the repository and create an isolated Python environment:

```bash
git clone <REPOSITORY-URL> vm-dev-lab
cd vm-dev-lab
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

PyYAML, Jinja2, and jsonschema are sufficient for offline development. Real
libvirt access also requires the optional binding:

```bash
python -m pip install -e '.[libvirt]'
```

`pyproject.toml` is the only authoritative Python dependency declaration. A
`pip` installation changes the selected Python environment; it does not start
services, create networks, or operate VMs.

Initial verification:

```bash
vmctl --version
vmctl --help
host-setup --help
python -m unittest discover -s tests -v
```

<a id="host-einrichten"></a>
## Configure the host

Host configuration is separate from the VM lifecycle. First inspect packages
and the environment, then create plans:

```bash
host-setup packages check
host-setup packages plan --output package-plan.json
host-setup environment check
host-setup environment plan --output environment-plan.json
```

These commands do not apply the planned administrative changes. Apply commands,
confirmation tokens, resource parameters, root requirements, and safe uninstall
are documented in [HOST-SETUP.md](HOST-SETUP.md). `vmctl` never starts or stops
host services and never creates host networks or storage pools.

Because Host Setup has not passed a fresh-host real-world acceptance run, treat
every administrative plan as experimental and review it against the actual
host before applying it.

## Trust-verified base image

`vmctl` does not download images. Supply a versioned Arch cloud image, its
detached signature, and a deliberately selected GnuPG keyring locally. Review
the source, release, and signing key before import.

```bash
vmctl image import \
  --cache-root ./local/image-cache \
  --image /path/to/Arch-Linux-x86_64-cloudimg.qcow2 \
  --signature /path/to/Arch-Linux-x86_64-cloudimg.qcow2.sig \
  --keyring /path/to/arch-image-signing.gpg
```

The import verifies the supplied artifacts and creates a content-addressed
local cache. Images, signatures, and keyrings are operator artifacts and must
not be committed.

## Initialize configuration

After host setup, `init` creates the configuration root and binds the host setup
record:

```bash
vmctl init \
  --config-root ./config \
  --host-record /etc/vm-dev-lab/host-setup.json
```

Edit the generated profile under `config/profiles/`. At minimum, its public SSH
key, image reference, network, pool, and resource limits must match the host.
Private keys belong neither in the profile nor in the repository.

```bash
vmctl config validate --root ./config arch-local
vmctl --dry-run create --root ./config arch-local --name dev-01
```

Only after both checks produce the expected result should a real Create be
considered:

```bash
vmctl create --root ./config arch-local --name dev-01
```

This command changes real VM state. Use only resources that the host setup
record unambiguously assigns to the lab.

## Upgrade and uninstall

Version 0.5.0 does not provide a stable cross-release upgrade contract. Back up
local profiles and state before an upgrade without adding VM disks or keys to
Git. Review the changelog and repeat validation afterward.

Remove VMs individually with `vmctl destroy`; published baselines may
intentionally remain. Remove host resources only through a fresh Host Setup
uninstall check and plan. Deleting the Python package or repository does not
remove libvirt resources.
