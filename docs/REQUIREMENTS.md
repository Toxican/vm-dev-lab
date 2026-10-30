# Requirements

This document is the authoritative dependency and platform matrix for
`vm-dev-lab 0.5.0`. For installation order and initialization commands, see
[INSTALLATION.md](INSTALLATION.md).

## Support status

- **VM Core:** tested with real VMs in the qualified development environment
- **Host Setup:** **Heavy Development / Experimental** and tested only offline
  with fixtures
- **Fresh-host installation:** not yet independently validated end to end

These results do not establish compatibility with arbitrary Linux hosts.

## Supported host platform

The automated host workflow currently supports exactly:

- Arch Linux x86_64
- systemd with modular system libvirt at `qemu:///system`
- QEMU/KVM with an accessible `/dev/kvm`
- qcow2 storage and OVMF UEFI firmware
- a private, conflict-free IPv4 `/24` for the dedicated NAT lab network

Other host distributions, session libvirt, and non-x86_64 hosts are not
qualified. The VM Core must not manage services, networks, or storage pools
that are not unambiguously owned by the lab.

## Arch Linux system packages

The `host-setup packages` catalog requires these packages:

| Package | Purpose |
| --- | --- |
| `qemu-desktop` | x86_64 system emulation |
| `qemu-img` | qcow2 validation, overlays, and offline image operations |
| `libvirt` | modular daemons, `virsh`, and host validation |
| `edk2-ovmf` | OVMF code and variable-store template |
| `dnsmasq` | DHCP and DNS for the dedicated libvirt NAT network |
| `iptables-nft` | nft-backed iptables interface required by libvirt |
| `acl` | `getfacl` and `setfacl` for bound storage access |
| `iproute2` | route, address, and link inventory through `ip` |
| `openssh` | SSH client, SFTP, and key tools |
| `cloud-image-utils` | `cloud-localds` for NoCloud seed media |
| `gnupg` | image signature and keyring verification |
| `git` | source-state and repository evidence |
| `python` | project runtime and virtual environments |
| `python-pip` | installation of declared Python dependencies |
| `curl` | manual retrieval of pinned release artifacts |

`iptables` conflicts with the required `iptables-nft` contract and requires an
explicit operator decision. The package assistant does not silently replace a
conflicting backend.

## Python requirements

Python 3.10 or newer is required. `pyproject.toml` is the authoritative package
metadata source.

Direct runtime dependencies:

- `PyYAML>=6.0`
- `Jinja2>=3.1`
- `jsonschema>=4.18`

Optional real-libvirt integration:

- `libvirt-python>=9.0` through the `libvirt` extra

The build backend requires `setuptools>=77` for SPDX license metadata. No
additional Python dependency is required merely to read the CLI help or run the
offline suite after the declared project dependencies have been installed.

## Development and verification tools

The standard offline checks use:

- Python `unittest` and `compileall`
- Bash for the host scripts
- ShellCheck for shell diagnostics
- Git for diff and tracked-file checks

Do not install missing tools automatically during a review. Report the missing
check instead. Real host, package, network, libvirt, or VM operations require
separate explicit authorization and are not part of ordinary offline tests.

## Local operator inputs

Real VM creation additionally needs:

- a reviewed Arch cloud image
- its detached signature
- an explicitly selected GnuPG keyring
- a public SSH key for the guest account
- a completed host setup record that binds the dedicated lab resources

Images, signatures, keyrings, private SSH keys, VM disks, host records, and
runtime state are local operator artifacts and must not be committed.

## Capacity and network planning

The operator must provide sufficient CPU, memory, and disk capacity for the
configured resource limits. Resource admission is enforced by the VM Core, but
it does not create host capacity.

The selected private `/24`, bridge name, network name, pool name, and storage
path must not conflict with LAN, VPN, container, or unrelated libvirt resources.
Names alone never prove ownership.
