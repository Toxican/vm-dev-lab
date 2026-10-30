# Host Setup

> **Status: Heavy Development / Experimental.** The implemented package,
> environment, resource, and uninstall workflows are covered by offline fixture
> tests. They have not yet passed an independent end-to-end acceptance run on a
> fresh Arch Linux host.

The installed `host-setup` command prepares supported prerequisites on an Arch
Linux host. It separates passive inventory, an immutable plan, and a confirmed
apply. `vmctl` never invokes this assistant automatically.

## Privilege model

The assistant never elevates privileges internally. Passive checks and plans
run without root where possible. The operator deliberately starts an entire
administrative action as root:

```bash
sudo host-setup <AREA> <ACTION> ...
```

There is no sudoers exception and no embedded `sudo`, `su`, or `pkexec` call.
Root, the lab operator, and the QEMU service account are separate identities.
`SUDO_USER` and filenames are not proof of ownership.

<a id="paket-check-plan-und-installation"></a>
## Package check, plan, and installation

```bash
host-setup packages check
host-setup packages plan --output package-plan.json
```

`check` inspects the distribution, architecture, and package state. `plan`
creates a JSON document containing missing packages, the complete intended
command, and a confirmation token. Review both the file and token before apply:

```bash
sudo host-setup packages apply \
  --plan /absolute/path/package-plan.json \
  --confirm <TOKEN>
```

Apply revalidates plan structure, host binding, age, ownership, and token. On
the exactly supported Arch target, it runs one confirmed
`pacman -Syu --needed` transaction. This is a real system-wide update. A
failure is not reported as success and no alternate package source is tried.

<a id="hostumgebung-check-und-plan"></a>
## Environment check and plan

```bash
host-setup environment check
host-setup environment plan --output environment-plan.json
```

The check inventories KVM, modular libvirt sockets, the QEMU service identity,
OVMF, and required tools. A plan may contain required socket activation for the
selected operating mode:

```bash
host-setup environment plan \
  --mode manual \
  --output environment-plan.json

sudo host-setup environment apply \
  --plan /absolute/path/environment-plan.json \
  --confirm <TOKEN>
```

`manual` starts required sockets for the current runtime without enabling them
at boot. `permanent` is a separate, deliberate operating choice that may change
systemd enablement. Apply touches only plan-bound units and verifies their state
again afterward.

<a id="libvirt-dienste"></a>
## libvirt services

The supported model uses modular system libvirt daemons. The assistant detects
actual unit names instead of assuming fixed names. `scripts/vm-host.sh
start|stop` remains a separate manual administrator tool; neither `vmctl` nor
tests invoke it.

An inactive socket, missing access, or ambiguous daemon state produces a
documented failure. The assistant does not weaken a security policy to obtain
socket access.

<a id="labressourcen-planen-und-anlegen"></a>
## Plan and create lab resources

With `--resources`, the assistant plans a dedicated NAT network, bridge, and
directory storage pool. Adapt every example value to the real host:

```bash
sudo host-setup environment plan \
  --resources \
  --owner <LAB-OPERATOR> \
  --qemu-user <QEMU-SERVICE-USER> \
  --network vm-dev-lab-nat \
  --pool vm-dev-lab \
  --bridge virbr-vdl \
  --subnet 192.168.124.0/24 \
  --storage /var/lib/libvirt/vm-dev-lab \
  --min-free-gib 20 \
  --reserve-gib 8 \
  --firmware-code /usr/share/edk2/x64/OVMF_CODE.fd \
  --firmware-vars /usr/share/edk2/x64/OVMF_VARS.fd \
  --output /root/vm-dev-lab-resource-plan.json
```

Before apply, review subnet conflicts with LAN, VPN, containers, and other
libvirt networks. Also verify the storage path, free space, account identities,
and firmware paths.

```bash
sudo host-setup environment apply \
  --plan /root/vm-dev-lab-resource-plan.json \
  --confirm <TOKEN>
```

Apply creates only the bound project-owned resources and a root-owned setup
record. It never adopts, overwrites, or cleans existing unrelated resources.
`--activate` is optional; autostart is not enabled implicitly.

<a id="hostressourcen-sicher-entfernen"></a>
## Safely remove host resources

Uninstall also requires fresh evidence and a three-step workflow:

```bash
sudo host-setup environment uninstall-check
sudo host-setup environment uninstall-plan \
  --output /root/vm-dev-lab-uninstall-plan.json
sudo host-setup environment uninstall \
  --plan /root/vm-dev-lab-uninstall-plan.json \
  --confirm <TOKEN>
```

The assistant removes the network, pool definition, storage directory, and
setup record only when their identities and complete ownership contract match
the completed setup. Running or registered lab VMs, unknown files, unrelated
volumes, active pool use, replaced paths, or drift block uninstall. There is no
force flag and no name-only ownership heuristic.

System packages and general libvirt services are not uninstalled. Baselines and
private state outside the bound storage target are not removed incidentally.

## Reports and automation

All actions support `--json`; `--output` writes the complete report or plan to a
new file. Existing output files are not silently overwritten. A plan is bound
to a host, observed state, and time. Create a new check and plan after changes.

Exit codes follow the same broad classes as `vmctl`: 0 success, 2 invalid
input, 3 missing prerequisite, 4 conflict, 5 policy rejection, and 6 failed
operation. The stable error code and report content remain authoritative.

Ambiguous, partial, or failed state requires operator review. The assistant
does not automatically retry, repair, broaden permissions, or remove resources
after a failure.

## Known limitations in 0.5.0

- Package automation supports only Arch Linux x86_64.
- No fresh-host real-world acceptance has been completed.
- Firewall and router configuration are outside the current assistant.
- The NAT network is a trusted development network, not a sandbox.
- Unrelated resources are never adopted or automatically repaired.
- Administrative workflows must not be presented as generally production-ready.
