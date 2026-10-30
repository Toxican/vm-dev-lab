# Architecture

## Goals and principles

`vm-dev-lab` provides reproducible Linux development VMs on a local KVM and
libvirt host. Its architecture prioritizes inspectable state, unambiguous
resource ownership, bounded multi-VM operation, and conservative failure
handling.

Core rules:

- libvirt is the only manager of real VM lifecycles.
- Configuration is validated before any mutation.
- Host Setup and the VM lifecycle are separate responsibilities.
- Names alone never establish ownership.
- Partial state is journaled and never silently reclassified as success.
- Real changes are explicit; passive checks do not repair state.

## Components

```text
Profiles and templates
        │
        ▼
  vmctl / validation ───── Image trust cache
        │
        ▼
 Lifecycle + registry + ResourceLedger
        │                 │
        │                 └── Journals, locks, manifests
        ▼
  libvirt qemu:///system
        │
        ▼
 Arch guest adapter ───── NoCloud + host-key-pinned SSH

 host-setup ───────────── Packages, sockets, owned network and pool
        (separate; never called implicitly by vmctl)
```

### CLI and configuration

`vmctl` is the public VM interface. YAML profiles and templates are validated
against bundled JSON schemas. Paths remain inside the selected configuration
root; symlink escapes, traversal, URLs, variable paths, and secret locations
are rejected. The generic model covers resources, images, networking, storage,
firmware, and guest adapters without product-specific logic.

### Image trust

Image import consumes local artifacts only. The base image, detached signature,
and explicit GnuPG keyring are verified together. The cache is
content-addressed and immutable; profiles bind a concrete digest rather than a
moving download name.

### Registry, journals, and locks

The local registry binds instance ID, domain UUID, resources, and private
files. Instance and global locks prevent conflicting operations. Mutating
workflows record planned and reached state in an operation journal. An
interruption can therefore be classified conservatively; unknown divergence
remains `review_required`.

### Resource accounting

`ResourceLedger` reserves vCPU, memory, and storage before a new instance is
published. Reservation and registry publication are atomically coupled. For a
new Create, the vCPU budget is the smaller of the persisted host limit and
twice the CPUs available to the process. This Create-time policy does not
retroactively change existing instances.

### libvirt lifecycle

Domain XML, qcow2 overlay, NVRAM, NoCloud seed, and logs are bound per instance.
Create, Start, Stop, Restart, and Destroy recheck registry, domain identity,
and files before mutation. There is no parallel direct QEMU process manager and
no general QMP control path.

The VM Core through the current guest command and file-transfer scope was
tested with real VMs in the qualified development environment. That evidence
does not qualify arbitrary hosts or the separate Host Setup assistant.

### Guest adapter and SSH

The first adapter supports Arch Linux. NoCloud supplies user, network, and SSH
configuration. The expected guest host key is bound before the first network
connection. Provisioning and later `ssh`, `exec`, and `copy` operations use only
that authenticated channel. Password authentication is not part of the
intended path.

### Baselines and restore

An immutable baseline contains qcow2 disk, NVRAM, domain configuration, and a
manifest. Their identities and hashes are verified together. Restore first
creates a private generation and activates it only after complete revalidation.
The full qcow2 backing chain and required file access are checked before every
start.

### Host Setup

`host-setup` has a separate check-plan-apply contract. It inspects and plans
Arch packages, libvirt sockets, the QEMU service identity, OVMF, and a dedicated
NAT network and directory pool. Administrative actions run only in a root
process deliberately started by the operator. A setup record binds created
resources for later VM and uninstall checks.

Host Setup is **Heavy Development / Experimental**. Its implemented workflows
are covered by offline fixtures, but no complete fresh-host real-world
acceptance has been completed.

## Trust and ownership boundaries

The project distinguishes:

- public repository code and documentation
- local operator configuration and public SSH keys
- private runtime state, journals, and manifests
- trust-verified immutable base images and baselines
- real libvirt resources owned by the lab
- unrelated resources on the same host

A resource is considered owned only when its stored identities, UUIDs, paths,
file identities, references, and expected properties agree. Unrelated or
ambiguous domains, networks, pools, volumes, and files are not adopted,
repaired, or cleaned up.

The NAT network supports trusted development workloads. It is not a security
boundary against malicious guests. Firewall, VPN, router, and container policy
remain the operator's responsibility.

## Failure and recovery model

Public errors contain an exit code, stable code, phase, message, hint, and retry
property. A retry is permitted only when persisted state makes it unambiguous.
Recovery requires the bound operation ID and rechecks the complete contract.
Contradictions block further mutation until the operator evaluates them outside
automatic paths.

## Local data

Configuration, state, cache, and runtime data are separated according to XDG
conventions. Missing `XDG_RUNTIME_DIR` does not create an unsafe lock fallback
under `/tmp`. Private directories and files require restrictive permissions;
unexpected permissions are not repaired incidentally.

VM disks, images, seeds, keys, setup plans, host records, logs, and local test
artifacts are not versioned. `.gitignore` guards common mistakes but does not
replace secret and diff review.

## Deliberate limitations

Version 0.5.0 does not support a GUI, USB assignment, audio integration, a
general ISO installer, or multiple lifecycle backends. Additional host
distributions and guest adapters each require an explicit support and test
contract. A successful offline clone or package build is not evidence of a
complete real fresh-host installation.
