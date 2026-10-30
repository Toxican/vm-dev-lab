# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Generate mutation-free Create plans from validated configuration.

"""Create plan from P01 configuration; reads neither host nor registry or images."""


def create_plan(result, name, no_start):
    vm = result.config['vm']
    steps = [
        ('validate', 'completed', 'Resolve and validate configuration'),
        ('preflight', 'unverified', 'Verify image trust, host, network, storage, and authorization'),
        ('ownership', 'unverified', 'Verify instance name, ownership, and resource budget'),
        ('allocate', 'planned', 'Create owned working disk, NVRAM, and instance identity'),
        ('seed', 'planned', 'Prepare an instance-specific NoCloud seed and SSH access'),
        ('define', 'planned', 'Define an owned libvirt domain without autostart'),
    ]
    if not no_start:
        steps.extend([
            ('boot', 'planned', 'Start the domain and collect serial diagnostics'),
            ('bootstrap', 'unverified', 'Confirm SSH host identity through a bound channel'),
            ('ssh-readiness', 'planned', 'Verify an authenticated SSH connection'),
            ('provisioning', 'planned', 'Verify cloud-init, Arch packages, versions, user, and SSH configuration'),
            ('project-readiness', 'planned', 'Publish project-ready only after all guest checks'),
        ])
    return {
        'kind': 'create', 'dry_run': True, 'can_execute': False,
        'target': {'name': name, 'uuid': None},
        'requested': {'cpus': vm['cpus'], 'memory_mib': vm['memory_mib'],
                      'disk_gib': vm['disk_gib'], 'network': vm['network'],
                      'image': vm['base_image'], 'packages': vm['packages'], 'no_start': no_start},
        'steps': [dict(phase=phase, status=status, description=description)
                  for phase, status, description in steps],
        'checks': {key: 'unverified' for key in
                   ('image_trust', 'host_capabilities', 'network_identity', 'storage_access',
                    'ownership', 'resource_budget', 'ssh_bootstrap', 'cloud_init', 'project_readiness')},
        'blocked_by': result.incomplete,
        'notice': 'Offline plan only; no creation or operational readiness established.',
    }
