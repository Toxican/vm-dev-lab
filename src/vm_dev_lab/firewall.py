# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Plan and execute fail-closed native nftables transactions.

"""Offline firewall planning and fail-closed native nftables transactions.

No VM lifecycle imports. Manager-specific adapters must use manager APIs; an
accept in one base chain is never treated as bypassing another chain.
"""
from copy import deepcopy
import hashlib
import ipaddress
import json
import re
import uuid


class FirewallError(ValueError):
    pass


def require(value, message):
    if not value:
        raise FirewallError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def stable(value):
    """Counters change without a policy change; handles intentionally remain."""
    if isinstance(value, list):
        return [stable(v) for v in value]
    if isinstance(value, dict):
        return {k: (None if k == 'counter' else stable(v)) for k, v in value.items()}
    return value


def inventory(snapshot):
    require(isinstance(snapshot, dict) and set(snapshot) == ({'schema_version', 'host_id', 'nft', 'legacy', 'managers', 'routing'} if snapshot.get('schema_version') == 2 else {'schema_version', 'host_id', 'nft', 'legacy', 'managers'}), 'Incomplete firewall inventory.')
    require(type(snapshot['schema_version']) is int and snapshot['schema_version'] in (1, 2) and re.fullmatch('[0-9a-f]{64}', snapshot['host_id']), 'Unknown inventory or host.')
    require(set(snapshot['legacy']) == {'ipv4', 'ipv6'} and all(v in ('absent', 'empty') for v in snapshot['legacy'].values()), 'Legacy iptables is active or unverified.')
    require(set(snapshot['managers']) == {'ufw', 'firewalld'} and all(v == 'inactive' for v in snapshot['managers'].values()), 'UFW or firewalld is active or unknown: a qualified manager adapter is missing.')
    data = snapshot['nft']
    require(isinstance(data, dict) and set(data) == {'nftables'} and isinstance(data['nftables'], list), 'No complete nft JSON.')
    for row in data['nftables']:
        require(isinstance(row, dict) and len(row) == 1 and next(iter(row)) in ('metainfo', 'table', 'chain', 'rule'), 'Sets, maps, flowtables, or unknown nft objects require manual qualification.')
        text = json.dumps(row).lower()
        require(not any(name in text for name in ('ufw-', 'ufw_', 'firewalld')), 'Manager rules exist despite an inactive or mismatched manager; do not modify them directly.')
    return data['nftables']


def standard_topology(setup, policy, snapshot, allow_missing_bridge=False):
    require(isinstance(policy, dict) and set(policy) == {'mode', 'lan_access', 'lan_interface'}, 'Firewall policy v2 requires mode, lan_access, and lan_interface; do not reinterpret the old service policy.')
    require(policy['mode'] == 'trusted-dev' and policy['lan_access'] in ('deny', 'allow', 'in', 'out'), 'trusted-dev with lan_access deny, allow, in, or out is required.')
    adapter = policy['lan_interface']; bridge = setup['bridge']
    require(isinstance(adapter, str) and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', adapter) and adapter != bridge, 'An explicit distinct LAN adapter is required.')
    require(snapshot.get('schema_version') == 2 and set(snapshot.get('routing', {})) == {'ipv4', 'links'}, 'A fresh v2 inventory with IPv4 routes and link data is required.')
    routes, links = snapshot['routing']['ipv4'], snapshot['routing']['links']
    require(isinstance(routes, list) and isinstance(links, list), 'Incomplete standard topology.')
    by_name = {l['ifname']: l for l in links}
    require((bridge not in by_name and allow_missing_bridge) or
            (bridge in by_name and by_name[bridge].get('linkinfo', {}).get('info_kind') == 'bridge'),
            'Dedicated virtual bridge was not confirmed.')
    require(adapter in by_name and not by_name[adapter].get('linkinfo') and by_name[adapter].get('link_type') != 'loopback', 'Standard LAN adapter is missing or virtual; configure the special topology manually.')
    for link in links:
        if bridge in by_name and link.get('master') in (bridge, by_name[bridge].get('ifindex')):
            info = link.get('linkinfo', {})
            require(info.get('info_kind') == 'tun' and info.get('info_data', {}).get('type') == 'tap', 'Physisches/unbekanntes Laborbridge-Mitglied.')
    selected = [r for r in routes if r.get('dev') == adapter]
    defaults = [r for r in selected if r.get('dst') in ('default', '0.0.0.0/0') and r.get('type', 'unicast') == 'unicast']
    require(len(defaults) == 1 and defaults[0].get('gateway') and 'nexthops' not in defaults[0], 'A simple default gateway through the LAN adapter is required; configure special routing manually.')
    networks = {ipaddress.IPv4Network(r['dst']) for r in selected if r.get('dst') not in (None, 'default', '0.0.0.0/0') and r.get('scope') == 'link' and not r.get('gateway') and r.get('type', 'unicast') == 'unicast'}
    require(len(networks) == 1, 'Exactly one directly connected IPv4 LAN is required on the selected adapter; configure special topology manually.')
    lan = networks.pop()
    require(not lan.is_multicast and not lan.is_loopback and not lan.is_link_local and lan.prefixlen > 0 and not lan.overlaps(ipaddress.ip_network(setup['subnet'])), 'LAN and lab must be separate suitable networks.')
    require(ipaddress.IPv4Address(defaults[0]['gateway']) in lan, 'Gateway is not in the directly connected LAN.')
    require(type(by_name[adapter].get('ifindex')) is int and by_name[adapter]['ifindex'] > 0 and
            (bridge not in by_name or type(by_name[bridge].get('ifindex')) is int and by_name[bridge]['ifindex'] > 0), 'Interface identity is missing.')
    return {'lan': str(lan), 'gateway': defaults[0]['gateway'],
            'interfaces': {bridge: by_name[bridge]['ifindex'] if bridge in by_name else None,
                           adapter: by_name[adapter]['ifindex']}}


def state_digest(snapshot, segment=None, policy=None):
    """Bind only the configured standard LAN, not unrelated routes or TAP churn."""
    value = deepcopy(snapshot)
    if segment is not None:
        value['routing'] = standard_topology(segment, policy, snapshot)
    return digest(stable(value))


def flows(setup, policy, snapshot, allow_missing_bridge=False):
    topology = standard_topology(setup, policy, snapshot, allow_missing_bridge)
    bridge = setup['bridge']; net = ipaddress.ip_network(setup['subnet'])
    require(net.version == 4 and net.prefixlen == 24 and net.is_private, 'A dedicated private IPv4 /24 is required.')
    require(re.fullmatch('[a-z][a-z0-9-]{0,14}', bridge) and setup['network'] != 'default', 'A dedicated bridge and network are required.')
    def address(value):
        if isinstance(value, dict) and set(value) == {'set'}:
            return {'set': [address(v) for v in value['set']]}
        if isinstance(value, str) and '/' in value:
            prefix = ipaddress.ip_network(value)
            return {'prefix': {'addr': str(prefix.network_address), 'len': prefix.prefixlen}}
        return value
    def match(left, right, op='=='):
        return {'match': {'op': op, 'left': left, 'right': address(right)}}
    def interface(key, value): return match({'meta': {'key': key}}, value)
    def ip(field, value): return match({'payload': {'protocol': 'ip', 'field': field}}, value)
    v4 = match({'meta': {'key': 'nfproto'}}, 'ipv4')
    inside = interface('iifname', bridge); outside = interface('oifname', bridge)
    result = []
    def rule(name, hook, expr, verdict='accept', version=None):
        result.append({'name': name, 'hook': hook, 'ip_version': version, 'expr': expr + [{verdict: None}]})
    # No transport/port/address restrictions on the trusted virtual segment.
    rule('host-input', 'input', [inside])
    rule('host-output', 'output', [outside])
    rule('lab-cross', 'forward', [inside, outside])
    # LAN direction is relative to the VM; reply traffic is never a new grant.
    adapter = policy['lan_interface']; lan = topology['lan']
    to_lan = [v4, inside, interface('oifname', adapter), ip('saddr', str(net)), ip('daddr', lan)]
    from_lan = [v4, interface('iifname', adapter), outside, ip('saddr', lan), ip('daddr', str(net))]
    reply = match({'ct': {'key': 'state'}}, {'set': ['established', 'related']}, 'in')
    if policy['lan_access'] in ('allow', 'out'):
        rule('lan-out', 'forward', to_lan, version=4)
    if policy['lan_access'] in ('allow', 'in'):
        rule('lan-in', 'forward', from_lan, version=4)
    if policy['lan_access'] == 'in':
        rule('lan-in-reply', 'forward', to_lan + [reply], version=4)
    rule('lan-deny', 'forward', [v4, inside, ip('daddr', lan)], 'drop', 4)
    rule('internet', 'forward', [v4, inside, interface('oifname', adapter), ip('saddr', str(net))], version=4)
    rule('internet-reply', 'forward', [v4, interface('iifname', adapter), outside, ip('daddr', str(net)), reply], version=4)
    # Other adapter paths and unsolicited ingress remain outside the grant.
    rule('lab-egress-guard', 'forward', [inside], 'drop')
    rule('lab-ingress-guard', 'forward', [outside], 'drop')
    return result



def build_plan(setup, policy, snapshot):
    if 'ufw' in snapshot:
        from . import ufw
        return ufw.build_plan(setup, policy, snapshot)
    rows = inventory(snapshot)
    require(setup['host_id'] == snapshot['host_id'], 'Firewall inventory belongs to a different host.')
    owner = str(uuid.UUID(setup['setup_id']))
    require(owner == setup['setup_id'], 'Invalid setup identity.')
    desired = flows(setup, policy, snapshot)
    chains = [r['chain'] for r in rows if 'chain' in r]
    rules = [r['rule'] for r in rows if 'rule' in r]
    prefix = 'vm-dev-lab:' + owner + ':'
    require(not any(r.get('comment', '').startswith(prefix) and ':anchor:' not in r.get('comment', '') for r in rules), 'Owned rules already exist; use status or apply with the original record.')
    commands = []
    # Every filtering base chain, including chains with policy accept, can drop.
    # Only direct, first-rule, operator-delegated anchors are supported initially.
    for chain in chains:
        if 'hook' not in chain: continue
        family, table, name = (chain[k] for k in ('family', 'table', 'name'))
        require(family in ('ip', 'ip6', 'inet'), 'bridge, netdev, or arp hooks are not qualified.')
        crules = [r for r in rules if (r['family'], r['table'], r['chain']) == (family, table, name)]
        if chain.get('type') == 'nat':
            require(all(set(e) <= {'match', 'counter', 'masquerade', 'snat', 'dnat', 'accept', 'return'} for r in crules for e in r.get('expr', [])) and chain.get('policy', 'accept') == 'accept', 'Unknown NAT control flow; do not change libvirt rules.')
            continue
        require(chain.get('type') == 'filter' and chain['hook'] in ('input', 'output', 'forward'), 'Unknown filter hook.')
        if chain['hook'] not in {f['hook'] for f in desired}: continue
        marker = prefix + 'anchor:' + chain['hook']
        require(crules and crules[0].get('comment') == marker and stable(crules[0].get('expr')) == [{'counter': None}], 'First explicitly delegated counter anchor is missing: '+table+'/'+name)
        require(type(crules[0].get('handle')) is int, 'Anchor handle is missing.')
        for flow in desired:
            if flow['hook'] != chain['hook'] or (flow['ip_version'] == 4 and family == 'ip6'): continue
            item = {'family': family, 'table': table, 'chain': name, 'handle': crules[0]['handle'], 'expr': flow['expr'], 'comment': prefix + flow['name']}
            commands.append({'insert': {'rule': item}})
    provided = {c['insert']['rule']['comment'][len(prefix):] for c in commands}
    require({f['name'] for f in desired} <= provided, 'Not all trusted-dev traffic paths have a delegated hook.')
    segment = {k: setup[k] for k in ('bridge', 'subnet', 'network')}
    plan = {'schema_version': 2, 'backend': 'nft-delegated-v2', 'host_id': setup['host_id'], 'setup_id': owner, 'network_uuid': setup['network_uuid'], 'setup_sha256': setup['sha256'], 'policy': deepcopy(policy), 'segment': segment, 'baseline': state_digest(snapshot, segment, policy), 'commands': commands, 'persistence': 'runtime-only; reload/reboot requires status and a newly reviewed plan', 'network_ready': False}
    plan['sha256'] = digest(plan)
    return plan


def owned_state(plan, record, snapshot):
    require(record and record.get('plan') == plan, 'Owned root record or plan is missing or differs.')
    rows = inventory(snapshot)
    prefix = 'vm-dev-lab:' + plan['setup_id'] + ':'
    expected = [dict(c['insert']['rule']) for c in plan['commands']]
    actual = [r['rule'] for r in rows if 'rule' in r and r['rule'].get('comment', '').startswith(prefix) and ':anchor:' not in r['rule'].get('comment', '')]
    require(len(actual) == len(expected), 'Owned rules are missing or duplicated; reload or partial state, no repair.')
    remaining = list(actual)
    for item in expected:
        item.pop('handle')
        matches = [r for r in remaining if {k: v for k, v in r.items() if k not in ('handle',)} == item]
        require(len(matches) == 1 and type(matches[0].get('handle')) is int, 'Owned rule was changed; do not delete it.')
        rule = matches[0]
        chain_rows = [r['rule'] for r in rows if 'rule' in r and all(r['rule'].get(k) == rule[k] for k in ('family', 'table', 'chain'))]
        anchor = next((r for r in chain_rows if r.get('comment', '').startswith(prefix+'anchor:')), None)
        require(anchor is not None and chain_rows.index(rule) < chain_rows.index(anchor), 'Owned rule was moved behind the delegation point.')
        remaining.remove(rule)
    foreign = deepcopy(snapshot)
    foreign['nft']['nftables'] = [r for r in rows if not ('rule' in r and r['rule'] in actual)]
    require(state_digest(foreign, plan.get('segment'), plan.get('policy')) == plan['baseline'], 'Foreign policy, anchors, or handles changed; review is required.')
    return actual


def apply(plan, setup, system, confirmation):
    if plan.get('backend') == 'ufw-framework-v1':
        from . import ufw
        return ufw.apply(plan, setup, system, confirmation)
    require(plan.get('schema_version') == 2 and plan.get('backend') == 'nft-delegated-v2', 'Do not apply an old firewall plan; review a new trusted-dev plan. Do not migrate old records; clean up only with matching original evidence.')
    require(confirmation == plan.get('sha256'), 'Confirm the specific firewall plan.')
    require(all(plan.get(k) == setup.get(k) for k in ('host_id', 'setup_id', 'network_uuid')) and plan.get('setup_sha256') == setup.get('sha256'), 'Host-setup binding changed.')
    require(plan['sha256'] == digest({k: v for k, v in plan.items() if k != 'sha256'}), 'Plan manipuliert.')
    with system.firewall_lock():
        record = system.firewall_record()
        snapshot = system.firewall_snapshot()
        if record and record.get('status') == 'removed':
            require(record['plan']['setup_id'] == setup['setup_id'], 'Different owner in the remote record.')
            record = None  # New explicit confirmed apply; full baseline/preflight below.
        if record:
            require(record.get('status') == 'complete', 'Firewall journal is incomplete; targeted review or rollback is required.')
            owned_state(plan, record, snapshot)
            return 'unchanged'
        require(build_plan(setup, plan['policy'], snapshot) == plan, 'Plan is stale or not bound to the owned host setup.')
        journal = {'status': 'pending', 'plan': plan}
        system.firewall_save(journal)
        try:
            system.firewall_batch(plan['commands'])  # One atomic nft transaction.
            owned_state(plan, journal, system.firewall_snapshot())
            journal['status'] = 'complete'; system.firewall_save(journal)
        except BaseException:
            journal['status'] = 'review_required'; system.firewall_save(journal)
            raise
    return 'applied-runtime-only'


def uninstall(plan, system, confirmation):
    if plan.get('backend') == 'ufw-framework-v1':
        from . import ufw
        return ufw.uninstall(plan, system, confirmation)
    require(confirmation == plan.get('sha256'), 'Confirm rollback or uninstall separately.')
    with system.firewall_lock():
        record = system.firewall_record()
        require(record and record.get('plan') == plan, 'No matching owned root record.')
        snapshot = system.firewall_snapshot()
        if state_digest(snapshot, plan.get('segment'), plan.get('policy')) == plan['baseline']:
            system.firewall_save({'status': 'removed', 'plan': plan})
            return 'unchanged'
        if record.get('status') == 'removed':
            require(state_digest(snapshot, plan.get('segment'), plan.get('policy')) == plan['baseline'], 'State changed after removal.')
            return 'unchanged'
        actual = owned_state(plan, record, snapshot)
        system.firewall_save({'status': 'removing', 'plan': plan})
        commands = [{'delete': {'rule': {k: r[k] for k in ('family', 'table', 'chain', 'handle')}}} for r in actual]
        system.firewall_batch(commands)
        require(state_digest(system.firewall_snapshot(), plan.get('segment'), plan.get('policy')) == plan['baseline'], 'Rollback was not fully confirmed; retain the record.')
        system.firewall_save({'status': 'removed', 'plan': plan})
    return 'removed-owned-rules-only'


def collect(run, read):
    """Read-only inventory. A missing/denied observation is never an empty firewall."""
    snapshot = {'schema_version': 2, 'host_id': hashlib.sha256(read('/etc/machine-id').encode()).hexdigest(),
                'nft': json.loads(run(['nft', '-j', 'list', 'ruleset'])), 'legacy': {}, 'managers': {}}
    snapshot['routing'] = {'ipv4': json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])),
                           'links': json.loads(run(['ip', '-j', '-d', 'link', 'show']))}
    for family, path in (('ipv4', '/proc/net/ip_tables_names'), ('ipv6', '/proc/net/ip6_tables_names')):
        try: names = read(path).strip()
        except FileNotFoundError: names = ''  # Legacy subsystem not registered in this netns.
        snapshot['legacy'][family] = 'active' if names else 'empty'
    # Query state, never start a service or D-Bus manager.
    for name, unit in (('ufw', 'ufw.service'), ('firewalld', 'firewalld.service')):
        state = run(['systemctl', 'show', '--property=ActiveState', '--value', unit]).strip()
        snapshot['managers'][name] = state if state in ('active', 'inactive') else 'unknown'
    return snapshot


def assessment(snapshot):
    details = {'status': 'UNVERIFIED', 'network_ready': False,
               'managers': snapshot.get('managers', {}), 'legacy': snapshot.get('legacy', {}),
               'ruleset_sha256': digest(stable(snapshot))}
    rows = snapshot.get('nft', {}).get('nftables', [])
    details['base_chains'] = [r['chain'] for r in rows if isinstance(r, dict) and isinstance(r.get('chain'), dict) and 'hook' in r['chain']]
    try:
        inventory(snapshot)
    except (FirewallError, ValueError, KeyError, TypeError) as error:
        details['message'] = str(error)
        return details
    details['message'] = 'Native nft view is complete; verify delegated anchors and owned rules against the setup record. No end-to-end trusted-dev network qualification.'
    return details
