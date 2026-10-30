# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Implement the bounded UFW adapter for the trusted lab network.

"""UFW adapter for the single-adapter trusted-dev lab; no VM management.

Rules use UFW's documented before.rules framework. Libvirt's independent NAT
forward filter needs a separate, narrowly scoped exception for LAN ingress.
"""
from copy import deepcopy
import ipaddress
import hashlib
import json
from pathlib import Path
import re
import shlex

from .firewall import FirewallError, require, digest, stable, standard_topology, flows

BEFORE4 = '/etc/ufw/before.rules'
BEFORE6 = '/etc/ufw/before6.rules'
AFTER = '/etc/ufw/after.init'
HELPER = '/etc/vm-dev-lab/ufw-sync.py'
SETTINGS = ('/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/before.init')
# Read and qualified no-op hooks of UFW 0.36.2 on the target host. Unknown
# executable hooks must be reviewed rather than executed during our reload.
QUALIFIED_HOOKS = {'/etc/ufw/before.init':'a1936d13aadea73df4a8d91dfed3c0433467ab9da1c4f344a308c36e6a0559cf',
                   AFTER:'1354ecc09be8b68eeb5d1d7b5f00af90bcbc6f53535b591546a6b4652ff5d807'}


def hook_path(setup_id):
    return '/etc/libvirt/hooks/network.d/50-vm-dev-lab-' + setup_id[:12]


def marker(setup_id):
    return 'vm-dev-lab:' + setup_id


def block(setup_id, text):
    return '# BEGIN ' + marker(setup_id) + '\n' + text.rstrip() + '\n# END ' + marker(setup_id) + '\n'


def patch_file(original, body, location):
    require(original is not None and body not in original, 'File is missing or owned block already exists.')
    if location == 'rules':
        require(len(re.findall(r'^\*filter\s*$', original, re.M)) == 1 and len(re.findall(r'^COMMIT\s*$', original, re.M)) == 1, 'Only a simple UFW filter file is supported.')
        match = re.search(r'^-A ', original, re.M)
        require(match is not None, 'UFW insertion point is missing.')
        pos = match.start()
    else:
        require(original.startswith('#!') and '\n' in original, 'Unbekanntes UFW-after.init.')
        pos = original.index('\n') + 1
    return original[:pos] + body + original[pos:]


def unpatch(text, body):
    require(text is not None and text.count(body) == 1, 'Owned persistent block is missing or changed.')
    return text.replace(body, '', 1)


def restore_rules(setup, policy, snapshot, version):
    """Compile the existing small network policy into iptables-restore syntax."""
    result = []
    for flow in flows(setup, policy, snapshot, allow_missing_bridge=True):
        if version == 6 and flow['ip_version'] == 4: continue
        chain = 'ufw' + ('6' if version == 6 else '') + '-before-' + flow['hook']
        args = ['-A', chain]
        for expr in flow['expr'][:-1]:
            m = expr['match']; left, right = m['left'], m['right']
            if 'meta' in left:
                key = left['meta']['key']
                if key == 'nfproto': continue  # Family is fixed by the UFW file.
                args += ['-i' if key == 'iifname' else '-o', right]
            elif 'payload' in left:
                if isinstance(right, dict):
                    right = str(right['prefix']['addr']) + '/' + str(right['prefix']['len'])
                args += ['-s' if left['payload']['field'] == 'saddr' else '-d', right]
            else:
                args += ['-m', 'conntrack', '--ctstate', ','.join(s.upper() for s in right['set'])]
        args += ['-m', 'comment', '--comment', marker(setup['setup_id']) + ':' + flow['name'], '-j', next(iter(flow['expr'][-1])).upper()]
        result.append(' '.join(args))
    return result


def rule_key(line):
    """Canonical semantic tuple; neither counters nor option ordering owns a rule."""
    tokens = shlex.split(re.sub(r'^\[\d+:\d+\]\s*', '', line))
    require(len(tokens) >= 2 and tokens[0] == '-A', 'Not a regular rule.')
    data = {'chain': tokens[1]}; index = 2
    keys = {'-i': 'in', '-o': 'out', '-s': 'src', '-d': 'dst', '-j': 'verdict', '--ctstate': 'state', '--comment': 'comment'}
    while index < len(tokens):
        key, value = tokens[index:index+2]
        if key == '-m':
            require(value in ('comment', 'conntrack'), 'Unknown rule matcher.')
        else:
            require(key in keys and keys[key] not in data, 'Unexpected or duplicate owned rule option.')
            if key in ('-s', '-d'): value = str(ipaddress.ip_network(value, strict=False))
            if key == '--ctstate': value = ','.join(sorted(value.split(',')))
            data[keys[key]] = value
        index += 2
    return data


def observe(run, read):
    files = {}
    for name in (BEFORE4, BEFORE6, AFTER, *SETTINGS):
        files[name] = read(name)
    return {'files': files, 'save4': run(['iptables-save', '-t', 'filter']),
            'save6': run(['ip6tables-save', '-t', 'filter']),
            'status': run(['ufw', 'status', 'verbose'])}


def check_coexisting_tables(rows):
    """Qualify observed desktop-owned tables without taking ownership of them."""
    managed = {('ip', 'filter'), ('ip6', 'filter'),
               ('ip', 'libvirt_network'), ('ip6', 'libvirt_network')}
    docker = {('ip', 'nat'), ('ip6', 'nat')}
    queues = {('inet', 'mangle'): ('output', 'route', 'output', -150),
              ('inet', 'filter'): ('input', 'filter', 'input', 0)}
    for row in rows:
        kind = next(iter(row)); obj = row[kind]
        if 'family' not in obj: continue
        key = (obj['family'], obj.get('table', obj.get('name')))
        require(key in managed | docker | set(queues), 'Additional firewall table or hook is not qualified.')
        if key in managed: continue
        if key in docker:
            require(kind in ('table', 'chain', 'rule'), 'Unknown Docker nft object.')
            if kind == 'chain':
                hooks = {'PREROUTING': ('nat', 'prerouting', -100),
                         'OUTPUT': ('nat', 'output', -100),
                         'POSTROUTING': ('nat', 'postrouting', 100)}
                require((obj['name'] == 'DOCKER' and not any(k in obj for k in ('type','hook','prio','policy'))) or
                        (obj['name'] in hooks and
                         (obj.get('type'), obj.get('hook'), obj.get('prio')) == hooks[obj['name']] and
                         obj.get('policy') == 'accept'), 'Unknown Docker NAT chain.')
            if kind == 'rule':
                require(obj.get('chain') in ('DOCKER', 'PREROUTING', 'OUTPUT', 'POSTROUTING') and
                        all(set(expr) <= {'match', 'counter', 'jump', 'xt', 'dnat', 'snat', 'masquerade', 'redirect', 'return'}
                            for expr in obj.get('expr', [])) and
                        all(expr.get('jump', {}).get('target') == 'DOCKER' for expr in obj.get('expr', []) if 'jump' in expr) and
                        not any(set(expr) & {'accept', 'drop', 'reject', 'queue'} for expr in obj.get('expr', [])),
                        'Unknown Docker NAT rule.')
            continue
        name, chain_type, hook, priority = queues[key]
        require(kind in ('table', 'chain', 'rule'), 'Unknown queue nft object.')
        if kind == 'chain':
            require((obj.get('name'), obj.get('type'), obj.get('hook'), obj.get('prio'), obj.get('policy')) ==
                    (name, chain_type, hook, priority, 'accept'), 'Unknown queue base hook.')
        if kind == 'rule':
            expr = obj.get('expr', [])
            require(obj.get('chain') == name and expr and
                    all(set(item) == {'match'} for item in expr[:-1]) and
                    expr[-1] == {'queue': {'flags': ['bypass'], 'num': 0}},
                    'Unknown queue rule.')


def check_environment(snapshot, setup_id=None):
    require(snapshot['managers'] == {'ufw': 'active', 'firewalld': 'inactive'}, 'Active UFW without parallel firewalld is required.')
    require(all(v in ('empty', 'absent') for v in snapshot['legacy'].values()), 'Legacy netfilter is not supported.')
    extra = snapshot.get('ufw'); require(isinstance(extra, dict), 'UFW files or runtime state were not read completely.')
    require(extra['status'].startswith('Status: active\n'), 'UFW is not active; never activate or deactivate it automatically.')
    config = extra['files']['/etc/default/ufw']
    require(re.search(r'^MANAGE_BUILTINS=["\']?no["\']?\s*$', config, re.M), 'UFW MANAGE_BUILTINS must remain no; no global table flushes.')
    require(re.search(r'^IPV6=["\']?yes["\']?\s*$', config, re.M), 'IPv6 UFW state is not qualified.')
    require(re.search(r'^ENABLED=yes\s*$', extra['files']['/etc/ufw/ufw.conf'], re.M), 'UFW persistence is not enabled; do not repair it.')
    for path, expected in QUALIFIED_HOOKS.items():
        text=extra['files'][path]
        if setup_id is not None and path==AFTER:
            text=re.sub(r'^# BEGIN '+re.escape(marker(setup_id))+r'\n.*?^# END '+re.escape(marker(setup_id))+r'\n', '', text, flags=re.M|re.S)
        require(hashlib.sha256(text.encode()).hexdigest()==expected, 'Unqualified UFW hook: '+path)
    rows = snapshot['nft']['nftables']
    check_coexisting_tables(rows)
    for row in rows:
        require(next(iter(row)) in ('metainfo', 'table', 'chain', 'rule'), 'Unknown nft objects; do not apply UFW blindly.')
        obj = next(iter(row.values()))
        if 'chain' in row and 'hook' in obj:
            if (obj['family'], obj['table']) not in {('ip', 'filter'), ('ip6', 'filter'),
                                                      ('ip', 'libvirt_network'), ('ip6', 'libvirt_network')}:
                continue
            require((obj['table'] == 'filter' and obj['type'] == 'filter' and obj['hook'] in ('input', 'output', 'forward')) or
                    (obj['table'] == 'libvirt_network' and ((obj['type'] == 'filter' and obj['hook'] == 'forward') or (obj['type'] == 'nat' and obj['hook'] == 'postrouting'))), 'Unknown nft base hook.')
    for family, prefix in (('ip','ufw'), ('ip6','ufw6')):
        for name, hook in (('INPUT','input'), ('OUTPUT','output'), ('FORWARD','forward')):
            expected=[prefix+'-'+stage+'-'+hook for stage in ('before-logging','before','after','after-logging','reject','track')]
            actual=[]
            for row in rows:
                r=row.get('rule',{})
                if (r.get('family'),r.get('table'),r.get('chain')) != (family,'filter',name): continue
                actual.append([e for e in r.get('expr',[]) if 'counter' not in e])
            positions=[i for i,expr in enumerate(actual) if len(expr)==1 and
                       expr[0].get('jump',{}).get('target') in expected]
            require(len(positions)==len(expected) and positions==list(range(positions[0],positions[0]+len(expected))) and
                    [actual[i][0]['jump']['target'] for i in positions] == expected,
                    'UFW built-in order differs: '+name)
            before=actual[:positions[0]]; after=actual[positions[-1]+1:]
            docker=[[{'jump':{'target':'DOCKER-USER'}}],[{'jump':{'target':'DOCKER-FORWARD'}}]]
            require(not before or (name=='FORWARD' and before==docker),
                    'Unqualified control flow before UFW: '+name)
            for expr in after:
                require(expr and set(expr[-1])=={'accept'} and all(set(e)=={'match'} for e in expr[:-1]) and
                        any(e['match'].get('left',{}).get('meta',{}).get('key') in ('iifname','oifname') and
                            isinstance(e['match'].get('right'),str) and e['match']['right'].startswith('virbr')
                            for e in expr[:-1]), 'Unqualified control flow after UFW: '+name)
            early=prefix+'-before-logging-'+hook
            require(all(set(e) <= {'counter','log','match','limit'} for row in rows if 'rule' in row and
                        (row['rule'].get('family'),row['rule'].get('table'),row['rule'].get('chain')) == (family,'filter',early)
                        for e in row['rule'].get('expr',[])), 'Early logging hook may drop lab traffic.')
    return extra


def exception_spec(setup, policy, topology):
    if policy['lan_access'] not in ('in', 'allow'): return None
    def match(left, right): return {'match': {'op': '==', 'left': left, 'right': right}}
    def prefix(net):
        value = ipaddress.ip_network(net)
        return {'prefix': {'addr': str(value.network_address), 'len': value.prefixlen}}
    expr = [match({'meta': {'key': 'iifname'}}, policy['lan_interface']),
            match({'meta': {'key': 'oifname'}}, setup['bridge']),
            match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, prefix(topology['lan'])),
            match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, prefix(setup['subnet'])), {'accept': None}]
    return {'family': 'ip', 'table': 'libvirt_network', 'chain': 'guest_input', 'expr': expr,
            'comment': marker(setup['setup_id']) + ':lan-in-libvirt'}


def xt_rule_expr(key, version):
    """Exact qualified iptables-nft JSON shape; opaque data comes from save view."""
    expr = []
    for field, payload in (('src', 'saddr'), ('dst', 'daddr')):
        if field in key:
            net = ipaddress.ip_network(key[field])
            expr.append({'match': {'op': '==', 'left': {'payload': {
                'protocol': 'ip' if version == 4 else 'ip6', 'field': payload}},
                'right': {'prefix': {'addr': str(net.network_address), 'len': net.prefixlen}}}})
    for field, meta in (('in', 'iifname'), ('out', 'oifname')):
        if field in key:
            expr.append({'match': {'op': '==', 'left': {'meta': {'key': meta}}, 'right': key[field]}})
    if 'state' in key:
        expr.append({'xt': {'type': 'match', 'name': 'conntrack'}})
    expr.append({'xt': {'type': 'match', 'name': 'comment'}})
    expr.append({key['verdict'].lower(): None})
    return expr


def owned_nft_rows(snapshot, plan):
    """Correlate full chain positions, exact save identity and exact nft structure.

    Never infer ownership from an opaque xt matcher, handle or position alone.
    Partial rollback may have no active own rules, but any present set must be
    complete for its family. All remaining rules stay in the foreign digest.
    """
    require(plan['sha256'] == digest({k:v for k,v in plan.items() if k != 'sha256'}),
            'Classification requires an unchanged record plan.')
    rows = snapshot['nft']['nftables']; owned = set(); tag = marker(plan['setup_id']) + ':'
    for version, family in ((4, 'ip'), (6, 'ip6')):
        lines = [l for l in snapshot['ufw']['save'+str(version)].splitlines() if l.startswith('-A ')]
        expected = [rule_key(l) for l in plan['rules'+str(version)]]
        selected = [rule_key(l) for l in lines if tag in l]
        require(not selected or sorted(selected, key=lambda k:k['chain']) == sorted(expected, key=lambda k:k['chain']),
                'Owned save rules are incomplete, changed, or duplicated.')
        for chain in {k['chain'] for k in expected}:
            saved = [l for l in lines if shlex.split(l)[1] == chain]
            indexed = [(i,r['rule']) for i,r in enumerate(rows) if 'rule' in r and
                       (r['rule'].get('family'),r['rule'].get('table'),r['rule'].get('chain')) == (family,'filter',chain)]
            require(len(saved) == len(indexed), 'nft and save chain lengths differ.')
            own_keys = [k for k in expected if k['chain'] == chain]
            if not selected: continue
            require([rule_key(l) for l in saved[:len(own_keys)]] == own_keys,
                    'Owned rules are not at the confirmed start of the chain.')
            for key, (index, rule) in zip(own_keys, indexed):
                require(set(rule) <= {'family','table','chain','handle','expr','comment'}, 'Unknown owned nft rule fields.')
                require(rule.get('comment') in (None, key['comment']), 'nft ownership comment differs.')
                expr = [e for e in rule['expr'] if set(e) != {'counter'}]
                require(expr == xt_rule_expr(key, version), 'Owned nft structure does not match save data or record.')
                owned.add(index)
    # Native libvirt exception has a readable comment: verify the whole rule,
    # never discard all rules merely carrying our prefix.
    for index, row in enumerate(rows):
        rule = row.get('rule', {})
        if index in owned or not rule.get('comment', '').startswith(tag): continue
        spec = plan['libvirt_exception']
        require(spec is not None and {k:v for k,v in rule.items() if k != 'handle'} == spec,
                'Unknown or changed rule with an owned ownership comment.')
        require(not any(rows[i].get('rule',{}).get('comment') == spec['comment'] for i in owned),
                'Duplicate owned libvirt exception.')
        owned.add(index)
    return owned


def foreign_digest(snapshot, setup_id, plan=None):
    """UFW reload recreates handles; only positively correlated rules are removed."""
    value = deepcopy(snapshot['nft'])
    require(plan is None or plan['setup_id'] == setup_id, 'Classification belongs to a different setup.')
    owned = owned_nft_rows(snapshot, plan) if plan is not None else set()
    value['nftables'] = [r for i,r in enumerate(value['nftables']) if i not in owned]
    def clean(v):
        if isinstance(v, list): return [clean(x) for x in v]
        if isinstance(v, dict): return {k: (None if k == 'counter' else clean(x)) for k, x in v.items() if k != 'handle'}
        return v
    normalized = clean(value)['nftables']
    normalized = [r for r in normalized if 'metainfo' not in r]
    normalized.sort(key=lambda r: (next(iter(r)), next(iter(r.values())).get('family',''), next(iter(r.values())).get('table',''), next(iter(r.values())).get('chain',next(iter(r.values())).get('name',''))))
    return digest(normalized)


def build_plan(setup, policy, snapshot):
    extra = check_environment(snapshot); topology = standard_topology(setup, policy, snapshot, allow_missing_bridge=True)
    require(setup['host_id'] == snapshot['host_id'], 'Different host.')
    tag = marker(setup['setup_id'])
    require(not any(tag in t for t in extra['files'].values()) and not any(tag+':' in extra['save'+str(v)] for v in (4,6)) and not any(r.get('rule',{}).get('comment','').startswith(tag+':') for r in snapshot['nft']['nftables']), 'Owned blocks already exist; inspect the original record.')
    changes = {}
    for version, filename in ((4, BEFORE4), (6, BEFORE6)):
        lines = restore_rules(setup, policy, snapshot, version)
        body = block(setup['setup_id'], '\n'.join(lines))
        original = extra['files'][filename]
        changes[filename] = {'before': original, 'after': patch_file(original, body, 'rules'), 'block': body}
    spec = exception_spec(setup, policy, topology)
    helper = hook = None
    if spec:
        # Only the observed libvirt NAT layout is qualified. No shared rule deletion.
        rows = snapshot['nft']['nftables']
        require(any('rule' in r and r['rule'].get('family') == 'ip' and r['rule'].get('table') == 'libvirt_network' and r['rule'].get('chain') == 'guest_input' and
                    any(e.get('match', {}).get('right') == setup['bridge'] for e in r['rule'].get('expr', [])) and
                    any('reject' in e for e in r['rule'].get('expr', [])) for r in rows), 'Owned libvirt ingress filter was not associated positively.')
        helper = Path(__file__).with_name('ufw_sync.py').read_text()
        body = block(setup['setup_id'], 'if [ "${1:-}" = start ]; then\n    /usr/bin/python3 '+HELPER+'\nfi')
        original = extra['files'][AFTER]
        changes[AFTER] = {'before': original, 'after': patch_file(original, body, 'script'), 'block': body}
        hook = '#!/bin/sh\n# '+tag+'\nif [ "${1:-}" = '+shlex.quote(setup['network'])+' ] && { [ "${2:-}" = started ] || [ "${2:-}" = updated ]; }; then\n    exec /usr/bin/python3 '+HELPER+'\nfi\n'
    plan = dict(schema_version=2, backend='ufw-framework-v1', host_id=setup['host_id'], setup_id=setup['setup_id'],
                network_uuid=setup['network_uuid'], setup_sha256=setup['sha256'], setup=deepcopy(setup), policy=deepcopy(policy),
                topology=topology, files=changes, settings={p: extra['files'][p] for p in SETTINGS},
                rules4=restore_rules(setup, policy, snapshot, 4), rules6=restore_rules(setup, policy, snapshot, 6),
                libvirt_exception=spec, helper=helper, hook=hook, foreign_sha256=foreign_digest(snapshot, setup['setup_id']))
    plan['sha256'] = digest(plan)
    return plan


def check_rules(plan, snapshot):
    extra = check_environment(snapshot, plan['setup_id'])
    for version in (4, 6):
        actual = [rule_key(l) for l in extra['save'+str(version)].splitlines() if l.startswith('-A ') and marker(plan['setup_id'])+':' in l]
        expected = [rule_key(l) for l in plan['rules'+str(version)]]
        require(sorted(actual, key=lambda r:r['chain']) == sorted(expected, key=lambda r:r['chain']), 'Active owned UFW rules are missing, changed, duplicated, or reordered (IPv'+str(version)+').')
        for chain in {r['chain'] for r in expected}:
            lines=[l for l in extra['save'+str(version)].splitlines() if l.startswith('-A '+chain+' ')]
            count=sum(r['chain']==chain for r in expected)
            require(all(marker(plan['setup_id'])+':' in l for l in lines[:count]) and len(lines)>=count, 'Owned UFW rules were moved behind foreign rules.')
    for path, change in plan['files'].items():
        require(extra['files'][path] == change['after'], 'Persistent file differs: '+path)
    require(all(extra['files'][p] == text for p, text in plan['settings'].items()), 'Global UFW settings changed.')
    current = standard_topology(plan['setup'], plan['policy'], snapshot, allow_missing_bridge=True)
    expected = plan['topology']; bridge = plan['setup']['bridge']; adapter = plan['policy']['lan_interface']
    require(current['lan'] == expected['lan'] and current['gateway'] == expected['gateway'] and
            current['interfaces'][adapter] == expected['interfaces'][adapter] and
            (current['interfaces'][bridge] == expected['interfaces'][bridge] or
             expected['interfaces'][bridge] is None and type(current['interfaces'][bridge]) is int),
            'LAN or bridge identity changed.')
    require(foreign_digest(snapshot, plan['setup_id'], plan) == plan['foreign_sha256'], 'Foreign firewall policy changed; review is required.')
    return True


def status(plan, record, snapshot, system):
    require(record and record.get('plan') == plan and record.get('status') == 'complete', 'UFW record is missing or requires review.')
    require(plan['sha256'] == digest({k:v for k,v in plan.items() if k!='sha256'}), 'UFW record plan is corrupted.')
    check_rules(plan, snapshot)
    if plan['libvirt_exception']:
        system.ufw_support_check(plan)
        system.ufw_exception_check(plan, mutate=False)
    return {'status': 'PASS', 'message': 'Owned trusted-dev UFW rules verified as persistent and active; foreign policy is unchanged.',
            'rules_present': True, 'persistence': 'UFW files; ingress hook if selected', 'network_ready': False,
            'real_reload_tested': record.get('real_reload_tested', False), 'real_boot_tested': bool(record.get('installed_boot_id') and snapshot['ufw'].get('boot_id') and record['installed_boot_id'] != snapshot['ufw']['boot_id'])}


def apply(plan, setup, system, confirmation):
    require(plan.get('backend') == 'ufw-framework-v1' and confirmation == plan.get('sha256') == digest({k:v for k,v in plan.items() if k!='sha256'}), 'UFW plan or confirmation is invalid.')
    require(setup == plan['setup'], 'Owned host-setup record changed.')
    with system.firewall_lock():
        record = system.firewall_record(); snapshot = system.firewall_snapshot()
        if record and record.get('status') != 'removed':
            status(plan, record, snapshot, system); return 'unchanged'
        require(build_plan(setup, plan['policy'], snapshot) == plan, 'UFW plan is stale; validate it again.')
        system.ufw_support_preflight(plan)
        journal = {'status': 'pending', 'plan': plan, 'completed_files': [], 'installed_boot_id':snapshot['ufw'].get('boot_id')}; system.firewall_save(journal)
        try:
            with system.ufw_file_lock():
                for path, change in plan['files'].items():
                    system.ufw_write(path, change['before'], change['after'])
                    journal['completed_files'].append(path); system.firewall_save(journal)
                journal['created_dirs'] = []
                system.ufw_support_install(plan, journal)
            system.ufw_reload()
            system.ufw_exception_check(plan, mutate=True)
            check_rules(plan, system.firewall_snapshot())
            journal['status'] = 'complete'; system.firewall_save(journal)
            status(plan, journal, system.firewall_snapshot(), system)
        except BaseException:
            journal['status'] = 'review_required'; system.firewall_save(journal); raise
    return 'applied-persistent-UFW'


def uninstall(plan, system, confirmation):
    require(confirmation == plan.get('sha256'), 'Confirm UFW uninstall separately.')
    with system.firewall_lock():
        record = system.firewall_record()
        require(record and record.get('plan') == plan, 'Matching owned UFW record is missing.')
        snapshot = system.firewall_snapshot()
        if record.get('status') == 'removed':
            require(all(snapshot['ufw']['files'][p] == c['before'] for p,c in plan['files'].items()), 'State changed after uninstall.')
            return 'unchanged'
        # Partial apply: each individual file may be exactly before or after, never guessed.
        for path, change in plan['files'].items():
            require(snapshot['ufw']['files'][path] in (change['before'], change['after']), 'Foreign file drift; no automatic restore: '+path)
        require(foreign_digest(snapshot, plan['setup_id'], plan) == plan['foreign_sha256'], 'Foreign policy changed since apply.')
        system.ufw_support_check(plan, partial=True)
        record['status'] = 'removing'; system.firewall_save(record)
        with system.ufw_file_lock():
            for path, change in plan['files'].items():
                if snapshot['ufw']['files'][path] == change['after']:
                    system.ufw_write(path, change['after'], unpatch(change['after'], change['block']))
        system.ufw_exception_remove(plan)
        system.ufw_reload()
        fresh = system.firewall_snapshot()
        require(all(fresh['ufw']['files'][p] == c['before'] for p,c in plan['files'].items()) and foreign_digest(fresh, plan['setup_id'], plan) == plan['foreign_sha256'], 'UFW rollback was not confirmed.')
        require(not any(marker(plan['setup_id'])+':' in fresh['ufw']['save'+str(v)] for v in (4,6)), 'Owned runtime rules remained.')
        system.ufw_support_remove(plan)
        system.firewall_save({'status':'removed','plan':plan})
    return 'removed-owned-UFW-rules'


def assess(snapshot, record, read):
    """P04's read-only path; a missing rule can never trigger a repair."""
    from . import ufw_sync
    class ReadOnly:
        def ufw_support_check(self, plan):
            require(read(HELPER)==plan['helper'] and read(hook_path(plan['setup_id']))==plan['hook'], 'Owned persistent helper or network hook is missing or changed.')
        def ufw_exception_check(self, plan, mutate=False):
            xml=read('/etc/libvirt/qemu/networks/'+plan['setup']['network']+'.xml')
            def forbidden(*args): raise FirewallError('Owned libvirt ingress exception is missing; P04 repairs nothing.')
            result=ufw_sync.sync(record, xml, snapshot['nft'], forbidden)
            require(result=='unchanged', 'Lab network or exception is inactive, or the journal is blocking.')
    try:
        require(record is not None and record.get('plan',{}).get('backend')=='ufw-framework-v1', 'Owned UFW record is missing; review HOST-SETUP.md.')
        require(record['plan']['host_id']==snapshot['host_id'], 'UFW record belongs to a different host.')
        return status(record['plan'], record, snapshot, ReadOnly())
    except (FirewallError, OSError, ValueError, KeyError, TypeError) as error:
        return {'status':'UNVERIFIED', 'message':str(error), 'network_ready':False}
