# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Provide an in-memory lifecycle backend for offline tests.

"""Pure in-memory backend contract with failures before or after side effects.

No subprocesses, libvirt imports, or real domains. Hooks are test injection.
"""
from copy import deepcopy
from threading import RLock

from .state import fail


class FakeBackend:
    def __init__(self, uri='qemu:///system', hook=None):
        self.uri, self.hook = uri, hook
        self.domains = {}
        self.calls = []
        self._lock = RLock()

    def _event(self, method, point):
        if self.hook:
            self.hook(method, point)

    def capabilities(self):
        return {'backend': 'fake', 'simulated': True, 'uri': self.uri}

    def inspect(self, domain_uuid):
        with self._lock:
            self._event('inspect', 'before')
            result = deepcopy(self.domains.get(domain_uuid))
            self._event('inspect', 'after')
            return result

    def _mutate(self, method, domain_uuid, action):
        with self._lock:
            self._event(method, 'before')
            self.calls.append((method, domain_uuid))
            action()
            self._event(method, 'after')

    def define(self, spec):
        def action():
            if spec['uri'] != self.uri or spec['uuid'] in self.domains or any(d['name'] == spec['name'] for d in self.domains.values()):
                fail('BACKEND_CONFLICT', 'Fake domain name, UUID, or URI conflicts.', 4)
            self.domains[spec['uuid']] = dict(deepcopy(spec), running=False)
        self._mutate('define', spec['uuid'], action)

    def start(self, domain_uuid):
        self._mutate('start', domain_uuid, lambda: self.domains[domain_uuid].update(running=True))

    def shutdown(self, domain_uuid):
        self._mutate('shutdown', domain_uuid, lambda: self.domains[domain_uuid].update(running=False))

    def undefine(self, domain_uuid):
        def action():
            if self.domains[domain_uuid]['running']:
                fail('BACKEND_CONFLICT', 'Do not undefine a running fake domain.', 4)
            del self.domains[domain_uuid]
        self._mutate('undefine', domain_uuid, action)
