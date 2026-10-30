# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Test the manual libvirt service script with simulated host tools.

"""Test the host script exclusively with simulated systemctl and virsh responses."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/vm-host.sh"
MOCKS = r'''
source "$1"
shift
require_root() { :; }
declare -A MOCK_ACTIVE=() MOCK_LOAD=() MOCK_BOOT=()
for daemon in "${DAEMONS[@]}" "${SUPPORT[@]}"; do
  for suffix in "${SOCKET_SUFFIXES[@]}" .service; do
    unit="$daemon$suffix"
    MOCK_LOAD[$unit]=loaded
    MOCK_BOOT[$unit]="${BOOT_STATE:-disabled}"
    MOCK_ACTIVE[$unit]=inactive
    if [[ ${INITIAL:-on} == on && " ${DAEMONS[*]} " == *" $daemon "* ]]; then MOCK_ACTIVE[$unit]=active; fi
    if [[ ${SUPPORT_ACTIVE:-0} == 1 && " ${SUPPORT[*]} " == *" $daemon "* ]]; then MOCK_ACTIVE[$unit]=active; fi
    if [[ " ${OFF_DAEMONS:-} " == *" $daemon "* ]]; then MOCK_ACTIVE[$unit]=inactive; fi
  done
 done
if [[ ${INITIAL:-on} == partial ]]; then
  MOCK_ACTIVE[virtqemud.socket]=active
  MOCK_ACTIVE[virtnetworkd.service]=active
fi
if [[ ${INITIAL:-on} == daemon ]]; then MOCK_ACTIVE[virtqemud.service]=active; fi
for unit in ${MISSING:-}; do MOCK_LOAD[$unit]=not-found; MOCK_ACTIVE[$unit]=inactive; MOCK_BOOT[$unit]=''; done
if [[ -n ${MASKED:-} ]]; then MOCK_LOAD[$MASKED]=masked; MOCK_BOOT[$MASKED]=masked; fi
if [[ ${ALTERNATIVE_ACTIVE:-0} == 1 ]]; then MOCK_LOAD[libvirtd.socket]=loaded; MOCK_ACTIVE[libvirtd.socket]=active; fi
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$CALL_LOG"
  local unit
  case "$1" in
    show)
      unit="${*: -1}"
      [[ ${SHOW_ERROR:-0} != 1 ]] || return 1
      printf 'LoadState=%s\nActiveState=%s\nUnitFileState=%s\n' "${MOCK_LOAD[$unit]:-not-found}" "${MOCK_ACTIVE[$unit]:-inactive}" "${MOCK_BOOT[$unit]:-}"
      ;;
    start|stop)
      local action="$1"
      shift
      for unit in "$@"; do
        if [[ $action == start ]]; then MOCK_ACTIVE[$unit]=active; else MOCK_ACTIVE[$unit]=inactive; fi
      done
      if [[ $action == stop && " $* " == *' virtqemud.service '* && ${REACTIVATE:-0} == 1 ]]; then MOCK_ACTIVE[virtqemud.service]=active; fi
      ;;
    *) echo "Disallowed systemctl invocation: $*" >&2; return 99 ;;
  esac
}
virsh_cmd() {
  printf 'virsh %s\n' "$*" >> "$CALL_LOG"
  if [[ -n ${QUERY_ERROR:-} && "$*" == *"$QUERY_ERROR"* ]]; then return 1; fi
  case "$*" in
    'list --name') printf '%s\n' "${GUESTS:-}" ;;
    'net-list --all --name'|'pool-list --all --name') printf '%s\n' "${RESOURCES-default}" ;;
    'net-list --all --persistent --name'|'pool-list --all --persistent --name') printf '%s\n' "${PERSISTENT-default}" ;;
    'net-list --name'|'pool-list --name') printf '%s\n' "${RESOURCE_ACTIVE-default}" ;;
    'net-destroy default'|'pool-destroy default') return 0 ;;
    *) echo "Disallowed virsh invocation: $*" >&2; return 99 ;;
  esac
}
for action in "$@"; do "$action"; done
'''


class HostScriptTests(unittest.TestCase):
    def invoke(self, *actions, **settings):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "calls"
            result = subprocess.run(
                ["bash", "-c", MOCKS, "test-vm-host", str(SCRIPT), *actions],
                env=dict(os.environ, CALL_LOG=str(log), **settings),
                text=True, capture_output=True, timeout=10,
            )
            calls = log.read_text().splitlines() if log.exists() else []
        # Every unexpected or persistent operation makes the mock fail.
        self.assertNotIn("Disallowed", result.stderr)
        return result, calls

    def assert_no_mutation(self, calls):
        self.assertFalse(any(c.startswith(("systemctl start", "systemctl stop", "virsh net-destroy", "virsh pool-destroy")) for c in calls), calls)

    def test_status_off_shows_states_without_waking_services(self):
        result, calls = self.invoke("status_host", INITIAL="off", MASKED="virtnetworkd.socket", MISSING="virtstoraged.socket")
        self.assertEqual(result.returncode, 0, result.stderr)
        for word in ("inactive", "disabled", "masked", "not-found", "not queried"):
            self.assertIn(word, result.stdout)
        self.assertFalse(any(c.startswith("virsh ") for c in calls))
        self.assert_no_mutation(calls)

    def test_start_twice_preserves_boot_policy_on_active_host(self):
        for initial in ("off", "on"):
            with self.subTest(initial=initial):
                result, calls = self.invoke("start_host", "start_host", "status_host", INITIAL=initial, BOOT_STATE="enabled")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("enabled", result.stdout)
                starts = [c for c in calls if c.startswith("systemctl start")]
                self.assertEqual(len(starts), 2)
                self.assertTrue(all("-admin" not in c and "-ro" not in c for c in starts))
                self.assertFalse(any(c.startswith("virsh ") for c in calls))

    def test_stop_twice_and_status_do_not_reconnect(self):
        result, calls = self.invoke("stop_host", "stop_host", "status_host", SUPPORT_ACTIVE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        stops = [c for c in calls if c.startswith("systemctl stop")]
        self.assertEqual(len(stops), 2)
        self.assertIn("virtqemud-admin.socket", stops[0])
        for c in stops:
            self.assertNotIn("virtlogd", c)
            self.assertNotIn("virtlockd", c)
            self.assertNotIn("virtnodedevd", c)
        first_stop = next(i for i, c in enumerate(calls) if c.startswith("systemctl stop"))
        self.assertFalse(any(c.startswith("virsh ") for c in calls[first_stop:]))
        self.assertIn("already off", result.stdout)

    def test_stop_already_off_does_not_query_guests(self):
        result, calls = self.invoke("stop_host", INITIAL="off", SUPPORT_ACTIVE="1", QUERY_ERROR="list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c.startswith("virsh ") for c in calls))
        self.assert_no_mutation(calls)

    def test_all_active_domain_states_prevent_stop(self):
        for state in ("running", "paused", "blocked", "pmsuspended", "foreign-domain"):
            with self.subTest(state=state):
                result, calls = self.invoke("stop_host", GUESTS=state)
                self.assertEqual(result.returncode, 1)
                self.assertIn("virsh list --name", calls)
                self.assert_no_mutation(calls)

    def test_query_failures_and_unsafe_resources_abort_before_mutation(self):
        for settings in ({"QUERY_ERROR": "list --name"}, {"QUERY_ERROR": "pool-list"}, {"QUERY_ERROR": "net-list"}, {"PERSISTENT": ""}, {"RESOURCE_ACTIVE": "default\nother"}, {"SHOW_ERROR": "1"}, {"ALTERNATIVE_ACTIVE": "1"}):
            with self.subTest(settings=settings):
                result, calls = self.invoke("stop_host", **settings)
                self.assertEqual(result.returncode, 1)
                self.assert_no_mutation(calls)

    def test_partial_or_service_only_operation(self):
        for initial in ("partial", "daemon"):
            with self.subTest(initial=initial):
                result, calls = self.invoke("stop_host", INITIAL=initial)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("virsh list --name", calls)
                self.assertFalse(any(c.startswith("virsh pool-list") for c in calls))

    def test_partial_without_qemu_refuses_shutdown(self):
        result, calls = self.invoke("stop_host", OFF_DAEMONS="virtqemud")
        self.assertEqual(result.returncode, 1)
        self.assert_no_mutation(calls)

    def test_missing_optional_storage_and_inactive_network(self):
        missing = "virtstoraged.socket virtstoraged-ro.socket virtstoraged-admin.socket virtstoraged.service"
        result, calls = self.invoke("start_host", "stop_host", MISSING=missing, RESOURCE_ACTIVE="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Optional socket is missing", result.stdout)
        self.assertFalse(any(c.startswith(("virsh pool-list", "virsh net-destroy", "virsh pool-destroy")) for c in calls))

    def test_missing_socket_with_live_service_is_still_checked(self):
        result, calls = self.invoke("stop_host", MISSING="virtstoraged.socket", QUERY_ERROR="pool-list")
        self.assertEqual(result.returncode, 1)
        self.assertIn("virsh pool-list --all --name", calls)
        self.assert_no_mutation(calls)

    def test_missing_primary_or_masked_start_fails_without_changes(self):
        for settings in ({"MISSING": "virtqemud.socket"}, {"MASKED": "virtqemud.socket"}):
            with self.subTest(settings=settings):
                result, calls = self.invoke("start_host", **settings)
                self.assertEqual(result.returncode, 1)
                self.assert_no_mutation(calls)

    def test_reactivation_is_not_reported_as_success(self):
        result, _ = self.invoke("stop_host", REACTIVATE="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reactivated", result.stderr)

    def test_invalid_arguments_do_not_call_tools(self):
        for args in ([], ["unknown"], ["stop", "extra"]):
            result = subprocess.run(["bash", str(SCRIPT), *args], text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
