#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 André Manz
# Purpose: Manually control modular libvirt runtime services with safety guards.

set -Eeuo pipefail

# Manual use only: switch runtime state while preserving boot and resource autostart.
# No implicit vmctl invocation. Boundaries: docs/HOST-SETUP.md#libvirt-services.
CONN=qemu:///system
DAEMONS=(virtqemud virtnetworkd virtstoraged)
# Display shared or optional services only; never stop them explicitly.
SUPPORT=(virtnodedevd virtnwfilterd virtsecretd virtinterfaced virtlogd virtlockd)
SOCKET_SUFFIXES=(.socket -ro.socket -admin.socket)
declare -A LOAD=() ACTIVE=() BOOT=()
SOCKETS=() SERVICES=()

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }
require_root() { (( EUID == 0 )) || fail 'Use sudo for start or stop.'; }
virsh_cmd() { virsh -c "$CONN" "$@"; }

read_unit() {
  local unit="$1" output key value
  output="$(systemctl show --property=LoadState,ActiveState,UnitFileState "$unit")" || fail "Unit query failed: $unit"
  LOAD[$unit]=''; ACTIVE[$unit]=''; BOOT[$unit]=''
  while IFS='=' read -r key value; do
    case "$key" in
      LoadState) LOAD[$unit]="$value" ;;
      ActiveState) ACTIVE[$unit]="$value" ;;
      UnitFileState) BOOT[$unit]="$value" ;;
    esac
  done <<< "$output"
  [[ -n ${LOAD[$unit]} && -n ${ACTIVE[$unit]} ]] || fail "Incomplete unit state: $unit"
  case "${LOAD[$unit]}" in
    loaded|masked|not-found) ;;
    *) fail "Unknown or invalid load state: $unit (${LOAD[$unit]})" ;;
  esac
  case "${ACTIVE[$unit]}" in
    active|inactive|failed) ;;
    *) fail "Unit is transitioning or unknown: $unit (${ACTIVE[$unit]}); check again later." ;;
  esac
}

collect_units() {
  local d suffix unit
  SOCKETS=(); SERVICES=()
  for d in "${DAEMONS[@]}"; do
    for suffix in "${SOCKET_SUFFIXES[@]}" .service; do
      unit="${d}${suffix}"
      read_unit "$unit"
      if [[ ${LOAD[$unit]} != not-found ]]; then
        if [[ $suffix == .service ]]; then SERVICES+=("$unit"); else SOCKETS+=("$unit"); fi
      fi
    done
  done
}

daemon_active() {
  local suffix
  for suffix in "${SOCKET_SUFFIXES[@]}" .service; do
    [[ ${ACTIVE[$1$suffix]} == active ]] && return 0
  done
  return 1
}

assert_modular_host() {
  local d suffix unit
  for d in libvirtd virtproxyd; do
    for suffix in .service "${SOCKET_SUFFIXES[@]}" -tcp.socket -tls.socket; do
      unit="$d$suffix"
      read_unit "$unit"
      # enabled is a boot policy, not a reason for runtime changes.
      [[ ${ACTIVE[$unit]} != active ]] || fail "Alternative management is active: $unit; resolve manually."
    done
  done
}

contains_name() {
  local list="$1" wanted="$2" line
  while IFS= read -r line; do [[ "$line" == "$wanted" ]] && return 0; done <<< "$list"
  return 1
}

assert_no_active_guests() {
  local names
  # virsh list without a state filter returns every active domain, including paused domains.
  names="$(virsh_cmd list --name)" || fail 'Unable to query active domains reliably; aborting.'
  [[ -z ${names//[[:space:]]/} ]] || fail "Active system-libvirt domains; shut them down cleanly first: $names"
}

load_resource_states() {
  local kind all active persistent name
  NET_ACTIVE=''; POOL_ACTIVE=''
  for kind in net pool; do
    if [[ $kind == net ]]; then
      daemon_active virtnetworkd || continue
    else
      daemon_active virtstoraged || continue
    fi
    all="$(virsh_cmd "$kind-list" --all --name)" || fail "$kind inventory cannot be queried."
    active="$(virsh_cmd "$kind-list" --name)" || fail "Active $kind resources cannot be queried."
    persistent="$(virsh_cmd "$kind-list" --all --persistent --name)" || fail "Persistent $kind resources cannot be queried."
    if contains_name "$all" default && ! contains_name "$persistent" default; then
      fail "$kind default is transient; resource changes are not allowed."
    fi
    while IFS= read -r name; do
      [[ -z $name || $name == default ]] || fail "Another active $kind resource exists: $name; resolve manually."
    done <<< "$active"
    if [[ $kind == net ]]; then NET_ACTIVE="$active"; else POOL_ACTIVE="$active"; fi
  done
}

start_host() {
  require_root
  collect_units
  assert_modular_host
  local d unit
  local start_sockets=()
  for d in "${DAEMONS[@]}"; do
    unit="$d.socket"
    if [[ ${LOAD[$unit]} == not-found ]]; then
      [[ $d != virtqemud ]] || fail 'virtqemud.socket is missing; modular system libvirt is required.'
      say "Optional socket is missing: $unit; it will not be provided."
      continue
    fi
    [[ ${LOAD[$unit]} != masked && ${LOAD[$d.service]} != masked ]] || fail "Socket or service is masked: $d; resolve manually."
    start_sockets+=("$unit")
  done
  # Provide only regular sockets; do not additionally expose read-only or admin sockets.
  systemctl start "${start_sockets[@]}"
  collect_units
  for unit in "${start_sockets[@]}"; do
    [[ ${ACTIVE[$unit]} == active ]] || fail "Socket is not active: $unit"
  done
  say 'Management sockets are available. Boot autostart, networks, and pools are unchanged.'
  say 'Shared helper services may start through systemd dependencies.'
}

stop_host() {
  require_root
  collect_units
  assert_modular_host
  if ! daemon_active virtqemud && ! daemon_active virtnetworkd && ! daemon_active virtstoraged; then
    say 'Managed services and sockets are already off. VMs, networks, and pools were not queried.'
    return 0
  fi
  # Do not implicitly start a fully stopped QEMU manager.
  daemon_active virtqemud || fail 'Partial operation without a reachable QEMU manager; safe VM inspection is impossible.'
  assert_no_active_guests
  load_resource_states
  assert_no_active_guests
  if contains_name "$NET_ACTIVE" default; then virsh_cmd net-destroy default; fi
  if contains_name "$POOL_ACTIVE" default; then virsh_cmd pool-destroy default; fi
  # No more libvirt connections from here: stop all sockets first, then daemons.
  if ((${#SOCKETS[@]})); then systemctl stop "${SOCKETS[@]}"; fi
  if ((${#SERVICES[@]})); then systemctl stop "${SERVICES[@]}"; fi
  collect_units
  local d
  for d in "${DAEMONS[@]}"; do
    if daemon_active "$d"; then fail "Still active or reactivated: $d; shutdown did not succeed."; fi
  done
  say 'Managed services and sockets are off; boot and resource autostart remain unchanged.'
  say 'Helper services, especially virtlogd and virtlockd, and other consumers remain untouched.'
}

status_host() {
  local d suffix unit
  printf '%-28s %-12s %-12s %-16s\n' 'Unit' 'Load state' 'Runtime' 'Boot autostart'
  for d in "${DAEMONS[@]}" "${SUPPORT[@]}"; do
    for suffix in "${SOCKET_SUFFIXES[@]}" .service; do
      unit="$d$suffix"
      read_unit "$unit"
      printf '%-28s %-12s %-12s %-16s\n' "$unit" "${LOAD[$unit]}" "${ACTIVE[$unit]}" "${BOOT[$unit]:--}"
    done
  done
  say 'VMs, networks, and pools: not queried (no libvirt socket activation).'
  say 'Only virtqemud, virtnetworkd, and virtstoraged are switched; helper services are only displayed.'
}

main() {
  if [[ $# -ne 1 || ! "$1" =~ ^(start|stop|status)$ ]]; then
    say "Usage: $0 {start|stop|status}" >&2; return 2
  fi
  command -v systemctl >/dev/null || fail 'systemctl is missing.'
  # virsh is required only for stop while management is still active.
  case "$1" in
    start) start_host ;;
    stop) stop_host ;;
    status) status_host ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
