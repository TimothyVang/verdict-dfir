#!/usr/bin/env bash
# sift-guest-ip.sh — print the SANS SIFT VM's current guest IP, or nothing.
#
# Resolution order:
#   1. VMware Tools via `vmrun getGuestIPAddress` (authoritative when Tools runs).
#   2. The VMware NAT DHCP lease file — preferring the lease whose client-hostname
#      looks like the SIFT VM. This is the fallback when Tools isn't running in the
#      guest (vmrun returns blank), so the turnkey flow still finds the VM.
#
# A wrong guess is harmless: every caller validates reachability (SSH + ewfmount)
# before using the IP. Override everything with FIND_EVIL_GUEST_IP / SIFT_VM_IP.
#
# Usage: scripts/sift-guest-ip.sh [vmx-path]
set -uo pipefail

VMX="${1:-${FIND_EVIL_SIFT_VMX:-${HOME}/vmware/Find-Evil-SIFT/Find-Evil-SIFT.vmx}}"
LEASES="${FIND_EVIL_VMWARE_LEASES:-/etc/vmware/vmnet8/dhcpd/dhcpd.leases}"

# Explicit override wins.
if [[ -n "${FIND_EVIL_GUEST_IP:-${SIFT_VM_IP:-}}" ]]; then
  printf '%s\n' "${FIND_EVIL_GUEST_IP:-${SIFT_VM_IP}}"
  exit 0
fi

ip="$(vmrun getGuestIPAddress "${VMX}" 2>/dev/null \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"

if [[ -z "${ip}" && -r "${LEASES}" ]]; then
  ip="$(awk '
    /^lease /         { ip=$2 }
    /client-hostname/ { if (tolower($0) ~ /sift/) sift=ip; last=ip }
    END               { if (sift!="") print sift; else if (last!="") print last }
  ' "${LEASES}" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
fi

[[ -n "${ip}" ]] && printf '%s\n' "${ip}"
exit 0
