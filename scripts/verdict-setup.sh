#!/usr/bin/env bash
# scripts/verdict-setup.sh — one-shot bootstrap so `/verdict` runs the whole
# pipeline with NO flags and NO manual installs.
#
# The forensic toolchain (ewfmount/TSK, Volatility, Hayabusa, Chainsaw,
# Velociraptor) lives pre-installed in the SANS SIFT VM, so "install everything"
# is solved by preparing the VM, not by installing those binaries on the host.
# This script:
#   1. builds the two MCP servers (the "app") via install.sh if missing;
#   2. uses n8n (post-verdict automation) only if already up — never started on
#      the default path; opt in with FINDEVIL_ENABLE_N8N=1;
#   3. prepares the SIFT VM: resolves its current IP (DHCP-safe via vmrun),
#      powers it on if needed, waits for SSH + the forensic toolchain.
#
# It prints two machine-readable lines on stdout for the caller (the skill):
#   FIND_EVIL_GUEST_IP=<ip-or-empty>
#   SIFT_OK=<0|1>
# All human progress goes to stderr.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
log()  { printf '\033[36m[setup]\033[0m %s\n' "$*" >&2; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*" >&2; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*" >&2; }
healthz() { curl -fsS --max-time "${2:-3}" "http://127.0.0.1:5678/healthz" >/dev/null 2>&1; }

# 1. MCP servers (the app) -----------------------------------------------------
if [[ -x target/release/findevil-mcp ]]; then
  ok "MCP server present (target/release/findevil-mcp)"
else
  log "building the MCP servers (scripts/install.sh — first run, a few minutes)…"
  if bash scripts/install.sh >/tmp/verdict-install.log 2>&1; then
    ok "MCP servers built + venv synced"
  else
    warn "install.sh reported issues — see /tmp/verdict-install.log (continuing)"
  fi
fi

# 2. n8n (post-verdict automation) — optional, OFF the default path -----------
# n8n is a post-verdict SOAR hook, not part of the proven DFIR flow. The default
# turnkey run never spends time starting it (an empty n8n with no deployed
# workflow just reports "skipped" anyway): it is used only if one is ALREADY up.
# Opt in with FINDEVIL_ENABLE_N8N=1 to actively start a local n8n and wait.
if healthz; then
  ok "n8n already up (:5678) — post-verdict automation available"
elif [ "${FINDEVIL_ENABLE_N8N:-}" = "1" ] && command -v n8n >/dev/null 2>&1; then
  log "FINDEVIL_ENABLE_N8N=1 — starting n8n in the background…"
  ( n8n start >/tmp/verdict-n8n-server.log 2>&1 & ) || true
  for _ in $(seq 1 20); do healthz 2 && break; sleep 1; done
  healthz 2 && ok "n8n up" || warn "n8n not reachable — automation/grounding will be skipped"
else
  log "n8n not running — post-verdict automation/grounding skipped (optional; FINDEVIL_ENABLE_N8N=1 to enable)"
fi

# 3. SIFT VM (the forensic toolchain) -----------------------------------------
SIFT_OK=0
GIP=""
VMX="${FIND_EVIL_SIFT_VMX:-${HOME}/vmware/Find-Evil-SIFT/Find-Evil-SIFT.vmx}"
GKEY="${FIND_EVIL_SSH_KEY:-${HOME}/.ssh/sift_key}"
GUSER="${FIND_EVIL_GUEST_USER:-sansforensics}"

_resolve_ip() {  # VMware Tools first, DHCP-lease fallback when Tools isn't running
                 # in the guest — shared with scripts/verdict via one helper so the
                 # turnkey flow resolves the VM the same way everywhere.
  bash "${REPO_ROOT}/scripts/sift-guest-ip.sh" "${VMX}" 2>/dev/null
}
_toolchain_ok() {  # SSH reachable AND ewfmount present in the guest
  timeout 12 ssh -i "${GKEY}" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=6 "${GUSER}@$1" 'command -v ewfmount >/dev/null && echo ok' \
    2>/dev/null | grep -q ok
}

if [[ -n "${FIND_EVIL_GUEST_IP:-}" ]] && _toolchain_ok "${FIND_EVIL_GUEST_IP}"; then
  GIP="${FIND_EVIL_GUEST_IP}"; SIFT_OK=1
  ok "SIFT VM reachable at ${GIP} (from FIND_EVIL_GUEST_IP)"
elif command -v vmrun >/dev/null 2>&1 && [[ -f "${VMX}" ]]; then
  if ! vmrun list 2>/dev/null | grep -qF "${VMX}"; then
    log "powering on the SIFT VM…"
    vmrun start "${VMX}" nogui >/dev/null 2>&1 || warn "vmrun start failed"
  fi
  log "resolving SIFT VM IP + waiting for the forensic toolchain…"
  for _ in $(seq 1 30); do
    GIP="$(_resolve_ip)"
    [[ -n "${GIP}" ]] && _toolchain_ok "${GIP}" && { SIFT_OK=1; break; }
    GIP=""; sleep 4
  done
  [[ "${SIFT_OK}" == "1" ]] && ok "SIFT VM ready at ${GIP} (full forensic toolchain)" \
    || warn "SIFT VM not reachable — will fall back to local mode"
else
  warn "no vmrun / SIFT VMX found — SIFT unavailable, will fall back to local mode"
fi

# 4. Local fallback toolchain (only matters if SIFT is unavailable) -----------
if [[ "${SIFT_OK}" != "1" ]]; then
  if ! command -v ewfmount >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1 \
     && sudo -n true 2>/dev/null; then
    log "SIFT unavailable — installing light local forensic tools (ewf-tools, sleuthkit)…"
    sudo -n apt-get install -y ewf-tools sleuthkit >/tmp/verdict-localtools.log 2>&1 \
      && ok "ewf-tools + sleuthkit installed locally" \
      || warn "local forensic install failed — see /tmp/verdict-localtools.log"
  fi
  warn "running LOCAL: disk images can only be custody-registered (no inner-volume"
  warn "extraction) without the SIFT VM. Memory/EVTX/network work if their tools are present."
fi

echo "FIND_EVIL_GUEST_IP=${GIP}"
echo "SIFT_OK=${SIFT_OK}"
