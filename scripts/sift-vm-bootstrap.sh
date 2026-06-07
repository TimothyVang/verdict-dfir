#!/usr/bin/env bash
# sift-vm-bootstrap.sh — one-time SIFT VM setup driven from the Windows host.
#
# Idempotent. Re-running picks up where it left off.
#
# Empirically derived sequence (from a real bring-up against
# sift-2026.03.24.ova on VMware Workstation 17.x + Git Bash on Windows):
#
#   1. ovftool: convert OVA → ~/Documents/Virtual Machines/Find-Evil-SIFT/
#      Skip if the .vmx already exists.
#
#   2. (Skipped) VMX overrides. The OVA's defaults (4 vCPU, 4 GB RAM,
#      e1000 NIC on NAT) are already what we want. Editing the VMX with
#      sed turned out to corrupt the file in ways VMware Workstation
#      rejects with "Cannot read the virtual machine configuration
#      file" — the OVA is what it is, leave it alone.
#
#   3. vmrun start: power on headless. Idempotent — no-op if already on.
#
#   4. Wait for VMware Tools' first IP report (typically <30s on this
#      SIFT image) then read it via vmrun getGuestIPAddress.
#
#   5. SSH key install: vmrun's runProgramInGuest / runScriptInGuest /
#      copyFileFromHostToGuest are all unreliable against this SIFT
#      VM (auth succeeds but file ops return "object is not a
#      directory" or "file name not valid" — likely a VMware Tools
#      VIX-vs-open-vm-tools quirk). Workaround: use paramiko (Python
#      SSH lib) for a one-time password connection that drops the
#      pubkey into ~/.ssh/authorized_keys. After this, ssh-key auth
#      works everywhere.
#
#   6. Repo sync: tar | ssh tar (rsync isn't on Git Bash by default).
#
#   7. Run scripts/sift-vm-setup.sh inside the VM via SSH.
#
#   8. Rewrite .mcp.json.sift to point at the discovered IP.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
OVA_PATH="${OVA_PATH:-${REPO_ROOT}/sift-2026.03.24.ova}"
VM_NAME="${VM_NAME:-Find-Evil-SIFT}"
VM_DIR="${VM_DIR:-$HOME/Documents/Virtual Machines/${VM_NAME}}"
VM_VMX="${VM_DIR}/${VM_NAME}.vmx"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/sift_key}"
GUEST_USER="${GUEST_USER:-sansforensics}"
GUEST_PASS="${GUEST_PASS:-forensics}"
GUEST_REPO_PATH="${GUEST_REPO_PATH:-/home/sansforensics/find-evil}"

VMRUN="/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"
OVFTOOL="/c/Program Files (x86)/VMware/VMware Workstation/OVFTool/ovftool.exe"

log()  { printf '[bootstrap] %s\n' "$*" >&2; }
warn() { printf '[bootstrap] WARN: %s\n' "$*" >&2; }
fail() { printf '[bootstrap] FAIL: %s\n' "$*" >&2; exit 1; }

to_winpath() {
  local p="$1"
  if [[ "$p" == /c/* ]]; then
    echo "C:\\${p#/c/}" | sed 's|/|\\|g'
  elif [[ "$p" == /[a-z]/* ]]; then
    local drive="${p:1:1}"
    echo "${drive^^}:\\${p#/?/}" | sed 's|/|\\|g'
  else
    cygpath -w "$p" 2>/dev/null || echo "$p"
  fi
}

# ---------------------------------------------------------------------
# Phase 0: Prereqs
# ---------------------------------------------------------------------
[[ -f "$OVA_PATH" ]] || fail "OVA not found at: $OVA_PATH
  The SANS SIFT Workstation OVA is not shipped in this repo (SANS-licensed,
  ~9.3 GB, gitignored). Download it from:
    https://www.sans.org/tools/sift-workstation/
  Save it as ${REPO_ROOT}/sift-2026.03.24.ova (or set OVA_PATH=/path/to/your.ova)."
[[ -f "$VMRUN" ]]    || fail "vmrun.exe not found at $VMRUN (install VMware Workstation)"
[[ -f "$OVFTOOL" ]]  || fail "ovftool not found at $OVFTOOL (ships with VMware Workstation)"
command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 || fail "python required for paramiko key install"
PYTHON="$(command -v python3 || command -v python)"
"$PYTHON" -c "import paramiko" 2>/dev/null || {
  log "phase 0: installing paramiko (one-time)..."
  "$PYTHON" -m pip install --quiet --user paramiko
}

mkdir -p "$VM_DIR"

# ---------------------------------------------------------------------
# Phase 1: OVA → VMX (skip if already converted)
# ---------------------------------------------------------------------
if [[ -f "$VM_VMX" ]]; then
  log "phase 1: VMX exists at $VM_VMX — skipping conversion"
else
  log "phase 1: ovftool $OVA_PATH → $VM_VMX (~5-10 min, ~10 GB written)"
  "$OVFTOOL" --acceptAllEulas --name="$VM_NAME" \
    "$(to_winpath "$OVA_PATH")" "$(to_winpath "$VM_VMX")"
  log "  conversion done."
fi

# ---------------------------------------------------------------------
# Phase 2: (intentionally skipped — see header note)
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Phase 3: Power-on
# ---------------------------------------------------------------------
VMX_WIN="$(to_winpath "$VM_VMX")"
if "$VMRUN" -T ws list | grep -qF "$VMX_WIN"; then
  log "phase 3: VM already running"
else
  log "phase 3: starting VM headless..."
  "$VMRUN" -T ws start "$VMX_WIN" nogui
fi

# ---------------------------------------------------------------------
# Phase 4: Wait for VMware Tools + discover guest IP
# ---------------------------------------------------------------------
log "phase 4: waiting for VMware Tools (up to 240s)..."
GUEST_IP=""
for i in $(seq 1 120); do
  ip="$("$VMRUN" -T ws getGuestIPAddress "$VMX_WIN" 2>/dev/null || true)"
  if [[ -n "$ip" && "$ip" != "unknown" && "$ip" != *Error* ]]; then
    GUEST_IP="$ip"
    log "  guest IP: $GUEST_IP (after ~$((i*2))s)"
    break
  fi
  sleep 2
done
[[ -n "$GUEST_IP" ]] || fail "VMware Tools didn't report a guest IP within 240s"

# ---------------------------------------------------------------------
# Phase 5: SSH key gen + paramiko-driven password install
# ---------------------------------------------------------------------
if [[ ! -f "$SSH_KEY" ]]; then
  log "phase 5: generating SSH keypair at $SSH_KEY"
  ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q -C "find-evil-sift-host"
fi

if ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new \
    "${GUEST_USER}@${GUEST_IP}" 'true' >/dev/null 2>&1; then
  log "phase 5: SSH key auth already works — skipping inject"
else
  log "phase 5: installing pubkey via password (paramiko one-shot)"
  "$PYTHON" - "$GUEST_IP" "$GUEST_USER" "$GUEST_PASS" "$SSH_KEY" <<'PY'
import paramiko, sys, pathlib
ip, user, password, key_path = sys.argv[1:]
pubkey = pathlib.Path(key_path + ".pub").read_text().strip()
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(ip, username=user, password=password, timeout=10,
               allow_agent=False, look_for_keys=False)
for cmd in ["mkdir -p ~/.ssh && chmod 700 ~/.ssh",
            f"echo '{pubkey}' >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
            "echo INSTALLED"]:
    _, out, err = client.exec_command(cmd, timeout=10)
    o = out.read().decode().strip()
    if o: print("  " + o)
client.close()
PY
fi

# ---------------------------------------------------------------------
# Phase 6: Sync repo via tar (rsync is not on Git Bash)
# ---------------------------------------------------------------------
log "phase 6: tar | ssh tar repo → ${GUEST_REPO_PATH}"
ssh -i "$SSH_KEY" "${GUEST_USER}@${GUEST_IP}" "rm -rf ${GUEST_REPO_PATH} && mkdir -p ${GUEST_REPO_PATH}"
tar -cz \
  --exclude='target' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='tmp' \
  --exclude='*.evtx' \
  --exclude='*.E01' --exclude='*.e01' \
  --exclude='*.ova' \
  --exclude='.git' \
  --exclude='ref-folders' \
  --exclude='test-forensics' \
  --exclude='fixtures/single-evtx' \
  -f - . \
  | ssh -i "$SSH_KEY" "${GUEST_USER}@${GUEST_IP}" \
    "cd ${GUEST_REPO_PATH} && tar -xz && echo \"  shipped: \$(find . -type f | wc -l) files, \$(du -sh . | cut -f1)\""

# ---------------------------------------------------------------------
# Phase 7: Run sift-vm-setup.sh inside (cargo build, deps, downloads)
# ---------------------------------------------------------------------
log "phase 7: scripts/sift-vm-setup.sh inside the VM (~10 min cold)"
ssh -i "$SSH_KEY" "${GUEST_USER}@${GUEST_IP}" \
    "cd ${GUEST_REPO_PATH} && bash scripts/sift-vm-setup.sh" \
    | tail -40

# ---------------------------------------------------------------------
# Phase 8: Rewrite .mcp.json.sift to use the discovered IP + key path
# ---------------------------------------------------------------------
log "phase 8: rewriting .mcp.json.sift for ${GUEST_USER}@${GUEST_IP}"
"$PYTHON" - "$GUEST_IP" "$SSH_KEY" "$GUEST_USER" "$GUEST_REPO_PATH" <<'PY'
import json, sys, pathlib
ip, key, user, repo = sys.argv[1:]
p = pathlib.Path(".mcp.json.sift")
data = json.loads(p.read_text(encoding="utf-8"))
for name, server in data["mcpServers"].items():
    args = []
    skip = 0
    seen_user_at = False
    for a in server["args"]:
        if skip:
            skip -= 1
            continue
        if a == "-p":
            skip = 1   # drop the port number too
            continue
        if a == "-i":
            args.extend(["-i", key])
            skip = 1
            continue
        if "@" in a and not seen_user_at:
            args.append(f"{user}@{ip}")
            seen_user_at = True
            continue
        if "/home/sansforensics/find-evil" in a:
            args.append(a.replace("/home/sansforensics/find-evil", repo))
            continue
        args.append(a)
    server["args"] = args
p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"  rewrote .mcp.json.sift for {user}@{ip}, key={key}, repo={repo}")
PY

# ---------------------------------------------------------------------
log "================================================================"
log "BOOTSTRAP COMPLETE"
log "  VM name      : $VM_NAME"
log "  VM file      : $VM_VMX"
log "  Guest IP     : $GUEST_IP"
log "  SSH key      : $SSH_KEY"
log "  Repo in VM   : $GUEST_REPO_PATH"
log ""
log "Next: bash scripts/find-evil-sift  →  Claude Code with SIFT-mode MCP"
log "Test SSH directly: ssh -i $SSH_KEY ${GUEST_USER}@${GUEST_IP}"
log "================================================================"
