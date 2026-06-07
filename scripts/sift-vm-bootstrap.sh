#!/usr/bin/env bash
# sift-vm-bootstrap.sh — one-time SIFT VM setup. Cross-platform.
#
# Idempotent. Re-running picks up where it left off.
#
# A fresh user drops the SANS SIFT Workstation OVA at the repo root and runs this
# (directly, or via scripts/install.sh, which offers it when an OVA is present).
# It converts/imports the OVA, boots the VM, installs an SSH key, syncs the repo
# in, builds the MCP server inside, and rewrites .mcp.json.sift to point at it.
#
# Three backends, auto-detected (override with SIFT_BACKEND=...):
#
#   windows-vmware  Git Bash on Windows + VMware Workstation (the original path;
#                   hardcoded vmrun.exe/ovftool.exe under C:\Program Files).
#   linux-vmware    Linux + VMware Workstation (vmrun/ovftool on PATH). Primary
#                   Linux path — matches the repo's documented hypervisor. Loads
#                   the vmmon/vmnet kernel modules via sudo vmware-modconfig if
#                   they aren't already up.
#   linux-libvirt   Linux without VMware — falls back to KVM/libvirt (apt-install
#                   qemu/libvirt/virtinst, convert OVA→qcow2, virt-install import).
#                   Best-effort/new: SIFT expects VMware Tools, so the guest IP
#                   comes from the DHCP lease, not a guest agent; SIFT_VM_IP=<ip>
#                   is the manual override.
#
# Shared sequence once the VM is up (all backends, empirically derived):
#   5. SSH key gen + paramiko one-shot password install (vmrun/virsh file copy is
#      unreliable against this SIFT image — paramiko drops the pubkey reliably).
#   6. Repo sync via tar | ssh tar (rsync isn't guaranteed on Git Bash).
#   7. Run scripts/sift-vm-setup.sh inside the VM (cargo build, uv, DFIR tools).
#   8. Rewrite .mcp.json.sift to the discovered IP + key + repo path.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
VM_NAME="${VM_NAME:-Find-Evil-SIFT}"
SSH_KEY="${SSH_KEY:-${SIFT_SSH_KEY:-$HOME/.ssh/sift_key}}"
GUEST_USER="${GUEST_USER:-sansforensics}"
GUEST_PASS="${GUEST_PASS:-forensics}"
GUEST_REPO_PATH="${GUEST_REPO_PATH:-/home/sansforensics/find-evil}"
GUEST_IP="${SIFT_VM_IP:-}"   # populated by the per-backend IP discovery

log()  { printf '[bootstrap] %s\n' "$*" >&2; }
warn() { printf '[bootstrap] WARN: %s\n' "$*" >&2; }
fail() { printf '[bootstrap] FAIL: %s\n' "$*" >&2; exit 1; }

# Convert a Unix path to a Windows path (only used by the windows-vmware backend).
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
# OS + backend detection
# ---------------------------------------------------------------------
case "$(uname -s)" in
  Linux)                 OS=linux ;;
  MINGW*|MSYS*|CYGWIN*)  OS=windows ;;
  *)                     OS=other ;;
esac

BACKEND="${SIFT_BACKEND:-}"
if [[ -z "$BACKEND" ]]; then
  if [[ "$OS" == "windows" ]]; then
    BACKEND="windows-vmware"
  elif command -v vmrun >/dev/null 2>&1 && command -v ovftool >/dev/null 2>&1; then
    BACKEND="linux-vmware"
  else
    BACKEND="linux-libvirt"
  fi
fi

# Per-OS VM working directory (libvirt uses the default image pool instead).
if [[ "$OS" == "windows" ]]; then
  VM_DIR="${VM_DIR:-$HOME/Documents/Virtual Machines/${VM_NAME}}"
else
  VM_DIR="${VM_DIR:-$HOME/vmware/${VM_NAME}}"
fi
VM_VMX="${VM_DIR}/${VM_NAME}.vmx"

log "os=${OS} backend=${BACKEND} vm=${VM_NAME}"

# ---------------------------------------------------------------------
# OVA discovery: honor $OVA_PATH, else largest sift-*.ova, else any *.ova.
# ---------------------------------------------------------------------
resolve_ova() {
  if [[ -n "${OVA_PATH:-}" ]]; then
    [[ -f "$OVA_PATH" ]] || fail "OVA_PATH set but not found: $OVA_PATH"
    echo "$OVA_PATH"; return
  fi
  local cand
  cand="$(ls -S "${REPO_ROOT}"/sift-*.ova 2>/dev/null | head -1 || true)"
  [[ -z "$cand" ]] && cand="$(ls -S "${REPO_ROOT}"/*.ova 2>/dev/null | head -1 || true)"
  [[ -n "$cand" ]] || fail "No OVA found in ${REPO_ROOT}.
  The SANS SIFT Workstation OVA is not shipped in this repo (SANS-licensed,
  ~9.3 GB, gitignored). Download it from:
    https://www.sans.org/tools/sift-workstation/
  Save it as ${REPO_ROOT}/sift-<version>.ova (or set OVA_PATH=/path/to/your.ova)."
  echo "$cand"
}

# ---------------------------------------------------------------------
# Phase 0: shared prereqs — python3 + paramiko (for the key install).
# ---------------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 \
  || fail "python required for paramiko key install"
PYTHON="$(command -v python3 || command -v python)"
if ! "$PYTHON" -c "import paramiko" 2>/dev/null; then
  log "phase 0: installing paramiko (one-time)..."
  "$PYTHON" -m pip install --quiet --user paramiko 2>/dev/null \
    || "$PYTHON" -m pip install --quiet --user --break-system-packages paramiko 2>/dev/null \
    || fail "could not install paramiko. Install it manually: ${PYTHON} -m pip install --user paramiko"
fi

# =====================================================================
# Backend: windows-vmware  (unchanged behavior)
# =====================================================================
provision_windows_vmware() {
  local VMRUN="${VMRUN:-/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe}"
  local OVFTOOL="${OVFTOOL:-/c/Program Files (x86)/VMware/VMware Workstation/OVFTool/ovftool.exe}"
  [[ -f "$VMRUN" ]]   || fail "vmrun.exe not found at $VMRUN (install VMware Workstation)"
  [[ -f "$OVFTOOL" ]] || fail "ovftool not found at $OVFTOOL (ships with VMware Workstation)"
  local OVA; OVA="$(resolve_ova)"
  mkdir -p "$VM_DIR"

  if [[ -f "$VM_VMX" ]]; then
    log "phase 1: VMX exists at $VM_VMX — skipping conversion"
  else
    log "phase 1: ovftool $OVA → $VM_VMX (~5-10 min, ~10 GB written)"
    "$OVFTOOL" --acceptAllEulas --name="$VM_NAME" \
      "$(to_winpath "$OVA")" "$(to_winpath "$VM_VMX")"
    log "  conversion done."
  fi

  local VMX_WIN; VMX_WIN="$(to_winpath "$VM_VMX")"
  if "$VMRUN" -T ws list | grep -qF "$VMX_WIN"; then
    log "phase 3: VM already running"
  else
    log "phase 3: starting VM headless..."
    "$VMRUN" -T ws start "$VMX_WIN" nogui
  fi

  log "phase 4: waiting for VMware Tools (up to 240s)..."
  local i ip
  for i in $(seq 1 120); do
    ip="$("$VMRUN" -T ws getGuestIPAddress "$VMX_WIN" 2>/dev/null || true)"
    if [[ -n "$ip" && "$ip" != "unknown" && "$ip" != *Error* ]]; then
      GUEST_IP="$ip"; log "  guest IP: $GUEST_IP (after ~$((i*2))s)"; break
    fi
    sleep 2
  done
  [[ -n "$GUEST_IP" ]] || fail "VMware Tools didn't report a guest IP within 240s"
}

# =====================================================================
# Backend: linux-vmware  (VMware Workstation on Linux — primary)
# =====================================================================
ensure_vmware_modules() {
  # Read /proc/modules directly — robust to PATH not having /usr/sbin (lsmod),
  # which happens in detached/non-login shells (e.g. install.sh under nohup).
  if grep -qE '^vmmon ' /proc/modules 2>/dev/null; then
    log "  vmware kernel modules already loaded"
    return 0
  fi
  warn "vmware kernel modules (vmmon/vmnet) not loaded — building them (needs sudo)."
  command -v vmware-modconfig >/dev/null 2>&1 \
    || fail "vmware-modconfig not found though vmrun is present — reinstall VMware Workstation."
  if sudo vmware-modconfig --console --install-all; then
    log "  vmware modules built + loaded."
  else
    fail "vmware-modconfig failed. Common causes:
  - Secure Boot enabled: unsigned vmmon/vmnet are rejected. Disable Secure Boot
    in firmware, or sign the modules (mokutil), then re-run.
  - Missing kernel headers: sudo apt-get install -y linux-headers-\$(uname -r)
  Then re-run: bash scripts/sift-vm-bootstrap.sh"
  fi
}

provision_linux_vmware() {
  local VMRUN OVFTOOL OVA
  VMRUN="$(command -v vmrun)"
  OVFTOOL="$(command -v ovftool)"
  OVA="$(resolve_ova)"
  mkdir -p "$VM_DIR"

  if [[ -f "$VM_VMX" ]]; then
    log "phase 1: VMX exists at $VM_VMX — skipping conversion"
  else
    log "phase 1: ovftool $OVA → $VM_VMX (~5-10 min, ~18 GB written)"
    "$OVFTOOL" --acceptAllEulas --name="$VM_NAME" "$OVA" "$VM_VMX"
    log "  conversion done."
  fi

  ensure_vmware_modules

  if "$VMRUN" -T ws list | grep -qF "$VM_VMX"; then
    log "phase 3: VM already running"
  else
    log "phase 3: starting VM headless..."
    "$VMRUN" -T ws start "$VM_VMX" nogui
  fi

  # IP: explicit override > VMware Tools (-wait blocks until reported) > dhcp lease.
  if [[ -n "$GUEST_IP" ]]; then
    log "phase 4: using SIFT_VM_IP override: $GUEST_IP"
  else
    log "phase 4: waiting for VMware Tools IP (getGuestIPAddress -wait, up to 300s)..."
    local ip
    ip="$(timeout 300 "$VMRUN" -T ws getGuestIPAddress "$VM_VMX" -wait 2>/dev/null || true)"
    if [[ -n "$ip" && "$ip" != "unknown" && "$ip" != *[Ee]rror* ]]; then
      GUEST_IP="$ip"
    else
      ip="$(read_vmware_dhcp_lease || true)"
      [[ -n "$ip" ]] && GUEST_IP="$ip"
    fi
    [[ -n "$GUEST_IP" ]] \
      || fail "no guest IP from VMware Tools. Find it (vmrun -T ws getGuestIPAddress \"$VM_VMX\" -wait, or your DHCP leases) and re-run with SIFT_VM_IP=<ip>."
    log "  guest IP: $GUEST_IP"
  fi
}

# Best-effort: last lease in the VMware NAT dhcpd lease file. SIFT_VM_IP is the
# reliable override; this is only a convenience when -wait times out.
read_vmware_dhcp_lease() {
  local leases=/etc/vmware/vmnet8/dhcpd/dhcpd.leases
  [[ -r "$leases" ]] || return 0
  awk '/^lease /{ip=$2} END{if(ip!="")print ip}' "$leases" 2>/dev/null || true
}

# =====================================================================
# Backend: linux-libvirt  (KVM/libvirt fallback — best-effort)
# =====================================================================
ensure_libvirt_tools() {
  local missing=()
  command -v virsh >/dev/null 2>&1        || missing+=(libvirt-clients)
  command -v virt-install >/dev/null 2>&1 || missing+=(virtinst)
  command -v qemu-img >/dev/null 2>&1     || missing+=(qemu-utils)
  command -v qemu-system-x86_64 >/dev/null 2>&1 || missing+=(qemu-system-x86 libvirt-daemon-system)
  if (( ${#missing[@]} )); then
    warn "installing KVM/libvirt tools (needs sudo): ${missing[*]}"
    sudo apt-get update -y && sudo apt-get install -y "${missing[@]}" \
      || fail "apt-get install failed for: ${missing[*]}. Install them manually and re-run."
  fi
  # Bring up the default NAT network (carries DHCP for the guest IP).
  if sudo virsh net-info default >/dev/null 2>&1; then
    sudo virsh net-start default     >/dev/null 2>&1 || true
    sudo virsh net-autostart default >/dev/null 2>&1 || true
  else
    warn "libvirt 'default' NAT network is not defined. The guest may not get an IP."
    warn "  Define it: sudo virsh net-define /usr/share/libvirt/networks/default.xml && sudo virsh net-start default"
  fi
}

provision_linux_libvirt() {
  warn "linux-libvirt is the fallback path (no VMware Workstation found). SIFT targets"
  warn "  VMware Tools, so the guest IP comes from the DHCP lease; if discovery fails,"
  warn "  re-run with SIFT_VM_IP=<ip>."
  ensure_libvirt_tools
  local OVA disk; OVA="$(resolve_ova)"
  disk="/var/lib/libvirt/images/${VM_NAME}.qcow2"

  if sudo virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    log "phase 1: libvirt domain '$VM_NAME' already defined — skipping import"
  else
    if ! sudo test -f "$disk"; then
      log "phase 1: extracting OVA + converting VMDK → qcow2 (~5-10 min)"
      local work vmdk; work="$(mktemp -d)"
      tar -xf "$OVA" -C "$work" || { rm -rf "$work"; fail "could not extract OVA $OVA"; }
      vmdk="$(ls -S "$work"/*.vmdk 2>/dev/null | head -1 || true)"
      [[ -n "$vmdk" ]] || { rm -rf "$work"; fail "no VMDK inside OVA $OVA"; }
      sudo qemu-img convert -p -O qcow2 "$vmdk" "$disk" \
        || { rm -rf "$work"; fail "qemu-img convert failed for $vmdk"; }
      rm -rf "$work"
    fi
    log "phase 1: defining + importing libvirt domain '$VM_NAME'"
    sudo virt-install --connect qemu:///system --import \
      --name "$VM_NAME" --memory 4096 --vcpus 4 \
      --disk "path=${disk},format=qcow2,bus=virtio" \
      --os-variant ubuntu22.04 \
      --network network=default,model=virtio \
      --graphics none --noautoconsole \
      || fail "virt-install failed. You may need to import the OVA manually via virt-manager,
  then re-run with SIFT_VM_IP=<ip>."
  fi

  local state; state="$(sudo virsh domstate "$VM_NAME" 2>/dev/null || echo unknown)"
  if [[ "$state" != "running" ]]; then
    log "phase 3: starting domain '$VM_NAME'..."
    sudo virsh start "$VM_NAME" || true
  else
    log "phase 3: domain already running"
  fi

  if [[ -n "$GUEST_IP" ]]; then
    log "phase 4: using SIFT_VM_IP override: $GUEST_IP"
  else
    log "phase 4: waiting for DHCP lease (up to 120s)..."
    local i ip
    for i in $(seq 1 60); do
      ip="$(sudo virsh -q domifaddr "$VM_NAME" --source lease 2>/dev/null \
            | awk '/ipv4/{gsub(/\/[0-9]+/,"",$4); print $4; exit}')"
      [[ -z "$ip" ]] && ip="$(sudo virsh -q net-dhcp-leases default 2>/dev/null \
            | awk '/ipv4/{gsub(/\/[0-9]+/,"",$5); print $5; exit}')"
      if [[ -n "$ip" ]]; then GUEST_IP="$ip"; log "  guest IP (lease): $GUEST_IP"; break; fi
      sleep 2
    done
    [[ -n "$GUEST_IP" ]] \
      || fail "no DHCP lease for '$VM_NAME' within 120s. Find it (sudo virsh net-dhcp-leases default) and re-run with SIFT_VM_IP=<ip>."
  fi
}

# ---------------------------------------------------------------------
# Provision: dispatch on backend → leaves the VM running with $GUEST_IP set.
# ---------------------------------------------------------------------
case "$BACKEND" in
  windows-vmware) provision_windows_vmware ;;
  linux-vmware)   provision_linux_vmware ;;
  linux-libvirt)  provision_linux_libvirt ;;
  *)              fail "unknown SIFT_BACKEND='$BACKEND' (expected windows-vmware|linux-vmware|linux-libvirt)" ;;
esac

# =====================================================================
# Shared phases 5–8 (backend-independent: need only $GUEST_IP + SSH).
# =====================================================================

# ---------------------------------------------------------------------
# Phase 5: SSH key gen + paramiko-driven password install
# ---------------------------------------------------------------------
if [[ ! -f "$SSH_KEY" ]]; then
  log "phase 5: generating SSH keypair at $SSH_KEY"
  mkdir -p "$(dirname "$SSH_KEY")"
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
# Phase 6: Sync repo via tar (rsync is not guaranteed on Git Bash).
# Excludes build caches, the .git dir, reference clones, and — critically —
# evidence/ and any disk images, so the multi-GB evidence vault is never shipped.
# ---------------------------------------------------------------------
log "phase 6: tar | ssh tar repo → ${GUEST_REPO_PATH}"
ssh -i "$SSH_KEY" "${GUEST_USER}@${GUEST_IP}" "rm -rf ${GUEST_REPO_PATH} && mkdir -p ${GUEST_REPO_PATH}"
tar -cz \
  --exclude='target' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='tmp' \
  --exclude='evidence' \
  --exclude='*.evtx' \
  --exclude='*.E01' --exclude='*.e01' \
  --exclude='*.dd' --exclude='*.img' --exclude='*.raw' --exclude='*.mem' \
  --exclude='*.ova' --exclude='*.vmdk' --exclude='*.qcow2' \
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
log "  backend      : $BACKEND"
log "  VM name      : $VM_NAME"
[[ "$BACKEND" == *vmware ]] && log "  VM file      : $VM_VMX"
log "  Guest IP     : $GUEST_IP"
log "  SSH key      : $SSH_KEY"
log "  Repo in VM   : $GUEST_REPO_PATH"
log ""
log "Next: bash scripts/find-evil-sift  →  Claude Code with SIFT-mode MCP"
log "      or: FIND_EVIL_GUEST_IP=$GUEST_IP bash scripts/verdict --sift <evidence-in-vm>"
log "Test SSH directly: ssh -i $SSH_KEY ${GUEST_USER}@${GUEST_IP}"
log "================================================================"
