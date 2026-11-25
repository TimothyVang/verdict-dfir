#!/usr/bin/env bash
# sift-vm-setup.sh — runs INSIDE the SIFT Workstation VM after import.
#
# Goal: bring the VM to a state where the Windows host can SSH in and
# spawn our two MCP servers (findevil-mcp + findevil-agent-mcp), with
# all 13 Rust DFIR tools reachable (Volatility3, Hayabusa, Velociraptor,
# YARA already shipped in SIFT; the in-process parsers come with our
# Rust crate). The 12th tool is `vol_psscan` — paired with `vol_pslist`
# for DKOM cross-validation.
#
# This script is idempotent. Re-running after a partial setup picks up
# wherever it left off. It does NOT mutate any /evidence path or any
# pre-existing forensic state — it only adds tooling under the
# sansforensics user's $HOME.
#
# Usage (inside the VM, as the sansforensics user):
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/scripts/sift-vm-setup.sh | bash
# OR after rsync'ing the repo into the VM:
#   bash ~/find-evil/scripts/sift-vm-setup.sh

set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/find-evil}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.88.0}"

log() { printf '[sift-vm-setup] %s\n' "$*" >&2; }
warn() { printf '[sift-vm-setup] WARN: %s\n' "$*" >&2; }
fail() { printf '[sift-vm-setup] FAIL: %s\n' "$*" >&2; exit 1; }

# Sanity: this should be SIFT, not some other Linux. Bail clearly if not.
if ! grep -q 'sift' /etc/issue 2>/dev/null && [[ "${SKIP_SIFT_CHECK:-0}" != "1" ]]; then
  warn "/etc/issue does not mention 'sift' — are you sure this is the SIFT Workstation?"
  warn "Set SKIP_SIFT_CHECK=1 to bypass this check."
fi

# We need to be the sansforensics user (or close enough). The script
# never sudo's on its own — anything privileged is announced and
# requires you to re-run with sudo if needed.
log "running as: $(whoami) in $(pwd)"

# ---------------------------------------------------------------------
# 1. Rustup + the pinned toolchain (1.88.0 per rust-toolchain.toml).
#    SIFT 2026.03.24 ships with rustc 1.75 — too old; clap_builder 4.6
#    needs edition-2024 (Rust ≥1.85). Pull our pinned toolchain via
#    rustup so we don't depend on the OS package version.
# ---------------------------------------------------------------------
if ! command -v rustup >/dev/null 2>&1; then
  log "installing rustup (default profile: minimal, no docs)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    -y --default-toolchain "${RUSTUP_TOOLCHAIN}" --profile minimal --no-modify-path
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
else
  log "rustup already present — ensuring toolchain ${RUSTUP_TOOLCHAIN}"
  rustup install "${RUSTUP_TOOLCHAIN}" --profile minimal --no-self-update
  rustup default "${RUSTUP_TOOLCHAIN}"
fi
# shellcheck disable=SC1091
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

# ---------------------------------------------------------------------
# 2. uv (the Python toolchain we use for services/agent_mcp/).
# ---------------------------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  log "installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # uv installs to ~/.local/bin/uv; make sure it's reachable for this script.
  export PATH="$HOME/.local/bin:$PATH"
fi

# ---------------------------------------------------------------------
# 3. Repo placement. If $REPO_DIR isn't there, bail with instructions
#    rather than guess where the user wants the source.
# ---------------------------------------------------------------------
if [[ ! -d "${REPO_DIR}" ]]; then
  fail "repo not at ${REPO_DIR}. Either:
    - rsync from Windows: rsync -av --exclude target/ --exclude node_modules/ \\
        /path/to/SANS-Hackathon/ sansforensics@<vm>:~/find-evil/
    - or git clone <url> ~/find-evil
    - or set REPO_DIR=/wherever/you/put/it before re-running this script."
fi
cd "${REPO_DIR}"

# ---------------------------------------------------------------------
# 4. Build the Rust MCP server (release for speed; takes ~2-4 min cold,
#    ~5 sec warm via Cargo's incremental cache).
# ---------------------------------------------------------------------
log "cargo build --release -p findevil-mcp..."
cargo build --release -p findevil-mcp --locked

# ---------------------------------------------------------------------
# 5. Sync Python deps for findevil-agent-mcp.
# ---------------------------------------------------------------------
log "uv sync for services/agent_mcp..."
(cd services/agent_mcp && uv sync --frozen 2>/dev/null || uv sync)

# ---------------------------------------------------------------------
# 6. DFIR tool reachability — verify what SIFT provides + flag gaps.
#    SIFT's 2026.03.24 ships Volatility3, YARA, the SleuthKit, log2timeline.
#    Hayabusa and Velociraptor are NOT in SIFT by default; we install
#    them lightly here so the wrapper tools actually function.
# ---------------------------------------------------------------------
log "checking DFIR tool reachability..."

# Volatility 3 — usually pip-installed in SIFT; verify.
if ! command -v vol >/dev/null 2>&1 && ! command -v vol.py >/dev/null 2>&1; then
  log "  installing volatility3 via pip --user..."
  pip3 install --user --quiet volatility3 || warn "vol3 install failed; the agent will get BinaryNotFound for vol_pslist/vol_malfind"
fi
command -v vol >/dev/null 2>&1 && log "  vol: $(command -v vol)" || true
command -v vol.py >/dev/null 2>&1 && log "  vol.py: $(command -v vol.py)" || true

# YARA — almost always present in SIFT.
command -v yara >/dev/null 2>&1 && log "  yara: $(command -v yara)" || warn "  yara absent — yara_scan still works in-process via yara-x crate"

# Sleuthkit (fls/icat/mmls) — ships with SIFT; disk_extract_artifacts reads
# .e01/.dd content directly with it. Verify, apt-install if somehow missing.
if ! command -v fls >/dev/null 2>&1; then
  log "  installing sleuthkit via apt..."
  sudo -n apt-get install -y sleuthkit >/dev/null 2>&1 || warn "  sleuthkit install failed; disk_extract_artifacts on .e01/.dd will fail"
fi
command -v fls >/dev/null 2>&1 && log "  sleuthkit: $(command -v fls)" || true

# nfdump (nfdump_query: NetFlow/IPFIX) — INSTALL-FIRST, absent on stock SIFT.
if ! command -v nfdump >/dev/null 2>&1; then
  log "  installing nfdump via apt..."
  sudo -n apt-get install -y nfdump >/dev/null 2>&1 || warn "  nfdump install failed; the agent will get BinaryNotFound for nfdump_query"
fi
command -v nfdump >/dev/null 2>&1 && log "  nfdump: $(command -v nfdump)" || true

# suricata (suricata_eve: IDS replay on PCAP) — INSTALL-FIRST, absent on stock SIFT.
if ! command -v suricata >/dev/null 2>&1; then
  log "  installing suricata via apt..."
  sudo -n apt-get install -y suricata >/dev/null 2>&1 || warn "  suricata install failed; the agent will get BinaryNotFound for suricata_eve"
fi
command -v suricata >/dev/null 2>&1 && log "  suricata: $(command -v suricata)" || true

# INDXParse (indx_parse: $I30/INDX slack) — INSTALL-FIRST, pip package.
if ! command -v INDXParse.py >/dev/null 2>&1; then
  log "  installing INDXParse via pip --user..."
  pip3 install --user --quiet INDXParse >/dev/null 2>&1 || warn "  INDXParse install failed; the agent will get BinaryNotFound for indx_parse"
fi
command -v INDXParse.py >/dev/null 2>&1 && log "  INDXParse: $(command -v INDXParse.py)" || true

# auditd/ausearch (ausearch: Linux audit.log) — INSTALL-FIRST, absent on stock SIFT.
if ! command -v ausearch >/dev/null 2>&1; then
  log "  installing auditd via apt..."
  sudo -n apt-get install -y auditd >/dev/null 2>&1 || warn "  auditd install failed; the agent will get BinaryNotFound for ausearch"
fi
command -v ausearch >/dev/null 2>&1 && log "  ausearch: $(command -v ausearch)" || true

# Hayabusa — not in SIFT; pull a release binary.
HAYABUSA_VERSION="${HAYABUSA_VERSION:-2.18.0}"
if ! command -v hayabusa >/dev/null 2>&1 && [[ ! -x "$HOME/.local/bin/hayabusa" ]]; then
  log "  installing hayabusa ${HAYABUSA_VERSION}..."
  TMPDIR_HBS="$(mktemp -d)"
  trap 'rm -rf "${TMPDIR_HBS}"' EXIT
  ARCHIVE="hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip"
  if curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${ARCHIVE}" \
      -o "${TMPDIR_HBS}/hbs.zip"; then
    (cd "${TMPDIR_HBS}" && unzip -q hbs.zip)
    install -Dm755 "${TMPDIR_HBS}"/hayabusa-* "$HOME/.local/bin/hayabusa" 2>/dev/null \
      || cp -f "${TMPDIR_HBS}"/hayabusa-* "$HOME/.local/bin/hayabusa"
    chmod +x "$HOME/.local/bin/hayabusa"
    log "    hayabusa → $HOME/.local/bin/hayabusa"
  else
    warn "  hayabusa download failed; the agent will get BinaryNotFound for hayabusa_scan"
  fi
fi
[[ -x "$HOME/.local/bin/hayabusa" ]] && log "  hayabusa: $HOME/.local/bin/hayabusa" || true

# hayabusa ships WITHOUT its Sigma rules. The MCP tool
# (services/mcp/src/tools/hayabusa_scan.rs resolve_rules_base) reads them from
# $XDG_DATA_HOME/hayabusa-mcp/rules (default ~/.local/share/hayabusa-mcp/rules).
# Without them every EVTX/Sigma scan aborts ("required rules and config files
# were not found") and silently returns zero alerts. Fetch into that base.
HAYABUSA_RULES_BASE="${HAYABUSA_RULES_BASE:-${XDG_DATA_HOME:-$HOME/.local/share}/hayabusa-mcp}"
if [[ -d "${HAYABUSA_RULES_BASE}/rules/config" ]]; then
  log "  hayabusa rules present (${HAYABUSA_RULES_BASE}/rules)"
elif [[ -x "$HOME/.local/bin/hayabusa" ]] || command -v hayabusa >/dev/null 2>&1; then
  log "  fetching hayabusa Sigma rules -> ${HAYABUSA_RULES_BASE}/rules ..."
  HB_BIN="$(command -v hayabusa || echo "$HOME/.local/bin/hayabusa")"
  mkdir -p "${HAYABUSA_RULES_BASE}"
  if "${HB_BIN}" update-rules -r "${HAYABUSA_RULES_BASE}/rules" >/dev/null 2>&1 \
     && [[ -d "${HAYABUSA_RULES_BASE}/rules/config" ]]; then
    log "    hayabusa rules -> ${HAYABUSA_RULES_BASE}/rules"
  else
    warn "  hayabusa update-rules failed (needs network; EVTX/Sigma scans return 0 alerts until rules are fetched)"
  fi
fi

# Velociraptor — not in SIFT; pull a release binary.
VELOCIRAPTOR_VERSION="${VELOCIRAPTOR_VERSION:-0.74.6}"
VELOCIRAPTOR_RELEASE="${VELOCIRAPTOR_RELEASE:-0.74}"
if ! command -v velociraptor >/dev/null 2>&1 && [[ ! -x "$HOME/.local/bin/velociraptor" ]]; then
  log "  installing velociraptor ${VELOCIRAPTOR_VERSION} from release ${VELOCIRAPTOR_RELEASE}..."
  if curl -fsSL "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_RELEASE}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-amd64-musl" \
      -o "$HOME/.local/bin/velociraptor"; then
    chmod +x "$HOME/.local/bin/velociraptor"
    log "    velociraptor → $HOME/.local/bin/velociraptor"
  else
    warn "  velociraptor download failed; the agent will get BinaryNotFound for vel_collect"
  fi
fi
[[ -x "$HOME/.local/bin/velociraptor" ]] && log "  velociraptor: $HOME/.local/bin/velociraptor" || true

# ---------------------------------------------------------------------
# 7. Quick build sanity check — actually run the smoke harness once
#    so any environment-specific failure surfaces here, not on the
#    Windows-host's first attempt.
# ---------------------------------------------------------------------
log "running rust-mcp-smoke (proves the binary speaks MCP 2024-11-05)..."
if python3 scripts/rust-mcp-smoke.py --release 2>&1 | tail -3; then
  log "  smoke passed."
else
  warn "  smoke failed — check the output above."
fi

# ---------------------------------------------------------------------
# 8. Done; print the SSH-side .mcp.json snippet the Windows host needs.
# ---------------------------------------------------------------------
log "VM-side setup complete."
cat <<EOF

Next steps, on the Windows host:

  1. Generate an SSH keypair if you don't already have one:
       ssh-keygen -t ed25519 -f ~/.ssh/sift_key

  2. Copy the public key into this VM's authorized_keys:
       cat ~/.ssh/sift_key.pub | ssh -p 2222 sansforensics@localhost \\
         "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

  3. Use the SSH-transport variant of .mcp.json:
       cp .mcp.json.sift .mcp.json   # or: scripts/find-evil-sift

  4. Open Claude Code in the repo on Windows and prompt:
       investigate /home/sansforensics/find-evil/fixtures/single-evtx/Security.evtx

The MCP servers will spawn over SSH inside this VM; you'll see the JSON-RPC
traffic in the .claude session log and the audit chain land in
/home/sansforensics/find-evil/tmp/smoke/local-demo-*/audit.jsonl.
EOF
