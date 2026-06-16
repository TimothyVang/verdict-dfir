#!/usr/bin/env bash
# scripts/install-dfir-tools.sh — install the host-side DFIR binaries the Rust
# MCP server shells out to, for LOCAL-host mode (the default; the SIFT VM and the
# Docker runner image already bundle these).
#
# User-space only: everything lands in ~/.local/bin (no sudo). Idempotent (skips
# anything already resolvable) and best-effort (a failed download warns and
# continues — a missing tool degrades to a clean BinaryNotFound the agent pivots
# on, never a crash). Tool versions are pinned below for reproducibility.
#
# pcap tooling (tshark) needs a system package; it is reported as an apt hint
# rather than installed, to avoid a sudo prompt. Override any version via env
# (e.g. HAYABUSA_VERSION=2.20.0 bash scripts/install-dfir-tools.sh).
#
# Run standalone or via scripts/install.sh. Safe to re-run any time to top up.

set -uo pipefail

c_grn=$'\033[0;32m'; c_yel=$'\033[0;33m'; c_blu=$'\033[0;34m'; c_off=$'\033[0m'
ok()   { echo "${c_grn}[OK]${c_off}    $*"; }
info() { echo "${c_blu}[INFO]${c_off}  $*"; }
warn() { echo "${c_yel}[WARN]${c_off}  $*"; }

LOCAL_BIN="${HOME}/.local/bin"
mkdir -p "${LOCAL_BIN}"
# Remember whether ~/.local/bin was already reachable, then make it reachable for
# the resolves below.
case ":${PATH}:" in *":${LOCAL_BIN}:"*) BIN_ON_PATH=1 ;; *) BIN_ON_PATH=0 ;; esac
export PATH="${LOCAL_BIN}:${PATH}"

HAYABUSA_VERSION="${HAYABUSA_VERSION:-2.19.0}"
CHAINSAW_VERSION="${CHAINSAW_VERSION:-2.13.0}"
VOLATILITY_VERSION="${VOLATILITY_VERSION:-2.11.0}"
VELOCIRAPTOR_VERSION="${VELOCIRAPTOR_VERSION:-0.74.6}"
VELOCIRAPTOR_RELEASE="${VELOCIRAPTOR_RELEASE:-0.74}"
PANDOC_VERSION="${PANDOC_VERSION:-3.1.11.1}"

have() { command -v "$1" >/dev/null 2>&1; }

# --- volatility3 (memory analysis) — pip --user ---
if have vol || have vol.py || have volatility3; then
  ok "volatility3 present ($(command -v vol vol.py volatility3 2>/dev/null | head -1))."
else
  info "Installing volatility3 ${VOLATILITY_VERSION} (pip --user)..."
  if pip3 install --user --quiet "volatility3==${VOLATILITY_VERSION}"; then
    ok "volatility3 installed."
  else
    warn "volatility3 install failed — try: uv tool install volatility3"
  fi
fi

# --- hayabusa (EVTX / Sigma) — release zip; unzip drops the exec bit ---
if have hayabusa || [ -x "${LOCAL_BIN}/hayabusa" ]; then
  ok "hayabusa present."
else
  info "Installing hayabusa ${HAYABUSA_VERSION}..."
  t="$(mktemp -d)"
  if curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" -o "${t}/h.zip" \
     && unzip -q "${t}/h.zip" -d "${t}"; then
    hb="$(find "${t}" -maxdepth 2 -name 'hayabusa-*-lin-x64-gnu' -type f | head -1)"
    if [ -n "${hb}" ]; then install -Dm755 "${hb}" "${LOCAL_BIN}/hayabusa" && ok "hayabusa -> ${LOCAL_BIN}/hayabusa"
    else warn "hayabusa binary not found in archive."; fi
  else
    warn "hayabusa download/extract failed (optional; EVTX/Sigma scans will BinaryNotFound)."
  fi
  rm -rf "${t}"
fi

# --- hayabusa Sigma rules (the binary ships WITHOUT them) ---
# hayabusa reads its rules + config from `./rules` relative to CWD. The MCP
# (services/mcp/src/tools/hayabusa_scan.rs) runs hayabusa with CWD set to this
# base dir, so populate `<base>/rules` here. Without it every EVTX/Sigma scan
# fails ("Cannot open file [rules/config/...]") and the lane reads as broken.
HAYABUSA_RULES_BASE="${HAYABUSA_RULES_BASE:-${XDG_DATA_HOME:-${HOME}/.local/share}/hayabusa-mcp}"
if [ -d "${HAYABUSA_RULES_BASE}/rules/config" ]; then
  ok "hayabusa rules present (${HAYABUSA_RULES_BASE}/rules)."
elif have hayabusa || [ -x "${LOCAL_BIN}/hayabusa" ]; then
  info "Fetching hayabusa Sigma rules -> ${HAYABUSA_RULES_BASE}/rules ..."
  hb_bin="$(command -v hayabusa || echo "${LOCAL_BIN}/hayabusa")"
  mkdir -p "${HAYABUSA_RULES_BASE}"
  if "${hb_bin}" update-rules -r "${HAYABUSA_RULES_BASE}/rules" >/dev/null 2>&1 \
     && [ -d "${HAYABUSA_RULES_BASE}/rules/config" ]; then
    ok "hayabusa rules -> ${HAYABUSA_RULES_BASE}/rules"
  else
    warn "hayabusa update-rules failed (needs network; EVTX/Sigma scans will degrade until rules are fetched)."
  fi
fi

# --- chainsaw (EVTX hunting) — release zip ---
if have chainsaw || [ -x "${LOCAL_BIN}/chainsaw" ]; then
  ok "chainsaw present."
else
  info "Installing chainsaw ${CHAINSAW_VERSION}..."
  t="$(mktemp -d)"
  if curl -fsSL "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_all_platforms+rules.zip" -o "${t}/c.zip" \
     && unzip -q "${t}/c.zip" -d "${t}"; then
    cs="$(find "${t}" -name 'chainsaw_x86_64-unknown-linux-gnu' -type f | head -1)"
    if [ -n "${cs}" ]; then install -Dm755 "${cs}" "${LOCAL_BIN}/chainsaw" && ok "chainsaw -> ${LOCAL_BIN}/chainsaw"
    else warn "chainsaw binary not found in archive."; fi
  else
    warn "chainsaw download/extract failed (optional; EVTX hunting will BinaryNotFound)."
  fi
  rm -rf "${t}"
fi

# --- velociraptor (collection) — single static binary ---
if have velociraptor || [ -x "${LOCAL_BIN}/velociraptor" ]; then
  ok "velociraptor present."
else
  info "Installing velociraptor ${VELOCIRAPTOR_VERSION}..."
  if curl -fsSL "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_RELEASE}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-amd64-musl" -o "${LOCAL_BIN}/velociraptor"; then
    chmod +x "${LOCAL_BIN}/velociraptor"; ok "velociraptor -> ${LOCAL_BIN}/velociraptor"
  else
    rm -f "${LOCAL_BIN}/velociraptor"; warn "velociraptor download failed (optional; vel_collect will BinaryNotFound)."
  fi
fi

# --- pandoc (report HTML/PDF render) — static tarball ---
if have pandoc || [ -x "${LOCAL_BIN}/pandoc" ]; then
  ok "pandoc present."
else
  info "Installing pandoc ${PANDOC_VERSION}..."
  t="$(mktemp -d)"
  if curl -fsSL "https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz" -o "${t}/p.tgz" \
     && tar -xzf "${t}/p.tgz" -C "${t}"; then
    pd="$(find "${t}" -type f -name pandoc -path '*/bin/*' | head -1)"
    if [ -n "${pd}" ]; then install -Dm755 "${pd}" "${LOCAL_BIN}/pandoc" && ok "pandoc -> ${LOCAL_BIN}/pandoc"
    else warn "pandoc binary not found in archive."; fi
  else
    warn "pandoc download/extract failed (optional; report HTML render skipped)."
  fi
  rm -rf "${t}"
fi

# --- matplotlib (report figures in scripts/render_report.py) — pip --user ---
# Host-side only: render_report runs in find_evil_auto.py on the host in BOTH
# local and --sift modes, so the SIFT VM never needs it. Without it the report
# still renders (text/HTML/PDF) but every figure is skipped.
if python3 -c 'import matplotlib' >/dev/null 2>&1; then
  ok "matplotlib present ($(python3 -c 'import matplotlib as m; print(m.__version__)' 2>/dev/null))."
else
  info "Installing matplotlib (pip --user; report figures)..."
  if pip3 install --user --quiet matplotlib; then
    ok "matplotlib installed."
  else
    warn "matplotlib install failed — try: pip3 install --user --break-system-packages matplotlib (or use a venv). Report figures will be skipped."
  fi
fi

# --- INDXParse ($I30 / INDX slack) — pip --user ---
# Provides INDXParse.py on ~/.local/bin for the indx_parse tool.
if have INDXParse.py; then
  ok "INDXParse present."
else
  info "Installing INDXParse (pip --user; indx_parse \$I30/INDX slack)..."
  if pip3 install --user --quiet INDXParse; then
    ok "INDXParse installed."
  else
    warn "INDXParse install failed — try: pip3 install --user --break-system-packages INDXParse. indx_parse will BinaryNotFound."
  fi
fi

# --- plaso / log2timeline (super-timeline) — pip --user, best-effort ---
# plaso pulls heavy low-level deps (libyal); on a stock host pip can fail to build
# them. It ships on the SANS SIFT VM. Best-effort: try pip --user, otherwise point
# at the SIFT VM / GIFT PPA. A miss degrades to a clean BinaryNotFound on plaso_parse.
if have log2timeline.py && have psort.py; then
  ok "plaso present (log2timeline.py/psort.py)."
else
  info "Installing plaso (pip --user; best-effort)..."
  if pip3 install --user --quiet plaso; then
    ok "plaso installed."
  else
    warn "plaso pip install failed (heavy native deps). It ships on the SANS SIFT VM; on a host use the GIFT PPA: sudo add-apt-repository ppa:gift/stable && sudo apt-get install -y plaso-tools. plaso_parse will BinaryNotFound until then."
  fi
fi

# --- Eric Zimmerman tools (ez_parse: LNK/Amcache/ShimCache/RecycleBin/shellbags) ---
# The cross-platform .NET 6 port needs the dotnet runtime; no clean user-space
# installer across distros, so it is reported, not auto-installed. Ships on SIFT.
if [ -n "${EZTOOLS_DIR:-}" ] || have LECmd || have AmcacheParser; then
  ok "EZ tools present."
else
  warn "EZ tools absent (ez_parse). They ship on the SANS SIFT VM; on a host install the .NET 6 build from https://ericzimmerman.github.io and set \$EZTOOLS_DIR (or add to PATH)."
fi

# --- mac_apt (mac_triage: macOS image triage) ---
# A Python project (git clone + pytsk3/native deps), not a clean pip package, so
# it is reported, not auto-installed. Ships on the SANS SIFT VM.
if [ -n "${MAC_APT:-}" ] || have mac_apt.py || have mac_apt; then
  ok "mac_apt present."
else
  warn "mac_apt absent (mac_triage). It ships on the SANS SIFT VM; on a host clone github.com/ydkhatri/mac_apt and set \$MAC_APT to mac_apt.py (or add to PATH)."
fi

# --- tshark (pcap_triage) — system package; not user-space installable ---
if have tshark; then
  ok "tshark present."
else
  warn "tshark absent (pcap_triage only). System package: sudo apt-get install -y tshark"
fi

# --- sleuthkit (disk_extract_artifacts / disk_mount) — system package ---
# fls/icat read .e01/.dd content directly; mmls resolves the partition offset.
# Without it, disk evidence stays custody-only (no registry/MFT/prefetch).
if have fls && have icat && have mmls; then
  ok "sleuthkit present (fls/icat/mmls)."
else
  warn "sleuthkit absent (disk_extract_artifacts on .e01/.dd → custody-only). System package: sudo apt-get install -y sleuthkit"
fi

echo
if [ "${BIN_ON_PATH}" -eq 0 ]; then
  warn "${LOCAL_BIN} is not on your PATH — claude/doctor won't find these tools."
  echo "    Add to your shell rc:  export PATH=\"\$HOME/.local/bin:\$PATH\""
else
  ok "DFIR tool install pass complete (${LOCAL_BIN} on PATH)."
fi
