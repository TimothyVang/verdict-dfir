#!/usr/bin/env bash
# fetch-fixtures.sh — download the L2/L3 fixtures listed in DATASET.md.
#
# Spec #3 §5 + docs/DATASET.md. Never commits fixtures to git —
# .gitignore excludes *.E01, *.ova, *.raw, *.mem, etc. This script
# populates fixtures/ at CI time (cached via actions/cache keyed on
# the SHA-256 manifest).
#
# Each fixture is verified against fixtures/sha256sums.txt. A
# mismatch aborts with clear error; absence (first-pull) appends a
# new line. Subsequent runs become idempotent checksum validations.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

FIXTURES="${FIXTURES:-fixtures}"
SHA_FILE="${FIXTURES}/sha256sums.txt"
mkdir -p "${FIXTURES}"
touch "${SHA_FILE}"

log() { printf '[fetch-fixtures] %s\n' "$*" >&2; }

# Download helper — atomic: downloads to .tmp, checksums, renames.
# fetch_fixture <url> <dest-subpath> <optional-expected-sha256>
fetch_fixture() {
  local url="$1"
  local dest="$2"
  local expected_sha="${3:-}"
  local abs="${FIXTURES}/${dest}"

  mkdir -p "$(dirname "${abs}")"
  if [[ -f "${abs}" ]]; then
    local actual_sha
    actual_sha="$(sha256sum "${abs}" | awk '{print $1}')"
    if grep -q "^${actual_sha}  ${dest}$" "${SHA_FILE}" 2>/dev/null; then
      log "ok: ${dest} (cached, sha verified)"
      return 0
    fi
    if [[ -n "${expected_sha}" ]] && [[ "${actual_sha}" != "${expected_sha}" ]]; then
      log "ERROR: ${dest} sha mismatch. expected=${expected_sha} actual=${actual_sha}"
      exit 1
    fi
  fi

  log "downloading ${url} → ${abs}"
  if ! curl -fsSL --retry 3 --retry-delay 2 --max-time 600 \
    "${url}" -o "${abs}.tmp"; then
    rm -f "${abs}.tmp"
    log "ERROR: failed to download ${url}"
    exit 1
  fi
  mv "${abs}.tmp" "${abs}"

  local got_sha
  got_sha="$(sha256sum "${abs}" | awk '{print $1}')"
  if [[ -n "${expected_sha}" ]] && [[ "${got_sha}" != "${expected_sha}" ]]; then
    log "ERROR: ${dest} downloaded sha mismatch. expected=${expected_sha} got=${got_sha}"
    rm -f "${abs}"
    exit 1
  fi

  # Record in SHA_FILE if not already present.
  if ! grep -q "  ${dest}$" "${SHA_FILE}" 2>/dev/null; then
    echo "${got_sha}  ${dest}" >> "${SHA_FILE}"
  fi
  log "ok: ${dest} (sha=${got_sha})"
}

# ---------------------------------------------------------------------
# 1. SANS starter case data (primary L3 golden — per DATASET.md).
#    The Egnyte URL is the official distribution from the hackathon;
#    it's a public listing page, not a direct file, so we require
#    operators to pre-stage the archive. If SANS_STARTER_URL is set,
#    fetch from there (useful for mirroring).
# ---------------------------------------------------------------------
if [[ -n "${SANS_STARTER_URL:-}" ]]; then
  log "SANS_STARTER_URL set — fetching SANS starter dataset"
  fetch_fixture "${SANS_STARTER_URL}" "sans-starter/sans-starter.zip" \
    "${SANS_STARTER_SHA256:-}"
  if [[ -f "${FIXTURES}/sans-starter/sans-starter.zip" ]]; then
    (cd "${FIXTURES}/sans-starter" && unzip -qo sans-starter.zip || true)
  fi
else
  log "SKIP sans-starter: set SANS_STARTER_URL to a mirror of https://sansorg.egnyte.com/fl/HhH7crTYT4JK"
fi

# ---------------------------------------------------------------------
# 2. NIST CFReDS Hacking Case (~4.5 GB E01). Public domain.
#    The canonical distribution URL is long-lived.
# ---------------------------------------------------------------------
fetch_fixture \
  "https://cfreds-archive.nist.gov/images/hacking-dd/SCHARDT.001" \
  "nist-hacking-case/SCHARDT.001" \
  ""  # sha recorded on first pull

# ---------------------------------------------------------------------
# 3. OTRF Security-Datasets — small EVTX/JSON samples. MIT.
#    Clone sparse (only one dataset family) to stay under ~100 MB.
# ---------------------------------------------------------------------
if [[ ! -d "${FIXTURES}/otrf-apt3-mordor/.git" ]]; then
  log "cloning OTRF Security-Datasets (sparse)..."
  rm -rf "${FIXTURES}/otrf-apt3-mordor"
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/OTRF/Security-Datasets.git \
    "${FIXTURES}/otrf-apt3-mordor"
  (cd "${FIXTURES}/otrf-apt3-mordor" && \
    git sparse-checkout set \
      datasets/atomic/windows/defense_evasion \
      datasets/atomic/windows/credential_access || true)
else
  log "ok: otrf-apt3-mordor already cloned"
fi

# ---------------------------------------------------------------------
# 4. Volatility Foundation memory samples — pick the smallest one.
#    CC-BY; requires attribution (done in DATASET.md).
# ---------------------------------------------------------------------
if ! (
  fetch_fixture \
    "https://downloads.volatilityfoundation.org/volatility3/images/cridex.vmem" \
    "volatility/cridex.vmem" \
    ""
); then
  log "WARN: volatility cridex.vmem mirror unavailable; continuing without optional memory fixture"
fi

# ---------------------------------------------------------------------
# 5. Synthetic benign baseline — generated in-repo on first run.
#    Zero bytes of real data; lives to verify the agent distinguishes
#    clean systems from compromised ones. See DATASET.md §Synthetic.
# ---------------------------------------------------------------------
if [[ ! -f "${FIXTURES}/synthetic-benign/.generated" ]]; then
  mkdir -p "${FIXTURES}/synthetic-benign"
  : > "${FIXTURES}/synthetic-benign/.generated"
  cat > "${FIXTURES}/synthetic-benign/README.md" <<'EOF'
Synthetic benign baseline — generated by `scripts/fetch-fixtures.sh`.

Contents intentionally minimal. The agent's acceptance criterion for
this fixture is that it produces **zero findings** and verdict
`NO_EVIL`. A nonzero result proves hallucination.
EOF
  log "ok: synthetic-benign placeholder written"
fi

# ---------------------------------------------------------------------
# 6. Public DFIR benchmark datasets (Anna Tchijova's verified/ranked list).
#    One scenario per artifact class so we can do live runs against each
#    DFIR artifact type. Ground truth for each lives in
#    goldens/<case-id>/expected-findings.json and is scored offline by
#    scripts/score-recall.py. None are committed to git.
#
#    Two idioms below:
#      - Direct sources (digitalcorpora, NIST CFReDS) have a default URL
#        that env overrides; a failed pull WARNs (does not abort the rest).
#      - Gated sources (archive.org, Dropbox) require an explicit env URL
#        because filenames vary per item; absent -> SKIP with instructions.
#    SHA is recorded on first pull; pin it via <NAME>_SHA256 to enforce.
# ---------------------------------------------------------------------

# 6a. Nitroba University Harassment — network (pcap). GREEN: score against.
NITROBA_URL="${NITROBA_URL:-https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/nitroba.pcap}"
if ! ( fetch_fixture "${NITROBA_URL}" "nitroba/nitroba.pcap" "${NITROBA_SHA256:-}" ); then
  log "WARN: nitroba fetch failed; override with NITROBA_URL=<mirror of https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/>"
fi

# 6b. NIST Data Leakage — disk (insider exfil + anti-forensics). GREEN.
if [[ -n "${DATA_LEAKAGE_URL:-}" ]]; then
  fetch_fixture "${DATA_LEAKAGE_URL}" "nist-data-leakage/data-leakage.zip" \
    "${DATA_LEAKAGE_SHA256:-}"
  if [[ -f "${FIXTURES}/nist-data-leakage/data-leakage.zip" ]]; then
    (cd "${FIXTURES}/nist-data-leakage" && unzip -qo data-leakage.zip || true)
  fi
else
  log "SKIP nist-data-leakage: set DATA_LEAKAGE_URL=<archive of https://cfreds.nist.gov/all/NIST/DataLeakageCase> (multi-file case; stage the packaged image)"
fi

# 6c. M57-Jean — disk/email (CFO spear-phish). ORANGE: practice only.
M57_JEAN_URL="${M57_JEAN_URL:-https://downloads.digitalcorpora.org/corpora/scenarios/m57-jean/jean.aff}"
if ! ( fetch_fixture "${M57_JEAN_URL}" "m57-jean/jean.aff" "${M57_JEAN_SHA256:-}" ); then
  log "WARN: m57-jean fetch failed; override with M57_JEAN_URL=<mirror of https://digitalcorpora.org/corpora/scenarios/m57-jean/>"
fi

# 6d. DFRWS 2008 Linux — memory+disk+network. YELLOW. Shallow git clone.
if [[ ! -d "${FIXTURES}/dfrws-2008-linux/.git" ]]; then
  log "cloning DFRWS 2008 challenge..."
  rm -rf "${FIXTURES}/dfrws-2008-linux"
  git clone --depth 1 https://github.com/dfrws/dfrws2008-challenge.git \
    "${FIXTURES}/dfrws-2008-linux" || log "WARN: dfrws-2008 clone failed"
else
  log "ok: dfrws-2008-linux already cloned"
fi

# 6e-g. Ali Hadi challenges — gated (archive.org item filenames vary per case).
#       Point each <NAME>_URL at the specific archive.org download link.
for spec in \
  "ALIHADI01_URL:alihadi-01-webserver:https://archive.org/details/dfir-case1" \
  "ALIHADI07_URL:alihadi-07-sysinternals:https://archive.org/download/sysinternals-case" \
  "ALIHADI09_URL:alihadi-09-encrypt:https://archive.org/details/anti-forensics-case-2"; do
  var="${spec%%:*}"; rest="${spec#*:}"; name="${rest%%:*}"; page="${rest#*:}"
  url="${!var:-}"
  if [[ -n "${url}" ]]; then
    fetch_fixture "${url}" "${name}/$(basename "${url}")" ""
  else
    log "SKIP ${name}: set ${var}=<direct file link from ${page}>"
  fi
done

# 6h. DFRWS 2011 Android — RED (Dropbox may vanish). Env-gated.
#     TRAP: upstream README hashes are labeled MD5 but are actually SHA1.
#     Recompute MD5+SHA256 on a clean copy; pin via DFRWS2011_SHA256.
if [[ -n "${DFRWS2011_URL:-}" ]]; then
  fetch_fixture "${DFRWS2011_URL}" "dfrws-2011-android/$(basename "${DFRWS2011_URL}")" \
    "${DFRWS2011_SHA256:-}"
else
  log "SKIP dfrws-2011-android: set DFRWS2011_URL=<mirror; upstream Dropbox at https://github.com/dfrws/dfrws2011-challenge> (note: README 'MD5' values are SHA1)"
fi

# 6i. Volatility Cridex — memory. RED for sourcing: canonical link is dead.
#     §4 above already attempts cridex.vmem at fixtures/volatility/. Mirror
#     it into the case-id path so score-recall.py can resolve the golden.
if [[ -n "${CRIDEX_URL:-}" ]]; then
  fetch_fixture "${CRIDEX_URL}" "volatility-cridex/cridex.vmem" "${CRIDEX_SHA256:-}"
elif [[ -f "${FIXTURES}/volatility/cridex.vmem" ]]; then
  mkdir -p "${FIXTURES}/volatility-cridex"
  cp -n "${FIXTURES}/volatility/cridex.vmem" "${FIXTURES}/volatility-cridex/cridex.vmem"
  log "ok: volatility-cridex linked from fixtures/volatility/cridex.vmem"
else
  log "SKIP volatility-cridex: canonical download is dead; set CRIDEX_URL=<verified mirror>"
fi

log "done. See ${SHA_FILE} for checksums."
