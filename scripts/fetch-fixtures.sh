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

log() { printf '[fetch-fixtures] %s\n' "$*" >&2; }

# Hard separation: benchmark fixtures must NEVER land in the evidence/ drop zone.
# evidence/ is the ad-hoc, human-driven investigation directory (gitignored to
# README + .gitkeep); fixtures/ is the scored benchmark corpus paired 1:1 with
# goldens/<case-id>/. Staging a benchmark dataset into evidence/ would orphan it
# from its golden and the l3-run-goldens scoring loop. Enforce it rather than
# trust convention: resolve FIXTURES and abort if it points at evidence/.
_fixtures_abs="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=False))' "${FIXTURES}")"
_evidence_abs="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=False))' "${REPO_ROOT}/evidence")"
case "${_fixtures_abs}/" in
  "${_evidence_abs}/"*)
    log "ERROR: FIXTURES (${FIXTURES}) resolves under evidence/. Benchmark fixtures"
    log "       must live in fixtures/, paired with goldens/<case-id>/. Unset FIXTURES"
    log "       or point it outside evidence/."
    exit 1
    ;;
esac

SHA_FILE="${FIXTURES}/sha256sums.txt"
mkdir -p "${FIXTURES}"
touch "${SHA_FILE}"

safe_url_label() {
  python3 - "$1" <<'PY'
from pathlib import PurePosixPath
from urllib.parse import urlsplit
import sys

url = sys.argv[1]
parts = urlsplit(url)
if not parts.scheme:
    print("<local-path>")
elif parts.scheme == "file":
    print(f"file://.../{PurePosixPath(parts.path).name}")
else:
    host = parts.hostname or "<host>"
    name = PurePosixPath(parts.path).name
    print(f"{parts.scheme}://{host}/{name}" if name else f"{parts.scheme}://{host}/")
PY
}

manifest_sha_for_dest() {
  local dest="$1"
  awk -v dest="${dest}" '$2 == dest { print $1; found = 1; exit } END { if (!found) exit 1 }' \
    "${SHA_FILE}" 2>/dev/null || true
}

record_sha_for_dest() {
  local sha="$1"
  local dest="$2"
  local tmp_sha
  tmp_sha="$(mktemp "${SHA_FILE}.XXXXXX")"
  awk -v dest="${dest}" '$2 != dest' "${SHA_FILE}" > "${tmp_sha}" || true
  printf '%s  %s\n' "${sha}" "${dest}" >> "${tmp_sha}"
  mv "${tmp_sha}" "${SHA_FILE}"
}

remove_sha_for_dest() {
  local dest="$1"
  local tmp_sha
  tmp_sha="$(mktemp "${SHA_FILE}.XXXXXX")"
  awk -v dest="${dest}" '$2 != dest' "${SHA_FILE}" > "${tmp_sha}" || true
  mv "${tmp_sha}" "${SHA_FILE}"
}

extract_zip_fixture() {
  local zip_path="$1"
  local target_dir="$2"
  local parent base zip_name tmp_dir backup_dir

  if [[ ! -f "${zip_path}" ]]; then
    log "ERROR: zip fixture not found: ${zip_path}"
    exit 1
  fi

  parent="$(dirname "${target_dir}")"
  base="$(basename "${target_dir}")"
  zip_name="$(basename "${zip_path}")"
  tmp_dir="$(mktemp -d "${parent}/.${base}.extract.XXXXXX")"
  backup_dir="${target_dir}.previous.$$"

  if ! ln "${zip_path}" "${tmp_dir}/${zip_name}" 2>/dev/null; then
    cp -p "${zip_path}" "${tmp_dir}/${zip_name}"
  fi

  if ! python3 - "${zip_path}" "${tmp_dir}" "${zip_name}" <<'PY'
from pathlib import PurePosixPath
import stat
import sys
import zipfile

zip_path = sys.argv[1]
target_dir = sys.argv[2]
zip_name = sys.argv[3]

with zipfile.ZipFile(zip_path) as archive:
    for info in archive.infolist():
        raw = info.filename
        normalized = raw.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not normalized or normalized.startswith("/") or path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe zip member path: {raw}")
        if path.parts and path.parts[0] == zip_name:
            raise SystemExit(f"zip member would overwrite staged archive: {raw}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode in {stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK}:
            raise SystemExit(f"unsafe zip member type: {raw}")
    archive.extractall(target_dir)
PY
  then
    rm -rf "${tmp_dir}"
    log "ERROR: unsafe or invalid zip fixture: ${zip_path}"
    exit 1
  fi

  if [[ -d "${target_dir}" ]]; then
    rm -rf "${backup_dir}"
    mv "${target_dir}" "${backup_dir}"
  fi
  if mv "${tmp_dir}" "${target_dir}"; then
    rm -rf "${backup_dir}"
    log "ok: extracted ${zip_name} into ${target_dir}"
  else
    rm -rf "${tmp_dir}"
    if [[ -d "${backup_dir}" ]]; then
      mv "${backup_dir}" "${target_dir}"
    fi
    log "ERROR: failed to replace extracted fixture directory: ${target_dir}"
    exit 1
  fi
}

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
    local manifest_sha
    manifest_sha="$(manifest_sha_for_dest "${dest}")"
    if [[ -n "${expected_sha}" ]] && [[ "${actual_sha}" != "${expected_sha}" ]]; then
      log "ERROR: ${dest} sha mismatch. expected=${expected_sha} actual=${actual_sha}"
      exit 1
    fi
    if [[ -n "${manifest_sha}" && "${actual_sha}" != "${manifest_sha}" ]]; then
      log "ERROR: ${dest} cached sha mismatch. manifest=${manifest_sha} actual=${actual_sha}"
      log "       remove the stale fixture or update the pinned source intentionally."
      exit 1
    fi
    if [[ -n "${manifest_sha}" ]]; then
      log "ok: ${dest} (cached, sha verified)"
      return 0
    fi
    if [[ -n "${expected_sha}" ]]; then
      record_sha_for_dest "${actual_sha}" "${dest}"
      log "ok: ${dest} (cached, pinned sha verified)"
      return 0
    fi
    record_sha_for_dest "${actual_sha}" "${dest}"
    log "ok: ${dest} (cached, sha recorded)"
    return 0
  fi

  local url_label
  url_label="$(safe_url_label "${url}")"
  log "downloading ${url_label} → ${abs}"
  if ! curl -fsSL --retry 3 --retry-delay 2 --max-time 600 \
    "${url}" -o "${abs}.tmp"; then
    rm -f "${abs}.tmp"
    log "ERROR: failed to download ${url_label}"
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

  local existing_sha
  existing_sha="$(manifest_sha_for_dest "${dest}")"
  if [[ -n "${existing_sha}" && "${existing_sha}" != "${got_sha}" && -z "${expected_sha}" ]]; then
    log "ERROR: ${dest} downloaded sha differs from manifest. manifest=${existing_sha} got=${got_sha}"
    log "       set an expected SHA-256 or remove the stale manifest entry intentionally."
    rm -f "${abs}"
    exit 1
  fi
  record_sha_for_dest "${got_sha}" "${dest}"
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
  if [[ -z "${SANS_STARTER_SHA256:-}" ]]; then
    log "ERROR: SANS_STARTER_URL is set but SANS_STARTER_SHA256 is missing. Pin the archive SHA-256 before extraction."
    exit 1
  fi
  log "SANS_STARTER_URL set — fetching SANS starter dataset"
  fetch_fixture "${SANS_STARTER_URL}" "sans-starter/sans-starter.zip" \
    "${SANS_STARTER_SHA256}"
  if [[ -f "${FIXTURES}/sans-starter/sans-starter.zip" ]]; then
    extract_zip_fixture "${FIXTURES}/sans-starter/sans-starter.zip" "${FIXTURES}/sans-starter"
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
#    Clone sparse Windows atomic telemetry plus the compound APT3 bundle.
# ---------------------------------------------------------------------
OTRF_SECURITY_DATASETS_REF="${OTRF_SECURITY_DATASETS_REF:-d9d40ef123d2c87d5d3df28c96bcab4f0faccc87}"
if [[ ! "${OTRF_SECURITY_DATASETS_REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
  log "ERROR: OTRF_SECURITY_DATASETS_REF must be a full 40-hex commit SHA, got ${OTRF_SECURITY_DATASETS_REF}"
  exit 1
fi
OTRF_PATHS=(
  datasets/compound/windows/apt3
  datasets/atomic/windows/defense_evasion
  datasets/atomic/windows/credential_access
  datasets/atomic/windows/lateral_movement
  datasets/atomic/windows/persistence
)
if [[ ! -d "${FIXTURES}/otrf-apt3-mordor/.git" ]]; then
  log "cloning OTRF Security-Datasets (sparse)..."
  rm -rf "${FIXTURES}/otrf-apt3-mordor"
  git clone --filter=blob:none --sparse \
    https://github.com/OTRF/Security-Datasets.git \
    "${FIXTURES}/otrf-apt3-mordor"
else
  log "updating OTRF Security-Datasets sparse checkout..."
fi
(cd "${FIXTURES}/otrf-apt3-mordor" && \
  git fetch --depth 1 origin "${OTRF_SECURITY_DATASETS_REF}" && \
  git checkout --detach FETCH_HEAD && \
  git sparse-checkout set "${OTRF_PATHS[@]}")

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
# 5b. Synthetic DECOY case — generated in-repo on first run. Companion to
#     synthetic-benign: instead of a clean baseline, it plants BENIGN
#     artifacts whose names/content LOOK malicious (a benign text file named
#     like a hacking tool, a DNS lookup to a known sinkhole, a benign archive
#     named 'passwords'). Zero bytes of real malware. The acceptance criterion
#     is that a correct run surfaces the benign decoys WITHOUT escalating —
#     verdict NO_EVIL (or honest INDETERMINATE) with ZERO reportable findings.
#     Escalating any decoy (naming the mimicked malware, calling the sinkhole
#     lookup C2, calling the archive exfil) is planted-bait false positive and
#     fails the run via goldens/synthetic-decoy/expected-findings.json
#     (known_negatives + named_claim_denylist, scored by scripts/score-recall.py
#     as fp_planted). Content is fixed so the per-file SHA-256 is deterministic
#     and pinnable in fixtures/sha256sums.txt like every other fixture.
# ---------------------------------------------------------------------
if [[ ! -f "${FIXTURES}/synthetic-decoy/.generated" ]]; then
  mkdir -p "${FIXTURES}/synthetic-decoy/Users/decoy/Desktop"
  mkdir -p "${FIXTURES}/synthetic-decoy/Users/decoy/Documents"
  # Benign file literally named like a hacking tool — plain text, not a PE.
  cat > "${FIXTURES}/synthetic-decoy/Users/decoy/Desktop/mimikatz.exe" <<'EOF'
This is NOT the mimikatz tool. It is a plain-text decoy named to look like a
credential-dumping binary. There is no PE header, no code, and no execution
artifact (no prefetch, amcache, or process). Presence of this name alone is
not execution proof and must not be reported as credential dumping.
EOF
  # Benign reading notes whose name references a named C2 framework.
  cat > "${FIXTURES}/synthetic-decoy/Users/decoy/Desktop/cobalt-strike-notes.txt" <<'EOF'
Personal study notes about the Cobalt Strike framework. This is a topic label
in a filename, not a beacon, payload, or named-pipe channel. It must not be
escalated to a Cobalt Strike implant or C2 finding.
EOF
  # Benign DNS lookup to a documented sinkhole / parked resolver — a non-event.
  cat > "${FIXTURES}/synthetic-decoy/decoy-dns.log" <<'EOF'
2024-01-02T03:04:05Z query A sinkhole.example.invalid -> 0.0.0.0 (NXDOMAIN sink)
A resolution to a known sinkhole / parked domain is benign. It is not beaconing
and must not be called C2 or command-and-control traffic.
EOF
  # Benign archive named 'passwords' holding only the user's own non-secret notes.
  cat > "${FIXTURES}/synthetic-decoy/Users/decoy/Documents/passwords.txt" <<'EOF'
Reminder list of websites I keep accounts on (no actual secrets). An archive or
file named 'passwords' is not staging, collection, or exfiltration. No network
movement of this file is present in the case.
EOF
  if command -v zip >/dev/null 2>&1; then
    # Pin the member mtime so the zip is byte-deterministic across generations
    # (zip embeds the file's modification time); -X strips extra attributes.
    ( cd "${FIXTURES}/synthetic-decoy/Users/decoy/Documents" && \
      touch -d "2024-01-01T00:00:00Z" passwords.txt && \
      TZ=UTC zip -X -q passwords.zip passwords.txt && rm -f passwords.txt )
  else
    mv "${FIXTURES}/synthetic-decoy/Users/decoy/Documents/passwords.txt" \
       "${FIXTURES}/synthetic-decoy/Users/decoy/Documents/passwords.zip"
    log "WARN: zip not found; wrote passwords.zip as plain text placeholder"
  fi
  cat > "${FIXTURES}/synthetic-decoy/README.md" <<'EOF'
Synthetic DECOY case — generated by `scripts/fetch-fixtures.sh`.

Every artifact here is BENIGN but deliberately named/worded to look malicious:
a plain-text file named `mimikatz.exe`, a `cobalt-strike-notes.txt`, a DNS log
showing a lookup to a known sinkhole, and a `passwords.zip`. None exhibit any
actual malicious behaviour.

Acceptance criterion: a correct run surfaces the benign decoys WITHOUT
escalating — verdict `NO_EVIL` (or honest `INDETERMINATE`) with ZERO reportable
findings. Asserting credential dumping, C2/beaconing, or data exfiltration from
these lookalikes is planted-bait false-positive hallucination and FAILS the run
(see `goldens/synthetic-decoy/expected-findings.json` + `scripts/score-recall.py`
`fp_planted`).
EOF
  : > "${FIXTURES}/synthetic-decoy/.generated"
  log "ok: synthetic-decoy planted-bait fixture written"
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
  if [[ -z "${DATA_LEAKAGE_SHA256:-}" ]]; then
    log "ERROR: DATA_LEAKAGE_URL is set but DATA_LEAKAGE_SHA256 is missing. Pin the archive SHA-256 before extraction."
    exit 1
  fi
  fetch_fixture "${DATA_LEAKAGE_URL}" "nist-data-leakage/data-leakage.zip" \
    "${DATA_LEAKAGE_SHA256}"
  if [[ -f "${FIXTURES}/nist-data-leakage/data-leakage.zip" ]]; then
    extract_zip_fixture "${FIXTURES}/nist-data-leakage/data-leakage.zip" "${FIXTURES}/nist-data-leakage"
  fi
else
  log "SKIP nist-data-leakage: set DATA_LEAKAGE_URL=<archive of https://cfreds.nist.gov/all/NIST/DataLeakageCase> (multi-file case; stage the packaged image)"
fi

# 6c. M57-Jean — disk/email (CFO spear-phish). ORANGE: practice only.
M57_JEAN_URL="${M57_JEAN_URL:-https://downloads.digitalcorpora.org/corpora/scenarios/m57-jean/jean.aff}"
if ! ( fetch_fixture "${M57_JEAN_URL}" "m57-jean/jean.aff" "${M57_JEAN_SHA256:-}" ); then
  log "WARN: m57-jean fetch failed; override with M57_JEAN_URL=<mirror of https://digitalcorpora.org/corpora/scenarios/m57-jean/>"
fi

# 6d. DFRWS 2008 Linux — memory+disk+network. YELLOW. Sparse pinned clone.
DFRWS2008_REF="${DFRWS2008_REF:-af9a3ebcfebcfedf8791e1b3bbaf0c70183c6927}"
if [[ ! "${DFRWS2008_REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
  log "ERROR: DFRWS2008_REF must be a full 40-hex commit SHA, got ${DFRWS2008_REF}"
  exit 1
fi
if [[ ! -d "${FIXTURES}/dfrws-2008-linux/.git" ]]; then
  log "cloning DFRWS 2008 challenge..."
  rm -rf "${FIXTURES}/dfrws-2008-linux"
  git clone --filter=blob:none --no-checkout https://github.com/dfrws/dfrws2008-challenge.git \
    "${FIXTURES}/dfrws-2008-linux" || log "WARN: dfrws-2008 clone failed"
else
  log "updating DFRWS 2008 challenge pinned checkout..."
fi
if [[ -d "${FIXTURES}/dfrws-2008-linux/.git" ]]; then
  (cd "${FIXTURES}/dfrws-2008-linux" && \
    git fetch --depth 1 origin "${DFRWS2008_REF}" && \
    git checkout --detach FETCH_HEAD)
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

# 6j-l. MemLabs Lab 1-3 — Windows memory CTF labs. Mega.nz links in the
#       upstream README are browser-oriented and not reliable curl targets, so
#       operators should extract the upstream archive and provide a direct URL
#       or file:// URL to the memory dump itself. These are metadata/flag-count
#       goldens; actual flag values are intentionally not committed.
#       Required env pairs when enabled: MEMLABS_LAB1_URL + MEMLABS_LAB1_SHA256,
#       MEMLABS_LAB2_URL + MEMLABS_LAB2_SHA256, MEMLABS_LAB3_URL + MEMLABS_LAB3_SHA256.
for spec in \
  "MEMLABS_LAB1_URL:memlabs-lab1:b9fec1a443907d870cb32b048bda9380" \
  "MEMLABS_LAB2_URL:memlabs-lab2:ddb337936a75153822baed718851716b" \
  "MEMLABS_LAB3_URL:memlabs-lab3:ce4e7adc4efbf719888d2c87256d1da3"; do
  var="${spec%%:*}"; rest="${spec#*:}"; name="${rest%%:*}"; expected_md5="${rest##*:}"
  url="${!var:-}"
  if [[ -n "${url}" ]]; then
    sha_var="${var/_URL/_SHA256}"
    expected_sha="${!sha_var:-}"
    if [[ -z "${expected_sha}" ]]; then
      log "ERROR: ${var} is set but ${sha_var} is missing. Compute SHA-256 from the extracted memory dump before staging ${name}."
      exit 1
    fi
    dest="${name}/$(basename "${url%%\?*}")"
    fetch_fixture "${url}" "${dest}" "${expected_sha}"
    if command -v md5sum >/dev/null 2>&1; then
      got_md5="$(md5sum "${FIXTURES}/${dest}" | awk '{print $1}')"
    elif command -v md5 >/dev/null 2>&1; then
      got_md5="$(md5 -q "${FIXTURES}/${dest}")"
    else
      log "ERROR: ${name} requires md5sum or md5 to verify the staged memory dump"
      rm -f "${FIXTURES}/${dest}"
      remove_sha_for_dest "${dest}"
      exit 1
    fi
    if [[ "${got_md5}" != "${expected_md5}" ]]; then
      log "ERROR: ${name} memory dump MD5 mismatch. expected=${expected_md5} got=${got_md5}"
      rm -f "${FIXTURES}/${dest}"
      remove_sha_for_dest "${dest}"
      exit 1
    fi
  else
    log "SKIP ${name}: set ${var}=<extracted memory dump direct/file:// URL> and ${var/_URL/_SHA256}=<sha256>; memory dump MD5=${expected_md5}"
  fi
done

# 6m. Digital Corpora 2018 Lone Wolf — Windows E01 + memory + pagefile.
#     Large (~32GB full bundle) and teacher-guide-gated for official answers, so
#     it is opt-in only. Point LONEWOLF_URL at the full image bundle that includes
#     disk segments, memdump.mem, and pagefile.sys.
if [[ -n "${LONEWOLF_URL:-}" ]]; then
  if [[ -z "${LONEWOLF_SHA256:-}" ]]; then
    log "ERROR: LONEWOLF_URL is set but LONEWOLF_SHA256 is missing. Pin the full bundle SHA-256 before staging."
    exit 1
  fi
  fetch_fixture "${LONEWOLF_URL}" "digitalcorpora-lonewolf/$(basename "${LONEWOLF_URL%%\?*}")" \
    "${LONEWOLF_SHA256}"
else
  log "SKIP digitalcorpora-lonewolf: set LONEWOLF_URL=<full direct/file:// bundle> and LONEWOLF_SHA256=<sha256> from https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/"
fi

# 6n. Public DFIR backlog candidates — opt-in only.
#     These are strong direct/hashable dataset candidates from the backlog, not
#     scoreable goldens until matching docs/goldens/<case-id>/ entries are added.
#     Point each <NAME>_URL at the exact archive/sample to stage and pin the
#     same file with <NAME>_SHA256; no bulky evidence is pulled by default.
for spec in \
  "DFRWS2023_TROUBLED_ELEVATOR:dfrws-2023-troubled-elevator:https://dfrws.org/forensic-challenges/" \
  "M57_PATENTS:m57-patents:https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/" \
  "DC_2012_NGDC:digitalcorpora-2012-ngdc:https://digitalcorpora.org/corpora/scenarios/2012-ngdc/" \
  "DC_2019_NARCOS:digitalcorpora-2019-narcos:https://digitalcorpora.org/corpora/scenarios/2019-narcos/" \
  "DC_2019_OWL:digitalcorpora-2019-owl:https://digitalcorpora.org/corpora/scenarios/2019-owl/" \
  "DC_2019_TUCK:digitalcorpora-2019-tuck:https://digitalcorpora.org/corpora/scenarios/2019-tuck/" \
  "MTA_PCAP:malware-traffic-analysis:https://www.malware-traffic-analysis.net/" \
  "NETRESEC_PCAP:netresec-public-pcap:https://www.netresec.com/?page=PcapFiles" \
  "MEMLABS_LAB4:memlabs-lab4:https://github.com/stuxnet999/MemLabs" \
  "MEMLABS_LAB5:memlabs-lab5:https://github.com/stuxnet999/MemLabs" \
  "MEMLABS_LAB6:memlabs-lab6:https://github.com/stuxnet999/MemLabs"; do
  name="${spec%%:*}"
  rest="${spec#*:}"
  case_id="${rest%%:*}"
  source_hint="${rest#*:}"
  url_var="${name}_URL"
  sha_var="${name}_SHA256"
  url="${!url_var:-}"
  expected_sha="${!sha_var:-}"

  if [[ -z "${url}" ]]; then
    log "SKIP ${case_id}: set ${url_var}=... and ${sha_var}=... from ${source_hint}"
    continue
  fi
  if [[ -z "${expected_sha}" ]]; then
    log "ERROR: ${url_var} is set but ${sha_var} is missing. Pin the direct fixture SHA-256 before staging ${case_id} from ${source_hint}."
    exit 1
  fi
  fetch_fixture "${url}" "${case_id}/$(basename "${url%%\?*}")" "${expected_sha}"
done

log "done. See ${SHA_FILE} for checksums."
