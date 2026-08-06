#!/usr/bin/env bash
# scripts/carve-probe-status.sh — honest status for a free-space carve probe.
#
# Never prints a recall percentage. Never claims any carving improvement without a
# scored golden match (this script does not implement golden scoring).
#
# Exit codes:
#   0 — STATUS=UNMEASURED or STATUS=PARTIAL_PROBE_UNMEASURED
#   1 — STATUS=ERROR (tool failure when a probe was attempted)
#
# Image selection, in order:
#   1. First positional argument
#   2. FINDEVIL_CARVE_IMAGE
# No image-specific default: with no image configured the script skips cleanly
# (STATUS=UNMEASURED, exit 0) so it stays evidence-agnostic and never no-ops
# silently against one hard-coded image.
#
# Probe controls:
#   FINDEVIL_CARVE_SKIP_PROBE=1     — only check prerequisites; do not run bulk_extractor
#   FINDEVIL_CARVE_PROBE_MB=512     — MiB to sample from the start of a larger image
#                                     (default 512, minimum 16)
#   FINDEVIL_CARVE_PROBE_TIMEOUT=180 — seconds to allow bulk_extractor (default 180,
#                                     minimum 30)
#
# A larger FINDEVIL_CARVE_PROBE_MB can make the partial probe less shallow. It
# still does not become a recall measurement, and this script still exits
# STATUS=UNMEASURED or STATUS=PARTIAL_PROBE_UNMEASURED unless the tool fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

have_bin=0
have_img=0
bin_path=""
img_path=""

if command -v bulk_extractor >/dev/null 2>&1; then
  have_bin=1
  bin_path="$(command -v bulk_extractor)"
fi

for cand in \
  "${1:-}" \
  "${FINDEVIL_CARVE_IMAGE:-}"
do
  if [ -n "${cand}" ] && [ -f "${cand}" ]; then
    have_img=1
    img_path="${cand}"
    break
  fi
done

echo "carve-probe-status"
echo "  bulk_extractor: $([ "$have_bin" = 1 ] && echo "yes ($bin_path)" || echo "no")"
echo "  carve_image:    $([ "$have_img" = 1 ] && echo "yes ($img_path)" || echo "no (pass a path or set FINDEVIL_CARVE_IMAGE)")"
echo "  note: synthetic carve smoke is separate (bulk_extract_smoke); this script never claims recall %"
echo "  scorer: none; probe rows are diagnostic-only and are not golden matches"

if [ "$have_bin" != 1 ] || [ "$have_img" != 1 ]; then
  echo "STATUS=UNMEASURED"
  echo "reason: missing prerequisites for an end-to-end carve measurement"
  exit 0
fi

if [ "${FINDEVIL_CARVE_SKIP_PROBE:-0}" = "1" ]; then
  echo "STATUS=UNMEASURED"
  echo "reason: prerequisites present but FINDEVIL_CARVE_SKIP_PROBE=1 (no probe run)"
  exit 0
fi

probe_mb="${FINDEVIL_CARVE_PROBE_MB:-512}"
if ! [[ "${probe_mb}" =~ ^[0-9]+$ ]] || [ "${probe_mb}" -lt 16 ]; then
  probe_mb=512
fi
timeout_s="${FINDEVIL_CARVE_PROBE_TIMEOUT:-180}"
if ! [[ "${timeout_s}" =~ ^[0-9]+$ ]] || [ "${timeout_s}" -lt 30 ]; then
  timeout_s=180
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Large images: sample only the first FINDEVIL_CARVE_PROBE_MB so the status gate
# stays operator-friendly. This is explicitly a partial probe.
img_size="$(wc -c <"${img_path}" | tr -d ' ')"
sample="${tmp}/sample.dd"
need_bytes=$((probe_mb * 1024 * 1024))
if [ "${img_size}" -gt "${need_bytes}" ]; then
  echo "  probe_sample: first ${probe_mb} MiB of ${img_size} byte image (partial probe; not a score)"
  dd if="${img_path}" of="${sample}" bs=1M count="${probe_mb}" status=none 2>/dev/null \
    || dd if="${img_path}" of="${sample}" bs=1048576 count="${probe_mb}" 2>/dev/null
  probe_img="${sample}"
  probe_was_partial=1
else
  echo "  probe_sample: full image (${img_size} bytes; still unscored)"
  probe_img="${img_path}"
  probe_was_partial=0
fi

# Broad probe terms only. Matching rows are not interpreted as a golden hit.
patterns_file="${tmp}/patterns.txt"
printf '%s\n' 'intrusion' 'email' 'outlook' 'plan' 'hacking' >"${patterns_file}"

set +e
if command -v timeout >/dev/null 2>&1; then
  timeout "${timeout_s}" bulk_extractor -q -j 1 -o "${tmp}/out" -E find \
    -F "${patterns_file}" -- "${probe_img}" >"${tmp}/probe.log" 2>&1
  rc=$?
else
  bulk_extractor -q -j 1 -o "${tmp}/out" -E find \
    -F "${patterns_file}" -- "${probe_img}" >"${tmp}/probe.log" 2>&1
  rc=$?
fi
set -e

if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
  echo "STATUS=UNMEASURED"
  echo "reason: bulk_extractor probe timed out after ${timeout_s}s (partial sample; measurement not completed)"
  exit 0
fi
if [ "$rc" -ne 0 ]; then
  echo "STATUS=ERROR"
  echo "reason: bulk_extractor exited ${rc}"
  tail -8 "${tmp}/probe.log" 2>/dev/null || true
  exit 1
fi

feat_lines=0
if [ -f "${tmp}/out/find.txt" ]; then
  feat_lines="$(grep -cv '^#' "${tmp}/out/find.txt" 2>/dev/null || echo 0)"
fi
echo "  probe_find_rows: ${feat_lines}"
if [ "${probe_was_partial}" = "1" ]; then
  echo "STATUS=PARTIAL_PROBE_UNMEASURED"
  echo "reason: partial find probe finished; no golden scorer was run"
else
  echo "STATUS=UNMEASURED"
  echo "reason: find probe finished; no golden scorer was run"
fi
exit 0
