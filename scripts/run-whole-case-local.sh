#!/usr/bin/env bash
# run-whole-case-local.sh — run scripts/verdict on every host of a staged
# multi-host case, locally (no SIFT VM), and emit a whole-case verdict table.
#
# It enumerates three kinds of targets under the case root:
#   <root>/hosts/<host>/        -> one memory-image case per host
#   <root>/disks/*.E01          -> one disk case per E01 (passed as a file path)
#   <out>/_xartifact/<name>/    -> derived cross-artifact case (disk + memory)
# It also runs standalone base-file disk/memory targets and an output-staged
# xart:base-file pair automatically when the SRL-2018 base-file pair is present.
#
# Each target is run with: verdict --no-dashboard --unattended --skip-build.
# Per-host run-summaries are captured so the script is RESUMABLE (a host whose
# summary already exists is skipped). A final table prints verdict + the offline
# manifest_verify result for every host.
#
# Usage:
#   scripts/run-whole-case-local.sh <case-root> [out-dir]
# Example (SRL-2018):
#   scripts/run-whole-case-local.sh evidence/cases/srl-2018
set -uo pipefail

usage() {
  echo "Usage: scripts/run-whole-case-local.sh <case-root> [out-dir]"
  echo "Example: scripts/run-whole-case-local.sh evidence/cases/srl-2018"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ $# -lt 1 ]; then
  usage >&2
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$1"
if ! ROOT="$(cd "$ROOT" && pwd)"; then
  echo "case root does not exist: $1" >&2
  exit 2
fi
OUT="${2:-$REPO/tmp/whole-case-local/$(basename "$ROOT")}"
ts() { date -u +%H:%M:%S; }

# --- build the target list: "label<TAB>path" ---
TARGETS=()
TARGETS_FILE="$OUT/targets.tsv"
TMP_TARGETS="$(mktemp "${TMPDIR:-/tmp}/whole-case-targets.XXXXXX")" || exit 1
cleanup_targets_tmp() { rm -f "$TMP_TARGETS"; }
trap cleanup_targets_tmp EXIT
python3 "$REPO/scripts/whole_case_targets.py" "$ROOT" "$OUT" > "$TMP_TARGETS" || exit $?
mkdir -p "$OUT"
mv "$TMP_TARGETS" "$TARGETS_FILE" || exit $?
trap - EXIT
while IFS=$'\t' read -r label path; do
  [ -n "$label" ] || continue
  TARGETS+=("$label	$path")
done < "$TARGETS_FILE"

[ ${#TARGETS[@]} -eq 0 ] && { echo "no targets under $ROOT (expected hosts/, disks/, or base-file pair)"; exit 1; }
echo "$(ts) whole-case local run — ${#TARGETS[@]} targets  (out: $OUT)"
RESULTS="$OUT/results.jsonl"; : > "$RESULTS"
failed=0

i=0
for entry in "${TARGETS[@]}"; do
  i=$((i + 1))
  label="${entry%%	*}"; path="${entry##*	}"
  safe=$(printf '%s' "$label" | tr ':/ ' '___')
  summ="$OUT/$safe.run-summary.json"
  run_status=0
  if [ -s "$summ" ]; then
    echo "$(ts) [$i/${#TARGETS[@]}] SKIP $label (done)"
  else
    echo "$(ts) [$i/${#TARGETS[@]}] RUN  $label  ($path)"
    if bash "$REPO/scripts/verdict" "$path" --no-dashboard --unattended --skip-build \
      --run-summary "$summ" > "$OUT/$safe.log" 2>&1; then
      run_status=0
    else
      run_status=$?
      failed=1
    fi
    echo "$(ts)        exit=$run_status -> $summ"
  fi
  if [ ! -s "$summ" ]; then
    echo "$(ts)        missing run summary for $label" >&2
    failed=1
    python3 - "$label" "$run_status" "$RESULTS" <<'PY'
import json, sys
label, status, res = sys.argv[1:4]
row = {"host": label, "verdict": "ERROR", "exit_code": int(status)}
open(res, "a").write(json.dumps(row) + "\n")
PY
    continue
  fi
  if ! python3 - "$label" "$summ" "$RESULTS" <<'PY'
import json, sys
label, summ, res = sys.argv[1:4]
status = 0
try:
    r = json.load(open(summ)).get("result", {})
    row = {"host": label, "verdict": r.get("verdict"),
           "manifest_ok": r.get("manifest_verify_overall"),
           "packet": r.get("packet_state"), "case_dir": r.get("local_dir")}
    if row.get("manifest_ok") is not True:
        status = 3
except Exception as e:
    row = {"host": label, "verdict": "ERROR", "error": str(e)}
    status = 3
open(res, "a").write(json.dumps(row) + "\n")
sys.exit(status)
PY
  then
    echo "$(ts)        manifest verification failed for $label" >&2
    failed=1
  fi
done

echo "$(ts) WHOLE-CASE RUN COMPLETE"
# Make this dir correlate-ready: fleet.json in the shape fleet_correlate reads.
python3 "$REPO/scripts/fleet_local.py" "$OUT" || true
echo "=== TABLE ==="
python3 - "$RESULTS" <<'PY'
import json, sys
from collections import Counter
rows = [json.loads(l) for l in open(sys.argv[1])]
w = max((len(r["host"]) for r in rows), default=8)
print(f'{"HOST":<{w}}  {"VERDICT":<14} {"MANIFEST":<9} PACKET')
for r in sorted(rows, key=lambda x: x["host"]):
    print(f'{r["host"]:<{w}}  {str(r.get("verdict")):<14} {str(r.get("manifest_ok")):<9} {r.get("packet", "")}')
print("\nverdict tally:", dict(Counter(r.get("verdict") for r in rows)))
print("manifest_ok:", sum(1 for r in rows if r.get("manifest_ok") is True), "/", len(rows))
PY

rows=$(wc -l < "$RESULTS" | tr -d ' ')
if [ "$rows" -ne "${#TARGETS[@]}" ]; then
  echo "$(ts) whole-case local run incomplete: $rows/${#TARGETS[@]} result rows" >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  echo "$(ts) whole-case local run failed" >&2
  exit 1
fi
