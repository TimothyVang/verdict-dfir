#!/usr/bin/env bash
# run-whole-case-local.sh — run scripts/verdict on every host of a staged
# multi-host case, locally (no SIFT VM), and emit a whole-case verdict table.
#
# It enumerates three kinds of targets under the case root:
#   <root>/hosts/<host>/        -> one memory-image case per host
#   <root>/disks/*.E01          -> one disk case per E01 (passed as a file path)
#   <root>/_xartifact/<name>/   -> cross-artifact case (disk + memory together)
# It also runs a <root>/_xartifact/base-file pair automatically if base-file's
# disk + memory sit at the case root (the SRL-2018 layout).
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

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${1:?usage: run-whole-case-local.sh <case-root> [out-dir]}"
ROOT="$(cd "$ROOT" && pwd)"
OUT="${2:-$REPO/tmp/whole-case-local/$(basename "$ROOT")}"
mkdir -p "$OUT"
ts() { date -u +%H:%M:%S; }

# --- build the target list: "label<TAB>path" ---
TARGETS=()
shopt -s nullglob
for d in "$ROOT"/hosts/*/; do TARGETS+=("mem:$(basename "$d")	$d"); done
# cross-artifact: hardlink base-file disk+memory into its own dir if present
if [ -e "$ROOT/base-file-cdrive.E01" ] && [ -e "$ROOT/base-file-memory.img" ]; then
  XDIR="$ROOT/_xartifact/base-file"; mkdir -p "$XDIR"
  [ -e "$XDIR/base-file-cdrive.E01" ] || ln "$ROOT/base-file-cdrive.E01" "$XDIR/" 2>/dev/null || cp -l "$ROOT/base-file-cdrive.E01" "$XDIR/"
  [ -e "$XDIR/base-file-memory.img" ] || ln "$ROOT/base-file-memory.img" "$XDIR/" 2>/dev/null || cp -l "$ROOT/base-file-memory.img" "$XDIR/"
  TARGETS+=("xart:base-file	$XDIR")
fi
for e in "$ROOT"/disks/*.E01; do TARGETS+=("disk:$(basename "$e" .E01)	$e"); done

[ ${#TARGETS[@]} -eq 0 ] && { echo "no targets under $ROOT (expected hosts/, disks/, or base-file pair)"; exit 1; }
echo "$(ts) whole-case local run — ${#TARGETS[@]} targets  (out: $OUT)"
RESULTS="$OUT/results.jsonl"; : > "$RESULTS"

i=0
for entry in "${TARGETS[@]}"; do
  i=$((i + 1))
  label="${entry%%	*}"; path="${entry##*	}"
  safe=$(echo "$label" | tr ':/ ' '___')
  summ="$OUT/$safe.run-summary.json"
  if [ -s "$summ" ]; then
    echo "$(ts) [$i/${#TARGETS[@]}] SKIP $label (done)"
  else
    echo "$(ts) [$i/${#TARGETS[@]}] RUN  $label  ($path)"
    bash "$REPO/scripts/verdict" "$path" --no-dashboard --unattended --skip-build \
      --run-summary "$summ" > "$OUT/$safe.log" 2>&1
    echo "$(ts)        exit=$? -> $summ"
  fi
  [ -s "$summ" ] && python3 - "$label" "$summ" "$RESULTS" <<'PY'
import json, sys
label, summ, res = sys.argv[1:4]
try:
    r = json.load(open(summ)).get("result", {})
    row = {"host": label, "verdict": r.get("verdict"),
           "manifest_ok": r.get("manifest_verify_overall"),
           "packet": r.get("packet_state"), "case_dir": r.get("local_dir")}
except Exception as e:
    row = {"host": label, "verdict": "ERROR", "error": str(e)}
open(res, "a").write(json.dumps(row) + "\n")
PY
done

echo "$(ts) WHOLE-CASE RUN COMPLETE"
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
