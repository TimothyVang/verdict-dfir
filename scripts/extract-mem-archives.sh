#!/usr/bin/env bash
# extract-mem-archives.sh — extract memory-capture archives into a per-host
# layout and verify each image against its embedded dc3dd MD5 (chain of custody).
#
# Each <name>.7z / <name>.zip is extracted into <hosts>/<name>/, the contained
# .img is MD5-checked against the .md5 the archive ships, and the archive is
# removed to reclaim space (the verified .img + .md5 are retained).
#
# Usage:
#   scripts/extract-mem-archives.sh <archives-dir> <hosts-dir>
# Example (SRL-2018):
#   scripts/extract-mem-archives.sh \
#     evidence/cases/srl-2018/mem_archives evidence/cases/srl-2018/hosts
#
# Requires: 7z (p7zip-full), md5sum, numfmt.
set -uo pipefail

ARCH="${1:?usage: extract-mem-archives.sh <archives-dir> <hosts-dir>}"
HOSTS="${2:?usage: extract-mem-archives.sh <archives-dir> <hosts-dir>}"
command -v 7z >/dev/null 2>&1 || { echo "error: 7z not found (apt install p7zip-full)"; exit 2; }
mkdir -p "$HOSTS"
ts() { date -u +%H:%M:%S; }

shopt -s nullglob
for a in "$ARCH"/*.7z "$ARCH"/*.zip; do
  base=$(basename "$a"); stem="${base%.*}"
  dest="$HOSTS/$stem"
  if ls "$dest"/*.img >/dev/null 2>&1; then echo "$(ts) SKIP $stem (img present)"; continue; fi
  mkdir -p "$dest"
  echo "$(ts) EXTRACT $base ..."
  if ! 7z x -y -o"$dest" "$a" >/dev/null 2>&1; then echo "$(ts) FAIL extract $base"; continue; fi
  img=$(ls "$dest"/*.img 2>/dev/null | head -1)
  md5f=$(ls "$dest"/*.md5 2>/dev/null | head -1)
  if [ -z "$img" ]; then echo "$(ts) FAIL no .img in $base"; continue; fi
  if [ -n "$md5f" ]; then
    want=$(grep -oE '[0-9a-f]{32}' "$md5f" | head -1)
    got=$(md5sum "$img" | cut -d' ' -f1)
    [ "$want" = "$got" ] && verdict="MD5_OK" || verdict="MD5_MISMATCH want=$want got=$got"
  else
    verdict="NO_MD5"
  fi
  echo "$(ts) DONE $stem  $(numfmt --to=iec "$(stat -c %s "$img")")  $verdict"
  rm -f "$a"
done

echo "$(ts) EXTRACTION COMPLETE — $(ls -d "$HOSTS"/*/ 2>/dev/null | wc -l) host dir(s)"
