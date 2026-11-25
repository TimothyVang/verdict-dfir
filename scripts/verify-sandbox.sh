#!/usr/bin/env bash
# verify-sandbox.sh — end-to-end sandbox verification harness.
#
# Spec #3 §8 AC. Runs every layer that can be exercised locally
# (L0 + L1; L2 requires Sysbox; L3 requires KVM + OVA) and emits a
# green/red table. Used manually and in the CI verification job.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

green()  { printf '\033[0;32m%s\033[0m' "$*"; }
red()    { printf '\033[0;31m%s\033[0m' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m' "$*"; }
hr()     { printf '\n--- %s ---\n' "$*"; }

result=0
rows=()

# ---------- L0 ----------
hr "L0 static checks"
if command -v actionlint >/dev/null 2>&1 && command -v shellcheck >/dev/null 2>&1; then
  actionlint_out=$(actionlint .github/workflows/*.yml 2>&1 || true)
  shellcheck_out=$(shellcheck -s bash scripts/*.sh 2>&1 || true)
  if [[ -z "${actionlint_out}" && -z "${shellcheck_out}" ]]; then
    rows+=("L0|$(green 'PASS')|actionlint+shellcheck clean")
  else
    rows+=("L0|$(red 'FAIL')|see output above")
    echo "${actionlint_out}"
    echo "${shellcheck_out}"
    result=1
  fi
else
  rows+=("L0|$(yellow 'SKIP')|actionlint or shellcheck not installed")
fi

# ---------- L1 ----------
hr "L1 dev-base image"
if command -v docker >/dev/null 2>&1; then
  if docker compose -f docker/l1-compose.yml config >/dev/null 2>&1; then
    rows+=("L1|$(green 'PASS')|docker-compose syntactically valid")
  else
    rows+=("L1|$(red 'FAIL')|docker-compose config invalid")
    result=1
  fi
  # Full build + run is too slow for quick verification. Skip here;
  # CI exercises it via l1-unit.yml.
else
  rows+=("L1|$(yellow 'SKIP')|docker not installed")
fi

# ---------- L2 ----------
hr "L2 SIFT-lite image"
if command -v docker >/dev/null 2>&1 && [[ -f docker/l2-siftlite.Dockerfile ]]; then
  # Hadolint the Dockerfile if available.
  if command -v hadolint >/dev/null 2>&1; then
    if hadolint docker/l2-siftlite.Dockerfile >/dev/null 2>&1; then
      rows+=("L2|$(green 'PASS')|hadolint clean on Dockerfile")
    else
      rows+=("L2|$(yellow 'WARN')|hadolint issues (advisory)")
    fi
  else
    rows+=("L2|$(yellow 'SKIP')|hadolint not installed")
  fi
else
  rows+=("L2|$(yellow 'SKIP')|docker or Dockerfile missing")
fi

# ---------- L3 Packer ----------
hr "L3 Packer template"
if command -v packer >/dev/null 2>&1 && [[ -f packer/sift-microvm.pkr.hcl ]]; then
  if packer validate packer/sift-microvm.pkr.hcl 2>&1; then
    rows+=("L3|$(green 'PASS')|packer validate green")
  else
    rows+=("L3|$(red 'FAIL')|packer validate failed")
    result=1
  fi
else
  rows+=("L3|$(yellow 'SKIP')|packer not installed or template missing")
fi

# ---------- Fixtures ----------
hr "Fixtures"
if [[ -x scripts/fetch-fixtures.sh ]]; then
  if [[ -d fixtures ]]; then
    count=$(find fixtures -mindepth 1 -maxdepth 1 -type d | wc -l)
    rows+=("Fixtures|$(green 'PASS')|${count} fixture dirs present")
  else
    rows+=("Fixtures|$(yellow 'WARN')|fixtures/ empty — run scripts/fetch-fixtures.sh")
  fi
else
  rows+=("Fixtures|$(red 'FAIL')|scripts/fetch-fixtures.sh missing or not executable")
  result=1
fi

# ---------- Goldens ----------
hr "Goldens"
missing_goldens=0
for fixture in nist-hacking-case synthetic-benign synthetic-decoy; do
  if [[ ! -f "goldens/${fixture}/expected-findings.json" ]]; then
    missing_goldens=$((missing_goldens + 1))
    echo "  missing: goldens/${fixture}/expected-findings.json"
  fi
done
if [[ ${missing_goldens} -eq 0 ]]; then
  rows+=("Goldens|$(green 'PASS')|expected-findings.json for all core fixtures")
else
  rows+=("Goldens|$(red 'FAIL')|${missing_goldens} goldens missing")
  result=1
fi

# ---------- Print summary table ----------
hr "Verification summary"
printf '%-12s  %-6s  %s\n' "LAYER" "STATUS" "DETAIL"
printf '%-12s  %-6s  %s\n' "------------" "------" "---------------------------------------"
for row in "${rows[@]}"; do
  IFS='|' read -r layer status detail <<< "${row}"
  printf '%-12s  %-6s  %s\n' "${layer}" "${status}" "${detail}"
done

if [[ ${result} -eq 0 ]]; then
  echo
  echo "$(green 'sandbox verification: all runnable checks green')"
else
  echo
  echo "$(red 'sandbox verification: at least one check red')"
fi
exit ${result}
