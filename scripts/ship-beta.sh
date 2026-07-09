#!/usr/bin/env bash
# scripts/ship-beta.sh — publish a CLEAN beta release to the beta repo's beta branch.
#
# Why this exists: `git ship`/`git push` publish EVERY tracked file. The dev tree
# tracks private surfaces (docs/internal, .claude, obsidian-mind, plans/specs/…),
# and `.gitattributes export-ignore` only filters `git archive` tarballs — NOT a
# push — and does not even cover everything. So a raw beta push leaks private files.
#
# This script instead exports a CLEAN tree (`git archive`, which honors
# export-ignore), AUDITS it for anything private that slipped through, and only
# then snapshots it onto the beta branch and ships a pre-release via git-ship.
#
# SAFE BY DEFAULT: dry-run (review only). Nothing is pushed unless you pass --push.
#
# Usage:
#   bash scripts/ship-beta.sh --tag v0.5.0-beta.1               # DRY-RUN review
#   bash scripts/ship-beta.sh --tag v0.5.0-beta.1 --push        # actually publish
#
# Options:
#   --tag vX.Y.Z-beta.N  beta tag (recommended). Omit to push the branch only.
#   --remote NAME        beta git remote (default: beta)
#   --branch NAME        beta branch name (default: beta)
#   --ref REF            source ref to export (default: HEAD)
#   --push               actually publish (default: dry-run, no push)
#   --force              publish even if the audit flags risky files (with --push)
#   -h|--help

set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
TAG=""; REMOTE="beta"; BRANCH="beta"; REF="HEAD"; PUSH=0; FORCE=0

c_grn=$'\033[0;32m'; c_yel=$'\033[0;33m'; c_blu=$'\033[0;34m'; c_red=$'\033[0;31m'; c_off=$'\033[0m'
info(){ echo "${c_blu}[ship-beta]${c_off} $*"; }
ok(){ echo "${c_grn}[ship-beta]${c_off} $*"; }
warn(){ echo "${c_yel}[ship-beta]${c_off} $*"; }
die(){ echo "${c_red}[ship-beta]${c_off} $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="${2:?}"; shift 2;;
    --remote) REMOTE="${2:?}"; shift 2;;
    --branch) BRANCH="${2:?}"; shift 2;;
    --ref) REF="${2:?}"; shift 2;;
    --push) PUSH=1; shift;;
    --force) FORCE=1; shift;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) die "unknown option: $1 (try --help)";;
  esac
done

git -C "$REPO" remote get-url "$REMOTE" >/dev/null 2>&1 || die "no '$REMOTE' remote; add one first"
URL="$(git -C "$REPO" remote get-url "$REMOTE")"
SLUG="$(printf '%s' "$URL" | sed -E 's#^[a-z]+://[^/]+/##; s#^[^:]+:##; s#\.git$##')"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"; mkdir -p "$TREE"
info "exporting a clean tree from $REF (honors .gitattributes export-ignore)..."
git -C "$REPO" archive --worktree-attributes "$REF" | tar -x -C "$TREE"

# ---- AUDIT the clean tree for private/risky leftovers ------------------------
# .claude is private EXCEPT skills/ (the /verdict slash-skill) and settings.json
# (the SHARED, reviewed agent-containment config — path-guard PreToolUse hooks
# only, no secrets, no machine paths; ships so installers get the same rules).
# settings.local.json stays private (it's export-ignored + gitignored).
risky_paths="$(cd "$TREE" && find . -type f \( \
  -path './docs/internal/*' -o -path './obsidian-mind/*' -o \
  \( -path './.claude/*' ! -path './.claude/skills/*' ! -path './.claude/settings.json' \) -o \
  -path './docs/plans/*' -o -path './docs/specs/*' -o -path './docs/reports/*' -o \
  -path './docs/superpowers/*' -o \
  -path './docs/legacy/*' -o -path './evidence/*' -o -path './tmp/*' -o \
  -name '.env' -o -name '.env.*' -o -name '.envrc' -o -name '*.pem' -o -name '*.key' -o \
  -name 'id_rsa*' -o -name '*.E01' -o -name '*.dd' -o -name '*.raw' -o -name '*.mem' -o \
  -name '*.evtx' -o -name '*.pcap' -o -name '*.pcapng' -o -name '*.sqlite' \
  \) 2>/dev/null | sed 's#^\./##' | sort || true)"

# Value-bearing patterns only — match a real secret, not a bare env-var NAME
# (e.g. `${ANTHROPIC_API_KEY:-}` guards and `export FOO=...` doc examples must NOT trip it).
secret_hits="$(cd "$TREE" && grep -rIlE \
  'BEGIN [A-Z ]*PRIVATE KEY|sk-ant-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|[A-Za-z0-9_]*(API_KEY|TOKEN|SECRET|PASSWORD)[A-Za-z0-9_]*[=:][[:space:]]*"?[A-Za-z0-9_/+.-]{20,}' \
  . 2>/dev/null | sed 's#^\./##' | sort || true)"

fcount="$(find "$TREE" -type f | wc -l | tr -d ' ')"
tsize="$(du -sh "$TREE" | awk '{print $1}')"

echo
echo "=============================================================="
echo " BETA PUBLISH PLAN"
echo "=============================================================="
echo "  source ref   : $REF ($(git -C "$REPO" rev-parse --short "$REF"))"
echo "  target repo  : $SLUG   (remote '$REMOTE')"
echo "  target branch: $BRANCH"
echo "  tag          : ${TAG:-<none — branch push only>}"
echo "  clean tree   : $fcount files, $tsize"
echo "  top-level    : $(cd "$TREE" && ls -1A | tr '\n' ' ')"
echo "--------------------------------------------------------------"
if [ -n "$risky_paths" ] || [ -n "$secret_hits" ]; then
  warn "AUDIT FOUND ITEMS THAT SHOULD NOT BE PUBLIC:"
  [ -n "$risky_paths" ] && { echo "  risky paths:"; printf '    %s\n' $risky_paths; }
  [ -n "$secret_hits" ] && { echo "  files matching secret patterns (review):"; printf '    %s\n' $secret_hits; }
  echo "  -> add these to .gitattributes export-ignore (or remove them), then re-run."
  AUDIT_BAD=1
else
  ok "audit clean — no private paths or secret patterns in the export."
  AUDIT_BAD=0
fi
echo "=============================================================="

if [ "$PUSH" != 1 ]; then
  echo
  warn "DRY-RUN — nothing was pushed. Review the plan/audit above."
  echo "  to publish: re-run with --push$([ "$AUDIT_BAD" = 1 ] && echo ' (and fix the audit, or add --force)')"
  exit 0
fi

[ "$AUDIT_BAD" = 1 ] && [ "$FORCE" != 1 ] && \
  die "audit flagged items above — refusing to publish. Fix export-ignore, or re-run with --force."

# ---- snapshot the clean tree onto the beta branch and ship -------------------
info "cloning $SLUG to stage the beta branch..."
git clone --quiet "$URL" "$WORK/repo"
cd "$WORK/repo"
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  git checkout -q "$BRANCH"
else
  git checkout -q --orphan "$BRANCH"
fi
git rm -rqf . >/dev/null 2>&1 || true
cp -a "$TREE/." .
git add -A
git -c user.name="Timothy Vang" -c user.email="121889316+TimothyVang@users.noreply.github.com" \
  commit -q -m "beta: ${TAG:-snapshot of $REF} (clean export)"
ok "staged clean beta snapshot on '$BRANCH'"

if [ -n "$TAG" ]; then
  bash "$REPO/scripts/git-ship" --remote origin --branch "$BRANCH" --tag "$TAG"
  gh release edit "$TAG" -R "$SLUG" --prerelease >/dev/null 2>&1 \
    && ok "marked $TAG as a pre-release" \
    || warn "could not mark $TAG pre-release (set it in the GitHub release UI)"
else
  git push -u origin "$BRANCH"
fi
ok "beta published to $SLUG ($BRANCH${TAG:+ @ $TAG})."
