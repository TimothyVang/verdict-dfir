#!/usr/bin/env bash
# setup-branch-protection.sh — apply glue Spec #4 §6 to the default `master` branch.
#
# Run ONCE after repo creation (or after any protection reset). The
# critic subagent's GitHub account must be a collaborator with
# 'write' role before this takes effect, since the subagent's
# `gh pr review --approve` will be what satisfies the required
# review count.
#
# Required: gh CLI authenticated to a user with admin rights on
# this repo.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

log() { printf '[branch-protection] %s\n' "$*" >&2; }

if ! command -v gh >/dev/null 2>&1; then
  log "ERROR: gh CLI not found"; exit 2
fi

# Resolve owner/repo from git remote or env override.
REPO_SLUG="${REPO_SLUG:-}"
if [[ -z "${REPO_SLUG}" ]]; then
  REPO_SLUG="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi
if [[ -z "${REPO_SLUG}" ]]; then
  log "ERROR: could not resolve REPO_SLUG; set REPO_SLUG=owner/repo"
  exit 2
fi

log "applying master-branch protection to ${REPO_SLUG}"

# Required checks: use the aggregate ci-required context. The underlying L0/L1
# jobs stay visible in GitHub Actions, but requiring one uniquely named aggregate
# avoids ambiguous duplicate status-check names blocking PRs.
gh api \
  "repos/${REPO_SLUG}/branches/master/protection" \
  --method PUT \
  --field 'required_status_checks[strict]=true' \
  --field 'required_status_checks[contexts][]=ci-required' \
  --field 'enforce_admins=true' \
  --field 'required_pull_request_reviews[required_approving_review_count]=1' \
  --field 'required_pull_request_reviews[dismiss_stale_reviews]=true' \
  --field 'required_pull_request_reviews[require_code_owner_reviews]=true' \
  --field 'restrictions=null' \
  --field 'allow_force_pushes=false' \
  --field 'allow_deletions=false'

log "master-branch protection applied."
log "Verify: gh api repos/${REPO_SLUG}/branches/master/protection --jq '.required_status_checks.contexts'"
