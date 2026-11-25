#!/usr/bin/env bash
# competitor-watch.sh — scan watched competitor repos and alert on
# any delta vs. last-week state.
#
# Glue Spec #4 §8. Called from .github/workflows/competitor-watch.yml
# on Monday 09:00 UTC (cron `0 9 * * 1`). Runs in the workflow's
# chore/competitor-state branch checkout so state/competitor-watch.json
# can be updated + pushed.

set -euo pipefail

STATE_FILE="${STATE_FILE:-state/competitor-watch.json}"
STATE_DIR="$(dirname "${STATE_FILE}")"
mkdir -p "${STATE_DIR}"
[[ -f "${STATE_FILE}" ]] || echo '{}' > "${STATE_FILE}"

# Watched repos — realigned 2026-06-17 to the ELITE rivals surfaced by the
# competitive analysis (competitive-analysis.md §6.1) plus two reference bars.
# AppliedIR/Valhuntir is the SANS-endorsed reference bar; teamdfir/protocol-sift
# is the hackathon's own reference. The remainder are the post-analysis top
# threats (signed/Merkle/HMAC custody AND committed self-correction). The earlier
# list (sift-mcp / yushin-dfir / findevil / find-evil) watched early entrants, not
# these rivals, so it was replaced. The generic topic:find-evil sweep below still
# catches any new entrant regardless of this curated list.
#
# 2026-06-18 post-deadline re-sweep added five strong NEW entrants surfaced once
# the Devpost gallery opened (field 122 -> 196): a second "verdict" name-collision
# (prabhakaran-jm), an honest-accuracy build (joshfrogers), a disk-vs-memory
# correlation build (ik-labs), a multi-agent framework (project-mantis), and the
# real AppliedIR/sift-mcp (Valhuntir) repo. See elite-learnings-2026-06-18.md.
#
# 2026-06-19 re-sweep added five strong serious rivals from a 16-repo deep-scan
# (still 0/16 at custody parity): an adversarial Prosecutor/Defender/Arbiter court
# (evidencegene-court), an in-product accuracy-harness build (trudi), a cloud/identity
# breadth build (valkyrie), an ingest-at-scale build (nighteye), and the deferred
# BLAKE3+Merkle custody contender (find-evil-sleuth) -- deep-scanned and confirmed NOT
# at parity. See elite-learnings-2026-06-19.md. (nNemy/sans-hackathon-nNemy is excluded
# deliberately: it is an earlier snapshot of VERDICT's own lineage, not a competitor.)
readarray -t WATCH_REPOS <<EOF
AppliedIR/Valhuntir
AppliedIR/sift-mcp
teamdfir/protocol-sift
threatroute66/EL
ahammadshawki8/DeepSIFT
annatchijova/vigia-intent-analysis
holeyfield33-art/aletheia-sentinel
tejcodes-rex/verdict
aryanbuilds/Project_SIFTMESH
prabhakaran-jm/verdict
joshfrogers/Find-Evil-Hackathon
ik-labs/findevil-dfir
codebyangelo/project-mantis
FUYOH666/evidencegene-court
nebulae/trudi
elchacal801/valkyrie
0xshivangpatel/nighteye
WilBtc/find-evil-sleuth
EOF

log() { printf '[competitor-watch] %s\n' "$*" >&2; }

# Alerts buffer.
alerts=()

check_repo() {
  local slug="$1"
  local key_prefix="repos.${slug//[\/.-]/_}"
  local last_sha
  last_sha=$(jq -r --arg k "${key_prefix}_sha" '.[$k] // ""' "${STATE_FILE}")
  local last_stars
  last_stars=$(jq -r --arg k "${key_prefix}_stars" '.[$k] // 0' "${STATE_FILE}")

  local meta
  if ! meta=$(gh api "repos/${slug}" 2>/dev/null); then
    log "fetch failed for ${slug}; skipping"
    return 0
  fi

  local stars
  stars=$(echo "${meta}" | jq -r '.stargazers_count // 0')

  local head
  if ! head=$(gh api "repos/${slug}/commits?per_page=1" 2>/dev/null); then
    return 0
  fi
  local sha
  sha=$(echo "${head}" | jq -r '.[0].sha // ""')
  local msg
  msg=$(echo "${head}" | jq -r '.[0].commit.message // "" | split("\n")[0]' | head -c 120)
  local url
  url=$(echo "${head}" | jq -r '.[0].html_url // ""')

  # New commit?
  if [[ -n "${sha}" ]] && [[ "${sha}" != "${last_sha}" ]] && [[ -n "${last_sha}" ]]; then
    alerts+=("• ${slug}: new commit ${sha:0:7} — ${msg} | ${url}")
  fi
  # Star delta ≥ 5?
  if (( stars >= last_stars + 5 )) && (( last_stars > 0 )); then
    alerts+=("• ${slug}: stars ${last_stars} → ${stars}")
  fi

  # Always write latest values so state file stays fresh.
  local tmp
  tmp=$(mktemp)
  jq \
    --arg k_sha "${key_prefix}_sha" --arg v_sha "${sha}" \
    --arg k_stars "${key_prefix}_stars" --argjson v_stars "${stars}" \
    '.[$k_sha] = $v_sha | .[$k_stars] = $v_stars' \
    "${STATE_FILE}" > "${tmp}"
  mv "${tmp}" "${STATE_FILE}"
}

for repo in "${WATCH_REPOS[@]}"; do
  [[ -n "${repo}" ]] || continue
  check_repo "${repo}"
done

# New find-evil-topic repos (escalated alert: also #ci-alerts).
last_topic=$(jq -r '.topic_repos // []' "${STATE_FILE}")
if ! latest_topic_json=$(gh api 'search/repositories?q=topic:find-evil&sort=updated&per_page=30' 2>/dev/null); then
  latest_topic_json='{"items":[]}'
fi
current_topic=$(echo "${latest_topic_json}" \
  | jq '[.items[] | select(.stargazers_count >= 3) | .full_name]')
new_entrants=$(jq -n --argjson old "${last_topic}" --argjson new "${current_topic}" \
  '$new - $old')
if [[ "$(echo "${new_entrants}" | jq 'length')" -gt 0 ]]; then
  while IFS= read -r entrant; do
    alerts+=("• NEW TOPIC ENTRANT (≥3 stars): ${entrant}")
  done < <(echo "${new_entrants}" | jq -r '.[]')
fi
# Update state regardless.
tmp=$(mktemp)
jq --argjson v "${current_topic}" '.topic_repos = $v' "${STATE_FILE}" > "${tmp}"
mv "${tmp}" "${STATE_FILE}"

# ---------------------------------------------------------------------
# Post to Slack.
# ---------------------------------------------------------------------
if [[ ${#alerts[@]} -eq 0 ]]; then
  log "no deltas this week"
  exit 0
fi

msg="[find-evil competitor-watch] Monday report — ${#alerts[@]} change(s) detected"
for line in "${alerts[@]}"; do
  msg="${msg}
${line}"
done
msg="${msg}

Full report: ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"

if [[ -n "${SLACK_WEBHOOK_COMPETITORS:-}" ]]; then
  curl -fsSL -X POST "${SLACK_WEBHOOK_COMPETITORS}" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nR --arg t "$msg" '{text:$t}')" \
    || log "competitors slack post failed"
fi

# Escalate new topic entrants to #ci-alerts.
if echo "${msg}" | grep -q 'NEW TOPIC ENTRANT' && [[ -n "${SLACK_WEBHOOK_CI:-}" ]]; then
  curl -fsSL -X POST "${SLACK_WEBHOOK_CI}" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nR --arg t "$msg" '{text:$t}')" \
    || log "ci-alerts slack post failed"
fi

log "posted ${#alerts[@]} alerts"
