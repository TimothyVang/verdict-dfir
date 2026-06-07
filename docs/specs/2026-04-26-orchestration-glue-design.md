# Spec #4 — Orchestration Glue: CI Pipeline

> **Status: SHIPPED, partially superseded by A6.** GHA workflows live in `.github/workflows/`. Branch protection, release pipeline (`release.yml` on `v*` tags), Devpost submission zip (`devpost-submit.yml` on `v-submit`), and competitor watch all wired. **Amendment A6 (2026-06-07) removed the build swarm and its `budget-guard.yml` workflow + `SWARM_HALT` machinery** — treat all budget-guard / `SWARM_HALT` / LiteLLM-`/spend` content below as historical. `scripts/build-deb.sh` and the `.deb` artifact were cut by A2 (PR #4 / `docs/runbooks/dockerfile-a2-decision.md`); current release artifacts are Docker image, `report.html`, and the Devpost zip.

**Date:** 2026-04-26
**Status:** Shipped — current workflow YAML wins where older design details below conflict
**Deadline:** 2026-06-15 22:45 CDT
**Parent:** `docs/specs/2026-04-23-find-evil-automation-master-design.md`
**Depends on:** Spec #3 (Sandbox), Spec #1 (Build Swarm), Spec #2 (Product)

This spec is thin glue. It does not redefine the sandbox layers (Spec #3 §4), the swarm internals (Spec #1), or the Product's agent graph (Spec #2). It defines only the GHA workflows, branch protection rules, release pipeline, leaderboard push contract, competitor monitoring, and Devpost submission automation that bind all three together.

---

## 1. Problem Statement

Three independently designed subsystems — the autonomous build swarm (#1), the Product (#2), and the layered test sandbox (#3) — produce value only when wired together. Without coordination: swarm PRs sit unmerged, L3 golden results never reach the M1 leaderboard, releases are cut manually with human error, and the Devpost submission on deadline night becomes a scramble. This spec defines the minimal CI glue layer that:

1. Validates every swarm-generated PR via L0+L1 gate before merge, with L2 advisory results posted.
2. Runs L3 goldens nightly on `main` and blocks every release tag when L3 is red.
3. Pushes nightly benchmark scores to the M1 public leaderboard at `findevil-bench.dev`.
4. Monitors three watched competitor repos weekly and alerts on any activity delta.
5. Packages a Docker image + offline `report.html` on every `v<N>` tag; `.deb` packaging was cut under A2.
6. Produces a complete Devpost submission zip automatically on the `v-submit` tag cut by 2026-06-14.

---

## 2. Pipeline Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  NIGHTLY (01:00 UTC, Mon-Sun)                                        │
│                                                                      │
│  build-swarm (local laptop, Spec #1)                                 │
│    │  opens draft PRs against main                                   │
│    ▼                                                                 │
│  PR opened / push to feature branch                                  │
│    │                                                                 │
│    ├──▶ l0-static.yml       (~45s)    ── REQUIRED pass ──┐           │
│    ├──▶ l1-unit.yml         (~3min)   ── REQUIRED pass ──┤           │
│    └──▶ l2-sift-lite.yml    (~8min)   ── advisory ───────┘           │
│                                              │                       │
│                               critic subagent (Spec #1)              │
│                               reviews L1 output + diff               │
│                               gh pr review --approve                 │
│                               gh pr merge --squash                   │
│                                              │                       │
│                               push to main ────────────────────┐     │
│                                                                │     │
│  l3-nightly.yml (02:30 UTC) ◀──────────── main push ──────────┘     │
│    QEMU microvm + golden matrix (Spec #3 §4.4)  5-20min              │
│    │                                                                 │
│    ├── PASS → push score to findevil-bench.dev                       │
│    └── FAIL → Slack #ci-alerts + block pending release tags          │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  RELEASE  (on git tag v<N> push)                                     │
│                                                                      │
│  release.yml                                                         │
│    ├── verify: L3 green on tagged commit (last 24h)                  │
│    ├── build-docker: ghcr.io/find-evil/find-evil:v<N>                │
│    ├── build-report: report.html (Vite lib build)                    │
│    ├── upload: report.html to GitHub Release; Docker by tag/digest   │
│    ├── push: release=true score to findevil-bench.dev                │
│    └── Slack #releases: "v<N> shipped"                               │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  WEEKLY                                                              │
│                                                                      │
│  competitor-watch.yml  (Monday 09:00 UTC)                            │
│    ├── gh api repos/yushin-dfir/...                                  │
│    ├── gh api repos/dhyabi2/findevil                                 │
│    ├── gh api repos/marez8505/find-evil                              │
│    ├── gh api repos/teamdfir/protocol-sift                           │
│    ├── gh api search/repositories?q=topic:find-evil                  │
│    └── delta vs last-week state → Slack #competitor-watch            │
│                                                                      │
│  l3-weekly-goldens.yml  (Sunday 23:00 UTC)                           │
│    └── full golden matrix → score update to leaderboard              │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  DEVPOST SUBMISSION  (on git tag v-submit, target 2026-06-14)        │
│                                                                      │
│  devpost-submit.yml                                                  │
│    ├── wait for release.yml green on v-submit                        │
│    ├── scripts/package-devpost.sh                                    │
│    │     ├── README-submission.md (from template + envsubst)         │
│    │     ├── benchmark-results.csv (from last L3 run artifacts)      │
│    │     ├── demo-video-link.txt                                     │
│    │     ├── LICENSE (Apache-2.0, static)                            │
│    │     └── report.html                                             │
│    ├── gh release upload v-submit find-evil-submission.zip           │
│    └── Slack #releases: "Devpost package ready for manual upload"    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. GHA Workflow Files

All files live under `.github/workflows/`. L0/L1/L2/L3 internals are defined in Spec #3; only triggers and integration contracts are specified here.

| File | Trigger | Purpose |
|---|---|---|
| `l0-static.yml` | PR + any branch push | Lint gate — Spec #3 §4.1. Required status check on master. |
| `l1-unit.yml` | PR + any branch push | Unit/build gate — Spec #3 §4.2. Required status check on master. |
| `l2-sift-lite.yml` | PR + any branch push | Advisory DFIR smoke — Spec #3 §4.3. Non-blocking; posts result comment on PR. |
| `l3-nightly.yml` | `cron: '30 2 * * *'` + `push: branches: [master]` | Nightly full-SIFT golden run; on pass pushes score to leaderboard; on fail posts to `#ci-alerts`. |
| `l3-weekly-goldens.yml` | `cron: '0 23 * * 0'` (Sunday 23:00 UTC) | Full golden matrix run weekly; score update to leaderboard. |
| `release.yml` | `push: tags: ['v[0-9]*', 'v-submit']` | Verifies L3 green; builds Docker + `report.html`; uploads release artifacts; Slack `#releases`. |
| `competitor-watch.yml` | `cron: '0 9 * * 1'` (Monday 09:00 UTC) | Repo delta scan for 3 competitors + topic search; Slack `#competitor-watch`. |
| `devpost-submit.yml` | `push: tags: ['v-submit']` | Waits for `release.yml` green; runs `scripts/package-devpost.sh`; uploads zip to GH Release. |
| `budget-guard.yml` | `cron: '0 6 * * *'` (daily 06:00 UTC) | Queries LiteLLM proxy `/spend`; sets `SWARM_HALT=true` variable and Slack-alerts if daily spend > $50. |

---

## 4. Release Workflow Sequence

For every `git tag v<N> && git push origin v<N>` (weeks 1-8):

1. **`release.yml` triggers** on tag pattern `v[0-9]*`.

2. **L3 gate.** Job step runs:
   ```
   gh run list \
     --workflow=l3-nightly.yml \
     --branch=master \
     --status=success \
     --limit=5 \
     --json headSha,databaseId \
     --jq ".[] | select(.headSha == env.COMMIT_SHA)"
   ```
   If no matching green run in the last 24 hours, the job posts to `#ci-alerts` and exits with code 1. The release tag is not deleted — re-trigger via `gh workflow run release.yml --ref v<N>` once L3 catches up.

3. **Parallel build jobs**:
   - `build-docker`: `docker buildx build --platform linux/amd64 --tag ghcr.io/find-evil/find-evil:v<N> --push .` using `GHCR_TOKEN` or `GITHUB_TOKEN`.
   - `build-report`: installs the web workspace and uploads `report.html`, falling back to a clear stub if the offline report build is unavailable.
   - `build-deb` is intentionally absent post-A2; the `.deb` wrapper had no runtime after Claude Code became the primary interface.

4. **Upload artifacts** to GH Release: `report.html` is uploaded; Docker is accessed by tag/digest.

5. **Leaderboard release ping** via `scripts/push-leaderboard-score.sh --release true --tag v<N>` using the score JSON from the gating L3 run.

6. **Slack `#releases`**: `"[find-evil CI] release | PASS | <sha> | <GH Release URL>"` plus Docker/report summary.

For `v-submit`, `devpost-submit.yml` runs downstream after `release.yml` succeeds (see §9).

---

## 5. Secrets and Environment Variables

| Name | Type | Scope | Used by | Notes |
|---|---|---|---|---|
| `SLACK_WEBHOOK_CI` | Secret | Repo | `l3-nightly.yml`, `budget-guard.yml`, `release.yml` | Posts to `#ci-alerts` |
| `SLACK_WEBHOOK_RELEASES` | Secret | Repo | `release.yml`, `devpost-submit.yml` | Posts to `#releases` |
| `SLACK_WEBHOOK_COMPETITORS` | Secret | Repo | `competitor-watch.yml` | Posts to `#competitor-watch` |
| `LEADERBOARD_API_KEY` | Secret | Repo | `l3-nightly.yml`, `l3-weekly-goldens.yml`, `release.yml` | Bearer token for `findevil-bench.dev` POST |
| `LITELLM_PROXY_URL` | Secret | Repo | `budget-guard.yml` | LiteLLM proxy base URL for `/spend` endpoint |
| `LITELLM_MASTER_KEY` | Secret | Repo | `budget-guard.yml` | LiteLLM master key auth |
| `GHCR_TOKEN` | Secret | Repo | `release.yml` build-docker job | GitHub PAT with `packages:write` scope |
| `OTS_CALENDAR_URL` | Secret | Repo | Passed into L3 run environment for M2 chain-of-custody | Optional; if empty, OTS anchor skipped |
| `BITCOIN_RPC_URL` | Secret | Repo | L3 run environment, M2 OTS optional anchor | Set to empty string to disable |
| `DEMO_VIDEO_URL` | Actions variable (not secret) | Repo | `devpost-submit.yml` via `scripts/package-devpost.sh` | Set with `gh variable set DEMO_VIDEO_URL` before cutting `v-submit` |
| `SWARM_HALT` | Actions variable | Repo | Build swarm supervisor checks this before nightly run | Set to `true` by `budget-guard.yml` when daily spend > $50 |
| `GITHUB_TOKEN` | Auto-injected | Workflow | All workflows | Default GHA token; needs `contents:write` for release uploads; `pull-requests:write` for PR comments |

All secrets are injected at the job level via `env:` blocks. No workflow-level `env:` for secrets (limits blast radius per GHA security best practice).

---

## 6. Branch Protection Configuration

Apply once to the `master` branch after repo creation. The reviewer for swarm PRs is the critic subagent's GitHub account (must have `write` collaborator access).

**`gh` CLI command:**

```
gh api \
  repos/{OWNER}/{REPO}/branches/master/protection \
  --method PUT \
  --field 'required_status_checks[strict]=true' \
  --field 'required_status_checks[contexts][]=l0-static' \
  --field 'required_status_checks[contexts][]=l1-unit' \
  --field 'enforce_admins=true' \
  --field 'required_pull_request_reviews[required_approving_review_count]=1' \
  --field 'required_pull_request_reviews[dismiss_stale_reviews]=true' \
  --field 'required_pull_request_reviews[require_code_owner_reviews]=false' \
  --field 'restrictions=null' \
  --field 'allow_force_pushes=false' \
  --field 'allow_deletions=false'
```

**Equivalent REST API JSON body** for `PUT /repos/{owner}/{repo}/branches/master/protection`:

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["l0-static", "l1-unit"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
```

**What each setting does:**

- `contexts: ["l0-static", "l1-unit"]` — only these two are required; `l2-sift-lite` is advisory and deliberately excluded so DFIR tool flakiness cannot stall swarm merges.
- `strict: true` — the branch must be up-to-date with `master` before the status checks run (prevents race conditions on concurrent swarm PRs).
- `enforce_admins: true` — the repo owner cannot bypass the rules; prevents accidental direct pushes during deadline rush.
- `required_approving_review_count: 1` — the critic subagent's `gh pr review --approve` satisfies this.
- `restrictions: null` — any collaborator can push to feature branches; only `master` is protected.

---

## 7. Leaderboard Push Contract

**Service:** `findevil-bench.dev` (M1 moonshot, built during week 6 per master design §7).

**Endpoint:** `POST https://findevil-bench.dev/api/scores`

**Auth:** `Authorization: Bearer <LEADERBOARD_API_KEY>`

**Content-Type:** `application/json`

**Payload schema:**

```json
{
  "submitter": "find-evil",
  "commit_sha": "<40-char SHA>",
  "run_id": "<GHA workflow run_id>",
  "timestamp_utc": "<ISO 8601, e.g. 2026-05-15T02:47:00Z>",
  "release": false,
  "release_tag": null,
  "cases": [
    {
      "fixture": "nist-hacking-case",
      "findings_matched": 14,
      "findings_expected": 14,
      "verdict": "CONFIRMED_EVIL",
      "verdict_correct": true,
      "wall_clock_seconds": 312
    },
    {
      "fixture": "otrf-apt3-mordor",
      "findings_matched": 9,
      "findings_expected": 11,
      "verdict": "CONFIRMED_EVIL",
      "verdict_correct": true,
      "wall_clock_seconds": 287
    },
    {
      "fixture": "synthetic-benign",
      "findings_matched": 0,
      "findings_expected": 0,
      "verdict": "NO_EVIL",
      "verdict_correct": true,
      "wall_clock_seconds": 145
    }
  ],
  "aggregate": {
    "accuracy": 1.0,
    "total_findings_matched": 23,
    "total_findings_expected": 25,
    "mean_wall_clock_seconds": 248
  }
}
```

When `release: true`, set `release_tag` to the tag string (e.g., `"v5"`). The leaderboard renders a milestone marker on the timeline chart for release pushes.

**Failure handling:** Non-2xx response is logged and a warning posted to `#ci-alerts`. The leaderboard push is non-blocking — a push failure does not block merge, nightly status, or the release workflow. The next successful L3 run corrects the leaderboard.

**Script:** `scripts/push-leaderboard-score.sh`. Reads `run.log` JSON output from `scripts/l3-run-goldens.sh` (Spec #3 §4.4), constructs the payload, fires `curl -X POST`. Called from `l3-nightly.yml`, `l3-weekly-goldens.yml`, and `release.yml`.

---

## 8. Competitor Watch Implementation

**Workflow:** `.github/workflows/competitor-watch.yml`
**Cron:** `0 9 * * 1` (Monday 09:00 UTC)
**Runner:** `ubuntu-24.04` standard

**Script:** `scripts/competitor-watch.sh`

**What it checks:**

| Target | API call | Comparison basis |
|---|---|---|
| `yushin-dfir` primary DFIR repo | `gh api repos/yushin-dfir/dfir-agent/commits?per_page=1` | commit SHA |
| `dhyabi2/findevil` | `gh api repos/dhyabi2/findevil/commits?per_page=1` | commit SHA |
| `marez8505/find-evil` | `gh api repos/marez8505/find-evil/commits?per_page=1` | commit SHA |
| All three star counts | `gh api repos/{owner}/{repo} --jq .stargazers_count` | integer delta |
| New `find-evil` topic repos | `gh api 'search/repositories?q=topic:find-evil&sort=updated' --jq '.items[].full_name'` | set membership |
| `teamdfir/protocol-sift` updates | `gh api repos/teamdfir/protocol-sift/commits?per_page=1` | commit SHA |

**State file:** `state/competitor-watch.json` on branch `chore/competitor-state`. The workflow checks out that branch, reads the file, runs all checks, computes deltas, writes the updated state, and pushes. Uses `git pull --rebase` before push to avoid conflicts.

**Alert logic:**
- Any changed commit SHA → Slack `#competitor-watch` with repo name, old/new SHA, link to the commit diff.
- Star count change ≥ 5 → Slack `#competitor-watch` with before/after count.
- New topic repo with stargazers_count ≥ 3 → Slack `#competitor-watch` AND `#ci-alerts` (escalated — new entrant may be a real threat).
- No changes → no Slack post (zero noise on quiet weeks).

**Slack message format for any delta:**

```
[find-evil competitor-watch] Monday report — <N> change(s) detected
• dhyabi2/findevil: new commit abc1234 — <commit message first line> | <diff link>
• marez8505/find-evil: stars 12 → 19
Full report: <link to GHA run>
```

---

## 9. Devpost Submission Automation

**Target:** `v-submit` tag cut by 2026-06-14 23:59 CDT (1 day buffer before deadline).

### Prerequisites (manual, done before tag cut)

1. Demo video recorded and uploaded externally (YouTube, etc.).
2. `gh variable set DEMO_VIDEO_URL --body "https://youtu.be/<id>"` — sets the Actions variable.
3. `v8` release green (or equivalent final week tag).

### `devpost-submit.yml` job sequence

1. **Verify `release.yml` green** on the same commit. Polls `gh run list --workflow=release.yml --status=success` up to 30 minutes (2-minute intervals). Exits 1 if not green within timeout.

2. **Verify `DEMO_VIDEO_URL` set.** `gh variable get DEMO_VIDEO_URL` — if empty or unset, exits 1 with message: `"Set DEMO_VIDEO_URL via: gh variable set DEMO_VIDEO_URL --body '<url>' before cutting v-submit"`.

3. **Download release artifacts** for `v-submit`: `report.html` and any optional legacy artifacts from `gh release download v-submit`.

4. **Download benchmark CSV.** Pull the `l3-verdicts` artifact from the most recent successful `l3-weekly-goldens.yml` run via `gh run download`. Then run `scripts/json-to-benchmark-csv.py run.log > benchmark-results.csv`.

5. **Run `scripts/package-devpost.sh`** which:
   - Reads `DEMO_VIDEO_URL` from env.
   - Runs `envsubst` on `docs/templates/devpost-readme.md` to produce `README-submission.md`.
   - Assembles `find-evil-submission.zip` containing:
     - `README-submission.md`
     - `benchmark-results.csv`
     - `demo-video-link.txt` (contains `$DEMO_VIDEO_URL` verbatim)
     - `LICENSE` (Apache-2.0, from repo root)
      - `report.html`

6. **Integrity check.** Script verifies zip contains all 5 required files; a legacy `.deb` is included only if an older release asset provided one. (Pre-Phase-3d the list included `SUBMISSION_NOTES.md`; that file was deleted 2026-05-02 — judge-facing Q&A migrated to README.md "Anticipated questions.")

7. **Upload.** `gh release upload v-submit find-evil-submission.zip`.

8. **Slack `#releases`**: `"[find-evil] Devpost package ready — find-evil-submission.zip on v-submit release. Download and attach to Devpost form manually. <GH Release URL>"`.

### Files involved

| File | Role |
|---|---|
| `.github/workflows/devpost-submit.yml` | Orchestration workflow |
| `scripts/package-devpost.sh` | Assembles zip; calls `envsubst`; runs integrity check |
| `scripts/json-to-benchmark-csv.py` | Converts `run.log` JSON to `benchmark-results.csv` |
| `docs/templates/devpost-readme.md` | README template; placeholders: `${DEMO_VIDEO_URL}`, `${RELEASE_TAG}`, `${ACCURACY}`, `${DATE}` |
| `LICENSE` | Apache-2.0 full text; committed at repo root from week 1 |

Note: Devpost form submission is a manual human step. The zip is staged in the GH Release. The user downloads it, opens the Devpost project page, and attaches it. This is intentional — no external API dependency on deadline night.

---

## 10. Monitoring

### Slack channels and routing

| Channel | What posts there |
|---|---|
| `#ci-alerts` | L3 nightly/weekly failures; release tag blocked on L3 red; `budget-guard` warn (>$40) or halt (>$50); leaderboard push non-2xx; new competitor entrant with ≥ 3 stars; `DEMO_VIDEO_URL` not set on `v-submit` tag |
| `#releases` | Successful `v<N>` release with artifact links; Devpost package ready notification |
| `#competitor-watch` | Monday competitor delta report (all deltas); new entrant alert (also goes to `#ci-alerts`) |

### GHA status badges (in `README.md`)

```markdown
![CI](https://github.com/{owner}/{repo}/actions/workflows/l1-unit.yml/badge.svg)
![L3 Goldens](https://github.com/{owner}/{repo}/actions/workflows/l3-nightly.yml/badge.svg)
```

Both badges are included in `README-submission.md` so judges see CI health from the Devpost page.

### Slack message format (all channels)

```
[find-evil CI] <workflow> | <PASS|FAIL|WARN> | <short SHA> | <GHA run URL>
<one-line description>
```

No Block Kit. Plain text only. Keeps webhook implementation trivially simple and immune to Slack API changes.

### Budget dead-man's switch

`budget-guard.yml` runs daily at 06:00 UTC. It queries `$LITELLM_PROXY_URL/spend` with `Authorization: Bearer $LITELLM_MASTER_KEY`. If the daily spend exceeds $40, posts a warning to `#ci-alerts`. If it exceeds $50, it additionally sets `gh api repos/{owner}/{repo}/actions/variables/SWARM_HALT --method PATCH --field value=true`. The swarm supervisor (Spec #1) checks `SWARM_HALT` before launching each nightly session and aborts if true, preserving the Anthropic API budget ceiling defined in master design §2.

---

## 11. Acceptance Criteria

### Swarm-to-release round-trip

- [ ] A draft PR pushed by the build swarm triggers `l0-static` and `l1-unit` as required status checks within 5 minutes of the push event.
- [ ] `l2-sift-lite` posts an advisory comment on the PR; its failure status does not prevent merge.
- [ ] Critic subagent `gh pr review --approve` satisfies the branch protection review requirement; `gh pr merge --squash` completes without manual human action.
- [ ] Merge to `main` triggers `l3-nightly.yml`; the run completes and posts a status message to `#ci-alerts` within 25 minutes.
- [ ] `git tag v2 && git push origin v2` starts `release.yml`; if no L3 green on `main` within the last 24h, the workflow exits 1 and posts to `#ci-alerts` without producing artifacts.
- [ ] When L3 is green: `release.yml` produces `ghcr.io/find-evil/find-evil:v2` image and `report.html`; `report.html` is attached to the GH Release page for `v2`.
- [ ] Release logs explicitly note that `build-deb`/`.deb` packaging is absent post-A2.
- [ ] `docker run --rm ghcr.io/find-evil/find-evil:v2 bash -lc 'ls /app || true'` exits 0 for build-state reproduction.
- [ ] `report.html` opens in a browser with `--disable-features=NetworkService` and renders the verdict card without network requests.

### Weekly competitor report

- [ ] `competitor-watch.yml` fires on the first Monday after repo setup and posts to `#competitor-watch` if any watched repo had a commit in the prior week.
- [ ] `state/competitor-watch.json` on branch `chore/competitor-state` is updated after each run.
- [ ] A newly created `find-evil`-topic repo with ≥ 3 stars triggers alerts in both `#competitor-watch` and `#ci-alerts`.
- [ ] No Slack post is made on a week with zero changes.

### Devpost package ready by 2026-06-14

- [ ] By 2026-06-14 23:59 CDT: `v-submit` tag exists on `main` and `devpost-submit.yml` completed successfully.
- [ ] `find-evil-submission.zip` is attached to the GH Release for `v-submit` and contains: `README-submission.md`, `benchmark-results.csv`, `demo-video-link.txt`, `LICENSE`, and `report.html`. (Pre-A2 also `.deb`; pre-Phase-3d also `SUBMISSION_NOTES.md`; both were removed.)
- [ ] `demo-video-link.txt` contains a non-placeholder URL (not empty, not a template variable).
- [ ] `LICENSE` contains the full Apache-2.0 text.
- [ ] `benchmark-results.csv` has at least one row with `fixture=nist-hacking-case` and `findings_matched` > 0.
- [ ] `README-submission.md` contains no un-substituted `${...}` template placeholders.

---

## 12. Risks and Mitigations

| # | Risk | Mitigation |
|---|---|---|
| G1 | GHA outage during nightly L3 run | Missed nightly is not catastrophic; next night catches up. Release tag: re-run via `gh workflow run release.yml --ref v<N>` after GHA recovers. Swarm PRs queue — merge order preserved by branch names. GHA failure emails serve as fallback alert if Slack is also down. |
| G2 | Slack webhook unavailable during demo or deadline night | All Slack messages are best-effort fire-and-forget. GH Release page and GHA run logs are the source of truth for all artifacts. The Devpost zip is uploaded to GH Release before the Slack notification fires. |
| G3 | Devpost deadline-night scramble | `v-submit` tag is cut 2026-06-14 by design, one day early. The zip is staged in GH Release by midnight. Manual Devpost form submission takes < 5 minutes from the pre-staged zip. No automation touches Devpost's external servers. |
| G4 | `findevil-bench.dev` (M1 leaderboard) down during judging week | Leaderboard is a bonus SEO asset — not required for Devpost submission. Judges evaluate the Product directly. The `benchmark-results.csv` in the Devpost zip serves as static evidence of benchmark accuracy. |
| G5 | Docker/report build fails on a mid-sprint release tag | Release workflow fails loudly; rerun after fixing the build. The canonical judge path remains `git clone` + `scripts/install.sh` + `claude`, not a `.deb`. |
| G6 | Critic subagent's GitHub account lacks approval permission | Critic's PAT account must be added as a repo collaborator with `write` role before the first nightly swarm run. Add with: `gh api repos/{owner}/{repo}/collaborators/{critic-account} --method PUT --field permission=write`. |
| G7 | `DEMO_VIDEO_URL` not set before `v-submit` tag cut | `package-devpost.sh` checks for non-empty value and exits 1 with an explicit error message. The `devpost-submit.yml` workflow fails loudly on Slack `#ci-alerts` before any zip is assembled. |
| G8 | Concurrent competitor-watch runs (unlikely but possible on re-run) | Workflow uses `git pull --rebase` before pushing state; single Monday cron means no true concurrency. If a manual re-run races with a scheduled run, last writer wins on `competitor-watch.json` — acceptable (idempotent state file). |
| G9 | L3 KVM larger runners deprecated mid-hackathon (risk S3 from Spec #3) | Switch `l3-nightly.yml` runner to Actuated; cost ~$250/mo flat. Release gates remain intact. No change to workflow logic needed — only the `runs-on:` field changes. |

---

## 13. Budget Estimate (Glue Layer Only)

Sandbox costs are already captured in Spec #3 §7. These are the incremental costs of the orchestration workflows only.

| Line | Estimate | Basis |
|---|---|---|
| `release.yml` builds (8 weekly releases) | ~$1.50 | ~6min avg × 8 × $0.016/min (report.html on standard runner; Docker on free tier buildx) |
| `competitor-watch.yml` (8 Monday runs) | ~$0.15 | ~3min × 8 × $0.016/min |
| `budget-guard.yml` (53 daily runs) | ~$0.10 | <1min each |
| `devpost-submit.yml` (1 run) | ~$0.08 | ~5min on standard runner |
| GHA artifact storage for 8 releases | ~$1-3 | report.html (~2MB) × 8 + zip (~20MB) × 1 |
| **Glue subtotal** | **~$5-7** | Negligible vs. L3 ($420-525) and swarm ($2,650 worst case) |

Total project budget ceiling remains ~$3,500-4,000 per master design §8.

---

## 14. Out of Scope

- The internal logic of the build swarm (supervisor, workers, LiteLLM proxy, PostgresSaver, git worktrees) — Spec #1.
- The L0/L1/L2/L3 sandbox specifications (image definitions, Packer config, golden fixture management) — Spec #3.
- The Product's agent graph, Rust MCP server, chain-of-custody layer, ACH agents, or UI components — Spec #2.
- Automated Devpost form submission via API — Devpost has no public submission API; the manual step is intentional and resilient.
- Cross-platform (Windows, macOS) CI — the Product targets SIFT (Ubuntu 22.04); all runners are Linux.
- LLM provider matrix testing — the Product is Anthropic Claude-only; provider switching is a LiteLLM proxy concern, not a CI pipeline concern.
- Multi-repo workflow dispatch — single-repo architecture; no cross-repo GHA triggers needed.
- Automatic release rollback — releases are append-only GH tags; rollback is a manual `gh release delete v<N>` + corrected tag re-push.
- Benchmark paper generation — the `benchmark-results.csv` in the Devpost zip is the machine-readable benchmark output; any narrative paper is written by hand in week 8.
