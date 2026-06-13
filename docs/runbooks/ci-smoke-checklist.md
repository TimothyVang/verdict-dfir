# CI smoke checklist — end-to-end pipeline verification

Glue plan Task 17. Follow this when:

- Setting up the repo for the first time on a fresh machine or a fresh fork.
- Pre-submission (week 8) — dry-run the full tag-to-Devpost-zip path against a throwaway `v-smoke` tag.
- After a major CI change (new workflow, protection rule rewrite, Docker base bump).

Every step declares its "green" condition. Stop at the first red; chase the root cause before continuing.

---

## Pre-flight

- [ ] `gh auth status` green (authenticated to the target repo).
- [ ] `docker` + `docker compose` + `bash` + `jq` + `git` + `curl` on `PATH`.
- [ ] Repo cloned at the expected path; `git status` clean on `master`.
- [ ] `bash scripts/verify-sandbox.sh` reports all runnable layers PASS.

## 1. Branch protection applied

- [ ] `bash scripts/setup-branch-protection.sh` exits 0 (or confirms rules already in place).
- [ ] `gh api repos/${OWNER}/${REPO}/branches/master/protection --jq '.required_status_checks.contexts'` returns the full list: `l0-static / workflow-lint`, `shell-lint`, `python-lint`, `rust-lint`, `typescript-lint`, `docs-consistency`, and `l1-unit / unit-build`.

## 2. PR → L0 → L1 happy path

- [ ] Push a throwaway branch with a trivial change and open a draft PR via `gh pr create --draft`.
- [ ] On the PR: `l0-static` and `l1-unit` workflows auto-trigger and go green within 10 minutes.
- [ ] `l2-sift-lite` (advisory) posts a sticky comment on the PR with "does not block merge" disclaimer.
- [ ] Merge the PR via `gh pr merge <N> --squash` (manual — never auto-merge).

## 3. L3 nightly on merge

- [ ] Merging to `master` triggers `l3-nightly.yml` automatically.
- [ ] Job either:
      - Completes green on a KVM-enabled runner, OR
      - Exits with `::warning::KVM not available` on a runner without `/dev/kvm`.
      The second is acceptable pre-launch; swap to a larger runner before release.
- [ ] Slack `#ci-alerts` fires on L3 failure; silent on success.

## 4. Release tag → artifacts

Cut a throwaway tag to exercise the release path end-to-end:

- [ ] `git tag v-smoke && git push origin v-smoke`.
- [ ] `release.yml` starts; `l3-gate` job either confirms green L3 or emits pre-Week-2 `::warning`.
- [ ] Confirm the release log notes the A2 removal of the `build-deb` job; no `.deb` artifact is expected.
- [ ] `build-docker` job pushes `ghcr.io/${OWNER,,}/find-evil:v-smoke` and `:latest`.
- [ ] `build-report` job uploads `report.html` from the current report-rendering path.
- [ ] `publish` job creates or updates the GH Release and runs `scripts/push-leaderboard-score.sh`.
  - Leaderboard push is non-fatal — acceptable if `LEADERBOARD_API_KEY` is unset.
- [ ] Slack `#releases` posts the "shipped" message.

Clean up with `gh release delete v-smoke -y && git push origin :refs/tags/v-smoke`.

## 5. Competitor watch

- [ ] `gh workflow run competitor-watch.yml` (manual dispatch).
- [ ] Run completes green.
- [ ] `chore/competitor-state` branch has an updated `state/competitor-watch.json` (only if any watched repo changed since last run).
- [ ] Slack `#competitor-watch` either posts a delta report or stays quiet (both correct).

## 6. Devpost submission dry-run

Pre-condition: set `DEMO_VIDEO_URL` actions variable to a real URL (YouTube/Vimeo):

```bash
gh variable set DEMO_VIDEO_URL --body "https://youtu.be/<id>"
```

- [ ] Cut an `v-submit-smoke` tag locally, push it (do NOT push `v-submit` in smoke mode — that's the real submission).
  - Alternative: manually trigger `devpost-submit.yml` against a `v-submit` tag from a throwaway fork.
- [ ] `wait-release` job polls until `release.yml` succeeds (up to 30 min).
- [ ] `package` job:
      - Verifies `DEMO_VIDEO_URL` non-empty, fails fast otherwise.
      - Downloads release artifacts + latest weekly L3 verdicts.
      - Includes `release-assets/readiness-packet.zip` when present; this optional expert-review packet comes from `scripts/readiness-gate.ps1`.
      - Runs `scripts/json-to-benchmark-csv.py` → `benchmark-results.csv`.
      - Runs `scripts/package-devpost.sh` → `find-evil-submission.zip`.
      - Integrity-checks the zip contents: `README-submission.md`, `benchmark-results.csv`, `demo-video-link.txt`, `LICENSE`, `report.html`, and optional `readiness-packet.zip` when bundled. (Pre-A2 also `.deb`; pre-Phase-3d also `SUBMISSION_NOTES.md`; both were removed.)
      - Uploads the zip to the GH Release under the `v-submit` tag.
- [ ] Slack `#releases` posts the "Devpost package ready" message.

Clean up any test tags: `gh release delete v-submit-smoke -y && git push origin :refs/tags/v-submit-smoke`.

## 6b. Local readiness packet

Run this on native Windows when preparing a human expert review packet:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker
```

Green condition:

- [ ] Command exits 0 and prints `READY_FOR_EXPERT_REVIEW`.
- [ ] `tmp/readiness-gates/<run-id>/readiness-summary.json` exists with `readiness_state` set to `READY_FOR_EXPERT_REVIEW` and `customer_releasable` set to `false`.
- [ ] `tmp/readiness-gates/<run-id>/packet/readiness-packet-manifest.json` lists the copied artifacts.
- [ ] `tmp/readiness-gates/<run-id>/readiness-packet.zip` exists.

If the gate prints `READINESS_BLOCKED`, inspect `blockers` in `readiness-summary.json`. A passing packet is ready for human expert review, not direct customer release.

Fixed `-RunId` reruns refresh generated packet contents. If the original `<run-id>-build` local-build child run already exists, the gate may create a fresh `<run-id>-build-<timestamp>` child run while keeping the readiness packet under the requested `<run-id>`.

## 7. Documentation parity

- [ ] `docs/architecture.md` renders the Mermaid diagrams (paste into a Mermaid-capable viewer or check on GitHub).
- [ ] `docs/DATASET.md` lists every fixture that `scripts/fetch-fixtures.sh` downloads.
- [ ] `CLAUDE.md` references the Amendment A1 credential modes and Option B.
- [ ] `README-submission.md` template placeholders all exist in `docs/templates/devpost-readme.md` and are declared in `scripts/package-devpost.sh` (`DEMO_VIDEO_URL`, `RELEASE_TAG`, `ACCURACY`, `DATE`).

---

## Escalation

If any step fails:

1. Post to Slack `#ci-alerts` with the GHA run URL and which step failed.
2. Open a GitHub issue tagged `ci-smoke` citing the step number and the exact error.
3. If it's a secret / credential problem, check the repo Settings → Secrets and Variables → Actions page for the missing name. See glue Spec #4 §5 for the canonical list.
4. If it's a workflow-syntax issue: run `actionlint .github/workflows/*.yml` locally and fix before pushing a patch.

Green run end-to-end: expect ~25–40 minutes when KVM runners are available, ~15–20 minutes when L3 gracefully skips.
