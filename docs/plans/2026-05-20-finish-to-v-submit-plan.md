# Finish-to-`v-submit` Plan

> **Status: SHIPPED** (2026-05-20). `v-submit` was released from commit `f19f587` and the GitHub release contains `report.html` plus the validated submission bundle. This plan is retained as launch history; it is superseded by [`2026-06-06-seamless-integration-and-submission-plan.md`](2026-06-06-seamless-integration-and-submission-plan.md) (combined finish plan for all three integration phases). Use [`../release-evidence/README.md`](../release-evidence/README.md) for current release evidence and [`../README.md`](../README.md) for the docs index.

**Created:** 2026-05-20 (26 days before the 2026-06-15 22:45 CDT SANS Find Evil! deadline)
**Reviewed/updated:** 2026-05-20 against live git, GitHub, readiness, CI, and Devpost packaging state.
**Scope chosen:** Launch path first; sprite + chrome polish remains optional unless explicitly pulled into the submission scope.
**Source question:** "how come this project isn't done?"

## Context

You asked because it feels unfinished, but the current evidence says the engineering product is mostly complete and the launch process is what remains. The current `v-submit` blockers are not another product rewrite. They are:

1. **A stalled local prep batch** - 17 tracked modified files from the `chore(submission): consolidate shipped work before v-submit` pass, plus this new launch-plan doc.
2. **Pre-submission GitHub/Devpost setup** - the remote exists, but the repo is still private and `DEMO_VIDEO_URL` is not set.
3. **Release CI evidence** - final `v-submit` workflows require green L3 evidence, but no successful `l3-nightly` or `l3-weekly` run is currently visible on GitHub.
4. **Readiness semantics** - `READY_FOR_EXPERT_REVIEW` is the intended automation stop state. The readiness gate deliberately does not mark `customer_releasable: true`; human expert approval remains required.
5. **Optional visual polish** - pixel-art sprites plus `AuditBeadString` / `HashChainBadge` / `FindingChip` remain parked design polish, not a core launch blocker.

---

## Evidence Summary

### Readiness packet

`tmp/readiness-gates/readiness-case-002-full-20260514T213523/readiness-summary.json` (2026-05-15T02:39:30Z):

- `readiness_state: "READY_FOR_EXPERT_REVIEW"`
- `blockers: []`
- All 6 packet steps passed: `local-build`, `find-evil-auto`, `l1-docker`, `manifest-verify-local`, `packet-zip`, `submission-assets-validator`.
- `signer: "stub"`
- `customer_releasable: false`
- Only warning: `report QA has warnings: EXPERT_REVIEW_DRAFT`.

Important correction: `scripts/readiness-gate.ps1` writes `customer_releasable = $false` by design, even when `-Signer sigstore` is used. `CLAUDE.md` also states that `READY_FOR_EXPERT_REVIEW` means ready for human expert review, not customer release.

### Autonomous queue

User-level queue: `C:/Users/newbi/.claude/projects/C--Users-newbi-Desktop-PUG-Projects-SANS-Hackathon/memory/project_autonomous_queue.md`.

- Status line 7: `autonomous-queue-exhausted`.
- Lines 427-433 still list hard blockers:
  - `[ ] GitHub remote + push`
  - `[ ] Demo video recording`
  - `[x] Dockerfile A2 alignment`
- Live review updates that queue text: the remote now exists, but the repo is still private and the demo URL variable is missing.

### Git and GitHub state

Reviewed 2026-05-20:

- Local branch: `master` tracking `origin/master` with no ahead/behind divergence.
- Remote: `https://github.com/TimothyVang/sans-hackathon.git`.
- GitHub repo visibility: `PRIVATE`.
- `DEMO_VIDEO_URL`: not found.
- Local `v-submit` tag: absent.
- Remote `v-submit` tag / GitHub release: absent.
- `git status --short`: 17 tracked modified files plus untracked `docs/plans/2026-05-20-finish-to-v-submit-plan.md`.

### Release CI state

- `.github/workflows/release.yml` accepts `v-submit`, and its L3 gate now searches successful `l3-nightly.yml` runs on branch `master`.
- The GitHub default branch is `master`.
- `.github/workflows/l3-nightly.yml` now has `push.branches: [master]`, matching the current default branch.
- No successful `l3-nightly.yml` or `l3-weekly-goldens.yml` runs were visible during review; recent L3 runs were queued or cancelled.
- `.github/workflows/devpost-submit.yml` blocks final `v-submit` if `DEMO_VIDEO_URL` is empty and also requires a successful weekly L3 verdict artifact.

### A3 dashboard / polish state

`docs/plans/2026-04-26-amendment-a3-plan.md:3` says A3 Phases 1-4 and the role-state dashboard shipped, while pixel-art and chrome polish are parked. Live code matches that:

- `apps/web/components/sprites/{PoolA,PoolB,Verifier,Judge,Correlator}Sprite.tsx` still contain placeholder visuals.
- `apps/web/public/sprites/` does not exist.
- `AuditBeadString`, `HashChainBadge`, and `FindingChip` are documented as remaining in `apps/web/README.md`, but not implemented as components.

---

## Diagnosis

The project is launch-blocked, not feature-blocked. The core product, MCP surfaces, readiness packet flow, Devpost packaging scripts, and dashboard shell exist. The actual remaining launch work is to consolidate the local prep diff, resolve GitHub/Devpost metadata, obtain green L3 evidence, cut `v-submit`, and manually submit the generated package to Devpost.

In one line: **the engine is done; the launch checklist is not.**

---

## Path to `v-submit` (ordered)

### Step 1 - Review and commit the stalled prep

- Review the 17 modified tracked files by group: docs, smoke scripts, web, docker.
- Include this launch plan in the docs commit.
- Stage into 2-3 logical commits using existing Conventional Commit style.
- Run the local smoke gate before pushing:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1`

### Step 2 - Produce required CI evidence

- `l3-nightly.yml` successful on `master` with `headSha` equal to the commit that will receive the `v-submit` tag.
- `l3-weekly-goldens.yml` successful with downloadable `l3-weekly-verdicts` artifact.

### Step 3 - Refresh the readiness packet

- Re-run the packet gate against current `master` after commits and CI fixes:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker`
- Optional custody rehearsal:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker -Signer sigstore`
- Expected state remains `READY_FOR_EXPERT_REVIEW`, `blockers: []`, and `customer_releasable: false`.
- `sigstore` is useful custody evidence; it does not remove the explicit human expert release gate.

### Step 4 - Resolve GitHub and demo-video blockers

- Make the repo public before final Devpost submission:
  - `gh repo edit TimothyVang/sans-hackathon --visibility public`
- Record the demo video per `docs/demo-script-a2.md`.
- Set the real demo URL before cutting `v-submit`:
  - `gh variable set DEMO_VIDEO_URL --repo TimothyVang/sans-hackathon --body 'https://youtu.be/<id>'`

### Step 5 - Cut and push `v-submit`

- Confirm status is clean and CI evidence exists.
- Cut the tag:
  - `git tag v-submit`
  - `git push origin v-submit`
- Watch both workflows:
  - `.github/workflows/release.yml`
  - `.github/workflows/devpost-submit.yml`
- Expected artifact: GitHub release `v-submit` contains `find-evil-submission.zip`.

### Step 6 - Submit to Devpost manually

The workflow packages the zip and uploads it to the GitHub release; it does not submit the Devpost form.

- Download the release artifact:
  - `gh release download v-submit --repo TimothyVang/sans-hackathon --pattern find-evil-submission.zip`
- Upload `find-evil-submission.zip`, the public repo URL, and the demo video URL to Devpost manually.

### Step 7 - Optional sprite + chrome polish

Only do this before `v-submit` if visual polish is explicitly in scope and time remains.

- Implement `AuditBeadString`, `HashChainBadge`, and `FindingChip` under `apps/web/components/`.
- Add pixel-art sprite assets under `apps/web/public/sprites/`.
- Swap placeholder JSX inside the five existing sprite components without changing their props.
- Verify with:
  - `pnpm --filter @findevil/web typecheck`
  - `pnpm --filter @findevil/web test`
  - `pnpm --filter @findevil/web build`

---

## Critical Files

- `CHANGELOG.md` - `[Unreleased]` block to settle before `v-submit`.
- `tmp/readiness-gates/readiness-case-002-full-20260514T213523/readiness-summary.json` - current readiness evidence.
- `scripts/readiness-gate.ps1` - authoritative readiness state writer; always stops at expert review.
- `scripts/find_evil_auto.py` - `--signer` flag and release-gate logic.
- `.github/workflows/l3-nightly.yml` - branch and L3 evidence source.
- `.github/workflows/l3-weekly-goldens.yml` - Devpost benchmark artifact source.
- `.github/workflows/release.yml` - `v-submit` release gate.
- `.github/workflows/devpost-submit.yml` - requires `DEMO_VIDEO_URL`, weekly L3 artifact, and release success.
- `scripts/package-devpost.sh` - assembles `find-evil-submission.zip`.
- `scripts/validate-submission-assets.py` - strict artifact validator.
- `docs/runbooks/github-remote-bootstrap.md` - repo visibility and final tag runbook.
- `docs/demo-script-a2.md` - 5-minute demo-video script.
- `apps/web/components/sprites/*.tsx` - placeholder sprite components.
- `apps/web/README.md` - documents remaining A3 visual polish.

## Verification Checklist

- After Step 1: `git status --short` shows no modified tracked files except any intentionally deferred work.
- After Step 1: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` exits 0.
- After Step 2: `gh run list --workflow=l3-nightly.yml --branch=master --status=success --json headSha,databaseId` shows a successful run whose `headSha` matches the commit to tag.
- After Step 2: `gh run list --workflow=l3-weekly-goldens.yml --status=success --limit=1 --json databaseId` returns a run ID, and `gh run download <run-id> --name l3-weekly-verdicts --dir <tmp-dir>` succeeds.
- After Step 3: new `readiness-summary.json` has `readiness_state: "READY_FOR_EXPERT_REVIEW"`, `blockers: []`, and `customer_releasable: false`.
- After Step 4: `gh repo view TimothyVang/sans-hackathon --json visibility` returns `PUBLIC`.
- After Step 4: `gh variable get DEMO_VIDEO_URL --repo TimothyVang/sans-hackathon` returns the real video URL.
- After Step 5: `gh release view v-submit --repo TimothyVang/sans-hackathon` shows `find-evil-submission.zip` attached and `devpost-submit.yml` is green.
- End-to-end: a judge can clone the public repo, run `scripts/install.sh`, start `claude` or `scripts/find-evil`, investigate a case, and verify the manifest offline via the `manifest_verify` MCP tool.

---

## Review Conclusion

The previous version of this plan was directionally right but overclaimed the sigstore/readiness outcome and missed two release blockers: the branch mismatch that would prevent `master` from satisfying release L3 gates, and the missing weekly L3 artifact required by Devpost packaging. The corrected plan treats `READY_FOR_EXPERT_REVIEW` as the automation finish line, keeps human expert release approval explicit, and adds the real GitHub/Devpost tasks that must happen before the hackathon submission is launched.
