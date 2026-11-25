# GitHub remote bootstrap — runbook

**Status:** historical bootstrap runbook, updated for the current dev-first release flow. Devpost points at `https://github.com/TimothyVang/verdict-dfir`, but release changes should land in `TimothyVang/dev-verdict-github` first for review before any curated promotion to the local `release` remote. The older bootstrap steps below are retained for archaeology and for anyone recreating the setup from scratch.

Current release facts:

- Public repo: `TimothyVang/verdict-dfir`
- Local release remote: `release`
- Existing public submission tag/release: `v-submit`
- Do not delete, retarget, or force-update `v-submit` unless the release workflows and gates have been explicitly re-verified.

---

## Decisions to make first

1. **Repo owner.** Personal account vs an org you control.
   Devpost just needs a public URL; the repo owner doesn't have
   to match the Devpost username.  Personal account is faster
   if you already have one configured for `gh auth login`.

2. **Repo name.** Three reasonable options:
   * `find-evil` — matches the project name + `find-evil`
     command everywhere in this repo.  Recommended.
   * `sans-find-evil-2026` — date-anchored, easier to find
     among SANS-related search.
   * `find-evil-submission` — distinguishes from a future
     non-hackathon fork.

3. **Visibility.** Two reasonable options:
   * **Public from day 1** — simplest, matches the Devpost
     contract.  Caveat: anyone watching SANS competitor
     repos sees your work-in-progress before submit.
   * **Private now, public at v-submit** — protects WIP from
     SANS competitor recon scripts (`scripts/competitor-watch.sh`
     is exactly that pattern from the other side).  Requires
     a `gh repo edit --visibility public` step at v-submit.
     Recommended unless you don't mind being scouted.

---

## Bootstrap commands

Assuming Decision 1 = personal `<your-username>`, Decision 2 =
`find-evil`, Decision 3 = private-then-public.

```bash
# Pre-flight: confirm gh is authenticated.
gh auth status
# Should show "Logged in to github.com as <your-username>".
# If not: gh auth login --web

# Create the repo (private).  --source pushes the current
# branch's commits in one shot.
gh repo create <your-username>/find-evil \
  --private \
  --source . \
  --push \
  --description "SANS Find Evil! 2026 - cryptographically-verifiable DFIR agent"

# Confirm the remote landed:
gh repo view <your-username>/find-evil
git remote -v
# origin should now be git@github.com:<your-username>/find-evil.git

# Run the post-push setup (branch protection on master).
bash scripts/setup-branch-protection.sh
# Verifies: required L0 + L1 status checks, no force-push,
# admin-bypass disabled.  Spec #4 §6.

# Set the Devpost video URL repo-variable now (even though
# the URL isn't recorded yet) so devpost-submit.yml's
# preflight on v-submit passes:
gh variable set DEMO_VIDEO_URL --body 'pending-record'
# Update later with the real https://youtu.be/<id>.
```

After these commands the L0 + L1 GHA workflows should kick off
on the first push.  Wait ~5 min and verify both green:

```bash
gh run list --limit 5
# All recent runs should show Status: completed, Conclusion: success.
```

---

## Pre-v-submit checklist (historical)

When recreating the original submission flow from a new repo:

```bash
# 1. Make the repo public if it was private.
gh repo edit <your-username>/find-evil --visibility public

# 2. Update DEMO_VIDEO_URL to the real video.
gh variable set DEMO_VIDEO_URL --body 'https://youtu.be/<your-id>'

# 3. Tag v-submit.  release.yml fires first (~10 min: Docker image +
#    report.html; .deb was cut under A2).  devpost-submit.yml fires after
#    release.yml succeeds (waits up to 30 min, then assembles the
#    submission zip).
git tag v-submit
git push origin v-submit

# 4. Wait for both workflows to finish; download the
#    find-evil-submission.zip artifact:
gh release download v-submit --pattern find-evil-submission.zip

# 5. Upload that zip to Devpost manually.
```

For the current repo, prefer:

```bash
git remote -v                       # confirm release points at TimothyVang/verdict-dfir
gh repo view TimothyVang/verdict-dfir
gh release view v-submit --repo TimothyVang/verdict-dfir
```

Only cut or refresh release assets after confirming the workflow registrations and required gates for the exact target commit. For active development, push a review branch to `origin` (`TimothyVang/dev-verdict-github`) and review it there first; after approval, promote the exact reviewed commit or a controlled cherry-pick to `release` (`TimothyVang/verdict-dfir`).

---

## What can go wrong

* **`gh auth status` says not logged in.**  Run
  `gh auth login --web` and pick HTTPS or SSH per your
  preference.
* **`gh repo create` fails with 422 "name already exists".**
  Either pick a different name or delete the existing repo
  with `gh repo delete <your-username>/find-evil` (irreversible).
* **First push hangs because the repo has 80 GB of test
  forensics in the working tree.**  Verify `.gitignore` is
  excluding `test-forensics/` (it should be; line 95-101).
  `git status --ignored` shows what would be committed.
* **L0 or L1 fail on first push.**  Most likely cause: a
  toolchain mismatch with the GHA runner (Rust 1.88 / Python
  3.11). The amendment-a2-guard job specifically
  fails if the dropped pre-A2 modules are committed —
  `git ls-files services/agent/findevil_agent/{cli,graph,api,
  supervisor,specialists}.py` should return nothing.
* **`setup-branch-protection.sh` fails with 403.**  Branch
  protection on master requires the repo owner; if `gh auth
  status` shows a different user, switch first.

---

## Recommendation framing

For new forks, pick a repo name that matches the public product (`verdict-dfir`) unless there is a concrete reason to preserve the older `find-evil` name. Internal script and package names still use `findevil` / `find-evil`; that is expected and not a release-blocking mismatch.
