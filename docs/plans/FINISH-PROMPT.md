# FINISH-PROMPT — Drive SANS Find Evil to a Re-cuttable `v-submit`

> Reusable finishing prompt. Paste the block below into a fresh `claude` session
> from the repo root, or queue it into `scripts/autonomous-loop.py` via
> `memory/project_autonomous_queue.md`.

**Last updated: 2026-06-07.** Phases 0–3 and Finish F1–F2 are **SHIPPED** (see
`CHANGELOG.md [v-submit]`). This prompt now starts at the remaining open work: F3
(smoke gate), F5 (demo video render + upload), and the human-only F6–F7 (Devpost).

---

You are the SANS Find Evil! build agent working in
`/home/analyst/Desktop/PUG-Projects/sans-hackathon`. The project is in its final
submission phase. Phases 0–3 and F1–F2 are fully shipped on `master` (commit
`7989d77`, tag `v-submit`). Your job is to complete the remaining open tasks, then
stop and hand off the human-only steps.

## Current state (as of 2026-06-07, commit 7989d77)

### DONE — do not re-execute
- Phase 0: L1 esperanto offline fix — shipped `ed03182`
- Phase 1.1–1.5: playbook.py, config.py, sprite-state.ts, CLAUDE_CODE_FORK_SUBAGENT docs — shipped
- Phase 2.1–2.7: cross-platform render, SIFT config, libvirt, starter data, find-evil-run, doctor/install, smoke registration — shipped
- Phase 3.1–3.4: Protocol SIFT positioning in architecture + README + divergence-smoke + codex-compat — shipped
- F1: CHANGELOG settled to 31-tool surface, `[v-submit]` section opened — shipped `823b16d`
- F2: 2026-05-20 plan marked superseded, README badges refreshed — shipped (part of `b2dbc71`)
- SUBMISSION_COMPLIANCE.md — 10-item Devpost compliance checklist — shipped `c6af41a`
- Remotion demo video pipeline — `scripts/make-demo-video/` + `scripts/make-demo-video.sh` — shipped `7289cad`
- `claude -p` narration enrichment — shipped `7989d77`

### OPEN — execute in this order

**F3 — Smoke gate + verify**
**F5 — Generate demo video + upload**
**F6 (human only) — Tag re-cut + Devpost**

---

## Preflight (run ONCE at session start)

1. `git status` — confirm clean tree on `master`. If dirty, stop and ask.
2. `git log --oneline -5` — confirm `7989d77` (or a later commit) is HEAD.
3. Derive remaining open work from `git log` + file presence. Never trust this
   file's task list blindly — verify each item is actually missing before executing.

---

## F3 — Smoke gate (automated)

Run the full local smoke gate and confirm exit 0:

```bash
bash scripts/run-all-smokes.sh
```

Expected: 17+ smokes, 0 failed. If any fail, fix root cause — do not skip.

Then create the draft PR (if one does not already exist):

```bash
gh pr create --draft --fill --base master
```

Gate: `gh pr list --state open --base master` shows an open draft PR.

---

## F5 — Demo video generation (automated, then human upload)

### F5a — Generate the MP4 (automated)

Prerequisites (one-time install):
```bash
pip install edge-tts
pnpm install --dir scripts/make-demo-video --ignore-workspace
```

Dry-run to verify beat parsing (no TTS/Remotion needed):
```bash
python3 scripts/make-demo-video-prep.py --dry-run
# Expected: 9 beats, total 300s
```

Full render (TTS + Remotion animated video → `docs/find-evil-demo.mp4`):
```bash
bash scripts/make-demo-video.sh
```

- If `claude` is on PATH, narrations are auto-enriched via `claude -p` before TTS.
- Uses `en-US-AriaNeural` Microsoft neural TTS (no API key).
- Remotion renders 1920×1080 animated title cards (fade-in, typewriter, spring transitions).
- Output replaces the 385 KB placeholder at `docs/find-evil-demo.mp4`.

Commit the generated video:
```bash
git add docs/find-evil-demo.mp4
git commit -m "feat(submission): generate demo video via Remotion + TTS"
git push origin master
```

### F5b — Host video (human only — cannot be automated)

1. Upload `docs/find-evil-demo.mp4` to YouTube or Vimeo.
2. Register the URL:
   ```bash
   gh variable set DEMO_VIDEO_URL --body 'https://youtu.be/<id>'
   ```
3. Update `SUBMISSION_COMPLIANCE.md` item #6 — change `SEE §6` to `SATISFIED` and
   paste the hosted URL.

---

## F6 — Re-cut `v-submit` tag (human only)

After F5b is confirmed green:

```bash
git tag -f v-submit HEAD
git push origin v-submit --force
```

This triggers `devpost-submit.yml` CI, which gates on `release.yml` (L3 green) and
produces the `find-evil-submission.zip` release artifact.

---

## F7 — Devpost upload (human only)

1. Download `find-evil-submission.zip` from the GitHub Release for `v-submit`.
2. Verify the zip contains `REPORT.html`, `audit.jsonl`, `run.manifest.json`, and
   `manifest_verify.json`.
3. On the Devpost submission form, fill in:
   - **Project URL:** `https://github.com/TimothyVang/sans-hackathon`
   - **Demo video URL:** the hosted YouTube/Vimeo URL from F5b
   - Upload the `find-evil-submission.zip` bundle
4. Confirm submission before the 2026-06-15 22:45 CDT deadline.

---

## Definition of done (the whole run is complete only when ALL hold)

- `bash scripts/run-all-smokes.sh` exits 0
- A draft PR exists against `master`
- `docs/find-evil-demo.mp4` is > 10 MB (full Remotion render, not the 385 KB placeholder)
- `SUBMISSION_COMPLIANCE.md` item #6 is `SATISFIED` with a hosted URL
- `v-submit` tag points to the commit with the rendered MP4
- Devpost form submitted before 2026-06-15 22:45 CDT

If any cannot be met, STOP and report exactly which and why — do not fake completion.

---

## Headless execution note (autonomous-loop)

When run via `scripts/autonomous-loop.py` (`claude -p --permission-mode acceptEdits`),
F3 smoke gate and F5a video generation are automatable. F5b (upload), F6 (tag re-cut),
and F7 (Devpost form) require human action — list them in the handoff instead of failing.
The `docker` L1 gate and `gh pr create` may also require interactive prompts; defer to
human if they fail.

---

## Reference: what shipped in Phases 0–3 + F1–F2

| Commit | Task |
|--------|------|
| `ed03182` | Phase 0: esperanto offline fix |
| `ed03182` | Phase 1.1: playbook.py unified detection rules |
| `47c4501` | Phase 1.2: resolve_memory_store_path + cross-case memory |
| `9e619e6` | Phase 1.3: contradiction resolution + self-score criteria |
| `057866a` | Phase 1.4: dashboard role-state from real audit kinds |
| `6e2bef7` | Phase 1.5: CLAUDE_CODE_FORK_SUBAGENT docs corrected |
| `a7adaae` | Phase 2.1: cross-platform pandoc/chrome resolver |
| `423514a` | Phase 2.2: SIFT MCP portable defaults |
| `1228e2a` | Phase 2.3: libvirt hypervisor path |
| `8df9259` | Phase 2.4: SANS starter staging hook + goldens stub |
| `83aeb84` | Phase 2.5: find-evil-run one-command entry |
| `7ee3006` | Phase 2.6: doctor.sh + install.sh deps |
| `f64f1f7` | Phase 2.7: smoke registration |
| `6bddfcc` | Phase 3.3: .mcp.json surface lock (divergence #10) |
| `779d42e` | Phase 3.4: codex-compat Protocol SIFT coexistence |
| `b2dbc71` | Phase 3.1+3.2 + F2: architecture + README + plan supersede |
| `823b16d` | F1: CHANGELOG settled to 31-tool surface |
| `c6af41a` | SUBMISSION_COMPLIANCE.md |
| `7289cad` | Remotion demo video pipeline (scripts/make-demo-video/) |
| `0e80ae0` | make-demo-video.py (legacy static-slide, superseded by Remotion) |
| `7989d77` | claude -p narration enrichment |
