# FINISH-PROMPT — Drive SANS Find Evil to a Re-cuttable `v-submit`

> Reusable finishing prompt. Paste the block below into a fresh `claude` session
> from the repo root, or queue it into `scripts/autonomous-loop.py` via
> `memory/project_autonomous_queue.md`. It executes every engineering task in
> `docs/plans/2026-06-06-seamless-integration-and-submission-plan.md` (Phases 0–3 +
> Finish F1–F4), then stops and hands off the human-only steps (F5–F7).

---

You are the SANS Find Evil! build agent working in `/home/analyst/Desktop/PUG-Projects/sans-hackathon`. Your goal: drive the project to a green, re-cuttable `v-submit` by executing every engineering task in `docs/plans/2026-06-06-seamless-integration-and-submission-plan.md`, then stop and hand off the human-only steps.

## Definition of done (the whole run is complete only when ALL hold)
- Every task in `docs/plans/2026-06-06-seamless-integration-and-submission-plan.md` for Phases 0–3 and Finish F1–F4 has landed as its own conventional commit (the plan gives the exact message per task).
- `docker compose -f docker/l1-compose.yml up --build --exit-code-from l1` exits 0 (Phase 0 gate).
- `bash scripts/run-all-smokes.sh` exits 0 (no new failures vs. baseline).
- `bash scripts/readiness-gate.sh` prints `SUBMISSION_READY` (or documents why it can't locally).
- A draft PR exists against `master` (`gh pr create --draft --fill`).
- Plan **Appendix B (End-to-end verification checklist)** passes.
- A handoff summary for F5–F7 is printed.
If any cannot be met, STOP and report exactly which and why — do not fake completion.

## Preflight (run ONCE at session start, before any edits)
1. `git status` and `git log --oneline -25` — confirm clean tree on `fix/dfir-claim-corrections` (or branch from `master`). If the tree is dirty with unrelated changes, stop and ask.
2. Read `docs/plans/2026-06-06-seamless-integration-and-submission-plan.md` IN FULL. **The plan is the source of truth** (this file is a navigation aid). Note it has NO checkboxes — it uses per-task tables with RED-test / Impl-files / Commit-message / Gate fields, a per-phase **Verify** line, plus **Appendix A** (exact ordered command sequence) and **Appendix B** (verification checklist). Follow the plan's own fields verbatim; where this file disagrees with the plan, the plan wins.
3. **Determine what's already done by `git log`, not by this file** — for each task, grep the log for its exact commit message (`git log --oneline | grep -F '<commit msg>'`) and confirm the code/file it describes is present. Skip done tasks; execute only the genuinely-open ones.
4. Build a TodoWrite list from the still-open tasks in the dependency order below. Mark each `in_progress` when you start it and `completed` only after its commit lands.
5. This prompt is **idempotent and resumable** — safe to re-run via `scripts/autonomous-loop.py`. Always re-derive remaining work from `git log` + code presence, never from memory of a prior pass.

## Ground rules (from CLAUDE.md — non-negotiable)
- Read `docs/plans/2026-06-06-seamless-integration-and-submission-plan.md` in full first; it is authoritative. Where spec and code disagree, **shipped code + pin files win** (CLAUDE.md §11).
- **TDD per task:** failing test (RED) → implement (GREEN) → one commit per task using the **exact commit message** the plan specifies. Never batch tasks. Never use `--no-verify`, `--no-gpg-sign`, or `--amend`.
- Conventional Commits; scopes already in use: `mcp`, `swarm`, `sandbox`, `ci`, `plan`, `agent`, `report`, `architecture`, `readme`, `changelog`, `divergence`, `codex-compat`.
- **Surgical changes** — touch only what each task requires; match existing style; don't refactor adjacent code.
- DFIR vocabulary (Case/Observable/Task/Finding/Verdict/Confidence). All timestamps UTC ISO-8601 `Z`.
- Stay on branch `fix/dfir-claim-corrections` (or branch from `master` if asked); **draft PRs only**, never push/merge `master`.
- Preserve invariants: no `execute_shell` tool; every Finding cites a `tool_call_id`; audit JSONL append-only; AGPL/GPL tools subprocess-only; 19+12=31 tool surface.

> NOTE: the task list below is a **navigation map** (titles + commit messages), not the spec.
> For each task, read the matching section in the plan and follow its RED / Impl / Commit / Gate
> fields exactly. The plan's **Appendix A** is the canonical ordered command sequence and **Appendix B**
> is the canonical verification checklist — prefer those over this summary if they ever differ.

## Execution order (sequential phases; respect intra-phase dependencies)

### Phase 0 — Unblock L1 (DO FIRST; hard blocker)
Make the esperanto LLM factory test pass offline in the L1 devbase (no live provider/network); pin/relax the dep so `uv` resolves it, skip cleanly when no provider configured.
- Commit: `fix(agent): make esperanto LLM factory test pass offline in L1 devbase`
- Fast inner loop (no Docker; the plan's RED command): `uv run --directory services/agent pytest -xvs tests/test_llm.py` must pass offline first.
- Authoritative gate: `docker compose -f docker/l1-compose.yml up --build --exit-code-from l1` exits 0. If Docker is unavailable in this environment, run the fast loop, say so explicitly in your report, and let CI (L1 workflow) be the final arbiter. Do not proceed to Phase 1 until the fast loop is green.

### Phase 1 — Unify the two run paths (1.1→1.2→1.3→1.4 sequential; 1.5 independent)
1.1 New `services/agent/findevil_agent/playbook.py` (`EVIDENCE_TYPE_RULES`, `ARTIFACT_CLASS_RULES`, `TOOL_SEQUENCES` as frozen `PlaybookStep`, `JUDGE_SELFSCORE_CRITERIA`); `find_evil_auto.py` imports it; delete the 3 duplicate Python tables; feed in-VM script the rules as JSON arg.
  - `refactor(plan): unify evidence-type + tool-sequence detection in findevil_agent.playbook`
1.2 Add `resolve_memory_store_path()` to `config.py` (mirror `resolve_case_home:160-175`); auto path calls `memory_recall` before drafting a Finding and `memory_remember` after judge, **CONFIRMED-only**.
  - `feat(agent): add resolve_memory_store_path and wire cross-case memory into headless path`
1.3 Share the 6 self-score criteria via `playbook.JUDGE_SELFSCORE_CRITERIA`; JUDGING.md/PLAYBOOK.md cite identical text.
  - `feat(plan): record contradiction resolution + share self-score criteria across paths`
1.4 Extend `apps/web/lib/sprite-state.ts` `deriveRoleStates` to read `judge_selfscore`, `contradiction_resolved`, `manifest_finalize`, real `pool_origin`/`pool`.
  - `feat(plan): derive dashboard role-state from real audit kinds across both paths`
1.5 Correct `CLAUDE_CODE_FORK_SUBAGENT` docs — real in the **swarm**; in the **product** Claude Code forks Pool A/B via native Task mechanism (no env var).
  - `docs(plan): correct CLAUDE_CODE_FORK_SUBAGENT to native subagent mechanism in product docs`

### Phase 2 — One frictionless operator path (2.1–2.7)
2.1 Cross-platform report renderer: resolve `PANDOC`/`CHROME` via `$PANDOC_BIN`/`$CHROME_BIN`→`shutil.which`; `render_html_pdf` degrades to `(html, None)` instead of raising; fix `file://` via `Path(html).as_uri()`.
  - `fix(report): resolve pandoc/chrome via PATH for cross-platform render`
2.2 De-hardcode `.mcp.json.sift` (portable defaults `~/.ssh/sift_key`, env host/user, keep guest `~/.local/bin/...`); `find-evil-sift:28` `VMRUN="${SIFT_VMRUN:-...}"`.
  - `fix(sandbox): derive SIFT MCP key/host/binaries from env, drop hardcoded operator paths`
2.3 Linux hypervisor path: libvirt IP discovery (`virsh -q domifaddr "$VM_NAME"`) + `HYPERVISOR` knob; clear exit when none resolves.
  - `feat(sandbox): add libvirt IP discovery and graceful hypervisor gate to find-evil-sift`
2.4 Document `SANS_STARTER_URL=file://<staged>.zip` + `SANS_STARTER_SHA256` contract; create `goldens/sans-starter/expected-findings.json` stub.
  - `feat(plan): add SANS starter staging hook and goldens stub`
2.5 New `scripts/find-evil-run` (extensionless bash) chaining doctor → install[skip if built] → fixtures present-or-staged → `find-evil-auto`.
  - `feat(plan): add find-evil-run one-command operator path`
2.6 `doctor.sh` adds `unzip`+`python3` checks (stays read-only); `install.sh:28` sources `~/.cargo/env` before cargo check.
  - `fix(plan): cover unzip/python deps in doctor and source cargo env in install`
2.7 Register the new Phase 2 smokes in `run_smoke` lines.
  - `test(ci): register Phase 2 cross-platform smokes in local gate`

### Phase 3 — Protocol SIFT positioning (3.1–3.4 independent, docs)
3.1 `docs/architecture.md` "Relationship to Protocol SIFT" (2 typed servers / 31 tools / no execute_shell vs 200+ shell-backed).
  - `docs(architecture): position narrow typed surface relative to Protocol SIFT`
3.2 README coexistence block (same SIFT VM after `protocol-sift install`, neither requires nor conflicts).
  - `docs(readme): explain Protocol SIFT coexistence and divergence`
3.3 `divergence-smoke.py` asserts `.mcp.json` mcpServers == exactly `{findevil-mcp, findevil-agent-mcp}` and no command/args contain `protocol-sift`/`sift-gateway`/`execute_shell`/`bash -c`.
  - `test(divergence): lock .mcp.json to two typed servers, no gateway/shell drift`
3.4 `docs/codex-compatibility.md`: one bullet — gateway welcome as common base, NOT a product-default MCP.
  - `docs(codex-compat): name Protocol SIFT gateway as non-default, coexisting`

### Finish F1–F5 (code/doc + PR + verify + demo video)
F1 Settle `CHANGELOG.md [Unreleased]` to the current **31-tool** surface (19 Rust + 12 Python) and open a `## [v-submit] - 2026-06-<dd>` section. Read the plan's F1 entry and the existing CHANGELOG narrative first — the count history is nuanced (25→23 pre/post-A5, 31 after the June doc audit), so reconcile rather than blindly find/replace.
  - `docs(changelog): settle Unreleased to current 31-tool surface and open v-submit`
F2 Mark `docs/plans/2026-05-20-finish-to-v-submit-plan.md` superseded → 2026-06-06 plan; refresh README badge/release links.
  - `docs(plans): supersede 2026-05-20 finish plan; refresh release links`
F3 `bash scripts/run-all-smokes.sh` exit 0; then `gh pr create --draft --fill --base master`.
F4 (read-only) Verify L1 + l3-nightly green on the exact commit to be tagged; l3-weekly-goldens artifact non-empty.
F5 **Automated demo video** — generate `docs/find-evil-demo.mp4` using TTS + ffmpeg:
  ```bash
  # Prerequisites (one-time):
  pip install edge-tts          # Microsoft neural TTS, no API key required
  # sudo apt install ffmpeg     # or brew install ffmpeg

  # Optional: set GITHUB_TOKEN to enrich narration via GitHub Models API
  # export GITHUB_TOKEN=$(gh auth token)

  # Generate the 5-minute MP4:
  python3 scripts/make-demo-video.py

  # Dry-run (no ffmpeg/TTS; verify beat parsing):
  python3 scripts/make-demo-video.py --dry-run
  ```
  The script reads the 9-beat structure from `docs/demo-script-a2.md`, generates TTS
  audio per beat (`en-US-AriaNeural` voice), renders 1920×1080 title cards via ffmpeg
  `drawtext`, muxes audio + video, and concatenates into `docs/find-evil-demo.mp4`.
  Commit the resulting MP4:
  - `feat(submission): generate demo video via TTS+ffmpeg`

Then run the plan's **Appendix A** ordered command sequence and confirm **Appendix B** verification checklist passes end-to-end.

## Stop condition + handoff
After F5, STOP. Print a handoff summary listing the **human-only** steps you must NOT perform:
- **F6** Upload `docs/find-evil-demo.mp4` to YouTube or Vimeo, then register the URL:
  `gh variable set DEMO_VIDEO_URL --body 'https://youtu.be/<id>'`. Then re-cut:
  `git tag -f v-submit && git push -f origin v-submit` at the green HEAD.
- **F7** Download the refreshed `find-evil-submission.zip` from the GitHub Release, validate, upload zip + public repo URL + hosted demo URL to the Devpost form.

Report, per task: commit SHA + message, test status, and any deviation from the plan (log deviations, don't silently diverge). If any gate fails, stop and surface the failure with output — do not proceed to the next phase.

## Headless execution note (autonomous-loop)
When run via `scripts/autonomous-loop.py` (`claude -p --permission-mode acceptEdits`), file edits auto-apply but `docker`, `gh`, and network commands may still prompt or be unavailable. In that mode: complete all file/test/commit work, run the fast (non-Docker) gates, and defer the Docker L1 gate, `gh pr create`, and CI verification (F3 PR-create, F4) to a human/interactive pass — list them in the handoff instead of failing the run.
