# Finish "Find Evil!" — Seamless Integration (3 phases) + Submission

**Created:** 2026-06-06 (~9 days before the 2026-06-15 22:45 CDT SANS Find Evil! deadline)
**Scope:** all three integration phases (phased) + full finish-to-submission.
**Supersedes:** `docs/plans/2026-05-20-finish-to-v-submit-plan.md` (combined into this doc — see
"What carried over" below). This is the single authoritative finish plan.

> **Superseded by two later consolidations — read before the task tables below:**
> 1. **One operator command is `scripts/verdict <evidence>`.** The Phase 2.5
>    `find-evil-run` entry shipped, but `find-evil-run` (and `find-evil-live`)
>    are now deprecated shims that forward to `scripts/verdict`; `find-evil-auto`
>    is the internal headless engine `verdict` calls; `find-evil-sift` is the
>    SIFT-VM helper (`scripts/verdict --sift`). Read every `find-evil-run` /
>    `find-evil-auto` invocation below as `scripts/verdict`.
> 2. **`judge_selfscore` is removed from the investigation pipeline.** The
>    Phase 1.3 wiring (auto path emitting `kind=judge_selfscore` into the audit
>    chain; dashboard reading it) was rolled back. The six-criterion grade now
>    lives only in the standalone maintainer tool `scripts/self-score.py`, run
>    by hand before submission (writes `<case>/self-score.json`; does not touch
>    the sealed audit chain). `agent-config/JUDGING.md` is that grader's rubric.
>    The `judge_findings` Pool A/B merge agent (core ACH) is unchanged.

## Context

The SANS **Find Evil!** submission is feature-rich but not *seamless*: the "many tools and files"
don't yet act as one coherent system, and the actual launch state has drifted from the last plan.
The user asked to (a) review the Devpost resources page and (b) "seamlessly integrate the many
tools and files," choosing **all three integration phases, phased**, and **full
finish-to-submission** scope.

The Devpost resources page (`https://findevil.devpost.com/resources`) points to: SIFT OVA, the
**Protocol SIFT** POC (`teamdfir/protocol-sift`), **starter case data** (Egnyte — the "missing
download"), the NotebookLM Q&A, and the **Valhuntir** quality bar. The starter case data is the
primary golden judges test against — and it is **not on this machine** and cannot be `curl`-fetched
(Egnyte is a listing page). The user will install it later, so the plan makes it a clean hook, not
a blocker.

### What carried over from the 2026-05-20 plan (now combined here)
The old plan was directionally right but **stale on almost every live fact** (see table). Its
durable, still-true content is folded in: the readiness-packet semantics and state machine,
the customer-release gate, the critical-files list, and the submission verification checklist.
The 2026-05-20 doc is retained only as launch history.

**Verified current state (read-only `git`/`gh`, 2026-06-06) — corrects the old plan:**

| Old-plan claim (2026-05-20) | Live truth (2026-06-06) | Source |
|---|---|---|
| repo PRIVATE | **PUBLIC** (`TimothyVang/verdict-dfir`) | `gh repo view` |
| DEMO_VIDEO_URL unset | **set**, but to a 393 KB committed placeholder blob (raw-GitHub) | `gh variable list` |
| no green L3 | l3-nightly **green on HEAD**; l3-weekly green 2026-05-31 | `gh run list` |
| v-submit tag absent | **exists** @ `f19f587`, GH release published | `git tag`, `gh release` |
| 17 stalled tracked files | tree **clean** | `git status` |
| `READY_FOR_EXPERT_REVIEW` | actual gate strings are **`PACKET_READY_FOR_EXPERT_REVIEW`** (PacketOnly) / **`SUBMISSION_READY`** (sh); both keep `customer_releasable:false` | `readiness-gate-smoke.py:218`, `readiness-gate.sh:84` |
| — | **L1 Unit+Build is RED on HEAD** (broke at `c15f5db` esperanto) | `gh run list` |
| — | **HEAD is 5 commits ahead of `v-submit`** → published bundle is stale | `git rev-list` |
| — | `.env` holds a **live API key** (gitignored, won't ship — rotate it) | local |

**Intended outcome:** one coherent, cross-platform, Protocol-SIFT-recognizable agent that a judge
runs end-to-end with minimal friction, on a green-CI commit re-tagged `v-submit` and uploaded to
Devpost.

## Hard invariants (every task preserves these)
No `execute_shell` tool ever · every Finding cites a `tool_call_id` · epistemic hierarchy
CONFIRMED>INFERRED>HYPOTHESIS · execution claims need ≥2 artifact classes · evidence read-only ·
append-only hash-chained audit (prev_hash → rs_merkle → sigstore, 3 tiers) · AGPL tools
subprocess-only · MIT/Apache-2.0 clean tree · UTC ISO-8601 Z · narrow **31-tool** typed surface
(19 Rust + 12 Python) is **intentional** · narrative "orchestrator that reduces friction."
**TDD mandatory** (RED→GREEN, one conventional commit per task, never `--no-verify`/`--amend`).
Work on a branch → **draft PR → human merges** (no direct `master` push). Code wins over specs.

---

## Recommended execution order

**Phase 0 (`fix(agent)`) is a hard prerequisite — nothing ships until L1 is green.** Then the
three integration phases raise the judging score, then finish-to-submission. Submission-critical
minimum = Phase 0 + Finish-to-submission; Phases 1–3 are quality/score.

---

## Phase 0 — Fix L1 red (BLOCKER, do first)

`docker/l1-compose.yml:74` runs `uv run pytest` in `services/agent`; L1 broke at `c15f5db` which
added `esperanto>=2.0,<3.0` (`services/agent/pyproject.toml:57`), `findevil_agent/llm.py`, and
`services/agent/tests/test_llm.py`. L1 is a required check on `master`.

- **RED (the gate is the test):** `uv run --directory services/agent pytest -xvs tests/test_llm.py`
  then `docker compose -f docker/l1-compose.yml up --build --exit-code-from l1`.
- **Fix:** make `test_llm.py` pass **offline / in the devbase** — the esperanto factory must not
  require a live provider/network (the agent already supports multi-mode creds). Pin/relax the dep
  so `uv` resolves it in the devbase, and/or skip cleanly when no provider is configured (mirror
  the offline-safe pattern in `services/agent_mcp/tests`).
- **Impl:** `services/agent/pyproject.toml` and/or `findevil_agent/llm.py` and/or `tests/test_llm.py`.
- **Commit:** `fix(agent): make esperanto LLM factory test pass offline in L1 devbase`
- **Gate:** L1 green on new HEAD before anything else.

---

## Phase 1 — Unify the two run paths + wire dangling pieces

**Problem:** interactive (`investigate` → Claude Code *is* the orchestrator per A2, driven by
`agent-config/` prose) and headless (`scripts/find_evil_auto.py`, ~5,700 lines, deterministic
Python) **duplicate** evidence-type detection + the playbook, and dangling features (judge
self-score, contradiction resolution, Hermes memory, dashboard role-state) are wired in one path
or neither. (`classify_artifact_path` exists **4×**, incl. a string copy inside the in-VM
`remote_script` at `find_evil_auto.py:460-486`; `detect_evidence_type` is a 5th, coarser variant;
PLAYBOOK.md prose is the 6th.)

| # | Task | Test (file::name) | Impl | Commit |
|---|---|---|---|---|
| 1.1 | **Single source of truth** — new `services/agent/findevil_agent/playbook.py` with `EVIDENCE_TYPE_RULES`, `ARTIFACT_CLASS_RULES`, `TOOL_SEQUENCES` (frozen `PlaybookStep`), `JUDGE_SELFSCORE_CRITERIA`. `find_evil_auto.py` imports it; delete the 3 duplicate Python tables; feed the in-VM script the rules as a JSON arg (it can't import the package). | `services/agent/tests/test_playbook.py::{test_detect_evidence_type_matches_legacy_cases,test_tool_sequences_cover_all_evidence_types,test_playbook_md_tables_match_module}` + extend `scripts/verdict-policy-smoke.py` (already imports both fns) | `playbook.py` (new), `find_evil_auto.py`, `agent-config/PLAYBOOK.md` (ref the module) | `refactor(plan): unify evidence-type + tool-sequence detection in findevil_agent.playbook` |
| 1.2 | **Shared memory-store path + wire Hermes both paths** — add `resolve_memory_store_path()` to `config.py` (mirror `resolve_case_home:160-175`); auto path calls `memory_recall` before drafting a Finding and `memory_remember` after judge **CONFIRMED-only**. **Fix invariant bug:** `scripts/agent-mcp-smoke.py:481` comment wrongly says a recall hit "counts toward the ≥2 rule" — prior memory is context only. | `services/agent/tests/test_config.py::test_resolve_memory_store_path_precedence` | `config.py`, `find_evil_auto.py`, `agent-mcp-smoke.py` (comment) | `feat(agent): add resolve_memory_store_path and wire cross-case memory into headless path` |
| 1.3 | **Consistent judge_selfscore + contradiction recording** — share the 6 criteria via `playbook.JUDGE_SELFSCORE_CRITERIA` (auto path consumes; JUDGING.md/PLAYBOOK.md cite identical text). Both paths append `kind="contradiction_resolved"` `{contradiction_id, resolution, approved_by}` (extract pure `build_contradiction_resolution_record`). Interactive emits via prompt. | `test_playbook.py::test_judge_selfscore_criteria_match_judging_md`; `verdict-policy-smoke.py::check_contradiction_resolution_record` | `playbook.py`, `find_evil_auto.py`, `agent-config/{JUDGING,PLAYBOOK}.md` | `feat(plan): record contradiction resolution + share self-score criteria across paths` |
| 1.4 | **Dashboard real role-state** — extend `apps/web/lib/sprite-state.ts` `deriveRoleStates` to read `judge_selfscore`, `contradiction_resolved`, `manifest_finalize`, and real `pool_origin`/`pool`; add those fields to the auto path's `finding_approved`/`tool_call_start` payloads (via `_audit`, so they're inside the chained record). | `apps/web/__tests__/sprite-state.test.ts::{derives judge stage,flips verifier on contradiction,settles on manifest_finalize,reads pool_origin}` | `sprite-state.ts`, `find_evil_auto.py` | `feat(plan): derive dashboard role-state from real audit kinds across both paths` |
| 1.5 | **Correct `CLAUDE_CODE_FORK_SUBAGENT` docs** — it's real/shipped in the **swarm** (`critic.py:154`, `base_worker.py:150`); in the **product**, Claude Code forks Pool A/B via its native Task mechanism (no env var). Fix the prose in 4 files; lock with a divergence check. | `scripts/divergence-smoke.py::forbid_product_fork_env_claim` | `CLAUDE.md`, `agent-config/{AGENTS,PLAYBOOK}.md`, `docs/architecture.md`, `divergence-smoke.py` | `docs(plan): correct CLAUDE_CODE_FORK_SUBAGENT to native subagent mechanism in product docs` |

Sequencing: 1.1 → 1.2 → 1.3 → 1.4 (depends on 1.3's record + 1.1's pool attribution); 1.5 independent.
**Verify Phase 1:** `bash scripts/run-all-smokes.sh` (0 failed) · `uv run --directory services/agent pytest tests/test_playbook.py tests/test_config.py -v` · `pnpm --filter @findevil/web test && pnpm --filter @findevil/web typecheck` · `cargo test --workspace --locked` (regression). Manual: a `find-evil-auto` run's `audit.jsonl` carries `pool_origin`, `contradiction_resolved`, 6 `judge_selfscore` before `manifest_finalize`, and `memory.sqlite` holds CONFIRMED-only rows.

---

## Phase 2 — One frictionless operator path (cross-platform)

**Problem:** no single command runs install→doctor→fetch→investigate→report; the **report
renderer is broken on Linux** (`render_report.py:33-34` hardcodes Windows pandoc/chrome with no
`shutil.which` fallback → silent PDF skip); `.mcp.json.sift` bakes `C:/Users/newbi/...` and
VMware-only paths; starter data has no local-staging hook wired through to goldens.

| # | Task | Test (file::name) | Impl | Commit |
|---|---|---|---|---|
| 2.1 | **Cross-platform report renderer** (the real blocker) — resolve `PANDOC`/`CHROME` via `$PANDOC_BIN`/`$CHROME_BIN` → `shutil.which` (chrome candidates: `google-chrome,-stable,chromium,chromium-browser`, matching `doctor.sh:169`) → Windows fallback list; `render_html_pdf` degrades cleanly (returns `(html, None)`) instead of raising; fix the no-op `file://` build with `Path(html).as_uri()`. | `scripts/render-binary-smoke.py::test_render_binaries_resolve_cross_platform` (loads module via `importlib`, à la `report-policy-smoke.py`) | `scripts/render_report.py` | `fix(report): resolve pandoc/chrome via PATH for cross-platform render` |
| 2.2 | **De-hardcode `.mcp.json.sift`** — portable committed defaults (`~/.ssh/sift_key`, env host/user, keep `~/.local/bin/...` SIFT-guest binaries); `find-evil-sift:28` `VMRUN="${SIFT_VMRUN:-...}"`. (The launcher already rewrites `.mcp.json.sift` from env at runtime — fix the *committed* defaults.) | `scripts/sift-config-smoke.py::test_sift_mcp_config_has_no_hardcoded_operator_paths` | `.mcp.json.sift`, `scripts/find-evil-sift` | `fix(sandbox): derive SIFT MCP key/host/binaries from env, drop hardcoded operator paths` |
| 2.3 | **Linux hypervisor path + graceful gate** — add libvirt IP discovery (`virsh -q domifaddr "$VM_NAME"`) and a `HYPERVISOR` knob; when no hypervisor resolves, exit with a clear message naming supported ones + `sift-vm-bootstrap.sh` (not a raw `C:/...` not-found). | `sift-config-smoke.py::test_sift_launcher_gates_unsupported_hypervisor_gracefully` | `scripts/find-evil-sift` | `feat(sandbox): add libvirt IP discovery and graceful hypervisor gate to find-evil-sift` |
| 2.4 | **Starter-data staging hook + goldens stub** — document the `SANS_STARTER_URL=file://<staged>.zip` + `SANS_STARTER_SHA256` contract (already in `fetch-fixtures.sh:78-87`); create `goldens/sans-starter/expected-findings.json` stub (`"status":"pending_manual_walkthrough"`, mirrors sibling schema) so `docs/DATASET.md:19`, `path-existence-smoke.py:171`, and `l3-run-goldens.sh:35` stop dangling. | `scripts/starter-data-smoke.py::test_starter_data_hook_skips_when_unset_and_stages_when_set` | `goldens/sans-starter/expected-findings.json` (new), `fetch-fixtures.sh` (doc note) | `feat(plan): add SANS starter staging hook and goldens stub` |
| 2.5 | **One-command operator entry** — new `scripts/find-evil-run` (extension-less bash) that **chains existing scripts** (doctor → install[skip if built] → fixtures present-or-staged → `find-evil-auto`); `--dry-run`/`--skip-build`; aborts if doctor fails. Reuses, does not reimplement. | `scripts/find-evil-run-smoke.py::test_find_evil_run_chains_doctor_install_fixtures_auto` (`bash -n` + grep-asserts each stage path; `--dry-run` consumes no inference) | `scripts/find-evil-run` (new) | `feat(plan): add find-evil-run one-command operator path` |
| 2.6 | **Doctor/install completeness** — `doctor.sh` adds `unzip` (used by fetch-fixtures) + `python3` checks, stays read-only; `install.sh:28` sources `~/.cargo/env` before the cargo check (consistency with doctor). | `scripts/doctor-completeness-smoke.py::test_doctor_and_install_cover_one_command_deps` | `scripts/doctor.sh`, `scripts/install.sh` | `fix(plan): cover unzip/python deps in doctor and source cargo env in install` |
| 2.7 | **Register new smokes** in the gate (`run_smoke` lines, with prereq guards). | run `bash scripts/run-all-smokes.sh` shows new tally | `scripts/run-all-smokes.{sh,ps1}` | `test(ci): register Phase 2 cross-platform smokes in local gate` |

Out of scope (note only): `sift-vm-bootstrap.sh` VMware paths (one-time, gated by 2.3); dev-mode
`C--Users-newbi-...` memory path in `CLAUDE.md:293`/autonomous-loop (not on the investigate path).
**Verify Phase 2:** each `python3 scripts/<new>-smoke.py` RED→GREEN; `python3 scripts/render_report.py goldens/nist-hacking-case` degrades cleanly (chrome present, pandoc absent here); `bash scripts/verdict --dry-run`; `bash scripts/run-all-smokes.sh` = baseline + 5 new, 0 failed.

---

## Phase 3 — Protocol SIFT alignment (position + co-exist; reject bridge shim)

**Decision: hybrid (c) position + (b) co-exist; explicitly REJECT (a) gateway shim.** Wiring the
protocol-sift FastMCP gateway in as an MCP server re-introduces a broad shell-backed surface — the
documented forbidden drift (`docs/codex-compatibility.md:20,111-122`, guarded by
`divergence-smoke.py` + L0 `amendment-a2-guard` + `mcp-scanner`). It re-litigates the whole
security pitch for zero judging benefit, since `STARTUP.md:47-57` already establishes protocol-sift
as the common SIFT-VM base our product runs *alongside*. The real gap is **recognition**: the root
README never names Protocol SIFT. Doc-heavy, zero runtime surface added.

| # | Task | Test | Impl | Commit |
|---|---|---|---|---|
| 3.1 | **"Relationship to Protocol SIFT" in architecture.md** — same OVA/install/UX, deliberately divergent MCP surface (2 typed servers / 31 tools / no execute_shell vs 200+ shell-backed). Write "19 typed Rust DFIR tools / 31 total" (divergence-smoke forbids "11/12 Rust"). | `python3 scripts/divergence-smoke.py`, `path-existence-smoke.py` | `docs/architecture.md` | `docs(architecture): position narrow typed surface relative to Protocol SIFT` |
| 3.2 | **README coexistence block** — name Protocol SIFT, "runs on the same SIFT VM after `protocol-sift install`, neither requires nor conflicts with the gateway." | `divergence-smoke.py`, `path-existence-smoke.py` | `README.md` | `docs(readme): explain Protocol SIFT coexistence and divergence` |
| 3.3 | **Co-exist surface lock** — `divergence-smoke.py` asserts `.mcp.json` mcpServers == exactly `{findevil-mcp, findevil-agent-mcp}` and no entry's command/args contain `protocol-sift`/`sift-gateway`/`execute_shell`/`bash -c`/fetch/fs/browser launchers. | `divergence-smoke.py::test_mcp_json_surface_is_exactly_two_typed_servers` | `scripts/divergence-smoke.py` | `test(divergence): lock .mcp.json to two typed servers, no gateway/shell drift` |
| 3.4 | **codex-compatibility.md** — one bullet: protocol-sift gateway welcome as common base, NOT a product-default MCP. | `path-existence-smoke.py`, `divergence-smoke.py` | `docs/codex-compatibility.md` | `docs(codex-compat): name Protocol SIFT gateway as non-default, coexisting` |

---

## Finish-to-submission

End state target: green required CI on the commit to tag · `v-submit` re-cut at that commit ·
`release.yml`+`devpost-submit.yml` green · refreshed `find-evil-submission.zip` on the GH release ·
readiness packet `*_READY_FOR_EXPERT_REVIEW` with `blockers:[]`, `customer_releasable:false` ·
Devpost form updated by a human.

### Readiness-packet semantics (carried over, corrected to live gate strings)
The readiness gate is **deliberately conservative** and stops at human expert review — it never
self-certifies customer release. A healthy packet (`scripts/readiness-gate.ps1 -Mode Full` /
`scripts/readiness-gate.sh`) shows:
- state **`PACKET_READY_FOR_EXPERT_REVIEW`** (PacketOnly) / **`SUBMISSION_READY`** (POSIX sh); `blockers: []`.
- all 6 packet steps pass: `local-build`, `find-evil-auto`, `l1-docker`, `manifest-verify-local`, `packet-zip`, `submission-assets-validator`.
- `signer: "stub"` (or `sigstore` for the custody rehearsal); `customer_releasable: false` **by design** even with `-Signer sigstore`.
- expected non-blocking warning: `report QA has warnings: EXPERT_REVIEW_DRAFT`.
Any skipped build, missing L1 evidence, failed manifest verify, failed report QA, or a
`customer_releasable:true` from automation flips it to `READINESS_BLOCKED`.

### CODE/DOC vs HUMAN-ONLY split
| Task | Type | What |
|---|---|---|
| Phase 0, 1.x, 2.x, 3.x | CODE/DOC | all integration + the L1 fix |
| **F1** settle CHANGELOG | CODE/DOC | `CHANGELOG.md [Unreleased]` still claims pre-A5 "12+11=23"; correct to **19+12=31**, open `## [v-submit] - 2026-06-<dd>`. Commit `docs(changelog): settle Unreleased to current 31-tool surface and open v-submit`. Test: `divergence-smoke.py`. |
| **F2** supersede old plan + links | CODE/DOC | mark `docs/plans/2026-05-20-finish-to-v-submit-plan.md` superseded → this doc; refresh README badge/release links. Commit `docs(plans): supersede 2026-05-20 finish plan; refresh release links`. Test: `path-existence-smoke.py`. |
| **F3** local gate + draft PR | CODE | `bash scripts/run-all-smokes.sh` exit 0; `gh pr create --draft --fill --base master`. |
| **F4** verify CI on tag commit | CODE (read-only) | L1 + l3-nightly green on the exact commit to tag (`gh run list ... --json headSha` match; `release.yml:36-42` matches exactly); l3-weekly-goldens artifact non-empty. |
| **F5** demo video | **HUMAN-ONLY** | record 5-min per `docs/demo-script-a2.md` (committed `docs/find-evil-demo.mp4` is a 393 KB placeholder), host on YouTube/Vimeo, `gh variable set DEMO_VIDEO_URL ... 'https://youtu.be/<id>'`. |
| **F6** re-cut v-submit | **HUMAN-ONLY** | `git tag -f v-submit && git push -f origin v-submit` at green HEAD (re-triggers release + devpost-submit; tag force-push allowed, master protected). |
| **F7** Devpost upload | **HUMAN-ONLY** | download refreshed zip, validate, upload zip + public repo URL + hosted demo URL to the Devpost form. Repo already PUBLIC → old `gh repo edit --visibility` is a no-op. |

---

## Critical files
- `services/agent/findevil_agent/playbook.py` (new — canonical detection/sequences/criteria)
- `scripts/find_evil_auto.py` (de-dup, memory, contradiction record, payload fields)
- `services/agent/findevil_agent/config.py` · `apps/web/lib/sprite-state.ts`
- `scripts/render_report.py` · `.mcp.json.sift` · `scripts/find-evil-sift` · `scripts/find-evil-run` (new)
- `scripts/{divergence,verdict-policy,path-existence}-smoke.py` · `scripts/run-all-smokes.{sh,ps1}`
- `services/agent/pyproject.toml` + `tests/test_llm.py` (L1 fix)
- `docs/architecture.md` · `README.md` · `docs/codex-compatibility.md` · `CHANGELOG.md`
- `goldens/sans-starter/expected-findings.json` (new stub)
- `scripts/readiness-gate.{ps1,sh}` · `scripts/validate-submission-assets.py` · `scripts/package-devpost.sh`
- `.github/workflows/{l1-unit,l3-nightly,l3-weekly-goldens,release,devpost-submit}.yml`

## Security note (action outside the plan)
`/.env` (93 bytes, **gitignored** so it won't ship) contains a live API key. Recommend **rotating
it** since it's been on disk; keep using `.env` (it's correctly ignored). Not committed anywhere.

---

## Appendix A — Exact ordered command sequence to a submittable state

```bash
cd ~/verdict   # repo root

# --- 0. Branch for the finish work (no direct master push) ---
git switch -c finish-to-submission

# --- Phase 0: reproduce + fix L1 red (esperanto / test_llm) ---
uv run --directory services/agent pytest -xvs tests/test_llm.py          # see the failure
#   (edit pyproject.toml and/or llm.py / test_llm.py to pass offline)
uv run --directory services/agent pytest -xvs tests/test_llm.py          # now green
docker compose -f docker/l1-compose.yml up --build --exit-code-from l1   # L1 parity green
git add -A && git commit -m "fix(agent): make esperanto LLM factory test pass offline in L1 devbase"

# --- Phases 1-3: each task = RED -> implement -> GREEN -> one commit (messages in tables above) ---
#   after each: bash scripts/run-all-smokes.sh

# --- F1/F2: settle CHANGELOG + supersede old plan + README links ---
python3 scripts/divergence-smoke.py
python3 scripts/path-existence-smoke.py
git add -A && git commit -m "docs(changelog): settle Unreleased to current 31-tool surface and open v-submit"

# --- F3: full local gate (must exit 0), then draft PR ---
bash scripts/run-all-smokes.sh
gh pr create --draft --fill --base master

# === after human merge to master, on the merged HEAD ===
# --- F4: confirm required CI green on the commit to tag ---
gh run list --workflow=l1-unit.yml           --branch=master --status=success --json headSha,databaseId
gh run list --workflow=l3-nightly.yml        --branch=master --status=success --json headSha,databaseId  # headSha == tag commit
gh run list --workflow=l3-weekly-goldens.yml --status=success --limit=1 --json databaseId                 # non-empty
gh repo view TimothyVang/verdict-dfir --json visibility                                                  # PUBLIC (already)

# --- F5 HUMAN: record + host demo, set the URL ---
gh variable set DEMO_VIDEO_URL --repo TimothyVang/verdict-dfir --body 'https://youtu.be/<id>'

# --- F6 HUMAN: re-cut v-submit at the green HEAD ---
git tag -f v-submit && git push -f origin v-submit
gh run watch   # release.yml then devpost-submit.yml

# --- F7 HUMAN: fetch the refreshed bundle + upload to Devpost ---
gh release download v-submit --repo TimothyVang/verdict-dfir --pattern find-evil-submission.zip
python3 scripts/validate-submission-assets.py --zip find-evil-submission.zip
# upload find-evil-submission.zip + public repo URL + hosted demo URL to the Devpost form
```

## Appendix B — End-to-end verification checklist (submittable)
1. `bash scripts/run-all-smokes.sh` exits 0; `cargo test --workspace --locked`; `pnpm --filter @findevil/web test`.
2. L1 + l3-nightly green on the exact commit tagged `v-submit` (`gh run list ... headSha` match).
3. l3-weekly-goldens has a downloadable `l3-weekly-verdicts` artifact.
4. One-command path: `bash scripts/verdict --dry-run` clean; a real run produces a signed
   `run.manifest.json` + report, with the unified audit stream (Phase 1 manual checks).
5. `python3 scripts/divergence-smoke.py` green (tool counts + `.mcp.json` surface lock).
6. Readiness packet (if re-run): `*_READY_FOR_EXPERT_REVIEW`, `blockers:[]`, `customer_releasable:false`.
7. `gh release view v-submit` shows refreshed `find-evil-submission.zip` + `report.html`;
   DEMO_VIDEO_URL is a real hosted link; Devpost form submitted by a human.
8. End-to-end judge path: clone public repo → `scripts/install.sh` → `claude`/`scripts/find-evil`
   → `investigate <case>` → verify the manifest offline via the `manifest_verify` MCP tool.
