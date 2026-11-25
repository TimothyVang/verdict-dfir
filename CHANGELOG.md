# Changelog

All notable changes to the VERDICT DFIR / Find Evil! submission. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The public
submission release tag is `v-submit`; later entries in `[Unreleased]` document
work that has landed after that release and should be merged through the
canonical GitHub repo before any refreshed release.

> **Dev-first release flow:** push review branches to `TimothyVang/dev-verdict-github`
> / `origin` first. Promote only the reviewed commit or a controlled cherry-pick
> to `TimothyVang/verdict-dfir` / `release` after approval.

## [Unreleased]

## [v0.2.0-beta.1] - 2026-06-22

First public beta. Headline changes since `v0.1.5`:

### Added — opt-in agent mode + provider-agnostic backend

- **`scripts/verdict --agent`** — opt-in Stage B LLM agent investigation loop (Pool A /
  Pool B) behind the default-on fact-fidelity gate; the deterministic engine stays the
  default. Backend defaults to Claude (headless `claude_cli`, no API key); provider-
  agnostic via `--agent-provider {anthropic,openai,openrouter,local,dgx}` over any
  OpenAI-compatible endpoint (`local`/`dgx` on-prem, no egress ack). Live-verified on
  single-artifact evidence at report-QA parity with the deterministic engine; not yet
  scaled to disk.
- **Fact-fidelity (entailment) gate is now ON by default** — a CONFIRMED finding must
  declare re-extractable `asserted_values`; a non-LLM check rejects a misread laundered
  through a valid `tool_call_id`. Mechanical claim-discipline + gate-safe composed
  finding descriptions on the agent path.

### Changed — dev repo renamed

- Dev remote/repo `sans-hackathon` → **`dev-verdict-github`** (the `verdict-dfir` release
  repo is unchanged).

### Added — community response

- **`docs/community-response.md`** — launch feedback from r/computerforensics /
  r/digitalforensics / r/rust, preserved verbatim and answered point by point with what
  shipped (honest about what is done vs opt-in vs partial).

### Added — recall surface: Outlook Express, network recon, accuracy diagnostic

- **`oe_dbx_parse` (32nd Rust tool)** — reads an Outlook Express `.dbx` mail/news
  store (OE-signature-validated; extracts RFC822 `Subject`/`From`/`Newsgroups`
  headers), the artifact no other parser covered. Drives an Outlook Express
  newsgroup-affiliation Finding. The product surface is now **45 audit-chained
  product tools (32 Rust DFIR + 13 Python)**.
- **`accuracy_compare` (13th Python tool)** — read-only ground-truth accuracy
  diagnostic (TP/FP/FN, precision/recall/F1, hallucination rate) for a finished
  Case vs a curated golden. A DIAGNOSTIC, never a Finding.
- **T1046 network-reconnaissance Finding** from System-log Service Control Manager
  events, anchored on executed discovery tooling (SCM events alone are never recon).
- **RecentDocs, service-recon, logon, and IE-history Findings** on the disk path
  (registry triage + plaso `winevt`/`msiecf`).

### Changed

- **Evidence-agnostic by hard rule.** Detection keys on general DFIR signatures,
  never per-image names/misspellings; a new `scripts/evidence-agnostic-smoke.py`
  gate fails on image-specific literals in production code.
- **plaso Findings now survive the pipeline** — `plaso_parse` stderr is normalized
  for deterministic `verify_finding` replay, and per-file finding IDs keep the batch
  from being collapsed at judge time.

### Fixed

- verdict-smoke SIFT checks and the sample-run REPORT.md doc policy — stale
  references to a replaced SIFT-staging design and to a removed submission doc.

### Removed

- **`SUBMISSION_COMPLIANCE.md`** (the Devpost submission checklist) — release
  hygiene; the REPORT.md-presence qualifier it carried now lives in
  `docs/sample-run/README.md`.

### Changed — release polish: brand mark, dashboard focus, showcase media

- **Post-`v-submit` developer/release docs refresh.** Current active docs now
  distinguish the historical `v-submit` submission snapshot from the post-tag
  working tree, document the dev-first `origin` review flow before curated
  `release` promotion, and keep the shipped product-surface count at
  **45 audit-chained product tools** (**32 Rust DFIR + 13 Python
  crypto/ACH/memory/ACP/expert-feedback**).

- **New brand mark: check-as-V.** Replaced the three-object circle (gavel +
  scale-rings + check, unreadable at small sizes) with a single bold checkmark
  that doubles as the V of VERDICT. Applied everywhere the mark renders:
  `BrandMark` (dashboard), `favicon.svg`, both `logo.svg` lockups,
  `logo-mark.svg`, and a regenerated 1200×400 `assets/logo/logo.png`.
- **Dashboard: removed the n8n UI** (`AutomationPanel`, `N8nAccessCard`,
  `/api/n8n`, and `automation.json` from the report-route allowlist) so the
  product surface is unambiguous: stream + timeline left, signed report right.
  The post-verdict n8n scripts still run host-side, off the default path,
  writing the out-of-band `automation.json` sidecar — never in the audit chain.
- **Showcase media** (`docs/showcase/`): browser-framed screenshots
  (verdict hero, tool-cited findings, signed report) plus the investigation
  GIFs in the showcase gallery, all captured from real runs on the current UI.
  README hero + gallery rewired to these; stale `assets/screenshots/demo.gif`
  and `dashboard.png` removed.
- **Doc tool-count reconciled to the shipped 43-tool surface (31 Rust + 12
  Python).** The post-`v-submit` Rust tool surface includes long-tail
  allow-listed wrappers (`vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`,
  `cloud_audit`, Linux/network/NTFS helpers) plus browser-history coverage.
  Active docs should cite **43 product tools** and reserve older counts for
  dated historical snapshots only.

### Added — production readiness: easy install, docs, cross-platform distribution

- **Canonical `INSTALL.md`** — one linear path (clone → `scripts/setup` → verify
  with `scripts/doctor.sh` → first run), plus the container path. Added to the L0
  docs-consistency guard and the L1 link-existence smoke.
- **`CONTRIBUTING.md` + `docs/glossary.md`** — contributor build/test commands
  (mirroring CI), the non-negotiable invariants and Conventional-Commit rules,
  and plain-language definitions + FAQ.
- **`scripts/install.sh --bootstrap`** (opt-in; or `FINDEVIL_BOOTSTRAP=1`) installs
  a C toolchain (`build-essential` on Debian/Ubuntu) and missing cargo/uv/node via
  their official installers. The default path is unchanged and stays fail-closed;
  guarded by `scripts/install-bootstrap-smoke.py` and wired into
  `scripts/run-all-smokes.sh`.
- **Prebuilt-binary install path** — `scripts/install.sh` can fetch a
  checksum-verified `findevil-mcp` instead of compiling (opt-in
  `FINDEVIL_MCP_PREBUILT=1` + `FINDEVIL_MCP_VERSION=<tag>`), falling back to a
  source build for any unpublished triple.
- **Cross-platform binary releases** — `release-binaries.yml` builds
  `findevil-mcp` for linux x86_64/aarch64 + macOS x86_64/arm64 and attaches
  checksummed tarballs + `SHA256SUMS` to the GitHub Release. findevil-mcp is pure
  Rust (links only libc/libm/libgcc), so no C-library cross-compilation is needed.
- **Advisory CI workflows** (separate, non-required, validate-on-branch):
  `cross-platform.yml` (build/test on macOS + Windows) and `sbom.yml` (CycloneDX
  SBOMs).

### Changed — front-door clarity

- **README "Hi, I'm new"** reframed from "two equivalent ways" to one canonical
  path (`bash scripts/setup`) plus a power option (the in-Claude `setup` trigger,
  which additionally fetches the gated SANS SIFT OVA).
- **`QUICKSTART.md`** now opens with a genuine 3-step quickstart; the
  environment/run-mode tutorial is "going deeper" below it.

### Fixed

- **`agent-config/PLAYBOOK.md`** — corrected a slash-joined tool shorthand
  (`vol_pslist`/`vol_psscan`/…) that `path-existence-smoke` flagged as a broken
  path, restoring a green smoke run.

### Removed — Amendment A6: build swarm subsystem deleted

- **Removed the build swarm (Spec #1) entirely.** The overnight
  draft-PR generator was dev-time automation, invisible to judges, and
  not part of the submission. Deleted: `services/swarm/`,
  `scripts/swarm-start.sh`, `scripts/swarm-status.sh`,
  `docker/swarm-postgres.yml`, the `autonomous-loop.*` scripts
  (`autonomous-loop.py`/`.sh`/`-smoke.py`/`-stop.sh`), the
  `budget-guard.yml` workflow, and the swarm spec/plan/runbook docs
  (`docs/specs/2026-04-24-autonomous-build-swarm-design.md`,
  `docs/plans/2026-04-23-build-swarm-plan.md`,
  `docs/runbooks/swarm-operations.md`).
- **CI/smoke guards updated** so the tree stays green without the swarm:
  removed the L0 `amendment-option-b-guard` job and the swarm
  required-file checks from `l0-static.yml`; dropped the
  `amendment-option-b-guard` required status check from
  `scripts/setup-branch-protection.sh`; removed swarm rules from
  `scripts/divergence-smoke.py`, `scripts/path-existence-smoke.py`,
  `scripts/smoke-regex-tests.py`, `scripts/verify-sandbox.sh`, and the
  `autonomous-loop` smoke from the smoke runners.
- **Subsystems collapse from 4 to 3** (Sandbox → Product →
  Orchestration Glue). Historical specs/amendments retain their bodies
  with a "superseded by A6" banner; the Product, its MCP tool surface,
  and the investigation pipeline are untouched.

> **Note:** The entries below describe the Amendment A5 removal work
> (OpenTimestamps/Bitcoin tier) and document the tool-count evolution during
> that period. The current post-`v-submit` working-tree state is **43 tools: 31
> Rust DFIR + 12 Python crypto/ACH/memory/ACP/expert-feedback.** Older counts
> in dated sections are historical snapshots.

### Changed — one `verdict` command + self-score moved out of the pipeline

- **One command: `scripts/verdict <evidence>`.** The per-mode launchers
  are consolidated behind a single entry point that runs preflight →
  investigate → live dashboard → signed verdict + report. `find-evil-run`
  and `find-evil-live` are now deprecated shims that forward to `verdict`;
  `find-evil-auto` is the internal headless engine `verdict` calls; and
  `find-evil-sift` remains the SIFT-VM helper (`scripts/verdict --sift`).
  The retired "Tesla-mode" codename is dropped in favor of plain language
  ("the `verdict` command" / "headless").
- **`judge_selfscore` is removed from the product** and now lives only as
  the standalone maintainer tool `scripts/self-score.py`, run by hand
  before submission (writes `<case>/self-score.json`; does not touch the
  sealed audit chain). See the detailed entry below. The `judge_findings`
  Pool A/B merge agent (core ACH) is unaffected.

### Changed — self-score moved out of the pipeline

- **`judge_selfscore` is no longer emitted during an investigation.**
  The six-criterion self-assessment moved out of the live pipeline
  (`find-evil-auto` no longer appends `kind=judge_selfscore` records to
  the sealed audit chain) into a standalone maintainer tool,
  `scripts/self-score.py`, run by hand before submission. It reads a
  completed case's `audit.jsonl`, reconstructs the criterion signals,
  and writes `<case>/self-score.json` without touching the audit chain.
  `agent-config/JUDGING.md` is reframed accordingly as the
  pre-submission self-assessment rubric the grader uses; the product,
  dashboard, and demo video do not reference it. The `judge_findings`
  Pool A/B merge agent is unaffected.

### Removed — Amendment A5 (2026-04-30 → 2026-05-01)

- **OpenTimestamps + Bitcoin tier of the cryptographic chain-of-custody.**
  The two MCP tools `ots_stamp` and `ots_verify` (commits `773bf6d`
  through `2b59572`), the `services/agent/findevil_agent/crypto/ots.py`
  implementation module + its 9 unit tests, and the
  `opentimestamps-client==0.7.2` dependency are all deleted. The
  five-link chain (sha256 → audit prev_hash → rs_merkle → sigstore →
  OpenTimestamps → Bitcoin) collapses to three composed primitives
  (audit prev_hash → rs_merkle → sigstore), now expressed as a 4-row
  primitive table in `docs/cryptographic-attestation.md`. The
  Python MCP server tool count drops 13 → 11; the total MCP tool
  count drops 25 → 23 (12 Rust + 11 Python).
- **BREAKING CHANGE in the cryptographic-attestation contract.**
  Old runs that produced `*.ots` receipts remain valid (the
  receipts are self-contained Bitcoin proofs and don't depend on
  the agent for verification). New runs will not produce them.
  Any external consumer that polled for `run.manifest.ots`
  alongside `run.manifest.json` needs to drop that expectation.
- **FRE 902(14) self-authenticating-evidence claim is weaker but
  still defensible.** Pre-A5, prong (b) of FRE 902(14) ("trusted
  timestamp from independent third party") was satisfied by the
  Bitcoin proof-of-work chain (zero trusted parties). Post-A5,
  prong (b) is satisfied by Sigstore's Rekor transparency log
  (one trusted party — the Linux Foundation operates the log).
  Honest disclaimer is in `docs/cryptographic-attestation.md`'s
  "What FRE 902(14) requires" section.
- **Why this happened:** the OpenTimestamps anchor required network
  reach to a calendar server plus a multi-hour wait for the
  Bitcoin attestation to mature. SANS judges scoring offline can
  exercise neither. The orchestrator never called `ots_stamp` in
  the first place — it was listed as "(Optional) Step 10" in
  `find_evil_auto.py`'s docstring but no code path invoked it.
  Removal changes documentation more than runtime behavior.

### Added — automation surface

- **Tiny regression fixture matrix.** `scripts/verdict-policy-smoke.py` now
  prints and asserts a named laptop-runnable matrix for benign, EVTX-only,
  memory DKOM, memory injection, custody-only disk, extracted-disk persistence,
  network-only, Velociraptor zip, and mixed full-case scenarios; `docs/DATASET.md`
  documents the smoke inputs without committing large evidence.
- **Deterministic scheduled-task EVTX triage.** `find-evil-auto` now turns
  Security EID 4698 scheduled-task creation rows with suspicious action content
  into cited HYPOTHESIS Findings mapped to T1053.005, preserving the rule that
  task creation alone does not prove execution or make a case suspicious.
- **Report QA false-positive overclaim locks.** Verdict-policy smoke now covers
  YARA-only, Hayabusa-only, malfind-only, memory-only, EVTX-only, and
  network-only overclaim wording, plus customer-ready language before release
  gates; these cases must stay blocked by report QA.
- **Expert miss feedback items in signoff metadata.** Captured
  `expert_miss_capture` entries now become structured signoff `feedback_items`
  with conversion targets for connector, playbook, rule, QA, escalation, or
  report-copy follow-up, and verdict metadata exposes the expert miss summary.
- **Velociraptor zip dispatch in `find-evil-auto`.** Single `.zip`
  evidence now routes to a Velociraptor collection lane instead of
  `unknown`; mixed case directories extract supported contained EVTX,
  Prefetch, Registry, MFT, USN, PCAP, Zeek, and Sysmon artifacts into
  the case work dir read-only, then dispatch them through the existing
  typed parsers. Unsafe zip-slip members, oversized members, and
  unsupported collection rows are recorded as limitations rather than
  silently treated as clean coverage.
- **Bounded disk artifact extraction.** `disk_extract_artifacts` now
  accepts `max_artifact_bytes` (default 512 MiB), skips oversized
  artifacts before copying them out of the mounted read-only view, and
  reports `artifacts_skipped_oversize` so broad YARA-target extraction
  cannot silently balloon a case workspace.
- **`scripts/autonomous-loop.py --min-hours` continuous-run floor.** The
  queue driver can now be launched as
  `python scripts/autonomous-loop.py --min-hours 8 --max-hours 10` so an
  overnight coding pass does not exit early just because the queue is briefly
  empty. If no unblocked item exists before the minimum wall-clock floor, the
  harness waits in `--empty-sleep-seconds` intervals for newly added queue
  work; rate limits and failed task exits still halt cleanly. The queue-parser
  self-test now covers the min-hours wait and sleep-cap helpers.
- **Autonomous-loop CLI smoke.** `python scripts/autonomous-loop-smoke.py` now
  validates `--min-hours 8 --max-hours 8 --dry-run` against a synthetic queue
  and a tiny empty-queue wait/stop path without requiring `claude` on PATH or
  consuming Claude usage; `scripts/run-all-smokes.sh` runs it by default.
- **Case completeness + unified timeline output.** `find-evil-auto`
  now writes a `case_completeness` matrix and `timeline_summary` into
  `verdict.json`, persists normalized timeline events to
  `timeline.json`, and renders both into `REPORT.md` / PDF. This gives
  analysts a quick view of what evidence classes were available,
  which were touched, and how missing artifacts affect confidence.
- **ATT&CK coverage, timeline CSV, and next analyst actions.**
  `find-evil-auto` now adds an `attack_coverage` matrix and
  `next_actions` queue to `verdict.json`, writes analyst-friendly
  `timeline.csv` beside `timeline.json`, and renders the coverage and
  next-action tables into `REPORT.md` / PDF.
- **`scripts/find-evil-auto`** headless single-command orchestrator
  (commit `4b38d27`). Detects evidence type, spawns both MCP servers
  inside the SIFT VM via SSH stdio, runs the per-type playbook,
  synthesizes Pool A/B Findings, runs the full ACH stack
  (detect_contradictions → judge_findings → correlate_findings →
  judge_selfscore → manifest_finalize), writes
  `verdict.json` + signed manifest + audit chain + PDF report.
  No interactive Claude Code session required.
- **`scripts/fleet_investigate.py` + `scripts/fleet_correlate.py` +
  `scripts/render_fleet_report.py`** — three-script fleet pipeline
  (commits `0de2e53` + `2403188` + `0b87b83`). Walks every `.img` in
  the evidence tree, invokes find-evil-auto per host, persists
  results after each so crashes don't lose progress, then detects
  cross-host patterns (uncommon process names on ≥2 hosts, 60s
  multi-host temporal clusters, MITRE technique density,
  Merkle-root uniqueness) and renders FLEET_REPORT.{md,html,pdf}
  with four matplotlib figures.
- **12th Rust MCP tool: `vol_psscan`** (commit `0de2e53`). Mirror of
  `vol_pslist` but invokes Volatility 3's `windows.psscan` instead.
  Critical for DKOM cross-validation against the active-list
  walker — `pslist=0` + `psscan>0` *can* indicate the MITRE T1014
  Rootkit signature, but the agent now disambiguates it from an
  acquisition smear before asserting T1014 (report §4.3 /
  `find_evil_auto.py` smear detection). Spec #2 §6 enumerated 11; this brings the
  shipped count to 12.
- **13th Rust MCP tool: `vol_psxview`**. Wraps Volatility 3's
  `windows.psxview` for cross-view process enumeration after a
  `vol_pslist` / `vol_psscan` divergence. This closes the SRL-2018
  DC report's DKOM corroboration gap and brings the shipped MCP
  surface to 24 tools (13 Rust + 11 Python).
- **`scripts/install.sh`** (commit `291828f`). Pre-flight + build
  script: detects three Claude credential modes per Amendment A1
  §3.2 (`CLAUDE_CODE_OAUTH_TOKEN` / interactive `~/.claude/` /
  `ANTHROPIC_API_KEY`), verifies cargo + uv toolchain, builds
  findevil-mcp release binary, syncs services/agent_mcp uv venv,
  sanity-checks .mcp.json registers both servers.
- **`scripts/agent-mcp-smoke.py --real-evidence` mode** (commit
  `79535e2`). Replays a real find-evil-auto case dir through the
  agent_mcp surface (audit_verify → manifest_verify →
  detect_contradictions → judge_findings → correlate_findings).
  Regression coverage proving the agent_mcp tools still parse
  production output shape after schema changes.

### Added — cryptographic chain-of-custody

- **`kind=judge_selfscore` audit records** wired end-to-end (commits
  `94c08dd` + `7729cfc` + `6f7f55a`). Per `agent-config/JUDGING.md`,
  the supervisor emits 6 audit records (one per SANS rubric
  criterion) BEFORE `manifest_finalize`. The records land in the
  audit chain → Merkle tree → sigstore signature, so the agent's
  self-score is itself part of the cryptographic attestation —
  the agent doesn't get to revise after seeing the score it got.
  Per-case `REPORT.pdf` and fleet `FLEET_REPORT.pdf` both surface
  the selfscore records with explanatory text.

### Added — documentation

- **CLAUDE.md "Spec/code divergences" SSE-not-WebSocket entry +
  `scripts/divergence-smoke.py` §8 guard** (PR #7 sha `281d26f`).
  A3 plan Task 4.2 said "WebSocket upgrade" for the dashboard's
  `audit.jsonl` push; PR #7 shipped Server-Sent Events instead
  because the data flow is strictly server→client (WebSocket's
  bidirectional channel is unused complexity), App Router routes
  don't natively support the WS upgrade handshake (would need a
  custom `server.ts` wrapper), and SSE has been universally
  supported since the IE 9 era. The new divergence-smoke §8 entry
  scans every active `package.json` for a re-introduced `"ws"`
  npm dep — the canary signal a future executor blindly followed
  the stale plan text. Live SSE handler at
  `apps/web/app/api/audit/route.ts`; iterator at
  `apps/web/lib/audit-tail.ts`.
- **Repo-root `README.md`** (commit `6813566`) — GitHub front page.
- **`services/agent/README.md` rewrite for A2** (commit `532b1db`).
  The package's README still described the pre-A2 architecture
  ("Hosts the LangGraph ACH graph, FastAPI SSE bus ... and CLI"),
  status table showed ⏳ Week N for components that have shipped
  under A2 (the entire crypto/ stack, mcp_client, verifier, pools,
  judge, contradiction, correlator), and "For swarm workers"
  recommended writing `findevil_agent/specialists/<name>.py` —
  which the L0 amendment-a2-guard explicitly forbids. Rewrote
  the header as "library not service under A2", bumped 15
  components ⏳→✅, added 5 strikethrough rows for the dropped
  pre-A2 modules with explicit "dropped per A2" annotations and
  L0-guard pointers, replaced the swarm-worker specialist bullet
  with explicit DO-NOT-generate guidance.
- **`docs/cryptographic-attestation.md`** (commit `08a9ff5`) — the
  five-link chain narrative (sha256 → audit prev_hash → rs_merkle →
  sigstore → OpenTimestamps Bitcoin) collected in one canonical
  doc, with FRE 902(14) prong-by-prong analysis and the negative
  test (tamper detection) live demonstration.
- **`docs/verdict-semantics.md`** (commit `16616a9`) — analyst
  triage flow for SUSPICIOUS / INDETERMINATE / NO_EVIL. Per-verdict
  triggers (verbatim from `compute_verdict`), per-verdict "what to
  do" guidance, "what the verdict does NOT mean" honesty block,
  triage flow diagram, and "when to override" pointer to the
  25-line policy in `find_evil_auto.py`.
- **`docs/demo-script-a2.md`** (commit `edf56f4`) — 5-minute
  Devpost video script with per-beat seconds, on-screen content,
  spoken narration, rubric-criterion mapping, recording mechanics.
- **`docs/false-positives.md` "Fleet cross-host correlation" entry**
  (commit `88554e1`) — documents the enterprise-AV FP trap and the
  COMMON_WIN_PROCS filter mitigation.
- **`docs/reports/2026-04-26-srl2018-dc-investigation.md` §9.1 fleet
  rollup** (commits `0c1e00b` + `f7df6c4`) — the showcase analyst
  report now references the 22-host fleet result.
- **`agent-config/JUDGING.md`** (commit `7808afd`) and rewritten
  `AGENTS.md` (commit `541e3b2`) + `TOOLS.md` (commit `5469935`).
  All 7 agent-config files now consistent with the shipped 12-tool
  MCP surface and the judge_selfscore wiring.

### Removed — A2 hard-blocker resolution

- **Dockerfile `find-evil` wrapper + `scripts/build-deb.sh` + release.yml `build-deb` job** (PR #4, 2026-04-27). Resolves the hard blocker recorded under "Hard blockers discovered" below ("Dockerfile A2 cli.py mismatch", commit `47f67b0`). Per `docs/runbooks/dockerfile-a2-decision.md` "Option B": A2's central claim is "Claude Code IS the orchestrator," so the in-container `find-evil` wrapper had no runtime to invoke and the `.deb` had no orchestrator binary to package. Cut from three places: (1) Dockerfile RUN block + CMD changed to `bash`, (2) `scripts/build-deb.sh` deleted entirely, (3) release.yml `build-deb` job removed + `publish` job's `needs:` array trimmed. The `divergence-smoke.py` §3 allow-list dropped its two exemptions (`Dockerfile`, `scripts/build-deb.sh`) — any future re-introduction of `python -m findevil_agent.cli` or `find-evil run/verify/serve` in active code will now fail the L1 smoke loudly. The Docker image still ships to `ghcr.io` (build-state reproduction); the canonical user contract remains `git clone` + `scripts/install.sh` + `claude .` per A2 §2.4. The runbook is preserved with a `DECISION TAKEN` header for future re-evaluation.

### Changed — accuracy

- **`fleet_correlate` known-FP filter expanded 21 → 94 entries**
  (commit `ba038c6`) covering the McAfee/Trellix endpoint stack,
  Windows infrastructure, VMware Tools, Microsoft Defender. Fleet
  correlation cross-host names dropped from 119 to 73; the "≥4
  hosts" finding list dropped from 68 to 30. Sysinternals tools
  (Autorunsc, PsExec) deliberately not filtered since cross-host
  runs of those ARE forensic findings worth analyst attention.
- **`fleet_correlate` MITRE density now counts distinct hosts**
  (commit `bf11c4d`), not findings. The earlier code reported
  T1014 = 24 on a 21-host fleet; the actual answer is T1014 = 11
  (each host can emit T1014 from both Pool A and Pool B; the
  per-host metric is what the analyst wants).

### Fixed

- **MCP tool timeout 120s → 600s with clean queue.Empty handling**
  (commit `d0f7fd5`). 120s was too tight for vol3 plugins on 5GB+
  memory images — vol_pslist alone takes 60-90s and the next call
  inherited the same budget. `vol_malfind` gets a 30-minute budget
  at the call site since it routinely exceeds 600s. Re-investigated
  base-admin (5GB DC RAM) successfully after this fix.
- **`COMMON_WIN_PROCS` drift between orchestrator and correlator**
  (commit `8638fa4`). The orchestrator's per-host filter and the
  fleet correlator's cross-host filter had separate hard-coded
  copies. Replaced the orchestrator's class attribute with a
  runtime import of `fleet_correlate.COMMON_WIN_PROCS` via
  `importlib.util` — single source of truth, no manual sync.
- **PDF render survives viewer-locked target** (commit `3170202`).
  Both render_report.py and render_fleet_report.py now Chrome-print
  to a sibling `<name>.new.pdf` and atomic-rename to the target.
  Previously, if the operator had REPORT.pdf open in Acrobat
  during a re-render, Chrome failed with "Access is denied" and the
  PDF render silently dropped. New flow leaves the .new.pdf in
  place and prints a clear warning naming both paths if the rename
  fails.
- **Demo-script Beat 6 on-screen command** (commit `102c59e`).
  The fleet-pipeline beat showed `bash scripts/find-evil-auto && …`
  but `find-evil-auto` is the single-host orchestrator and errors
  out without an evidence-path arg. Replaced with the actual fleet
  pipeline command (`fleet_investigate.py && fleet_correlate.py
  && render_fleet_report.py`) so a future re-recording doesn't
  fail mid-take. demo-script-smoke (4ddb04a) parses the beat-map
  structure not the prose, so this passed CI before — caught by
  fresh-eyes read of Beat 6.
- **Swarm invocation strings in CLAUDE.md + services/swarm/README.md**
  (commit `ec85639`). Both said `uv run python -m services.swarm.main
  --week 4 --dry-run-gate` (and `--resume` variant), but the shipped
  package is `findevil_swarm` (matches `findevil_agent` /
  `findevil_agent_mcp` / `findevil-mcp`), the CLI grew a `run`
  subcommand so bare `--week 4` no longer parses, and uv needs
  `--directory services/swarm` (or `cd` first) to find the right
  pyproject. Fixed both files to match the canonical
  `scripts/swarm-start.sh:105` invocation
  (`cd services/swarm && exec uv run python -m findevil_swarm.main
  run "$@"`); verified with `--help`. Added a 6th entry to CLAUDE.md
  "Spec/code divergences" so the next session doesn't re-litigate
  the build-swarm-plan's `services.swarm.*` import paths (~50
  references in the historical TDD plan, code shipped under
  `findevil_swarm.*` for naming consistency).
- **Cryptographic-attestation third-party verification recipe**
  (commit `43cdbdd`). `docs/cryptographic-attestation.md` "How a
  third party verifies offline" said `uv run --directory
  services/agent_mcp python -m findevil_agent_mcp.server &` followed
  by "then over MCP stdio, call manifest_verify" — backgrounding a
  stdio server with `&` disconnects it from the launching shell, so
  there's nothing to call from. Replaced with a working two-path
  recipe: (1) direct Python library call —
  `from findevil_agent.crypto.manifest import verify_manifest` —
  smoke-tested against a real case dir (overall=True, all four
  sub-checks True); (2) `scripts/agent-mcp-smoke.py --real-evidence`
  as the fuller alternative that exercises audit_verify +
  detect_contradictions + judge_findings + correlate_findings through
  the actual MCP wire. Same prose-vs-code drift shape as the Beat 6
  + swarm-invocation fixes — this one was a recipe that looked
  plausible but couldn't be executed.
- **`find_evil_auto.py` argparse prog name** (commit `6f22382`).
  `bash scripts/find-evil-auto --help` printed
  `usage: find_evil_auto.py ...` — but every doc invokes the script
  as `find-evil-auto` (the bash wrapper). One-line fix passing
  `prog="find-evil-auto"` to ArgumentParser. Usage line now matches.
  Lower impact than the previous four prose-vs-code fixes (cosmetic
  rather than executable bug) but same drift shape — doc name vs
  self-reported name. The other four argparse scripts in scripts/
  (fleet_investigate, fleet_correlate, render_report,
  render_fleet_report) are invoked directly as
  `python scripts/<name>.py` so their default prog matches; left
  alone.
- **CLAUDE.md documents the autonomous-loop harness** (commit
  `eaed5c4`). New subsection in the "Commands" section names the
  driver (`python scripts/autonomous-loop.py`), the stop
  conditions, the subscription auth path (Amendment A1 — no API
  key), and a one-line decision rule for picking between the
  swarm and the autonomous-loop ("PRs (swarm) vs commits-on-
  current-branch (autonomous-loop)"). Also added `^memory/` to
  path-existence-smoke ALLOW_PATTERNS since CLAUDE.md cites
  `memory/project_autonomous_queue.md` which lives in user-level
  `~/.claude/projects/<project>/memory/`, not at repo root —
  third time path-existence-smoke caught a real ref-vs-reality
  mismatch on first run after I edited a doc (5e01954 +
  385c867 + this).
- **smoke-regex-tests now covers autonomous-loop + rate-limit fix**
  (commit `7d31e07`). Extended `smoke-regex-tests.py` with 12 new
  cases for the new harness (5 queue-parser + 7 rate-limit
  detector). The new tests immediately caught a real bug in the
  harness: `RATE_LIMIT_PATTERNS` had `"usage limit reached"` but
  Anthropic also emits `"You have reached your usage limit"`
  (different word order) — if rate-limit fired with the second
  phrasing the harness would have kept burning subprocess spawns
  instead of halting. Added the second pattern. The
  protect-the-protectors arc paying off in real time: a regex
  bug in production-bound code caught less than one iteration
  after the code shipped, not a hypothetical save. 42/42 regex
  tests pass; 14/14 full smokes green.
- **`scripts/autonomous-loop.py` replaces `/loop` with a real harness**
  (commit `150a8a0`). Per two user redirects in this session
  ("Why can't u just use the Claude code sdk to run this continuously"
  + "Why are you using loop research a better autonomous method
  like harnessing"), this is the harness the /loop session should
  have used from the start. Reads the queue, picks the highest-
  priority unblocked item, spawns `claude -p --permission-mode
  acceptEdits` headless per item, loops until queue exhausted /
  --max-hours cap / 429 detected. Key behavioral difference from
  /loop: exits cleanly when the queue is exhausted (verified via
  dry-run on current state — "queue exhausted (only Hard blockers
  remain). Stopping cleanly."). /loop kept cycling forever, padding
  ~30 iterations of this session with diminishing-returns audit
  polish. Auth inherits from the `claude` CLI subprocess (Amendment
  A1 subscription path; no API key). No new pip dep. ~219 lines.
  Saved feedback `feedback_use_harness_not_loop.md` carries the
  preference forward across sessions.
- **DKOM finding is INFERRED, not CONFIRMED — SOUL.md alignment**
  (commit `6dcc1fc`). Caught by extending last iteration's
  narrative-consistency audit to demo-script-a2.md Beat 3:
  voice-over says "agent labels finding INFERRED because two
  tool outputs corroborate", but find_evil_auto.py line 433
  was labeling the textbook DKOM case (pslist=0/psscan>0) as
  `confidence="CONFIRMED"`. SOUL.md "Epistemic hierarchy" §2
  says ≥2 confirmed facts → INFERRED; the rootkit-attribution
  is INFERRED from confirmed observations. In practice this
  branch never fires (real fleet hosts all hit line-450's
  INFERRED branch since they always have pslist > 0; verified
  by sampling 25 case dirs — 0 CONFIRMED / 15 INFERRED / 33
  HYPOTHESIS). The CONFIRMED label was a latent SOUL.md
  violation that a fully-rootkitted future host would have
  surfaced. 1-line change CONFIRMED → INFERRED + comment
  block explaining the SOUL.md mapping. Existing case dirs
  not retroactively re-tiered (change is prospective).
- **README example terminal output internal-consistency fix**
  (commit `47b41fd`). The "What it is" block mixed three
  illustrative values (pslist=0/psscan=124/verdict=SUSPICIOUS)
  with one real merkle (`21a2859b...` from base-admin) — but
  base-admin's actual values are pslist=232/psscan=244/verdict=
  INDETERMINATE per the queue's re-investigation record. Three
  illustrative numbers + one real merkle glued together as if
  one run. A reader trying to verify by running the agent
  would see different values; a reader cross-referencing
  tmp/auto-runs/ for the cited merkle would find different
  pslist/psscan. Reframed as obviously-stylized: placeholder
  names (`<host>`, `<uuid4>`, `<hex digest>`) + dynamic-count
  symbols (N1, N2, K, F, F') + explicit "Stylized" footnote
  pointing at the actual artifact set in docs/reports/...
  Caught by a new audit shape — "narrative consistency" (does
  the prose tell a story whose pieces fit together when cross-
  referenced?). Harder to lock in CI than the existing audit
  shapes; stays one-shot for now.
- **`run-all-smokes.sh` adds `cargo clippy` + `cargo test`**
  (commit `e021c46`). Closes the last 2 gaps with the autonomous-
  loop directive's verification spec ("cargo test + cargo clippy
  -D warnings + ruff check + ruff format check"). Of those 4,
  ruff was original; cargo fmt added in `7549cba`; cargo clippy
  + cargo test added here. Both invocations match L0 GHA exactly
  (`cargo clippy --workspace --all-targets --locked -- -D warnings`
  + `cargo test --workspace --locked`). Cargo test gated on
  `SKIP_SLOW_RUST` env for fast-iteration mode. Local
  verification: 14/14 pass in ~10s incremental;
  `SKIP_SLOW_RUST=1` drops to 13/13. The local-runner-mirrors-
  only-one-CI-workflow pattern has now been closed across all
  four gates the user's directive expects (ruff check, ruff
  format, cargo clippy, cargo test) — third instance of the
  pattern, fix is now structural.
- **`run-all-smokes.sh` also gates `cargo fmt --check`** (commit
  `7549cba`). L0 GHA runs `cargo fmt --all --check` but
  run-all-smokes only mirrored ruff. Same shape as the earlier
  ruff lint-gate addition (`f0dbfb1`) — local-runner-mirrors-
  only-one-CI-workflow misses violations. Added as entry 12,
  gated on `command -v cargo && [ -f Cargo.toml ]` for clean
  SKIP. Negative-tested by tampering with services/mcp/src/lib.rs
  (cargo fmt --check exit 1 caught it) and restoring (exit 0
  clean). QUICKSTART smoke-count 11 → 12 entries. Second
  instance of the local-runner-mirrors-only-one-CI-workflow
  pattern; if a third surfaces (shellcheck / hadolint?), the
  right move is to audit the full L0 job set against
  run-all-smokes end-to-end rather than fix one at a time.
- **`scripts/smoke-regex-tests.py` protects the audit-smoke regexes**
  (commit `0de00b2`). The 3 audit smokes (divergence + launcher +
  path-existence) catch drift in the rest of the codebase, but the
  smokes themselves had no automated regression coverage — a future
  contributor breaking a regex (typo / over-broadening / over-
  narrowing) would silently let bugs through. New smoke imports
  each smoke module and runs 30 synthetic test cases (11 + 9 + 10)
  against the key regexes / classifiers. Fixtures derived from the
  manual negative tests run when each smoke first shipped (0155503
  + c5bfa1b + e90b4f9). Tamper-tested by deliberately breaking
  one divergence regex; tester returned the expected failure with
  a precise diagnostic. Wired into docker/l1-compose.yml + run-
  all-smokes.sh as the 9th smoke (then the 2 lint gates → 11
  entries total). The audit-pattern arc has now run four times,
  the fourth being a meta-application protecting the protectors.
- **`launcher-smoke` shebang-based extension-less launcher discovery**
  (commit `3dc51b1`). Same anti-drift refactor as `5c1f324`
  (path-existence) applied to launcher-smoke. Replaced the explicit
  3-entry `EXTENSIONLESS_LAUNCHERS = ["find-evil", "find-evil-auto",
  "find-evil-sift"]` with a glob over `scripts/*` filtered by no-dot
  basename + shell-shebang detection (reads first 80 bytes,
  matches `#!/usr/bin/env bash` etc.). Same 22 launchers / 66
  assertions found. Negative-tested by dropping a synthetic
  extension-less launcher with a bash shebang + bad invocation;
  new discovery picked it up (count went 22→23) and the smoke
  FAILed correctly. Two of the three audit smokes (path-existence
  + launcher) are now drop-in-resistant.
- **`path-existence-smoke` glob-based doc discovery** (commit
  `5c1f324`). Replaced the explicit 22-entry `SCAN_LIST` tuple
  with `EXPLICIT_DOCS` (3 root-level entries) + 4 `GLOB_PATTERNS`
  (`docs/*.md`, `docs/runbooks/*.md`, `agent-config/*.md`,
  `services/*/README.md`) + 1 `GLOB_EXCLUDES` (devpost README
  template with envsubst placeholders). Discovery now auto-gates
  any new doc dropped under those directories — the previous
  explicit list silently un-gated new files until a contributor
  remembered to add them (the github-remote-bootstrap runbook in
  41594d0 needed a manual update for that exact reason). Same 23
  docs / 193 paths resolve. Negative-tested with a synthetic
  doc/runbook bad-path; smoke FAILs correctly. Structural fix —
  no new bugs caught — but the gate is now resistant to
  drop-in-and-forget drift.
- **`docs/runbooks/github-remote-bootstrap.md`** (commit `41594d0`).
  Second decision-helper runbook (first was the Dockerfile A2 one
  in `ea14aeb`). The "GitHub remote + push" hard blocker has been
  open since 2026-04-25 and requires user input on 3 decisions
  (owner / name / visibility) plus one-time bootstrap commands.
  Runbook frames the 3 decisions with recommendations + concrete
  `gh` command sequences + post-push checklist + pre-v-submit
  steps + "what can go wrong" debugging guide. Added to
  path-existence-smoke SCAN_LIST (193 paths / 23 docs all
  resolve). Deliberately NOT added to L0 docs-consistency:
  decision-helper runbooks are conditional artifacts — once the
  hard blocker resolves, the user should be free to delete the
  runbook. Stays inside autonomous-loop scope (preparing the
  artifact, not making the decision).
- **release.yml release-notes pointed at non-existent file**
  (commit `2bf9bc6`). `gh release create --notes "...See
  docs/architecture.md + README-submission.md for details."`
  references README-submission.md, but that file is **generated**
  by `scripts/package-devpost.sh` into the Devpost zip artifact,
  NOT into the GH release (the release artifact set is .deb +
  report.html). A user clicking through release notes would have
  hit a 404 trying to find README-submission.md in the GH web
  UI. Replaced with `README.md` (which does exist in the repo
  root). Caught by extending the path-existence audit shape to
  workflow YAML (the existing path-existence-smoke covers
  operator-facing markdown only). Whether to extend the smoke
  to YAML is a separate decision — false-positive surface in
  workflow YAML is wider (env vars, action refs, secret names
  all look path-shaped).
- **`scripts/path-existence-smoke.py` graduates the path-audit
  shape** (commit `e90b4f9`). Third CI smoke graduated from the
  audit-pattern arc (after launcher-smoke + divergence-smoke).
  Walks 22 operator-facing docs, extracts every backtick-quoted
  path-shaped token, asserts each resolves to a real file/dir
  via 3 resolution attempts (doc-relative, repo-relative,
  package-relative for service READMEs). 192 paths checked, 0
  missing on first run; negative-tested with synthetic doc
  containing one good + one allow-listed + one bad path — all
  three classified correctly. ALLOW_PATTERNS captures the 43-of-
  47 false-positive shapes from the two manual audit iterations:
  URLs, MCP wire identifiers, runtime user dirs, install paths,
  deferred-per-A2 surfaces, dropped-per-A2 modules deliberately
  quoted to document removal, future-tense fixture files, OTRF
  external dataset paths, documented-removed-pre-A1 modules,
  Windows event-log channels, GitHub Actions references, state
  files, conventional shorthand. Wired into docker/l1-compose.yml
  + scripts/run-all-smokes.sh as the 8th L1 smoke; QUICKSTART
  row updated 9 → 10 entries. The discover → systematize → lock
  arc has now run three times for three distinct drift shapes.
- **4 broken paths from extended path-existence audit**
  (commit `385c867`). Second pass of the path-existence audit
  shape, this time across agent-config/*.md + services/*/README.md
  + docs/runbooks/ + docs/DATASET.md (the previous pass covered
  CLAUDE.md + README + QUICKSTART + 4 docs/). 108 paths checked;
  47 missing of which 43 were false positives (package-relative
  paths, MCP wire identifiers like `tools/list`, deferred-per-A2
  paths, runtime user dirs). 4 real bugs:
  services/swarm/README.md:21 `services/swarm/main.py` →
  `services/swarm/findevil_swarm/main.py` (same drift the
  CLAUDE.md fix in 5e01954 caught — the README was missed);
  services/swarm/README.md:36 same shape on `session_guard.py`;
  docs/DATASET.md:35 named the NIST goldens file
  `goldens/nist-hacking-case.findings.json` but the actual path
  is `goldens/nist-hacking-case/expected-findings.json` (subdir
  + different name) — a contributor reading the "14 canonical
  findings" claim would have hit a 404 trying to verify the
  recall target; agent-config/TOOLS.md:39 `.LOG1/2` reformatted
  to `.LOG1` / `.LOG2` (registry transaction-log abbreviation).
  Across two iterations the path-existence audit has now found
  3 + 4 = 7 real bugs — graduating it to a CI smoke is now
  warranted (deferred to a future iteration since this commit
  is already self-contained).
- **CLAUDE.md "Vendored reference clones" section drift**
  (commit `861d1ed`). The section claimed 4 directories
  (`openclaw/`, `hermes-agent/`, `Linear-Coding-Agent-Harness/`,
  `.playwright-mcp/`) "live in-repo for reference reading only" —
  but `ls` shows none of them exist locally and none have ever
  been committed to git. Plus the section described `openclaw run
  --case X.e01` as a Product entry point (A2 dropped this) and
  Hermes as part of Spec #2 §4 Layer 4 (deferred to bonus under
  A2). Plus the cited `.gitignore` line range (72-76) was off by
  4 (actual: 76-80). Reframed as "directory names *reserved* for
  contributor-local research clones" — the .gitignore safety net
  is the load-bearing part. Renamed section heading "Vendored"
  → "External" since vendored implies in-tree checked-in code
  (which these aren't). The inverse of the deletion-rot audit
  pattern: docs claimed something existed when it didn't.
- **L0 docs-consistency catches deletion of all load-bearing docs**
  (commit `bd06995`). The L0 GHA job verified existence of 4
  per-subsystem specs + 4 plans + 3 root docs, but CLAUDE.md
  "Document hierarchy" treats more files as load-bearing
  (master design + 2 active amendments + 4 root ops docs +
  6 canonical analyst docs + 7 agent-config runtime-identity
  files = 20 newly-gated paths). Silent deletion of any would
  only surface at read time; a SANS judge opening the repo
  could hit a 404 cross-reference. Extended the file-existence
  check to cover all 20. Verified yaml parses + every path
  exists in the current tree. Wall-clock unchanged
  (test -f is microseconds). Catches deletion-rot, complementing
  the divergence-smoke + launcher-smoke (which catch content
  drift).
- **`docs/runbooks/dockerfile-a2-decision.md`** (commit `ea14aeb`).
  Decision-helper for the Dockerfile A2 hard blocker that's been
  open since commit `47f67b0`. Lays out both architectural paths
  (rewrite to find-evil-auto vs cut wrapper + .deb) side-by-side
  with concrete diff sketches, pros/cons, and next-step
  estimates. Recommendation framing names option B as more
  A2-idiomatic but flags the decision as user's call. Added to
  `divergence-smoke.py`'s ALLOWED_FILES since the runbook
  deliberately quotes both halves of the divergence (same
  situation as CHANGELOG/CLAUDE.md). Stays inside autonomous
  scope — preparing the decision artifact, not making the
  decision.
- **Smokes weren't ruff-format-clean + run-all-smokes lacked
  lint gate** (commit `f0dbfb1`). Caught while running the
  user's green-bar verification command verbatim
  (`cargo test + cargo clippy -D warnings + ruff check +
  ruff format check`). The two recent smokes (launcher-smoke.py,
  divergence-smoke.py) weren't `ruff format --check`-clean - L0
  GHA would have failed on next push. Reformatted (whitespace
  + line-wrap only, smokes pass identically). Added
  `ruff check` + `ruff format --check` as entries 8 + 9 in
  `scripts/run-all-smokes.sh` so the lint gate runs alongside
  the test smokes locally - matching what L0 enforces in CI.
  ~50ms wall-clock added; both gated on `command -v ruff` so
  a stripped install SKIPs cleanly. The contributor running
  `bash scripts/run-all-smokes.sh` before commit now hits the
  same gates the autonomous-loop directive specifies, rather
  than a subset.
- **3 broken file-path references in operator docs**
  (commit `5e01954`). New audit shape: extract backtick-quoted
  path-shaped strings from ops-facing docs, verify each exists
  on disk. 61 paths checked; 14 missing of which 11 were false
  positives (URLs/wildcards/deferred-per-A2 paths/runtime-user
  dirs/protocol-sift-example paths) and 3 were real:
  `crypto/audit.py` (actual: `audit_log.py`) in
  cryptographic-attestation.md's five-link chain table;
  `services/swarm/session_guard.py` (actual:
  `services/swarm/findevil_swarm/session_guard.py`, package
  level) in CLAUDE.md's build-swarm rate-limit-handling
  paragraph; `tests/acceptance/AC13_no_execute_shell.sh`
  (doesn't exist anywhere) in architecture.md's testable-
  bypass claim — reframed to match the actual `goldens/`
  layout. Different audit shape from the prose-vs-code patterns
  launcher-smoke + divergence-smoke cover; complementary. If
  similar drift surfaces in future iterations, this audit
  warrants its own smoke with the same allow-list pattern as
  divergence-smoke (deferred-per-A2 paths get exceptions).
- **`scripts/divergence-smoke.py` locks executable divergence guards**
  (commit `c5bfa1b`). Three iterations of the divergence-sweep
  procedure (782f364, e6ddc2d, fb319dd) cleaned active drift; this
  smoke makes the cleanup permanent. Scans every active text file
  (~191 files) and asserts no "bad half" of a documented Spec/code
  divergence has resurfaced. 6 executable divergences checked (#1 Rust
  1.83-bookworm, #3 dropped CLI invocations, #4 "11 typed Rust",
  #5 uncommented rmcp, #6 services.swarm.* imports, #8 dashboard
  WebSocket dependency drift); #2 is declarative-only and #7 is
  doc-only. Regex for #3 uses a backtick negative-lookbehind
  so prose that *quotes* the bad pattern (e.g. comments documenting
  why we replaced it) doesn't fire. Regex for #5 only matches
  uncommented lines so the deliberate-marker line in
  services/mcp/Cargo.toml passes. Negative-tested both inclusions
  and exclusions with 8 synthetic shapes — all 8 behave correctly.
  Wired into docker/l1-compose.yml and run-all-smokes.sh as part of
  the local smoke gates; QUICKSTART points operators at those scripts
  without pinning a smoke count. While running the smoke caught one
  more genuine drift the manual sweeps missed: services/mcp/src/crypto/mod.rs:7
  docstring referenced `find-evil verify` — fixed to point at
  `verify_manifest` + `manifest_verify` MCP tool. **Each executable
  wrong-pattern divergence now has a machine-checked guardrail; purely
  declarative/doc-only sections remain documented source-of-truth
  constraints.**
- **rmcp-related stale docs sweep — divergence §5**
  (commit `fb319dd`). Third iteration of the divergence-sweep
  procedure. CLAUDE.md "Spec/code divergences" §5 has long flagged
  that `rmcp` is intentionally NOT a runtime dep — the server is
  hand-rolled. Four stale references survived implying rmcp is
  used at runtime: CLAUDE.md:81 (Repo-layout entry called
  services/mcp "rmcp-based"), services/mcp/src/lib.rs:4 (crate-
  level docstring said the binary wires modules into an rmcp
  ServerHandler), services/mcp/src/tools/mod.rs:9 (tools module
  docstring said each tool is callable from the rmcp wire-up),
  and three legacy Cargo.toml comments that framed rmcp as
  "kept dormant until the full tool surface lands". Each
  reframed to reflect the shipped state with a pointer to the
  divergence. cargo check still succeeds; 6/6 smokes pass.
  Process win: the divergence-sweep procedure has now run three
  times, all four "active" divergences swept (§1 Rust toolchain,
  §3 A2/cli.py, §4 11→12, §5 rmcp); the remaining two (§2
  Cargo.lock-committed and §6 swarm-package-name) are
  declarative + already swept in-band in earlier iterations.
- **`11 → 12` Rust MCP tool count downstream sweep**
  (commit `e6ddc2d`). Same divergence-sweep procedure as 782f364,
  applied to CLAUDE.md "Spec/code divergences" §4. The earlier
  11→12 sweep (6cba0cd) had hit the architecture diagram +
  QUICKSTART + PLAYBOOK but missed four more downstream usages:
  docs/architecture.md:263 (pre-A2-vs-A2 comparison table),
  docs/reports/2026-04-26-srl2018-dc-investigation.md:231
  (§8.1 in the showcase analyst report — a SANS judge would have
  seen "11" there and "12" in CLAUDE.md and wondered which is
  correct), docs/templates/devpost-readme.md:35 (Devpost
  submission template, envsubst'd at v-submit), and
  scripts/sift-vm-setup.sh:6 (the script header). Re-rendered
  the showcase report's HTML+PDF since judges read the PDF
  artifact, not the markdown source. Same pandoc + chrome
  --headless recipe as f7df6c4. PDF grew from 1325101 to 1594607
  bytes (different Chrome build embeds fonts more aggressively;
  content delta is one sentence + one parenthetical). Process
  win: documenting a divergence + applying the sweep is now a
  repeatable two-step workflow.
- **`find-evil verify` / `find-evil run` downstream sweep**
  (commit `782f364`). Last iteration's lesson said "when a
  divergence is documented, sweep for downstream usages." Applied
  to the A2/cli.py drop in §3, found 5 more broken references:
  scripts/l3-run-goldens.sh:153 SSH'd `find-evil run` into the
  SIFT VM (replaced with `bash scripts/find-evil-auto` — the
  surviving A2 orchestrator); services/agent/findevil_agent/crypto/
  audit_log.py + merkle.py + __init__.py docstrings all referenced
  `find-evil verify` as the offline-verification path (replaced
  with pointers to `verify_manifest` + the `manifest_verify` MCP
  tool); docs/DATASET.md:177 used `find-evil verify <manifest>` as
  the reproducibility recipe (replaced with a pointer to
  docs/cryptographic-attestation.md). Also extended CLAUDE.md
  "Spec/code divergences" §3 to flag a sixth broken reference:
  `scripts/build-deb.sh:57` inlines the same dropped
  `findevil_agent.cli` wrapper into the .deb postinst, and line 96
  tells the user to run `find-evil run` — both broken under A2.
  Did NOT unilaterally fix build-deb.sh; same hard-blocker class as
  the Dockerfile (architectural decision pending). Verified:
  6/6 smokes pass; 156/156 agent tests pass.
- **CLAUDE.md "Python agent + swarm" Commands section drift**
  (commit `93a9def`). Five drifts caught by attempting the
  documented commands literally: `uv sync` from repo root claimed
  "root pyproject.toml is a uv workspace" but there is none (verified
  errors "No pyproject.toml found"); `uv run pytest -xvs --cov` from
  repo root collects 156 tests but errors on swarm imports without
  the service-specific deps; `tests/swarm/test_package_imports.py`
  doesn't exist (the actual tree is `services/swarm/tests/`);
  `tests/agent/test_graph_smoke.py::test_kill_resume_restores_state`
  doesn't exist either (was part of the pre-A2 graph.py the L0
  amendment-a2-guard now forbids); the "Run the agent graph
  directly (dev)" entry pointed at
  `python -m findevil_agent.cli run --case ...` — but A2 dropped
  `findevil_agent/cli.py`. Fixed all five with commands that
  actually execute (`uv run --directory services/agent pytest
  tests/test_crypto_audit_log.py::TestCanonicalize::test_sorted_keys
  -v` verified runs + passes). Also brought the line-99
  Repo-layout footer's Dockerfile reference in line with the
  "Spec/code divergences" §3 caveat already in the same file.
  Same drift shape as the previous seven prose-vs-code fixes;
  internally-consistent because the A2 caveat that flagged this
  was *already* in CLAUDE.md - just the dev-command examples
  hadn't been rewritten to match.
- **`scripts/find-evil-sift` `claude-code` remnant** (commit
  `cc4e93e`). The earlier `claude-code → claude` sweep (c167aec)
  used grep filters `--include="*.sh"`, which missed
  `scripts/find-evil-sift` (no extension). The script's launch path
  ran `command -v claude-code` first, then fell back to `claude .` —
  both passing `.` as a positional arg, which `claude` treats as a
  prompt not a directory. Simplified to a single `claude` check
  with no positional arg (script already cd's to repo root).
  Logged the lesson in the autonomous-queue: extension-less shell
  scripts (the `find-evil` family deliberately drops `.sh` to read
  like CLI tools) need to be in the audit grep too.
- **`claude-code` → `claude` across the Product entry path**
  (commit `c167aec`). The Anthropic Claude Code CLI binary is
  `claude`, not `claude-code`. The repo had `claude-code` everywhere
  including in the **actual executable** `scripts/find-evil` (the
  Product entry point judges run): `command -v claude-code` +
  `exec claude-code . "$@"`. Verified — `which claude-code` returns
  non-zero on this system, `which claude` resolves to
  ~/.local/bin/claude. Following the documented recipe verbatim
  (`bash scripts/find-evil` OR `claude-code .`) would have errored
  "command not found". Also: `claude` doesn't take a positional path
  arg (per `claude --help`); it uses cwd. The trailing `.` was
  wrong in either form. Surgical sweep across 8 active files:
  scripts/find-evil (3 spots), scripts/install.sh (stdout instruction),
  README.md, QUICKSTART.md, CLAUDE.md (3 refs), docs/architecture.md
  (4 refs), docs/demo-script-a2.md (recording playbook),
  docs/templates/devpost-readme.md. Deliberately untouched: filenames
  with `claude-code` (amendment doc names like
  `claude-code-mode.md`), the third-party `claude-code-scheduler`
  project name, the `docs.anthropic.com/.../claude-code/install` URL
  path, the test-fixture string in test_session_guard.py (tests a
  regex that matches "rate limit exceeded" globally; CLI-name prefix
  is illustrative not load-bearing). Highest-impact prose-vs-code
  drift caught this session — previous three fixes were doc-only;
  this one broke the Product's actual entry-point script. Caught by
  attempting `which claude-code` after auditing the doc references.

### Operator UX

- **find_evil_auto pre-flight SSH/VM check** (commits `9816585` +
  `244f5e7`). A judge running `bash scripts/find-evil-auto <path>`
  without a configured SIFT VM previously got a Python stack trace
  deep in the SSH stdio reader thread. Now `preflight_check()` runs
  at the top of `main()`: verifies SSH key exists, SSHes into the
  VM with a 10s ConnectTimeout, and probes all three MCP server
  prerequisites in one round-trip — Rust binary + agent_mcp dir +
  uv binary. Failure → exit 2 with the exact ssh command attempted,
  exit code, stderr tail, an enumeration of the three required
  paths so the operator spots which one is wrong, and a three-line
  remediation playbook (first time / VM down / alt host) pointing
  at scripts/sift-vm-bootstrap.sh and the
  FIND_EVIL_GUEST_IP/USER/REPO env vars. `--skip-preflight` flag
  added so fleet_investigate.py doesn't re-check the same VM 22
  times per fleet run.

### Documentation

- **Rust toolchain pin alignment** (commits `f61860d` + `6902bd0`
  + `f429894`). Cargo.toml line-13 comment said "Pinned toolchain
  is Rust 1.83" right next to a [workspace.package] block
  correctly stating "Rust 1.88". Subsequent grep audit found the
  same staleness in four more places: Dockerfile FROM line
  (`rust:1.83-bookworm` → would have failed `docker build` once
  rust-toolchain.toml's 1.88.0 took effect via rustup pull),
  sandbox-plan §Task 2 scope text + planned commit-message
  template, product-plan Tech Stack line + Task 31 instruction.
  All five places now read 1.88 with pointers to CLAUDE.md
  "Spec/code divergences" §1; only the historical CHANGELOG
  reference describing what the OLD Cargo.toml said remains as
  audit-trail.
- **`rmcp` hand-rolled divergence flagged in CLAUDE.md** (commit
  `e89848d`). Spec #2 §4.1 lists `rmcp 0.16.x` as the MCP server
  framework; we ship a hand-rolled stdio JSON-RPC 2.0
  implementation in `services/mcp/src/server.rs` instead (chosen
  for wire-format stability across rmcp churn + dispatch-shape
  parity with the Python `findevil-agent-mcp`). The deliberate
  omission was visible only in `services/mcp/Cargo.toml` line 27
  (commented-out rmcp line) and `services/mcp/README.md`'s NB
  note — neither was guaranteed reading. CLAUDE.md "Spec/code
  divergences" now has a 5th entry making the architectural
  choice load-bearing across the codebase: a future contributor
  cleaning up commented code can no longer silently re-introduce
  the dep.

### Hard blockers discovered

- **Dockerfile A2 cli.py mismatch** (commit `47f67b0`). The
  shipped `Dockerfile`'s `find-evil` wrapper invokes
  `python3 -m findevil_agent.cli` — but Amendment A2 dropped
  `services/agent/findevil_agent/cli.py` (the L0
  `amendment-a2-guard` job fails CI if it reappears). The .deb
  package would error at first invocation. Two architectural paths
  forward: (a) rewrite the wrapper to invoke
  `scripts/find-evil-auto` headless against the SIFT VM, or
  (b) cut the `find-evil` wrapper entirely since A2's "Claude
  Code IS the orchestrator" makes the in-container CLI redundant
  (the .deb becomes documentation + CI artifacts only).
  Architectural choice; flagged as a hard blocker pending user
  resolution before the `v-submit` tag is cut.
- **QUICKSTART.md inbound links** (commit `e3677c4`) to the two
  analyst-facing canonical docs (`verdict-semantics.md` +
  `cryptographic-attestation.md`). Step 5/6 of the find-evil-auto
  walkthrough now point at the verdict triage flow and the
  offline-verification recipe; the "Recommended reading order"
  table gains two new rows for "what do the verdicts mean?" and
  "how does the chain-of-custody work?". Both docs now reachable
  from all three top-level entry points (README + QUICKSTART +
  CLAUDE.md).

### CI

- **L1 now runs both MCP smoke harnesses end-to-end** (commit
  `ed3c35c`). `docker/l1-compose.yml`'s command sequence gained
  steps that run `scripts/rust-mcp-smoke.py` (12-tool dispatch +
  error-path checks) and `scripts/agent-mcp-smoke.py` (synthetic-
  Findings flow through the full demo path). Catches a class of
  integration drift unit tests miss — dispatcher/registry mismatch,
  ToolAnnotations bool flip, etc. Estimated CI cost ~20s, well
  within L1's 2-5min budget.
- **L0 amendment-A2 guard already in place** from earlier session
  (commit `ad4a36e`). Fails CI if any of the dropped pre-A2
  modules (graph.py / api.py / cli.py / supervisor.py /
  specialists/) reappear under any filename.
- **Policy-lock smokes for compute_verdict + fleet_correlate +
  detect_evidence_type** (commits `b0a9a2e` + `395e2b6` +
  `62b3fdf`). Two CI assertions covering load-bearing policy that
  was previously documented but unverified.
  `scripts/verdict-policy-smoke.py` (27 cases) asserts: the
  SUSPICIOUS / INDETERMINATE / NO_EVIL triggers in
  `compute_verdict` match `docs/verdict-semantics.md` (11 cases
  including a regression anchor for the real SRL-2018 base-rd-05
  finding shape — 2 HYPOTHESIS → INDETERMINATE), AND the
  `detect_evidence_type` dispatch (16 cases covering all 6
  memory extensions, evtx, 6 disk variants including .E01
  case-insensitivity and .001 split-image, and 3 unknown
  including the deliberate non-routing of .zip Velociraptor
  bundles).
  `scripts/fleet-policy-smoke.py` (46 cases — commits `925725e` +
  `31a03f3` + `682a5bd` + this iteration each added 4-7 cases on
  top of the original 28) asserts: `normalize_image_name` 14-char
  Volatility-truncation behavior; `COMMON_WIN_PROCS` filter
  coverage of the McAfee/Trellix + VMware Tools + Windows
  infrastructure stack with deliberate Sysinternals exclusions
  per `docs/false-positives.md`; `cross_host_processes` end-to-end
  filter+threshold behavior; `temporal_clusters` 60s-window
  multi-host detection (anchored against the SRL-2018 Autorunsc-
  on-multiple-hosts pattern that headlines `FLEET_REPORT.pdf`);
  `mitre_density` distinct-host counting (regression anchor for
  bug fix in commit `bf11c4d` that prevented counting Pool A +
  Pool B as 2 hosts); `merkle_uniqueness` duplicate-root detection
  (anchor for the fleet.json patch mistake earlier this session
  that pointed two hosts at the same case_dir); `selfscore_aggregate`
  modal-answer + distinct-answers logic. Both smokes load the
  target functions via `importlib` so they assert against shipped
  logic — no copy-paste of policy. ~150ms wall-clock combined;
  wired into `docker/l1-compose.yml` after the agent-mcp-smoke
  step.
- **`scripts/demo-script-smoke.py` locks the 5:00 demo timing**
  (commit `4ddb04a`). `docs/demo-script-a2.md` encodes the Devpost
  video plan as 9 beats with explicit start/end timestamps in a
  markdown table; a future contributor editing one beat without
  adjusting adjacent ones could silently break the timing. The
  smoke parses the `## Beat map` table (handles U+2013 em-dash
  separator), asserts 9 contiguous beats numbered 1-9 starting at
  0:00 and ending at 5:00, length-column = end-start, sum of
  lengths = 300s. ~30ms wall-clock; wired into
  `docker/l1-compose.yml` after fleet-policy-smoke. CI now runs
  three policy-lock smokes per L1 build (~180ms total).
- **`scripts/run-all-smokes.sh` — local-iteration smoke runner**
  (commits `cecef5d` + `f7ff81f` for TTY detection). Single
  command for the 5 L1 smokes outside docker, in the same order
  docker/l1-compose.yml runs them. Per-smoke ✓/✗/SKIP status with
  prereq checks (clean SKIP if `target/release/findevil-mcp`
  missing or `services/agent_mcp/` absent rather than confusing
  failure), final tally, and remediation footer naming `cargo
  build --release -p findevil-mcp` and `uv sync --extra dev` if
  anything fails. ANSI color codes are gated on `[ -t 1 ]` so
  CI-captured logs and Windows-cmd-without-VT output stays plain
  ASCII. ~25s wall-clock combined (dominated by the two MCP-server
  spawn smokes). Closes the local-iteration friction gap for a
  developer changing `compute_verdict`, fleet_correlate logic,
  or the demo script.
- **`scripts/launcher-smoke.py` locks the 6-iteration prose-vs-code
  audit findings** (commit `0155503`). Six bugs across three shapes
  were caught by ad-hoc audit (102c59e Beat 6, ec85639 swarm
  invocations, 43cdbdd crypto recipe, c167aec claude-code → claude
  the catastrophic one, 6f22382 argparse prog, cc4e93e extension-
  less remnant). The smoke now locks all three shapes: bash -n on
  every shell launcher in scripts/ (extension-less + *.sh — the
  find-evil family deliberately drops .sh, so the glob is explicit);
  no bare or `command -v` `claude-code` invocations (catches the
  c167aec class); no `claude .` positional-arg invocations (catches
  the cc4e93e class). 22 launchers x 3 checks = 66 assertions;
  ~50ms. Negative-tested with synthetic fixtures - both bad-binary
  and bad-invocation patterns fire. Wired into docker/l1-compose.yml
  as the 6th L1 smoke and scripts/run-all-smokes.sh as the 6th
  run-all entry. QUICKSTART table updated 5 → 6 smokes. First lock
  protecting against doc/code drift in shell scripts (the prior
  five locks all protected Python data-shape policy).

### Real-evidence runs

- **22-host SRL-2018 fleet investigation completed** (artifact:
  `tmp/fleet-runs/fleet-20260426T055440Z/`). 12 SUSPICIOUS, 10
  INDETERMINATE, 0 NO_EVIL. 22/22 unique Merkle roots — chain
  integrity intact across the fleet. 11/22 hosts show the
  `pslist`=0/`psscan`>0 enumeration divergence — treated as a
  HYPOTHESIS (likely a shared acquisition smear, **not** 11 confirmed
  rootkits; see report §4.3) — and 9/22 show T1055 (Process
  Injection) leads. Headline
  cross-host patterns: 6 hosts ran `Autorunsc.exe` at the *exact
  same second* (cluster 1 in `temporal_clusters.png` — automated
  recon sweep fingerprint), `rubyw.exe` on 13 hosts and `ruby.exe`
  on 12 (Ruby for Windows is not standard enterprise tooling),
  `msadvapi2_32.e` and `msadvapi2_64.e` on 8 hosts each
  (name-spoofing the legitimate `advapi32.dll`).

## [v-submit] - 2026-06-07

Snapshot of the current shipped state before final submission (updated 2026-06-07 with Phase 1–3 integration work + submission packaging + Remotion demo video automation).

### Summary

The current `master` HEAD (commit 8fc18a2 onwards) ships a **31-tool MCP surface** for the SANS Find Evil! 2026 hackathon. The tool count evolved as follows:

- **Pre-A5 (pre-2026-04-30):** 5 tiers cryptographic chain (sha256 → audit → merkle → sigstore → OpenTimestamps/Bitcoin); 13 Rust DFIR + 13 Python crypto/ACH/memory (26 total) plus OTS pair (28 total).
- **Amendment A5 (2026-04-30 removal):** OpenTimestamps/Bitcoin tier and both `ots_stamp`/`ots_verify` tools removed. Chain collapses to 3 tiers. Nominal shipped count pre-2026-05-20: 13 Rust DFIR + 11 Python (24 total).
- **Post-2026-05-20 discovery:** Additional Rust tools beyond documentation. Current audit reveals 19 Rust DFIR + 12 Python crypto/ACH/memory/ACP/expert-feedback tools present in the shipped codebase, confirmed in CLAUDE.md §4 tool-surface table and README.md line 20.

### Shipped MCP Surface (Confirmed 2026-06-06)

- **`findevil-mcp` (Rust):** 19 typed DFIR tools — `case_open`, `disk_mount`, `disk_extract_artifacts`, `disk_unmount`, `evtx_query`, `mft_timeline`, `hayabusa_scan`, `vol_pslist`, `vol_psscan`, `vol_psxview`, `vol_malfind`, `yara_scan`, `usnjrnl_query`, `registry_query`, `prefetch_parse`, `vel_collect`, `sysmon_network_query`, `zeek_summary`, `pcap_triage`.
- **`findevil-agent-mcp` (Python):** 12 typed crypto/ACH/memory/ACP/expert-feedback tools — `audit_append`, `audit_verify`, `manifest_finalize`, `manifest_verify`, `verify_finding`, `detect_contradictions`, `judge_findings`, `correlate_findings`, `memory_remember`, `memory_recall`, `pool_handoff`, `expert_miss_capture`.
- **Total:** 31 tools across two MCP servers. **NO `execute_shell` or broad shell-backed surface.** Cryptographic chain-of-custody locked to 3-tier model (audit prev_hash → rs_merkle → sigstore).

### Phase 1–3 Integration Work (2026-06-07, branch fix/dfir-claim-corrections)

- **playbook.py** — `services/agent/findevil_agent/playbook.py` added as single-source-of-truth for DFIR detection rules, tool sequences, and JUDGE_SELFSCORE_CRITERIA (6 rubric entries matching JUDGING.md verbatim). `find_evil_auto.py` delegates to it.
- **config.py** — `resolve_memory_store_path()` added; Hermes memory SQLite path contract formalized.
- **sprite-state.ts** — dashboard role-state machine handles `judge_selfscore`, `contradiction_resolved`, `manifest_finalize` events.
- **CLAUDE_CODE_FORK_SUBAGENT** corrected — product docs updated to "native Task mechanism"; divergence-smoke check #9 enforces the boundary.
- **Cross-platform render** — `scripts/render_report.py` resolves pandoc/chrome via `$PANDOC_BIN`/`$CHROME_BIN` → `shutil.which`; degrades to `(html, None)` gracefully.
- **SIFT config** — `.mcp.json.sift` uses portable defaults (`~/.ssh/sift_key`, `127.0.0.1`); `find-evil-sift` adds libvirt IP discovery.
- **Starter data** — `goldens/sans-starter/expected-findings.json` stub; `scripts/starter-data-smoke.py` verifies the `SANS_STARTER_URL` contract.
- **find-evil-run** — new one-command operator entry chaining doctor → build → fixtures → find-evil-auto.
- **doctor.sh / install.sh** — python3, git, unzip added to pre-flight; `source ~/.cargo/env` added to install.
- **divergence-smoke #10** — `.mcp.json` surface locked to exactly two typed servers, no gateway/shell tokens.
- **Protocol SIFT coexistence** — positioned in `docs/codex-compatibility.md` and `docs/architecture.md`.

### Submission Packaging + Demo Video Automation (2026-06-07, commits c6af41a–7989d77)

- **SUBMISSION_COMPLIANCE.md** — top-level 10-item checklist mapping every required Devpost component to an exact file path/URL. Linked from the first line of `README.md`.
- **Remotion demo video pipeline** — `scripts/make-demo-video/` is a Remotion 4.0 (React, headless Chrome) project that generates `docs/find-evil-demo.mp4` from the 9-beat structure in `docs/demo-script-a2.md`. Animations: spring-animated rubric badges, typewriter narration, per-beat accent-color gradients, fade-in/out, progress bar.
- **edge-tts TTS layer** — `scripts/make-demo-video-prep.py` generates per-beat MP3 audio using Microsoft Azure neural TTS (`en-US-AriaNeural`, no API key) layered as Remotion `<Audio>` tracks.
- **`claude -p` narration enrichment** — prep script auto-detects the `claude` CLI on PATH and calls `claude -p` per beat to rewrite raw narration into a tighter voiceover script before TTS. Uses the existing Claude Code session token — no `GITHUB_TOKEN` or separate API key required.
- **`scripts/make-demo-video.sh`** — one-command orchestrator: TTS prep → Remotion install (idempotent) → `remotion render` → `docs/find-evil-demo.mp4`.
- **`scripts/make-demo-video-smoke.py`** — 4 smoke tests (prep syntax, Remotion dep, `registerRoot` presence, dry-run beat count/duration). Registered in `run-all-smokes.sh` + `.ps1`.
- All 10 compositions verified: `FindEvilDemo` (9000 frames / 300.00s) + `Beat01`–`Beat09` at correct individual durations.

### Note on Tool-Count Documentation

The [Unreleased] section above preserves the historical A5 removal narrative,
which documents the pre/post OTS-removal evolution (25->23 count). That entry
reflects the tool-count understanding at the time of A5 (April 30, 2026). The
`v-submit` snapshot later confirmed the 31-tool reality then known; the current
post-`v-submit` working tree has since expanded and documented the product
surface as 43 audit-chained tools: 31 Rust DFIR + 12 Python.

---

*This changelog is updated as commits land on `master`. The
`v-submit` tag will be cut by `package-devpost.sh` on or before
2026-06-15 22:45 CDT and will template-substitute the demo video
URL, accuracy benchmark score, and final commit SHA into
`docs/templates/devpost-readme.md`.*
