# Live-Test Gate & Command Reference

The "done" gate for dev work, plus the full command catalog. Pairs with `CLAUDE.md` "Running A Case".
`QUICKSTART.md` is the 3-step quick start; this doc is the exhaustive reference. Quote these
commands verbatim so generated code and human work use the same paths. Don't hard-code smoke
counts — the runners print the current pass/skip/fail tally.

---

## Live tests (the "done" gate — run this before claiming "done")

A change is not "done" until a **live test** passes: run the real pipeline against real
evidence and confirm a real Verdict plus a verified manifest. Smoke scripts are a CI
predictor (below), not the verification standard.

```bash
scripts/verdict evidence/DE_1102_security_log_cleared.evtx   # the staged known-good evtx Case
scripts/verdict --watch                                       # drop any supported evidence into evidence/, auto-runs
scripts/verdict <path>                                        # supported evidence path
```

Output lands in `tmp/auto-runs/<case-id>/` (`verdict.json`, `manifest_verify.json`,
`REPORT.{md,html,pdf}`).

**A live test PASSES when all four hold** (read `verdict.json` + `manifest_verify.json`):
1. The pipeline ran **past `case_open`** — a non-empty tool/audit chain, not a one-tool stub.
2. **Every Finding cites a `tool_call_id`** (`verdict.json.findings[].tool_call_id`).
3. **`manifest_verify.json.overall == true`** (audit chain + Merkle root + leaf count all OK).
4. The Verdict word is **honest about coverage** — an `INDETERMINATE` on a custody-only disk is a PASS, not a failure; limited coverage is never read as `NO_EVIL`. See `docs/verdict-semantics.md`.

PASS does **not** require `SUSPICIOUS`. A correct `INDETERMINATE` or a scoped `NO_EVIL` (with
its scope stated) is a passing outcome. A run that stops at `case_open`, or emits a Finding
without a `tool_call_id`, is a FAIL regardless of the Verdict word.

### Live-test matrix by evidence type

The bar is the same per type: the app runs the real DFIR process and emits an honest,
manifest-verified Verdict. "Works today" vs "known gap" is documented honestly so a gap reads
as a gap, not a clean bill of health.

| # | Type / drop | Live-test command | What PASS looks like | Works today vs KNOWN GAP |
|---|---|---|---|---|
| 1 | `.evtx` (`evidence/DE_1102_security_log_cleared.evtx`) | `scripts/verdict evidence/DE_1102_security_log_cleared.evtx` | `evidence_type:"evtx"`, `verdict:"SUSPICIOUS"`, ≥1 CONFIRMED (event 1102 → T1070.001), Finding cites `tool_call_id`, `manifest_verify.overall=true` | **WORKS** — staged reference Case |
| 2 | Memory `.mem, .raw, .dmp, .vmem` | `scripts/verdict evidence/base-dc-memory.img` (`--sift` for in-VM tools) | audit ≥4 `tool_call_start`; `vol_pslist` + `vol_psscan` + `vol_psxview` all present; DKOM (T1014) only at `INFERRED`+ when corroborated **and** acquisition-smear ruled out first | **WORKS** for process/injection triage; **GAP** acquisition-smear can mimic DKOM (`KeNumberProcessors=0`, psscan-only OS singletons) → honest `HYPOTHESIS`/`INDETERMINATE` is still a PASS |
| 3 | Disk `.E01, .dd, .raw, .aff` (`evidence/SCHARDT.dd`) | local: `scripts/verdict evidence/SCHARDT.dd`; VM parity: `scripts/verdict --sift <vm-path>` (both use `disk_mount` + `disk_extract_artifacts` and Sleuth Kit direct-read where available) | **local and `--sift`: real content verdicts** with Findings only from parsed artifacts, never from `case_open` alone. If Sleuth Kit/mount/extract prerequisites are absent, the correct PASS is a scoped `INDETERMINATE` with `analysis_limitations`, never `NO_EVIL` | **WORKS locally and under `--sift` for NIST SCHARDT** → `SUSPICIOUS`, 8 CONFIRMED hacking-tool executions (cain/netstumbler/mirc/ethereal) via the in-tree XP-hive registry parser (`regf.rs`) + Prefetch×UserAssist execution corroboration. **GAP** broader disk coverage still depends on supported parsers/artifact classes; unsupported classes stay limitations, not clean findings |
| 4 | Velociraptor `.zip` | `scripts/verdict evidence/<coll>.zip` | zip extracted safely (zip-slip / oversize rejected); per-artifact tools ran; Findings cite `tool_call_id`; manifest verifies | **WORKS** to the extent the 45 typed product tools reach the carried artifacts; classes they don't cover are a documented gap, not `NO_EVIL` |
| 5 | Mixed case directory | `scripts/verdict evidence/<case-folder>/` | each contained type ran per its playbook under one `case_id`; merged Verdict; `detect_contradictions` surfaced Pool A/B disagreements; manifest verifies | **WORKS** (each sub-type inherits its own row's status; disk items parse only when row 3 prerequisites produce supported artifacts) |
| 6 | Network `.pcap, .pcapng` | `scripts/verdict evidence/<cap>.pcap` | `pcap_triage` / `zeek_summary` ran; flagged endpoints are leads-until-corroborated; Findings cite `tool_call_id`; manifest verifies | **WORKS** for triage; network leads alone don't satisfy execution/exfil corroboration (need finding-specific staging + a 2nd artifact class) |

---

## Local smoke runners (CI predictor — optional)

L1 CI runs these on every push; running them locally just predicts CI. They are **not** live
tests and do not exercise a real investigation end-to-end. Counts are printed by the runner.
- POSIX/Git Bash: `bash scripts/run-all-smokes.sh`
- Native Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1`

## Rust MCP server (`services/mcp/`)
- Build: `cargo build --workspace --release --locked`
- Lint: `cargo check --workspace && cargo clippy --workspace --all-targets -- -D warnings`
- All tests: `cargo test --workspace --locked`
- Single test (named fn in integration test file): `cargo test -p findevil-mcp --test tool_smoke test_case_open_returns_handle`
- Single crate's unit tests: `cargo test -p findevil-mcp --lib`

## Python (`services/agent/`, `services/agent_mcp/`)
- **No root `pyproject.toml`** — each service is its own uv project. Use `--directory <svc>` (or `cd` first) for any uv command needing a project context.
- Env sync per service: `uv sync --directory services/agent` (and `services/agent_mcp`)
- Lint + format check (works from repo root): `ruff check . && ruff format --check .`
- All tests: see `docker/l1-compose.yml` lines 60–68; locally use the smoke gate above or run each service's pytest separately.
- Single file: `uv run --directory services/agent pytest tests/test_crypto_audit_log.py -v`
- Single test fn: `uv run --directory services/agent pytest tests/test_crypto_audit_log.py::TestCanonicalize::test_sorted_keys -v`

## Next.js web (`apps/web/`)
`apps/mcp-widgets/` remains deferred per A2 §2.1; commands below filter to `@findevil/web`
since it's the only live workspace member.
- Install: `pnpm install --frozen-lockfile` (from repo root)
- Typecheck: `pnpm --filter @findevil/web typecheck`
- Build: `pnpm --filter @findevil/web build`
- Test: `pnpm --filter @findevil/web test` (8 Vitest tests covering `audit-tail.ts` + the path allow-list)
- Test one file: `pnpm --filter @findevil/web test -- __tests__/audit-tail.test.ts`
- Dev server: `pnpm --filter @findevil/web dev` then `http://localhost:3000` (placeholder dashboard) or `http://localhost:3000/debug` (live SSE event viewer)
- Regenerate audit-event TS types from Pydantic: `pnpm --filter @findevil/web codegen:events` (writes `apps/web/lib/events.ts`)

## Readiness packet gates
- **Native Windows (packet-producing):** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker`. Full mode runs `scripts/build-checker.py run`, invokes the same internal automation engine used by `scripts/verdict` unless `-ExistingRunDir` is supplied, verifies `run.manifest.json` against `audit.jsonl`, checks report QA / expert-signoff / customer-release blockers, copies required artifacts into `tmp/readiness-gates/<run-id>/packet/`, writes `readiness-summary.json` and packet/readiness-packet-manifest.json`, then creates `readiness-packet.zip`.
- **Fixed `-RunId` reruns** are supported: gate refreshes packet contents; if `<run-id>-build` exists, uses a fresh `<run-id>-build-<timestamp>` local-build child run instead of failing.
- **Fast packet validation:** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode PacketOnly -ExistingRunDir tmp/auto-runs/<case-id>`. Packages/checks but doesn't claim full submission readiness.
- **POSIX strict check-only:** `EVIDENCE_RUN_DIR=<run-dir> L1_DOCKER_STATUS=passed L1_DOCKER_LOG=<log-with-READINESS_L1_PASS> bash scripts/readiness-gate.sh`. Prints `SUBMISSION_READY` or `READINESS_BLOCKED`; doesn't assemble `readiness-packet.zip`.
- Readiness states are deliberately conservative: `READY_FOR_EXPERT_REVIEW` / `PACKET_READY_FOR_EXPERT_REVIEW` means ready for human expert review, **not** customer release. Any skipped build, missing L1 evidence, failed manifest verification, failed report QA, or customer-releasable flag emitted by automation becomes `READINESS_BLOCKED`.

## Sandbox layers (Spec #3)
- L1 locally: `docker compose -f docker/l1-compose.yml up --build --exit-code-from l1` (base: `docker/l1-devbase.Dockerfile`)
- L2 locally (Sysbox installed): `bash scripts/l2-dfir-smoke.sh` (base: `docker/l2-siftlite.Dockerfile`)
- L3 Packer build: `packer build packer/sift-microvm.pkr.hcl` (reads `sift-2026.03.24.ova` from repo root)
- L3 goldens in CI: `bash scripts/l3-run-goldens.sh` (expects warm qcow2 in GHA cache)

## Workflows and CI (Spec #4)
- Static check workflow files: `actionlint .github/workflows/*.yml`
- Simulate a workflow job locally: `act -j l0-static`
- Cut weekly release: `git tag v<N> && git push origin v<N>` (triggers `release.yml`, gates on L3 green)
- Cut final submission: `git tag v-submit && git push origin v-submit` (triggers `devpost-submit.yml` after `release.yml` succeeds)
