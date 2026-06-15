# Stage Two evidence map

A judge-facing index that ties each of the six Official Rules criteria to the
**committed, verifiable artifact** that supports it, plus the one command that
checks it. Every item below points at real files in this repository — nothing
here is asserted without a path you can open or a command you can run.

> Honesty note (per the rules' "Honesty valued over perfection"): where the
> public evidence is intentionally scoped, this map says so rather than implying
> more coverage than the committed runs prove. Stars are the judge's to assign;
> this document only surfaces the evidence.

---

## 1. Autonomous execution quality

**Claim:** real, in-log self-correction — not staged.

- **Artifact:** [`natural-self-correction-trace.jsonl`](natural-self-correction-trace.jsonl) + [`natural-self-correction-summary.json`](natural-self-correction-summary.json).
- **What it shows:** a genuine `registry_query` failure on a truncated RegBack hive (`hive truncated, header too small`) → named `course_correction` (`narrow … continue remaining hive triage`) → after consecutive failures, `heartbeat_failure` escalates to an honest partial / `INDETERMINATE` verdict.
- **Why it is not theater:** the string `fault_injection` never appears in the source run — the failure is organic. Any injected re-dispatch run is labeled demo-only in [`../accuracy-report.md`](../accuracy-report.md) (`## Stage Two Adversarial Checks`).
- **Verify:** `grep -c fault_injection docs/release-evidence/natural-self-correction-trace.jsonl` → `0`; `grep course_correction …` shows the named recovery records with `seq`/`ts`/`prev_hash`.
- **Scope (honest):** the audit chain emits `tool_call` / `finding_approved` / `course_correction` / `heartbeat_failure` records; it does not yet emit labeled `plan_step` / `hypothesis` records, so the recovery arc is shown through real failure→adjust→escalate evidence rather than an explicit hypothesis log.

## 2. IR accuracy

**Claim:** findings are labeled by confidence, replayed before they count, and the accuracy report is self-critical with specifics.

- **Artifacts:** [`../accuracy-report.md`](../accuracy-report.md) (`## False Positives`, `## Missed Artifacts`, `## Hallucinated Claims Found During Testing`, `## Evidence Integrity`), and [`../../agent-config/SOUL.md`](../../agent-config/SOUL.md) epistemic hierarchy (`CONFIRMED` / `INFERRED` / `HYPOTHESIS`).
- **Specifics the report names (not adjectives):** `alihadi-09-encrypt` dual-use control → expected `INDETERMINATE`; NIST Hacking Case `7/14` recall with the seven unmatched `nhc-*` IDs listed; the Nitroba `NO_EVIL` overclaim caught during testing and the exact fix.
- **Verify:** `grep -nE '^## (False Positives|Missed Artifacts|Hallucinated Claims)' docs/accuracy-report.md`.

## 3. Breadth and depth of analysis

**Claim:** depth is measured and partial coverage is never sold as clean.

- **Artifacts:** every run writes a `coverage_manifest.json` (each artifact class marked `parsed` / `failed` / `unsupported` / `not_supplied`); the ≥2-artifact-class rule for execution claims is a hard rule in [`../../CLAUDE.md`](../../CLAUDE.md) and `agent-config/SOUL.md`.
- **Verify:** see the `coverage_manifest` block referenced in [`evtx-security-log-clear-trace-summary.json`](evtx-security-log-clear-trace-summary.json) (records the not-supplied classes for that run).
- **Scope (honest):** the committed public runs are intentionally scoped (EVTX packet; Nitroba `5/5`; NIST `7/14`). The depth gold standard — a single deep chain correlated across **disk and memory** — is the next evidence to commit, not something the current public packets demonstrate. This is stated plainly rather than implied.

## 4. Constraint implementation

**Claim:** guardrails are architectural (typed surface, no shell), and bypass was tested.

- **Artifacts:** the 43 typed product tools (no `execute_shell`); read-only `case_open` with SHA-256 image hash; hash-chained `audit.jsonl` (`prev_hash`). **Bypass test:** [`../../services/mcp/tests/bypass_paths.rs`](../../services/mcp/tests/bypass_paths.rs).
- **What the test proves:** `case_open_reads_shell_payload_filename_as_a_literal_file` — a shell-payload filename is invoked through a **fixed argv**, so it resolves to an ordinary file (or not), never an executed command; the opened image still produces a 64-hex SHA-256. (The test also documents, honestly, that there is deliberately no path jail because evidence runs at the analyst's own privilege — the guarantee is "no shell," not "no `..`".)
- **Verify:** `cargo test -p findevil-mcp --test bypass_paths`.

## 5. Audit trail quality

**Claim:** any finding traces to its tool execution, and the chain verifies offline.

- **Artifact:** [`evtx-security-log-clear-trace.jsonl`](evtx-security-log-clear-trace.jsonl) + [`evtx-security-log-clear-trace-summary.json`](evtx-security-log-clear-trace-summary.json).
- **Worked trace (one clean finding, end to end):** Finding `f-A-evtx-audit-log-cleared` → cited `tool_call_id` `tc-002` (`evtx_query`) → `tool_call_output.output_hash` → `manifest_verify.overall = true` (ed25519 signature verified, Merkle root ok, audit chain ok).
- **Three-claim trace (the judge's check):** run `scripts/trace-finding <run-dir>` over any fresh case — it resolves **every** finding to its producing tool execution and replays the hash. (`scripts/trace-finding` is the same tool that flags a tampered chain, e.g. it reports `AUDIT CHAIN BROKEN` on the deliberate `refute-tamper` test run.)
- **Verify:** `jq .manifest_verify.overall docs/release-evidence/evtx-security-log-clear-trace-summary.json` → `true`.

## 6. Usability and documentation

**Claim:** a practitioner can deploy and extend it.

- **Deploy:** `scripts/find-evil` (local) / `scripts/verdict <evidence>`; prerequisites in `INSTALL.md` / `QUICKSTART.md`; Apache-2.0.
- **Extend:** [`../extending-the-tool-surface.md`](../extending-the-tool-surface.md) — "add a typed DFIR tool" in five steps, with `services/mcp/src/tools/prefetch_parse.rs` as the reference implementation.
- **Verify:** `bash scripts/doctor.sh` (preflight) then `scripts/verdict <supported-evidence>`.

---

### What would raise the two scoped criteria to their ceiling (honest, not yet committed)

- **Crit 3 (depth):** commit one run that corroborates a single execution chain across **disk + memory** (the disk/memory discrepancy signal the rubric names). Requires a real paired-artifact run.
- **Crit 1 (autonomous execution):** emit labeled `plan_step` / `hypothesis` records in the audit chain and commit a run that shows the full hypothesis→test→re-sequence arc. Requires a small real code change plus a fresh run.

These are listed so the map stays honest about the gap rather than implying coverage the committed runs do not prove.
