# Spark seal smoke receipt (Milestone 13)

**Date:** 2026-07-09T17:02Z (UTC)  
**Host:** operator workstation  
**Script:** `scripts/spark-local-seal-smoke.sh`  
**Branch:** `agent/m13-spark-seal-receipt`  
**Env:**

```bash
export VERDICT_DFIR_HOME=/home/assessor/Desktop/PUG-Projects/verdict/dev
export VERDICT_LLM_BASEURL=http://10.126.60.100:11434
export CASEFORGE_SPARK_ENDPOINT=http://10.126.60.100:11434/v1
export CASEFORGE_SPARK_SMOKE_TIMEOUT=240
```

## Spark tags probe (HTTPS not used — LAN Ollama HTTP only)

```text
curl -sS -m 2 http://10.126.60.100:11434/api/tags
# models present include: qwen3.6:35b-a3b, gpt-oss:120b, llama4:16x17b, llama3.1:8b, gpt-oss:20b
```

## Final line (quoted — exact)

```
PASS: investigate completed via fallback (not agent seal)
```

## Supporting evidence (quoted)

```
evidence: signature_kind=ed25519 signer_effective=ed25519 overall=true signature_verified=true used_fallback=1 inv_rc=0
run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/tmp/auto-runs/auto-7618e1c5-760e-428a-83fe-363481de2ed8
```

Investigate log notes agent path failed open (`Error: Not Found: 404 page not found` against the local route), then:

```
[caseforge] agent run did not produce a complete sealed EVTX run; using deterministic local EVTX auto-runner fallback.
...
signer          = ed25519
...
manifest_verify = PASS
...
[caseforge] verifying deterministic EVTX fallback run: .../auto-7618e1c5-760e-428a-83fe-363481de2ed8
[OK] ...
  manifest custody: verified
```

## What this proves

- Spark Ollama was reachable (`/api/tags` returned models).
- Investigate completed with **custody verified** and **ed25519** on the **deterministic EVTX fallback** path (`used_fallback=1`).
- Smoke script classification is honest: **PASS fallback**, not agent seal.

## What this does NOT prove

- Autonomous Spark / gpt-oss completion of the full seal sequence without fallback.
- That the agent path is healthy (this run saw agent fail with HTTP 404 before fallback).
- Offline-only seal-proof scripts (`local-ed25519-seal-proof.sh`) are a different gate.

## m15 root cause (agent 404) — caseforge fix

m13 set `VERDICT_LLM_BASEURL=http://10.126.60.100:11434` **without** `/v1`.
`configs/opencode/opencode.json` wires `@ai-sdk/openai-compatible` with that
baseURL; the client POSTs `${baseURL}/chat/completions` →
`http://…:11434/chat/completions`. Ollama only serves OpenAI-compat under
`/v1/chat/completions`, so the agent path fails immediately with
`Error: Not Found: 404 page not found` and investigate falls back to the
deterministic EVTX auto-runner (`used_fallback=1`).

Doctor greened the bare root because it rewrites `/v1` → `/api/tags` for the
liveness probe (or hits the Ollama root `200 Ollama is running`), which is not
the OpenAI chat path.

**Caseforge-only fix (m15):** `normalizeOpenAiCompatBaseUrl` appends `/v1` when
the URL path is empty/root — used by `investigate` (env passed to engine),
`doctor` (`selectedLocalEndpoint`), and `spark-local-seal-smoke.sh`. Engine
(opencode) does not need a URL rewrite; it correctly uses the provided baseURL.

With bare-root normalized, agent may still hang/timeout on long Spark tool
runs (m13 `/v1` attempt rc=124) — that is separate from the 404. Do not claim
`used_fallback=0` without a fresh smoke that seals on the agent path.

## Prior attempt in the same session (not the quoted outcome)

With `VERDICT_LLM_BASEURL=http://10.126.60.100:11434/v1`, investigate hung until the smoke timeout (rc=124). Case dir existed with only `case.json` (no `run.manifest.json`). Exact line from that attempt:

```
FAIL: run dir missing run.manifest.json (inv_rc=124 run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/.project-local/findevil/cases/4a1361c0-861e-4752-a7e6-3a616f4a2769)
```

That FAIL is model/timeout hang behavior, not a smoke-script path/parse bug. No seal claim was made for that attempt.

## Script status

No smoke-script bug fixed in this lane. Receipt only.

## m17 hang residual (after /v1 + hang messaging) — diagnosis only

**Not agent seal.** Live m17 seal smoke (2026-07-09, inotify max_user_watches=524288,
`CASEFORGE_SPARK_SMOKE_TIMEOUT=600`) still stalls on the agent path after doctor
greens `/v1`.

### Primary (model / Spark Ollama)

Evidence from concurrent seal investigate (`verdict run --pure`, route
`spark-ollama` → `gpt-oss:20b` via `verdict-local/local`):

- opencode log reaches `stream providerID=verdict-local modelID=local … agent=verdict`
  then sits with ESTAB TCP to `10.126.60.100:11434` and no further session steps.
- Direct probe (same host/model) returned **0 bytes for 30s**:

```bash
curl -sS --max-time 30 http://10.126.60.100:11434/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-oss:20b","messages":[{"role":"user","content":"Reply with exactly: pong"}],"max_tokens":8,"stream":false}'
# curl: (28) Operation timed out after 30001 milliseconds with 0 bytes received
```

- `GET /api/tags` and doctor `selected local endpoint reachable (…/v1)` stay OK —
  liveness ≠ chat completion under load.
- m16 hang (rc=124, no case/run) already had this model-wait shape; m16 also had
  `inotify_add_watch … ENOSPC` (raised this session). m17 no longer shows ENOSPC
  on the live path; hang remains model non-response.

**Conclusion:** residual hang is **not** a missing caseforge abort, bare-baseURL
404, or investigate wrapper loop. It is Spark Ollama / `gpt-oss:20b` failing to
return chat completions in time. Operator mitigations: smaller model
(`VERDICT_LLM_MODEL=llama3.1:8b`), free Ollama capacity, or accept fallback PASS
(not agent seal).

### Secondary (harness noise — handoff to opencode / subtree-pull)

Installed binary version string:

```text
0.0.0-agent/m4-verdict-opencode-runtime-202607080429
```

Background config install pins `@opencode-ai/plugin@${InstallationVersion}`.
A version containing `/` is treated by npm as GitHub `owner/repo`, so a child
process hangs on:

```text
git ls-remote ssh://git@github.com/0.0.0-agent/m4-verdict-opencode-runtime-202607080429.git
# SSH SYN-SENT to github.com:22 (observed under live investigate)
```

Root: build embeds git branch as channel (`0.0.0-${CHANNEL}-…` in
`engine/packages/script/src/index.ts`); branch `agent/m4-…` injects `/`.
Install is `forkDetach` (does not block the LLM stream), but is still a real
harness bug. **Fix belongs in verdict-opencode** (sanitize `/` in channel/version
before npm pin, or skip non-semver pins) → rebuild `verdict` → optional
caseforge `engine/` subtree-pull. Do **not** dual-edit the same paths in the
opencode lane.

m16 binary `0.0.0-main-202607050502` (no slash) still hung 300s on model —
slash bug is additive noise, not the m16 root cause.

### Engine / caseforge code action (m17)

No caseforge investigate or smoke-script functional fix in this lane (model-side
primary). Hang-timeout messaging already lands via PR #19. This section is the
m17 diagnosis receipt only.

## Milestone 14 — REQUIRE_AGENT gate (script option)

`CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1` makes the smoke **FAIL** when the
deterministic EVTX fallback ran (`used_fallback=1`). Default remains `0`
(m13 behavior: PASS with fallback, never claim agent seal).

This option does **not** produce an agent seal by itself. A true
`used_fallback=0` agent-path seal is still open until the investigate
agent path succeeds without fallback.

```bash
# Default (honest fallback PASS when agent path fails open):
bash scripts/spark-local-seal-smoke.sh

# Strict (FAIL if fallback was used — use when debugging agent path only):
CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1 bash scripts/spark-local-seal-smoke.sh
```

## Milestone 24 — FORCE_AGENT DE_1102 scorecard (REQUIRE_AGENT=1)

**Date:** 2026-07-09T19:55–20:08Z (UTC)  
**Branch:** `agent/m24-force-agent-scorecard`  
**Binary feed (opencode wave1):** `VERDICT_BIN=/home/assessor/.local/bin/verdict`  
**Runtime version (quoted):** `0.0.0-agent-m24-binary-rebuild-202607091953`  
**Log:** `tmp/m24-logs/seal-smoke.log` (umbrella)

### Recipe (m20/m23 + m24 binary)

```bash
export VERDICT_BIN=/home/assessor/.local/bin/verdict   # opencode m24 rebuild post-#15
export VERDICT_DFIR_HOME=/home/assessor/Desktop/PUG-Projects/verdict/dev
export VERDICT_LLM_BASEURL=http://10.126.60.100:11434
export CASEFORGE_SPARK_ENDPOINT=http://10.126.60.100:11434/v1
export VERDICT_LLM_MODEL=gpt-oss:20b
export OPENCODE_TOOL_CHOICE=required
export VERDICT_FORCE_TOOL_CHOICE=1
export CASEFORGE_FORCE_AGENT=1
export CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1
export CASEFORGE_SPARK_SMOKE_TIMEOUT=480
export CASEFORGE_SPARK_SMOKE_TIMEOUT_FORCE=1
bash scripts/spark-local-seal-smoke.sh
```

### Quoted outcomes (do not invent `used_fallback=0`)

**Attempt 1** (missing `findevil-mcp` binary under `VERDICT_DFIR_HOME/target/release/`):
agent path emitted prose JSON tool stubs; fallback also failed pre-flight; no case/run dir.

**Attempt 2** (MCP restored) — exact lines:

```
evidence: signature_kind=ed25519 signer_effective=ed25519 overall=true signature_verified=true used_fallback=1 inv_rc=0
FAIL: agent seal not achieved: used_fallback=1 (CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1). signature_kind=ed25519 overall=true run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/tmp/auto-runs/auto-742b9767-20c5-47b4-89dc-6cfa22045a38
```

Agent failure mode (quoted): model called garbled name `findevil-agent_mcp_audit_append` →
`Model tried to call unavailable tool 'invalid'` (available-tools list from opencode #15
was returned). Incomplete case → deterministic `find_evil_auto` fallback sealed ed25519.

**Attempt 3** — exact lines:

```
evidence: signature_kind=ed25519 signer_effective=ed25519 overall=true signature_verified=true used_fallback=1 inv_rc=0
FAIL: agent seal not achieved: used_fallback=1 (CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1). signature_kind=ed25519 overall=true run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/tmp/auto-runs/auto-4477ade6-3476-48ce-bdb9-33cad17f4a63
```

Agent ran `findevil-mcp_evtx_query` only; never sealed audit/manifest → incomplete → fallback.

### What this proves

- m24 PATH `verdict` post-#15 rebuild was used (`0.0.0-agent-m24-binary-rebuild-202607091953`).
- Under `CASEFORGE_FORCE_AGENT=1` + `REQUIRE_AGENT=1`, **agent-path seal was not achieved**
  on either usable attempt: both **`used_fallback=1`**.
- Fallback product path still seals **ed25519** with `overall=true` (custody OK) — that is
  **not** an agent seal.

### What this does NOT prove

- Stable `used_fallback=0` agent seal (m23 demonstrated once; m24 re-smokes failed).
- That the agent path exceeds the Claude / product-path fair-fight arm — **no agent-path
  technique pack numbers** were produced; do not claim exceed.
- That opencode #15 is insufficient: available-tool errors fired; residual is model tool-name
  garbling / incomplete seal sequence, not a missing binary alone (after attempt 1 fix).

## Milestone 26 — offline gates residual (no Spark)

**Date:** 2026-07-09  
**Branch:** `agent/m26-offline-gates`  
**Scope:** model-independent offline verification only. Spark / Ollama /  
`spark-local-seal-smoke` **not** run.

### Offline results (quoted)

- `npm run typecheck` — ok (SDK + TUI build; CLI `tsc --noEmit`)
- `node scripts/selftest.mjs` — **127 passed, 0 failed**
- `caseforge doctor` — required items mostly ok; selected local endpoint **MISS**
  (`http://SPARK-HOST:11434/v1` down — expected offline)
- DE_1102 fixture present at  
  `verdict/dev/evidence/DE_1102_security_log_cleared.evtx` (1 118 208 bytes);
  selftest covers 1102 audit→finding assembly without agent/MCP

### Residual (explicit — do not invent)

`CASEFORGE_FORCE_AGENT=1` agent-path seal (`used_fallback=0`) remains **Spark-gated**.
It requires a live Ollama endpoint + `scripts/spark-local-seal-smoke.sh` (optionally
`CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1`). Offline m26 does **not** claim
`used_fallback=0`; last FORCE_AGENT scorecard remains m24 (`used_fallback=1` under
REQUIRE_AGENT).
