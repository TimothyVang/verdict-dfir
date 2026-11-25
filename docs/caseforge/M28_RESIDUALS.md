# Milestone 28 — evidenced `used_fallback` + gated cloud harness

**Branch:** `agent/m28-residuals` (from `origin/main` @ `d8b065f`)
**Scope:** two m27 honesty/harness residuals, fixed model-independently. No live
cloud call was made by the agent lane (operator-gated, see below).

## Residual 1 — `used_fallback` must be evidenced, never synthesized

m27 asserted `used_fallback=0` for the cloud path but recorded it in **no**
custody artifact, so `caseforge verify` could not attest it and the claim was
retracted.

**Fix (caseforge side):**
- SDK `packages/caseforge-sdk/src/runrecord.ts`:
  - `readUsedFallback(result)` — returns the boolean only when the runtime run
    result literally carries a `used_fallback` boolean; otherwise `null`. Never
    coerces strings/numbers, never invents a value.
  - `assembleRunRecord({ runtimeResult, engineUsedFallback })` — sources
    `used_fallback` in priority order: (1) the runtime run result, (2) caseforge's
    own control-flow fact that it selected the deterministic engine, (3) `null`
    (unknown). It never defaults to a synthesized `false`.
  - `writeCaseforgeRun` / `readCaseforgeRun` / `attestUsedFallback` — persist and
    read a caseforge-owned `caseforge_run.json` alongside the sealed custody
    files; `attestUsedFallback` derives live from the runtime `run_result.json`
    when no record exists.
- `caseforge investigate` records provenance (`recordRunProvenance`) at each
  verified run dir, reading the runtime run result (`run_result.json`) that the
  opencode lane emits.
- `caseforge verify` surfaces a `used_fallback: yes|no|unknown (source: …)` line.
  It is **informational** — it does not change the exit code.

Honest boundary: caseforge reads the value; the `verdict`/opencode runtime is
what emits `used_fallback` in its run result (that emission lands in the opencode
lane, not here). When nothing is recorded, `verify` prints `unknown`, never a
fabricated `no`.

## Residual 2 — outward cloud call must be operator-gated

m27's lane harness permitted an ungated outward cloud call (an always-approve
lane fired a live xAI investigation unprompted).

**Fix:** SDK `cloudAckGate` (in `privacy.ts`) + wiring in `investigate`:
- A `--privacy cloud-ok` (or any cloud-route) investigation **refuses** unless the
  operator sets `CASEFORGE_CLOUD_ACK=1` (or passes `--cloud-ack`). Defaults OFF.
- The gate fires **after** the privacy router and **before** any OAuth check or
  runtime spawn — no egress on refusal.
- Local routes never require acknowledgement.

Observed (real CLI, refusal path only — no egress):
```
REFUSED: outward cloud investigation refused: set CASEFORGE_CLOUD_ACK=1 (or pass
--cloud-ack) to acknowledge that evidence/prompts leave the host
```

## Verification (this lane, offline)

- `npm run build` — ok (SDK → TUI → CLI, ordered)
- `npm run typecheck` — ok
- `node scripts/selftest.mjs` — **183 passed, 0 failed** (28 new assertions;
  tests written first, confirmed RED → GREEN)
- `caseforge verify fixtures/synthetic/sample-run` — surfaces
  `used_fallback: unknown (source: unknown)` (no run result present → honest)

## PREPARED operator cloud command (NOT run by the agent)

Bounded live cloud investigation on ONLY the public fixture. The operator runs
this — the agent lane did not. The operator must re-authenticate the xAI
SuperGrok subscription OAuth first (`caseforge auth login`), then acknowledge the
egress with `CASEFORGE_CLOUD_ACK=1`.

Primary route — `xai-grok-oauth`:
```bash
export VERDICT_DFIR_HOME="$HOME/Desktop/PUG-Projects/verdict/dev"
export CASEFORGE_CLOUD_ACK=1   # operator acknowledges outward cloud egress

env -u XAI_API_KEY -u OPENAI_API_KEY \
  node packages/caseforge-cli/dist/src/cli.js investigate \
  "$HOME/Desktop/PUG-Projects/verdict/dev/evidence/DE_1102_security_log_cleared.evtx" \
  --privacy cloud-ok --evidence public \
  --route xai-grok-oauth --cloud-ack
```

Fallback route — `chatgpt-oauth` (if xAI re-auth is unavailable):
```bash
env -u OPENAI_API_KEY -u XAI_API_KEY \
  node packages/caseforge-cli/dist/src/cli.js investigate \
  "$HOME/Desktop/PUG-Projects/verdict/dev/evidence/DE_1102_security_log_cleared.evtx" \
  --privacy cloud-ok --evidence public \
  --route chatgpt-oauth --cloud-ack
```

Notes:
- `--evidence public` is honest: `DE_1102_security_log_cleared.evtx` is a public
  DFIR sample, not seized/real evidence. Cloud-ok + public passes the privacy
  router.
- After the run, `caseforge verify <run-dir>` will surface the `used_fallback`
  line sourced from the runtime run result recorded into that run dir.
- Do NOT run against any real/sensitive evidence on a cloud route.
