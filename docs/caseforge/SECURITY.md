# Security & Custody Model — caseforge-core

> The LLM is not the forensic source of truth. Show me the evidence: a finding
> without tool-backed custody is not a finding.

## 1. Default Security Rule — LLM Is Not Source of Truth

The language model may **propose investigative steps** and **draft reports**.
It may not, by itself, establish fact. **Every reportable finding must be backed
by:**

- **VERDICT tool evidence** — the finding traces to a real read-only tool call.
- **`tool_call_id`** — the specific call that produced the evidence.
- **`output_sha256`** — a hash of that tool's output, bound to the finding.
- **Manifest verification** — the run manifest verifies against recorded hashes.

If any of these is missing, the finding is **rejected**. Model-asserted claims
with no tool backing never reach the report.

## 2. Chain of Custody

Custody is enforced per finding and per run.

| Level | Mechanism | Failure outcome |
|-------|-----------|-----------------|
| Finding | `tool_call_id` present and resolvable | Finding rejected |
| Finding | `output_sha256` matches tool output | Finding rejected |
| Run | VERDICT artifacts present (`verdict.json`, `coverage_manifest.json`, `run.manifest.json`, `manifest_verify.json`, `audit.jsonl`) | Run marked **incomplete** |
| Run | Manifest verification passes | Run marked **custody-invalid** |

The `audit.jsonl` append-only log records tool calls and routing decisions so a
reviewer can replay how each finding was reached.

## 3. Default Privacy Rule

**Real / private evidence uses local-only by default.** Cloud models are allowed
only for:

- Synthetic evidence,
- Public datasets,
- Explicit operator-approved evidence, or
- Redacted summaries.

Routing modes (full decision table in MODEL_ROUTING.md):

| Mode | Cloud APIs | Web access | Evidence class |
|------|-----------|-----------|----------------|
| `local-only` | Blocked | Blocked | Real / private (default) |
| `redacted-cloud` | Allowed after redaction | Restricted | Real, only redacted content leaves host |
| `cloud-ok` | Allowed | Allowed | Synthetic / public / lab / operator-approved |

Redaction (in `redacted-cloud`) covers usernames, hostnames, IPs (if required),
domains (if required), emails, secrets, API keys, tokens, and sensitive document
text.

## 4. Fail-Closed Defaults

- Default mode is **`local-only`**. Absence of an explicit, permissive mode means cloud + web are **blocked**.
- The OpenCode config is **locked** at controller start; the model cannot widen its own tool or network scope.
- Missing artifacts fail the run to **incomplete** (not "assume complete").
- Failed manifest verification fails the run to **custody-invalid** (not "assume valid").
- Unbacked findings are dropped, not "best-effort included".

## 5. Threat Model

| Threat | Vector | Control |
|--------|--------|---------|
| Evidence leakage | Model/tool sends real evidence to a cloud API or the web | `local-only` default; privacy router blocks cloud + web; `redacted-cloud` requires redaction before egress. |
| Hallucinated findings | Model asserts a conclusion with no tool basis | Findings require `tool_call_id` + `output_sha256` + manifest; unbacked findings rejected. |
| Silent bad run | Missing/corrupt artifacts pass unnoticed | Artifact validator marks incomplete; manifest verify marks custody-invalid. |
| Evidence tampering in-run | Tool output altered before it reaches the report | `output_sha256` binds finding to exact tool output; manifest verify cross-checks. |
| Scope escalation | Model tries to reach shell/filesystem/network beyond policy | Locked config; only VERDICT read-only MCP tools exposed; no generic shell/fs/Docker/K8s MCP. |
| CI evidence exposure | Real evidence checked into or run through CI | CI runs **synthetic/public fixtures only**; real evidence in GitHub Actions is excluded. |

## 6. What Runs in CI

GitHub Actions runs **synthetic and public fixtures only**. Real, private, or
seized evidence never enters CI. The fixture-only workflow (Phase 10) is the
enforced boundary — a green CI run proves the harness works against fixtures,
not that it has processed any real case.

## 7. Excluded By Design (Attack Surface Reduction)

No generic shell MCP, generic filesystem MCP, Docker/Kubernetes MCP, or broad
GitHub admin MCP is wired in. The model's reachable capability is limited to the
VERDICT read-only forensic tools. Narrow surface, fewer ways to leak or mutate.
