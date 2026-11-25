# Model Routing — caseforge-core

> Three modes decide where the model runs and what evidence it may see. The
> router is fail-closed: absent an explicit permissive mode, evidence stays on
> the host.

## 1. Routing Modes

| Mode | What it allows | Intended evidence class |
|------|----------------|-------------------------|
| `local-only` | Only local backends: vLLM, Ollama, llama.cpp, LM Studio, NIM, or another local OpenAI-compatible endpoint. **Cloud APIs and web access are blocked.** | Real / private evidence (default). |
| `redacted-cloud` | API/cloud models, but **only after redaction** of sensitive content. | Real evidence, egress limited to redacted content. |
| `cloud-ok` | Cloud / API models freely. | Synthetic fixtures, public datasets, lab cases, operator-approved non-sensitive evidence. |

### xAI Grok cloud

Named routes **`xai-grok`** / **`xai-grok-mini`** call **xAI’s API** (`XAI_API_KEY`), not
local Ollama/Spark. See **[GROK_CLOUD.md](GROK_CLOUD.md)**. Example:

```bash
export XAI_API_KEY=...
caseforge investigate fixtures/synthetic \
  --privacy cloud-ok --evidence synthetic --route xai-grok
```

`local-only` is the default. Redaction under `redacted-cloud` covers usernames,
hostnames, IPs (if required), domains (if required), emails, secrets, API keys,
tokens, and sensitive document text.

## 2. Decision Table

Provider location × mode × evidence class → allow / deny.

| Provider location | Mode | Evidence class | Decision |
|-------------------|------|----------------|----------|
| Local | `local-only` | Real / private | **Allow** |
| Local | `local-only` | Synthetic / public | **Allow** |
| Cloud / API | `local-only` | Any | **Deny** (cloud + web blocked) |
| Local | `redacted-cloud` | Real / private | **Allow** |
| Cloud / API | `redacted-cloud` | Real, redacted | **Allow** (only after redaction) |
| Cloud / API | `redacted-cloud` | Real, unredacted | **Deny** |
| Local | `cloud-ok` | Any | **Allow** |
| Cloud / API | `cloud-ok` | Synthetic / public / lab / operator-approved | **Allow** |
| Cloud / API | `cloud-ok` | Real / private (not approved) | **Deny** |

> The router evaluates every model route before egress. In `local-only` there is
> no code path that reaches a cloud API or the web.

## 3. GPU / Tool-Calling Reality Constraint

Local-only real investigations require a **GPU + vLLM serving a strong
tool-caller**. This is an empirical constraint, not an aspiration.

**What was tested (controlled, on CPU-only hardware without a working GPU):**

| Model | Result |
|-------|--------|
| `qwen2.5-coder:7b` (local) | Could **not** reliably drive the forensic tools — emitted tool calls as plain text instead of structured tool calls. |
| `llama3.1:8b` (local) | Could **not** reliably drive the tools — **fabricated findings**. |
| `gpt-5.5` (cloud) | Executed the real `case_open` → `pcap_triage` chain. |
| `gpt-5.4-mini` (cloud) | Executed the real `case_open` → `pcap_triage` chain. |

**Interpretation (honest scope):** these are small local models on CPU-only
hardware. The failures show that a weak/underserved local tool-caller is unsafe
for real DFIR — one could not even emit valid tool calls, the other invented
evidence, which is exactly the hallucination the custody model exists to catch.
The capable cloud models drove the real tool chain. This does **not** prove that
no local model can do the job; it shows that on CPU-only hardware the tested
small models cannot, and that a capable tool-caller is required.

**Implication for routing:**

- `local-only` real investigations need a GPU and vLLM serving a model strong at structured tool-calling. Underpowered local serving will fail closed (bad tool calls) or, worse, fabricate — the custody validator (Phase 8) is the backstop that rejects fabricated, unbacked findings.
- Where only CPU-only local hardware is available, a real investigation is better served by `redacted-cloud` (redacted egress) or `cloud-ok` for synthetic/public/approved evidence — never by trusting a weak local tool-caller.
- Provider tool-calling capability should be benchmarked (Phase 14) to set safe routing defaults.

See LLM_SUPPORT_2026.md for the per-provider support and tool-calling notes.
