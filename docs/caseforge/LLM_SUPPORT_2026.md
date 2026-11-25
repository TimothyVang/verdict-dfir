# LLM Support (2026) — caseforge-core

> Universal routing across local/offline and online/API providers. The harness
> is provider-agnostic; the privacy router decides what any given provider is
> allowed to see.

## 1. Support Status

Support is stated per provider as one of exactly two levels. **Config presence is
not live support.**

| `route_status` | Meaning |
|---|---|
| **named-route** | A route in `configs/model-routes.yaml` targets this provider. It is selectable by `caseforge investigate --route <id>` and privacy-gated by the router. |
| **capability-only** | **Experimental / unverified.** The provider is described in `configs/provider-capabilities.yaml` so the router knows its location and auth shape, but **no named route exists**, nothing selects it, and no live receipt has been obtained. |

`route_status` is machine-checked: `scripts/selftest.mjs` fails if a provider
claims `named-route` without one, or if a `capability-only` provider acquires a
route without being re-labelled.

The privacy-mode router (Phase 6) that governs every route is implemented, and
its verdict is asserted across the entire named-route surface in the self-test:
`local-only` denies every cloud route; `cloud-ok` admits cloud routes only for
synthetic / public / approved evidence.

Live local investigations still require a running, strong tool-calling endpoint;
a registered local route does not by itself mean a reachable one (use
`caseforge doctor --route <id>`).

## 2. Local / Offline Providers

Reachable in every mode, including `local-only`.

| Provider | `route_status` | Route id | Tool-calling notes |
|----------|----------------|----------|--------------------|
| vLLM | named-route | `local-vllm` | Preferred local serving for `local-only` real investigations; must serve a strong tool-caller. Needs a GPU. |
| Ollama | named-route | `local-ollama`, `spark-ollama` | Convenient local serving; tested small models (qwen2.5-coder:7b, llama3.1:8b) were unreliable tool-callers on CPU-only hardware. |
| llama.cpp | named-route | `local-llamacpp` | Local OpenAI-compatible endpoint; tool-calling depends on the served model/template. |
| LM Studio | named-route | `local-lmstudio` | Local OpenAI-compatible endpoint; tool support per loaded model. |
| NIM | named-route | `local-nim` | NVIDIA inference microservice; local OpenAI-compatible endpoint. |

Any other local OpenAI-compatible endpoint can be driven through an existing
local route by exporting `VERDICT_LLM_BASEURL` / `VERDICT_LLM_MODEL`.

## 3. Cloud / API Providers

Reachable only in `redacted-cloud` (after redaction) or `cloud-ok` (synthetic /
public / approved). Blocked in `local-only`.

### 3.1 Routable today (`named-route`)

| Provider | Route id | Auth | Tool-calling notes |
|----------|----------|------|--------------------|
| OpenAI | `chatgpt-oauth` | ChatGPT subscription OAuth | Strong tool-caller (gpt-5.5, gpt-5.4-mini drove the real tool chain). Never uses `OPENAI_API_KEY`. |
| OpenAI | `openai-api` | `OPENAI_API_KEY` | Platform API billing. |
| xAI | `xai-grok-oauth` | SuperGrok subscription OAuth | Never uses `XAI_API_KEY`. |
| xAI | `xai-grok`, `xai-grok-mini` | `XAI_API_KEY` | Platform API billing (console.x.ai). |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | Aggregator; tool support is per underlying model. |
| Z.AI | `zai-direct` | `ZAI_API_KEY` | Direct GLM family (glm-4.6). |

### 3.2 Capability-only — experimental / unverified

Declared in `provider-capabilities.yaml` so the privacy router knows their
location and auth shape. **No named route, nothing selects them, no live receipt.**
Do not read their presence as support.

| Provider | Why capability-only |
|----------|---------------------|
| LiteLLM | Universal gateway (Phase 3). Effective privacy depends on its upstreams; the router would need to resolve the concrete backend first. |
| Anthropic | No route registered or exercised. |
| Gemini | No route registered or exercised. |
| Bedrock | AWS credential chain, not a single key; no route registered. |
| Azure OpenAI | Needs endpoint + deployment name beyond a key; no route registered. |
| Groq | No route registered or exercised. |
| Together | No route registered; tool support is model-dependent. |
| Fireworks | No route registered; tool support is model-dependent. |

Promoting one of these means: add the route to `model-routes.yaml`, flip its
`route_status` to `named-route`, and obtain a live receipt. The self-test
enforces the first two; only an operator run supplies the third.

## 4. Empirical Tool-Calling Finding

Controlled testing on **CPU-only hardware without a working GPU**:

| Model | Location | Outcome |
|-------|----------|---------|
| `qwen2.5-coder:7b` | Local (Ollama) | Emitted tool calls as **plain text** — could not reliably drive the forensic tools. |
| `llama3.1:8b` | Local (Ollama) | **Fabricated findings** — could not reliably drive the forensic tools. |
| `gpt-5.5` | Cloud (OpenAI) | Executed the real `case_open` → `pcap_triage` chain. |
| `gpt-5.4-mini` | Cloud (OpenAI) | Executed the real `case_open` → `pcap_triage` chain. |

**Honest scope:** this is a small sample of small local models on CPU-only
hardware versus two capable cloud models. It shows that a weak/underserved local
tool-caller is unsafe for real DFIR (invalid tool calls or fabrication), and that
capable cloud models handled the real chain. It does **not** establish that no
local model can do this — a GPU serving a strong tool-caller via vLLM is the path
for `local-only` real investigations (see MODEL_ROUTING.md). The custody
validator (Phase 8) is the backstop: fabricated, unbacked findings are rejected
regardless of which model produced them.

## 5. Practical Guidance

- **Real evidence, GPU available:** `local-only` with vLLM + a strong tool-caller.
- **Real evidence, CPU-only:** prefer `redacted-cloud` (redacted egress) over trusting a weak local model; never rely on an unreliable local tool-caller for reportable findings.
- **Synthetic / public / approved evidence:** `cloud-ok` with any capable cloud tool-caller.
- **Benchmark before trusting a provider** for tool-driven DFIR (Phase 14, planned).
