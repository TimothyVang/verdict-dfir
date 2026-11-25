# VERDICT + xAI Grok **cloud** (not local LLM / not Spark)

This is the **cloud model path**: the agent runtime calls **xAI’s Grok API** over the
internet. It is **not** Ollama on a DGX Spark and **not** `local-only` privacy.

## Privacy (read first)

| Mode | Grok cloud allowed? |
|------|---------------------|
| `local-only` (default) | **No** — privacy router blocks `privacy_locations: [cloud]` |
| `redacted-cloud` | Yes **after** redaction |
| `cloud-ok` | Yes for **synthetic / public / lab / operator-approved** evidence only |

**Never** send seized/private case evidence to Grok under `cloud-ok` unless the
operator has explicitly approved cloud egress and classified evidence correctly.

## Setup — SuperGrok **subscription OAuth** (preferred)

Uses the same OAuth path as the Grok CLI (device code / browser), **not**
`XAI_API_KEY` platform billing.

1. Ensure `VERDICT_BIN` points at a recent verdict/opencode binary (with xAI plugin).
2. Log in:

```bash
# Headless / remote (device code — open URL on any phone/laptop):
caseforge auth login --provider xai --method headless

# Or loopback browser on this machine (port 56121):
caseforge auth login --provider xai --method browser

caseforge auth status --provider xai
```

3. Investigate with the **oauth** route:

```bash
export VERDICT_DFIR_HOME=/path/to/dev-verdict
export VERDICT_BIN=/path/to/verdict

caseforge investigate fixtures/synthetic \
  --privacy cloud-ok \
  --evidence synthetic \
  --route xai-grok-oauth
```

Credentials live in `~/.local/share/opencode/auth.json` under provider `xai`
(`type: oauth`). Route `xai-grok-oauth` **deletes** `XAI_API_KEY` from the child
env so API keys cannot silently override subscription auth.

### Alternative — platform API key (not subscription)

```bash
export XAI_API_KEY=xai-...   # from https://console.x.ai/ API keys
caseforge investigate fixtures/synthetic \
  --privacy cloud-ok --evidence synthetic --route xai-grok
```

## Routes

| Route id | Auth | Model ref | Notes |
|----------|------|-----------|--------|
| **`xai-grok-oauth`** | SuperGrok OAuth | `xai/grok-3` | **Preferred** for Grok subscription |
| `xai-grok` | `XAI_API_KEY` | `xai/grok-3` | Platform API billing |
| `xai-grok-mini` | `XAI_API_KEY` | `xai/grok-3-mini` | Platform API, smaller |

## Commands

List routes (Grok should show **deny** under local-only, **allow** under cloud-ok + synthetic):

```bash
caseforge models --privacy local-only
caseforge models --privacy cloud-ok --evidence synthetic
```

Smoke helper (OAuth first; falls back to API key):

```bash
# After: caseforge auth login --provider xai --method headless
CASEFORGE_GROK_ROUTE=xai-grok-oauth bash scripts/grok-cloud-smoke.sh
```

## vs Spark / local

| | Spark Ollama | Grok cloud |
|--|--------------|------------|
| Route | `spark-ollama` | `xai-grok` |
| Endpoint | Your LAN Ollama | `https://api.x.ai/v1` |
| Privacy | `local` | `cloud` |
| Env | `VERDICT_LLM_BASEURL` | `XAI_API_KEY` |
| When offline Spark | fails | works if internet + key |

## Doctor

```bash
caseforge doctor --route xai-grok
# Expect: route present; cloud key not probed the same as local endpoint
```

If `XAI_API_KEY` is missing, investigate will fail at model auth — export the key first.
