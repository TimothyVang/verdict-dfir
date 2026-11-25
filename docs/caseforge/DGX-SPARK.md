# Running caseforge on a DGX Spark (local, offline model)

Goal: `git clone` on your box, serve a strong tool-calling model **locally on the
DGX Spark's GPU** (via Ollama), and drive the VERDICT DFIR agent with **no
outbound LLM traffic** — evidence and inference stay on your hardware.

> `caseforge-core` is the agent harness (it absorbed the earlier
> `verdict-agent-harness`). Everything below uses `caseforge-core`.

## Topology

```
your terminal ─▶ caseforge-core (agent harness)  ─▶ Ollama on the DGX Spark (GB10 GPU)
                 + VERDICT forensic MCP tools         serves the model, fully local
```

- **Model** → always on the Spark (GB10). Served by Ollama over the LAN.
- **Harness (caseforge + VERDICT MCP)** → the client box (a VM/laptop/workstation).
  It does **no inference**; 4 vCPU / 8 GB is plenty.
- Privacy: a Spark on your own network is `privacy_locations: [local]` — evidence
  never leaves your hardware, so `local-only` mode permits it.

## Model choice (agentic tool-calling first)

The harness is an agent: **tool-calling reliability + multi-step reasoning**
matter most; forensic knowledge comes from the MCP tools/evidence, not the
model's weights. A strong general agentic model beats a small "cyber" model.

| Model | Why | Footprint |
|---|---|---|
| **Qwen3.x-35B-A3B** (MoE, ~3B active) | top-tier tool/function-calling, fast agent loops | ~20 GB @ 4-bit |
| **gpt-oss-120b** | deeper reasoning; slower — worth an A/B for analysis quality | ~63 GB |

Pick by **empirical A/B** on a real DFIR task: tool-call success rate, analysis
quality, tokens/s. Confirm the exact Ollama tag before pulling.

> **Hardware note (unverified here):** the DGX Spark is **ARM64 (aarch64)**. The
> `verdict` binary and the Rust `findevil-mcp` must be built **on the box that
> runs them** (or a matching arch). The opencode fork's build is single-target
> for the current platform, and `cargo build` is native — so building on the
> Spark/VM produces the right arch. I have **not** tested any of this on GB10/ARM.

## One-time setup

### 1. Serve the model on the Spark

Ollama typically runs in a container on the Spark (no host `ollama` binary):

```bash
# on the Spark (adjust to your setup)
docker run -d --name ollama --gpus all -p 11434:11434 -v ollama:/root/.ollama ollama/ollama:latest
docker exec ollama ollama pull qwen3.6:35b-a3b        # confirm the exact tag
docker exec ollama ollama pull gpt-oss:120b            # A/B candidate
docker exec ollama ollama list
```

Verify tool-calling before trusting a model — POST `/api/chat` with a `tools`
array and confirm it returns real `tool_calls` (not text):

```bash
curl -s http://<spark-ip>:11434/api/chat -d '{"model":"qwen3.6:35b-a3b","stream":false,
  "messages":[{"role":"user","content":"list files in /tmp"}],
  "tools":[{"type":"function","function":{"name":"ls","description":"list a dir",
    "parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}]}' \
  | grep -q tool_calls && echo "tool-calling OK" || echo "model did not emit a tool_call"
```

### 2. Set up the harness on the client box

```bash
# prerequisites: git, node>=20, rust/cargo, uv, and bun (to build the verdict binary)
bash caseforge-core/scripts/setup.sh        # see below — clones+builds everything
```

`scripts/setup.sh` clones and builds the three repos it needs:
`verdict-opencode` (the `verdict` agent binary), `verdict-dfir-community` (the
forensic MCP tools → `VERDICT_DFIR_HOME`), and `caseforge-core` itself.

### 3. Point caseforge at the Spark

```bash
export VERDICT_DFIR_HOME=$PWD/verdict-dfir-community
export VERDICT_LLM_BASEURL=http://<spark-ip>:11434/v1
export VERDICT_LLM_MODEL=qwen3.6:35b-a3b
export CASEFORGE_PRIVACY=local-only

node caseforge-core/packages/caseforge-cli/dist/src/cli.js doctor
```

## Run

```bash
CLI="node caseforge-core/packages/caseforge-cli/dist/src/cli.js"

# any local route now targets the Spark (VERDICT_LLM_BASEURL/MODEL override the route)
$CLI models --privacy local-only            # spark-ollama shows [allow]
$CLI investigate /path/to/case --privacy local-only --route spark-ollama
$CLI verify "$VERDICT_DFIR_HOME/.project-local/findevil/cases/<case-id>"
```

## Confirm it's fully offline

```bash
# during a run, on the client box — there must be NO outbound LLM/API connections:
ss -tnp | grep -vE '11434|:22|127\.0\.0\.1' | grep ESTAB || echo "no external egress"
```
`local-only` mode also refuses every cloud route by construction, so caseforge
will not contact a cloud model even if one is configured.

## A/B and lock the winner

Run the same real DFIR task against `qwen3.6:35b-a3b` and `gpt-oss:120b`; compare
tool-call success, analysis quality, and tokens/s; set the winner as your
`VERDICT_LLM_MODEL`. (A 3-Spark cluster for larger models — e.g. a 397B at FP4 —
is a later effort; only the endpoint/model tag changes, the harness wiring is
identical.)

## What is and isn't verified

- **Verified on x86 Linux:** caseforge builds, `doctor`/`models`/`verify` work,
  privacy routing enforces local-only, and the agent→MCP→tool chain executes real
  forensic tools with a capable model.
- **Verified on the DGX Spark (GB10 / ARM64), 2026-07-08:** native `aarch64` builds
  of `verdict` and `findevil-mcp`, Ollama-on-Spark serving `gpt-oss:120b` on the
  GB10 GPU, and end-to-end `caseforge investigate` running **entirely on-box**
  against a local (`localhost`) endpoint — producing a **custody-verified** sealed
  run (`auto-95f54362`, `manifest_verify.overall = true`, ed25519 signature verified,
  `EXIT_CODE=0`). See [`SPARK_INVESTIGATION_RESULTS.md`](./SPARK_INVESTIGATION_RESULTS.md)
  for the full receipt and the observed-vs-expected technique scorecard.
- **Caveat on that run:** the verdict came from caseforge's **deterministic EVTX
  fallback** (the gpt-oss agent run did not seal), it read **only 1 of the case's 2
  EVTX files**, and the verdict is **INDETERMINATE** — the policy default for
  single-source EVTX. It is a real, hash-chained local run, **not** a confirmed
  intrusion or a full-battery detection. The results doc records the detection gap
  (unread WMI file, missing T1047 target) and the fixes it implies.
- **Still NOT verified:** the **remote-endpoint / over-the-LAN** topology described
  above (client box driving a Spark across the network) and a **complete sealed
  agent run** (as opposed to the EVTX fallback) on the Spark.
