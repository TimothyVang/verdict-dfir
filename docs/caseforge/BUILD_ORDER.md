# Build Order — caseforge-core

> Phases 0–14. Status reflects the current build increment. The MVP core is
> Phases 0–2 (partial), 4 (route readiness), 6, 7, 8, 9, 10. Everything else
> is planned/stubbed.

## Status Legend

| Marker | Meaning |
|--------|---------|
| Done | Implemented in the current increment (as MVP core). |
| Partial | Started; enough to serve the MVP, not complete. |
| Planned | Stubbed or not yet implemented. |

## Checklist

- [~] **Phase 0 — SDK + CLI shell.** `@verdict/caseforge-sdk` + `@verdict/caseforge-cli` skeleton; `caseforge` command surface. **(Partial)**
- [~] **Phase 1 — Wire OpenCode SDK.** OpenCode controller with locked config, agent loop entry. **(Partial)**
- [~] **Phase 2 — Wire VERDICT MCP commands.** Load `findevil-mcp` (32 Rust read-only tools) + `findevil-agent-mcp` (14 Python crypto/custody/reasoning tools). **(Partial)**
- [ ] **Phase 3 — LiteLLM universal gateway.** Single gateway fronting local + cloud providers. **(Planned)**
- [~] **Phase 4 — Local vLLM + Ollama route readiness.** Registered local serving backends with selected-route doctor/readiness; live use requires a running endpoint. **(Partial)**
- [ ] **Phase 5 — OpenRouter + direct Z.AI routes.** Add these cloud/API routes. **(Planned)**
- [x] **Phase 6 — Enforce privacy-mode routing.** `local-only` / `redacted-cloud` / `cloud-ok`, fail-closed. **(Done — MVP core)**
- [x] **Phase 7 — Structured finding schema.** Canonical JSON schema for findings. **(Done — MVP core)**
- [x] **Phase 8 — Verify `tool_call_id` + `output_sha256`.** Bind each finding to its tool evidence. **(Done — MVP core)**
- [x] **Phase 9 — Validate VERDICT run artifacts.** `verdict.json`, `coverage_manifest.json`, `run.manifest.json`, `manifest_verify.json`, `audit.jsonl`; incomplete / custody-invalid gating. **(Done — MVP core)**
- [x] **Phase 10 — Fixture-only GitHub workflow.** CI runs synthetic/public fixtures only. **(Done — MVP core)**
- [ ] **Phase 11 — OCR router.** Route document/image OCR (`caseforge ocr <case-id>`). **(Planned)**
- [ ] **Phase 12 — Rust ingest core.** `caseforge-core` crate; `caseforge ingest <evidence-path>`. **(Planned)**
- [ ] **Phase 13 — Expose Rust ingest as read-only MCP.** Serve ingest core over MCP, read-only. **(Planned)**
- [ ] **Phase 14 — Benchmark + provider capability tests.** `caseforge benchmark run`. **(Planned)**

## MVP Core Boundary

The current increment delivers the SDK controller + privacy router + finding
schema + artifact/custody validator + CLI (`doctor`, `models`, `investigate`,
`verify`) + the fixtures workflow. That is Phases 0–2 (partial), 4 (route
readiness), 6, 7, 8, 9, 10.

Honesty note: Phases 3 and 5 (LiteLLM gateway and OpenRouter/Z.AI hardening),
11 (OCR), 12–13 (Rust ingest), and 14 (benchmarks) are **not yet implemented**.
Phase 4 route readiness is implemented, but live local-model investigation still
requires a running vLLM/Ollama/Spark endpoint. Where the CLI exposes
`gateway start`, `benchmark run`, `ocr`, or `ingest`, those commands are stubs
pending their phases.

## Suggested Sequence After MVP

1. **Phase 3 and 5** to unlock real model routing breadth (gateway + cloud route hardening). Keep Phase 4 focused on proving a running GPU-served local tool-caller when hardware is available (see MODEL_ROUTING.md).
2. **Phase 14** early-partial to benchmark tool-calling capability per provider, informing routing defaults.
3. **Phase 11** OCR router once evidence types demand it.
4. **Phase 12–13** Rust ingest core + read-only MCP for high-throughput ingest.
