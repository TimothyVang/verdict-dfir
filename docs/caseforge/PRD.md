# Product Requirements — caseforge-core

> Headless, agent-friendly DFIR controller built around VERDICT tools, the OpenCode
> SDK, and universal LLM routing. Show me the evidence: every reportable
> finding is backed by tool output, not model assertion.

## 1. Problem

Digital forensics and incident response (DFIR) increasingly want to put a
language model in the loop — to triage evidence, propose investigative steps,
and draft reports. But an LLM left unchecked hallucinates findings, leaks
sensitive evidence to third-party APIs, and produces conclusions with no chain
of custody. None of that survives review.

`caseforge-core` is the agentic harness that makes LLM-driven DFIR
defensible. It wraps VERDICT's read-only forensic tools, enforces a
privacy-mode router so real evidence stays local, and rejects any finding that
is not backed by verifiable tool evidence. It is headless by design — no
examiner GUI — so it runs the same on a Linux laptop, a DGX/Spark box, a SIFT
workstation, a server, or a CI fixture runner.

## 2. Users

| User | Need |
|------|------|
| DFIR analyst / examiner | Run a case through forensic tools with an agent driving triage, without hand-wiring every step, and get findings that hold up in review. |
| Incident response (IR) team | Fast, repeatable triage of pcap/disk/memory artifacts across many hosts, with custody guarantees. |
| CI / fixture runner | Automated regression testing of the harness against synthetic and public fixtures — no real evidence, ever. |
| Tool/platform engineer | A stable SDK + CLI surface to extend, benchmark providers, and integrate the future Rust ingest core. |

## 3. Goals

- Headless DFIR controller driven by the OpenCode SDK controller — no GUI dependency.
- Universal LLM routing: local/offline models and online/API providers behind one gateway.
- Privacy-mode router that keeps real evidence local by default.
- Structured finding schema with enforced evidence backing.
- VERDICT artifact and custody validation as a hard gate on run validity.
- Provider-agnostic model support (local vLLM/Ollama/llama.cpp/LM Studio/NIM; cloud LiteLLM/OpenRouter/Z.AI/OpenAI/Anthropic/Gemini/Bedrock/Azure/Groq/Together/Fireworks).
- A future Rust ingest core exposed as a read-only MCP.

## 4. Non-Goals (Excludes)

The following are explicitly out of scope. caseforge-core does **not**
build, embed, or depend on:

- Autopsy, Autopsy MCP/modules, or case-DB adapters.
- Any examiner GUI workbench logic.
- Generic shell MCP.
- Generic filesystem MCP.
- Docker / Kubernetes MCP.
- Broad GitHub admin MCP.
- Real evidence in GitHub Actions.

## 5. MVP Target

Run a **synthetic fixture** through the harness using a **local model**, VERDICT
MCP tools, structured findings, and artifact validation — **without sending
evidence to the cloud**.

### MVP Success Criteria

- [ ] OpenCode starts with a locked configuration.
- [ ] VERDICT MCP servers load (`findevil-mcp`, `findevil-agent-mcp`).
- [ ] Model route respects the active privacy mode.
- [ ] Agent can produce structured JSON findings.
- [ ] Invalid findings are rejected.
- [ ] Missing VERDICT artifacts mark the run **incomplete**.
- [ ] Failed manifest verification marks the run **custody-invalid**.
- [ ] GitHub Actions runs only synthetic/public fixtures.
- [ ] No raw evidence leaves the host in `local-only` mode.

## 6. Phased Roadmap (0–14)

Status reflects the **current build increment**. Phases 0–2 (partial), 4 (route
readiness), 6, 7, 8, 9, 10 form the MVP core. The rest are planned/stubbed.

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 0 | SDK + CLI shell | Partial |
| 1 | Wire OpenCode SDK | Partial |
| 2 | Wire VERDICT MCP commands | Partial |
| 3 | LiteLLM universal gateway | Planned |
| 4 | Local vLLM + Ollama route readiness | Partial |
| 5 | OpenRouter + direct Z.AI routes | Planned |
| 6 | Enforce privacy-mode routing | Done (MVP core) |
| 7 | Structured finding schema | Done (MVP core) |
| 8 | Verify `tool_call_id` + `output_sha256` | Done (MVP core) |
| 9 | Validate VERDICT run artifacts | Done (MVP core) |
| 10 | Fixture-only GitHub workflow | Done (MVP core) |
| 11 | OCR router | Planned |
| 12 | Rust ingest core | Planned |
| 13 | Expose Rust ingest as read-only MCP | Planned |
| 14 | Benchmark + provider capability tests | Planned |

> Honesty note: "Done (MVP core)" means the phase is implemented in the current
> increment as part of the MVP. It does not mean the whole product ships. Phases
> 3–5, 11, 12–13, and 14 are not yet implemented.

## 7. Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Evidence leakage to cloud APIs | Confidentiality breach, case ruined | Fail-closed `local-only` default; privacy-mode router blocks cloud + web. |
| Hallucinated findings | Non-defensible conclusions | LLM is not source of truth; findings require `tool_call_id` + `output_sha256` + manifest verify. |
| Weak local tool-callers | Local-only real investigations fail | Empirically, small CPU-only models (qwen2.5-coder:7b, llama3.1:8b) could not reliably drive tools; require a GPU + vLLM serving a strong tool-caller. See MODEL_ROUTING.md. |
| Missing/corrupt VERDICT artifacts | Silent bad runs | Missing artifacts => run incomplete; failed manifest verify => custody-invalid. |
| Scope creep into GUI/workbench | Loses headless posture | Hard exclude list; bridge to, never depend on, external workbenches. |
