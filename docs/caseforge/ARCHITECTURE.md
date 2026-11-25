# Architecture — caseforge-core

> Headless DFIR controller. Evidence flows in, verified structured findings flow
> out. The LLM orchestrates; VERDICT tools are the source of truth.

## 1. Components

| Component | Package / Crate | Role |
|-----------|-----------------|------|
| CLI | `@verdict/caseforge-cli` | Operator entrypoint (`caseforge …`). Parses commands, selects privacy mode, invokes SDK. |
| SDK controller | `@verdict/caseforge-sdk` | Hosts the OpenCode SDK controller + privacy router. Locks OpenCode config, starts the agent loop, mediates every tool call. |
| OpenCode SDK controller | (in SDK) | Runs the agent with a locked config; connects to VERDICT MCP servers; exposes tools to the model. |
| Privacy-mode router | (in SDK) | Enforces `local-only` / `redacted-cloud` / `cloud-ok` on every model route. Fail-closed. |
| VERDICT MCP servers | external MCP | `findevil-mcp` = 32 Rust read-only DFIR tools; `findevil-agent-mcp` = 14 Python crypto/custody/reasoning tools. |
| Universal LLM gateway | (planned, Phase 3+) | LiteLLM-based gateway fronting local + cloud providers. |
| Structured finding schema | (in SDK) | Canonical JSON schema every reportable finding must satisfy. |
| Custody validator | (in SDK) | Verifies `tool_call_id` + `output_sha256` + manifest for each finding. |
| Artifact validator | (in SDK) | Validates VERDICT run artifacts; marks runs incomplete / custody-invalid. |
| OCR router | (planned, Phase 11) | Routes document/image OCR requests. |
| Rust ingest core | `caseforge-core` (planned, Phase 12–13) | High-throughput evidence ingest, later exposed as a read-only MCP. |

## 2. Data Flow

```
evidence-path
    │
    ▼
caseforge-cli  ──selects privacy mode──►
    │
    ▼
caseforge-sdk
    ├── OpenCode controller (locked config)
    │        │  proposes steps / drafts report (NOT source of truth)
    │        ▼
    ├── privacy router ──► enforce local-only / redacted-cloud / cloud-ok
    │        │            (blocks cloud + web in local-only)
    │        ▼
    ├── VERDICT MCP tools ──► findevil-mcp (32 Rust read-only)
    │        │                findevil-agent-mcp (14 Python crypto/custody/reasoning)
    │        ▼
    ├── structured findings (JSON schema)
    │        ▼
    ├── custody validation (tool_call_id + output_sha256 + manifest)
    │        ▼
    └── run artifacts ──► verdict.json, coverage_manifest.json,
                          run.manifest.json, manifest_verify.json, audit.jsonl
```

### Flow narrative

1. Operator runs `caseforge investigate <evidence-path>` with a privacy mode.
2. The CLI hands control to the SDK, which starts the OpenCode controller under a **locked** config.
3. The model proposes investigative steps and calls VERDICT tools. It does not itself constitute evidence.
4. Every model route passes the **privacy router** first; in `local-only`, cloud APIs and web access are blocked.
5. Tool calls hit the VERDICT MCP servers (read-only). Each returns output that is hashed (`output_sha256`) and tied to a `tool_call_id`.
6. The agent emits **structured findings**; each must validate against the schema and carry evidence backing.
7. The **custody validator** checks `tool_call_id` + `output_sha256` + manifest. Findings without backing are rejected.
8. The **artifact validator** confirms the VERDICT run artifacts exist and verify. Missing artifacts => incomplete; failed manifest verify => custody-invalid.

## 3. Run Artifacts

The canonical output of a valid run (`caseforge verify <run-dir>` checks these):

| Artifact | Purpose |
|----------|---------|
| `verdict.json` | Structured findings + verdict for the run. |
| `coverage_manifest.json` | What evidence/scope was covered. |
| `run.manifest.json` | Run-level manifest (inputs, tools, hashes). |
| `manifest_verify.json` | Result of manifest verification. |
| `audit.jsonl` | Append-only audit log of tool calls and decisions. |

## 4. Monorepo Layout

```
caseforge-core/
├── packages/
│   ├── caseforge-sdk/      # @verdict/caseforge-sdk — controller, privacy router,
│   │                       #   finding schema, custody + artifact validators
│   └── caseforge-cli/      # @verdict/caseforge-cli — caseforge command surface
├── crates/
│   └── caseforge-core/     # Rust ingest core (planned, Phase 12–13)
├── configs/                # locked OpenCode config, model routes, privacy policy
├── docs/                   # this documentation set
├── scripts/                # dev / ops automation
└── .github/                # fixture-only CI workflow (Phase 10)
```

## 5. CLI Surface

| Command | Purpose | Status |
|---------|---------|--------|
| `caseforge doctor` | Environment + config + MCP health check. | MVP |
| `caseforge models` | List available/routable models. | MVP |
| `caseforge investigate <evidence-path>` | Run an agentic investigation. | MVP |
| `caseforge verify <run-dir>` | Validate run artifacts + custody. | MVP |
| `caseforge gateway start` | Start the universal LLM gateway. | Planned (Phase 3) |
| `caseforge benchmark run` | Provider capability + benchmark tests. | Planned (Phase 14) |
| `caseforge ocr <case-id>` | Route OCR for a case. | Planned (Phase 11) |
| `caseforge fleet [run-dir ...]` | DFIR investigation multiplexer (Rust/ratatui): status grid, live-attach, socket API, detach/reattach. | Done (crates/caseforge-fleet) |
| `caseforge ingest <evidence-path>` | Rust ingest core entrypoint. | Planned (Phase 12) |

## 6. Design Invariants

- **Headless.** No examiner GUI; every capability is CLI/SDK/agent-driven.
- **Read-only forensics.** VERDICT tools do not mutate evidence.
- **Fail-closed privacy.** Default `local-only`; the router blocks cloud/web unless mode allows.
- **Evidence-backed findings only.** No `tool_call_id` + `output_sha256` + manifest => not a finding.
- **Bridge, don't depend.** External workbenches are bridged to, never a dependency (see EXTERNAL_WORKBENCH_BRIDGES.md).
